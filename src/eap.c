/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2018  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ell/ell.h>

#include "src/missing.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "crypto.h"
#include "util.h"

static uint32_t default_mtu;
struct l_queue *eap_methods;
static struct l_queue *erp_key_cache;

static void dump_eap(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s\n", prefix, str);
}

enum eap_erp_type {
	EAP_ERP_TYPE_REAUTH_START	= 1,
	EAP_ERP_TYPE_REAUTH		= 2,
};

enum eap_erp_tlv {
	EAP_ERP_TLV_KEYNAME_NAI = 1,
	EAP_ERP_TV_RRK_LIFETIME = 2,
	EAP_ERP_TV_RMSK_LIFETIME = 3,
	EAP_ERP_TLV_DOMAIN_NAME = 4,
	EAP_ERP_TLV_CRYPTOSUITES = 5,
	EAP_ERP_TLV_AUTH_INDICATION = 6,
	EAP_ERP_TLV_CALLED_STATION_ID = 128,
	EAP_ERP_TLV_CALLING_STATION_ID = 129,
	EAP_ERP_TLV_NAS_IDENTIFIER = 130,
	EAP_ERP_TLV_NAS_IP_ADDRESS = 131,
	EAP_ERP_TLV_NAS_IPV6_ADDRESS = 132,
};

enum eap_erp_cryptosuite {
	EAP_ERP_CRYPTOSUITE_SHA256_64 = 1,
	EAP_ERP_CRYPTOSUITE_SHA256_128 = 2,
	EAP_ERP_CRYPTOSUITE_SHA256_256 = 3,
};

struct eap_erp_state {
	uint8_t emsk[64];
	size_t emsk_len;
	uint8_t r_rk[64];
	uint8_t r_ik[64];
	char keyname_nai[254];
	uint16_t seq;
};

struct erp_tlv_iter {
	unsigned int max;
	unsigned int pos;
	const unsigned char *tlv;
	unsigned int tag;
	unsigned int len;
	const unsigned char *data;
};

struct eap_state {
	eap_tx_packet_func_t tx_packet;
	eap_key_material_func_t set_key_material;
	eap_complete_func_t complete;
	eap_event_func_t event_func;
	void *user_data;
	size_t mtu;

	struct eap_method *method;
	char *identity;
	char *erp_domain;

	int last_id;
	void *method_state;
	bool method_success;
	struct l_timeout *complete_timeout;
	struct eap_erp_state *erp;

	bool erp_allowed:1;
	bool discard_success_and_failure:1;
};

struct erp_cache_entry {
	void *id;
	size_t id_len;
	void *emsk;
	size_t emsk_len;
	void *session_id;
	size_t session_len;
	/*
	 * TODO: Support key lifetimes. For proper support this will require
	 * writing these keys/expirations to disk so the lifetimes will remain
	 * relevant between boots.
	 */
};

static void erp_tlv_iter_init(struct erp_tlv_iter *iter,
				const unsigned char *tlv, unsigned int len)
{
	iter->tlv = tlv;
	iter->max = len;
	iter->pos = 0;
}

static bool erp_tlv_iter_next(struct erp_tlv_iter *iter)
{
	const unsigned char *tlv = iter->tlv + iter->pos;
	const unsigned char *end = iter->tlv + iter->max;
	unsigned int tag;
	unsigned int len;

	if (iter->pos + 1 >= iter->max)
		return false;

	tag = *tlv++;

	/*
	 * These two tags are not actually TLVs (they are just type-value). Both
	 * are 32-bit integers.
	 */
	if (tag != EAP_ERP_TV_RMSK_LIFETIME && tag != EAP_ERP_TV_RRK_LIFETIME)
		len = *tlv++;
	else
		len = 4;

	if (tlv + len > end)
		return false;

	iter->tag = tag;
	iter->len = len;
	iter->data = tlv;

	iter->pos = tlv + len - iter->tlv;

	return true;
}

static void erp_destroy_entry(void *data)
{
	struct erp_cache_entry *entry = data;

	l_free(entry->id);
	l_free(entry->emsk);
	l_free(entry->session_id);
	l_free(entry);
}

static void erp_cache_add_key(const void *id, size_t id_len,
				const void *session_id, size_t session_len,
				const void *emsk, size_t emsk_len)
{
	struct erp_cache_entry *entry;

	if (!unlikely(id || session_id || emsk))
		return;

	entry = l_new(struct erp_cache_entry, 1);

	entry->id = l_memdup(id, id_len);
	entry->id_len = id_len;
	entry->emsk = l_memdup(emsk, emsk_len);
	entry->emsk_len = emsk_len;
	entry->session_id = l_memdup(session_id, session_len);
	entry->session_len = session_len;

	l_queue_push_head(erp_key_cache, entry);
}

static struct erp_cache_entry *find_keycache(const void *id, size_t id_len)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(erp_key_cache); entry;
			entry = entry->next) {
		struct erp_cache_entry *cache = entry->data;

		if (cache->id_len != id_len)
			continue;

		if (memcmp(cache->id, id, id_len))
			continue;

		return cache;
	}

	return NULL;
}

static bool erp_cache_get_key(const void *id, size_t id_len, void *session,
				size_t *session_len, void *emsk,
				size_t *emsk_len)
{
	struct erp_cache_entry *cache = find_keycache(id, id_len);

	if (!cache)
		return false;

	memcpy(emsk, cache->emsk, cache->emsk_len);
	*emsk_len = cache->emsk_len;
	memcpy(session, cache->session_id, cache->session_len);
	*session_len = cache->session_len;

	return true;
}

static bool erp_cache_remove_key(const void *id, size_t id_len)
{
	struct erp_cache_entry *cache = find_keycache(id, id_len);

	if (!cache)
		return false;

	l_queue_remove(erp_key_cache, cache);

	erp_destroy_entry(cache);

	return true;
}

static bool erp_cache_has_key(const void *id, size_t id_len)
{
	return find_keycache(id, id_len) != NULL;
}

bool eap_has_cached_keys(struct l_settings *settings)
{
	struct eap_state *tmp;

	if (!settings)
		return false;

	tmp = eap_new(NULL, NULL, NULL);

	if (!eap_load_settings(tmp, settings, "EAP-"))
		return false;

	if (!erp_cache_has_key(tmp->identity, strlen(tmp->identity)))
		goto err;

	eap_free(tmp);
	return true;

err:
	eap_free(tmp);
	return false;
}

struct eap_state *eap_new(eap_tx_packet_func_t tx_packet,
			eap_complete_func_t complete, void *user_data)
{
	struct eap_state *eap;

	eap = l_new(struct eap_state, 1);

	eap->last_id = -1;
	eap->mtu = default_mtu;

	eap->tx_packet = tx_packet;
	eap->complete = complete;
	eap->user_data = user_data;

	return eap;
}

/*
 * Setting a non-NULL set_key_material callback for this EAP instance will
 * disable the legacy methods that don't generate key material, such
 * as EAP-MD5.
 */
void eap_set_key_material_func(struct eap_state *eap,
				eap_key_material_func_t func)
{
	eap->set_key_material = func;
}

void eap_set_event_func(struct eap_state *eap, eap_event_func_t func)
{
	eap->event_func = func;
}

void eap_set_erp_allowed(struct eap_state *eap, bool erp_allowed)
{
	eap->erp_allowed = erp_allowed;
}

bool eap_reset(struct eap_state *eap)
{
	if (eap->method_state && eap->method->reset_state) {
		if (!eap->method->reset_state(eap))
			return false;
	}

	eap->method_success = false;
	l_timeout_remove(eap->complete_timeout);
	eap->complete_timeout = NULL;

	return true;
}

static void eap_free_common(struct eap_state *eap)
{
	if (eap->method_state && eap->method->free)
		eap->method->free(eap);

	eap->method = NULL;

	if (eap->identity) {
		l_free(eap->identity);
		eap->identity = NULL;
	}

	if (eap->erp_domain)
		l_free(eap->erp_domain);

	if (eap->erp)
		l_free(eap->erp);
}

void eap_free(struct eap_state *eap)
{
	eap_free_common(eap);
	l_timeout_remove(eap->complete_timeout);

	l_free(eap);
}

/* Note: callers must check for a minimum value */
void eap_set_mtu(struct eap_state *eap, size_t mtu)
{
	eap->mtu = mtu;
}

size_t eap_get_mtu(struct eap_state *eap)
{
	return eap->mtu;
}

/**
 * eap_send_response:
 * @eap: EAP state
 * @type: Type of response being sent
 * @buf: Buffer to send
 * @len: Size of the buffer
 *
 * Sends out a response to a received request.  This method first fills the
 * EAP header into the buffer based on the EAP type response being sent.
 *
 * If the response type is EAP_TYPE_EXPANDED, then the Vendor-Id and
 * Vendor-Type fields are filled in based on contents of the eap_method
 * associated with @eap.
 *
 * The buffer passed in MUST be at least 12 bytes long if @type is
 * EAP_TYPE_EXPANDED and at least 5 bytes for other cases.
 **/
void eap_send_response(struct eap_state *eap, enum eap_type type,
						uint8_t *buf, size_t len)
{
	buf[0] = EAP_CODE_RESPONSE;
	buf[1] = eap->last_id;
	l_put_be16(len, &buf[2]);
	buf[4] = type;

	if (type == EAP_TYPE_EXPANDED) {
		memcpy(buf + 5, eap->method->vendor_id, 3);
		l_put_be32(eap->method->vendor_type, buf + 8);
	}

	eap->tx_packet(buf, len, eap->user_data);
}

static void eap_complete_timeout(struct l_timeout *timeout, void *user_data)
{
	struct eap_state *eap = user_data;

	eap->complete_timeout = NULL;

	eap->complete(eap->method_success ? EAP_RESULT_SUCCESS :
			EAP_RESULT_TIMEOUT, eap->user_data);
}

void eap_start_complete_timeout(struct eap_state *eap)
{
	if (eap->complete_timeout)
		l_timeout_remove(eap->complete_timeout);

	eap->complete_timeout = l_timeout_create(5, eap_complete_timeout,
							eap, NULL);
}

static void eap_send_identity_response(struct eap_state *eap, char *identity)
{
	int len = identity ? strlen(identity) : 0;
	uint8_t buf[5 + len];

	if (!identity)
		identity = "";

	memcpy(buf + 5, identity, len);

	eap_send_response(eap, EAP_TYPE_IDENTITY, buf, len + 5);
}

#define ERP_RRK_LABEL	"EAP Re-authentication Root Key@ietf.org"
#define ERP_RIK_LABEL	"Re-authentication Integrity Key@ietf.org"
#define ERP_RMSK_LABEL	"Re-authentication Master Session Key@ietf.org"

/*
 * RFC 5295 - Section 3.2. EMSK and USRK Name Derivation
 */
static void erp_derive_emsk_name(const uint8_t *session_id, size_t session_len,
					char buf[17])
{
	uint8_t hex[8];
	char info[7];
	char *ascii;

	strcpy(info, "EMSK");
	l_put_be16(8, info + 5);

	hkdf_expand(L_CHECKSUM_SHA256, session_id, session_len, info,
				sizeof(info), hex, 8);

	ascii = l_util_hexstring(hex, 8);

	strcpy(buf, ascii);

	l_free(ascii);
}

/*
 * RFC 6696 - Section 4.1 and 4.3 - rRK and rIK derivation
 *
 * All reauth keys form a hiearchy, and all ultimately are derived from the
 * EMSK. All keys follow the rule:
 *
 * "The length of the <key> MUST be equal to the length of the parent key used
 *  to derive it."
 *
 * Therefore all keys derived are equal to the EMSK length.
 */
static void erp_derive_reauth_keys(const uint8_t *emsk, size_t emsk_len,
					void *r_rk, void *r_ik)
{
	uint8_t info[256];
	uint8_t *ptr = info;
	size_t info_len;

	info_len = strlen(ERP_RRK_LABEL);

	strcpy((char *)ptr, ERP_RRK_LABEL);
	ptr += info_len + 1;
	l_put_be16(emsk_len, ptr);
	ptr += 2;

	hkdf_expand(L_CHECKSUM_SHA256, emsk, emsk_len, (const char *)info,
			ptr - info, r_rk, emsk_len);

	info_len = strlen(ERP_RIK_LABEL);
	ptr = info;

	strcpy((char *)ptr, ERP_RIK_LABEL);
	ptr += info_len + 1;
	*ptr++ = EAP_ERP_CRYPTOSUITE_SHA256_128;
	l_put_be16(emsk_len, ptr);
	ptr += 2;

	hkdf_expand(L_CHECKSUM_SHA256, r_rk, emsk_len, (const char *) info,
			ptr - info, r_ik, emsk_len);
}

/*
 * RFC 6696 Section 5.3.2 - EAP-Initiate/Re-auth Packet
 */
bool eap_send_initiate_reauth(struct eap_state *eap)
{
	uint8_t buf[512];
	uint8_t *ptr = buf;
	uint8_t session_id[64];
	size_t session_len;
	char emsk_name[17];
	size_t nai_len;

	struct eap_erp_state *erp;

	if (!eap->erp_domain) {
		l_error("No known ERP Domain");
		return false;
	}

	erp = l_new(struct eap_erp_state, 1);

	if (!erp_cache_get_key(eap->identity, strlen(eap->identity), session_id,
				&session_len, erp->emsk, &erp->emsk_len)) {
		l_error("Identity %s not found in ERP cache", eap->identity);
		l_free(erp);
		return false;
	}

	erp_derive_emsk_name(session_id, session_len, emsk_name);
	erp_derive_reauth_keys(erp->emsk, erp->emsk_len, erp->r_rk, erp->r_ik);

	nai_len = sprintf(erp->keyname_nai, "%s@%s", emsk_name,
				eap->erp_domain);

	*ptr++ = EAP_CODE_INITIATE;
	*ptr++ = 0;
	/* Header (8) + TL (2) + NAI (nai_len) + CS (1) + auth tag (16) */
	l_put_be16(27 + nai_len, ptr);
	ptr += 2;
	*ptr++ = EAP_ERP_TYPE_REAUTH;
	*ptr++ = 0;
	l_put_be16(erp->seq, ptr);
	ptr += 2;

	/* keyName-NAI TLV */
	*ptr++ = EAP_ERP_TLV_KEYNAME_NAI;
	*ptr++ = nai_len;
	memcpy(ptr, erp->keyname_nai, nai_len);
	ptr += nai_len;

	*ptr++ = EAP_ERP_CRYPTOSUITE_SHA256_128;

	hmac_sha256(erp->r_ik, erp->emsk_len, buf, ptr - buf, ptr, 16);
	ptr += 16;

	eap->erp = erp;

	eap->tx_packet(buf, ptr - buf, eap->user_data);

	return true;
}

static void eap_handle_initiate(struct eap_state *eap, const uint8_t *pkt,
				size_t len)
{
	uint8_t type = pkt[0];
	const uint8_t *ptr = pkt;
	char *erp_domain = NULL;
	struct erp_tlv_iter iter;

	if (type != EAP_ERP_TYPE_REAUTH_START)
		return;

	/* No point in continuing, the domain is already known */
	if (eap->erp_domain)
		return;

	if (len < 2)
		return;

	/* Advance to TLVs */
	ptr += 2;
	len -= 2;

	erp_tlv_iter_init(&iter, ptr, len);

	while (erp_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case EAP_ERP_TLV_DOMAIN_NAME:
			erp_domain = l_strndup((char *)iter.data, iter.len);
			break;
		default:
			/*
			 * TOOD: Channel binding should be parsed in the future
			 */
			break;
		}
	}

	if (!erp_domain)
		return;

	/*
	 * TODO: This is currently pointless unless this is an actual re-auth.
	 * Hostapd seems to only send this before a full EAP authenticate
	 * attempt. For this reason we *should* be writing this to the settings
	 * file as "EAP-ERP-Domain" unless this is already specified.
	 */
	eap->erp_domain = erp_domain;
}

static void eap_handle_finish(struct eap_state *eap, const uint8_t *pkt,
				size_t len)
{
	struct eap_erp_state *erp = eap->erp;
	struct erp_tlv_iter iter;
	enum eap_erp_cryptosuite cs;
	uint8_t hash[16];
	uint8_t rmsk[64];
	char info[256];
	char *ptr = info;
	const uint8_t *nai = NULL;
	uint8_t type;
	uint16_t seq;
	bool r;

	/*
	 * Not including the TLVs we have:
	 * header (8) + cryptosuite (1) + auth tag (16) = 25 bytes
	 */
	if (len < 25)
		goto eap_failed;

	/*
	 * We can skip code/id/len, since that was already parsed. We just need
	 * the whole packet so we can verify the Auth tag.
	 */
	type = pkt[4];

	if (type != EAP_ERP_TYPE_REAUTH)
		return;

	r = util_is_bit_set(pkt[5], 0);
	if (r)
		goto eap_failed;

	/*
	 * TODO: Parse B and L bits. L bit indicates rRK lifetime, but our ERP
	 * cache does not yet support this.
	 */

	seq = l_get_be16(pkt + 6);

	if (seq != eap->erp->seq)
		goto eap_failed;

	/*
	 * The Cryptosuite byte comes after the TLVs. Because of this we cannot
	 * parse the TLVs yet since we don't actually know where they end. There
	 * is really no good way to do this, but (at least for now) we can just
	 * require the 128 bit cryptosuite. If we limit to only this suite we
	 * can work backwards from the end (17 bytes) to get the cryptosuite. If
	 * it is not the 128 bit suite we just fail. If it is, we now know where
	 * the TLVs end;
	 */
	cs = *(pkt + len - 17);

	if (cs != EAP_ERP_CRYPTOSUITE_SHA256_128)
		goto eap_failed;

	hmac_sha256(erp->r_ik, erp->emsk_len, pkt, len - 16, hash, 16);

	if (memcmp(hash, pkt + len - 16, 16) != 0) {
		l_debug("Authentication Tag did not verify");
		goto eap_failed;
	}

	erp_tlv_iter_init(&iter, pkt + 8, len - 8 - 17);

	while (erp_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case EAP_ERP_TLV_KEYNAME_NAI:
			if (nai)
				goto eap_failed;

			nai = iter.data;
			break;
		default:
			break;
		}
	}

	/*
	 * RFC 6696 Section 5.3.3
	 *
	 * Exactly one instance of the keyName-NAI attribute SHALL be present
	 * in an EAP-Finish/Re-auth message
	 */
	if (!nai) {
		l_error("AP did not include keyName-NAI in EAP-Finish");
		goto eap_failed;
	}

	if (memcmp(nai, erp->keyname_nai, strlen(erp->keyname_nai))) {
		l_error("keyName-NAI did not match");
		goto eap_failed;
	}

	/*
	 * RFC 6696 Section 4.6 - rMSK Derivation
	 */
	strcpy(ptr, ERP_RMSK_LABEL);
	ptr += strlen(ERP_RMSK_LABEL);
	*ptr++ = '\0';
	l_put_be16(eap->erp->seq, ptr);
	ptr += 2;
	l_put_be16(64, ptr);
	ptr += 2;

	hkdf_expand(L_CHECKSUM_SHA256, eap->erp->r_rk, eap->erp->emsk_len,
			info, ptr - info, rmsk, eap->erp->emsk_len);

	eap_set_key_material(eap, rmsk, eap->erp->emsk_len, NULL, 0, NULL, 0,
				NULL, 0);

	eap->complete(EAP_RESULT_SUCCESS, eap->user_data);

	l_free(eap->erp);
	eap->erp = NULL;

	return;

eap_failed:
	l_free(eap->erp);
	eap->erp = NULL;

	erp_cache_remove_key(eap->identity, strlen(eap->identity));

	/*
	 * TODO: If ERP is enabled separately from FILS we could potentially
	 * recover here. The AP itself would have failed this connection, but
	 * rather than failing the DBus connection, we could go ahead and
	 * attempt a full EAP connection immediately, and e.g. return a new
	 * result code EAP_RESULT_ERP_FAILED which could be handled by any
	 * listeners.
	 */
	eap->complete(EAP_RESULT_FAIL, eap->user_data);
}

void __eap_handle_request(struct eap_state *eap, uint16_t id,
				const uint8_t *pkt, size_t len)
{
	enum eap_type type;
	uint8_t buf[10];
	int buf_len;
	bool retransmit;

	if (len < 1)
		/* Invalid packets to be ignored */
		return;

	type = pkt[0];
	if (type >= __EAP_TYPE_MIN_METHOD && !eap->method) {
		l_warn("EAP server tried method %i while client had no method "
			"configured", type);

		goto unsupported_method;
	}

	retransmit = id == eap->last_id ? true : false;
	eap->last_id = id;

	if (type >= __EAP_TYPE_MIN_METHOD) {
		void (*op)(struct eap_state *eap,
					const uint8_t *pkt, size_t len);

		if (type != eap->method->request_type) {
			l_warn("EAP server tried method %i while client was "
					"configured for method %i",
					type, eap->method->request_type);

			goto unsupported_method;
		}

		op = retransmit && eap->method->handle_retransmit ?
						eap->method->handle_retransmit :
						eap->method->handle_request;

		if (type != EAP_TYPE_EXPANDED) {
			op(eap, pkt + 1, len - 1);
			return;
		}

		/*
		 * TODO: Handle Expanded Nak if our vendor-id / vendor-types
		 * don't match
		 */
		if (len < 8)
			return;

		op(eap, pkt + 8, len - 8);
		return;
	}

	switch (type) {
	case EAP_TYPE_IDENTITY:
		if (len >= 2)
			l_debug("Optional EAP server identity prompt: \"%.*s\"",
					(int) len - 1, pkt + 1);

		if (eap->erp_allowed && erp_cache_has_key(eap->identity,
							strlen(eap->identity)))
			if (eap_send_initiate_reauth(eap))
				return;

		/* ERP failed for some reason, we can continue EAP */
		eap_send_identity_response(eap, eap->identity);

		return;

	case EAP_TYPE_NOTIFICATION:
		if (len < 2)
			/* Invalid packets to be ignored */
			return;

		l_warn("EAP notification: \"%.*s\"", (int) len - 1, pkt + 1);

		eap_send_response(eap, EAP_TYPE_NOTIFICATION, buf, 5);

		return;

	default:
	unsupported_method:
		if (!eap->method) {
			l_info("Received an unhandled EAP packet:");
			l_util_hexdump(true, pkt, len, dump_eap, "[EAP] ");
		}

		/* Send a legacy NAK response */
		buf_len = 5;

		/*
		 * RFC3748, Section 5.3.1: "A peer supporting Expanded Types
		 * that receives a Request for an unacceptable authentication
		 * Type (4-253,255) MAY include the value 254 in the Nak
		 * Response (Type 3) to indicate the desire for an Expanded
		 * authentication Type."
		 */
		buf[buf_len++] = eap->method ? eap->method->request_type : 0;

		eap_send_response(eap, EAP_TYPE_NAK, buf, buf_len);
		return;
	}
}

void eap_rx_packet(struct eap_state *eap, const uint8_t *pkt, size_t len)
{
	uint8_t code, id;
	uint16_t eap_len;

	if (len < 4 || l_get_be16(&pkt[2]) < 4 || len < l_get_be16(&pkt[2]))
		/* Invalid packets to be silently discarded */
		return;

	code = pkt[0];
	id = pkt[1];
	eap_len = l_get_be16(&pkt[2]);

	switch ((enum eap_code) code) {
	case EAP_CODE_REQUEST:
		__eap_handle_request(eap, id, pkt + 4, eap_len - 4);
		return;

	case EAP_CODE_FAILURE:
	case EAP_CODE_SUCCESS:
		if (eap->discard_success_and_failure)
			return;

		l_timeout_remove(eap->complete_timeout);
		eap->complete_timeout = NULL;

		/* RFC3748, Section 4.2
		 *
		 * The Identifier field of the Success and Failure packets
		 * MUST match the Identifier field of the Response packet that
		 * it is sent in response to. However, many currently deployed
		 * implementations ignore this rule and increment Identity for
		 * the Success and Failure packets. In order to support
		 * interoperability with these products we validate id against
		 * eap->last_id and its incremented value.
		 */
		if (id != eap->last_id && id != eap->last_id + 1)
			return;

		if (eap_len != 4)
			/* Invalid packets to be silently discarded */
			return;

		if (code == EAP_CODE_SUCCESS && !eap->method_success)
			/* "Canned" success packets to be discarded */
			return;

		if (code == EAP_CODE_FAILURE && eap->method_success)
			/*
			 * "On the peer, after success result indications have
			 * been exchanged by both sides, a Failure packet MUST
			 * be silently discarded."
			 *
			 * "Where the peer authenticates successfully to the
			 * authenticator, but the authenticator does not send
			 * a result indication, the authenticator MAY deny
			 * access by sending a Failure packet where the peer
			 * is not currently authorized for network access."
			 * -- eap->method_success implies we've received
			 * a full result indication.
			 */
			return;

		eap->complete(code == EAP_CODE_SUCCESS ? EAP_RESULT_SUCCESS :
				EAP_RESULT_FAIL, eap->user_data);
		return;
	case EAP_CODE_INITIATE:
		if (!eap->erp_allowed)
			return;

		eap_handle_initiate(eap, pkt + 4, eap_len - 4);
		break;
	case EAP_CODE_FINISH:
		if (!eap->erp_allowed)
			return;

		if (!eap->erp) {
			l_debug("EAP-Finish without ERP session");
			return;
		}

		eap_handle_finish(eap, pkt, len);

		break;

	default:
		/* Invalid packets to be silently discarded */
		return;
	}
}

bool eap_secret_info_match(const void *a, const void *b)
{
	const struct eap_secret_info *s = a;

	return !strcmp(s->id, b);
}

void eap_append_secret(struct l_queue **out_missing, enum eap_secret_type type,
			const char *id, const char *id2, const char *parameter,
			enum eap_secret_cache_policy cache_policy)
{
	struct eap_secret_info *info;

	if (!*out_missing)
		*out_missing = l_queue_new();

	info = l_new(struct eap_secret_info, 1);
	info->id = l_strdup(id);
	info->id2 = l_strdup(id2);
	info->type = type;
	info->parameter = l_strdup(parameter);
	info->cache_policy = cache_policy;
	l_queue_push_tail(*out_missing, info);
}

void eap_secret_info_free(void *data)
{
	struct eap_secret_info *info = data;

	if (!info)
		return;

	if (info->value) {
		size_t value_len = strlen(info->value) + 1;

		if (info->type == EAP_SECRET_REMOTE_USER_PASSWORD)
			value_len += strlen(info->value + value_len);

		explicit_bzero(info->value, value_len);
		l_free(info->value);
	}

	if (info->parameter) {
		explicit_bzero(info->parameter, strlen(info->parameter));
		l_free(info->parameter);
	}

	l_free(info->id);
	l_free(info->id2);
	l_free(info);
}

static struct eap_method *eap_find_method(struct l_settings *settings,
						const char *prefix)
{
	char setting[64];
	const char *method_name;
	const struct l_queue_entry *entry;
	struct eap_method *method = NULL;

	if (!settings)
		return false;

	snprintf(setting, sizeof(setting), "%sMethod", prefix);
	method_name = l_settings_get_value(settings, "Security", setting);

	if (!method_name)
		return false;

	for (entry = l_queue_get_entries(eap_methods); entry;
					entry = entry->next) {
		method = entry->data;

		if (!strcasecmp(method_name, method->name))
			break;
	}

	return method;
}

int __eap_check_settings(struct l_settings *settings, struct l_queue *secrets,
				const char *prefix, bool set_key_material,
				struct l_queue **missing)
{
	struct eap_method *method;
	int ret = 0;

	method = eap_find_method(settings, prefix);

	if (!method) {
		l_error("Property %sMethod missing", prefix);
		return -ENOENT;
	}

	/* Check if selected method is suitable for 802.1x */
	if (set_key_material && !method->exports_msk) {
		l_error("EAP method \"%s\" doesn't export key material",
				method->name);
		return -ENOTSUP;
	}

	if (method->check_settings) {
		ret = method->check_settings(settings, secrets,
						prefix, missing);

		if (ret < 0)
			return ret;
	}

	/*
	 * Individual methods are responsible for ensuring, inside their
	 * check_settings(), that they have enough data to return the
	 * identity after load_settings() if it is required.
	 */

	return 0;
}

int eap_check_settings(struct l_settings *settings, struct l_queue *secrets,
			const char *prefix, bool set_key_material,
			struct l_queue **out_missing)
{
	struct l_queue *missing = NULL;
	int ret = __eap_check_settings(settings, secrets, prefix,
					set_key_material, &missing);

	if (ret < 0) {
		l_queue_destroy(missing, eap_secret_info_free);
		return ret;
	}

	if (missing && l_queue_isempty(missing)) {
		l_queue_destroy(missing, NULL);
		missing = NULL;
	}

	*out_missing = missing;
	return 0;
}

bool eap_load_settings(struct eap_state *eap, struct l_settings *settings,
			const char *prefix)
{
	char setting[64];

	eap->method = eap_find_method(settings, prefix);

	if (!eap->method)
		return false;

	/* Check if selected method is suitable for 802.1x */
	if (eap->set_key_material && !eap->method->exports_msk)
		goto err;

	if (eap->method->load_settings)
		if (!eap->method->load_settings(eap, settings, prefix))
			goto err;

	/* get identity from settings or from EAP method */
	if (!eap->method->get_identity) {
		snprintf(setting, sizeof(setting), "%sIdentity", prefix);
		eap->identity = l_settings_get_string(settings,
							"Security", setting);
	} else {
		eap->identity = l_strdup(eap->method->get_identity(eap));
	}

	/*
	 * RFC 4282 Section 2.2 - NAI Length Considerations
	 *
	 * Devices handling NAIs MUST support an NAI length of at least 72
	 * octets. Support for an NAI length of 253 octets is RECOMMENDED.
	 * ...
	 * RADIUS is unable to support NAI lengths beyond 253 octets
	 */
	if (eap->identity && strlen(eap->identity) > 253) {
		l_error("Identity is too long");
		goto err;
	}

	snprintf(setting, sizeof(setting), "%sERP-Domain", prefix);
	eap->erp_domain = l_settings_get_string(settings, "Security", setting);

	/* No domain override, try parsing from identity */
	if (!eap->erp_domain)
		eap->erp_domain = l_strdup(util_get_domain(eap->identity));

	/*
	 * If we still dont have the ERP Domain, the only option left is to
	 * parse if from the EAP-Re-auth-Start packet (which may or may not
	 * be sent by the AP).
	 */

	return true;

err:
	eap_free_common(eap);

	return false;
}

void eap_set_data(struct eap_state *eap, void *data)
{
	eap->method_state = data;
}

void *eap_get_data(struct eap_state *eap)
{
	return eap->method_state;
}

enum eap_type eap_get_method_type(struct eap_state *eap)
{
	return eap->method->request_type;
}

const char *eap_get_method_name(struct eap_state *eap)
{
	return eap->method->name;
}

void eap_set_key_material(struct eap_state *eap,
				const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				const uint8_t *session_id, size_t session_len)
{
	if (!eap->set_key_material)
		return;

	/* Only cache if this is a full EAP auth, and all keys are provided */
	if (!eap->erp && emsk_data && session_id)
		erp_cache_add_key(eap->identity, strlen(eap->identity),
					session_id, session_len,
					emsk_data, emsk_len);

	eap->set_key_material(msk_data, msk_len, emsk_data, emsk_len,
				iv, iv_len, eap->user_data);
}

void eap_method_event(struct eap_state *eap, unsigned int id, const void *data)
{
	if (!eap->event_func)
		return;

	eap->event_func(id, data, eap->user_data);
}

bool eap_method_is_success(struct eap_state *eap)
{
	return eap->method_success;
}

void eap_method_success(struct eap_state *eap)
{
	eap->method_success = true;
}

void eap_discard_success_and_failure(struct eap_state *eap, bool discard)
{
	eap->discard_success_and_failure = discard;
}

void eap_method_error(struct eap_state *eap)
{
	/*
	 * It looks like neither EAP nor EAP-TLS specify the error handling
	 * behavior.
	 */
	eap->complete(EAP_RESULT_FAIL, eap->user_data);
}

void eap_save_last_id(struct eap_state *eap, uint8_t *last_id)
{
	*last_id = eap->last_id;
}

void eap_restore_last_id(struct eap_state *eap, uint8_t last_id)
{
	eap->last_id = last_id;
}

int eap_register_method(struct eap_method *method)
{
	if (!method->handle_request)
		return -EPERM;

	l_queue_push_head(eap_methods, method);
	return 0;
}

int eap_unregister_method(struct eap_method *method)
{
	bool r;

	r = l_queue_remove(eap_methods, method);
	if (r)
		return 0;

	return -ENOENT;
}

static void __eap_method_enable(struct eap_method_desc *start,
					struct eap_method_desc *stop)
{
	struct eap_method_desc *desc;

	l_debug("");

	if (start == NULL || stop == NULL)
		return;

	for (desc = start; desc < stop; desc++) {
		if (!desc->init)
			continue;

		desc->init();
	}
}

static void __eap_method_disable(struct eap_method_desc *start,
					struct eap_method_desc *stop)
{
	struct eap_method_desc *desc;

	l_debug("");

	if (start == NULL || stop == NULL)
		return;

	for (desc = start; desc < stop; desc++) {
		if (!desc->exit)
			continue;

		desc->exit();
	}
}

extern struct eap_method_desc __start___eap[];
extern struct eap_method_desc __stop___eap[];

void eap_init(uint32_t mtu)
{
	eap_methods = l_queue_new();
	__eap_method_enable(__start___eap, __stop___eap);

	/*
	 * RFC 3748, Section 3.1, [4], "Minimum MTU":
	 * EAP is capable of functioning on lower layers that
	 *        provide an EAP MTU size of 1020 octets or greater.
	 */
	if (mtu == 0)
		default_mtu = 1020;
	else
		default_mtu = mtu;

	erp_key_cache = l_queue_new();
}

void eap_exit(void)
{
	__eap_method_disable(__start___eap, __stop___eap);
	l_queue_destroy(eap_methods, NULL);
	l_queue_destroy(erp_key_cache, erp_destroy_entry);
}
