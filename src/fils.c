/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "ie.h"
#include "fils.h"
#include "eap.h"
#include "handshake.h"
#include "mpdu.h"
#include "crypto.h"
#include "util.h"
#include "missing.h"

#define FILS_NONCE_LEN		16
#define FILS_SESSION_LEN	8

struct fils_sm {
	struct eap_state *eap;
	struct handshake_state *hs;
	void *user_data;

	fils_tx_authenticate_func_t auth;
	fils_tx_associate_func_t assoc;
	fils_complete_func_t complete;

	uint8_t nonce[FILS_NONCE_LEN];
	uint8_t anonce[FILS_NONCE_LEN];
	uint8_t session[FILS_SESSION_LEN];

	uint8_t ick[48];
	size_t ick_len;
	uint8_t kek_and_tk[64 + 16];
	size_t kek_len;

	bool in_auth : 1;
};

static void fils_failed(struct fils_sm *fils)
{
	explicit_bzero(fils->ick, sizeof(fils->ick));
	explicit_bzero(fils->kek_and_tk, sizeof(fils->kek_and_tk));

	fils->complete(MMPDU_STATUS_CODE_UNSPECIFIED, fils->in_auth,
				fils->user_data);
}

static void fils_eap_tx_func(const uint8_t *eap_data, size_t len,
				void *user_data)
{
	struct fils_sm *fils = user_data;
	uint8_t data[256];
	uint8_t *ptr = data;

	l_getrandom(fils->nonce, 16);
	l_getrandom(fils->session, 8);

	/* transaction */
	l_put_le16(1, ptr);
	ptr += 2;
	/* status success */
	l_put_le16(0, ptr);
	ptr += 2;

	/* FILS Nonce */
	*ptr++ = IE_TYPE_EXTENSION;
	*ptr++ = 17;
	*ptr++ = IE_TYPE_FILS_NONCE - 256;
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);

	/* FILS Session */
	*ptr++ = IE_TYPE_EXTENSION;
	*ptr++ = 9;
	*ptr++ = IE_TYPE_FILS_SESSION - 256;
	memcpy(ptr, fils->session, sizeof(fils->session));
	ptr += sizeof(fils->session);

	*ptr++ = IE_TYPE_EXTENSION;
	*ptr++ = len + 1;
	*ptr++ = IE_TYPE_FILS_WRAPPED_DATA - 256;
	memcpy(ptr, eap_data, len);
	ptr += len;

	fils->auth(data, ptr - data, fils->user_data);
}

static void fils_eap_complete(enum eap_result result, void *user_data)
{
	struct fils_sm *fils = user_data;

	if (result == EAP_RESULT_SUCCESS)
		return;

	l_error("FILS ERP failed");

	fils_failed(fils);
}

static void fils_eap_key_materials(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				void *user_data)
{
	struct fils_sm *fils = user_data;
	uint8_t key[FILS_NONCE_LEN * 2];
	uint8_t pmk[48];
	uint8_t key_data[64 + 48 + 16]; /* largest ICK, KEK, TK */
	uint8_t key_auth[48];
	uint8_t data[44];
	uint8_t *ptr = data;
	struct iovec iov[3];
	uint8_t ies[64];
	size_t hash_len;
	bool sha384;

	/*
	 * IEEE 802.11ai - Section 12.12.2.5.3
	 */
	if (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FILS_SHA256) {
		sha384 = false;
		hash_len = 32;
		fils->kek_len = 32;
	} else {
		sha384 = true;
		hash_len = 48;
		fils->kek_len = 64;
	}

	/* key is SNonce || ANonce */
	memcpy(key, fils->nonce, sizeof(fils->nonce));
	memcpy(key + FILS_NONCE_LEN, fils->anonce, sizeof(fils->anonce));

	if (sha384)
		hmac_sha384(key, sizeof(key), msk_data, msk_len, pmk, hash_len);
	else
		hmac_sha256(key, sizeof(key), msk_data, msk_len, pmk, hash_len);

	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);

	if (sha384)
		kdf_sha384(pmk, hash_len, "FILS PTK Derivation",
				strlen("FILS PTK Derivation"), data,
				sizeof(data), key_data,
				hash_len + fils->kek_len + 16);
	else
		kdf_sha256(pmk, hash_len, "FILS PTK Derivation",
				strlen("FILS PTK Derivation"), data,
				sizeof(data), key_data,
				hash_len + fils->kek_len + 16);

	/* PMK is no longer needed */
	explicit_bzero(pmk, hash_len);

	ptr = data;

	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;

	memcpy(fils->ick, key_data, hash_len);
	fils->ick_len = hash_len;

	if (sha384)
		hmac_sha384(fils->ick, hash_len, data, ptr - data,
				key_auth, hash_len);
	else
		hmac_sha256(fils->ick, hash_len, data, ptr - data,
				key_auth, hash_len);

	ptr = ies;

	iov[0].iov_base = alloca(hash_len + 3);
	iov[0].iov_len = hash_len + 3;

	ptr = iov[0].iov_base;

	/* FILS Nonce */
	*ptr++ = IE_TYPE_EXTENSION;
	*ptr++ = hash_len + 1;
	*ptr++ = IE_TYPE_FILS_KEY_CONFIRMATION - 256;
	memcpy(ptr, key_auth, hash_len);
	ptr += hash_len;

	iov[1].iov_base = alloca(11);
	iov[1].iov_len = 11;

	ptr = iov[1].iov_base;

	/* FILS Session */
	*ptr++ = IE_TYPE_EXTENSION;
	*ptr++ = 9;
	*ptr++ = IE_TYPE_FILS_SESSION - 256;
	memcpy(ptr, fils->session, sizeof(fils->session));
	ptr += sizeof(fils->session);

	iov[2].iov_base = fils->hs->supplicant_ie;
	iov[2].iov_len = fils->hs->supplicant_ie[1] + 2;

	memcpy(data, fils->nonce, sizeof(fils->nonce));
	memcpy(data + sizeof(fils->nonce), fils->anonce, sizeof(fils->anonce));

	memcpy(fils->kek_and_tk, key_data + hash_len, fils->kek_len + 16);

	fils->assoc(iov, 3, fils->kek_and_tk, fils->kek_len, data,
			FILS_NONCE_LEN * 2, fils->user_data);

	fils->in_auth = false;
}

struct fils_sm *fils_sm_new(struct handshake_state *hs,
				fils_tx_authenticate_func_t auth,
				fils_tx_associate_func_t assoc,
				fils_complete_func_t complete, void *user_data)
{
	struct fils_sm *fils = l_new(struct fils_sm, 1);

	fils->auth = auth;
	fils->assoc = assoc;
	fils->complete = complete;
	fils->user_data = user_data;
	fils->hs = hs;
	fils->in_auth = true;

	fils->eap = eap_new(fils_eap_tx_func, fils_eap_complete, fils);

	eap_set_key_material_func(fils->eap, fils_eap_key_materials);

	eap_set_erp_allowed(fils->eap, true);

	if (!eap_load_settings(fils->eap, hs->settings_8021x, "EAP-")) {
		eap_free(fils->eap);
		l_free(fils);
		return NULL;
	}

	return fils;
}

void fils_sm_free(struct fils_sm *fils)
{
	eap_free(fils->eap);
	l_free(fils);
}

void fils_start(struct fils_sm *fils)
{
	if (!eap_send_initiate_reauth(fils->eap))
		fils->complete(MMPDU_STATUS_CODE_UNSPECIFIED, fils->in_auth,
				fils->user_data);
}

void fils_rx_authenticate(struct fils_sm *fils, const uint8_t *frame,
				size_t len)
{
	const struct mmpdu_header *hdr = mpdu_validate(frame, len);
	const struct mmpdu_authentication *auth;
	struct ie_tlv_iter iter;
	const uint8_t *anonce = NULL;
	const uint8_t *session = NULL;
	const uint8_t *wrapped = NULL;
	size_t wrapped_len = 0;

	if (!hdr) {
		l_debug("Auth frame header did not validate");
		return;
	}

	auth = mmpdu_body(hdr);

	if (!auth) {
		l_debug("Auth frame body did not validate");
		return;
	}

	if (auth->algorithm != MMPDU_AUTH_ALGO_FILS_SK &&
			auth->algorithm != MMPDU_AUTH_ALGO_FILS_SK_PFS) {
		l_debug("invalid auth algorithm %u", auth->algorithm);
		goto auth_failed;
	}

	if (auth->status != 0) {
		l_debug("invalid status %u", auth->status);
		goto auth_failed;
	}

	ie_tlv_iter_init(&iter, auth->ies, (const uint8_t *) hdr + len -
				auth->ies);
	while (ie_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case IE_TYPE_FILS_NONCE:
			if (iter.len != FILS_NONCE_LEN)
				goto auth_failed;

			anonce = iter.data;
			break;
		case IE_TYPE_FILS_SESSION:
			if (iter.len != FILS_SESSION_LEN)
				goto auth_failed;

			session = iter.data;
			break;
		case IE_TYPE_FILS_WRAPPED_DATA:
			wrapped = iter.data;
			wrapped_len = iter.len;
			break;
		default:
			continue;
		}
	}

	if (!anonce || !session || !wrapped) {
		l_debug("Auth did not include required IEs");
		goto auth_failed;
	}

	memcpy(fils->anonce, anonce, FILS_NONCE_LEN);

	eap_rx_packet(fils->eap, wrapped, wrapped_len);

	/* EAP should now call the key materials callback, giving us the rMSK */
	return;

auth_failed:
	fils_failed(fils);
}

void fils_rx_associate(struct fils_sm *fils, const uint8_t *frame, size_t len)
{
	const struct mmpdu_header *hdr = mpdu_validate(frame, len);
	const struct mmpdu_association_response *assoc;
	struct ie_tlv_iter iter;
	uint8_t key_rsc[8];
	const uint8_t *gtk = NULL;
	size_t gtk_len;
	uint8_t gtk_key_index;
	const uint8_t *igtk = NULL;
	size_t igtk_len;
	uint8_t igtk_key_index;
	const uint8_t *ap_key_auth = NULL;
	uint8_t expected_key_auth[48];
	bool sha384 = (fils->hs->akm_suite == IE_RSN_AKM_SUITE_FILS_SHA384);
	uint8_t data[44];
	uint8_t *ptr = data;

	if (!hdr) {
		l_debug("Assoc frame header did not validate");
		return;
	}

	assoc = mmpdu_body(hdr);

	if (!assoc) {
		l_debug("Assoc frame body did not validate");
		return;
	}

	ie_tlv_iter_init(&iter, assoc->ies, (const uint8_t *) hdr + len -
				assoc->ies);

	while (ie_tlv_iter_next(&iter)) {
		switch (iter.tag) {
		case IE_TYPE_KEY_DELIVERY:
			if (iter.len < 8)
				goto assoc_failed;

			memcpy(key_rsc, iter.data, 8);

			gtk = handshake_util_find_gtk_kde(iter.data + 8,
								iter.len - 8,
								&gtk_len);
			if (!gtk)
				goto assoc_failed;

			gtk_key_index = util_bit_field(gtk[0], 0, 2);
			gtk += 2;
			gtk_len -= 2;

			if (!fils->hs->mfp)
				break;

			igtk = handshake_util_find_igtk_kde(iter.data + 8,
								iter.len - 8,
								&igtk_len);
			if (!igtk)
				goto assoc_failed;

			igtk_key_index = l_get_le16(igtk);;
			igtk += 2;
			igtk_len -= 2;

			break;
		case IE_TYPE_FILS_KEY_CONFIRMATION:
			if (sha384 && iter.len != 48)
				goto assoc_failed;

			if (iter.len != 32)
				goto assoc_failed;

			ap_key_auth = iter.data;
		}
	}

	if (!ap_key_auth) {
		l_debug("Associate did not include KeyAuth IE");
		goto assoc_failed;
	}

	ptr = data;

	memcpy(ptr, fils->anonce, sizeof(fils->anonce));
	ptr += sizeof(fils->anonce);
	memcpy(ptr, fils->nonce, sizeof(fils->nonce));
	ptr += sizeof(fils->nonce);
	memcpy(ptr, fils->hs->aa, 6);
	ptr += 6;
	memcpy(ptr, fils->hs->spa, 6);
	ptr += 6;


	if (sha384)
		hmac_sha384(fils->ick, fils->ick_len, data, ptr - data,
				expected_key_auth, fils->ick_len);
	else
		hmac_sha256(fils->ick, fils->ick_len, data, ptr - data,
				expected_key_auth, fils->ick_len);

	if (memcmp(ap_key_auth, expected_key_auth, fils->ick_len)) {
		l_error("AP KeyAuth did not verify");
		goto assoc_failed;
	}

	if (gtk)
		handshake_state_install_gtk(fils->hs, gtk_key_index, gtk,
						gtk_len, key_rsc, 6);

	if (igtk)
		handshake_state_install_igtk(fils->hs, igtk_key_index,
						igtk + 6, igtk_len - 6, igtk);

	handshake_state_set_ptk(fils->hs, fils->kek_and_tk, fils->kek_len + 16);
	handshake_state_install_ptk(fils->hs);

	fils->complete(0, fils->in_auth, fils->user_data);

	return;

assoc_failed:
	fils_failed(fils);
}
