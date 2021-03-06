/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include <errno.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "linux/nl80211.h"

#include "src/iwd.h"
#include "src/scan.h"
#include "src/device.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/mpdu.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/ap.h"

struct ap_state {
	struct device *device;
	char *ssid;
	char *psk;
	ap_event_cb_t event_cb;
	int channel;
	unsigned int ciphers;
	uint32_t beacon_interval;
	struct l_uintset *rates;
	uint8_t pmk[32];
	struct l_queue *frame_watch_ids;
	uint32_t start_stop_cmd_id;
	uint32_t eapol_watch_id;
	uint32_t netdev_watch_id;

	uint16_t last_aid;
	struct l_queue *sta_states;
};

struct sta_state {
	uint8_t addr[6];
	bool associated;
	bool rsna;
	uint16_t aid;
	struct mmpdu_field_capability capability;
	uint16_t listen_interval;
	struct l_uintset *rates;
	uint32_t assoc_resp_cmd_id;
	struct ap_state *ap;
	uint8_t *assoc_rsne;
	size_t assoc_rsne_len;
	uint64_t key_replay_counter;
	uint8_t anonce[32];
	uint8_t snonce[32];
	uint8_t ptk[64];
	unsigned int frame_retry;
	struct l_timeout *frame_timeout;
	bool have_anonce : 1;
	bool ptk_complete : 1;
};

static struct l_genl_family *nl80211 = NULL;

static struct l_queue *ap_list = NULL;

static void ap_sta_free(void *data)
{
	struct sta_state *sta = data;

	l_uintset_free(sta->rates);
	l_free(sta->assoc_rsne);

	if (sta->assoc_resp_cmd_id)
		l_genl_family_cancel(nl80211, sta->assoc_resp_cmd_id);

	if (sta->frame_timeout)
		l_timeout_remove(sta->frame_timeout);

	l_free(sta);
}

static void ap_frame_watch_remove(void *data, void *user_data)
{
	struct netdev *netdev = user_data;

	if (L_PTR_TO_UINT(data))
		netdev_frame_watch_remove(netdev, L_PTR_TO_UINT(data));
}

static void ap_free(void *data)
{
	struct ap_state *ap = data;
	struct netdev *netdev = device_get_netdev(ap->device);

	l_free(ap->ssid);
	memset(ap->psk, 0, strlen(ap->psk));
	l_free(ap->psk);

	l_queue_foreach(ap->frame_watch_ids, ap_frame_watch_remove, netdev);
	l_queue_destroy(ap->frame_watch_ids, NULL);

	if (ap->start_stop_cmd_id)
		l_genl_family_cancel(nl80211, ap->start_stop_cmd_id);

	eapol_frame_watch_remove(ap->eapol_watch_id);

	netdev_watch_remove(netdev, ap->netdev_watch_id);

	l_queue_destroy(ap->sta_states, ap_sta_free);

	if (ap->rates)
		l_uintset_free(ap->rates);

	l_free(ap);
}

static bool ap_sta_match_addr(const void *a, const void *b)
{
	const struct sta_state *sta = a;

	return !memcmp(sta->addr, b, 6);
}

static void ap_set_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("SET_STATION failed: %i", l_genl_msg_get_error(msg));
}

static void ap_del_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("DEL_STATION failed: %i", l_genl_msg_get_error(msg));
}

static void ap_new_key_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("NEW_KEY failed: %i", l_genl_msg_get_error(msg));
}

static void ap_del_key_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_debug("DEL_KEY failed: %i", l_genl_msg_get_error(msg));
}

static void ap_new_rsna(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = device_get_ifindex(ap->device);
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHORIZED) |
			(1 << NL80211_STA_FLAG_MFP),
		.set = (1 << NL80211_STA_FLAG_AUTHORIZED),
	};
	uint8_t key_id = 0;
	const struct crypto_ptk *ptk = (struct crypto_ptk *) sta->ptk;
	uint32_t cipher = ie_rsn_cipher_suite_to_cipher(ap->ciphers);
	uint32_t key_type = NL80211_KEYTYPE_PAIRWISE;
	uint8_t tk_buf[32];

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2, 8, &flags);

	if (!l_genl_family_send(nl80211, msg, ap_set_sta_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing SET_STATION failed");
		return;
	}

	sta->rsna = true;

	switch (cipher) {
	case CRYPTO_CIPHER_CCMP:
		/*
		 * 802.11-2016 12.8.3 Mapping PTK to CCMP keys:
		 * "A STA shall use the temporal key as the CCMP key
		 * for MPDUs between the two communicating STAs."
		 */
		memcpy(tk_buf, ptk->tk, 16);
		break;
	case CRYPTO_CIPHER_TKIP:
		/*
		 * 802.11-2016 12.8.1 Mapping PTK to TKIP keys:
		 * "A STA shall use bits 0-127 of the temporal key as its
		 * input to the TKIP Phase 1 and Phase 2 mixing functions.
		 *
		 * A STA shall use bits 128-191 of the temporal key as
		 * the michael key for MSDUs from the Authenticator's STA
		 * to the Supplicant's STA.
		 *
		 * A STA shall use bits 192-255 of the temporal key as
		 * the michael key for MSDUs from the Supplicant's STA
		 * to the Authenticator's STA."
		 */
		memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_ENCR_KEY, ptk->tk, 16);
		memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_TX_MIC_KEY,
			ptk->tk + 16, 8);
		memcpy(tk_buf + NL80211_TKIP_DATA_OFFSET_RX_MIC_KEY,
			ptk->tk + 24, 8);
		break;
	default:
		l_error("Unexpected cipher: %x", cipher);
		return;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_NEW_KEY, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_DATA,
				crypto_cipher_key_len(cipher), tk_buf);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_TYPE, 4, &key_type);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_CIPHER, 4, &cipher);

	if (!l_genl_family_send(nl80211, msg, ap_new_key_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing NEW_KEY failed");
		return;
	}
}

static void ap_drop_rsna(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = device_get_ifindex(ap->device);
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHORIZED) |
			(1 << NL80211_STA_FLAG_MFP),
		.set = 0,
	};
	uint8_t key_id = 0;

	sta->rsna = false;

	if (sta->frame_timeout) {
		l_timeout_remove(sta->frame_timeout);
		sta->frame_timeout = NULL;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_SET_STATION, 128);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2, 8, &flags);

	if (!l_genl_family_send(nl80211, msg, ap_set_sta_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing SET_STATION failed");
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_KEY, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_KEY_IDX, 1, &key_id);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);

	if (!l_genl_family_send(nl80211, msg, ap_del_key_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing DEL_KEY failed");
	}
}

#define CIPHER_SUITE_GROUP_NOT_ALLOWED 0x000fac07

static void ap_set_rsn_info(struct ap_state *ap, struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = ap->ciphers;
	rsn->group_cipher = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
}

static void ap_error_deauth_sta(struct sta_state *sta,
				enum mmpdu_reason_code reason);

/* Default dot11RSNAConfigPairwiseUpdateCount value */
#define AP_PAIRWISE_UPDATE_COUNT 3

static void ap_set_eapol_key_timeout(struct sta_state *sta,
					l_timeout_notify_cb_t cb)
{
	/*
	 * 802.11-2016 12.7.6.6: "The retransmit timeout value shall be
	 * 100 ms for the first timeout, half the listen interval for the
	 * second timeout, and the listen interval for subsequent timeouts.
	 * If there is no listen interval or the listen interval is zero,
	 * then 100 ms shall be used for all timeout values."
	 */
	unsigned int timeout_ms = 100;
	unsigned int beacon_us = sta->ap->beacon_interval * 1024;

	sta->frame_retry++;

	if (sta->frame_retry == 2 && sta->listen_interval != 0)
		timeout_ms = sta->listen_interval * beacon_us / 2000;
	else if (sta->frame_retry > 2 && sta->listen_interval != 0)
		timeout_ms = sta->listen_interval * beacon_us / 1000;

	if (sta->frame_retry > 1)
		l_timeout_modify_ms(sta->frame_timeout, timeout_ms);
	else {
		if (sta->frame_timeout)
			l_timeout_remove(sta->frame_timeout);

		sta->frame_timeout = l_timeout_create_ms(timeout_ms, cb, sta,
								NULL);
	}
}

/* 802.11-2016 Section 12.7.6.2 */
static void ap_send_ptk_1_of_4(struct ap_state *ap, struct sta_state *sta)
{
	uint32_t ifindex = device_get_ifindex(ap->device);
	const uint8_t *aa = device_get_address(ap->device);
	uint8_t frame_buf[512];
	struct eapol_key *ek = (struct eapol_key *) frame_buf;
	enum crypto_cipher cipher = ie_rsn_cipher_suite_to_cipher(ap->ciphers);
	uint8_t pmkid[16];

	if (!l_getrandom(sta->anonce, 32)) {
		l_error("l_getrandom failed");
		return;
	}

	sta->have_anonce = true;
	sta->ptk_complete = false;

	sta->key_replay_counter++;

	memset(ek, 0, sizeof(struct eapol_key));
	ek->header.protocol_version = EAPOL_PROTOCOL_VERSION_2004;
	ek->header.packet_type = 0x3;
	ek->descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211;
	/* Must be HMAC-SHA1-128 + AES when using CCMP with PSK or 8021X */
	ek->key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES;
	ek->key_type = true;
	ek->key_ack = true;
	ek->key_length = L_CPU_TO_BE16(crypto_cipher_key_len(cipher));
	ek->key_replay_counter = L_CPU_TO_BE64(sta->key_replay_counter);
	memcpy(ek->key_nonce, sta->anonce, sizeof(ek->key_nonce));

	/* Write the PMKID KDE into Key Data field unencrypted */
	crypto_derive_pmkid(ap->pmk, sta->addr, aa, pmkid, false);
	eapol_key_data_append(ek, HANDSHAKE_KDE_PMKID, pmkid, 16);

	ek->header.packet_len = L_CPU_TO_BE16(sizeof(struct eapol_key) +
					L_BE16_TO_CPU(ek->key_data_len) - 4);

	eapol_tx_frame(ifindex, ETH_P_PAE, sta->addr,
			(struct eapol_frame *) ek);
}

static void ap_ptk_1_of_4_retry(struct l_timeout *timeout, void *user_data)
{
	struct sta_state *sta = user_data;

	if (sta->frame_retry >= AP_PAIRWISE_UPDATE_COUNT) {
		ap_error_deauth_sta(sta,
				MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
		return;
	}

	ap_send_ptk_1_of_4(sta->ap, sta);

	ap_set_eapol_key_timeout(sta, ap_ptk_1_of_4_retry);

	l_debug("attempt %i", sta->frame_retry);
}

/* 802.11-2016 Section 12.7.6.4 */
static void ap_send_ptk_3_of_4(struct ap_state *ap, struct sta_state *sta)
{
	uint32_t ifindex = device_get_ifindex(ap->device);
	uint8_t frame_buf[512];
	uint8_t key_data_buf[128];
	struct eapol_key *ek = (struct eapol_key *) frame_buf;
	size_t key_data_len;
	enum crypto_cipher cipher = ie_rsn_cipher_suite_to_cipher(ap->ciphers);
	const struct crypto_ptk *ptk = (struct crypto_ptk *) sta->ptk;
	struct ie_rsn_info rsn;

	sta->key_replay_counter++;

	memset(ek, 0, sizeof(struct eapol_key));
	ek->header.protocol_version = EAPOL_PROTOCOL_VERSION_2004;
	ek->header.packet_type = 0x3;
	ek->descriptor_type = EAPOL_DESCRIPTOR_TYPE_80211;
	/* Must be HMAC-SHA1-128 + AES when using CCMP with PSK or 8021X */
	ek->key_descriptor_version = EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES;
	ek->key_type = true;
	ek->install = true;
	ek->key_ack = true;
	ek->key_mic = true;
	ek->secure = true;
	ek->encrypted_key_data = true;
	ek->key_length = L_CPU_TO_BE16(crypto_cipher_key_len(cipher));
	ek->key_replay_counter = L_CPU_TO_BE64(sta->key_replay_counter);
	memcpy(ek->key_nonce, sta->anonce, sizeof(ek->key_nonce));
	/*
	 * We don't currently handle group traffic, to support that we'd need
	 * to provide the NL80211_ATTR_KEY_SEQ value from NL80211_CMD_GET_KEY
	 * here.
	 */
	l_put_be64(1, ek->key_rsc);

	/*
	 * Just one RSNE in Key Data as we only set one cipher in ap->ciphers
	 * currently.
	 */
	ap_set_rsn_info(ap, &rsn);
	if (!ie_build_rsne(&rsn, key_data_buf))
		return;

	if (!eapol_encrypt_key_data(ptk->kek, key_data_buf,
					2 + key_data_buf[1], ek))
		return;

	key_data_len = L_BE16_TO_CPU(ek->key_data_len);
	ek->header.packet_len = L_CPU_TO_BE16(sizeof(struct eapol_key) +
						key_data_len - 4);

	if (!eapol_calculate_mic(ptk->kck, ek, ek->key_mic_data))
		return;

	eapol_tx_frame(ifindex, ETH_P_PAE, sta->addr,
			(struct eapol_frame *) ek);
}

static void ap_ptk_3_of_4_retry(struct l_timeout *timeout, void *user_data)
{
	struct sta_state *sta = user_data;

	if (sta->frame_retry >= AP_PAIRWISE_UPDATE_COUNT) {
		ap_error_deauth_sta(sta,
				MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
		return;
	}

	ap_send_ptk_3_of_4(sta->ap, sta);

	ap_set_eapol_key_timeout(sta, ap_ptk_3_of_4_retry);

	l_debug("attempt %i", sta->frame_retry);
}

/* 802.11-2016 Section 12.7.6.3 */
static void ap_handle_ptk_2_of_4(struct sta_state *sta,
					const struct eapol_key *ek)
{
	const uint8_t *rsne;
	enum crypto_cipher cipher;
	size_t ptk_size;
	uint8_t ptk_buf[64];
	struct crypto_ptk *ptk = (struct crypto_ptk *) ptk_buf;
	const uint8_t *aa = device_get_address(sta->ap->device);

	l_debug("");

	if (!eapol_verify_ptk_2_of_4(ek))
		return;

	if (L_BE64_TO_CPU(ek->key_replay_counter) != sta->key_replay_counter)
		return;

	cipher = ie_rsn_cipher_suite_to_cipher(sta->ap->ciphers);
	ptk_size = sizeof(struct crypto_ptk) + crypto_cipher_key_len(cipher);

	if (!crypto_derive_pairwise_ptk(sta->ap->pmk, sta->addr, aa,
					sta->anonce, ek->key_nonce,
					ptk, ptk_size, false))
		return;

	if (!eapol_verify_mic(ptk->kck, ek))
		return;

	/* Bitwise identical RSNE required */
	rsne = eapol_find_rsne(ek->key_data,
				L_BE16_TO_CPU(ek->key_data_len), NULL);
	if (!rsne || rsne[1] != sta->assoc_rsne_len ||
			memcmp(rsne + 2, sta->assoc_rsne, rsne[1])) {
		ap_error_deauth_sta(sta, MMPDU_REASON_CODE_IE_DIFFERENT);
		return;
	}

	memcpy(sta->ptk, ptk_buf, ptk_size);
	memcpy(sta->snonce, ek->key_nonce, sizeof(sta->snonce));
	sta->ptk_complete = true;

	sta->frame_retry = 0;
	ap_ptk_3_of_4_retry(NULL, sta);
}

/* 802.11-2016 Section 12.7.6.5 */
static void ap_handle_ptk_4_of_4(struct sta_state *sta,
					const struct eapol_key *ek)
{
	const struct crypto_ptk *ptk = (struct crypto_ptk *) sta->ptk;

	l_debug("");

	if (!eapol_verify_ptk_4_of_4(ek, false))
		return;

	if (L_BE64_TO_CPU(ek->key_replay_counter) != sta->key_replay_counter)
		return;

	if (!eapol_verify_mic(ptk->kck, ek))
		return;

	l_timeout_remove(sta->frame_timeout);
	sta->frame_timeout = NULL;

	ap_new_rsna(sta->ap, sta);
}

static void ap_eapol_key_handle(struct sta_state *sta,
				const struct eapol_frame *frame)
{
	size_t frame_len = 4 + L_BE16_TO_CPU(frame->header.packet_len);
	const struct eapol_key *ek = eapol_key_validate((const void *) frame,
							frame_len);

	if (!ek)
		return;

	if (ek->request)
		return; /* Not supported */

	if (!sta->have_anonce)
		return; /* Not expecting an EAPoL-Key yet */

	if (!sta->ptk_complete)
		ap_handle_ptk_2_of_4(sta, ek);
	else if (!sta->rsna)
		ap_handle_ptk_4_of_4(sta, ek);
}

static void ap_eapol_rx(uint16_t proto, const uint8_t *from,
			const struct eapol_frame *frame, void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;

	l_debug("");

	if (proto != ETH_P_PAE) {
		l_error("AP data frame of unknown protocol %04x from %s",
			proto, util_address_to_string(from));
		return;
	}

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta || !sta->associated) {
		l_error("AP EAPoL from disassociated STA %s",
			util_address_to_string(from));
		return;
	}

	switch (frame->header.packet_type) {
	case 3: /* EAPoL-Key */
		ap_eapol_key_handle(sta, frame);
		break;
	default:
		l_error("AP received unknown packet type %i from %s",
			frame->header.packet_type,
			util_address_to_string(from));
		break;
	}
}

/*
 * Build a Beacon frame or a Probe Response frame's header and body until
 * the TIM IE.  Except for the optional TIM IE which is inserted by the
 * kernel when needed, our contents for both frames are the same.
 * See Beacon format in 8.3.3.2 and Probe Response format in 8.3.3.10.
 */
static size_t ap_build_beacon_pr_head(struct ap_state *ap,
					enum mpdu_management_subtype stype,
					const uint8_t *dest, uint8_t *out_buf)
{
	struct mmpdu_header *mpdu = (void *) out_buf;
	unsigned int len;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	const uint8_t *bssid = device_get_address(ap->device);
	uint32_t minr, maxr, count, r;
	uint8_t *rates;
	struct ie_tlv_builder builder;

	memset(mpdu, 0, 36); /* Zero out header + non-IE fields */

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = stype;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, bssid, 6);	/* SA */
	memcpy(mpdu->address_3, bssid, 6);	/* BSSID */

	/* Body non-IE fields */
	l_put_le16(ap->beacon_interval, out_buf + 32);	/* Beacon Interval */
	l_put_le16(capability, out_buf + 34);		/* Capability Info */

	ie_tlv_builder_init(&builder);
	builder.tlv = out_buf + 36;

	/* SSID IE */
	ie_tlv_builder_next(&builder, IE_TYPE_SSID);
	ie_tlv_builder_set_length(&builder, strlen(ap->ssid));
	memcpy(ie_tlv_builder_get_data(&builder), ap->ssid, strlen(ap->ssid));

	/* Supported Rates IE */
	ie_tlv_builder_next(&builder, IE_TYPE_SUPPORTED_RATES);
	rates = ie_tlv_builder_get_data(&builder);

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			*rates++ = r | flag;
		}

	ie_tlv_builder_set_length(&builder, rates -
					ie_tlv_builder_get_data(&builder));

	/* DSSS Parameter Set IE for DSSS, HR, ERP and HT PHY rates */
	ie_tlv_builder_next(&builder, IE_TYPE_DSSS_PARAMETER_SET);
	ie_tlv_builder_set_length(&builder, 1);
	((uint8_t *) ie_tlv_builder_get_data(&builder))[0] = ap->channel;

	ie_tlv_builder_finalize(&builder, &len);
	return 36 + len;
}

/* Beacon / Probe Response frame portion after the TIM IE */
static size_t ap_build_beacon_pr_tail(struct ap_state *ap, uint8_t *out_buf)
{
	size_t len;
	struct ie_rsn_info rsn;

	/* TODO: Country IE between TIM IE and RSNE */

	/* RSNE */
	ap_set_rsn_info(ap, &rsn);
	if (!ie_build_rsne(&rsn, out_buf))
		return 0;
	len = 2 + out_buf[1];

	return len;
}

static uint32_t ap_send_mgmt_frame(struct ap_state *ap,
					const struct mmpdu_header *frame,
					size_t frame_len, bool wait_ack,
					l_genl_msg_func_t callback,
					void *user_data)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = device_get_ifindex(ap->device);
	uint32_t id;
	uint32_t ch_freq = scan_channel_to_freq(ap->channel, SCAN_BAND_2_4_GHZ);

	msg = l_genl_msg_new_sized(NL80211_CMD_FRAME, 128 + frame_len);

	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_WIPHY_FREQ, 4, &ch_freq);
	l_genl_msg_append_attr(msg, NL80211_ATTR_FRAME, frame_len, frame);
	if (!wait_ack)
		l_genl_msg_append_attr(msg, NL80211_ATTR_DONT_WAIT_FOR_ACK,
					0, NULL);

	id = l_genl_family_send(nl80211, msg, callback, user_data, NULL);

	if (!id)
		l_genl_msg_unref(msg);

	return id;
}

static void ap_associate_sta_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("NEW_STATION/SET_STATION failed: %i",
			l_genl_msg_get_error(msg));
		return;
	}

	sta->frame_retry = 0;
	ap_ptk_1_of_4_retry(NULL, sta);
}

static void ap_associate_sta(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = device_get_ifindex(ap->device);
	/*
	 * This should hopefully work both with and without
	 * NL80211_FEATURE_FULL_AP_CLIENT_STATE.
	 */
	struct nl80211_sta_flag_update flags = {
		.mask = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED) |
			(1 << NL80211_STA_FLAG_AUTHORIZED) |
			(1 << NL80211_STA_FLAG_MFP),
		.set = (1 << NL80211_STA_FLAG_AUTHENTICATED) |
			(1 << NL80211_STA_FLAG_ASSOCIATED),
	};
	uint8_t rates[256];
	uint32_t r, minr, maxr, count = 0;
	uint16_t capability = l_get_le16(&sta->capability);
	uint8_t cmd = NL80211_CMD_NEW_STATION;

	if (sta->associated)
		cmd = NL80211_CMD_SET_STATION;

	sta->associated = true;
	sta->rsna = false;
	sta->key_replay_counter = 0;

	minr = l_uintset_find_min(sta->rates);
	maxr = l_uintset_find_max(sta->rates);

	for (r = minr; r <= maxr; r++)
		if (l_uintset_contains(sta->rates, r))
			rates[count++] = r;

	msg = l_genl_msg_new_sized(cmd, 300);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_FLAGS2, 8, &flags);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_SUPPORTED_RATES,
				count, &rates);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, 2,
				&sta->listen_interval);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_CAPABILITY, 2,
				&capability);

	if (!l_genl_family_send(nl80211, msg, ap_associate_sta_cb, sta, NULL)) {
		l_genl_msg_unref(msg);
		if (cmd == NL80211_CMD_NEW_STATION)
			l_error("Issuing NEW_STATION failed");
		else
			l_error("Issuing SET_STATION failed");
	}
}

static void ap_disassociate_sta(struct ap_state *ap, struct sta_state *sta)
{
	struct l_genl_msg *msg;
	uint32_t ifindex = device_get_ifindex(ap->device);

	sta->associated = false;
	sta->rsna = false;

	if (sta->frame_timeout) {
		l_timeout_remove(sta->frame_timeout);
		sta->frame_timeout = NULL;
	}

	msg = l_genl_msg_new_sized(NL80211_CMD_DEL_STATION, 64);
	l_genl_msg_append_attr(msg, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(msg, NL80211_ATTR_MAC, 6, sta->addr);
	l_genl_msg_append_attr(msg, NL80211_ATTR_STA_AID, 2, &sta->aid);

	if (!l_genl_family_send(nl80211, msg, ap_del_sta_cb, NULL, NULL)) {
		l_genl_msg_unref(msg);
		l_error("Issuing DEL_STATION failed");
	}
}

static void ap_error_deauth_sta(struct sta_state *sta,
				enum mmpdu_reason_code reason)
{
	struct ap_state *ap = sta->ap;
	const uint8_t *bssid = device_get_address(ap->device);
	uint8_t mpdu_buf[128];
	struct mmpdu_header *mpdu = (void *) mpdu_buf;
	struct mmpdu_deauthentication *deauth;

	memset(mpdu, 0, sizeof(*mpdu));
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION;
	memcpy(mpdu->address_1, sta->addr, 6);	/* DA */
	memcpy(mpdu->address_2, bssid, 6);	/* SA */
	memcpy(mpdu->address_3, bssid, 6);	/* BSSID */

	deauth = (void *) mmpdu_body(mpdu);
	deauth->reason_code = L_CPU_TO_LE16(reason);

	ap_send_mgmt_frame(ap, mpdu, deauth->ies - mpdu_buf, false, NULL, NULL);

	if (sta->associated)
		ap_disassociate_sta(ap, sta);

	l_queue_remove(ap->sta_states, sta);

	ap_sta_free(sta);
}

static bool ap_common_rates(struct l_uintset *ap_rates,
				struct l_uintset *sta_rates)
{
	uint32_t minr = l_uintset_find_min(ap_rates);

	/* Our lowest rate is a Basic Rate so must be supported */
	if (l_uintset_contains(sta_rates, minr))
		return true;

	return false;
}

static void ap_success_assoc_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	struct sta_state *sta = user_data;
	struct ap_state *ap = sta->ap;

	sta->assoc_resp_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("AP (Re)Association Response not sent or not ACKed: %i",
			l_genl_msg_get_error(msg));

		/* If we were in State 3 or 4 go to back to State 2 */
		if (sta->associated)
			ap_disassociate_sta(ap, sta);

		return;
	}

	/* If we were in State 2, 3 or 4 also go to State 3 */
	ap_associate_sta(ap, sta);

	l_info("AP (Re)Association Response ACK received");
}

static void ap_fail_assoc_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP (Re)Association Response with an error status not "
			"sent or not ACKed: %i", l_genl_msg_get_error(msg));
	else
		l_info("AP (Re)Association Response with an errror status "
			"delivered OK");
}

static uint32_t ap_assoc_resp(struct ap_state *ap, struct sta_state *sta,
				const uint8_t *dest, uint16_t aid,
				enum mmpdu_reason_code status_code,
				bool reassoc, l_genl_msg_func_t callback)
{
	const uint8_t *addr = device_get_address(ap->device);
	uint8_t mpdu_buf[128];
	struct mmpdu_header *mpdu = (void *) mpdu_buf;
	struct mmpdu_association_response *resp;
	size_t ies_len = 0;
	uint16_t capability = IE_BSS_CAP_ESS | IE_BSS_CAP_PRIVACY;
	uint32_t r, minr, maxr, count;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = reassoc ?
		MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE :
		MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Association Response body */
	resp = (void *) mmpdu_body(mpdu);
	l_put_le16(capability, &resp->capability);
	resp->status_code = L_CPU_TO_LE16(status_code);
	resp->aid = L_CPU_TO_LE16(aid | 0xc000);

	/* Supported Rates IE */
	resp->ies[ies_len++] = IE_TYPE_SUPPORTED_RATES;

	minr = l_uintset_find_min(ap->rates);
	maxr = l_uintset_find_max(ap->rates);
	count = 0;
	for (r = minr; r <= maxr && count < 8; r++)
		if (l_uintset_contains(ap->rates, r)) {
			uint8_t flag = 0;

			/* Mark only the lowest rate as Basic Rate */
			if (count == 0)
				flag = 0x80;

			resp->ies[ies_len + 1 + count++] = r | flag;
		}

	resp->ies[ies_len++] = count;
	ies_len += count;

	return ap_send_mgmt_frame(ap, mpdu, resp->ies + ies_len - mpdu_buf,
					true, callback, sta);
}

/*
 * This handles both the Association and Reassociation Request frames.
 * Association Request is documented in 802.11-2016 9.3.3.6 (frame format),
 * 802.11-2016 11.3.5.3 (MLME/SME) and Reassociation in 802.11-2016
 * 9.3.3.8 (frame format), 802.11-2016 11.3.5.3 (MLME/SME).
 *
 * The difference between Association and Reassociation procedures is
 * documented in 11.3.5.1 "General" but seems inconsistent with specific
 * instructions in 11.3.5.3 vs. 11.3.5.5 and 11.3.5.2 vs. 11.3.5.4.
 * According to 11.3.5.1:
 *  1. Reassociation requires the STA to be already associated in the ESS,
 *     Association doesn't.
 *  2. Unsuccessful Reassociation should not cause a state transition of
 *     the authentication state between the two STAs.
 *
 * The first requirement is not present in 11.3.5.5 which is virtually
 * identical with 11.3.5.3, but we do implement it.  Number 2 is also not
 * reflected in 11.3.5.5 where the state transitions are the same as in
 * 11.3.5.3 and 11.3.5.4 where the state transitions are the same as in
 * 11.3.5.2 including f) "If a Reassociation Response frame is received
 * with a status code other than SUCCESS [...] 1. [...] the state for
 * the AP [...] shall be set to State 2 [...]"
 *
 * For the record here are the apparent differences between 802.11-2016
 * 11.3.5.2 and 11.3.5.4 ignoring the s/Associate/Reassociate/ changes
 * and the special case of Reassociation during a Fast Transition.
 *  o Points c) and d) are switched around.
 *  o On success, the STA is disassociated from all other APs in 11.3.5.2,
 *    and from the previous AP in 11.3.5.4 c).  (Shouldn't make a
 *    difference as there seems to be no way for the STA to become
 *    associated with more than one AP)
 *  o After Association a 4-Way Handshake is always performed, after
 *    Reassociation it is only performed if STA was in State 3 according
 *    to 11.3.5.4 g).  This is not reflected in 11.3.5.5 though.
 *    Additionally 11.3.5.4 and 11.3.5.5 require the STA and AP
 *    respectively to delete current PTKSA/GTKSA/IGTKSA at the beginning
 *    of the procedure independent of the STA state so without a 4-Way
 *    Handshake the two stations end up with no encryption keys.
 *
 * The main difference between 11.3.5.3 and 11.3.5.5 is presence of p).
 */
static void ap_assoc_reassoc(struct sta_state *sta, bool reassoc,
				const struct mmpdu_field_capability *capability,
				uint16_t listen_interval,
				struct ie_tlv_iter *ies)
{
	struct ap_state *ap = sta->ap;
	const char *ssid = NULL;
	const uint8_t *rsn = NULL;
	size_t ssid_len = 0, rsn_len = 0;
	struct l_uintset *rates = NULL;
	struct ie_rsn_info rsn_info;
	int err;

	if (sta->assoc_resp_cmd_id)
		return;

	if (reassoc && !sta->associated) {
		err = MMPDU_REASON_CODE_CLASS3_FRAME_FROM_NONASSOC_STA;
		goto unsupported;
	}

	while (ie_tlv_iter_next(ies))
		switch (ie_tlv_iter_get_tag(ies)) {
		case IE_TYPE_SSID:
			ssid = (const char *) ie_tlv_iter_get_data(ies);
			ssid_len = ie_tlv_iter_get_length(ies);
			break;

		case IE_TYPE_SUPPORTED_RATES:
		case IE_TYPE_EXTENDED_SUPPORTED_RATES:
			if (ie_parse_supported_rates(ies, &rates) < 0) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			break;

		case IE_TYPE_RSN:
			if (ie_parse_rsne(ies, &rsn_info) < 0) {
				err = MMPDU_REASON_CODE_INVALID_IE;
				goto bad_frame;
			}

			rsn = (const uint8_t *) ie_tlv_iter_get_data(ies);
			rsn_len = ie_tlv_iter_get_length(ies);
			break;
		}

	if (!rates || !ssid || !rsn || ssid_len != strlen(ap->ssid) ||
			memcmp(ssid, ap->ssid, ssid_len)) {
		err = MMPDU_REASON_CODE_INVALID_IE;
		goto bad_frame;
	}

	if (!ap_common_rates(ap->rates, rates)) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto unsupported;
	}

	if (rsn_info.mfpr && rsn_info.spp_a_msdu_required) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto unsupported;
	}

	if (!(rsn_info.pairwise_ciphers & ap->ciphers)) {
		err = MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER;
		goto unsupported;
	}

	if (rsn_info.akm_suites != IE_RSN_AKM_SUITE_PSK) {
		err = MMPDU_REASON_CODE_INVALID_AKMP;
		goto unsupported;
	}

	if (!sta->associated) {
		/*
		 * Everything fine so far, assign an AID, send response.
		 * According to 802.11-2016 11.3.5.3 l) we will only go to
		 * State 3 (set sta->associated) once we receive the station's
		 * ACK or gave up on resends.
		 */
		sta->aid = ++ap->last_aid;
	}

	sta->capability = *capability;
	sta->listen_interval = listen_interval;

	if (sta->rates)
		l_uintset_free(sta->rates);

	sta->rates = rates;

	if (sta->assoc_rsne)
		l_free(sta->assoc_rsne);

	sta->assoc_rsne = l_memdup(rsn, rsn_len);
	sta->assoc_rsne_len = rsn_len;

	/* 802.11-2016 11.3.5.3 j) */
	if (sta->rsna)
		ap_drop_rsna(ap, sta);

	sta->assoc_resp_cmd_id = ap_assoc_resp(ap, sta, sta->addr, sta->aid, 0,
						reassoc,
						ap_success_assoc_resp_cb);
	if (!sta->assoc_resp_cmd_id)
		l_error("Sending success (Re)Association Response failed");

	return;

unsupported:
bad_frame:
	/*
	 * TODO: MFP
	 *
	 * 802.11-2016 11.3.5.3 m)
	 * "If the ResultCode in the MLME-ASSOCIATE.response primitive is
	 * not SUCCESS and management frame protection is in use the state
	 * for the STA shall be left unchanged.  If the ResultCode is not
	 * SUCCESS and management frame protection is not in use the state
	 * for the STA shall be set to State 3 if it was State 4."
	 *
	 * For now, we need to drop the RSNA.
	 */
	if (sta && sta->associated && sta->rsna)
		ap_drop_rsna(ap, sta);

	if (rates)
		l_uintset_free(rates);

	if (!ap_assoc_resp(ap, NULL, sta->addr, 0, err, reassoc,
				ap_fail_assoc_resp_cb))
		l_error("Sending error (Re)Association Response failed");
}

/* 802.11-2016 9.3.3.6 */
static void ap_assoc_req_cb(struct netdev *netdev,
				const struct mmpdu_header *hdr,
				const void *body, size_t body_len,
				void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const uint8_t *from = hdr->address_2;
	const struct mmpdu_association_request *req = body;
	const uint8_t *bssid = device_get_address(ap->device);
	struct ie_tlv_iter iter;

	l_info("AP Association Request from %s", util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta) {
		if (!ap_assoc_resp(ap, NULL, from, 0,
				MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH,
				false, ap_fail_assoc_resp_cb))
			l_error("Sending error Association Response failed");

		return;
	}

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));
	ap_assoc_reassoc(sta, false, &req->capability,
				L_LE16_TO_CPU(req->listen_interval), &iter);
}

/* 802.11-2016 9.3.3.8 */
static void ap_reassoc_req_cb(struct netdev *netdev,
				const struct mmpdu_header *hdr,
				const void *body, size_t body_len,
				void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const uint8_t *from = hdr->address_2;
	const struct mmpdu_reassociation_request *req = body;
	const uint8_t *bssid = device_get_address(ap->device);
	struct ie_tlv_iter iter;
	int err;

	l_info("AP Reassociation Request from %s",
		util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);
	if (!sta) {
		err = MMPDU_REASON_CODE_STA_REQ_ASSOC_WITHOUT_AUTH;
		goto bad_frame;
	}

	if (memcmp(req->current_ap_address, bssid, 6)) {
		err = MMPDU_REASON_CODE_UNSPECIFIED;
		goto bad_frame;
	}

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));
	ap_assoc_reassoc(sta, true, &req->capability,
				L_LE16_TO_CPU(req->listen_interval), &iter);
	return;

bad_frame:
	if (!ap_assoc_resp(ap, NULL, from, 0, err, true, ap_fail_assoc_resp_cb))
		l_error("Sending error Reassociation Response failed");
}

static void ap_probe_resp_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP Probe Response not sent: %i",
			l_genl_msg_get_error(msg));
	else
		l_info("AP Probe Response sent OK");
}

/*
 * Parse Probe Request according to 802.11-2016 9.3.3.10 and act according
 * to 802.11-2016 11.1.4.3
 */
static void ap_probe_req_cb(struct netdev *netdev,
				const struct mmpdu_header *hdr,
				const void *body, size_t body_len,
				void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_probe_request *req = body;
	const char *ssid = NULL;
	const uint8_t *ssid_list = NULL;
	size_t ssid_len = 0, ssid_list_len = 0, len;
	int dsss_channel = -1;
	struct ie_tlv_iter iter;
	const uint8_t *bssid = device_get_address(ap->device);
	bool match = false;
	uint8_t resp[512];

	l_info("AP Probe Request from %s",
		util_address_to_string(hdr->address_2));

	ie_tlv_iter_init(&iter, req->ies, body_len - sizeof(*req));

	while (ie_tlv_iter_next(&iter))
		switch (ie_tlv_iter_get_tag(&iter)) {
		case IE_TYPE_SSID:
			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_SSID_LIST:
			ssid_list = ie_tlv_iter_get_data(&iter);
			ssid_list_len = ie_tlv_iter_get_length(&iter);
			break;

		case IE_TYPE_DSSS_PARAMETER_SET:
			if (ie_tlv_iter_get_length(&iter) != 1)
				return;

			dsss_channel = ie_tlv_iter_get_data(&iter)[0];
			break;
		}

	/*
	 * Check if we should reply to this Probe Request according to
	 * 802.11-2016 section 11.1.4.3.2.
	 */

	if (memcmp(hdr->address_1, bssid, 6) &&
			!util_is_broadcast_address(hdr->address_1))
		match = false;

	if (memcmp(hdr->address_3, bssid, 6) &&
			!util_is_broadcast_address(hdr->address_3))
		match = false;

	if (!ssid || ssid_len == 0) /* Wildcard SSID */
		match = true;
	else if (ssid && ssid_len == strlen(ap->ssid) && /* Specific SSID */
			!memcmp(ssid, ap->ssid, ssid_len))
		match = true;
	else if (ssid_list) { /* SSID List */
		ie_tlv_iter_init(&iter, ssid_list, ssid_list_len);

		while (ie_tlv_iter_next(&iter)) {
			if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_SSID)
				return;

			ssid = (const char *) ie_tlv_iter_get_data(&iter);
			ssid_len = ie_tlv_iter_get_length(&iter);

			if (ssid_len == strlen(ap->ssid) &&
					!memcmp(ssid, ap->ssid, ssid_len)) {
				match = true;
				break;
			}
		}
	}

	if (dsss_channel != -1 && dsss_channel != ap->channel)
		match = false;

	if (!match)
		return;

	len = ap_build_beacon_pr_head(ap,
					MPDU_MANAGEMENT_SUBTYPE_PROBE_RESPONSE,
					hdr->address_2, resp);
	len += ap_build_beacon_pr_tail(ap, resp + len);

	ap_send_mgmt_frame(ap, (struct mmpdu_header *) resp, len, false,
				ap_probe_resp_cb, NULL);
}

/* 802.11-2016 9.3.3.5 (frame format), 802.11-2016 11.3.5.9 (MLME/SME) */
static void ap_disassoc_cb(struct netdev *netdev,
				const struct mmpdu_header *hdr,
				const void *body, size_t body_len,
				void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const struct mmpdu_disassociation *disassoc = body;
	const uint8_t *bssid = device_get_address(ap->device);

	l_info("AP Disassociation from %s, reason %i",
		util_address_to_string(hdr->address_2),
		(int) L_LE16_TO_CPU(disassoc->reason_code));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, hdr->address_2);

	if (sta && sta->assoc_resp_cmd_id) {
		l_genl_family_cancel(nl80211, sta->assoc_resp_cmd_id);
		sta->assoc_resp_cmd_id = 0;
	}

	if (!sta || !sta->associated)
		return;

	ap_disassociate_sta(ap, sta);
}

static void ap_auth_reply_cb(struct l_genl_msg *msg, void *user_data)
{
	if (l_genl_msg_get_error(msg) < 0)
		l_error("AP Authentication frame 2 not sent or not ACKed: %i",
			l_genl_msg_get_error(msg));
	else
		l_info("AP Authentication frame 2 ACKed by STA");
}

static void ap_auth_reply(struct ap_state *ap, const uint8_t *dest,
				enum mmpdu_reason_code status_code)
{
	const uint8_t *addr = device_get_address(ap->device);
	uint8_t mpdu_buf[64];
	struct mmpdu_header *mpdu = (struct mmpdu_header *) mpdu_buf;
	struct mmpdu_authentication *auth;

	memset(mpdu, 0, sizeof(*mpdu));

	/* Header */
	mpdu->fc.protocol_version = 0;
	mpdu->fc.type = MPDU_TYPE_MANAGEMENT;
	mpdu->fc.subtype = MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION;
	memcpy(mpdu->address_1, dest, 6);	/* DA */
	memcpy(mpdu->address_2, addr, 6);	/* SA */
	memcpy(mpdu->address_3, addr, 6);	/* BSSID */

	/* Authentication body */
	auth = (void *) mmpdu_body(mpdu);
	auth->algorithm = L_CPU_TO_LE16(MMPDU_AUTH_ALGO_OPEN_SYSTEM);
	auth->transaction_sequence = L_CPU_TO_LE16(2);
	auth->status = L_CPU_TO_LE16(status_code);

	ap_send_mgmt_frame(ap, mpdu, (uint8_t *) auth + 6 - mpdu_buf, true,
				ap_auth_reply_cb, NULL);
}

/*
 * 802.11-2016 9.3.3.12 (frame format), 802.11-2016 11.3.4.3 and
 * 802.11-2016 12.3.3.2 (MLME/SME)
 */
static void ap_auth_cb(struct netdev *netdev, const struct mmpdu_header *hdr,
			const void *body, size_t body_len, void *user_data)
{
	struct ap_state *ap = user_data;
	const struct mmpdu_authentication *auth = body;
	const uint8_t *from = hdr->address_2;
	const uint8_t *bssid = device_get_address(ap->device);
	struct sta_state *sta;

	l_info("AP Authentication from %s", util_address_to_string(from));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	/* Only Open System authentication implemented here */
	if (L_LE16_TO_CPU(auth->algorithm) !=
			MMPDU_AUTH_ALGO_OPEN_SYSTEM) {
		ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (L_LE16_TO_CPU(auth->transaction_sequence) != 1) {
		ap_auth_reply(ap, from, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	sta = l_queue_find(ap->sta_states, ap_sta_match_addr, from);

	/*
	 * Figure 11-13 in 802.11-2016 11.3.2 shows a transition from
	 * States 3 / 4 to State 2 on "Successful 802.11 Authentication"
	 * however 11.3.4.2 and 11.3.4.3 clearly say the connection goes to
	 * State 2 only if it was in State 1:
	 *
	 * "c) [...] the state for the indicated STA shall be set to State 2
	 * if it was State 1; the state shall remain unchanged if it was other
	 * than State 1."
	 */
	if (sta)
		goto done;

	/*
	 * Per 12.3.3.2.3 with Open System the state change is immediate,
	 * no waiting for the response to be ACKed as with the association
	 * frames.
	 */
	sta = l_new(struct sta_state, 1);
	memcpy(sta->addr, from, 6);
	sta->ap = ap;

	if (!ap->sta_states)
		ap->sta_states = l_queue_new();

	l_queue_push_tail(ap->sta_states, sta);

	/*
	 * Nothing to do here netlink-wise as we can't receive any data
	 * frames until after association anyway.  We do need to add a
	 * timeout for the authentication and possibly the kernel could
	 * handle that if we registered the STA with NEW_STATION now (TODO)
	 */

done:
	ap_auth_reply(ap, from, 0);
}

/* 802.11-2016 9.3.3.13 (frame format), 802.11-2016 11.3.4.5 (MLME/SME) */
static void ap_deauth_cb(struct netdev *netdev, const struct mmpdu_header *hdr,
				const void *body, size_t body_len,
				void *user_data)
{
	struct ap_state *ap = user_data;
	struct sta_state *sta;
	const struct mmpdu_deauthentication *deauth = body;
	const uint8_t *bssid = device_get_address(ap->device);

	l_info("AP Deauthentication from %s, reason %i",
		util_address_to_string(hdr->address_2),
		(int) L_LE16_TO_CPU(deauth->reason_code));

	if (memcmp(hdr->address_1, bssid, 6) ||
			memcmp(hdr->address_3, bssid, 6))
		return;

	sta = l_queue_remove_if(ap->sta_states, ap_sta_match_addr,
				hdr->address_2);
	if (!sta)
		return;

	if (sta->associated)
		ap_disassociate_sta(ap, sta);

	ap_sta_free(sta);
}

static void ap_stopped(struct ap_state *ap)
{
	ap->event_cb(ap->device, AP_EVENT_STOPPED);

	ap_free(ap);

	l_queue_remove(ap_list, ap);
}

static void ap_netdev_notify(struct netdev *netdev,
				enum netdev_watch_event event, void *user_data)
{
	struct ap_state *ap = user_data;

	switch (event) {
	case NETDEV_WATCH_EVENT_DOWN:
		ap_stopped(ap);
		break;
	default:
		break;
	}
}

static void ap_start_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0) {
		l_error("START_AP failed: %i", l_genl_msg_get_error(msg));

		ap_stopped(ap);
	} else {
		l_info("START_AP ok");

		ap->event_cb(ap->device, AP_EVENT_STARTED);
	}
}

static bool ap_match_device(const void *a, const void *b)
{
	const struct ap_state *ap = a;

	return ap->device == b;
}

static struct l_genl_msg *ap_build_cmd_start_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;

	uint8_t head[256], tail[256];
	size_t head_len, tail_len;

	uint32_t dtim_period = 3;
	uint32_t ifindex = device_get_ifindex(ap->device);
	uint32_t hidden_ssid = NL80211_HIDDEN_SSID_NOT_IN_USE;
	uint32_t nl_ciphers = ie_rsn_cipher_suite_to_cipher(ap->ciphers);
	uint32_t nl_akm = CRYPTO_AKM_PSK;
	uint32_t wpa_version = NL80211_WPA_VERSION_2;
	uint32_t auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
	uint32_t ch_freq = scan_channel_to_freq(ap->channel, SCAN_BAND_2_4_GHZ);
	uint32_t ch_width = NL80211_CHAN_WIDTH_20;

	static const uint8_t bcast_addr[6] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	head_len = ap_build_beacon_pr_head(ap, MPDU_MANAGEMENT_SUBTYPE_BEACON,
						bcast_addr, head);
	tail_len = ap_build_beacon_pr_tail(ap, tail);

	if (!head_len || !tail_len)
		return NULL;

	cmd = l_genl_msg_new_sized(NL80211_CMD_START_AP, 128 + head_len +
					tail_len + strlen(ap->ssid));

	/* SET_BEACON attrs */
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_HEAD, head_len, head);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_TAIL, tail_len, tail);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_PROBE_RESP, 0, "");
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IE_ASSOC_RESP, 0, "");

	/* START_AP attrs */
	l_genl_msg_append_attr(cmd, NL80211_ATTR_BEACON_INTERVAL, 4,
				&ap->beacon_interval);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_DTIM_PERIOD, 4, &dtim_period);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_SSID, strlen(ap->ssid),
				ap->ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_HIDDEN_SSID, 4,
				&hidden_ssid);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, 4,
				&nl_ciphers);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WPA_VERSIONS, 4, &wpa_version);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_AKM_SUITES, 4, &nl_akm);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_AUTH_TYPE, 4, &auth_type);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_WIPHY_FREQ, 4, &ch_freq);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_CHANNEL_WIDTH, 4, &ch_width);

	return cmd;
}

int ap_start(struct device *device, const char *ssid, const char *psk,
		ap_event_cb_t event_cb)
{
	struct netdev *netdev = device_get_netdev(device);
	struct wiphy *wiphy = device_get_wiphy(device);
	uint32_t ifindex = device_get_ifindex(device);
	struct ap_state *ap;
	struct l_genl_msg *cmd;
	const struct l_queue_entry *entry;
	uint32_t id;

	if (l_queue_find(ap_list, ap_match_device, device))
		return -EEXIST;

	ap = l_new(struct ap_state, 1);
	ap->device = device;
	ap->ssid = l_strdup(ssid);
	ap->psk = l_strdup(psk);
	ap->event_cb = event_cb;
	/* TODO: Start a Get Survey to decide the channel */
	ap->channel = 6;
	/* TODO: Add all ciphers supported by wiphy */
	ap->ciphers = wiphy_select_cipher(wiphy, 0xffff);
	ap->beacon_interval = 100;
	/* TODO: Use actual supported rates */
	ap->rates = l_uintset_new(200);
	l_uintset_put(ap->rates, 2); /* 1 Mbps*/
	l_uintset_put(ap->rates, 11); /* 5.5 Mbps*/
	l_uintset_put(ap->rates, 22); /* 11 Mbps*/

	if (crypto_psk_from_passphrase(psk, (uint8_t *) ssid, strlen(ssid),
					ap->pmk) < 0)
		goto error;

	ap->frame_watch_ids = l_queue_new();

	id = netdev_frame_watch_add(netdev, 0x0000 |
			(MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST << 4),
			NULL, 0, ap_assoc_req_cb, ap);
	l_queue_push_tail(ap->frame_watch_ids, L_UINT_TO_PTR(id));

	id = netdev_frame_watch_add(netdev, 0x0000 |
			(MPDU_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST << 4),
			NULL, 0, ap_reassoc_req_cb, ap);
	l_queue_push_tail(ap->frame_watch_ids, L_UINT_TO_PTR(id));

	id = netdev_frame_watch_add(netdev, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_PROBE_REQUEST << 4),
				NULL, 0, ap_probe_req_cb, ap);
	l_queue_push_tail(ap->frame_watch_ids, L_UINT_TO_PTR(id));

	id = netdev_frame_watch_add(netdev, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_DISASSOCIATION << 4),
				NULL, 0, ap_disassoc_cb, ap);
	l_queue_push_tail(ap->frame_watch_ids, L_UINT_TO_PTR(id));

	id = netdev_frame_watch_add(netdev, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION << 4),
				NULL, 0, ap_auth_cb, ap);
	l_queue_push_tail(ap->frame_watch_ids, L_UINT_TO_PTR(id));

	id = netdev_frame_watch_add(netdev, 0x0000 |
				(MPDU_MANAGEMENT_SUBTYPE_DEAUTHENTICATION << 4),
				NULL, 0, ap_deauth_cb, ap);
	l_queue_push_tail(ap->frame_watch_ids, L_UINT_TO_PTR(id));

	for (entry = l_queue_get_entries(ap->frame_watch_ids); entry;
			entry = entry->next)
		if (!L_PTR_TO_UINT(entry->data))
			goto error;

	cmd = ap_build_cmd_start_ap(ap);
	if (!cmd)
		goto error;

	ap->start_stop_cmd_id = l_genl_family_send(nl80211, cmd, ap_start_cb,
							ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		goto error;
	}

	ap->eapol_watch_id = eapol_frame_watch_add(ifindex, ap_eapol_rx, ap);

	ap->netdev_watch_id = netdev_watch_add(netdev, ap_netdev_notify, ap);

	if (!ap_list)
		ap_list = l_queue_new();

	l_queue_push_tail(ap_list, ap);

	return 0;

error:
	ap_free(ap);

	return -EIO;
}

static void ap_stop_cb(struct l_genl_msg *msg, void *user_data)
{
	struct ap_state *ap = user_data;

	ap->start_stop_cmd_id = 0;

	if (l_genl_msg_get_error(msg) < 0)
		l_error("STOP_AP failed: %i", l_genl_msg_get_error(msg));
	else
		l_info("STOP_AP ok");

	ap_stopped(ap);
}

static struct l_genl_msg *ap_build_cmd_stop_ap(struct ap_state *ap)
{
	struct l_genl_msg *cmd;
	uint32_t ifindex = device_get_ifindex(ap->device);

	cmd = l_genl_msg_new_sized(NL80211_CMD_STOP_AP, 16);
	l_genl_msg_append_attr(cmd, NL80211_ATTR_IFINDEX, 4, &ifindex);

	return cmd;
}

int ap_stop(struct device *device)
{
	struct l_genl_msg *cmd;
	struct ap_state *ap = l_queue_find(ap_list, ap_match_device, device);

	if (!ap)
		return -ENODEV;

	cmd = ap_build_cmd_stop_ap(ap);
	if (!cmd)
		return -ENOMEM;

	if (ap->start_stop_cmd_id)
		l_genl_family_cancel(nl80211, ap->start_stop_cmd_id);

	ap->start_stop_cmd_id = l_genl_family_send(nl80211, cmd, ap_stop_cb,
							ap, NULL);
	if (!ap->start_stop_cmd_id) {
		l_genl_msg_unref(cmd);
		return -EIO;
	}

	return 0;
}

void ap_init(struct l_genl_family *in)
{
	nl80211 = in;

	/*
	 * TODO: Check wiphy supports AP mode, supported channels,
	 * check wiphy's NL80211_ATTR_TX_FRAME_TYPES.
	 */
}

void ap_exit(void)
{
	l_queue_destroy(ap_list, ap_free);
}
