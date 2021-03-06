/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation. All rights reserved.
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <ell/ell.h>

#include "crypto.h"
#include "eapol.h"
#include "ie.h"
#include "util.h"
#include "mpdu.h"
#include "eap.h"
#include "handshake.h"
#include "watchlist.h"

struct l_queue *state_machines;
struct l_queue *preauths;
struct watchlist frame_watches;

eapol_deauthenticate_func_t deauthenticate = NULL;
eapol_rekey_offload_func_t rekey_offload = NULL;

static struct l_io *pae_io;
eapol_tx_packet_func_t tx_packet = NULL;
void *tx_user_data;

uint32_t next_frame_watch_id;

/*
 * BPF filter to match skb->dev->type == 1 (ARPHRD_ETHER) and
 * match skb->protocol == 0x888e (PAE) or 0x88c7 (preauthentication).
 */
static struct sock_filter pae_filter[] = {
	{ 0x28,  0,  0, 0xfffff01c },	/* ldh #hatype		*/
	{ 0x15,  0,  4, 0x00000001 },	/* jne #1, drop		*/
	{ 0x28,  0,  0, 0xfffff000 },	/* ldh #proto		*/
	{ 0x15,  1,  0, 0x0000888e },	/* je  #0x888e, keep	*/
	{ 0x15,  0,  1, 0x000088c7 },	/* jne #0x88c7, drop	*/
	{ 0x06,  0,  0, 0xffffffff },	/* keep: ret #-1	*/
	{ 0x06,  0,  0, 0000000000 },	/* drop: ret #0		*/
};

static const struct sock_fprog pae_fprog = { .len = 7, .filter = pae_filter };

static struct l_io *pae_open(void)
{
	struct l_io *io;
	int fd;

	fd = socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							htons(ETH_P_ALL));
	if (fd < 0)
		return NULL;

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					&pae_fprog, sizeof(pae_fprog)) < 0) {
		close(fd);
		return NULL;
	}

	io = l_io_new(fd);
	l_io_set_close_on_destroy(io, true);

	return io;
}

static bool pae_read(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	struct sockaddr_ll sll;
	socklen_t sll_len;
	ssize_t bytes;
	uint8_t frame[IEEE80211_MAX_DATA_LEN];

	memset(&sll, 0, sizeof(sll));
	sll_len = sizeof(sll);

	bytes = recvfrom(fd, frame, sizeof(frame), 0,
				(struct sockaddr *) &sll, &sll_len);
	if (bytes <= 0) {
		l_error("EAPoL read socket: %s", strerror(errno));
		return false;
	}

	if (sll.sll_halen != ETH_ALEN)
		return true;

	__eapol_rx_packet(sll.sll_ifindex, sll.sll_addr,
				ntohs(sll.sll_protocol), frame, bytes);

	return true;
}

static void pae_destroy()
{
	pae_io = NULL;
}

static void pae_write(uint32_t ifindex, const uint8_t *aa, const uint8_t *spa,
			uint16_t proto, const struct eapol_frame *ef)
{
	size_t frame_size;
	struct sockaddr_ll sll;
	ssize_t r;
	int fd;

	if (!pae_io) {
		if (tx_packet) /* Used for unit tests */
			tx_packet(ifindex, aa, spa, ef, tx_user_data);

		return;
	}

	fd = l_io_get_fd(pae_io);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons(proto);
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, aa, ETH_ALEN);

	frame_size = sizeof(struct eapol_header) +
			L_BE16_TO_CPU(ef->header.packet_len);

	r = sendto(fd, ef, frame_size, 0,
			(struct sockaddr *) &sll, sizeof(sll));
	if (r < 0)
		l_error("EAPoL write socket: %s", strerror(errno));
}

void eapol_pae_open()
{
	pae_io = pae_open();
	if (!pae_io)
		return;

	l_io_set_read_handler(pae_io, pae_read, NULL, pae_destroy);
}

void eapol_pae_close()
{
	l_io_destroy(pae_io);
}

#define VERIFY_IS_ZERO(field)						\
	do {								\
		if (!util_mem_is_zero((field), sizeof((field))))	\
			return false;					\
	} while (false)							\

/*
 * MIC calculation depends on the selected hash function.  The has function
 * is given in the EAPoL Key Descriptor Version field.
 *
 * The MIC length is always 16 bytes for currently known Key Descriptor
 * Versions.
 *
 * The input struct eapol_key *frame should have a zero-d MIC field
 */
bool eapol_calculate_mic(const uint8_t *kck, const struct eapol_key *frame,
				uint8_t *mic)
{
	size_t frame_len = sizeof(struct eapol_key);

	frame_len += L_BE16_TO_CPU(frame->key_data_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		return hmac_md5(kck, 16, frame, frame_len, mic, 16);
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		return hmac_sha1(kck, 16, frame, frame_len, mic, 16);
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		return cmac_aes(kck, 16, frame, frame_len, mic, 16);
	default:
		return false;
	}
}

bool eapol_verify_mic(const uint8_t *kck, const struct eapol_key *frame)
{
	size_t frame_len = sizeof(struct eapol_key);
	uint8_t mic[16];
	struct iovec iov[3];
	struct l_checksum *checksum = NULL;

	iov[0].iov_base = (void *) frame;
	iov[0].iov_len = offsetof(struct eapol_key, key_mic_data);

	memset(mic, 0, sizeof(mic));
	iov[1].iov_base = mic;
	iov[1].iov_len = sizeof(mic);

	iov[2].iov_base = ((void *) frame) +
				offsetof(struct eapol_key, key_data_len);
	iov[2].iov_len = frame_len - offsetof(struct eapol_key, key_data_len) +
				L_BE16_TO_CPU(frame->key_data_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		checksum = l_checksum_new_hmac(L_CHECKSUM_MD5, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
		checksum = l_checksum_new_hmac(L_CHECKSUM_SHA1, kck, 16);
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		checksum = l_checksum_new_cmac_aes(kck, 16);
		break;
	default:
		return false;
	}

	if (checksum == NULL)
		return false;

	l_checksum_updatev(checksum, iov, 3);
	l_checksum_get_digest(checksum, mic, 16);
	l_checksum_free(checksum);

	if (!memcmp(frame->key_mic_data, mic, 16))
		return true;

	return false;
}

uint8_t *eapol_decrypt_key_data(const uint8_t *kek,
				const struct eapol_key *frame,
				size_t *decrypted_size)
{
	size_t key_data_len = L_BE16_TO_CPU(frame->key_data_len);
	const uint8_t *key_data = frame->key_data;
	size_t expected_len;
	uint8_t *buf;

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		expected_len = key_data_len;
		break;
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		expected_len = key_data_len - 8;
		break;
	default:
		return NULL;
	};

	buf = l_new(uint8_t, expected_len);

	switch (frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	{
		uint8_t key[32];
		bool ret;

		memcpy(key, frame->eapol_key_iv, 16);
		memcpy(key + 16, kek, 16);

		ret = arc4_skip(key, 32, 256, key_data, key_data_len, buf);
		memset(key, 0, sizeof(key));

		if (!ret)
			goto error;

		break;
	}
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		if (key_data_len < 24 || key_data_len % 8)
			goto error;

		if (!aes_unwrap(kek, key_data, key_data_len, buf))
			goto error;

		break;
	}

	if (decrypted_size)
		*decrypted_size = expected_len;

	return buf;

error:
	l_free(buf);
	return NULL;
}

/*
 * Pad and encrypt the plaintext Key Data contents in @key_data using
 * the encryption scheme required by @out_frame->key_descriptor_version,
 * write results to @out_frame->key_data and @out_frame->key_data_len.
 *
 * Note that for efficiency @key_data is being modified, including in
 * case of failure, so it must be sufficiently larger than @key_data_len.
 */
bool eapol_encrypt_key_data(const uint8_t *kek, uint8_t *key_data,
				size_t key_data_len,
				struct eapol_key *out_frame)
{
	switch (out_frame->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
		/* Not supported */
		return false;

	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		if (key_data_len < 16 || key_data_len % 8)
			key_data[key_data_len++] = 0xdd;
		while (key_data_len < 16 || key_data_len % 8)
			key_data[key_data_len++] = 0x00;

		if (!aes_wrap(kek, key_data, key_data_len, out_frame->key_data))
			return false;

		key_data_len += 8;

		break;
	}

	out_frame->key_data_len = L_CPU_TO_BE16(key_data_len);

	return true;
}

void eapol_key_data_append(struct eapol_key *ek, enum handshake_kde selector,
				const uint8_t *data, size_t data_len)
{
	uint16_t key_data_len = L_BE16_TO_CPU(ek->key_data_len);

	ek->key_data[key_data_len++] = IE_TYPE_VENDOR_SPECIFIC;
	ek->key_data[key_data_len++] = 4 + data_len; /* OUI + Data type + len */
	l_put_be32(selector, ek->key_data + key_data_len);
	key_data_len += 4;

	memcpy(ek->key_data + key_data_len, data, data_len);
	key_data_len += data_len;

	ek->key_data_len = L_CPU_TO_BE16(key_data_len);
}

const struct eapol_key *eapol_key_validate(const uint8_t *frame, size_t len)
{
	const struct eapol_key *ek;
	uint16_t key_data_len;

	if (len < sizeof(struct eapol_key))
		return NULL;

	ek = (const struct eapol_key *) frame;

	switch (ek->header.protocol_version) {
	case EAPOL_PROTOCOL_VERSION_2001:
	case EAPOL_PROTOCOL_VERSION_2004:
		break;
	default:
		return NULL;
	}

	if (ek->header.packet_type != 3)
		return NULL;

	switch (ek->descriptor_type) {
	case EAPOL_DESCRIPTOR_TYPE_RC4:
	case EAPOL_DESCRIPTOR_TYPE_80211:
	case EAPOL_DESCRIPTOR_TYPE_WPA:
		break;
	default:
		return NULL;
	}

	switch (ek->key_descriptor_version) {
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_MD5_ARC4:
	case EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES:
	case EAPOL_KEY_DESCRIPTOR_VERSION_AES_128_CMAC_AES:
		break;
	default:
		return NULL;
	}

	key_data_len = L_BE16_TO_CPU(ek->key_data_len);
	if (len < sizeof(struct eapol_key) + key_data_len)
		return NULL;

	return ek;
}

#define VERIFY_PTK_COMMON(ek)	\
	if (!ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false	\

bool eapol_verify_ptk_1_of_4(const struct eapol_key *ek)
{
	/* Verify according to 802.11, Section 11.6.6.2 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);
	VERIFY_IS_ZERO(ek->key_mic_data);

	return true;
}

bool eapol_verify_ptk_2_of_4(const struct eapol_key *ek)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.3 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

bool eapol_verify_ptk_3_of_4(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.4 */
	VERIFY_PTK_COMMON(ek);

	/*
	 * TODO: Handle cases where install might be 0:
	 * For PTK generation, 0 only if the AP does not support key mapping
	 * keys, or if the STA has the No Pairwise bit (in the RSN Capabilities
	 * field) equal to 1 and only the group key is used.
	 */
	if (!ek->install)
		return false;

	if (!ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure != !is_wpa)
		return false;

	/* Must be encrypted when GTK is present but reserved in WPA */
	if (!ek->encrypted_key_data && !is_wpa)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 16 && key_len != 32)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	/* 0 (Version 2) or random (Version 1) */
	if (ek->key_descriptor_version ==
			EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES)
		L_WARN_ON(!util_mem_is_zero(ek->eapol_key_iv,
						sizeof(ek->eapol_key_iv)));

	return true;
}

bool eapol_verify_ptk_4_of_4(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.6.5 */
	VERIFY_PTK_COMMON(ek);

	if (ek->install)
		return false;

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (ek->secure != !is_wpa)
		return false;

	if (ek->encrypted_key_data)
		return false;

	if (ek->wpa_key_id)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

#define VERIFY_GTK_COMMON(ek)	\
	if (ek->key_type)	\
		return false;	\
	if (ek->smk_message)	\
		return false;	\
	if (ek->request)	\
		return false;	\
	if (ek->error)		\
		return false;	\
	if (ek->install)	\
		return false	\

bool eapol_verify_gtk_1_of_2(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	VERIFY_GTK_COMMON(ek);

	if (!ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	/* Must be encrypted when GTK is present but reserved in WPA */
	if (!ek->encrypted_key_data && !is_wpa)
		return false;

	/*
	 * In P802.11i/D3.0 the Key Length should be 16 for WPA but hostapd
	 * uses 16 for CCMP and 32 for TKIP.  Since 802.11i-2004 there's
	 * inconsistency in the required value, for example 0 is clearly
	 * specified in 802.11-2012 11.6.7.2 but 11.6.2 doesn't list 0 and
	 * makes the value depend on the pairwise key type.
	 */
	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0 && key_len != 16 && key_len != 32)
		return false;

	VERIFY_IS_ZERO(ek->reserved);

	/* 0 (Version 2) or random (Version 1) */
	if (ek->key_descriptor_version ==
			EAPOL_KEY_DESCRIPTOR_VERSION_HMAC_SHA1_AES)
		VERIFY_IS_ZERO(ek->eapol_key_iv);

	/*
	 * WPA_80211_v3_1, Section 2.2.4:
	 * "Key Index (bits 4 and 5): specifies the key id of the temporal
	 * key of the key derived from the message. The value of this shall be
	 * zero (0) if the value of Key Type (bit 4) is Pairwise (1). The Key
	 * Type and Key Index shall not both be 0 in the same message.
	 *
	 * Group keys shall not use key id 0. This means that key ids 1 to 3
	 * are available to be used to identify Group keys. This document
	 * recommends that implementations reserve key ids 1 and 2 for Group
	 * Keys, and that key id 3 is not used.
	 */
	if (is_wpa && !ek->wpa_key_id)
		return false;

	return true;
}

bool eapol_verify_gtk_2_of_2(const struct eapol_key *ek, bool is_wpa)
{
	uint16_t key_len;

	/* Verify according to 802.11, Section 11.6.7.3 */
	VERIFY_GTK_COMMON(ek);

	if (ek->key_ack)
		return false;

	if (!ek->key_mic)
		return false;

	if (!ek->secure)
		return false;

	if (ek->encrypted_key_data)
		return false;

	key_len = L_BE16_TO_CPU(ek->key_length);
	if (key_len != 0)
		return false;

	VERIFY_IS_ZERO(ek->key_nonce);
	VERIFY_IS_ZERO(ek->eapol_key_iv);
	VERIFY_IS_ZERO(ek->key_rsc);
	VERIFY_IS_ZERO(ek->reserved);

	return true;
}

static struct eapol_key *eapol_create_common(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				bool secure,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				int key_type,
				bool is_wpa)
{
	size_t to_alloc = sizeof(struct eapol_key);
	struct eapol_key *out_frame = l_malloc(to_alloc + extra_len);

	memset(out_frame, 0, to_alloc + extra_len);

	out_frame->header.protocol_version = protocol;
	out_frame->header.packet_type = 0x3;
	out_frame->header.packet_len = L_CPU_TO_BE16(to_alloc + extra_len - 4);
	out_frame->descriptor_type = is_wpa ? EAPOL_DESCRIPTOR_TYPE_WPA :
		EAPOL_DESCRIPTOR_TYPE_80211;
	out_frame->key_descriptor_version = version;
	out_frame->key_type = key_type;
	out_frame->install = false;
	out_frame->key_ack = false;
	out_frame->key_mic = true;
	out_frame->secure = secure;
	out_frame->error = false;
	out_frame->request = false;
	out_frame->encrypted_key_data = false;
	out_frame->smk_message = false;
	out_frame->key_length = 0;
	out_frame->key_replay_counter = L_CPU_TO_BE64(key_replay_counter);
	memcpy(out_frame->key_nonce, snonce, sizeof(out_frame->key_nonce));
	out_frame->key_data_len = L_CPU_TO_BE16(extra_len);
	memcpy(out_frame->key_data, extra_data, extra_len);

	return out_frame;
}

struct eapol_key *eapol_create_ptk_2_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				const uint8_t snonce[],
				size_t extra_len,
				const uint8_t *extra_data,
				bool is_wpa)
{
	return eapol_create_common(protocol, version, false, key_replay_counter,
					snonce, extra_len, extra_data, 1,
					is_wpa);
}

struct eapol_key *eapol_create_ptk_4_of_4(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa)
{
	uint8_t snonce[32];

	memset(snonce, 0, sizeof(snonce));
	return eapol_create_common(protocol, version,
					is_wpa ? false : true,
					key_replay_counter, snonce, 0, NULL,
					1, is_wpa);
}

struct eapol_key *eapol_create_gtk_2_of_2(
				enum eapol_protocol_version protocol,
				enum eapol_key_descriptor_version version,
				uint64_t key_replay_counter,
				bool is_wpa, uint8_t wpa_key_id)
{
	uint8_t snonce[32];
	struct eapol_key *step2;

	memset(snonce, 0, sizeof(snonce));
	step2 = eapol_create_common(protocol, version, true,
					key_replay_counter, snonce, 0, NULL,
					0, is_wpa);

	if (!step2)
		return step2;

	/*
	 * WPA_80211_v3_1, Section 2.2.4:
	 * "The Key Type and Key Index shall not both be 0 in the same message"
	 *
	 * The above means that even though sending the key index back to the
	 * AP has no practical value, we must still do so.
	 */
	if (is_wpa)
		step2->wpa_key_id = wpa_key_id;

	return step2;
}

struct eapol_sm {
	struct handshake_state *handshake;
	enum eapol_protocol_version protocol_version;
	uint64_t replay_counter;
	eapol_sm_event_func_t event_func;
	void *user_data;
	struct l_timeout *timeout;
	struct l_timeout *eapol_start_timeout;
	bool have_replay:1;
	bool started:1;
	bool use_eapol_start:1;
	bool require_handshake:1;
	bool eap_exchanged:1;
	struct eap_state *eap;
	struct eapol_frame *early_frame;
	uint32_t watch_id;
	uint8_t installed_gtk_len;
	uint8_t installed_gtk[CRYPTO_MAX_GTK_LEN];
	uint8_t installed_igtk_len;
	uint8_t installed_igtk[CRYPTO_MAX_IGTK_LEN];
};

static void eapol_sm_destroy(void *value)
{
	struct eapol_sm *sm = value;

	l_timeout_remove(sm->timeout);
	l_timeout_remove(sm->eapol_start_timeout);

	if (sm->eap)
		eap_free(sm->eap);

	l_free(sm->early_frame);

	eapol_frame_watch_remove(sm->watch_id);

	sm->installed_gtk_len = 0;
	memset(sm->installed_gtk, 0, sizeof(sm->installed_gtk));
	sm->installed_igtk_len = 0;
	memset(sm->installed_igtk, 0, sizeof(sm->installed_igtk));

	l_free(sm);

	l_queue_remove(state_machines, sm);
}

struct eapol_sm *eapol_sm_new(struct handshake_state *hs)
{
	struct eapol_sm *sm;

	sm = l_new(struct eapol_sm, 1);

	sm->handshake = hs;

	if (hs->settings_8021x)
		sm->use_eapol_start = true;

	sm->require_handshake = true;

	return sm;
}

void eapol_sm_free(struct eapol_sm *sm)
{
	eapol_sm_destroy(sm);
}

void eapol_sm_set_protocol_version(struct eapol_sm *sm,
				enum eapol_protocol_version protocol_version)
{
	sm->protocol_version = protocol_version;
}

void eapol_sm_set_user_data(struct eapol_sm *sm, void *user_data)
{
	sm->user_data = user_data;
}

void eapol_sm_set_event_func(struct eapol_sm *sm, eapol_sm_event_func_t func)
{
	sm->event_func = func;
}

static inline void handshake_failed(struct eapol_sm *sm, uint16_t reason_code)
{
	if (deauthenticate)
		deauthenticate(sm->handshake->ifindex,
				sm->handshake->aa, sm->handshake->spa,
				reason_code, sm->user_data);

	eapol_sm_free(sm);
}

static void eapol_timeout(struct l_timeout *timeout, void *user_data)
{
	struct eapol_sm *sm = user_data;

	l_timeout_remove(sm->timeout);
	sm->timeout = NULL;

	handshake_failed(sm, MMPDU_REASON_CODE_4WAY_HANDSHAKE_TIMEOUT);
}

static void eapol_write(struct eapol_sm *sm, const struct eapol_frame *ef)
{
	pae_write(sm->handshake->ifindex,
			sm->handshake->aa, sm->handshake->spa, ETH_P_PAE, ef);
}

static void eapol_install_gtk(struct eapol_sm *sm, uint8_t gtk_key_index,
					const uint8_t *gtk, size_t gtk_len,
					const uint8_t *rsc)
{
	/*
	 * Don't install the same GTK.  On older kernels this resets the
	 * replay counters, etc and can lead to various attacks
	 */
	if (sm->installed_gtk_len == gtk_len &&
			!memcmp(sm->installed_gtk, gtk, gtk_len))
		return;

	handshake_state_install_gtk(sm->handshake, gtk_key_index,
					gtk, gtk_len, rsc, 6);
	memcpy(sm->installed_gtk, gtk, gtk_len);
	sm->installed_gtk_len = gtk_len;
}

static void eapol_install_igtk(struct eapol_sm *sm, uint8_t igtk_key_index,
					const uint8_t *igtk, size_t igtk_len)
{
	/*
	 * Don't install the same IGTK.  On older kernels this resets the
	 * replay counters, etc and can lead to various attacks
	 */
	if (sm->installed_igtk_len == igtk_len - 6 &&
			!memcmp(sm->installed_igtk, igtk + 6, igtk_len - 6))
		return;

	handshake_state_install_igtk(sm->handshake, igtk_key_index,
						igtk + 6, igtk_len - 6, igtk);
	memcpy(sm->installed_igtk, igtk + 6, igtk_len - 6);
	sm->installed_igtk_len = igtk_len - 6;
}

static void send_eapol_start(struct l_timeout *timeout, void *user_data)
{
	struct eapol_sm *sm = user_data;
	uint8_t buf[sizeof(struct eapol_frame)];
	struct eapol_frame *frame = (struct eapol_frame *) buf;

	l_timeout_remove(sm->eapol_start_timeout);
	sm->eapol_start_timeout = NULL;

	if (!sm->protocol_version)
		sm->protocol_version = EAPOL_PROTOCOL_VERSION_2001;

	frame->header.protocol_version = sm->protocol_version;
	frame->header.packet_type = 1;
	l_put_be16(0, &frame->header.packet_len);

	eapol_write(sm, frame);
}

static void eapol_handle_ptk_1_of_4(struct eapol_sm *sm,
					const struct eapol_key *ek)
{
	const struct crypto_ptk *ptk;
	struct eapol_key *step2;
	uint8_t mic[16];
	uint8_t *ies;
	size_t ies_len;
	const uint8_t *own_ie = sm->handshake->own_ie;
	const uint8_t *pmkid;
	struct ie_rsn_info rsn_info;

	if (!eapol_verify_ptk_1_of_4(ek))
		goto error_unspecified;

	pmkid = handshake_util_find_pmkid_kde(ek->key_data,
					L_BE16_TO_CPU(ek->key_data_len));

	/*
	 * Require the PMKID KDE whenever we've sent a list of PMKIDs in
	 * our RSNE and we've haven't seen any EAPOL-EAP frame since
	 * (sm->eap_exchanged is false), otherwise treat it as optional and
	 * only validate it against our PMK.  Some 802.11-2012 sections
	 * show message 1/4 without a PMKID KDE and there are APs that
	 * send no PMKID KDE.
	 */
	if (!sm->eap_exchanged && !sm->handshake->wpa_ie &&
			ie_parse_rsne_from_data(own_ie, own_ie[1] + 2,
						&rsn_info) >= 0 &&
			rsn_info.num_pmkids) {
		bool found = false;
		int i;

		if (!pmkid)
			goto error_unspecified;

		for (i = 0; i < rsn_info.num_pmkids; i++)
			if (!memcmp(rsn_info.pmkids + i * 16, pmkid, 16)) {
				found = true;
				break;
			}

		if (!found)
			goto error_unspecified;
	} else if (pmkid) {
		uint8_t own_pmkid[16];

		if (handshake_state_get_pmkid(sm->handshake, own_pmkid) &&
				memcmp(pmkid, own_pmkid, 16)) {
			/*
			 * If the AP has a different PMKSA from ours and we
			 * have means to create a new PMKSA through EAP then
			 * try that, otherwise give up.
			 */
			if (sm->eap) {
				send_eapol_start(NULL, sm);
				return;
			} else
				goto error_unspecified;
		}
	}

	/*
	 * If we're in a state where we have successfully processed Message 3,
	 * then assume that the new message 1 is a PTK rekey and start a new
	 * handshake
	 */
	if (!sm->handshake->have_snonce ||
			memcmp(sm->handshake->anonce,
					ek->key_nonce, sizeof(ek->key_nonce)) ||
			sm->handshake->ptk_complete) {
		handshake_state_new_snonce(sm->handshake);
		handshake_state_set_anonce(sm->handshake, ek->key_nonce);

		if (!handshake_state_derive_ptk(sm->handshake))
			goto error_unspecified;
	}

	if (sm->handshake->akm_suite &
			(IE_RSN_AKM_SUITE_FT_OVER_8021X |
			 IE_RSN_AKM_SUITE_FT_USING_PSK |
			 IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256)) {
		const uint8_t *mde = sm->handshake->mde;
		const uint8_t *fte = sm->handshake->fte;

		/*
		 * Rebuild the RSNE to include the PMKR1Name and append
		 * MDE + FTE.
		 */
		ies = alloca(512);

		rsn_info.num_pmkids = 1;
		rsn_info.pmkids = sm->handshake->pmk_r1_name;

		ie_build_rsne(&rsn_info, ies);
		ies_len = ies[1] + 2;

		memcpy(ies + ies_len, mde, mde[1] + 2);
		ies_len += mde[1] + 2;

		memcpy(ies + ies_len, fte, fte[1] + 2);
		ies_len += fte[1] + 2;
	} else {
		ies_len = own_ie[1] + 2;
		ies = (uint8_t *) own_ie;
	}

	step2 = eapol_create_ptk_2_of_4(sm->protocol_version,
					ek->key_descriptor_version,
					L_BE64_TO_CPU(ek->key_replay_counter),
					sm->handshake->snonce, ies_len, ies,
					sm->handshake->wpa_ie);

	ptk = handshake_state_get_ptk(sm->handshake);

	if (!eapol_calculate_mic(ptk->kck, step2, mic)) {
		l_info("MIC calculation failed. "
			"Ensure Kernel Crypto is available.");
		l_free(step2);
		handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);

		return;
	}

	memcpy(step2->key_mic_data, mic, sizeof(mic));
	eapol_write(sm, (struct eapol_frame *) step2);
	l_free(step2);

	l_timeout_remove(sm->timeout);
	sm->timeout = NULL;

	return;

error_unspecified:
	handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
}

const uint8_t *eapol_find_rsne(const uint8_t *data, size_t data_len,
				const uint8_t **optional)
{
	struct ie_tlv_iter iter;
	const uint8_t *first = NULL;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_RSN)
			continue;

		if (!first) {
			first = ie_tlv_iter_get_data(&iter) - 2;
			continue;
		}

		if (optional)
			*optional = ie_tlv_iter_get_data(&iter) - 2;

		return first;
	}

	return first;
}

static const uint8_t *eapol_find_wpa_ie(const uint8_t *data, size_t data_len)
{
	struct ie_tlv_iter iter;

	ie_tlv_iter_init(&iter, data, data_len);

	while (ie_tlv_iter_next(&iter)) {
		if (ie_tlv_iter_get_tag(&iter) != IE_TYPE_VENDOR_SPECIFIC)
			continue;

		if (is_ie_wpa_ie(ie_tlv_iter_get_data(&iter),
				ie_tlv_iter_get_length(&iter)))
			return ie_tlv_iter_get_data(&iter) - 2;
	}

	return NULL;
}

static void eapol_handle_ptk_3_of_4(struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size)
{
	const struct crypto_ptk *ptk;
	struct eapol_key *step4;
	uint8_t mic[16];
	const uint8_t *gtk = NULL;
	size_t gtk_len;
	const uint8_t *igtk = NULL;
	size_t igtk_len;
	const uint8_t *rsne;
	const uint8_t *optional_rsne = NULL;
	uint8_t gtk_key_index;
	uint8_t igtk_key_index;

	if (!eapol_verify_ptk_3_of_4(ek, sm->handshake->wpa_ie)) {
		handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	/*
	 * 802.11-2016, Section 12.7.6.4:
	 * "On reception of message 3, the Supplicant silently discards the
	 * message if the Key Replay Counter field value has already been used
	 * or if the ANonce value in message 3 differs from the ANonce value
	 * in message 1."
	 */
	if (memcmp(sm->handshake->anonce, ek->key_nonce, sizeof(ek->key_nonce)))
		return;

	/*
	 * 11.6.6.4: "Verifies the RSNE. If it is part of a Fast BSS Transition
	 * Initial Mobility Domain Association, see 12.4.2. Otherwise, if it is
	 * not identical to that the STA received in the Beacon or Probe
	 * Response frame, the STA shall disassociate.
	 */
	if (!sm->handshake->wpa_ie)
		rsne = eapol_find_rsne(decrypted_key_data,
					decrypted_key_data_size,
					&optional_rsne);
	else
		rsne = eapol_find_wpa_ie(decrypted_key_data,
					decrypted_key_data_size);

	if (!rsne)
		goto error_ie_different;

	if (!handshake_util_ap_ie_matches(rsne, sm->handshake->ap_ie,
						sm->handshake->wpa_ie))
		goto error_ie_different;

	if (sm->handshake->akm_suite &
			(IE_RSN_AKM_SUITE_FT_OVER_8021X |
			 IE_RSN_AKM_SUITE_FT_USING_PSK |
			 IE_RSN_AKM_SUITE_FT_OVER_SAE_SHA256)) {
		struct ie_tlv_iter iter;
		struct ie_rsn_info ie_info;
		const uint8_t *mde = sm->handshake->mde;
		const uint8_t *fte = sm->handshake->fte;

		ie_parse_rsne_from_data(rsne, rsne[1] + 2, &ie_info);

		if (ie_info.num_pmkids != 1 || memcmp(ie_info.pmkids,
						sm->handshake->pmk_r1_name, 16))
			goto error_ie_different;

		ie_tlv_iter_init(&iter, decrypted_key_data,
					decrypted_key_data_size);

		while (ie_tlv_iter_next(&iter))
			switch (ie_tlv_iter_get_tag(&iter)) {
			case IE_TYPE_MOBILITY_DOMAIN:
				if (memcmp(ie_tlv_iter_get_data(&iter) - 2,
						mde, mde[1] + 2))
					goto error_ie_different;

				break;

			case IE_TYPE_FAST_BSS_TRANSITION:
				if (memcmp(ie_tlv_iter_get_data(&iter) - 2,
						fte, fte[1] + 2))
					goto error_ie_different;

				break;
			}
	}

	/*
	 * If ptk_complete is set, then we are receiving Message 3 again.
	 * It must be a retransmission, otherwise the anonce wouldn't match
	 * and we wouldn't get here.  Skip processing the rest of the message
	 * and send our reply.  Do not install the keys again.
	 */
	if (sm->handshake->ptk_complete)
		goto retransmit;

	/*
	 * 11.6.6.4: "If a second RSNE is provided in the message, the
	 * Supplicant uses the pairwise cipher suite specified in the second
	 * RSNE or deauthenticates."
	 */
	if (optional_rsne) {
		struct ie_rsn_info info1;
		struct ie_rsn_info info2;
		uint16_t override;

		if (ie_parse_rsne_from_data(rsne, rsne[1] + 2, &info1) < 0)
			goto error_ie_different;

		if (ie_parse_rsne_from_data(optional_rsne, optional_rsne[1] + 2,
						&info2) < 0)
			goto error_ie_different;

		/*
		 * 11.6.2:
		 * It may happen, for example, that a Supplicant selects a
		 * pairwise cipher suite which is advertised by an AP, but
		 * which policy disallows for this particular STA. An
		 * Authenticator may, therefore, insert a second RSNE to
		 * overrule the STA’s selection. An Authenticator’s SME shall
		 * insert the second RSNE, after the first RSNE, only for this
		 * purpose. The pairwise cipher suite in the second RSNE
		 * included shall be one of the ciphers advertised by the
		 * Authenticator. All other fields in the second RSNE shall be
		 * identical to the first RSNE.
		 *
		 * - Check that akm_suites and group_cipher are the same
		 *   between rsne1 and rsne2
		 * - Check that pairwise_ciphers is not the same between rsne1
		 *   and rsne2
		 * - Check that rsne2 pairwise_ciphers is a subset of rsne
		 */
		if (info1.akm_suites != info2.akm_suites ||
				info1.group_cipher != info2.group_cipher)
			goto error_ie_different;

		override = info2.pairwise_ciphers;

		if (override == info1.pairwise_ciphers ||
				!(info1.pairwise_ciphers & override) ||
				__builtin_popcount(override) != 1) {
			handshake_failed(sm,
				MMPDU_REASON_CODE_INVALID_PAIRWISE_CIPHER);
			return;
		}

		handshake_state_override_pairwise_cipher(sm->handshake,
								override);
	}

	if (!sm->handshake->wpa_ie && sm->handshake->group_cipher !=
			IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC) {
		gtk = handshake_util_find_gtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&gtk_len);
		if (!gtk) {
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		/* TODO: Handle tx bit */

		gtk_key_index = util_bit_field(gtk[0], 0, 2);
		gtk += 2;
		gtk_len -= 2;
	} else
		gtk = NULL;

	if (sm->handshake->mfp) {
		igtk = handshake_util_find_igtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&igtk_len);
		if (!igtk) {
			handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
			return;
		}

		igtk_key_index = l_get_le16(igtk);;
		igtk += 2;
		igtk_len -= 2;
	} else
		igtk = NULL;

retransmit:
	/*
	 * 802.11-2016, Section 12.7.6.4:
	 * "b) Verifies the message 3 MIC. If the calculated MIC does not match
	 * the MIC that the Authenticator included in the EAPOL-Key frame, the
	 * Supplicant silently discards message 3."
	 * "c) Updates the last-seen value of the Key Replay Counter field."
	 *
	 * Note that part b was done in eapol_key_handle
	 */
	sm->replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);
	sm->have_replay = true;

	step4 = eapol_create_ptk_4_of_4(sm->protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter,
					sm->handshake->wpa_ie);

	ptk = handshake_state_get_ptk(sm->handshake);

	if (!eapol_calculate_mic(ptk->kck, step4, mic)) {
		l_free(step4);
		handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	memcpy(step4->key_mic_data, mic, sizeof(mic));
	eapol_write(sm, (struct eapol_frame *) step4);
	l_free(step4);

	if (sm->handshake->ptk_complete)
		return;

	handshake_state_install_ptk(sm->handshake);

	if (gtk)
		eapol_install_gtk(sm, gtk_key_index, gtk, gtk_len, ek->key_rsc);

	if (igtk)
		eapol_install_igtk(sm, igtk_key_index, igtk, igtk_len);

	if (rekey_offload)
		rekey_offload(sm->handshake->ifindex, ptk->kek, ptk->kck,
				sm->replay_counter, sm->user_data);

	return;

error_ie_different:
	handshake_failed(sm, MMPDU_REASON_CODE_IE_DIFFERENT);
}

static void eapol_handle_gtk_1_of_2(struct eapol_sm *sm,
					const struct eapol_key *ek,
					const uint8_t *decrypted_key_data,
					size_t decrypted_key_data_size)
{
	const struct crypto_ptk *ptk;
	struct eapol_key *step2;
	uint8_t mic[16];
	const uint8_t *gtk;
	size_t gtk_len;
	uint8_t gtk_key_index;
	const uint8_t *igtk;
	size_t igtk_len;
	uint8_t igtk_key_index;

	if (!eapol_verify_gtk_1_of_2(ek, sm->handshake->wpa_ie)) {
		handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	if (!sm->handshake->wpa_ie) {
		gtk = handshake_util_find_gtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&gtk_len);
		if (!gtk)
			return;

		gtk_key_index = util_bit_field(gtk[0], 0, 2);
		gtk += 2;
		gtk_len -= 2;
	} else {
		gtk = decrypted_key_data;
		gtk_len = decrypted_key_data_size;

		if (!gtk || gtk_len < CRYPTO_MIN_GTK_LEN ||
						gtk_len > CRYPTO_MAX_GTK_LEN)
			return;

		gtk_key_index = ek->wpa_key_id;
	}

	if (sm->handshake->mfp) {
		igtk = handshake_util_find_igtk_kde(decrypted_key_data,
							decrypted_key_data_size,
							&igtk_len);
		if (!igtk)
			return;

		igtk_key_index = l_get_le16(igtk);;
		igtk += 2;
		igtk_len -= 2;
	} else
		igtk = NULL;

	/*
	 * 802.11-2016, Section 12.7.7.2:
	 * "
	 * a) Verifies that the Key Replay Counter field value has not yet been
	 * seen before, i.e., its value is strictly larger than that in any
	 * other EAPOL-Key frame received thus far during this session.
	 * b) Verifies that the MIC is valid, i.e., it uses the KCK that is
	 * part of the PTK to verify that there is no data integrity error.
	 * c) Uses the MLME-SETKEYS.request primitive to configure the temporal
	 * GTK and, when present, IGTK into its IEEE 802.11 MAC.
	 * d) Responds by creating and sending message 2 of the group key
	 * handshake to the Authenticator and incrementing the replay counter.
	 * "
	 * Note: steps a & b are performed in eapol_key_handle
	 */
	sm->replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);
	sm->have_replay = true;

	step2 = eapol_create_gtk_2_of_2(sm->protocol_version,
					ek->key_descriptor_version,
					sm->replay_counter,
					sm->handshake->wpa_ie, ek->wpa_key_id);

	ptk = handshake_state_get_ptk(sm->handshake);

	if (!eapol_calculate_mic(ptk->kck, step2, mic)) {
		l_free(step2);
		handshake_failed(sm, MMPDU_REASON_CODE_UNSPECIFIED);
		return;
	}

	memcpy(step2->key_mic_data, mic, sizeof(mic));
	eapol_write(sm, (struct eapol_frame *) step2);
	l_free(step2);

	eapol_install_gtk(sm, gtk_key_index, gtk, gtk_len, ek->key_rsc);

	if (igtk)
		eapol_install_igtk(sm, igtk_key_index, igtk, igtk_len);
}

static struct eapol_sm *eapol_find_sm(uint32_t ifindex, const uint8_t *aa)
{
	const struct l_queue_entry *entry;
	struct eapol_sm *sm;

	for (entry = l_queue_get_entries(state_machines); entry;
					entry = entry->next) {
		sm = entry->data;

		if (sm->handshake->ifindex != ifindex)
			continue;

		if (memcmp(sm->handshake->aa, aa, ETH_ALEN))
			continue;

		return sm;
	}

	return NULL;
}

static void eapol_key_handle(struct eapol_sm *sm,
				const struct eapol_frame *frame)
{
	const struct eapol_key *ek;
	const struct crypto_ptk *ptk;
	uint8_t *decrypted_key_data = NULL;
	size_t key_data_len = 0;
	uint64_t replay_counter;

	ek = eapol_key_validate((const uint8_t *) frame,
				sizeof(struct eapol_header) +
				L_BE16_TO_CPU(frame->header.packet_len));
	if (!ek)
		return;

	/* Wrong direction */
	if (!ek->key_ack)
		return;

	/* Further Descriptor Type check */
	if (!sm->handshake->wpa_ie &&
			ek->descriptor_type != EAPOL_DESCRIPTOR_TYPE_80211)
		return;
	else if (sm->handshake->wpa_ie &&
			ek->descriptor_type != EAPOL_DESCRIPTOR_TYPE_WPA)
		return;

	replay_counter = L_BE64_TO_CPU(ek->key_replay_counter);

	/*
	 * 802.11-2016, Section 12.7.2:
	 * "The Supplicant and Authenticator shall track the key replay counter
	 * per security association. The key replay counter shall be
	 * initialized to 0 on (re)association. The Authenticator shall
	 * increment the key replay counter on each successive EAPOL-Key frame."
	 *
	 * and
	 *
	 * "The Supplicant should also use the key replay counter and ignore
	 * EAPOL-Key frames with a Key Replay Counter field value smaller than
	 * or equal to any received in a valid message. The local Key Replay
	 * Counter field should not be updated until after the EAPOL-Key MIC is
	 * checked and is found to be valid. In other words, the Supplicant
	 * never updates the Key Replay Counter field for message 1 in the
	 * 4-way handshake, as it includes no MIC. This implies the Supplicant
	 * needs to allow for retransmission of message 1 when checking for
	 * the key replay counter of message 3."
	 *
	 * Note: The latter condition implies that Message 1 and Message 3
	 * can have the same replay counter, though other parts of the spec
	 * mandate that the Authenticator has to increment the replay counter
	 * for each frame sent.  Contradictory.
	 */
	if (sm->have_replay && sm->replay_counter >= replay_counter)
		return;

	ptk = handshake_state_get_ptk(sm->handshake);

	if (ek->key_mic) {
		/* Haven't received step 1 yet, so no ptk */
		if (!sm->handshake->have_snonce)
			return;

		if (!eapol_verify_mic(ptk->kck, ek))
			return;
	}

	if ((ek->encrypted_key_data && !sm->handshake->wpa_ie) ||
			(ek->key_type == 0 && sm->handshake->wpa_ie)) {
		/* Haven't received step 1 yet, so no ptk */
		if (!sm->handshake->have_snonce)
			return;

		decrypted_key_data = eapol_decrypt_key_data(ptk->kek, ek,
						&key_data_len);
		if (!decrypted_key_data)
			return;
	} else
		key_data_len = L_BE16_TO_CPU(ek->key_data_len);

	if (ek->key_type == 0) {
		/* GTK handshake allowed only after PTK handshake complete */
		if (!sm->handshake->ptk_complete)
			goto done;

		if (sm->handshake->group_cipher ==
				IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC)
			goto done;

		if (!decrypted_key_data)
			goto done;

		eapol_handle_gtk_1_of_2(sm, ek, decrypted_key_data,
					key_data_len);
		goto done;
	}

	/* If no MIC, then assume packet 1, otherwise packet 3 */
	if (!ek->key_mic)
		eapol_handle_ptk_1_of_4(sm, ek);
	else {
		if (!key_data_len)
			goto done;

		eapol_handle_ptk_3_of_4(sm, ek,
					decrypted_key_data ?: ek->key_data,
					key_data_len);
	}

done:
	l_free(decrypted_key_data);
}

/* This respresentes the eapMsg message in 802.1X Figure 8-1 */
static void eapol_eap_msg_cb(const uint8_t *eap_data, size_t len,
					void *user_data)
{
	struct eapol_sm *sm = user_data;
	uint8_t buf[sizeof(struct eapol_frame) + len];
	struct eapol_frame *frame = (struct eapol_frame *) buf;

	frame->header.protocol_version = sm->protocol_version;
	frame->header.packet_type = 0;
	l_put_be16(len, &frame->header.packet_len);

	memcpy(frame->data, eap_data, len);

	eapol_write(sm, frame);
}

/* This respresentes the eapTimout, eapFail and eapSuccess messages */
static void eapol_eap_complete_cb(enum eap_result result, void *user_data)
{
	struct eapol_sm *sm = user_data;

	l_info("EAP completed with %s", result == EAP_RESULT_SUCCESS ?
			"eapSuccess" : (result == EAP_RESULT_FAIL ?
				"eapFail" : "eapTimeout"));

	eap_free(sm->eap);
	sm->eap = NULL;

	if (result != EAP_RESULT_SUCCESS)
		handshake_failed(sm, MMPDU_REASON_CODE_IEEE8021X_FAILED);
}

/* This respresentes the eapResults message */
static void eapol_eap_results_cb(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				void *user_data)
{
	struct eapol_sm *sm = user_data;
	ssize_t pmk_len;
	const uint8_t *pmk_data;

	l_debug("EAP key material received");

	/*
	 * 802.11i 8.5.1.2:
	 *    "When not using a PSK, the PMK is derived from the AAA key.
	 *    The PMK shall be computed as the first 256 bits (bits 0–255)
	 *    of the AAA key: PMK ← L(PTK, 0, 256)."
	 * 802.11 11.6.1.3:
	 *    "When not using a PSK, the PMK is derived from the MSK.
	 *    The PMK shall be computed as the first 256 bits (bits 0–255)
	 *    of the MSK: PMK ← L(MSK, 0, 256)."
	 * RFC5247 explains AAA-Key refers to the MSK and confirms the
	 * first 32 bytes of the MSK are used.  MSK is at least 64 octets
	 * long per RFC3748.  Note WEP derives the PTK from MSK differently.
	 *
	 * In a Fast Transition initial mobility domain association the PMK
	 * maps to the XXKey except with EAP:
	 * 802.11 11.6.1.7.3:
	 *    "If the AKM negotiated is 00-0F-AC:3, then XXKey shall be the
	 *    second 256 bits of the MSK (which is derived from the IEEE
	 *    802.1X authentication), i.e., XXKey = L(MSK, 256, 256)."
	 */

	if (sm->handshake->akm_suite == IE_RSN_AKM_SUITE_FT_OVER_8021X) {
		pmk_len = (ssize_t) msk_len - 32;
		pmk_data = msk_data + 32;
	} else {
		pmk_len = msk_len;
		pmk_data = msk_data;
	}

	if (pmk_len < 32)
		goto msk_short;

	handshake_state_set_pmk(sm->handshake, pmk_data);

	return;

msk_short:
	l_error("EAP method's MSK too short for AKM suite %u",
			sm->handshake->akm_suite);

	handshake_failed(sm, MMPDU_REASON_CODE_IEEE8021X_FAILED);
}

static void eapol_eap_event_cb(unsigned int event,
				const void *event_data, void *user_data)
{
	struct eapol_sm *sm = user_data;

	if (!sm->event_func)
		return;

	sm->event_func(event, event_data, sm->user_data);
}

void eapol_sm_set_use_eapol_start(struct eapol_sm *sm, bool enabled)
{
	sm->use_eapol_start = enabled;
}

void eapol_sm_set_require_handshake(struct eapol_sm *sm, bool enabled)
{
	sm->require_handshake = enabled;

	if (!sm->require_handshake)
		sm->use_eapol_start = false;
}

static void eapol_rx_packet(uint16_t proto, const uint8_t *from,
				const struct eapol_frame *frame,
				void *user_data)
{
	struct eapol_sm *sm = user_data;

	if (proto != ETH_P_PAE || memcmp(from, sm->handshake->aa, 6))
		return;

	if (!sm->started) {
		size_t len = sizeof(struct eapol_header) +
			L_BE16_TO_CPU(frame->header.packet_len);

		/*
		 * If the state machine hasn't started yet save the frame
		 * for processing later.
		 */
		if (sm->early_frame) /* Is the 1-element queue full */
			return;

		sm->early_frame = l_memdup(frame, len);

		return;
	}

	if (!sm->protocol_version)
		sm->protocol_version = frame->header.protocol_version;

	switch (frame->header.packet_type) {
	case 0: /* EAPOL-EAP */
		l_timeout_remove(sm->eapol_start_timeout);
		sm->eapol_start_timeout = 0;

		if (!sm->eap) {
			/* If we're not configured for EAP, send a NAK */
			sm->eap = eap_new(eapol_eap_msg_cb,
						eapol_eap_complete_cb, sm);

			if (!sm->eap)
				return;

			eap_set_key_material_func(sm->eap,
							eapol_eap_results_cb);
		}

		sm->eap_exchanged = true;

		eap_rx_packet(sm->eap, frame->data,
				L_BE16_TO_CPU(frame->header.packet_len));

		break;

	case 3: /* EAPOL-Key */
		if (!sm->handshake->have_pmk) {
			if (!sm->eap)
				return;

			/*
			 * Either this is an error (EAP negotiation in
			 * progress) or the server is giving us a chance to
			 * use a cached PMK.  We don't yet cache PMKs so
			 * send an EAPOL-Start if we haven't sent one yet.
			 */
			if (sm->eapol_start_timeout)
				send_eapol_start(NULL, sm);

			return;
		}

		eapol_key_handle(sm, frame);
		break;

	default:
		return;
	}
}

void __eapol_update_replay_counter(uint32_t ifindex, const uint8_t *spa,
				const uint8_t *aa, uint64_t replay_counter)
{
	struct eapol_sm *sm;

	sm = eapol_find_sm(ifindex, aa);

	if (!sm)
		return;

	if (sm->replay_counter >= replay_counter)
		return;

	sm->replay_counter = replay_counter;
}

void __eapol_set_tx_packet_func(eapol_tx_packet_func_t func)
{
	tx_packet = func;
}

void __eapol_set_tx_user_data(void *user_data)
{
	tx_user_data = user_data;
}

void __eapol_set_deauthenticate_func(eapol_deauthenticate_func_t func)
{
	deauthenticate = func;
}

void __eapol_set_rekey_offload_func(eapol_rekey_offload_func_t func)
{
	rekey_offload = func;
}

void eapol_register(struct eapol_sm *sm)
{
	l_queue_push_head(state_machines, sm);

	sm->watch_id = eapol_frame_watch_add(sm->handshake->ifindex,
						eapol_rx_packet, sm);
}

bool eapol_start(struct eapol_sm *sm)
{
	if (sm->handshake->settings_8021x) {
		sm->eap = eap_new(eapol_eap_msg_cb, eapol_eap_complete_cb, sm);

		if (!sm->eap)
			goto eap_error;

		if (!eap_load_settings(sm->eap, sm->handshake->settings_8021x,
					"EAP-")) {
			eap_free(sm->eap);
			sm->eap = NULL;

			goto eap_error;
		}

		eap_set_key_material_func(sm->eap, eapol_eap_results_cb);
		eap_set_event_func(sm->eap, eapol_eap_event_cb);
	}

	sm->started = true;

	if (sm->require_handshake)
		sm->timeout = l_timeout_create(2, eapol_timeout, sm, NULL);

	if (sm->use_eapol_start) {
		/*
		 * We start a short timeout, if EAP packets are not received
		 * from AP, then we send the EAPoL-Start
		 */
		sm->eapol_start_timeout =
				l_timeout_create(1, send_eapol_start, sm, NULL);
	}

	/* Process any frames received early due to scheduling */
	if (sm->early_frame) {
		eapol_rx_packet(ETH_P_PAE, sm->handshake->aa,
				sm->early_frame, sm);
		l_free(sm->early_frame);
		sm->early_frame = NULL;
	}

	return true;

eap_error:
	l_error("Error initializing EAP for ifindex %i",
			(int) sm->handshake->ifindex);

	return false;
}

struct eapol_frame_watch {
	uint32_t ifindex;
	struct watchlist_item super;
};

static void eapol_frame_watch_free(struct watchlist_item *item)
{
	struct eapol_frame_watch *efw =
		container_of(item, struct eapol_frame_watch, super);

	l_free(efw);
}

static const struct watchlist_ops eapol_frame_watch_ops = {
	.item_free = eapol_frame_watch_free,
};

uint32_t eapol_frame_watch_add(uint32_t ifindex,
				eapol_frame_watch_func_t handler,
				void *user_data)
{
	struct eapol_frame_watch *efw;

	efw = l_new(struct eapol_frame_watch, 1);
	efw->ifindex = ifindex;

	return watchlist_link(&frame_watches, &efw->super,
				handler, user_data, NULL);
}

bool eapol_frame_watch_remove(uint32_t id)
{
	return watchlist_remove(&frame_watches, id);
}

void eapol_tx_frame(uint32_t ifindex, uint16_t proto, const uint8_t *dst,
			const struct eapol_frame *frame)
{
	pae_write(ifindex, dst, NULL, proto, frame);
}

struct preauth_sm {
	uint32_t ifindex;
	uint8_t aa[6];
	uint8_t spa[6];
	struct eap_state *eap;
	uint8_t pmk[32];
	eapol_preauth_cb_t cb;
	eapol_preauth_destroy_func_t destroy;
	void *user_data;
	struct l_timeout *timeout;
	uint32_t watch_id;
	bool initial_rx:1;
};

#define EAPOL_TIMEOUT_SEC 1

static void preauth_sm_destroy(void *value)
{
	struct preauth_sm *sm = value;

	if (sm->destroy)
		sm->destroy(sm->user_data);

	eap_free(sm->eap);
	l_timeout_remove(sm->timeout);
	eapol_frame_watch_remove(sm->watch_id);
	l_free(sm);
}

static void preauth_frame(struct preauth_sm *sm, uint8_t packet_type,
				const uint8_t *data, size_t data_len)
{
	uint8_t buf[sizeof(struct eapol_frame) + data_len];
	struct eapol_frame *frame = (struct eapol_frame *) buf;

	frame->header.protocol_version = EAPOL_PROTOCOL_VERSION_2001;
	frame->header.packet_type = packet_type;
	l_put_be16(data_len, &frame->header.packet_len);

	if (data_len)
		memcpy(frame->data, data, data_len);

	pae_write(sm->ifindex, sm->aa, sm->spa, 0x88c7, frame);
}

static void preauth_rx_packet(uint16_t proto, const uint8_t *from,
				const struct eapol_frame *frame,
				void *user_data)
{
	struct preauth_sm *sm = user_data;

	if (proto != 0x88c7 || memcmp(from, sm->aa, 6))
		return;

	if (frame->header.packet_type != 0) /* EAPOL-EAP */
		return;

	if (!sm->initial_rx) {
		sm->initial_rx = true;

		/*
		 * Initial frame from authenticator received, it's alive
		 * so set a longer timeout.  The timeout is for the whole
		 * EAP exchange as we have no way to monitor the
		 * negotiation progress and keep rearming the timer each
		 * time progress is made.
		 */
		l_timeout_modify(sm->timeout, EAPOL_TIMEOUT_SEC * 3);
	}

	eap_rx_packet(sm->eap, frame->data,
			L_BE16_TO_CPU(frame->header.packet_len));
}

static void preauth_eap_msg_cb(const uint8_t *eap_data, size_t len,
				void *user_data)
{
	struct preauth_sm *sm = user_data;

	preauth_frame(sm, 0, eap_data, len);
}

static void preauth_eap_complete_cb(enum eap_result result, void *user_data)
{
	struct preauth_sm *sm = user_data;

	l_info("Preauthentication completed with %s",
		result == EAP_RESULT_SUCCESS ? "eapSuccess" :
		(result == EAP_RESULT_FAIL ? "eapFail" : "eapTimeout"));

	l_queue_remove(preauths, sm);

	if (result == EAP_RESULT_SUCCESS)
		sm->cb(sm->pmk, sm->user_data);
	else
		sm->cb(NULL, sm->user_data);

	preauth_sm_destroy(sm);
}

/* See eapol_eap_results_cb for documentation */
static void preauth_eap_results_cb(const uint8_t *msk_data, size_t msk_len,
				const uint8_t *emsk_data, size_t emsk_len,
				const uint8_t *iv, size_t iv_len,
				void *user_data)
{
	struct preauth_sm *sm = user_data;

	l_debug("Preauthentication EAP key material received");

	if (msk_len < 32)
		goto msk_short;

	memcpy(sm->pmk, msk_data, 32);

	return;

msk_short:
	l_error("Preauthentication MSK too short");

	l_queue_remove(preauths, sm);

	sm->cb(NULL, sm->user_data);

	preauth_sm_destroy(sm);
}

static void preauth_timeout(struct l_timeout *timeout, void *user_data)
{
	struct preauth_sm *sm = user_data;

	l_error("Preauthentication timeout");

	l_queue_remove(preauths, sm);

	sm->cb(NULL, sm->user_data);

	preauth_sm_destroy(sm);
}

struct preauth_sm *eapol_preauth_start(const uint8_t *aa,
					const struct handshake_state *hs,
					eapol_preauth_cb_t cb, void *user_data,
					eapol_preauth_destroy_func_t destroy)
{
	struct preauth_sm *sm;

	sm = l_new(struct preauth_sm, 1);

	sm->ifindex = hs->ifindex;
	memcpy(sm->aa, aa, 6);
	memcpy(sm->spa, hs->spa, 6);
	sm->cb = cb;
	sm->destroy = destroy;
	sm->user_data = user_data;

	sm->eap = eap_new(preauth_eap_msg_cb, preauth_eap_complete_cb, sm);
	if (!sm->eap)
		goto err_free_sm;

	if (!eap_load_settings(sm->eap, hs->settings_8021x, "EAP-"))
		goto err_free_eap;

	eap_set_key_material_func(sm->eap, preauth_eap_results_cb);

	sm->timeout = l_timeout_create(EAPOL_TIMEOUT_SEC, preauth_timeout,
					sm, NULL);

	sm->watch_id = eapol_frame_watch_add(sm->ifindex,
						preauth_rx_packet, sm);

	l_queue_push_head(preauths, sm);

	/* Send EAPOL-Start */
	preauth_frame(sm, 1, NULL, 0);

	return sm;

err_free_eap:
	eap_free(sm->eap);
err_free_sm:
	l_free(sm);

	return NULL;
}

static bool preauth_remove_by_ifindex(void *data, void *user_data)
{
	struct preauth_sm *sm = data;

	if (sm->ifindex != L_PTR_TO_UINT(user_data))
		return false;

	preauth_sm_destroy(sm);

	return true;
}

void eapol_preauth_cancel(uint32_t ifindex)
{
	l_queue_foreach_remove(preauths, preauth_remove_by_ifindex,
				L_UINT_TO_PTR(ifindex));
}

static bool eapol_frame_watch_match_ifindex(const void *a, const void *b)
{
	struct eapol_frame_watch *efw =
		container_of(a, struct eapol_frame_watch, super);

	return efw->ifindex == L_PTR_TO_UINT(b);
}

void __eapol_rx_packet(uint32_t ifindex, const uint8_t *src, uint16_t proto,
					const uint8_t *frame, size_t len)
{
	const struct eapol_header *eh;

	/* Validate Header */
	if (len < sizeof(struct eapol_header))
		return;

	eh = (const struct eapol_header *) frame;

	switch (eh->protocol_version) {
	case EAPOL_PROTOCOL_VERSION_2001:
	case EAPOL_PROTOCOL_VERSION_2004:
		break;
	default:
		return;
	}

	if (len < sizeof(struct eapol_header) + L_BE16_TO_CPU(eh->packet_len))
		return;

	WATCHLIST_NOTIFY_MATCHES(&frame_watches,
					eapol_frame_watch_match_ifindex,
					L_UINT_TO_PTR(ifindex),
					eapol_frame_watch_func_t, proto, src,
					(const struct eapol_frame *) eh);
}

bool eapol_init()
{
	state_machines = l_queue_new();
	preauths = l_queue_new();
	watchlist_init(&frame_watches, &eapol_frame_watch_ops);

	return true;
}

bool eapol_exit()
{
	if (!l_queue_isempty(state_machines))
		l_warn("stale eapol state machines found");

	l_queue_destroy(state_machines, eapol_sm_destroy);

	if (!l_queue_isempty(preauths))
		l_warn("stale preauth state machines found");

	l_queue_destroy(preauths, preauth_sm_destroy);

	watchlist_destroy(&frame_watches);

	return true;
}
