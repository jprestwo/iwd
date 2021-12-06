/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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
struct l_ecc_point;
struct l_ecc_scalar;

enum dpp_attribute_type {
	/* 0000 - 0FFF reserved */
	DPP_ATTR_STATUS				= 0x1000,
	DPP_ATTR_INITIATOR_BOOT_KEY_HASH	= 0x1001,
	DPP_ATTR_RESPONDER_BOOT_KEY_HASH	= 0x1002,
	DPP_ATTR_INITIATOR_PROTOCOL_KEY		= 0x1003,
	DPP_ATTR_WRAPPED_DATA			= 0x1004,
	DPP_ATTR_INITIATOR_NONCE		= 0x1005,
	DPP_ATTR_INITIATOR_CAPABILITIES		= 0x1006,
	DPP_ATTR_RESPONDER_NONCE		= 0x1007,
	DPP_ATTR_RESPONDER_CAPABILITIES		= 0x1008,
	DPP_ATTR_RESPONDER_PROTOCOL_KEY		= 0x1009,
	DPP_ATTR_INITIATOR_AUTH_TAG		= 0x100a,
	DPP_ATTR_RESPONDER_AUTH_TAG		= 0x100b,
	DPP_ATTR_CONFIGURATION_OBJECT		= 0x100c,
	DPP_ATTR_CONNECTOR			= 0x100d,
	DPP_ATTR_CONFIGURATION_REQUEST		= 0x100e,
	DPP_ATTR_BOOTSTRAPPING_KEY		= 0x100f,
	/* 1010 - 1011 reserved */
	DPP_ATTR_FINITE_CYCLIC_GROUP		= 0x1012,
	DPP_ATTR_ENCRYPTED_KEY			= 0x1013,
	DPP_ATTR_ENROLLEE_NONCE			= 0x1014,
	DPP_ATTR_CODE_IDENTIFIER		= 0x1015,
	DPP_ATTR_TRANSACTION_ID			= 0x1016,
	DPP_ATTR_BOOTSTRAPPING_INFO		= 0x1017,
	DPP_ATTR_CHANNEL			= 0x1018,
	DPP_ATTR_PROTOCOL_VERSION		= 0x1019,
	DPP_ATTR_ENVELOPED_DATA			= 0x101a,
	DPP_ATTR_SEND_CONN_STATUS		= 0x101b,
	DPP_ATTR_CONN_STATUS			= 0x101c,
	DPP_ATTR_RECONFIGURATION_FLAGS		= 0x101d,
	DPP_ATTR_C_SIGN_KEY_HASH		= 0x101e,
	DPP_ATTR_CSR_ATTRIBUTES_REQUEST		= 0x101f,
	DPP_ATTR_ANONCE				= 0x1020,
	DPP_ATTR_EID				= 0x1021,
	DPP_ATTR_CONFIGURATOR_NONCE		= 0x1022,
};

struct dpp_attr_iter {
	const uint8_t *pos;
	const uint8_t *end;
};

void dpp_attr_iter_init(struct dpp_attr_iter *iter, const uint8_t *pdu,
			size_t len);
bool dpp_attr_iter_next(struct dpp_attr_iter *iter,
			enum dpp_attribute_type *type, size_t *len,
			const uint8_t **data);

char *dpp_generate_uri(const uint8_t *asn1, size_t asn1_len, uint8_t version,
			const uint8_t *mac, const uint32_t *freqs,
			size_t freqs_len, const char *info, const char *host);

size_t dpp_nonce_len_from_key_len(size_t len);

bool dpp_hash(enum l_checksum_type type, uint8_t *out, unsigned int num, ...);

bool dpp_derive_r_auth(const void *i_nonce, const void *r_nonce,
				size_t nonce_len, struct l_ecc_point *i_proto,
				struct l_ecc_point *r_proto,
				struct l_ecc_point *r_boot,
				void *r_auth);
bool dpp_derive_i_auth(const void *r_nonce, const void *i_nonce,
				size_t nonce_len, struct l_ecc_point *r_proto,
				struct l_ecc_point *i_proto,
				struct l_ecc_point *r_boot, void *i_auth);
struct l_ecc_scalar *dpp_derive_k1(const struct l_ecc_point *i_proto_public,
				const struct l_ecc_scalar *boot_private,
				void *k1);
struct l_ecc_scalar *dpp_derive_k2(const struct l_ecc_point *i_proto_public,
				const struct l_ecc_scalar *proto_private,
				void *k2);
bool dpp_derive_ke(const uint8_t *i_nonce, const uint8_t *r_nonce,
				struct l_ecc_scalar *m, struct l_ecc_scalar *n,
				void *ke);
