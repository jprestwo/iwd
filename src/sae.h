/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

struct sae_sm;
struct handshake_state;

typedef int (*sae_tx_packet_func_t)(uint32_t ifindex, const uint8_t *dest,
					const uint8_t *frame, size_t len,
					void *user_data);
typedef int (*sae_associate_func_t)(uint32_t ifindex);

typedef void (*sae_failed_func_t)(uint32_t ifindex, uint16_t reason,
					void *user_data);

struct sae_sm *sae_sm_new(struct handshake_state *hs);
void sae_sm_free(struct sae_sm *sm);

void sae_register(struct sae_sm *sm);

void __sae_rx_packet(uint32_t ifindex, const uint8_t *src,
				const uint8_t *frame, size_t len);
void __sae_set_tx_packet_func(sae_tx_packet_func_t func);
void __sae_set_associate_func(sae_associate_func_t func);
void __sae_set_failed_func(sae_failed_func_t func);
void __sae_set_tx_user_data(void *user_data);

void sae_init(void);
void sae_exit(void);
