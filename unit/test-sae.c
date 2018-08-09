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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <linux/if_ether.h>
#include <ell/ell.h>
#include <ell/tls-private.h>
#include <ell/key-private.h>

#include "src/util.h"
#include "src/eapol.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/sae.h"

struct test_handshake_state {
	struct handshake_state super;
	const uint8_t *tk;
	bool handshake_failed;
};

struct test_data {
	bool test_commit_success;
	bool test_anti_clogging;
	bool commit_success;

	bool tx_called;

	uint8_t tx_packet[512];
	size_t tx_packet_len;
};

static uint8_t spa[] = {2, 0, 0, 0, 0, 0};
static uint8_t aa[] = {2, 0, 0, 0, 0, 1};
static char *passphrase = "secret123";

static void test_handshake_state_free(struct handshake_state *hs)
{
	struct test_handshake_state *ths =
			container_of(hs, struct test_handshake_state, super);

	l_free(ths);
}

static struct handshake_state *test_handshake_state_new(uint32_t ifindex)
{
	struct test_handshake_state *ths;

	ths = l_new(struct test_handshake_state, 1);

	ths->super.ifindex = ifindex;
	ths->super.free = test_handshake_state_free;

	return &ths->super;
}

static int test_associate_func(struct handshake_state *hs)
{
	printf("ASSOCIATE\n");

	return 0;
}

static uint8_t test_clogging_token[32];

static bool test_tx_check_commit;
static bool test_tx_check_commit_success;
static bool test_tx_check_commit_anti_clogging;

static uint8_t last_packet[512];
static size_t last_packet_len;

static int test_tx_func(uint32_t ifindex, const uint8_t *dest,
					const uint8_t *frame, size_t len,
					void *user_data)
{
	struct test_data *td = user_data;

	td->tx_called = true;

	memset(td->tx_packet, 0, sizeof(td->tx_packet));
	memcpy(td->tx_packet, frame, len);
	td->tx_packet_len = len;

	assert(ifindex == 1);
	assert(!memcmp(dest, aa, 6));

	if (td->test_commit_success) {
		assert(l_get_u16(frame) == 1);		/* transaction */
		assert(l_get_u16(frame + 2) == 0);	/* status */
		assert(l_get_u16(frame + 4) == 19);	/* group */

		if (td->test_anti_clogging) {
			assert(len == 134);
			assert(!memcmp(frame + 6, test_clogging_token, 32));
		} else {
			assert(len == 102);
		}

		td->commit_success = true;

		return 0;
	}

	return 0;
}

enum handshake_event test_last_event;
static void test_handshake_event(struct handshake_state *hs,
					enum handshake_event event,
					void *event_data, void *user_data)
{
	test_last_event = event;
}

static struct sae_sm *test_initialize(struct test_data *td)
{
	struct sae_sm *sm;
	struct handshake_state *hs = test_handshake_state_new(1);

	sae_init();

	handshake_state_set_supplicant_address(hs, spa);
	handshake_state_set_authenticator_address(hs, aa);
	handshake_state_set_passphrase(hs, passphrase);
	handshake_state_set_event_func(hs, test_handshake_event, NULL);

	memset(test_clogging_token, 0xde, 32);

	__sae_set_tx_packet_func(test_tx_func);
	__sae_set_associate_func(test_associate_func);
	__sae_set_tx_user_data(td);

	sm = sae_sm_new(hs);

	td->test_commit_success = true;
	td->commit_success = false;
	sae_register(sm);

	assert(td->commit_success == true);
	assert(test_last_event == HANDSHAKE_EVENT_SAE_STARTED);

	return sm;
}

static void test_clogging(const void *arg)
{
	uint8_t frame[34];
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	l_put_u16(1, frame);
	l_put_u16(MMPDU_REASON_CODE_ANTI_CLOGGING_TOKEN_REQ, frame + 2);
	l_put_u16(19, frame + 4);
	memcpy(frame + 6, test_clogging_token, 32);

	td->test_anti_clogging = true;
	td->test_commit_success = true;
	td->commit_success = false;

	__sae_rx_packet(1, aa, frame, 38);

	assert(td->commit_success == true);

	l_free(td);
	sae_sm_free(sm);
	sae_exit();
}

static void print_buf(char *tag, uint8_t *buf, size_t len)
{
	int i;

	printf("%s: ", tag);
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

static void test_early_confirm(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);

	uint8_t frame[38];
	uint8_t first_commit[100];
	size_t first_commit_len;

	/* save the initial commit */
	memcpy(first_commit, td->tx_packet, td->tx_packet_len);
	first_commit_len = td->tx_packet_len;

	l_put_u16(2, frame);
	l_put_u16(0, frame + 2);

	memset(frame + 4, 0xfe, 32);

	td->test_commit_success = false;
	td->test_anti_clogging = false;

	__sae_rx_packet(1, aa, frame, 36);

	/* verify earlier commit matched most recent */
	assert(!memcmp(td->tx_packet, first_commit, td->tx_packet_len));

	l_free(td);
	sae_sm_free(sm);
	sae_exit();
}

static void test_reflection(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct sae_sm *sm = test_initialize(td);
	uint8_t frame[512];

	td->tx_called = false;
	/* send reflect same commit */
	__sae_rx_packet(1, aa, td->tx_packet, td->tx_packet_len);

	assert(td->tx_called == false);

	sae_sm_free(sm);
	l_free(td);
	sae_exit();
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("SAE anti-clogging", test_clogging, NULL);
	l_test_add("SAE early confirm", test_early_confirm, NULL);
	l_test_add("SAE reflection", test_reflection, NULL);

	return l_test_run();
}
