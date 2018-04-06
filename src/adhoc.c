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

#include "linux/nl80211.h"

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
//#include "src/mpdu.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
//#include "src/ap.h"
#include "src/common.h"
#include "src/network.h"
#include "src/adhoc.h"
#include "src/dbus.h"

#include <stdio.h>

struct adhoc_state {
	struct device *device;
	char *ssid;
	char *psk;
	uint8_t pmk[32];
	adhoc_event_cb_t cb;
	uint32_t stop_join_id;
	uint32_t stop_iface_cmd_id;
	uint32_t channel;
	uint32_t beacon_interval;
	struct l_uintset *rates;
	unsigned int ciphers;
	uint16_t last_aid;
	struct l_queue *sta_states;
	struct l_queue *early_frames;
	uint32_t sta_watch_id;
	struct l_dbus_message *start_pending;
};

struct sta_state {
	uint8_t addr[6];
	bool sta_authenticated : 1;
	bool aa_authenticated : 1;
	uint16_t aid;
	struct l_uintset *rates;
	struct adhoc_state *adhoc;
	struct eapol_sm *sm;
	struct handshake_state *hs_sta;
	struct eapol_sm *sm_a;
	struct handshake_state *hs_auth;
};

static struct l_genl_family *nl80211 = NULL;

static void adhoc_set_rsn_info(struct adhoc_state *ap, struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = 0x0008;
	rsn->group_cipher = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
}

static void adhoc_eapol_event(unsigned int event,
		const void *event_data, void *user_data)
{
	struct sta_state *sta = user_data;

	switch (event) {
		/* TODO FIX THIS */
	//case EAPOL_EVENT_HANDSHAKE_SUCCESS:
	//	sta->sta_authenticated = true;
	//	printf("STA AUTHENTICATED\n");
	//	break;
	case EAPOL_EVENT_HANDSHAKE_SUCCESS:
		sta->aa_authenticated = true;
		printf("AA AUTHENTICATED\n");
		break;
	case EAPOL_EVENT_HANDSHAKE_FAILED:
		l_debug("STA "MAC" failed to authenticate", MAC_STR(sta->addr));
		sta->sta_authenticated = false;
		sta->aa_authenticated = true;
		netdev_remove_station(device_get_netdev(sta->adhoc->device), sta->addr);
		handshake_state_free(sta->hs_auth);
		sta->hs_auth = NULL;
		handshake_state_free(sta->hs_sta);
		sta->hs_sta = NULL;
		/* sm's get freed by eapol */
		sta->sm_a = NULL;
		sta->sm = NULL;
		break;
	}

	if (sta->sta_authenticated && sta->aa_authenticated) {
		printf("Signalling property changed\n");
		l_dbus_property_changed(dbus_get_bus(),
				device_get_path(sta->adhoc->device),
				IWD_ADHOC_INTERFACE, "ConnectedPeers");
	}
}

static struct eapol_sm *adhoc_new_sm(struct sta_state *sta, bool authenticator)
{
	struct netdev *netdev = device_get_netdev(sta->adhoc->device);
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct network *network;
	struct scan_bss bss;
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[24];
	struct handshake_state *hs;
	struct eapol_sm *sm;

	network = network_create(sta->adhoc->device, sta->adhoc->ssid,
			SECURITY_PSK);
	if (!network) {
		l_error("could not create network object");
		return NULL;
	}

	if (!network_set_psk(network, (const uint8_t *)sta->adhoc->pmk)) {
		l_error("could not set network PSK\n");
		return NULL;
	}

	/* fill in only what handshake setup requires */
	memset(&bss, 0, sizeof(bss));
	adhoc_set_rsn_info(sta->adhoc, &rsn);
	ie_build_rsne(&rsn, bss_rsne);
	bss.rsne = bss_rsne;

	hs = device_handshake_setup(sta->adhoc->device, network, &bss);
	if (!hs) {
		l_error("could not create handshake object");
		return NULL;
	}

	handshake_state_set_own_rsn(hs, bss.rsne);

	if (authenticator) {
		handshake_state_set_authenticator_address(hs, own_addr);
		handshake_state_set_supplicant_address(hs, sta->addr);
	} else {
		handshake_state_set_authenticator_address(hs, sta->addr);
		handshake_state_set_supplicant_address(hs, own_addr);
		/*
		* after 4-way is complete, netdev adds keys which require
		* access to netdev->handshake->aa.
		*/
		netdev_set_handshake(netdev, hs);
	}

	sm = eapol_sm_new(hs);
	if (!sm) {
		l_error("could not create sm object");
		return NULL;
	}

	eapol_sm_set_user_data(sm, sta->adhoc->device);
	eapol_sm_set_listen_interval(sm, 100);
	eapol_sm_set_protocol_version(sm, EAPOL_PROTOCOL_VERSION_2001);
	eapol_sm_set_event_func(sm, adhoc_eapol_event);
	eapol_sm_set_user_data(sm, sta);

	if (authenticator)
		sta->hs_auth = hs;
	else
		sta->hs_sta = hs;

	return sm;
}

static bool ap_sta_match_addr(const void *a, const void *b)
{
	const struct sta_state *sta = a;

	return !memcmp(sta->addr, b, 6);
}

static void adhoc_sta_destroy(void *data)
{
	struct sta_state *sta = data;

	eapol_sm_free(sta->sm);
	eapol_sm_free(sta->sm_a);
}

struct adhoc_parameters *adhoc_parameters_new(struct netdev *netdev,
		const char *ssid, const char *psk)
{
	struct wiphy *wiphy = netdev_get_wiphy(netdev);
	struct adhoc_parameters *cfg = l_new(struct adhoc_parameters, 1);

	memset(cfg, 0, sizeof(struct adhoc_parameters));

	cfg->ssid = l_strdup(ssid);
	cfg->psk = l_strdup(psk);
	/* set to default values, caller can change if needed */
	cfg->channel = 6;
	cfg->beacon_interval = 100;
	cfg->rates = l_uintset_new(200);
	l_uintset_put(cfg->rates, 2);
	l_uintset_put(cfg->rates, 11);
	l_uintset_put(cfg->rates, 22);
	cfg->rsn = l_malloc(sizeof(struct ie_rsn_info));
	memset(cfg->rsn, 0, sizeof(struct ie_rsn_info));
	cfg->rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	cfg->rsn->pairwise_ciphers = wiphy_select_cipher(wiphy, 0xffff);
	cfg->rsn->group_cipher = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;

	return cfg;
}

void adhoc_parameters_free(struct adhoc_parameters *cfg)
{
	l_free(cfg->ssid);
	l_free(cfg->psk);
	l_uintset_free(cfg->rates);
	l_free(cfg->rsn);
	l_free(cfg);
}

void adhoc_free(struct adhoc_state *adhoc)
{
	l_free(adhoc->ssid);
	l_free(adhoc->psk);
	l_uintset_free(adhoc->rates);

	l_queue_destroy(adhoc->sta_states, adhoc_sta_destroy);

	l_free(adhoc);
}

static void adhoc_del_station(struct adhoc_state *adhoc, const uint8_t *mac)
{
	struct sta_state *sta;

	sta = l_queue_find(adhoc->sta_states, ap_sta_match_addr, mac);
	if (!sta) {
		l_warn("could not find station "MAC" in list", MAC_STR(mac));
		return;
	}

	l_debug("lost station "MAC, MAC_STR(mac));

	//netdev_remove_station(device_get_netdev(sta->adhoc->device), sta->addr, sta->aid);

	eapol_sm_free(sta->sm);
	eapol_sm_free(sta->sm_a);

	l_queue_remove(adhoc->sta_states, sta);
}

static void adhoc_new_station(struct adhoc_state *adhoc, const uint8_t *mac)
{
	struct sta_state *sta;

	sta = l_queue_find(adhoc->sta_states, ap_sta_match_addr, mac);
	if (sta) {
		l_warn("new station event with already connected STA");
		/* TODO: do something here? cleanup? error? */
		return;
	}

	sta = l_new(struct sta_state, 1);

	memset(sta, 0, sizeof(struct sta_state));

	memcpy(sta->addr, mac, 6);
	sta->adhoc = adhoc;

	l_queue_push_tail(adhoc->sta_states, sta);

	l_info("new Station: "MAC" adhoc=%p", MAC_STR(mac), adhoc);

	/* TODO: cleanup */
	sta->sm_a = adhoc_new_sm(sta, true);
	if (!sta->sm_a) {
		l_error("could not create authenticator state machine");
		return;
	}

	sta->sm = adhoc_new_sm(sta, false);
	if (!sta->sm) {
		l_error("could not create station state machine");
		return;
	}

	eapol_register(sta->sm);
	eapol_register_authenticator(sta->sm_a);

	eapol_start(sta->sm);
}

static void adhoc_station_changed_cb(struct netdev *netdev,
		const uint8_t *mac, bool added, void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	if (added)
		adhoc_new_station(adhoc, mac);
	else
		adhoc_del_station(adhoc, mac);
}

static void adhoc_join_cb(struct netdev *netdev,
		enum netdev_result result, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct l_dbus_message *reply;

	if (result != NETDEV_RESULT_OK) {
		if (device_get_state(adhoc->device) == DEVICE_STATE_ADHOC)
			netdev_set_iftype(netdev, NETDEV_IFTYPE_STATION);

		if (adhoc->start_pending) {
			reply = dbus_error_failed(adhoc->start_pending);

			dbus_pending_reply(&adhoc->start_pending, reply);
		}

		return;
	}

	adhoc->sta_watch_id = netdev_station_watch_add(netdev,
			adhoc_station_changed_cb, adhoc);

	reply = l_dbus_message_new_method_return(adhoc->start_pending);

	dbus_pending_reply(&adhoc->start_pending, reply);

	adhoc->start_pending = NULL;
}

static int adhoc_join(struct adhoc_state *adhoc, const char *ssid,
		const char *psk, struct l_dbus_message *pending)
{
	struct netdev *netdev = device_get_netdev(adhoc->device);
	struct adhoc_parameters *cfg = adhoc_parameters_new(netdev, ssid, psk);

	adhoc->ssid = l_strdup(ssid);
	adhoc->start_pending = l_dbus_message_ref(pending);
	adhoc->sta_states = l_queue_new();

	if (crypto_psk_from_passphrase(psk, (uint8_t *) ssid, strlen(ssid),
					adhoc->pmk) < 0)
		goto error;

	if (netdev_join_adhoc(netdev, cfg, adhoc_join_cb, adhoc)) {
		l_error("Netdev failed to start adhoc\n");
		goto error;
	}

	return 0;

error:
	return -1;
}

static struct l_dbus_message *adhoc_start(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct device *device = adhoc->device;
	struct netdev *netdev = device_get_netdev(device);
	const char *ssid, *wpa2_psk;
	enum device_state state = device_get_state(device);

	if (!l_dbus_message_get_arguments(message, "ss", &ssid, &wpa2_psk))
		return dbus_error_invalid_args(message);


	netdev_set_iftype(netdev, NETDEV_IFTYPE_ADHOC);

	if (adhoc_join(adhoc, ssid, wpa2_psk, message)) {
		netdev_set_iftype(netdev, NETDEV_IFTYPE_STATION);
		return dbus_error_failed(message);
	}

	return NULL;
}

static void sta_append(void *data, void *user_data)
{
	struct sta_state *sta = data;
	struct l_dbus_message_builder *builder = user_data;
	const char* macstr;

	if (!sta->addr)
		return;

	if (!(sta->sta_authenticated && sta->aa_authenticated))
		return;

	macstr = util_address_to_string(sta->addr);

	printf("Appending %s\n", macstr);

	l_dbus_message_builder_append_basic(builder, 's', macstr);
}

static bool adhoc_property_get_peers(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	printf("GET PEERS\n");

	l_dbus_message_builder_enter_array(builder, "s");

	l_queue_foreach(adhoc->sta_states, sta_append, builder);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void adhoc_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Start", 0, adhoc_start, "",
			"ss", "ssid", "wpa2_psk");
	l_dbus_interface_property(interface, "ConnectedPeers", 0, "as",
					adhoc_property_get_peers, NULL);
}

bool adhoc_add_interface(struct device *device)
{
	/*
	 * The adhoc network has yet to be created, but still the state must
	 * be allocated here in order to set the dbus interface user_data.
	 */
	struct adhoc_state *adhoc = l_new(struct adhoc_state, 1);

	adhoc->device = device;

	/* setup adhoc dbus interface */
	if (!l_dbus_object_add_interface(dbus_get_bus(), device_get_path(device),
					IWD_ADHOC_INTERFACE, adhoc)) {
		l_info("Unable to register %s interface", IWD_ADHOC_INTERFACE);
		l_free(adhoc);
		return false;
	}

	return true;
}

int adhoc_stop(struct device *device)
{
	return 0;
}

bool adhoc_init(struct l_genl_family *in)
{
	nl80211 = in;

	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_ADHOC_INTERFACE,
					adhoc_setup_interface,
					NULL, false))
		return false;

	return true;
}

void adhoc_exit(void)
{
	return;
}