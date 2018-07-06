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

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/device.h"
#include "src/netdev.h"
#include "src/wiphy.h"
#include "src/crypto.h"
#include "src/ie.h"
#include "src/util.h"
#include "src/eapol.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/adhoc.h"
#include "src/dbus.h"

struct adhoc_state {
	struct device *device;
	char *ssid;
	uint8_t pmk[32];
	struct l_queue *sta_states;
	uint32_t sta_watch_id;
	uint32_t netdev_watch_id;
	struct l_dbus_message *pending;
	bool started : 1;
};

struct sta_state {
	uint8_t addr[6];
	struct adhoc_state *adhoc;
	struct eapol_sm *sm;
	struct handshake_state *hs_sta;
	struct eapol_sm *sm_a;
	struct handshake_state *hs_auth;

	bool sta_authenticated : 1;
	bool aa_authenticated : 1;
	/* flag if either handshakes have failed */
	bool handshake_failed : 1;
};

static void adhoc_sta_free(void *data)
{
	struct sta_state *sta = data;

	eapol_sm_free(sta->sm);
	handshake_state_free(sta->hs_sta);
	eapol_sm_free(sta->sm_a);
	handshake_state_free(sta->hs_auth);

	l_free(sta);
}

static void adhoc_remove_sta(struct sta_state *sta)
{
	l_queue_remove(sta->adhoc->sta_states, sta);

	/* signal station has been removed */
	if (sta->aa_authenticated && sta->sta_authenticated) {
		l_dbus_property_changed(dbus_get_bus(),
				device_get_path(sta->adhoc->device),
				IWD_ADHOC_INTERFACE, "ConnectedPeers");
	}

	adhoc_sta_free(sta);
}

static void adhoc_reset(struct adhoc_state *adhoc)
{
	if (adhoc->pending)
		dbus_pending_reply(&adhoc->pending,
				dbus_error_aborted(adhoc->pending));

	l_free(adhoc->ssid);

	netdev_station_watch_remove(device_get_netdev(adhoc->device),
			adhoc->sta_watch_id);

	l_queue_destroy(adhoc->sta_states, adhoc_sta_free);

	adhoc->started = false;
}

static void adhoc_set_rsn_info(struct adhoc_state *adhoc,
		struct ie_rsn_info *rsn)
{
	memset(rsn, 0, sizeof(*rsn));
	rsn->akm_suites = IE_RSN_AKM_SUITE_PSK;
	rsn->pairwise_ciphers = wiphy_select_cipher(
			device_get_wiphy(adhoc->device), 0xffff);
	rsn->group_cipher = IE_RSN_CIPHER_SUITE_NO_GROUP_TRAFFIC;
}

static bool ap_sta_match_addr(const void *a, const void *b)
{
	const struct sta_state *sta = a;

	return !memcmp(sta->addr, b, 6);
}

static void adhoc_handshake_event(struct handshake_state *hs,
		enum handshake_event event, void *event_data, void *user_data)
{
	struct sta_state *sta = user_data;
	struct adhoc_state *adhoc = sta->adhoc;

	switch (event) {
	case HANDSHAKE_EVENT_SETTING_KEYS_FAILED:
	case HANDSHAKE_EVENT_FAILED:
		l_error("handshake failed with STA "MAC, MAC_STR(sta->addr));

		/*
		 * If either of the two handshakes fails we only want to send a
		 * single DEL_STATION.
		 */
		if (sta->handshake_failed) {
			/* other handshake has failed (DEL_STATION happened) */
			adhoc_remove_sta(sta);
			return;
		} else if (sta->sta_authenticated || sta->aa_authenticated) {
			/* other handshake has succeeded */
			netdev_del_station(device_get_netdev(adhoc->device),
					sta->addr,
					MMPDU_REASON_CODE_UNSPECIFIED, false);
			adhoc_remove_sta(sta);
			return;
		}

		netdev_del_station(device_get_netdev(adhoc->device),
					sta->addr,
					MMPDU_REASON_CODE_UNSPECIFIED, false);
		sta->handshake_failed = true;

		return;
	case HANDSHAKE_EVENT_COMPLETE:
		if (sta->hs_auth == hs)
			sta->aa_authenticated = true;
		else if (sta->hs_sta == hs)
			sta->sta_authenticated = true;
		else
			l_error("invalid handshake object");

		break;
	default:
		break;
	}

	if (sta->sta_authenticated && sta->aa_authenticated)
		l_dbus_property_changed(dbus_get_bus(),
				device_get_path(adhoc->device),
				IWD_ADHOC_INTERFACE, "ConnectedPeers");
}

static void adhoc_netdev_notify(struct netdev *netdev,
				enum netdev_watch_event event, void *user_data)
{
	struct adhoc_state *ap = user_data;

	switch (event) {
	case NETDEV_WATCH_EVENT_DOWN:
		adhoc_reset(ap);
		break;
	default:
		break;
	}
}

static struct eapol_sm *adhoc_new_sm(struct sta_state *sta, bool authenticator)
{
	struct netdev *netdev = device_get_netdev(sta->adhoc->device);
	struct adhoc_state *adhoc = sta->adhoc;
	const uint8_t *own_addr = netdev_get_address(netdev);
	struct ie_rsn_info rsn;
	uint8_t bss_rsne[24];
	struct handshake_state *hs;
	struct eapol_sm *sm;

	/* fill in only what handshake setup requires */
	adhoc_set_rsn_info(adhoc, &rsn);
	ie_build_rsne(&rsn, bss_rsne);

	hs = netdev_handshake_state_new(netdev);
	if (!hs) {
		l_error("could not create handshake object");
		return NULL;
	}

	handshake_state_set_event_func(hs, adhoc_handshake_event, sta);
	handshake_state_set_ssid(hs, (void *)adhoc->ssid, strlen(adhoc->ssid));
	/* we dont have the connecting peer rsn info, so just set ap == own */
	handshake_state_set_ap_rsn(hs, bss_rsne);
	handshake_state_set_own_rsn(hs, bss_rsne);
	handshake_state_set_pmk(hs, adhoc->pmk, 32);

	if (authenticator) {
		handshake_state_set_authenticator_address(hs, own_addr);
		handshake_state_set_supplicant_address(hs, sta->addr);
	} else {
		handshake_state_set_authenticator_address(hs, sta->addr);
		handshake_state_set_supplicant_address(hs, own_addr);
	}

	sm = eapol_sm_new(hs);
	if (!sm) {
		l_error("could not create sm object");
		return NULL;
	}

	eapol_sm_set_listen_interval(sm, 100);
	eapol_sm_set_protocol_version(sm, EAPOL_PROTOCOL_VERSION_2004);

	if (authenticator)
		sta->hs_auth = hs;
	else
		sta->hs_sta = hs;

	return sm;
}

static void adhoc_free(struct adhoc_state *adhoc)
{
	adhoc_reset(adhoc);

	netdev_watch_remove(device_get_netdev(adhoc->device),
			adhoc->netdev_watch_id);

	l_free(adhoc);
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

static void adhoc_del_station(struct adhoc_state *adhoc, const uint8_t *mac)
{
	struct sta_state *sta;

	sta = l_queue_find(adhoc->sta_states, ap_sta_match_addr, mac);
	if (!sta) {
		l_warn("could not find station "MAC" in list", MAC_STR(mac));
		return;
	}

	l_debug("lost station "MAC, MAC_STR(mac));

	adhoc_remove_sta(sta);
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

static void adhoc_join_cb(struct netdev *netdev, int result, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct l_dbus_message *reply;

	if (result < 0) {
		l_error("Failed to join adhoc network, %i", result);

		if (adhoc->pending) {
			reply = dbus_error_failed(adhoc->pending);

			dbus_pending_reply(&adhoc->pending, reply);

			adhoc->pending = NULL;
		}

		return;
	}

	adhoc->sta_watch_id = netdev_station_watch_add(netdev,
			adhoc_station_changed_cb, adhoc);

	reply = l_dbus_message_new_method_return(adhoc->pending);

	dbus_pending_reply(&adhoc->pending, reply);

	adhoc->started = true;
}

static struct l_dbus_message *adhoc_dbus_start(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct adhoc_state *adhoc = user_data;
	struct device *device = adhoc->device;
	struct netdev *netdev = device_get_netdev(device);
	const char *ssid, *wpa2_psk;

	if (!l_dbus_message_get_arguments(message, "ss", &ssid, &wpa2_psk))
		return dbus_error_invalid_args(message);

	adhoc->ssid = l_strdup(ssid);
	adhoc->pending = l_dbus_message_ref(message);
	adhoc->sta_states = l_queue_new();

	if (crypto_psk_from_passphrase(wpa2_psk, (uint8_t *) ssid,
			strlen(ssid), adhoc->pmk))
		return dbus_error_invalid_args(message);

	if (netdev_join_adhoc(netdev, ssid, adhoc_join_cb, adhoc))
		return dbus_error_invalid_args(message);

	return NULL;
}

static void adhoc_leave_cb(struct netdev *netdev, int result, void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	if (!adhoc->pending)
		goto end;

	if (result < 0) {
		l_error("Failed to join adhoc network, %i", result);

		dbus_pending_reply(&adhoc->pending,
				dbus_error_failed(adhoc->pending));

		return;
	}

	dbus_pending_reply(&adhoc->pending,
			l_dbus_message_new_method_return(adhoc->pending));

end:
	adhoc_reset(adhoc);
}

static struct l_dbus_message *adhoc_dbus_stop(struct l_dbus *dbus,
		struct l_dbus_message *message, void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	if (adhoc->pending)
		return dbus_error_busy(message);

	/* already stopped, no-op */
	if (!adhoc->started)
		return l_dbus_message_new_method_return(message);

	if (!netdev_leave_adhoc(device_get_netdev(adhoc->device),
			adhoc_leave_cb, adhoc))
		return dbus_error_failed(message);

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

	l_dbus_message_builder_append_basic(builder, 's', macstr);
}

static bool adhoc_property_get_peers(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	l_dbus_message_builder_enter_array(builder, "s");

	l_queue_foreach(adhoc->sta_states, sta_append, builder);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void adhoc_setup_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "Start", 0, adhoc_dbus_start, "",
			"ss", "ssid", "wpa2_psk");
	l_dbus_interface_method(interface, "Stop", 0, adhoc_dbus_stop, "", "");
	l_dbus_interface_property(interface, "ConnectedPeers", 0, "as",
			adhoc_property_get_peers, NULL);
}

static void adhoc_destroy_interface(void *user_data)
{
	struct adhoc_state *adhoc = user_data;

	adhoc_free(adhoc);
}

bool adhoc_init(void)
{
	return l_dbus_register_interface(dbus_get_bus(), IWD_ADHOC_INTERFACE,
			adhoc_setup_interface, adhoc_destroy_interface, false);
}

void adhoc_exit(void)
{
	l_dbus_unregister_interface(dbus_get_bus(), IWD_ADHOC_INTERFACE);
}

bool adhoc_add_interface(struct device *device)
{
	struct adhoc_state *adhoc;

	/* just allocate/set device, Start method will complete setup */
	adhoc = l_new(struct adhoc_state, 1);
	adhoc->device = device;

	adhoc->netdev_watch_id = netdev_watch_add(device_get_netdev(device),
			adhoc_netdev_notify, adhoc);

	/* setup ap dbus interface */
	return l_dbus_object_add_interface(dbus_get_bus(),
			device_get_path(device), IWD_ADHOC_INTERFACE, adhoc);
}

bool adhoc_remove_interface(struct device *device)
{
	return l_dbus_object_remove_interface(dbus_get_bus(),
			device_get_path(device), IWD_ADHOC_INTERFACE);
}
