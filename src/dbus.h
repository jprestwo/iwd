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

#include <stdbool.h>

#define IWD_SERVICE "net.connman.iwd"

#define IWD_AGENT_MANAGER_INTERFACE "net.connman.iwd.AgentManager"
#define IWD_WIPHY_INTERFACE "net.connman.iwd.Adapter"
#define IWD_DEVICE_INTERFACE "net.connman.iwd.Device"
#define IWD_NETWORK_INTERFACE "net.connman.iwd.Network"
#define IWD_AGENT_INTERFACE "net.connman.iwd.Agent"
#define IWD_WSC_INTERFACE "net.connman.iwd.WiFiSimpleConfiguration"
#define IWD_KNOWN_NETWORKS_INTERFACE "net.connman.iwd.KnownNetworks"
#define IWD_SIGNAL_AGENT_INTERFACE "net.connman.iwd.SignalLevelAgent"

#define IWD_AGENT_MANAGER_PATH "/"
#define IWD_KNOWN_NETWORKS_PATH "/"

struct l_dbus;

struct l_dbus *dbus_get_bus(void);

void dbus_pending_reply(struct l_dbus_message **msg,
				struct l_dbus_message *reply);

void dbus_dict_append_string(struct l_dbus_message_builder *builder,
				const char *key, const char *strval);
void dbus_dict_append_bool(struct l_dbus_message_builder *builder,
				const char *key, bool boolval);
void dbus_dict_append_object(struct l_dbus_message_builder *builder,
				const char *key, const char *object_path);
void dbus_dict_append_bytearray(struct l_dbus_message_builder *builder,
				const char *key, const uint8_t *arrayval,
				const int len);

struct l_dbus_message *dbus_error_busy(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_failed(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_aborted(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_available(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_invalid_args(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_invalid_format(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_already_exists(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_found(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_supported(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_no_agent(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_connected(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_configured(struct l_dbus_message *msg);
struct l_dbus_message *dbus_error_not_implemented(struct l_dbus_message *msg);

bool dbus_init(bool enable_debug);
bool dbus_exit(void);
void dbus_shutdown(void);
