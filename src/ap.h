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

enum ap_event {
	AP_EVENT_STARTED,
	AP_EVENT_STOPPED,
};

struct device;

typedef void (*ap_event_cb_t)(struct device *device, enum ap_event event_type);

int ap_start(struct device *device, const char *ssid, const char *psk,
		ap_event_cb_t event_cb);
int ap_stop(struct device *device);

void ap_init(struct l_genl_family *in);
void ap_exit(void);
