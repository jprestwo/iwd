/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2014-2016  Intel Corporation. All rights reserved.
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

#include <stddef.h>
#include <string.h>

#include "src/iwd.h"
#include "src/common.h"

const char *security_to_str(enum security security)
{
	switch (security) {
	case SECURITY_NONE:
		return "open";
	case SECURITY_WEP:
		return "wep";
	case SECURITY_PSK:
		return "psk";
	case SECURITY_8021X:
		return "8021x";
	}

	return NULL;
}

bool security_from_str(const char *str, enum security *security)
{
	if (!strcmp(str, "open"))
		*security = SECURITY_NONE;
	else if (!strcmp(str, "wep"))
		*security = SECURITY_WEP;
	else if (!strcmp(str, "psk"))
		*security = SECURITY_PSK;
	else if (!strcmp(str, "8021x"))
		*security = SECURITY_8021X;
	else
		return false;

	return true;
}
