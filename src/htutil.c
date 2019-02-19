/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>

#include <ell/ell.h>

#include "util.h"
#include "htutil.h"

#include "linux/nl80211.h"

enum ht_channel_width {
	HT_CHANNEL_WIDTH_20MHZ = 0,
	HT_CHANNEL_WIDTH_40MHZ,
};

/*
 * Base RSSI values for 20MHz channel. These values can be used to calculate
 * the minimum RSSI values for all other channel widths.
 */
static int32_t base_rssi[] = { -82, -79, -77, -74, -70, -66, -65, -64 };

struct ht_rate {
	uint64_t rate;
	uint64_t sgi_rate;
};

static struct ht_rate ht_rates[] = {
	[HT_CHANNEL_WIDTH_20MHZ] = { .rate = 6500000, .sgi_rate = 7200000 },
	[HT_CHANNEL_WIDTH_40MHZ] = { .rate = 13500000, .sgi_rate = 15000000 },
};

static bool calculate_ht_data_rate(uint8_t index, int32_t rssi,
				bool support_40mhz, bool short_gi,
				uint64_t *data_rate)
{
	uint64_t base_rate;
	int32_t width_adjust = (support_40mhz) ? 3 : 0;
	struct ht_rate *rate;

	l_debug("MCS: %u, RSSI: %d, 40MHZ: %u, SGI: %u", index, rssi, support_40mhz, short_gi);

	if (rssi < base_rssi[index % 8] + width_adjust)
		return false;

	/* Found an acceptable MCS index */

	if (support_40mhz)
		rate = &ht_rates[HT_CHANNEL_WIDTH_40MHZ];
	else
		rate = &ht_rates[HT_CHANNEL_WIDTH_20MHZ];

	base_rate = (short_gi) ? rate->sgi_rate : rate->rate;

	/* Adjust base by spatial streams */
	base_rate *= ((index / 8) + 1);

	/*
	 * Adjust base by MCS index. The relative index per spatial streams
	 * jumps from 4 to 6 after relative index 4, hence the check here.
	 */
	if ((index % 8) + 1 <= 4)
		base_rate *= ((index % 8) + 1);
	else
		base_rate *= ((index % 8) + 3);

	*data_rate = base_rate;

	return true;
}

bool ht_calculate_data_rate(const uint8_t ht_ie[26], int32_t rssi,
				uint64_t *data_rate)
{
	const uint8_t *data = ht_ie;
	uint8_t ht_cap;
	int i;
	bool support_40mhz = false;
	bool short_gi = false;

	/* Parse out channel width set and short GI */
	ht_cap = l_get_u8(data++);

	if (util_is_bit_set(ht_cap, 1))
		support_40mhz = true;;

	if (!support_40mhz && util_is_bit_set(ht_cap, 5))
		short_gi = true;

	if (support_40mhz && util_is_bit_set(ht_cap, 6))
		short_gi = true;

	data += 2;

	/*
	 * TODO: Support MCS values 32 - 76
	 *
	 * The MCS values > 31 do not follow the same pattern since they use
	 * unequal modulation per spatial stream. These higher MCS values
	 * actually don't follow a pattern at all, since each stream can have a
	 * different modulation a higher MCS value does not mean higher
	 * throughput. For this reason these MCS indexes are left out.
	 */
	for (i = 31; i >= 0; i--) {
		uint8_t byte = i / 8;
		uint8_t bit = i % 8;

		if (util_is_bit_set(data[byte], bit)) {
			if (calculate_ht_data_rate(i, rssi, support_40mhz,
						short_gi, data_rate))
				return true;
		}
	}

	return false;
}

struct basic_rate_map {
	int32_t rssi;
	uint8_t rate;
};

/*
 * We have to store this mapping since basic rates dont come with a convenient
 * MCS index. Rates are stored as they are encoded in the Supported Rates IE.
 * This does not include non 802.11g data rates, e.g. 1/2/4Mbps. This data was
 * taken from 802.11 Section 17.3.10.2 and Table 10-7.
 *
 * Section 17.3.10.2 defines minimum RSSI for modulations, and Table
 * 10-7 defines reference rates for the different modulations. Together we
 * have minimum RSSI required for a given data rate.
 */
static struct basic_rate_map rate_rssi_map[] = {
	{ -82, 12 },
	{ -81, 18 },
	{ -79, 24 },
	{ -77, 36 },
	{ -74, 48 },
	{ -70, 72 },
	{ -66, 96 },
	{ -65, 108 },
};

bool basic_calculate_data_rate(struct l_uintset *rates, int32_t rssi,
				uint32_t chan_width, uint8_t *data_rate)
{
	int i;
	int32_t width_adjust = 0;

	if (chan_width == NL80211_BSS_CHAN_WIDTH_10)
		width_adjust = 3;
	else if (chan_width == NL80211_BSS_CHAN_WIDTH_5)
		width_adjust = 6;

	for (i = L_ARRAY_SIZE(rate_rssi_map) - 1; i >= 0; i--) {
		struct basic_rate_map *map = &rate_rssi_map[i];

		l_debug("Checking rate: %u, cur_rssi=%d, min_rssi=%d", map->rate, rssi, map->rssi - width_adjust);

		if (l_uintset_contains(rates, map->rate) &&
					rssi > map->rssi - width_adjust) {
			*data_rate = map->rate;
			return true;
		}
	}

	/*
	 * Either our RSSI was very low or 'rates' only included data rates
	 * lower than 6 Mbps. In either case this is probably not a great BSS
	 * to connect to.
	 */

	return false;
}
