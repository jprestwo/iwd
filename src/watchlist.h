/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016-2017  Intel Corporation. All rights reserved.
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

typedef void (*watchlist_item_destroy_func_t)(void *data);

struct watchlist_item {
	unsigned int id;
	void *notify;
	void *notify_data;
	watchlist_item_destroy_func_t destroy;
};

struct watchlist_ops {
	void (*item_free)(struct watchlist_item *item);
};

struct watchlist {
	int next_id;
	struct l_queue *items;
	bool in_notify : 1;
	bool stale_items : 1;
	const struct watchlist_ops *ops;
};

struct watchlist *watchlist_new(const struct watchlist_ops *ops);
void watchlist_init(struct watchlist *watchlist,
					const struct watchlist_ops *ops);
unsigned int watchlist_add(struct watchlist *watchlist, void *notify,
					void *notify_data,
					watchlist_item_destroy_func_t destroy);
unsigned int watchlist_link(struct watchlist *watchlist,
					struct watchlist_item *item,
					void *notify, void *notify_data,
					watchlist_item_destroy_func_t destroy);
bool watchlist_remove(struct watchlist *watchlist, unsigned int id);
void watchlist_destroy(struct watchlist *watchlist);
void watchlist_free(struct watchlist *watchlist);

void __watchlist_prune_stale(struct watchlist *watchlist);

#define WATCHLIST_NOTIFY(watchlist, type, args...)			\
	do {								\
		const struct l_queue_entry *entry =			\
				l_queue_get_entries((watchlist)->items);\
									\
		(watchlist)->in_notify = true;				\
		for (; entry; entry = entry->next) {			\
			struct watchlist_item *item = entry->data;	\
			type t = item->notify;				\
			t(args, item->notify_data);			\
		}							\
		(watchlist)->in_notify = false;				\
		if ((watchlist)->stale_items)				\
			__watchlist_prune_stale(watchlist);		\
	} while	(false)							\

#define WATCHLIST_NOTIFY_MATCHES(watchlist, match, match_data, type, args...) \
	do {								\
		const struct l_queue_entry *entry =			\
				l_queue_get_entries((watchlist)->items);\
									\
		(watchlist)->in_notify = true;				\
		for (; entry; entry = entry->next) {			\
			struct watchlist_item *item = entry->data;	\
			type t = item->notify;				\
									\
			if (!match(item, match_data))			\
				continue;				\
									\
			t(args, item->notify_data);			\
		}							\
		(watchlist)->in_notify = false;				\
		if ((watchlist)->stale_items)				\
			__watchlist_prune_stale(watchlist);		\
	} while	(false)

#define WATCHLIST_NOTIFY_NO_ARGS(watchlist, type)			\
	do {								\
		const struct l_queue_entry *entry =			\
				l_queue_get_entries((watchlist)->items);\
									\
		(watchlist)->in_notify = true;				\
		for (; entry; entry = entry->next) {			\
			struct watchlist_item *item = entry->data;	\
			type t = item->notify;				\
			t(item->notify_data);			\
		}							\
		(watchlist)->in_notify = false;				\
		if ((watchlist)->stale_items)				\
			__watchlist_prune_stale(watchlist);		\
	} while	(false)
