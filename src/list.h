/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

/*
 * String list management routines.
 */

#ifndef _JOHN_LIST_H
#define _JOHN_LIST_H

/*
 * String list entry, allocated as (sizeof(struct list_entry) + strlen(data)).
 */
struct list_entry {
	struct list_entry *next;

	char data[1];
};

/*
 * Main string list structure, head is used to start scanning the list, while
 * tail is used to add new entries.
 */
struct list_main {
	struct list_entry *head, *tail;

	int count;
};

/*
 * Initializes an empty string list.
 */
extern void list_init(struct list_main **list);

/*
 * Adds an entry to the list.
 */
extern void list_add(struct list_main *list, char *data);

/*
 * Adds multiple entries to the list from a comma-separated string.
 */
extern void list_add_multi(struct list_main *list, char *data);

/*
 * Adds an entry to the list checking for dupes. This is slow, and should
 * only be used on tiny lists.
 */
extern void list_add_unique(struct list_main *list, char *data);

/*
 * Deletes the entry following prev from the list.
 */
extern void list_del_next(struct list_main *list, struct list_entry *prev);

#endif
