/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
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
 * Adds an existing list to a list, using just pointers.
 */
extern void list_add_list(struct list_main *list, struct list_main *list2);

/*
 * Adds a previously allocated entry to the list.
 */
extern void list_add_link(struct list_main *list, struct list_entry *entry);

/*
 * Adds multiple entries to the list from a comma-separated string.
 */
extern void list_add_multi(struct list_main *list, char *data);

/*
 * Adds an entry to the list checking for dupes.  This is slow, and should
 * only be used on tiny lists.
 */
extern void list_add_unique(struct list_main *list, char *data);

/*
 * Adds an entry to the list checking for dupes.  This version checks for
 * dupes against a 'global' list as well.
 */
extern void list_add_global_unique(struct list_main *list,
                                   struct list_main *global, char *data);

/*
 * print list to stderr preceded by message.
 */
extern void list_dump(char *message, struct list_main *list);

#if 0
/*
 * Deletes the entry following prev from the list.
 */
extern void list_del_next(struct list_main *list, struct list_entry *prev);
#endif

/*
 * Returns 1 if the list contains 'data'.
 */
extern int list_check(struct list_main *list, char *data);

/*
 * Gets 'cnt' entries starting from offset 'off' from list 'src'.
 * Adds the above entries to list 'dst'.
 * Returns 1 on success.
 */
int list_extract_list(struct list_main *dst, struct list_main *src,
		int off, int cnt);

#endif
