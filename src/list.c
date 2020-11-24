/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>

#include "memory.h"
#include "list.h"

void list_init(struct list_main **list)
{
	*list = mem_alloc_tiny(sizeof(struct list_main), MEM_ALIGN_WORD);
	(*list)->tail = (*list)->head = NULL;
	(*list)->count = 0;
}

void list_add(struct list_main *list, char *data)
{
	struct list_entry *entry;

	entry = mem_alloc_tiny(sizeof(struct list_entry) + strlen(data),
		MEM_ALIGN_WORD);
	strcpy(entry->data, data);

	list_add_link(list, entry);
}

void list_add_list(struct list_main *list, struct list_main *list2)
{
	if (list->tail)
		list->tail->next = list2->head;
	else
		list->head = list2->head;
	list->tail = list2->tail;

	list->count += list2->count;
}

void list_add_link(struct list_main *list, struct list_entry *entry)
{
	entry->next = NULL;

	if (list->tail)
		list->tail = list->tail->next = entry;
	else
		list->tail = list->head = entry;

	list->count++;
}

void list_add_unique(struct list_main *list, char *data)
{
	struct list_entry *current;

	if ((current = list->head))
	do {
		if (!strcmp(current->data, data)) return;
	} while ((current = current->next));

	list_add(list, data);
}

void list_add_multi(struct list_main *list, char *data)
{
	char *comma;

	do {
		if ((comma = strchr(data, ',')))
			*comma = 0;

		list_add_unique(list, data);

		data = comma + 1;
		if (comma)
			*comma = ',';
	} while (comma);
}

void list_add_global_unique(struct list_main *list, struct list_main *global,
                            char *data)
{
	struct list_entry *current;

	if ((current = list->head))
	do {
		if (!strcmp(current->data, data)) return;
	} while ((current = current->next));

	if (list != global && (current = global->head))
	do {
		if (!strcmp(current->data, data)) return;
	} while ((current = current->next));

	list_add(list, data);
}

void list_dump(char *message, struct list_main *list)
{
	struct list_entry *current;

	fprintf(stderr, "%s:\n", message);

	if ((current = list->head))
	do {
		fprintf(stderr, "%s\n", current->data);
	} while ((current = current->next));
}

#if 0
void list_del_next(struct list_main *list, struct list_entry *prev)
{
	if (prev) {
		if (!(prev->next = prev->next->next)) list->tail = prev;
	} else
		if (!(list->head = list->head->next)) list->tail = NULL;
	list->count--;
}
#endif

int list_check(struct list_main *list, char *data)
{
	struct list_entry *current;

	for (current = list->head; current; current = current->next)
		if (!strcmp(current->data, data))
			return 1;

	return 0;
}

int list_extract_list(struct list_main *dst, struct list_main *src,
		int off, int cnt)
{
	struct list_entry *current;
	int curr_cnt = 0;

	if (!dst || !src || src->count < off + cnt)
		return 0;

	for (current = src->head; current; current = current->next)
		if (curr_cnt == off)
			break;
		else
			curr_cnt++;

	while (1) {
		if (off + cnt < ++curr_cnt)
			return 1;
		list_add(dst, current->data);
		current = current->next;
	}

	return 1;
}
