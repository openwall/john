/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2009,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "config.h"
#include "john.h"

char *cfg_name = NULL;
static struct cfg_section *cfg_database = NULL;

static char *trim(char *s)
{
	char *e;

	while (*s && (*s == ' ' || *s == '\t')) s++;
	if (!*s) return s;

	e = s + strlen(s) - 1;
	while (e >= s && (*e == ' ' || *e == '\t')) e--;
	*++e = 0;
	return s;
}

static void cfg_add_section(char *name)
{
	struct cfg_section *last;

	last = cfg_database;
	cfg_database = mem_alloc_tiny(
		sizeof(struct cfg_section), MEM_ALIGN_WORD);
	cfg_database->next = last;

	cfg_database->name = str_alloc_copy(name);
	cfg_database->params = NULL;

	if (!strncmp(name, "list.", 5)) {
		cfg_database->list = mem_alloc_tiny(
			sizeof(struct cfg_list), MEM_ALIGN_WORD);
		cfg_database->list->head = cfg_database->list->tail = NULL;
	} else {
		cfg_database->list = NULL;
	}
}

static void cfg_add_line(char *line, int number)
{
	struct cfg_list *list;
	struct cfg_line *entry;

	entry = mem_alloc_tiny(sizeof(struct cfg_line), MEM_ALIGN_WORD);
	entry->next = NULL;

	entry->data = str_alloc_copy(line);
	entry->number = number;

	list = cfg_database->list;
	if (list->tail)
		list->tail = list->tail->next = entry;
	else
		list->tail = list->head = entry;
}

static void cfg_add_param(char *name, char *value)
{
	struct cfg_param *current, *last;

	last = cfg_database->params;
	current = cfg_database->params = mem_alloc_tiny(
		sizeof(struct cfg_param), MEM_ALIGN_WORD);
	current->next = last;

	current->name = str_alloc_copy(name);
	current->value = str_alloc_copy(value);
}

static int cfg_process_line(char *line, int number)
{
	char *p;

	line = trim(line);
	if (!*line || *line == '#' || *line == ';') return 0;

	if (*line == '[') {
		if ((p = strchr(line, ']'))) *p = 0; else return 1;
		cfg_add_section(strlwr(trim(line + 1)));
	} else
	if (cfg_database && cfg_database->list) {
		cfg_add_line(line, number);
	} else
	if (cfg_database && (p = strchr(line, '='))) {
		*p++ = 0;
		cfg_add_param(strlwr(trim(line)), trim(p));
	} else {
		return 1;
	}

	return 0;
}

static void cfg_error(char *name, int number)
{
	if (john_main_process)
		fprintf(stderr, "Error in %s at line %d\n",
		    path_expand(name), number);
	error();
}

void cfg_init(char *name, int allow_missing)
{
	FILE *file;
	char line[LINE_BUFFER_SIZE];
	int number;

	if (cfg_database) return;

	if (!(file = fopen(path_expand(name), "r"))) {
		if (allow_missing && errno == ENOENT) return;
		pexit("fopen: %s", path_expand(name));
	}

	number = 0;
	while (fgetl(line, sizeof(line), file))
	if (cfg_process_line(line, ++number)) cfg_error(name, number);

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");

	cfg_name = str_alloc_copy(path_expand(name));
}

static struct cfg_section *cfg_get_section(char *section, char *subsection)
{
	struct cfg_section *current;
	char *p1, *p2;

	if ((current = cfg_database))
	do {
		p1 = current->name; p2 = section;
		while (*p1 && *p1 == tolower((int)(unsigned char)*p2)) {
			p1++; p2++;
		}
		if (*p2) continue;

		if ((p2 = subsection))
		while (*p1 && *p1 == tolower((int)(unsigned char)*p2)) {
			p1++; p2++;
		}
		if (*p1) continue;
		if (p2) if (*p2) continue;

		return current;
	} while ((current = current->next));

	return NULL;
}

struct cfg_list *cfg_get_list(char *section, char *subsection)
{
	struct cfg_section *current;

	if ((current = cfg_get_section(section, subsection)))
		return current->list;

	return NULL;
}

char *cfg_get_param(char *section, char *subsection, char *param)
{
	struct cfg_section *current_section;
	struct cfg_param *current_param;
	char *p1, *p2;

	if ((current_section = cfg_get_section(section, subsection)))
	if ((current_param = current_section->params))
	do {
		p1 = current_param->name; p2 = param;
		while (*p1 && *p1 == tolower((int)(unsigned char)*p2)) {
			p1++; p2++;
		}
		if (*p1 || *p2) continue;

		return current_param->value;
	} while ((current_param = current_param->next));

	return NULL;
}

int cfg_get_int(char *section, char *subsection, char *param)
{
	char *s_value, *error;
	long l_value;

	if ((s_value = cfg_get_param(section, subsection, param))) {
		l_value = strtol(s_value, &error, 10);
		if (!*s_value || *error || (l_value & ~0x3FFFFFFFL))
			return -1;
		return (int)l_value;
	}

	return -1;
}

int cfg_get_bool(char *section, char *subsection, char *param, int def)
{
	char *value;

	if (!(value = cfg_get_param(section, subsection, param)))
		return def;

	switch (*value) {
	case 'y':
	case 'Y':
	case 't':
	case 'T':
	case '1':
		return 1;
	}

	return 0;
}
