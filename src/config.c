/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2009 by Solar Designer
 *
 * ...with changes in the jumbo patch, by magnum
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
#include "logger.h"
#include "external.h"

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

char *cfg_name = NULL;
static struct cfg_section *cfg_database = NULL;
static int cfg_recursion;
static int cfg_process_directive(char *line, int number);

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
	entry->cfg_name = cfg_name;

	list = cfg_database->list;
	if (list->tail) {
		entry->id = list->tail->id + 1;
		list->tail = list->tail->next = entry;
	}
	else {
		entry->id = 0;
		list->tail = list->head = entry;
	}
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
	if (!*line || *line == '#' || *line == ';')
		return 0;
	if (*line == '.')
		return cfg_process_directive(line, number);
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
#ifdef HAVE_MPI
	if (mpi_id == 0)
#endif
	fprintf(stderr, "Error in %s at line %d\n",
		path_expand(name), number);
	error();
}

void cfg_init(char *name, int allow_missing)
{
	FILE *file;
	char line[LINE_BUFFER_SIZE];
	int number;

	if (cfg_database && !cfg_recursion) return;

	cfg_name = str_alloc_copy(path_expand(name));
	file = fopen(cfg_name, "r");
	if (!file) {
		cfg_name = str_alloc_copy(path_expand_ex(name));
		file = fopen(cfg_name, "r");
		if (!file) {
			if (allow_missing && errno == ENOENT) return;
			pexit("fopen: %s", cfg_name);
		}
	}

	number = 0;
	while (fgetl(line, sizeof(line), file))
	if (cfg_process_line(line, ++number)) cfg_error(cfg_name, number);

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");
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

#ifndef BENCH_BUILD
void cfg_print_subsections(char *section, char *function, char *notfunction)
{
	struct cfg_section *current;
	char *p1, *p2;

	if ((current = cfg_database))
	do {
		p1 = current->name; p2 = section;
		while (*p1 && *p1 == tolower((int)(unsigned char)*p2)) {
			p1++; p2++;
		}
		if (*p1++ != ':') continue;
		if (!*p1 || *p2) continue;
		if (notfunction && ext_has_function(p1, notfunction))
			continue;
		if (!function || ext_has_function(p1, function))
			printf("%s\n", p1);
	} while ((current = current->next));
}
#endif
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

// Handle .include [section]
static int cfg_process_directive_include_section(char *line, int number)
{
	struct cfg_section *newsection;
	char *p = &line[10];
	char *p2 = strchr(&p[1], ']');
	char Section[256];
	if (!p2) {
		fprintf(stderr, "ERROR, invalid config include line:  %s\n", line);
#ifndef BENCH_BUILD
		log_event ("! Error, invalid config include line:  %s", line);
#endif
		return 1;
	}
	if (!cfg_database || !cfg_database->name) {
		fprintf(stderr, "ERROR, invalid section include, when not in a section:  %s\n", line);
#ifndef BENCH_BUILD
		log_event ("! ERROR, invalid section include, when not in a section:  %s", line);
#endif
		return 1;
	}
	*p2 = 0;
	strlwr(p);
	if (!strcmp(cfg_database->name, p)) {
		fprintf(stderr, "ERROR, invalid to load the current section (recursive):  %s\n", line);
#ifndef BENCH_BUILD
		log_event ("! ERROR, invalid to load the current section (recursive):  %s", line);
#endif
		return 1;
	}
	p = strtok(p, ":");
	p2 = strtok(NULL, "");
	if (!p || !p2) {
		fprintf(stderr, "ERROR, invalid .include line, can not find this section:  %s\n", line);
#ifndef BENCH_BUILD
		log_event("! ERROR, invalid .include line, can not find this section:  %s", line);
#endif
		return 1;
	}
	*Section = ':';
	strnzcpy(&Section[1], p2, 254);
	if ((newsection = cfg_get_section(p, Section))) {
		if (newsection->list) {
			struct cfg_line *pLine = newsection->list->head;
			while (pLine) {
				cfg_add_line(pLine->data, number);
				pLine = pLine->next;
			}
			return 0;
		}
		else {
			struct cfg_param *current = newsection->params;
			while (current) {
				cfg_add_param(current->name, current->value);
				current = current->next;
			}
			return 0;
		}
	}
	fprintf(stderr, "ERROR, could not find include section:  %s%s]\n", line, Section);
#ifndef BENCH_BUILD
	log_event("! ERROR, could not find include section:  %s%s]", line, Section);
#endif
	return 1;
}

// Handle a .include "file"   or a .include <file>
static int cfg_process_directive_include_config(char *line, int number)
{
	char *p, *p2, *saved_fname;
	char Name[PATH_BUFFER_SIZE];
	// Ok, we are including a file.
	if (!strncmp(line, ".include \"", 10)) {
		p = &line[10];
		p2 = strchr(&p[1], '\"');
		if (!p2) {
			fprintf(stderr, "ERROR, invalid config include line:  %s\n", line);
#ifndef BENCH_BUILD
			log_event("! ERROR, invalid config include line:  %s", line);
#endif
			return 1;
		}
		*p2 = 0;
		strnzcpy(Name, p, PATH_BUFFER_SIZE);
	}
	else {
		p = &line[10];
		p2 = strchr(&p[1], '>');
		if (!p2) {
			fprintf(stderr, "ERROR, invalid config include line:  %s\n", line);
#ifndef BENCH_BUILD
			log_event("! ERROR, invalid config include line:  %s", line);
#endif
			return 1;
		}
		*p2 = 0;
		strcpy(Name, "$JOHN/");
		strnzcpy(&Name[6], p, PATH_BUFFER_SIZE - 6);
	}
	if (cfg_recursion == 20) {
		fprintf(stderr, "ERROR, .include recursion too deep in john.ini processing file .include \"%s\"\n", p);
#ifndef BENCH_BUILD
		log_event("! ERROR, .include recursion too deep in john.ini processing file .include \"%s\"", p);
#endif
		return 1;
	}
	saved_fname = cfg_name;
	cfg_recursion++;
	cfg_init(Name, 0);
	cfg_recursion--;
	cfg_name = saved_fname;
	return 0;
}

// Handle a .directive line.  Curently only .include syntax is handled.
static int cfg_process_directive(char *line, int number)
{
	if (!strncmp(line, ".include \"", 10) || !strncmp(line, ".include <", 10))
		return cfg_process_directive_include_config(line, number);
	if (!strncmp(line, ".include [", 10))
		return cfg_process_directive_include_section(line, number);
	fprintf (stderr, "Unknown directive in the .conf file:  '%s'\n", line);
#ifndef BENCH_BUILD
	log_event("! Unknown directive in the .conf file:  %s", line);
#endif
	return 1;
}
