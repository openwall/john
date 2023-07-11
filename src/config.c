/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2009,2013,2019 by Solar Designer
 *
 * ...with changes in the jumbo patch, by magnum and JimF
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
#include "logger.h"
#include "external.h"
#ifndef BENCH_BUILD
#include "options.h"
#endif

char *cfg_name = NULL;
static struct cfg_section *cfg_database = NULL;
static int cfg_recursion;
static int cfg_process_directive(char *line, int number, int in_hcmode);
static int cfg_loading_john_local, cfg_loaded_john_local;

/* we have exposed this to the dyna_parser file, so that it can easily
 * walk the configuration list one time, to determine which dynamic formats
 * are in the file.  Before we would walk the entire configuration list
 * 4000 times. Now only 1 time. We return the pointer to this data in
 * a const manner, telling the outside function to NOT make changes.
 */
const struct cfg_section *get_cfg_db() {
	return cfg_database;
}

static char *trim(char *s, int right)
{
	while (*s == ' ' || *s == '\t')
		s++;

	if (!*s)
		return s;

	if (right) {
		char *e = s + strlen(s) - 1;
		while (*e == ' ' || *e == '\t') {
			*e = 0;
			if (e == s)
				break;
			e--;
		}
	}

	return s;
}

static int cfg_merge_local_section() {
	struct cfg_section *parent;
	struct cfg_param *p1, *p2;

	if (!cfg_database) return 0;
	if (strncmp(cfg_database->name, "local:", 6)) return 0;
	if (!strncmp(cfg_database->name, "local:list.", 11)) return 0;
	parent = (struct cfg_section*)cfg_get_section(&cfg_database->name[6], NULL);
	if (!parent) return 0;
	// now update the params in parent section
	p1 = cfg_database->params;
	while (p1) {
		int found = 0;
		p2 = parent->params;
		while (p2) {
			if (!strcmp(p1->name, p2->name)) {
				found = 1;
				p2->value = p1->value;
				break;
			}
			p2 = p2->next;
		}
		if (!found) {
			// add a new item. NOTE, fixes bug #767
			// https://github.com/openwall/john/issues/767
#if ARCH_ALLOWS_UNALIGNED
			struct cfg_param *p3 = (struct cfg_param*)mem_alloc_tiny(sizeof(struct cfg_param), 1);
#else
			struct cfg_param *p3 = (struct cfg_param*)mem_alloc_tiny(sizeof(struct cfg_param), MEM_ALIGN_WORD);
#endif
			p3->next = parent->params;
			p3->name = p1->name;
			p3->value = p1->value;
			parent->params = p3;
		}
		p1 = p1->next;
	}
	return 1;
}

static void cfg_add_section(const char *name)
{
	struct cfg_section *last;
	int merged;

	// if the last section was a 'Local:" section, then merge it.
	merged = cfg_merge_local_section();
	if (!merged && !strncmp(name, "list.", 5)) {
		last = cfg_database;
		while (last) {
			if (!strcmp(last->name, name)) {
				if (!cfg_loading_john_local) {
					if (john_main_process)
						fprintf(stderr, "Warning! john.conf section [%s] is multiple declared.\n", name);
				}
#ifndef BENCH_BUILD
				else if (john_main_process && options.verbosity >= VERB_DEFAULT)
					fprintf(stderr, "Warning! Section [%s] overridden by john-local.conf\n", name);
#endif
				break;
			}
			last = last->next;
		}
	}
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

static void cfg_add_line(const char *line, int number)
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

static void cfg_add_param(const char *name, const char *value)
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
	static int in_hc_mode;

	line = trim(line, 0);
	if (*line == '!' && line[1] == '!') {
		if (!strcmp(line, "!! hashcat logic ON"))
			in_hc_mode = 1;
		else if (!strcmp(line, "!! hashcat logic OFF"))
			in_hc_mode = 0;

	}
	if (!*line || *line == '#' || *line == ';')
		return 0;
	if (*line == '.') {
		int ret = cfg_process_directive(line, number, in_hc_mode);
		if (ret != -1)
			return ret;
	}
	if (*line == '[' && !in_hc_mode) {
		if ((p = strchr(line, ']'))) *p = 0; else return 1;
		cfg_add_section(strlwr(trim(line + 1, 1)));
	} else
	if (cfg_database && cfg_database->list) {
		cfg_add_line(line, number);
	} else
	if (cfg_database && (p = strchr(line, '='))) {
		*p++ = 0;
		cfg_add_param(strlwr(trim(line, 1)), trim(p, 1));
	} else {
		return 1;
	}

	return 0;
}

static void cfg_error(const char *name, int number)
{
	if (john_main_process)
		fprintf(stderr, "Error in %s at line %d\n",
		    path_expand(name), number);
	error();
}

void cfg_init(const char *name, int allow_missing)
{
	FILE *file;
	char line[LINE_BUFFER_SIZE];
	int number;

	if (cfg_database && !cfg_recursion) return;

	cfg_name = str_alloc_copy(path_expand(name));

	if (!(file = fopen(cfg_name, "r"))) {
		if (allow_missing && errno == ENOENT) return;
		pexit("fopen: %s", cfg_name);
	}

	number = 0;
	while (fgetl(line, sizeof(line), file))
	if (cfg_process_line(line, ++number)) cfg_error(name, number);

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");

	// merge final section (if it is a 'Local:" section)
	cfg_merge_local_section();
}

const struct cfg_section *cfg_get_section(const char *section, const char *subsection)
{
	const struct cfg_section *current;
	const char *p1, *p2;

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

struct cfg_list *cfg_get_list(const char *section, const char *subsection)
{
	const struct cfg_section *current;

	if ((current = cfg_get_section(section, subsection)))
		return current->list;

	return NULL;
}

#ifndef BENCH_BUILD
void cfg_print_section_names(int which)
{
	struct cfg_section *current;

	if ((current = cfg_database))
	do {
		if ((which == 0) ||
		    (which == 1 && current->params != NULL) ||
		    (which == 2 && current->list != NULL))
			printf("%s\n", current->name);
	} while ((current = current->next));
}

int cfg_print_section_params(const char *section, const char *subsection)
{
	const struct cfg_section *current;
	const struct cfg_param *param;
	const char *value;
	int param_count = 0;

	if ((current = cfg_get_section(section, subsection))) {
		if ((param = current->params))
		do {
			value = cfg_get_param(section, subsection, param->name);
			if (!strcmp(param->value, value)) {
				printf("%s = %s\n", param->name, param->value);
				param_count++;
			}
		} while ((param = param-> next));
		return param_count;
	}
	else return -1;

}

int cfg_print_section_list_lines(const char *section, const char *subsection)
{
	const struct cfg_section *current;
	const struct cfg_line *line;
	int line_count = 0;

	if ((current = cfg_get_section(section, subsection))) {
		if (current->list && (line = current->list->head))
		do {
			// we only want to see the line contents
			// printf("%s-%d_%d:%s\n", line->cfg_name, line->id, line->number, line->data);
			printf("%s\n", line->data);
			line_count++;
		} while((line = line->next));
		return line_count;
	}
	else return -1;
}

int cfg_print_subsections(const char *section, const char *function, const char *notfunction, int print_heading)
{
	int ret = 0;
	const struct cfg_section *current;
	const char *p1, *p2;

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
		if (!function || ext_has_function(p1, function)) {
			if (ret == 0 && print_heading != 0)
				printf("Subsections of [%s]:\n", section);
			ret++;
			printf("%s\n", p1);
		}
	} while ((current = current->next));
	return ret;
}
#endif

const char *cfg_get_param(const char *section, const char *subsection, const char *param)
{
	const struct cfg_section *current_section;
	const struct cfg_param *current_param;
	const char *p1, *p2;

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

int cfg_get_int(const char *section, const char *subsection, const char *param)
{
	char *s_value, *error;
	long l_value;

	if ((s_value = (char*)cfg_get_param(section, subsection, param))) {
		l_value = strtol(s_value, &error, 10);
		if (!*s_value || *error || (l_value & ~0x3FFFFFFFL))
			return -1;
		return (int)l_value;
	}

	return -1;
}

void cfg_get_int_array(const char *section, const char *subsection, const char *param,
		int *array, int array_len)
{
	char *s_value, *error;
	long l_value;
	int i = 0;

	s_value = (char*)cfg_get_param(section, subsection, param);
	if (s_value) {
		for (;;) {
			if (!*s_value)
				break;
			l_value = strtol(s_value, &error, 10);
			if (error == s_value || (l_value & ~0x3FFFFFFFL))
				break;
			array[i++] = (int)l_value;
			if (!*error || i == array_len)
				break;
			s_value = error + 1;
		}
	}

	for ( ; i < array_len; i++)
		array[i] = -1;
}

int cfg_get_bool(const char *section, const char *subsection, const char *param, int def)
{
	const char *value;

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
	const struct cfg_section *newsection;
	char *p = &line[10];
	char *p2 = strchr(&p[1], ']');
	char Section[256];
	if (!p2) {
		if (john_main_process)
			fprintf(stderr, "ERROR, invalid config include line:  %s\n", line);
#ifndef BENCH_BUILD
		log_event ("! Error, invalid config include line:  %s", line);
#endif
		return 1;
	}
	if (!cfg_database || !cfg_database->name) {
		if (john_main_process)
			fprintf(stderr, "ERROR, invalid section include, when not in a section:  %s\n", line);
#ifndef BENCH_BUILD
		log_event ("! ERROR, invalid section include, when not in a section:  %s", line);
#endif
		return 1;
	}
	*p2 = 0;
	strlwr(p);
	if (!strcmp(cfg_database->name, p)) {
		if (john_main_process)
			fprintf(stderr, "ERROR, invalid to load the current section (recursive):  %s\n", line);
#ifndef BENCH_BUILD
		log_event ("! ERROR, invalid to load the current section (recursive):  %s", line);
#endif
		return 1;
	}
	p = strtokm(p, ":");
	p2 = strtokm(NULL, "");
	if (!p) {
		if (john_main_process)
			fprintf(stderr, "ERROR, invalid .include line, can not find this section:  %s\n", line);
#ifndef BENCH_BUILD
		log_event("! ERROR, invalid .include line, can not find this section:  %s", line);
#endif
		return 1;
	}
	*Section = ':';
	if (p2)
		strnzcpy(&Section[1], p2, 254);
	else
		*Section = 0;
	if ((newsection = cfg_get_section(p, Section))) {
		if (newsection->list) {
			// Must check cfg_database->list before cfg_add_line()
			if (NULL != cfg_database->list) {
				struct cfg_line *pLine = newsection->list->head;
				while (pLine) {
					cfg_add_line(pLine->data, number);
					pLine = pLine->next;
				}
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
	if (john_main_process)
		fprintf(stderr, "ERROR, could not find include section:  %s%s]\n", line, Section);
#ifndef BENCH_BUILD
	log_event("! ERROR, could not find include section:  %s%s]", line, Section);
#endif
	return 1;
}

// Handle a .include "file"   or a .include <file>   or a .include 'file'
static int cfg_process_directive_include_config(char *line, int number)
{
	char *p, *p2, *saved_fname;
	char Name[PATH_BUFFER_SIZE];
	int allow_missing = 0;

	// Ok, we are including a file.
	if (!strncmp(line, ".include \"", 10)) {
		p = &line[10];
		p2 = strchr(&p[1], '\"');
		if (!p2) {
			if (john_main_process)
				fprintf(stderr, "ERROR, invalid config include line:  %s\n", line);
#ifndef BENCH_BUILD
			log_event("! ERROR, invalid config include line:  %s", line);
#endif
			return 1;
		}
		*p2 = 0;
		strnzcpy(Name, p, PATH_BUFFER_SIZE);
	} else if (!strncmp(line, ".include '", 10)) {
		p = &line[10];
		p2 = strchr(&p[1], '\'');
		if (!p2) {
			if (john_main_process)
				fprintf(stderr, "ERROR, invalid config include line:  %s\n", line);
#ifndef BENCH_BUILD
			log_event("! ERROR, invalid config include line:  %s", line);
#endif
			return 1;
		}
		*p2 = 0;
		strnzcpy(Name, p, PATH_BUFFER_SIZE);
		allow_missing = 1;
	} else {
		p = &line[10];
		p2 = strchr(&p[1], '>');
		if (!p2) {
			if (john_main_process)
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
		if (john_main_process)
			fprintf(stderr, "ERROR, .include recursion too deep in john.ini processing file .include \"%s\"\n", p);
#ifndef BENCH_BUILD
		log_event("! ERROR, .include recursion too deep in john.ini processing file .include \"%s\"", p);
#endif
		return 1;
	}

	if (strstr(Name, "/john-local.conf")) {
		if (!strcmp(Name, "$JOHN/john-local.conf") ||
		    !strcmp(Name, "./john-local.conf")) {
			if (!strcmp(path_expand("$JOHN/"), "./") &&
			    cfg_loaded_john_local)
				return 0;
			else
				cfg_loaded_john_local = 1;
		}
		cfg_loading_john_local = 1;
	}
	saved_fname = cfg_name;
	cfg_recursion++;
	cfg_init(Name, allow_missing);
	cfg_recursion--;
	cfg_name = saved_fname;
	cfg_loading_john_local = 0;
	return 0;
}

// Handle a .directive line.  Currently only .include syntax is handled.
static int cfg_process_directive(char *line, int number, int in_hc_mode)
{
	if (!strncmp(line, ".include \"", 10) || !strncmp(line, ".include <", 10) || !strncmp(line, ".include '", 10))
		return cfg_process_directive_include_config(line, number);
	if (!strncmp(line, ".include [", 10))
		return cfg_process_directive_include_section(line, number);
	if (in_hc_mode)
		return -1;
	if (!strncmp(line, ".log ", 5))
		return -1;
	if (john_main_process)
		fprintf(stderr, "Unknown directive in the .conf file:  '%s'\n", line);
#ifndef BENCH_BUILD
	log_event("! Unknown directive in the .conf file:  %s", line);
#endif
	return 1;
}
