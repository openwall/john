/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2009 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Configuration file loader.
 */

#ifndef _JOHN_CONFIG_H
#define _JOHN_CONFIG_H

/*
 * Parameter list entry.
 */
struct cfg_param {
	struct cfg_param *next;
	char *name, *value;
};

/*
 * Line list entry.
 */
struct cfg_line {
	struct cfg_line *next;
	char *data;
	int number;
};

/*
 * Main line list structure, head is used to start scanning the list, while
 * tail is used to add new entries.
 */
struct cfg_list {
	struct cfg_line *head, *tail;
};

/*
 * Section list entry.
 */
struct cfg_section {
	struct cfg_section *next;
	char *name;
	struct cfg_param *params;
	struct cfg_list *list;
};

/*
 * Name of the currently loaded configuration file, or NULL for none.
 */
extern char *cfg_name;

/*
 * Loads a configuration file, or does nothing if one is already loaded.
 */
extern void cfg_init(char *name, int allow_missing);

/*
 * Searches for a section with the supplied name, and returns its line list
 * structure, or NULL if the search fails.
 */
extern struct cfg_list *cfg_get_list(char *section, char *subsection);

/*
 * Searches for a section with the supplied name and a parameter within the
 * section, and returns the parameter's value, or NULL if not found.
 */
extern char *cfg_get_param(char *section, char *subsection, char *param);

/*
 * Similar to the above, but does an atoi(). Returns -1 if not found.
 */
extern int cfg_get_int(char *section, char *subsection, char *param);

/*
 * Converts the value to boolean. Returns def if not found.
 */
extern int cfg_get_bool(char *section, char *subsection, char *param, int def);

#endif
