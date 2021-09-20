/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2006,2011,2021 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "params.h"
#include "memory.h"

struct shadow_entry {
	struct shadow_entry *next;
	char *login, *passwd;
};

static struct shadow_entry **shadow_table;

static void alloc_hash(void)
{
	int size;

	size = SHADOW_HASH_SIZE * sizeof(struct shadow_entry *);
	shadow_table = (struct shadow_entry **)mem_alloc(size);
	memset(shadow_table, 0, size);
}

static unsigned int login_hash(char *login)
{
	unsigned int hash, extra;
	char *p;

	p = login + 2;
	hash = (unsigned char)login[0];
	if (!hash)
		goto out;
	extra = (unsigned char)login[1];
	if (!extra)
#if SHADOW_HASH_SIZE >= 0x100
		goto out;
#else
		goto out_and;
#endif

	while (*p) {
		hash <<= 5;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
		extra *= hash | 1812433253;
		extra += (unsigned char)p[1];
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> SHADOW_HASH_LOG;
			extra ^= extra >> SHADOW_HASH_LOG;
			hash &= SHADOW_HASH_SIZE - 1;
		}
	}

	hash -= extra;
	hash ^= extra << (SHADOW_HASH_LOG / 2);

	hash ^= hash >> SHADOW_HASH_LOG;
#if SHADOW_HASH_LOG <= 15
	hash ^= hash >> (2 * SHADOW_HASH_LOG);
#endif
#if SHADOW_HASH_LOG <= 10
	hash ^= hash >> (3 * SHADOW_HASH_LOG);
#endif

#if SHADOW_HASH_SIZE < 0x100
out_and:
#endif
	hash &= SHADOW_HASH_SIZE - 1;
out:
	return hash;
}

static void read_file(char *name, void (*process_line)(char *line))
{
	FILE *file;
	char line[LINE_BUFFER_SIZE];

	if (!(file = fopen(name, "r")))
		pexit("fopen: %s", name);

	while (fgetl(line, sizeof(line), file))
		process_line(line);

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");
}

static void process_shadow_line(char *line)
{
	static struct shadow_entry **entry = NULL;
	struct shadow_entry *last;
	char *login, *passwd, *tail;

	/* AIX "password = " */
	if (!(passwd = strchr(line, ':'))) {
		/* skip spaces and tabs */
		line += strspn(line, " \t");
		if (!strncmp(line, "password", 8)) {
			line += 8;
			line += strspn(line, " \t");
			if (*line == '=') {
				line++;
				line += strspn(line, " \t");
				if (entry)
					(*entry)->passwd = str_alloc_copy(line);
			}
		}
		return;
	}

	login = line;
	*passwd++ = 0;

	/* DU / Tru64 C2, HP-UX tcb */
	if (!strncmp(passwd, "u_name=", 7)) {
		if ((passwd = strstr(passwd, ":u_pwd=")))
			passwd += 7;
	} else
	/* HP-UX tcb */
	if (!strncmp(passwd, "u_pwd=", 6) && entry) {
		passwd += 6;
		if ((tail = strchr(passwd, ':')))
			*tail = 0;
		(*entry)->passwd = str_alloc_copy(passwd);
		return;
	}

	if (passwd && (tail = strchr(passwd, ':')))
		*tail = 0;

	entry = &shadow_table[login_hash(login)];
	last = *entry;
	*entry = mem_alloc_tiny(sizeof(struct shadow_entry), MEM_ALIGN_WORD);
	(*entry)->next = last;
	(*entry)->login = str_alloc_copy(login);
	(*entry)->passwd = passwd ? str_alloc_copy(passwd) : "*";
}

static void process_passwd_line(char *line)
{
	char *pos1, *pos2;
	struct shadow_entry *current;

	if (!(pos1 = strchr(line, ':'))) return;
	*pos1++ = 0;

	if (!(pos2 = strchr(pos1, ':')))
		pos2 = pos1 + strlen(pos1);

	if (pos2 > pos1 && (current = shadow_table[login_hash(line)]))
	do {
		if (!strcmp(current->login, line)) {
			printf("%s:%s%s\n", line, current->passwd, pos2);
			return;
		}
	} while ((current = current->next));

	printf("%s:%s\n", line, pos1);
}

int unshadow(int argc, char **argv)
{
	if (argc != 3) {
		puts("Usage: unshadow PASSWORD-FILE SHADOW-FILE");

		if (argc <= 1)
			return 0;
		else
			error();
	}

	alloc_hash();

	read_file(argv[2], process_shadow_line);
	read_file(argv[1], process_passwd_line);

	return 0;
}
