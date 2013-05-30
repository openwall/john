/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1998,2005,2006 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>

#include "misc.h"

#define DB_ENTRY_SIZE			200

static void process_entry(unsigned char *entry, char *cell)
{
	char *name = (char *)&entry[40];
	char *instance = (char *)&entry[104];
	unsigned char *key = &entry[168];
	int index;

	if (!name[0]) return;

	name[63] = 0;
	printf("%s", name);
	if (instance[0]) {
		instance[63] = 0;
		printf(".%s", instance);
	}
	printf(":$K4$");

	for (index = 0; index < 8; index++)
		printf("%02x", (int)key[index]);

	printf(",%s\n", cell);
}

static int process_db(FILE *file, char *cell)
{
	unsigned char buffer[DB_ENTRY_SIZE];
	long size;

	if (fread(buffer, 8, 1, file) != 1) return 1;
	size =
		((long)buffer[6] << 8) |
		(long)buffer[7];
	if (size == 0) size = 64; /* OpenAFS */
	if (fseek(file, size, SEEK_SET)) pexit("fseek");

	if (fread(buffer, 8, 1, file) != 1) return 1;
	size +=
		((long)buffer[4] << 24) |
		((long)buffer[5] << 16) |
		((long)buffer[6] << 8) |
		(long)buffer[7];
	if (fseek(file, size, SEEK_SET)) pexit("fseek");

	while (fread(buffer, 1, DB_ENTRY_SIZE, file) == DB_ENTRY_SIZE)
		process_entry(buffer, cell);

	return 0;
}

int unafs(int argc, char **argv)
{
	FILE *file;

	if (argc != 3) {
		puts("Usage: unafs DATABASE-FILE CELL-NAME");

		if (argc <= 1)
			return 0;
		else
			error();
	}

	if (!(file = fopen(argv[1], "rb")))
		pexit("fopen: %s", argv[1]);

	if (process_db(file, argv[2]))
	if (!ferror(file)) {
		fprintf(stderr, "fread: Unexpected EOF\n");
		error();
	}

	if (ferror(file)) pexit("fread");

	if (fclose(file)) pexit("fclose");

	return 0;
}
