/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Symlink emulation for Win32.
 */

#include <string.h>
#include <process.h>

#define MAIN_NAME			"john.exe"

int main(int argc, char **argv)
{
	char path[strlen(argv[0] ? argv[0] : "") + sizeof(MAIN_NAME)];
	char *name;

	if (!argv[0])
		name = path;
	else
	if ((name = strrchr(strcpy(path, argv[0]), '/')))
		name++;
	else
		name = path;
	strcpy(name, MAIN_NAME);

	execv(path, argv);
	return 1;
}
