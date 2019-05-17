/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * ...with changes in the jumbo patch for MSC, by JimF.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Symlink emulation for Windows.
 */

#include <string.h>
#include <process.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#ifndef MAIN_NAME
#define MAIN_NAME			"john.exe"
#endif

int main(int argc, char *argv[])
{
	char *name, *path;

	path = malloc((argv[0] ? strlen(argv[0]) : 0) + sizeof(MAIN_NAME));
	if (!path) {
		perror("malloc");
		exit(1);
	}

	if (!argv[0])
		name = path;
	else if ((name = strrchr(strcpy(path, argv[0]), '/')) || (name = strrchr(path, '\\')))
		name++;
	else
		name = path;
	strcpy(name, MAIN_NAME);

	execv(path, argv);
	return 1;
}
