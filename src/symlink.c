/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * ...with changes in the jumbo patch for MSC, by JimF.
 */

/*
 * Symlink emulation for Win32.
 */

#include <string.h>
#include <process.h>

#define MAIN_NAME			"john.exe"

int main(int argc, char **argv)
{
#if !defined (_MSC_VER)
	char path[strlen(argv[0] ? argv[0] : "") + sizeof(MAIN_NAME)];
#else
#pragma warning ( disable : 4996 )
    char path[4096];
#endif

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
