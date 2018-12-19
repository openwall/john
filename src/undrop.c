/*
 * Eggdrop userfile converter
 * Copyright (c) 2002 by Sun-Zero <sun-zero at freemail.hu>
 * This is a free software distributable under terms of the GNU GPL.
 * See the file COPYING for details.
 *
 * 2003-04-21
*/

#include <stdio.h>
#include <string.h>
#include "os.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif


#define USERFILE_HEADER "#4v:"
#define USERNAME_LENGTH 11
#define PASSWORD_LENGTH 13
#define MAX_FLAGS_LENGTH 32
#define BUFSIZE 512

int undrop(int argc, char *argv[]) {

    FILE *userfile;
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
    char flags[MAX_FLAGS_LENGTH];
    char t_username[BUFSIZE];
    char t_flags[BUFSIZE];
    char t_line[BUFSIZE];

    if (argc != 2) {
	userfile = stdin;
	printf("# userfile reading from stdin\n");
    } else {
        if ((userfile = fopen(argv[1], "rt")) == NULL) {
	        fprintf(stderr, "opening userfile\n");
	        userfile = stdin;
        }
    }


    if (fgets(t_line, sizeof(t_line) - 1, userfile) == NULL)
	return 1;

    if (strncmp(t_line, USERFILE_HEADER, strlen(USERFILE_HEADER)) != 0) {
	fprintf(stderr, "usefile format is wrong\n");
	fclose(userfile);
	return 1;
    } else {
	printf("# userfile format OK\n\n");
    }

    while (fgets(t_line, sizeof(t_line) - 1, userfile) != NULL) {
	if (sscanf(t_line, "%10s - %24s\n", t_username, t_flags)  == 2) {
	    if (strncmp(t_username, "! ", 2) != 0 &&
		strncmp(t_username, "--", 2) != 0 &&
		strncmp(t_username, "&&", 2) != 0 &&
		strncmp(t_username, "::", 2) != 0 &&
		strncmp(t_username, "$$", 2) != 0
	    ) {
		strncpy(username, t_username, USERNAME_LENGTH);
	        strncpy(flags, t_flags, MAX_FLAGS_LENGTH);
	    }
	}

	if (strncmp(t_line, "--PASS +", 8) == 0) {
	    sscanf(t_line, "--PASS +%12s", password);
	    printf("%s:+%s:::%s:\n", username, password, flags);
	}
	fflush(stdout);
    }
    fclose(userfile);
    return 0;
}
