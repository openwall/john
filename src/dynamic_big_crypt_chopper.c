/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.'
 *
 * dynamic_big_crypt_chopper.c.  This is a 'smart' sed like script.
 * it will read command line, and all vars from command line should
 * be in token=value format. Then the program will read all lines
 * from stdin, and for all #{token} items found on the line, this
 * will replace with appropriate value strings.
 * Also, if token == DEFINED, then value is a CPP defined value, and
 * we will parse code out properly in that way.  If token is UNDEFINED
 * then we will know that this CPP value is NOT defined in our build.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *defined[20], *token[40], *value[40], Line[16*1024], tmpLine[16*1024];
int ndefined, ntokens;
int define_stack[10]={1,0}, nstack=1; // stack starts seeded in a 'defined' state.

void detok();
int in_defined();

int main(int argc, char **argv) {
	int i;
	for (i = 1; i < argc; ++i) {
		if (!strncmp(argv[i], "DEFINED=", 8)) {
			defined[ndefined] = malloc(strlen(argv[i])-6);
			defined[ndefined][0] = 'Y';
			strcpy(&defined[ndefined++][1], &argv[i][8]);
		} else if (!strncmp(argv[i], "UNDEFINED=", 10)) {
			defined[ndefined] = malloc(strlen(argv[i])-8);
			defined[ndefined][0] = 'N';
			strcpy(&defined[ndefined++][1], &argv[i][10]);
		} else {
			token[ntokens] = malloc(strlen(argv[i])+1);
			strcpy(token[ntokens], argv[i]);
			strtok(token[ntokens], "=");
			value[ntokens++] = strtok(NULL, "");
		}
	}
	// now read stdin, and modify, and write to stdout
	if (!fgets(Line, sizeof(Line), stdin))
		return 0;
	while (!feof(stdin)) {
		detok();
		if (in_defined())
			printf("%s\n", tmpLine);
		if (!fgets(Line, sizeof(Line), stdin))
			return 0;
	}
}

// removes all the #{token} and replaces with value
void detok() {
	char *cp, *cpI, *cpO;
	int i;
	cp = strstr(Line, "#{");
	if (!cp) {
		strcpy(tmpLine, Line);
		strtok(tmpLine, "\r\n");
		if (*tmpLine == '\n')
			*tmpLine = 0;
		return;
	}
	cpI = Line;
	cpO = tmpLine;
	while (cp) {
		int fnd=0;
		*cp = 0;
		cp += 2;
		strcpy(cpO, cpI);
		cpO += strlen(cpO);
		for (i = 0; i < ntokens; ++i) {
			if (!strncmp(cp, token[i], strlen(token[i])) && cp[strlen(token[i])] == '}') {
				strcpy(cpO, value[i]);
				cpO += strlen(cpO);
				cp += strlen(token[i])+1;
				cpI = cp;
				cp = strstr(cp, "#{");
				fnd = 1;
				break;
			}
		}
		if (!fnd) {
			fprintf(stderr, "Could not find token:  ${%s\n", cp);
			exit(1);
		}
	}
	if (cpI && strlen(cpI))
		strcpy(cpO, cpI);
	strtok(tmpLine, "\r\n");
}

char get_defined_char(char *p) {
	int i;
	for (i = 0; i < ndefined; ++i) {
		if (!strncmp(p, &defined[i][1], strlen(&defined[i][1]))) {
			// found it.
			return defined[i][0];
		}
	}
	return 'U'; // not one we care about, leave the define stack like it is.
}

// tracks defined and undefined sections. If we are in an undefined section,
// we do not print.  If we are in a defined, then we do print.  the file
// always starts out in a defined state. Then defined and undefined sections
// get pushed and popped off the define stack.
int in_defined() {
	if (!strncmp(tmpLine, "#ifdef ", 7)) {
		// ok, see if this is one of our defines, or UNDEFINES.
		char *cp = &tmpLine[7];
		char defined_YNU = get_defined_char(cp);
		if (defined_YNU == 'Y') {
			define_stack[nstack++] = 1;
			return 0;
		}
		if (defined_YNU == 'N') {
			define_stack[nstack++] = 0;
			return 0;
		}
	} else if (!strncmp(tmpLine, "#else  //", 9)) {
		// this one may be the else statement for something defined or undefined.
		char defined_YNU, *cp = strstr(tmpLine, "defined ");
		if (cp) {
			tmpLine[5] = 0;
			defined_YNU = get_defined_char(cp+8);
			if (defined_YNU == 'Y') {
				define_stack[nstack-1] = 0;
				return 0;
			}
			if (defined_YNU == 'N') {
				define_stack[nstack-1] = 1;
				return 0;
			}
		}
	} else if (!strncmp(tmpLine, "#endif  //", 10)) {
		// this one may be the endif statement for something defined or undefined.
		char defined_YNU, *cp = strstr(tmpLine, "defined ");
		if (cp) {
			tmpLine[6] = 0;
			defined_YNU = get_defined_char(cp+8);
			if (defined_YNU == 'Y' || defined_YNU == 'N') {
				--nstack;
				return 0;
			}
		}
	}
	return define_stack[nstack-1];
}
