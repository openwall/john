/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2010 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#include <string.h>
#include <stdlib.h>

#include "misc.h"
#include "params.h"
#include "memory.h"
#include "path.h"

static char *john_home_path = NULL;
static int john_home_length;

#if JOHN_SYSTEMWIDE
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

static char *user_home_path = NULL;
static int user_home_length;
#endif


void path_init(char **argv)
{
#if JOHN_SYSTEMWIDE
	char *home_dir;
#ifdef JOHN_PRIVATE_HOME
	const char *private;
#endif
#else
	char *pos;
#endif

#if JOHN_SYSTEMWIDE
	john_home_path = mem_alloc(PATH_BUFFER_SIZE);
	strnzcpy(john_home_path, JOHN_SYSTEMWIDE_HOME "/", PATH_BUFFER_SIZE);
	john_home_length = strlen(john_home_path);

	if (user_home_path) return;

	/* $HOME may override user's home directory */
	if (!(home_dir = getenv("HOME"))) {
		struct passwd *pw;

		pw = getpwuid(getuid());
		endpwent();
		if (!pw)
			return;
		home_dir = pw->pw_dir;
	}

	user_home_length = strlen(home_dir) + 1;
	if (user_home_length >= PATH_BUFFER_SIZE) return;

	user_home_path = mem_alloc(PATH_BUFFER_SIZE);
	memcpy(user_home_path, home_dir, user_home_length - 1);
	user_home_path[user_home_length - 1] = '/';

#ifdef JOHN_PRIVATE_HOME
	private = path_expand(JOHN_PRIVATE_HOME);
	if (mkdir(private, S_IRUSR | S_IWUSR | S_IXUSR)) {
		if (errno != EEXIST) pexit("mkdir: %s", private);
	} else
		fprintf(stderr, "Created directory: %s\n", private);
#if HAVE_OPENCL
	private = path_expand(JOHN_PRIVATE_HOME "/opencl");
	if (mkdir(private, S_IRUSR | S_IWUSR | S_IXUSR)) {
		if (errno != EEXIST) pexit("mkdir: %s", private);
	} else
		fprintf(stderr, "Created directory: %s\n", private);
#endif
#endif
#else
	if (argv[0]) {
		int dos=0;
		if (!john_home_path) {
			pos = strrchr(argv[0], '/');
			if (!pos) {
				pos = strrchr(argv[0], '\\'); // handle this for MSVC and MinGW which use 'DOS' style C:\path\run\john  syntax.
				if (pos>argv[0] && argv[0][1] == ':') {
					argv[0] += 2;
					dos = 1;
				}
			}
			if (pos) {
				john_home_length = pos - argv[0] + 1;
				if (john_home_length >= PATH_BUFFER_SIZE) return;

				john_home_path = mem_alloc(PATH_BUFFER_SIZE);
				memcpy(john_home_path, argv[0], john_home_length);
				john_home_path[john_home_length] = 0;
				pos = strchr(john_home_path, '\\');
				while (dos && pos) {
					*pos = '/';
					pos = strchr(pos, '\\');
				}
#if !(defined(__DJGPP__) || defined(__CYGWIN__) || defined(_MSC_VER) || defined(__MINGW32__))
			} else {
				fprintf(stderr,
				    "Error: Cannot find John home. Invoke the program via full or relative pathname.\n"
				    "For example, /full/path/%s or path/%s, or set and use a shell alias.\n", argv[0], argv[0]);
				error();
#endif
			}
		}
	}
#endif
}

const char *path_expand(const char *name)
{
	if (!strncmp(name, "$JOHN/", 6)) {
		if (john_home_path &&
		    john_home_length + strlen(name) - 6 < PATH_BUFFER_SIZE) {
			strnzcpy(&john_home_path[john_home_length], &name[6],
				PATH_BUFFER_SIZE - john_home_length);
			return john_home_path;
		}
		return name + 6;
	}

#if JOHN_SYSTEMWIDE
	if (!strncmp(name, "~/", 2)) {
		if (user_home_path &&
		    user_home_length + strlen(name) - 2 < PATH_BUFFER_SIZE) {
			strnzcpy(&user_home_path[user_home_length], &name[2],
				PATH_BUFFER_SIZE - user_home_length);
			return user_home_path;
		}
		return name + 2;
	}
#endif

	return name;
}

const char *path_expand_safe(const char *name)
{
	char *full_path;

	full_path = (char *) mem_calloc(PATH_BUFFER_SIZE, sizeof(char));

	if (!strncmp(name, "$JOHN/", 6)) {
		if (john_home_path &&
		    john_home_length + strlen(name) - 6 < PATH_BUFFER_SIZE) {
			memcpy(full_path, john_home_path, PATH_BUFFER_SIZE);
			strnzcpy(&full_path[john_home_length], &name[6],
				PATH_BUFFER_SIZE - john_home_length);
			return full_path;
		}
		memcpy(full_path, name + 6, strlen(name) - 6);
		return full_path;
	}

#if JOHN_SYSTEMWIDE
	if (!strncmp(name, "~/", 2)) {
		if (user_home_path &&
		    user_home_length + strlen(name) - 2 < PATH_BUFFER_SIZE) {
			memcpy(full_path, user_home_path, PATH_BUFFER_SIZE);
			strnzcpy(&full_path[user_home_length], &name[2],
				PATH_BUFFER_SIZE - user_home_length);
			return full_path;
		}
		memcpy(full_path, name + 2, strlen(name) - 2);
		return full_path;
	}
#endif
	memcpy(full_path, name, strlen(name));
	return full_path;
}

char *path_session(const char *session, const char *suffix)
{
	int keep, add;
	char *p;

	keep = strlen(session);
#ifdef __DJGPP__
	if ((p = strchr(session, '.')))
		keep = p - session;
#endif

	if (!keep) {
		fprintf(stderr, "Invalid session name requested\n");
		error();
	}

	add = strlen(suffix) + 1;
	p = mem_alloc_tiny(keep + add, MEM_ALIGN_NONE);
	memcpy(p, session, keep);
	memcpy(p + keep, suffix, add);

	return p;
}

void path_done(void)
{
	MEM_FREE(john_home_path);
#if JOHN_SYSTEMWIDE
	MEM_FREE(user_home_path);
#endif
}
