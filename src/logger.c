/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "config.h"

static int log_fd = 0;
static char *log_buffer;
static char *log_bufptr;

static int cfg_beep;

void log_init(char *name)
{
	if (chmod(path_expand(name), S_IRUSR | S_IWUSR))
	if (errno != ENOENT)
		pexit("chmod: %s", path_expand(name));

	if ((log_fd = open(path_expand(name), O_WRONLY | O_CREAT | O_APPEND,
	    S_IRUSR | S_IWUSR)) < 0)
		pexit("open: %s", path_expand(name));

	log_bufptr = log_buffer =
		mem_alloc(LOG_BUFFER_SIZE + LINE_BUFFER_SIZE);

	cfg_beep = cfg_get_bool(SECTION_OPTIONS, NULL, "Beep");
}

static void log_write(void)
{
	int size;

	size = log_bufptr - log_buffer;
	log_bufptr = log_buffer;

#if defined(LOCK_EX) && OS_FLOCK
	if (flock(log_fd, LOCK_EX)) pexit("flock");
#endif
	if (write_loop(log_fd, log_buffer, size) < 0) pexit("write");
#if defined(LOCK_EX) && OS_FLOCK
	if (flock(log_fd, LOCK_UN)) pexit("flock");
#endif
}

void log_guess(char *login, char *ciphertext, char *plaintext)
{
	printf("%-16s (%s)\n", plaintext, login);

	if (log_fd && ciphertext)
	if (strlen(ciphertext) + strlen(plaintext) < LINE_BUFFER_SIZE - 3) {
		log_bufptr += (int)sprintf(log_bufptr,
			"%s:%s\n", ciphertext, plaintext);
		if (log_bufptr - log_buffer > LOG_BUFFER_SIZE) log_write();
	}

	if (cfg_beep)
		write_loop(fileno(stderr), "\007", 1);
}

void log_flush(void)
{
	if (log_fd) {
		if (log_bufptr != log_buffer) log_write();
#ifndef __CYGWIN32__
		if (fsync(log_fd)) pexit("fsync");
#endif
	}
}

void log_done(void)
{
	if (log_fd) {
		log_flush();
		if (close(log_fd)) pexit("close");
		log_fd = 0;

		mem_free((void **)&log_buffer);
	}
}
