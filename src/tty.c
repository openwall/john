/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2010 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef __DJGPP__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#else
#include <bios.h>
#endif

#if !defined(O_NONBLOCK) && defined(O_NDELAY)
#define O_NONBLOCK			O_NDELAY
#endif

#ifdef __CYGWIN32__
#include <string.h>
#include <sys/socket.h>
#ifndef __CYGWIN__
extern int tcgetattr(int fd, struct termios *termios_p);
extern int tcsetattr(int fd, int actions, struct termios *termios_p);
#endif
#endif

#include "tty.h"

#ifndef __DJGPP__
static int tty_fd = -1;
static struct termios saved_ti;
#endif

void tty_init(int stdin_mode)
{
#ifndef __DJGPP__
	int fd;
	struct termios ti;

	if (tty_fd >= 0) return;

/*
 * If we're in "--stdin" mode (reading candidate passwords from stdin), then
 * only initialize the tty if stdin is not a tty.  Otherwise it could be the
 * same tty, in which case we'd interfere with the user's ability to type
 * candidate passwords directly to John.
 */
	if (stdin_mode && !tcgetattr(0, &ti))
		return;

	if ((fd = open("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0) return;

#ifndef __CYGWIN32__
	if (tcgetpgrp(fd) != getpid()) {
		close(fd); return;
	}
#endif

	tcgetattr(fd, &ti);
	saved_ti = ti;
	ti.c_lflag &= ~(ICANON | ECHO);
	ti.c_cc[VMIN] = 1;
	ti.c_cc[VTIME] = 0;
	tcsetattr(fd, TCSANOW, &ti);

	tty_fd = fd;

	atexit(tty_done);
#endif
}

int tty_getchar(void)
{
#ifndef __DJGPP__
	int c;
#ifdef __CYGWIN32__
	fd_set set;
	struct timeval tv;
#endif

	if (tty_fd >= 0) {
#ifdef __CYGWIN32__
		FD_ZERO(&set); FD_SET(tty_fd, &set);
		tv.tv_sec = 0; tv.tv_usec = 0;
		if (select(tty_fd + 1, &set, NULL, NULL, &tv) <= 0)
			return -1;
#endif
		c = 0;
		if (read(tty_fd, &c, 1) > 0) return c;
	}
#else
	if (_bios_keybrd(_KEYBRD_READY))
		return _bios_keybrd(_KEYBRD_READ);
#endif

	return -1;
}

void tty_done(void)
{
#ifndef __DJGPP__
	int fd;

	if (tty_fd < 0) return;

	fd = tty_fd; tty_fd = -1;
	tcsetattr(fd, TCSANOW, &saved_ti);

	close(fd);
#endif
}
