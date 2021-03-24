/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2010 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC, by JimF.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "arch.h"
#if defined (__MINGW32__) || defined (_MSC_VER)
#include <conio.h>
#else
#ifndef __DJGPP__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if !AC_BUILT || HAVE_TERMIOS_H
#include <termios.h>
#endif
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <stdlib.h>
#else
#include <bios.h>
#endif

#if !defined(O_NONBLOCK) && defined(O_NDELAY)
#define O_NONBLOCK			O_NDELAY
#endif

#ifdef __CYGWIN__
#include <string.h>
#include <sys/socket.h>
#endif
#endif /* !defined __MINGW32__ */

#include "tty.h"

#if !defined(__DJGPP__) && !defined(__MINGW32__) && !defined (_MSC_VER)
static int tty_fd = -1;
static struct termios saved_ti;
#else
static int in_stdin_mode;
#endif

/*
 * This must be async signal-safe (for MPI builds, at least)
 */
int tty_has_keyboard(void)
{
#if !defined(__DJGPP__) && !defined(__MINGW32__) && !defined (_MSC_VER)
	return (tty_fd >= 0);
#else
	return !(in_stdin_mode && isatty(fileno(stdin)));
#endif
}

void tty_init(opt_flags stdin_mode)
{
#if !defined(__DJGPP__) && !defined(__MINGW32__) && !defined (_MSC_VER)
	int fd;
	struct termios ti;

	if (tty_fd >= 0)
		return;
/*
 * If we're in "--stdin" mode (reading candidate passwords from stdin), then
 * only initialize the tty if stdin is not a tty.  Otherwise it could be the
 * same tty, in which case we'd interfere with the user's ability to type
 * candidate passwords directly to John.
 */
	if (stdin_mode && isatty(fileno(stdin)))
		return;

	if ((fd = open("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0)
		return;

/*
 * Give up the keyboard if we're not the foreground process.  This can be
 * overridden with --force-tty option.
 */
#ifndef BENCH_BUILD
	if (!(options.flags & FLG_FORCE_TTY))
#endif
	if (tcgetpgrp(fd) != getpid()) {
		close(fd);
		return;
	}

	tcgetattr(fd, &ti);
	saved_ti = ti;
/*
 * Set up terminal for reading keystrokes, and no echo.
 */
	ti.c_lflag &= ~(ICANON | ECHO);
	ti.c_cc[VMIN] = 1;
	ti.c_cc[VTIME] = 0;
	tcsetattr(fd, TCSANOW, &ti);

	tty_fd = fd;

	atexit(tty_done);
#else
	in_stdin_mode = stdin_mode;
#endif
}

int tty_getchar(void)
{
#if !defined(__DJGPP__) && !defined(__MINGW32__) && !defined (_MSC_VER)
	int c;
#if defined (__NOT_NEEDED_ANY_MORE___) && defined (__CYGWIN__)
	fd_set set;
	struct timeval tv;
#endif

	if (tty_fd >= 0) {
#if defined (__NOT_NEEDED_ANY_MORE___) && defined (__CYGWIN__)
#error "Should NOT get here"
		FD_ZERO(&set); FD_SET(tty_fd, &set);
		tv.tv_sec = 0; tv.tv_usec = 0;
		if (select(tty_fd + 1, &set, NULL, NULL, &tv) <= 0)
		//if (!(select(tty_fd + 1, &set, NULL, NULL, &tv) && FD_ISSET(tty_fd, &set)))
			return -1;
#endif
		c = 0;
		if (read(tty_fd, &c, 1) > 0)
			return c;
	}
#elif defined(__DJGPP__)
	if (_bios_keybrd(_KEYBRD_READY))
		return _bios_keybrd(_KEYBRD_READ);
#else /* defined(__MINGW32__) or _MSC_VER */
	if (_kbhit())
		return _getch();
#endif

	return -1;
}

void tty_done(void)
{
#if !defined(__DJGPP__) && !defined(__MINGW32__) && !defined (_MSC_VER)
	int fd;

	if (tty_fd < 0)
		return;

	fd = tty_fd; tty_fd = -1;

/* Do the usually-best-thing in the race condition sometimes caused by --force-tty */
#ifndef BENCH_BUILD
	if (options.flags & FLG_FORCE_TTY)
		saved_ti.c_lflag |= (ICANON | ECHO);
#endif

	tcsetattr(fd, TCSANOW, &saved_ti);

	close(fd);
#endif
}
