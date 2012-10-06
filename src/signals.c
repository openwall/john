/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC, by JimF.
 */

#ifdef HAVE_MPI
#include "john-mpi.h"
#endif
#if defined (__MINGW32__) || defined (_MSC_VER)
#define __CYGWIN32__
#define SIGALRM SIGFPE
#define SIGHUP SIGILL
#endif

#define _XOPEN_SOURCE 500 /* for setitimer(2) and siginterrupt(3) */

#ifdef __ultrix__
#define __POSIX
#define _POSIX_SOURCE
#endif

#ifdef _SCO_C_DIALECT
#include <limits.h>
#endif
#include <stdio.h>
#if !defined (_MSC_VER)
#include <sys/time.h>
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#ifdef __DJGPP__
#include <dos.h>
#endif

#ifdef __CYGWIN32__
#include <windows.h>
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "tty.h"
#include "config.h"
#include "options.h"
#include "bench.h"

volatile int event_pending = 0;
volatile int event_abort = 0, event_save = 0, event_status = 0;
volatile int event_ticksafety = 0;

volatile int timer_abort = -1, timer_status = -1;
static int timer_save_interval, timer_save_value;
static clock_t timer_ticksafety_interval, timer_ticksafety_value;

#if !OS_TIMER

#include <time.h>
#if !defined (__MINGW32__) && !defined (_MSC_VER)
#include <sys/times.h>
#endif

static clock_t timer_emu_interval = 0;
static unsigned int timer_emu_count = 0, timer_emu_max = 0;

void sig_timer_emu_init(clock_t interval)
{
	timer_emu_interval = interval;
	timer_emu_count = 0; timer_emu_max = 0;
}

void sig_timer_emu_tick(void)
{
	static clock_t last = 0;
	clock_t current;
#if !defined (__MINGW32__) && !defined (_MSC_VER)
	struct tms buf;
#endif

	if (++timer_emu_count < timer_emu_max) return;

#if defined (__MINGW32__) || defined (_MSC_VER)
	current = clock();
#else
	current = times(&buf);
#endif

	if (!last) {
		last = current;
		return;
	}

	if (current - last < timer_emu_interval && current >= last) {
		timer_emu_max += timer_emu_max + 1;
		return;
	}

	last = current;
	timer_emu_count = 0;
	timer_emu_max >>= 1;

	raise(SIGALRM);
}

#endif

static void sig_install_update(void);

static void sig_handle_update(int signum)
{
	event_save = event_pending = 1;

#ifdef HAVE_MPI
	event_status = 1;
#endif
#ifndef SA_RESTART
	sig_install_update();
#endif
}

static void sig_install_update(void)
{
#ifdef SA_RESTART
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handle_update;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &sa, NULL);
#ifdef HAVE_MPI
	sigaction(SIGUSR1, &sa, NULL);
#endif /* HAVE_MPI */
#else
	signal(SIGHUP, sig_handle_update);
#ifdef HAVE_MPI
	signal(SIGUSR1, sig_handle_update);
#endif /* HAVE_MPI */
#endif
}

static void sig_remove_update(void)
{
	signal(SIGHUP, SIG_IGN);
#ifdef HAVE_MPI
	signal(SIGUSR1, SIG_DFL);
#endif
}

void check_abort(int be_async_signal_safe)
{
	if (!event_abort) return;

	tty_done();

	if (be_async_signal_safe) {
		if (timer_abort)
			write_loop(2, "Session aborted\n", 16);
		else
			write_loop(2, "Session stopped (max run-time reached)\n", 39);
#if defined(HAVE_MPI) && defined(JOHN_MPI_ABORT)
		if (mpi_p > 1) {
			write_loop(2, "Aborting other nodes...\n", 24);
			MPI_Abort(MPI_COMM_WORLD,1);
		}
#endif
		_exit(1);
	}

	fprintf(stderr, "Session %s\n", timer_abort ?
	        "aborted" : "stopped (max run-time reached)");
	error();
}

static void sig_install_abort(void);

static void sig_handle_abort(int signum)
{
	int saved_errno = errno;

	check_abort(1);

	event_abort = event_pending = 1;

	write_loop(2, "Wait...\r", 8);

	sig_install_abort();

	errno = saved_errno;
}

#ifdef __CYGWIN32__
#if defined (_MSC_VER)
static BOOL WINAPI sig_handle_abort_ctrl(DWORD ctrltype)
{
	sig_handle_abort(SIGINT);
	return TRUE;
}
#else
static CALLBACK BOOL sig_handle_abort_ctrl(DWORD ctrltype)
{
	sig_handle_abort(SIGINT);
	return TRUE;
}
#endif
#endif

static void sig_install_abort(void)
{
#ifdef __DJGPP__
	setcbrk(1);
#endif

#ifdef __CYGWIN32__
	SetConsoleCtrlHandler(sig_handle_abort_ctrl, TRUE);
#endif

	signal(SIGINT, sig_handle_abort);
#ifndef HAVE_MPI
	signal(SIGTERM, sig_handle_abort);
#endif
#ifdef SIGXCPU
	signal(SIGXCPU, sig_handle_abort);
#endif
#ifdef SIGXFSZ
	signal(SIGXFSZ, sig_handle_abort);
#endif
}

static void sig_remove_abort(void)
{
#ifdef __CYGWIN32__
	SetConsoleCtrlHandler(sig_handle_abort_ctrl, FALSE);
#endif

	signal(SIGINT, SIG_DFL);
#ifndef HAVE_MPI
	signal(SIGTERM, SIG_DFL);
#endif
#ifdef SIGXCPU
	signal(SIGXCPU, SIG_DFL);
#endif
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_DFL);
#endif
}

#ifdef __CYGWIN32__

static int sig_getchar(void)
{
	int c;

	if ((c = tty_getchar()) == 3) {
		sig_handle_abort(CTRL_C_EVENT);
		return -1;
	}

	return c;
}

#else

#define sig_getchar tty_getchar

#endif

static void sig_install_timer(void);

static void sig_handle_timer(int signum)
{
	int saved_errno = errno;

	if (!--timer_save_value) {
		timer_save_value = timer_save_interval;

		event_save = event_pending = 1;
	}

	if (!--timer_abort)
		event_abort = event_pending = 1;

	if (!--timer_status) {
		event_status = event_pending = 1;
		timer_status = options.status_interval;
	}

	if (!--timer_ticksafety_value) {
		timer_ticksafety_value = timer_ticksafety_interval;

		event_ticksafety = event_pending = 1;
	}

	if (sig_getchar() >= 0) {
		while (sig_getchar() >= 0);

		event_status = event_pending = 1;
	}

#if !OS_TIMER
	signal(SIGALRM, sig_handle_timer);
#elif !defined(SA_RESTART) && !defined(__DJGPP__)
	sig_install_timer();
#endif

	errno = saved_errno;
}

static void sig_install_timer(void)
{
#if !OS_TIMER
	signal(SIGALRM, sig_handle_timer);
	sig_timer_emu_init(TIMER_INTERVAL * clk_tck);
#else
	struct sigaction sa;
	struct itimerval it;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handle_timer;
#ifdef SA_RESTART
	sa.sa_flags = SA_RESTART;
#endif
	sigaction(SIGALRM, &sa, NULL);
#if !defined(SA_RESTART) && !defined(__DJGPP__)
	siginterrupt(SIGALRM, 0);
#endif

	it.it_value.tv_sec = TIMER_INTERVAL;
	it.it_value.tv_usec = 0;
#if defined(SA_RESTART) || defined(__DJGPP__)
	it.it_interval = it.it_value;
#else
	memset(&it.it_interval, 0, sizeof(it.it_interval));
#endif
	if (setitimer(ITIMER_REAL, &it, NULL)) pexit("setitimer");
#endif
}

static void sig_remove_timer(void)
{
#if OS_TIMER
	struct itimerval it;

	memset(&it, 0, sizeof(it));
	if (setitimer(ITIMER_REAL, &it, NULL)) perror("setitimer");
#endif

	signal(SIGALRM, SIG_DFL);
}

static void sig_done(void);

void sig_init(void)
{
	clk_tck_init();

	timer_save_interval = cfg_get_int(SECTION_OPTIONS, NULL, "Save");
	if (timer_save_interval < 0)
		timer_save_interval = TIMER_SAVE_DELAY;
	else
	if ((timer_save_interval /= TIMER_INTERVAL) <= 0)
		timer_save_interval = 1;
	timer_save_value = timer_save_interval;

	timer_ticksafety_interval = (clock_t)1 << (sizeof(clock_t) * 8 - 4);
	timer_ticksafety_interval /= clk_tck;
	if ((timer_ticksafety_interval /= TIMER_INTERVAL) <= 0)
		timer_ticksafety_interval = 1;
	timer_ticksafety_value = timer_ticksafety_interval;

	atexit(sig_done);

	sig_install_update();
	sig_install_abort();
	sig_install_timer();
}

static void sig_done(void)
{
	sig_remove_update();
	sig_remove_abort();
	sig_remove_timer();
}
