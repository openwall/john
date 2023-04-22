/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2010,2013,2015 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if !AC_BUILT && _XOPEN_SOURCE < 500
#undef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500 /* for setitimer(2) and siginterrupt(3) */
#define _XPG6
#endif

#define NEED_OS_TIMER
#define NEED_OS_FORK
#include "os.h"

#if _MSC_VER || __MINGW32__ || __MINGW64__ || HAVE_WINDOWS_H
#define WIN32_SIGNAL_HANDLER
#define SIGALRM SIGFPE
#define SIGHUP SIGILL
#include <windows.h>
#endif

#include <stdio.h>
#if !AC_BUILT || HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#if HAVE_DOS_H
#include <dos.h>
#endif

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "tty.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#include "john.h"
#include "status.h"
#include "signals.h"
#include "john_mpi.h"
#ifdef HAVE_MPI
#include "tty.h" /* For tty_has_keyboard() */
#endif

volatile int event_pending = 0, event_reload = 0;
volatile int event_abort = 0, event_help = 0, event_save = 0, event_status = 0, event_delayed_status = 0;
volatile int event_ticksafety = 0;
volatile int event_mpiprobe = 0, event_poll_files = 0;
volatile int event_fix_state = 0, event_refresh_salt = 0;

volatile int timer_abort = 0, timer_status = 0;
static int timer_save_interval;
#ifndef BENCH_BUILD
static int timer_save_value;
#endif
static clock_t timer_ticksafety_interval, timer_ticksafety_value;
volatile int aborted_by_timer = 0;
static int abort_grace_time = 30;

#if !OS_TIMER

#include <time.h>
#if !defined (__MINGW32__) && !defined (_MSC_VER)
#include <sys/times.h>
#endif

static int timer_emu_running;
static clock_t timer_emu_interval = 0;
static unsigned int timer_emu_count = 0, timer_emu_max = 0;

void sig_timer_emu_init(clock_t interval)
{
	timer_emu_interval = interval;
	timer_emu_count = 0; timer_emu_max = 0;
	timer_emu_running = 1;
}

void sig_timer_emu_tick(void)
{
	static clock_t last = 0;
	clock_t current;
#if !defined (__MINGW32__) && !defined (_MSC_VER)
	struct tms buf;
#endif

	if (!timer_emu_running)
		return;
	if (++timer_emu_count < timer_emu_max)
		return;

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

#if OS_FORK
static void signal_children(int signum)
{
	int i;
	for (i = 0; i < john_child_count; i++)
		if (john_child_pids[i])
			kill(john_child_pids[i], signum);
}
#endif

static void sig_install(void *handler, int signum)
{
#ifdef SA_RESTART
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sa.sa_flags = SA_RESTART;
	sigaction(signum, &sa, NULL);
#else
	signal(signum, handler);
#endif
}

static void sig_handle_update(int signum)
{
	event_reload = event_save = event_pending = 1;

#ifndef SA_RESTART
	sig_install(sig_handle_update, signum);
#endif
}

static void sig_remove_update(void)
{
	signal(SIGHUP, SIG_IGN);
}

#ifdef SIGUSR2
static void sig_remove_reload(void)
{
	signal(SIGUSR2, SIG_IGN);
}
#endif

void check_abort(int be_async_signal_safe)
{
	char *abort_msg = (aborted_by_timer) ?
		"Session stopped (max run-time reached)\n" :
		"Session aborted\n";

	if (!event_abort) return;

	tty_done();

#ifndef BENCH_BUILD
	if (john_max_cands && status.cands >= john_max_cands)
		abort_msg = "Session stopped (max candidates reached)\n";
#endif

	if (be_async_signal_safe) {
		if (john_main_process)
			write_loop(2, abort_msg, strlen(abort_msg));
		_exit(1);
	}

	if (john_main_process)
		fprintf(stderr, "%s", abort_msg);
	error();
}

static void sig_install_abort(void);

static void sig_handle_abort(int signum)
{
	int saved_errno = errno;

#if OS_FORK
	if (john_main_process && !aborted_by_timer) {
/*
 * We assume that our children are running on the same tty with us, so if we
 * receive a SIGINT they probably do as well without us needing to forward the
 * signal to them.  If we forwarded the signal anyway, this could result in
 * them receiving the signal twice for a single Ctrl-C keypress and proceeding
 * with immediate abort without updating the files, which is behavior that we
 * reserve for (presumably intentional) repeated Ctrl-C keypress.
 *
 * We forward the signal as SIGINT even though ours was different (typically a
 * SIGTERM) in order not to trigger a repeated same signal for children if the
 * user does e.g. "killall john", which would send SIGTERM directly to children
 * and also have us forward a signal.
 */
		if (signum != SIGINT)
			signal_children(SIGINT);
	} else {
		static int prev_signum;
/*
 * If it's not the same signal twice in a row, don't proceed with immediate
 * abort since these two signals could have been triggered by the same killall
 * (perhaps a SIGTERM from killall directly and a SIGINT as forwarded by our
 * parent).  event_abort would be set back to 1 just below the check_abort()
 * call.  We only reset it to 0 temporarily to skip the immediate abort here.
 */
		if (prev_signum && signum != prev_signum)
			event_abort = 0;
		prev_signum = signum;
	}
#endif

	check_abort(1);

	event_abort = event_pending = 1;

	write_loop(2, "Wait...\r", 8);

	sig_install_abort();

	errno = saved_errno;
}

#ifdef WIN32_SIGNAL_HANDLER
#ifdef __CYGWIN__
static CALLBACK BOOL sig_handle_abort_ctrl(DWORD ctrltype)
#else
static BOOL WINAPI sig_handle_abort_ctrl(DWORD ctrltype)
#endif
{
	sig_handle_abort(SIGINT);
	return TRUE;
}
#endif

static void sig_install_abort(void)
{
#ifdef __DJGPP__
	setcbrk(1);
#elif defined(WIN32_SIGNAL_HANDLER)
/*
 * "If the HandlerRoutine parameter is NULL, [...] a FALSE value restores
 * normal processing of CTRL+C input.  This attribute of ignoring or processing
 * CTRL+C is inherited by child processes."  So restore normal processing here
 * in case our parent (such as Johnny the GUI) had disabled it.
 */
	SetConsoleCtrlHandler(NULL, FALSE);
	SetConsoleCtrlHandler(sig_handle_abort_ctrl, TRUE);
#endif

	signal(SIGINT, sig_handle_abort);
	signal(SIGTERM, sig_handle_abort);
#ifdef SIGXCPU
	signal(SIGXCPU, sig_handle_abort);
#endif
#ifdef SIGXFSZ
	signal(SIGXFSZ, sig_handle_abort);
#endif
}

static void sig_remove_abort(void)
{
#ifdef WIN32_SIGNAL_HANDLER
	SetConsoleCtrlHandler(sig_handle_abort_ctrl, FALSE);
#endif

	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
#ifdef SIGXCPU
	signal(SIGXCPU, SIG_DFL);
#endif
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_DFL);
#endif
}

static void sig_install_timer(void);
#ifndef BENCH_BUILD
#ifdef SIGUSR2
static void sig_handle_reload(int signum);
#endif
#endif

void sig_reset_timer(void)
{
#ifndef BENCH_BUILD
#if OS_TIMER
	timer_save_value = timer_save_interval;
#else
	timer_save_value = status_get_time() + timer_save_interval;
#endif
#endif
}

static void sig_handle_timer(int signum)
{
	int saved_errno = errno;
#if !OS_TIMER
	unsigned int time;
#endif
#ifndef BENCH_BUILD
#if OS_TIMER
	/* Some stuff only done every fourth second */
	if (((timer_save_interval - timer_save_value) & 3) == 0) {
#ifdef HAVE_MPI
		if (!event_reload && mpi_p > 1) {
			event_pending = event_mpiprobe = 1;
		}
#endif
		event_poll_files = event_pending = 1;
#ifdef SIGUSR2
		sig_install(sig_handle_reload, SIGUSR2);
#endif
	}
	if (!--timer_save_value) {
		event_save = event_pending = 1;
		event_reload = options.reload_at_save;
	}
	if (timer_abort && !--timer_abort) {
		aborted_by_timer = 1;
		if (abort_grace_time > 0)
			timer_abort = abort_grace_time;
		else if (abort_grace_time < 0)
			timer_abort = 0;
		else /* no grace time, kill immediately */
			event_abort = 1;
		sig_handle_abort(0);
	}
	if (timer_status && !--timer_status) {
		timer_status = options.status_interval;
		event_status = event_pending = 1;
	}
#else /* no OS_TIMER */
	time = status_get_time();

	/* Some stuff only done every fourth second */
	if ((time & 3) == 0) {
#ifdef HAVE_MPI
		if (!event_reload && mpi_p > 1) {
			event_pending = event_mpiprobe = 1;
		}
#endif
		event_poll_files = event_pending = 1;
#ifdef SIGUSR2
		sig_install(sig_handle_reload, SIGUSR2);
#endif
	}
	if (time >= timer_save_value) {
		timer_save_value += timer_save_interval;
		event_save = event_pending = 1;
		event_reload = options.reload_at_save;
	}
	if (timer_abort && time >= timer_abort) {
		aborted_by_timer = 1;
		if (abort_grace_time > 0)
			timer_abort += abort_grace_time;
		else if (abort_grace_time < 0)
			timer_abort = 0;
		else /* no grace time, kill immediately */
			event_abort = 1;
		sig_handle_abort(0);
	}
	if (timer_status && time >= timer_status) {
		timer_status += options.status_interval;
		event_status = event_pending = 1;
	}
#endif /* OS_TIMER */

	event_fix_state = 1;
	event_refresh_salt++;

#endif /* !BENCH_BUILD */

	if (!--timer_ticksafety_value) {
		timer_ticksafety_value = timer_ticksafety_interval;

		event_ticksafety = event_pending = 1;
	}

#ifdef HAVE_MPI
	if (tty_has_keyboard())
#else
	if (john_main_process)
#endif
	{
		int c;
#if OS_FORK
		int new_abort = 0, new_status = 0;
#endif
		while ((c = tty_getchar()) >= 0) {
#ifndef BENCH_BUILD
			char verb_msg[] = "Verbosity now 0\n";
#endif
			if (c == 3 || c == 'q') {
#if OS_FORK
				new_abort = 1;
#endif
				sig_handle_abort(0);
#ifndef BENCH_BUILD
			} else if (c == 'h') {
				event_help = event_pending = 1;
			} else if (c == '>' && options.verbosity < VERB_DEBUG) {
				options.verbosity++;
				if (john_main_process) {
					verb_msg[14] += options.verbosity;
					write_loop(2, verb_msg, sizeof(verb_msg) - 1);
				}
			} else if (c == '<' && options.verbosity > 1) {
				options.verbosity--;
				if (john_main_process) {
					verb_msg[14] += options.verbosity;
					write_loop(2, verb_msg, sizeof(verb_msg) - 1);
				}
			} else if (c == 'd' || c == 'D') {
				event_delayed_status = 1 + (c == 'D');
				write_loop(2, "Delayed status pending...\r", 26);
#endif
			} else {
#if OS_FORK
				new_status = 1;
#endif
				event_status = event_pending = 1;
				if (c == 's' || c == 'S')
					event_status = 2;
			}
		}

#if OS_FORK
		if (new_abort || new_status)
			signal_children(new_abort ? SIGTERM : SIGUSR1);
#endif
	}

#if !OS_TIMER
	signal(SIGALRM, sig_handle_timer);
#elif !defined(SA_RESTART) && !defined(__DJGPP__)
	sig_install_timer();
#endif

	errno = saved_errno;
}

#if OS_TIMER
static void sig_init_timer(void)
{
	struct itimerval it;

	it.it_value.tv_sec = TIMER_INTERVAL;
	it.it_value.tv_usec = 0;
#if defined(SA_RESTART) || defined(__DJGPP__)
	it.it_interval = it.it_value;
#else
	memset(&it.it_interval, 0, sizeof(it.it_interval));
#endif
	if (setitimer(ITIMER_REAL, &it, NULL))
		pexit("setitimer");
}
#endif

static void sig_install_timer(void)
{
#if !OS_TIMER
	signal(SIGALRM, sig_handle_timer);
	sig_timer_emu_init(TIMER_INTERVAL * clk_tck);
#else
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handle_timer;
#ifdef SA_RESTART
	sa.sa_flags = SA_RESTART;
#endif
	sigaction(SIGALRM, &sa, NULL);
#if !defined(SA_RESTART) && !defined(__DJGPP__)
	siginterrupt(SIGALRM, 0);
#endif

	sig_init_timer();
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

#ifdef SIGUSR1
static void sig_handle_status(int signum)
{
	/* We currently disable --fork for Cygwin in os.h due to problems
	   with proper session save when a job is aborted. This cludge
	   could be a workaround: First press a key, then abort it after
	   status line was printed. */
#if OS_FORK && defined(__CYGWIN32__) && !defined(BENCH_BUILD)
	if (options.fork)
		event_save = 1;
#endif
	/* Similar cludge for MPI. Only SIGUSR1 is supported for showing
	   status because the fascist MPI daemons will send us a SIGKILL
	   seconds after a SIGHUP and there's nothing we can do about it. */
#ifdef HAVE_MPI
	if (mpi_p > 1 || getenv("OMPI_COMM_WORLD_SIZE"))
		event_save = 1;
#endif
	event_status = event_pending = 1;
#ifndef SA_RESTART
	sig_install(sig_handle_status, signum);
#endif
}
#endif

#ifndef BENCH_BUILD
#ifdef SIGUSR2
static void sig_handle_reload(int signum)
{
#if OS_FORK && !defined(BENCH_BUILD)
	if (!event_reload && options.fork) {
		if (john_main_process)
			signal_children(signum);
		else
			kill(getppid(), signum);
	}
#endif
	if (!event_abort)
		event_reload = 1;
	/* Avoid loops from signalling ppid. We re-enable this signal
	   in sig_handle_timer() */
	signal(signum, SIG_IGN);
}
#endif
#endif

static void sig_done(void);

void sig_preinit(void)
{
#ifdef SIGUSR2
	sig_remove_reload();
#endif
#ifdef SIGUSR1
	sig_install(sig_handle_status, SIGUSR1);
#endif
}

void sig_init(void)
{
	clk_tck_init();

	timer_save_interval = cfg_get_int(SECTION_OPTIONS, NULL, "Save");
	if (timer_save_interval < 0)
		timer_save_interval = TIMER_SAVE_DELAY;
	else
	if ((timer_save_interval /= TIMER_INTERVAL) <= 0)
		timer_save_interval = 1;
	if (cfg_get_param(SECTION_OPTIONS, NULL, "AbortGraceTime")) {
		abort_grace_time =
			cfg_get_int(SECTION_OPTIONS, NULL, "AbortGraceTime");
	}

	timer_ticksafety_interval = (clock_t)1 << (sizeof(clock_t) * 8 - 4);
	timer_ticksafety_interval /= clk_tck;
	if ((timer_ticksafety_interval /= TIMER_INTERVAL) <= 0)
		timer_ticksafety_interval = 1;
	timer_ticksafety_value = timer_ticksafety_interval;

	atexit(sig_done);

	sig_install_abort();
}

void sig_init_late(void)
{
#ifndef BENCH_BUILD
	unsigned int time;

#if OS_TIMER
	timer_save_value = timer_save_interval + ((NODE + 1) & 63);

	time = 0;
#else
	timer_save_value =
		status_get_time() + timer_save_interval + ((NODE + 1) & 63);
	time = status_get_time();
#endif
#endif

	sig_install(sig_handle_update, SIGHUP);
	sig_install_timer();
#ifndef BENCH_BUILD
	if (options.max_run_time)
		timer_abort = time + abs(options.max_run_time);
	if (options.status_interval)
		timer_status = time + options.status_interval;
#endif
}

void sig_init_child(void)
{
#ifdef SIGUSR1
	sig_install(sig_handle_status, SIGUSR1);
#endif
#ifdef SIGUSR2
	sig_remove_reload();
#endif
}

static void sig_done(void)
{
	sig_remove_update();
	sig_remove_abort();
	sig_remove_timer();
#ifdef SIGUSR2
	sig_remove_reload();
#endif
}

void sig_help(void)
{
	fprintf(stderr, "The following keypresses are recognized:\n"
	    "'q' or Ctrl-C to abort\n"
	    "'h' for help (this message)\n"
	    "'>' and '<' to increase or decrease verbosity, respectively\n"
	    "'s' for detailed status (and changes since its previous display)\n"
	    "'d' for delayed status (right upon completion of current batch)\n"
	    "'D' for delayed detailed status\n"
	    "Almost any other key for simple status\n");
	event_help = 0;
}
