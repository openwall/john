/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006,2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Signal handling.
 */

#ifndef _JOHN_SIGNALS_H
#define _JOHN_SIGNALS_H

#ifndef _JOHN_OS_H
#error Need to include os.h before signals.h
#endif

#include "arch.h"

/*
 * Event flags.
 *
 * Why aren't these put into a bitmask? The reason is that it's not possible
 * to clear individual flags in a bitmask without a race condition on RISC,
 * or having to block the signals.
 */
extern volatile int event_pending;	/* An event is pending */
extern volatile int event_abort;	/* Abort requested */
extern volatile int event_reload;	/* Restart requested */
extern volatile int event_save;		/* Save the crash recovery file */
extern volatile int event_status;	/* Status display requested */
extern volatile int event_ticksafety;	/* System time in ticks may overflow */

/* --max-run-time timer, zero if reached */
extern volatile int timer_abort;

/* --progress-every timer */
extern volatile int timer_status;

/* --reload-every timer */
extern volatile int timer_reload;

#if !OS_TIMER
/*
 * Timer emulation for systems with no setitimer(2).
 */
#include <time.h>
#if HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif

extern void sig_timer_emu_init(clock_t interval);
extern void sig_timer_emu_tick(void);
#endif

/*
 * Installs the signal handlers.
 */
extern void sig_init(void);

/*
 * Performs additional (re-)initialization after fork().  Assumes that
 * sig_init() has already been called.
 */
extern void sig_init_child(void);

/*
 * Terminates the process if event_abort is set.
 */
extern void check_abort(int be_async_signal_safe);

/*
 * Reset signals and timers. Normally called via atexit() but not when execv().
 */
void sig_done(void);
#endif
