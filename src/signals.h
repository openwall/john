/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2006 by Solar Designer
 *
 * ...with changes in the jumbo patch for mingw and MSC, by JimF.
 */

/*
 * Signal handling.
 */

#ifndef _JOHN_SIGNALS_H
#define _JOHN_SIGNALS_H

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
extern volatile int event_save;		/* Save the crash recovery file */
extern volatile int event_status;	/* Status display requested */
extern volatile int event_ticksafety;	/* System time in ticks may overflow */

/* Zero if --max-run-time was reached */
extern volatile int timer_abort;

/* Zero if --progress-every was reached */
extern volatile int timer_status;

#if !OS_TIMER
/*
 * Timer emulation for systems with no setitimer(2).
 */
#if defined (__MINGW32__) || defined (_MSC_VER)
#include <time.h>
#else
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
 * Terminates the process if event_abort is set.
 */
extern void check_abort(int be_async_signal_safe);

#endif
