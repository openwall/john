/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

/*
 * Idle priority support routines.
 */

#ifndef _JOHN_IDLE_H
#define _JOHN_IDLE_H

/*
 * Sets this process to idle priority, if supported and enabled in the
 * configuration file.
 */
extern void idle_init(void);

/*
 * If the idle_init() call was unable to set the idle priority, this can
 * still be used to yield a timeslice if there's something else to do.
 */
extern void idle_yield(void);

#endif
