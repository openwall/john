/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Idle priority support routines.
 */

#ifndef _JOHN_IDLE_H
#define _JOHN_IDLE_H

#include "formats.h"

/*
 * Returns non-zero if idle priority is requested in the configuration file and
 * is actually to be enabled for the supplied "format".
 */
extern int idle_requested(struct fmt_main *format);

/*
 * Sets this process to idle priority if requested and supported.
 */
extern void idle_init(struct fmt_main *format);

/*
 * If the idle_init() call was unable to "fully" set the idle priority, yet it
 * was requested, this will yield a timeslice if there's something else to do.
 */
extern void idle_yield(void);

#endif
