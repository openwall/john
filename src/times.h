/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Workaround a DJGPP time functions problem which could cause the system
 * date not to advance at midnight when a BIOS time query function resets
 * the overflow flag before DOS has a chance to see it. Note that there's
 * still a race condition in the code below, it's just far less likely to
 * cause any harm. The real fix would be more complicated...
 */

#if !defined(_JOHN_TIMES_H) && defined(__DJGPP__)
#define _JOHN_TIMES_H

#include <sys/times.h>
#include <dpmi.h>

inline static clock_t safe_times(struct tms *buffer)
{
	__dpmi_regs r;

	r.h.ah = 0x2C;
	__dpmi_int(0x21, &r);

	return times(buffer);
}

#define times				safe_times

#endif
