/*
 * This file is Copyright (c) 2021 by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _JOHN_TIMER_H
#define _JOHN_TIMER_H

extern const char* john_nano_clock;

extern uint64_t john_get_nano(void);            // Get a nanosecond timestamp
extern uint64_t john_timer_stats(int *latency); // Return resolution/latency

#endif /* _JOHN_TIMER_H */
