/*
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions go in this file.
 *
 * This software is
 * Copyright (c) 2014 by Sayantan Datta
 * Copyright (c) 2012-2016 Claudio André <claudioandre.br at gmail.com>
 * and is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#ifndef _JOHN_OPENCL_MASK_EXTRAS_H
#define _JOHN_OPENCL_MASK_EXTRAS_H

#ifdef _OPENCL_COMPILER
//To keep Sayantan license, some code was moved to this file.

#ifndef BITMAP_SIZE_MINUS1
#define BITMAP_SIZE_MINUS1 0
#endif

#define MASK_KEYS_GENERATION(id)                                    \
        uint32_t ikl = int_key_loc[get_global_id(0)];               \
        uint32_t pos = (ikl & 0xff) + W_OFFSET;                     \
        PUTCHAR(w, pos, (int_keys[id] & 0xff));                     \
                                                                    \
        pos = ((ikl & 0xff00U) >> 8) + W_OFFSET;                    \
        if ((ikl & 0xff00) != 0x8000)                               \
            PUTCHAR(w, pos, ((int_keys[id] & 0xff00U) >> 8));       \
                                                                    \
        pos = ((ikl & 0xff0000U) >> 16) + W_OFFSET;                 \
        if ((ikl & 0xff0000) != 0x800000)                           \
            PUTCHAR(w, pos, ((int_keys[id] & 0xff0000U) >> 16));    \
                                                                    \
        pos = ((ikl & 0xff000000U) >> 24) + W_OFFSET;               \
        if ((ikl & 0xff000000) != 0x80000000)                       \
            PUTCHAR(w, pos, ((int_keys[id] & 0xff000000U) >> 24));  \

#endif

#endif
