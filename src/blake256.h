// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#ifndef _BLAKE256_H_
#define _BLAKE256_H_

#include <stdint.h>

typedef struct {
	uint32_t h[8], s[4], t[2];
	int buflen, nullt;
	uint8_t buf[64];
} state;

typedef struct {
	state inner;
	state outer;
} hmac_state;

void blake256_init(state *);
void blake224_init(state *);

void blake256_update(state *, const uint8_t *, uint64_t);
void blake224_update(state *, const uint8_t *, uint64_t);

void blake256_final(state *, uint8_t *);
void blake224_final(state *, uint8_t *);

void blake256_hash(uint8_t *, const uint8_t *, uint64_t);
void blake224_hash(uint8_t *, const uint8_t *, uint64_t);

/* HMAC functions: */

void hmac_blake256_init(hmac_state *, const uint8_t *, uint64_t);
void hmac_blake224_init(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake256_update(hmac_state *, const uint8_t *, uint64_t);
void hmac_blake224_update(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake256_final(hmac_state *, uint8_t *);
void hmac_blake224_final(hmac_state *, uint8_t *);

void hmac_blake256_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);
void hmac_blake224_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);

#endif /* _BLAKE256_H_ */
