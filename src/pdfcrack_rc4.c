/**
 * Copyright (C) 2006 Henning Norén
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */
#include <string.h>
#include <assert.h>

#include "pdfcrack_rc4.h"

#ifdef _MSC_VER
#define inline _inline
#endif
#ifndef __GNUC__
#define ATTR_PURE
#define likely(x)       (x)
#define unlikely(x)     (x)
#else
#define ATTR_PURE __attribute__ ((pure))
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif

/** Seems to faster to do a memcpy of this on my machine than to create
    the array with a loop
*/
static const uint8_t
initial_state[256] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
  0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
  0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
  0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
  0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
  0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
  0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
  0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
  0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
  0xfc, 0xfd, 0xfe, 0xff};

#define key_pass(n) {				\
    tmp = state[++i];				\
    j = (j + tmp + key[n]);			\
    state[i] = state[j];			\
    state[j] = tmp;				\
  }

/** Do rc4-decrypt with key on bs of length 32 and compare it to match */
ATTR_PURE bool
rc4Match40b(const uint8_t *key, const uint8_t *bs,const uint8_t *match) {
  uint8_t state[256];
  register unsigned int i;
  register uint8_t j, tmp;

  /** initialize the state */
  memcpy(state, initial_state, 256);

  /** do the shuffle */
  j = key[0];
  state[0] = j;
  state[j] = 0;
  i = 0;
  do {
    key_pass(1);
    key_pass(2);
    key_pass(3);
    key_pass(4);
    key_pass(0);
  } while(i < 255);

  j = 0;
  for(i=1;i<=32;++i) {
    tmp = state[i];
    j += tmp;
    state[i] = state[j];
    state[j] = tmp;

    /**
	Only continue if we match the match-strings characters.
	The match should only happen once every 256 try or so and that is
	the motivation behind the likely-hint
    */
    tmp += state[i];
    if(likely((bs[i-1]^state[tmp]) != match[i-1]))
      return false;
  }
  return true;
}

static void
(*rc4d)(const uint8_t *key, const uint8_t *bs,
	const unsigned int len, uint8_t *out) = NULL;

/** Do 40-bit rc4-decrypt with key on bs of length len and
    put the result in out
*/
static void
rc4Decrypt40b(const uint8_t *key, const uint8_t *bs,
	      const unsigned int len, uint8_t *out) {
  uint8_t state[256];
  register unsigned int i;
  register uint8_t j, tmp;

  assert(len < 256);

  /** initialize the state */
  memcpy(state, initial_state, 256);

  /** do the shuffle */
  j = key[0];
  state[0] = j;
  state[j] = 0;
  i = 0;
  do {
    key_pass(1);
    key_pass(2);
    key_pass(3);
    key_pass(4);
    key_pass(0);
  } while(i < 255);

  j = 0;
  for(i=1;i<=len;++i) {
    tmp = state[i];
    j += tmp;
    state[i] = state[j];
    state[j] = tmp;

    tmp += state[i];
    out[i-1] = bs[i-1]^state[tmp];
  }
}

/** Do 128-bit rc4-decrypt with key on bs of length len and
    put the result in out
*/
static void
rc4Decrypt128b(const uint8_t *key, const uint8_t *bs,
	       const unsigned int len, uint8_t *out) {
  uint8_t state[256];
  register int i;
  register uint8_t j, tmp;

  assert(len < 256);

  /** initialize the state */
  memcpy(state, initial_state, 256);

  /** do the shuffle */
  j = 0;
  i = -1;
  do {
    key_pass( 0);
    key_pass( 1);
    key_pass( 2);
    key_pass( 3);
    key_pass( 4);
    key_pass( 5);
    key_pass( 6);
    key_pass( 7);
    key_pass( 8);
    key_pass( 9);
    key_pass(10);
    key_pass(11);
    key_pass(12);
    key_pass(13);
    key_pass(14);
    key_pass(15);
  } while(i < 255);

  j = 0;
  for(i=1;(unsigned int)i<=len;++i) {
    tmp = state[i];
    j += tmp;
    state[i] = state[j];
    state[j] = tmp;

    tmp += state[i];
    out[i-1] = bs[i-1]^state[tmp];
  }
}

/** Just a wrapper for the function optimized for a specific length */
void
rc4Decrypt(const uint8_t *key, const uint8_t *bs,
	   const unsigned int len, uint8_t *out) {
  rc4d(key, bs, len, out);
}

/** sets which function the wrapper should call */
ATTR_PURE bool
setrc4DecryptMethod(const unsigned int length) {
  if(length == 128)
    rc4d = &rc4Decrypt128b;
  else if(length == 40)
    rc4d = &rc4Decrypt40b;
  else
    return false;
  return true;
}
