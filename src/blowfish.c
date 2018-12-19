/*
 * blowfish.c - part of blowfish.mod
 * handles: encryption and decryption of passwords
 */
/*
 * The first half of this is very lightly edited from public domain
 * sourcecode.  For simplicity, this entire module will remain public
 * domain.
 */
/*
 * This is ripped from eggdrop 1.3.28's source files (blowfish.mod)
 * Modified by Sun-Zero <sun-zero at freemail.hu>
 * 2002-04-16
*/

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blowfish.h"
#include "bf_tab.h"		/* P-box P-array, S-box */
#include "memory.h"
#include "johnswap.h"

/* #define S(x,i) (bf_S[i][x.w.byte##i]) */
#define S0(x) (bf_S[0][x.w.byte0])
#define S1(x) (bf_S[1][x.w.byte1])
#define S2(x) (bf_S[2][x.w.byte2])
#define S3(x) (bf_S[3][x.w.byte3])
#define bf_F(x) (((S0(x) + S1(x)) ^ S2(x)) + S3(x))
#define ROUND(a,b,n) (a.word ^= bf_F(b) ^ bf_P[n])

static void blowfish_encipher(UWORD_32bits *bf_P, UWORD_32bits bf_S[][256], UWORD_32bits * xl, UWORD_32bits * xr)
{
  union aword Xl;
  union aword Xr;

  Xl.word = *xl;
  Xr.word = *xr;

  Xl.word ^= bf_P[0];
  ROUND(Xr, Xl, 1);
  ROUND(Xl, Xr, 2);
  ROUND(Xr, Xl, 3);
  ROUND(Xl, Xr, 4);
  ROUND(Xr, Xl, 5);
  ROUND(Xl, Xr, 6);
  ROUND(Xr, Xl, 7);
  ROUND(Xl, Xr, 8);
  ROUND(Xr, Xl, 9);
  ROUND(Xl, Xr, 10);
  ROUND(Xr, Xl, 11);
  ROUND(Xl, Xr, 12);
  ROUND(Xr, Xl, 13);
  ROUND(Xl, Xr, 14);
  ROUND(Xr, Xl, 15);
  ROUND(Xl, Xr, 16);
  Xr.word ^= bf_P[17];

  *xr = Xl.word;
  *xl = Xr.word;
}

static void blowfish_init(UWORD_32bits bf_P[], UWORD_32bits (*bf_S)[256], UBYTE_08bits * key, short keybytes)
{
  int i, j;
  UWORD_32bits data;
  UWORD_32bits datal;
  UWORD_32bits datar;
  union aword temp;

  /* robey: reset blowfish boxes to initial state */
  /* (i guess normally it just keeps scrambling them, but here it's
   * important to get the same encrypted result each time) */
  for (i = 0; i < bf_N + 2; i++)
    bf_P[i] = initbf_P[i];
  for (i = 0; i < 4; i++)
    for (j = 0; j < 256; j++)
      bf_S[i][j] = initbf_S[i][j];

  j = 0;
  for (i = 0; i < bf_N + 2; ++i) {
    temp.word = 0;
    temp.w.byte0 = key[j];
    temp.w.byte1 = key[(j + 1) % keybytes];
    temp.w.byte2 = key[(j + 2) % keybytes];
    temp.w.byte3 = key[(j + 3) % keybytes];
    data = temp.word;
    bf_P[i] = bf_P[i] ^ data;
    j = (j + 4) % keybytes;
  }
  datal = 0x00000000;
  datar = 0x00000000;
  for (i = 0; i < bf_N + 2; i += 2) {
    blowfish_encipher(bf_P, bf_S, &datal, &datar);
    bf_P[i] = datal;
    bf_P[i + 1] = datar;
  }
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 256; j += 2) {
      blowfish_encipher(bf_P, bf_S, &datal, &datar);
      bf_S[i][j] = datal;
      bf_S[i][j + 1] = datar;
    }
  }
}

/* stuff below this line was written by robey for eggdrop use */

/* of course, if you change either of these, then your userfile will
 * no longer be able to be shared. :) */
#define SALT1  0xdeadd061
#define SALT2  0x23f6b095

static void blowfish_encrypt_pass(char *text, char *new)
{
  UWORD_32bits left, right;
  UWORD_32bits bf_S[4][256];
  UWORD_32bits bf_P[bf_N+2];

  blowfish_init(bf_P, bf_S, (UBYTE_08bits *) text, strlen(text));
  left = SALT1;
  right = SALT2;
  blowfish_encipher(bf_P, bf_S, &left, &right);

#if 1
#if !ARCH_LITTLE_ENDIAN
  left = JOHNSWAP(left);
  right = JOHNSWAP(right);
#endif
  /* We lose one byte due to flawed base64 below */
  memcpy(new, (unsigned char*)&right, 32/8);
  memcpy(new + 32/8, (unsigned char*)&left, 32/8 - 1);
#else
  int n;
  char *p;

  p = new;
  *p++ = '+';			/* + means encrypted pass */
  n = 32;
  while (n > 0) {
    *p++ = base64[right & 0x3f];
    right = (right >> 6);
    n -= 6;
  }
  n = 32;
  while (n > 0) {
    *p++ = base64[left & 0x3f];
    left = (left >> 6);
    n -= 6;
  }
  *p = 0;
#endif
}
