/* modified 19jul1996 by robey -- uses autoconf values now */
#ifndef _H_BLOWFISH
#define _H_BLOWFISH

#include "arch.h"

#define bf_N             16
#define noErr            0
#define DATAERROR        -1

#define UBYTE_08bits  unsigned char
#define UWORD_16bits  unsigned short

#if !defined(SIZEOF_INT) || SIZEOF_INT==4
#define UWORD_32bits  unsigned int
#else
#if SIZEOF_LONG==4
#define UWORD_32bits  unsigned long
#endif
#endif

/* choose a byte order for your hardware */

#if !ARCH_LITTLE_ENDIAN
/* ABCD - big endian - motorola */
union aword {
  UWORD_32bits word;
  UBYTE_08bits byte[4];
  struct {
    unsigned int byte0:8;
    unsigned int byte1:8;
    unsigned int byte2:8;
    unsigned int byte3:8;
  } w;
};
#endif				/* !ARCH_LITTLE_ENDIAN */

#if ARCH_LITTLE_ENDIAN
/* DCBA - little endian - intel */
union aword {
  UWORD_32bits word;
  UBYTE_08bits byte[4];
  struct {
    unsigned int byte3:8;
    unsigned int byte2:8;
    unsigned int byte1:8;
    unsigned int byte0:8;
  } w;
};

#endif				/* ARCH_LITTLE_ENDIAN */

#endif
