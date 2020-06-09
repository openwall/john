/* This program gives the 64-bit optimized bitslice implementation of JH using ANSI C

   --------------------------------
   Performance

   Microprocessor: Intel CORE 2 processor (Core 2 Duo Mobile T6600 2.2GHz)
   Operating System: 64-bit Ubuntu 10.04 (Linux kernel 2.6.32-22-generic)
   Speed for long message:
   1) 45.8 cycles/byte   compiler: Intel C++ Compiler 11.1   compilation option: icc -O2
   2) 56.8 cycles/byte   compiler: gcc 4.4.3                 compilation option: gcc -O3

   --------------------------------
   Last Modified: January 16, 2011
*/

#ifndef _JOHN_JH_H
#define _JOHN_JH_H

typedef unsigned char BitSequenceJH;
typedef unsigned long long DataLengthJH;
typedef enum {SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2} HashReturn;

HashReturn jh_hash(int hashbitlen, const BitSequenceJH *data, DataLengthJH databitlen, BitSequenceJH *hashval);

#endif
