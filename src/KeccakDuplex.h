/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by the designers,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakDuplex_h_
#define _KeccakDuplex_h_

#include "KeccakF-1600-interface.h"

#ifdef ALIGN
#undef ALIGN
#endif

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

/**
  * Structure that contains the duplex instance for use with the
  * Keccak_Duplex* functions.
  * It gathers the state processed by the permutation as well as
  * the rate.
  */
ALIGN typedef struct Keccak_DuplexInstanceStruct {
    /** The state processed by the permutation. */
    ALIGN unsigned char state[KeccakF_width/8];
    /** The value of the rate in bits.*/
    unsigned int rate;
} Keccak_DuplexInstance;

/**
  * Function to initialize a duplex object Duplex[Keccak-f[r+c], pad10*1, r].
  * @param  duplexInstance  Pointer to the duplex instance to be initialized.
  * @param  rate        The value of the rate r.
  * @param  capacity    The value of the capacity c.
  * @pre    One must have r+c=1600 in this implementation.
  * @pre    3 ≤ @a rate ≤ 1600, and otherwise the value of the rate is unrestricted.
  * @return Zero if successful, 1 otherwise.
  */
int Keccak_DuplexInitialize(Keccak_DuplexInstance *duplexInstance, unsigned int rate, unsigned int capacity);

/**
  * Function to make a duplexing call to the duplex object initialized
  * with Keccak_DuplexInitialize().
  * @param  duplexInstance  Pointer to the duplex instance initialized
  *                     by Keccak_DuplexInitialize().
  * @param  sigmaBegin  Pointer to the first part of the input σ given as bytes.
  *                     Trailing bits are given in @a delimitedSigmaEnd.
  * @param  sigmaBeginByteLen   The number of input bytes provided in @a sigmaBegin.
  * @param  Z           Pointer to the buffer where to store the output data Z.
  * @param  ZByteLen    The number of output bytes desired for Z.
  *                     If @a ZByteLen*8 is greater than the rate r,
  *                     the last byte contains only r modulo 8 bits,
  *                     in the least significant bits.
  * @param  delimitedSigmaEnd   Byte containing from 0 to 7 trailing bits that must be
  *                     appended to the input data in @a sigmaBegin.
  *                     These <i>n</i>=|σ| mod 8 bits must be in the least significant bit positions.
  *                     These bits must be delimited with a bit 1 at position <i>n</i>
  *                     (counting from 0=LSB to 7=MSB) and followed by bits 0
  *                     from position <i>n</i>+1 to position 7.
  *                     Some examples:
  *                         - If |σ| is a multiple of 8, then @a delimitedSigmaEnd must be 0x01.
  *                         - If |σ| mod 8 is 1 and the last bit is 1 then @a delimitedSigmaEnd must be 0x03.
  *                         - If |σ| mod 8 is 4 and the last 4 bits are 0,0,0,1 then @a delimitedSigmaEnd must be 0x18.
  *                         - If |σ| mod 8 is 6 and the last 6 bits are 1,1,1,0,0,1 then @a delimitedSigmaEnd must be 0x67.
  *                     .
  * @note   The input bits σ are the result of the concatenation of the bytes in @a sigmaBegin
  *                     and the bits in @a delimitedSigmaEnd before the delimiter.
  * @pre    @a delimitedSigmaEnd ≠ 0x00
  * @pre    @a sigmaBeginByteLen*8+<i>n</i> ≤ (r-2)
  * @pre    @a ZByteLen ≤ ceil(r/8)
  * @return Zero if successful, 1 otherwise.
  */
int Keccak_Duplexing(Keccak_DuplexInstance *duplexInstance, const unsigned char *sigmaBegin, unsigned int sigmaBeginByteLen, unsigned char *Z, unsigned int ZByteLen, unsigned char delimitedSigmaEnd);

#endif
