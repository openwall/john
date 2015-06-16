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

#ifndef _KeccakSponge_h_
#define _KeccakSponge_h_

#include "KeccakF-1600-interface.h"

// on Mac OS-X and possibly others, ALIGN(x) is defined in param.h, and -Werror chokes on the redef.
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
  * Structure that contains the sponge instance attributes for use with the
  * Keccak_Sponge* functions.
  * It gathers the state processed by the permutation as well as the rate,
  * the position of input/output bytes in the state and the phase
  * (absorbing or squeezing).
  */
ALIGN typedef struct Keccak_SpongeInstanceStruct {
    /** The state processed by the permutation. */
    ALIGN unsigned char state[KeccakF_width/8];
    /** The value of the rate in bits.*/
    unsigned int rate;
    /** The position in the state of the next byte to be input (when absorbing) or output (when squeezing). */
    unsigned int byteIOIndex;
    /** If set to 0, in the absorbing phase; otherwise, in the squeezing phase. */
    int squeezing;
} Keccak_SpongeInstance;

/**
  * Function to initialize the state of the Keccak[r, c] sponge function.
  * The phase of the sponge function is set to absorbing.
  * @param  spongeInstance  Pointer to the sponge instance to be initialized.
  * @param  rate        The value of the rate r.
  * @param  capacity    The value of the capacity c.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits (one byte) in this implementation.
  * @return Zero if successful, 1 otherwise.
  */
int Keccak_SpongeInitialize(Keccak_SpongeInstance *spongeInstance, unsigned int rate, unsigned int capacity);

/**
  * Function to give input data bytes for the sponge function to absorb.
  * @param  spongeInstance  Pointer to the sponge instance initialized by Keccak_SpongeInitialize().
  * @param  data        Pointer to the input data.
  * @param  dataByteLen  The number of input bytes provided in the input data.
  * @pre    The sponge function must be in the absorbing phase,
  *         i.e., Keccak_SpongeSqueeze() or Keccak_SpongeAbsorbLastFewBits()
  *         must not have been called before.
  * @return Zero if successful, 1 otherwise.
  */
int Keccak_SpongeAbsorb(Keccak_SpongeInstance *spongeInstance, const unsigned char *data, unsigned long long dataByteLen);

/**
  * Function to give input data bits for the sponge function to absorb
  * and then to switch to the squeezing phase.
  * @param  spongeInstance  Pointer to the sponge instance initialized by Keccak_SpongeInitialize().
  * @param  delimitedData   Byte containing from 0 to 7 trailing bits
  *                     that must be absorbed.
  *                     These <i>n</i> bits must be in the least significant bit positions.
  *                     These bits must be delimited with a bit 1 at position <i>n</i>
  *                     (counting from 0=LSB to 7=MSB) and followed by bits 0
  *                     from position <i>n</i>+1 to position 7.
  *                     Some examples:
  *                         - If no bits are to be absorbed, then @a delimitedData must be 0x01.
  *                         - If the 2-bit sequence 0,0 is to be absorbed, @a delimitedData must be 0x04.
  *                         - If the 5-bit sequence 0,1,0,0,1 is to be absorbed, @a delimitedData must be 0x32.
  *                         - If the 7-bit sequence 1,1,0,1,0,0,0 is to be absorbed, @a delimitedData must be 0x8B.
  *                     .
  * @pre    The sponge function must be in the absorbing phase,
  *         i.e., Keccak_SpongeSqueeze() or Keccak_SpongeAbsorbLastFewBits()
  *         must not have been called before.
  * @pre    @a delimitedData ≠ 0x00
  * @return Zero if successful, 1 otherwise.
  */
int Keccak_SpongeAbsorbLastFewBits(Keccak_SpongeInstance *spongeInstance, unsigned char delimitedData);

/**
  * Function to squeeze output data from the sponge function.
  * If the sponge function was in the absorbing phase, this function
  * switches it to the squeezing phase
  * as if Keccak_SpongeAbsorbLastFewBits(spongeInstance, 0x01) was called.
  * @param  spongeInstance  Pointer to the sponge instance initialized by Keccak_SpongeInitialize().
  * @param  data        Pointer to the buffer where to store the output data.
  * @param  dataByteLen The number of output bytes desired.
  * @return Zero if successful, 1 otherwise.
  */
int Keccak_SpongeSqueeze(Keccak_SpongeInstance *spongeInstance, unsigned char *data, unsigned long long dataByteLen);

#endif
