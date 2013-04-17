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

#include <string.h>
#include "KeccakDuplex.h"
#include "KeccakF-1600-interface.h"
#ifdef KeccakReference
#include "displayIntermediateValues.h"
#endif

int InitDuplex(duplexState *state, unsigned int rate, unsigned int capacity)
{
    if (rate+capacity != 1600)
        return 1;
    if ((rate <= 0) || (rate > 1600))
        return 1;
    KeccakInitialize();
    state->rate = rate;
    state->capacity = capacity;
    state->rho_max = rate-2;
    KeccakInitializeState(state->state);
    return 0;
}

int Duplexing(duplexState *state, const unsigned char *in, unsigned int inBitLen, unsigned char *out, unsigned int outBitLen)
{
    ALIGN unsigned char block[KeccakPermutationSizeInBytes];

    if (inBitLen > state->rho_max)
        return 1;
    if ((inBitLen % 8) != 0) {
        unsigned char mask = ~((1 << (inBitLen % 8)) - 1);
        if ((in[inBitLen/8] & mask) != 0)
            return 1; // The bits of the last incomplete byte must be aligned on the LSB
    }
    if (outBitLen > state->rate)
        return 1; // The output length must not be greater than the rate

    memcpy(block, in, (inBitLen+7)/8);
    memset(block+(inBitLen+7)/8, 0, ((state->rate+63)/64)*8 - (inBitLen+7)/8);

    block[inBitLen/8] |= 1 << (inBitLen%8);
    block[(state->rate-1)/8] |= 1 << ((state->rate-1) % 8);

    #ifdef KeccakReference
    displayBytes(1, "Block to be absorbed (after padding)", block, (state->rate+7)/8);
    #endif
    KeccakAbsorb(state->state, block, (state->rate+63)/64);

    KeccakExtract(state->state, block, (state->rate+63)/64);
    memcpy(out, block, (outBitLen+7)/8);
    if ((outBitLen % 8) != 0) {
        unsigned char mask = (1 << (outBitLen % 8)) - 1;
        out[outBitLen/8] &= mask;
    }

    return 0;
}
