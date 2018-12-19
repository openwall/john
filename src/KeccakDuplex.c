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

int Keccak_DuplexInitialize(Keccak_DuplexInstance *instance, unsigned int rate, unsigned int capacity)
{
    if (rate+capacity != 1600)
        return 1;
    if ((rate <= 2) || (rate > 1600))
        return 1;
    KeccakF1600_Initialize();
    instance->rate = rate;
    KeccakF1600_StateInitialize(instance->state);
    return 0;
}

int Keccak_Duplexing(Keccak_DuplexInstance *instance, const unsigned char *sigmaBegin, unsigned int sigmaBeginByteLen, unsigned char *Z, unsigned int ZByteLen, unsigned char delimitedSigmaEnd)
{
    unsigned char delimitedSigmaEnd1[1];
    const unsigned int rho_max = instance->rate - 2;

    if (delimitedSigmaEnd == 0)
        return 1;
    if (sigmaBeginByteLen*8 > rho_max)
        return 1;
    if (rho_max - sigmaBeginByteLen*8 < 7) {
        unsigned int maxBitsInDelimitedSigmaEnd = rho_max - sigmaBeginByteLen*8;
        if (delimitedSigmaEnd >= (1 << (maxBitsInDelimitedSigmaEnd+1)))
            return 1;
    }
    if (ZByteLen > (instance->rate+7)/8)
        return 1; // The output length must not be greater than the rate (rounded up to a byte)

    if ((sigmaBeginByteLen%KeccakF_laneInBytes) > 0) {
        unsigned int offsetBeyondLane = (sigmaBeginByteLen/KeccakF_laneInBytes)*KeccakF_laneInBytes;
        unsigned int beyondLaneBytes = sigmaBeginByteLen%KeccakF_laneInBytes;
        KeccakF1600_StateXORBytesInLane(instance->state, sigmaBeginByteLen/KeccakF_laneInBytes,
            sigmaBegin+offsetBeyondLane, 0, beyondLaneBytes);
    }

    delimitedSigmaEnd1[0] = delimitedSigmaEnd;
    // Last few bits, whose delimiter coincides with first bit of padding
    KeccakF1600_StateXORBytesInLane(instance->state, sigmaBeginByteLen/KeccakF_laneInBytes,
        delimitedSigmaEnd1, sigmaBeginByteLen%KeccakF_laneInBytes, 1);
    // Second bit of padding
    KeccakF1600_StateComplementBit(instance->state, instance->rate - 1);
    KeccakF1600_StateXORPermuteExtract(instance->state, sigmaBegin, sigmaBeginByteLen/KeccakF_laneInBytes,
        Z, ZByteLen/KeccakF_laneInBytes);

    if ((ZByteLen%KeccakF_laneInBytes) > 0) {
        unsigned int offsetBeyondLane = (ZByteLen/KeccakF_laneInBytes)*KeccakF_laneInBytes;
        unsigned int beyondLaneBytes = ZByteLen%KeccakF_laneInBytes;
        KeccakF1600_StateExtractBytesInLane(instance->state, ZByteLen/KeccakF_laneInBytes,
            Z+offsetBeyondLane, 0, beyondLaneBytes);
    }
    if (ZByteLen*8 > instance->rate) {
        unsigned char mask = (1 << (instance->rate % 8)) - 1;
        Z[ZByteLen-1] &= mask;
    }

    return 0;
}
