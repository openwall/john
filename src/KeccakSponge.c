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
#include "KeccakSponge.h"
#include "KeccakF-1600-interface.h"
#include "johnswap.h"

/* ---------------------------------------------------------------- */

int Keccak_SpongeInitialize(Keccak_SpongeInstance *instance, unsigned int rate, unsigned int capacity)
{
    if (rate+capacity != 1600)
        return 1;
    if ((rate <= 0) || (rate > 1600) || ((rate % 8) != 0))
        return 1;
    KeccakF1600_Initialize();
    KeccakF1600_StateInitialize(instance->state);
    instance->rate = rate;
    instance->byteIOIndex = 0;
    instance->squeezing = 0;

    return 0;
}

/* ---------------------------------------------------------------- */

int Keccak_SpongeAbsorb(Keccak_SpongeInstance *instance, const unsigned char *data, unsigned long long dataByteLen)
{
    unsigned long long i, j;
    unsigned int partialBlock;
    const unsigned char *curData;
    unsigned int rateInBytes = instance->rate/8;

#if !ARCH_LITTLE_ENDIAN
    unsigned long long lldat[rateInBytes/8];
    const unsigned long long *ll;
#endif

    if (instance->squeezing)
        return 1; // Too late for additional input

    i = 0;
    curData = data;
    while(i < dataByteLen) {
        if ((instance->byteIOIndex == 0) && (dataByteLen >= (i + rateInBytes))) {
            // fast lane: processing whole blocks first
            for (j=dataByteLen-i; j>=rateInBytes; j-=rateInBytes) {
                if ((rateInBytes % KeccakF_laneInBytes) > 0)
                    KeccakF1600_StateXORBytesInLane(instance->state, rateInBytes/KeccakF_laneInBytes,
                        curData+(rateInBytes/KeccakF_laneInBytes)*KeccakF_laneInBytes,
                        0, rateInBytes%KeccakF_laneInBytes);
#if !ARCH_LITTLE_ENDIAN
		ll = (const unsigned long long *)curData;
		for (i = 0; i < rateInBytes/8; ++i)
			lldat[i] = JOHNSWAP64(ll[i]);
                KeccakF1600_StateXORPermuteExtract(instance->state, (const unsigned char *)lldat, rateInBytes/KeccakF_laneInBytes, 0, 0);
#else
                KeccakF1600_StateXORPermuteExtract(instance->state, curData, rateInBytes/KeccakF_laneInBytes, 0, 0);
#endif
                curData+=rateInBytes;
            }
            i = dataByteLen - j;
        }
        else {
            // normal lane: using the message queue
            partialBlock = (unsigned int)(dataByteLen - i);
            if (partialBlock+instance->byteIOIndex > rateInBytes)
                partialBlock = rateInBytes-instance->byteIOIndex;
            i += partialBlock;
            if ((instance->byteIOIndex == 0) && (partialBlock >= KeccakF_laneInBytes)) {
                KeccakF1600_StateXORLanes(instance->state, curData, partialBlock/KeccakF_laneInBytes);
                curData += (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes;
                instance->byteIOIndex += (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes;
                partialBlock -= (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes;
            }
            while(partialBlock > 0) {
                unsigned int offsetInLane = instance->byteIOIndex % KeccakF_laneInBytes;
                unsigned int bytesInLane = KeccakF_laneInBytes - offsetInLane;
                if (bytesInLane > partialBlock)
                    bytesInLane = partialBlock;
                KeccakF1600_StateXORBytesInLane(instance->state, instance->byteIOIndex/KeccakF_laneInBytes, curData, offsetInLane, bytesInLane);
                curData += bytesInLane;
                instance->byteIOIndex += bytesInLane;
                partialBlock -= bytesInLane;
            }
            if (instance->byteIOIndex == rateInBytes) {
                KeccakF1600_StatePermute(instance->state);
                instance->byteIOIndex = 0;
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- */

int Keccak_SpongeAbsorbLastFewBits(Keccak_SpongeInstance *instance, unsigned char delimitedData)
{
    unsigned char delimitedData1[8]; // allocate 8 bytes (instead of 1) to make ASan happy
    unsigned int rateInBytes = instance->rate/8;

    if (delimitedData == 0)
        return 1;
    if (instance->squeezing)
        return 1; // Too late for additional input

    delimitedData1[0] = delimitedData;
    #ifdef KeccakReference
    displayBytes(1, "Block to be absorbed (last few bits + first bit of padding)", delimitedData1, 1);
    #endif
    // Last few bits, whose delimiter coincides with first bit of padding
    KeccakF1600_StateXORBytesInLane(instance->state, instance->byteIOIndex/KeccakF_laneInBytes,
        delimitedData1, instance->byteIOIndex%KeccakF_laneInBytes, 1);
    // If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding
    if ((delimitedData >= 0x80) && (instance->byteIOIndex == (rateInBytes-1)))
        KeccakF1600_StatePermute(instance->state);
    // Second bit of padding
    KeccakF1600_StateComplementBit(instance->state, rateInBytes*8-1);
    #ifdef KeccakReference
    {
        unsigned char block[KeccakF_width/8];
        memset(block, 0, KeccakF_width/8);
        block[rateInBytes-1] = 0x80;
        displayBytes(1, "Second bit of padding", block, rateInBytes);
    }
    #endif
    KeccakF1600_StatePermute(instance->state);
    instance->byteIOIndex = 0;
    instance->squeezing = 1;
    #ifdef KeccakReference
    displayText(1, "--- Switching to squeezing phase ---");
    #endif
    return 0;
}

/* ---------------------------------------------------------------- */

int Keccak_SpongeSqueeze(Keccak_SpongeInstance *instance, unsigned char *data, unsigned long long dataByteLen)
{
    unsigned long long i, j;
    unsigned int partialBlock;
    unsigned int rateInBytes = instance->rate/8;
    unsigned char *curData;

    if (!instance->squeezing)
        Keccak_SpongeAbsorbLastFewBits(instance, 0x01);

    i = 0;
    curData = data;
    while(i < dataByteLen) {
        if ((instance->byteIOIndex == rateInBytes) && (dataByteLen >= (i + rateInBytes))) {
            // fast lane: processing whole blocks first
            for (j=dataByteLen-i; j>=rateInBytes; j-=rateInBytes) {
                KeccakF1600_StateXORPermuteExtract(instance->state, 0, 0, curData, rateInBytes/KeccakF_laneInBytes);
                if ((rateInBytes % KeccakF_laneInBytes) > 0)
                    KeccakF1600_StateExtractBytesInLane(instance->state, rateInBytes/KeccakF_laneInBytes,
                        curData+(rateInBytes/KeccakF_laneInBytes)*KeccakF_laneInBytes, 0,
                        rateInBytes%KeccakF_laneInBytes);
                #ifdef KeccakReference
                displayBytes(1, "Squeezed block", curData, rateInBytes);
                #endif
                curData+=rateInBytes;
            }
            i = dataByteLen - j;
        }
        else {
            // normal lane: using the message queue
            if (instance->byteIOIndex == rateInBytes) {
                KeccakF1600_StatePermute(instance->state);
                instance->byteIOIndex = 0;
            }
            partialBlock = (unsigned int)(dataByteLen - i);
            if (partialBlock+instance->byteIOIndex > rateInBytes)
                partialBlock = rateInBytes-instance->byteIOIndex;
            i += partialBlock;
            if ((instance->byteIOIndex == 0) && (partialBlock >= KeccakF_laneInBytes)) {
                KeccakF1600_StateExtractLanes(instance->state, curData, partialBlock/KeccakF_laneInBytes);
                #ifdef KeccakReference
                displayBytes(1, "Squeezed block (part)", curData, (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes);
                #endif
                curData += (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes;
                instance->byteIOIndex += (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes;
                partialBlock -= (partialBlock/KeccakF_laneInBytes)*KeccakF_laneInBytes;
            }
            while(partialBlock > 0) {
                unsigned int offsetInLane = instance->byteIOIndex % KeccakF_laneInBytes;
                unsigned int bytesInLane = KeccakF_laneInBytes-offsetInLane;
                if (bytesInLane > partialBlock)
                    bytesInLane = partialBlock;
                KeccakF1600_StateExtractBytesInLane(instance->state, instance->byteIOIndex/KeccakF_laneInBytes, curData, offsetInLane, bytesInLane);
                #ifdef KeccakReference
                displayBytes(1, "Squeezed block (part)", curData, bytesInLane);
                #endif
                curData += bytesInLane;
                instance->byteIOIndex += bytesInLane;
                partialBlock -= bytesInLane;
            }
        }
    }
    return 0;
}
