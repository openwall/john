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
#include <stdlib.h>
#include "brg_endian.h"
#include "KeccakHash.h"
#include "KeccakF-1600-opt64-settings.h"
#include "KeccakF-1600-interface.h"

typedef unsigned char UINT8;
typedef unsigned long long int UINT64;

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

#if defined(UseLaneComplementing)
#define UseBebigokimisa
#endif

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(UseSHLD)
    #define ROL64(x,N) ({ \
    register UINT64 __out; \
    register UINT64 __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
#endif

#include "KeccakF-1600-64.macros"
#include "KeccakF-1600-unrolling.macros"

/* ---------------------------------------------------------------- */

void KeccakF1600_Initialize( void )
{
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateInitialize(void *state)
{
    memset(state, 0, sizeof(Keccak_HashInstance));
#ifdef UseLaneComplementing
    ((UINT64*)state)[ 1] = ~(UINT64)0;
    ((UINT64*)state)[ 2] = ~(UINT64)0;
    ((UINT64*)state)[ 8] = ~(UINT64)0;
    ((UINT64*)state)[12] = ~(UINT64)0;
    ((UINT64*)state)[17] = ~(UINT64)0;
    ((UINT64*)state)[20] = ~(UINT64)0;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateXORBytesInLane(void *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    UINT64 lane = ((UINT64*)data)[0];
    if (length == 0)
        return;
    lane <<= (8-length)*8;
    lane >>= (8-length-offset)*8;
#else
    UINT64 lane = 0;
    unsigned int i;
    for (i=0; i<length; i++)
        lane |= ((UINT64)data[i]) << ((i+offset)*8);
#endif
    ((UINT64*)state)[lanePosition] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateXORLanes(void *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned int i = 0;
    for ( ; (i+8)<=laneCount; i+=8) {
        ((UINT64*)state)[i+0] ^= ((UINT64*)data)[i+0];
        ((UINT64*)state)[i+1] ^= ((UINT64*)data)[i+1];
        ((UINT64*)state)[i+2] ^= ((UINT64*)data)[i+2];
        ((UINT64*)state)[i+3] ^= ((UINT64*)data)[i+3];
        ((UINT64*)state)[i+4] ^= ((UINT64*)data)[i+4];
        ((UINT64*)state)[i+5] ^= ((UINT64*)data)[i+5];
        ((UINT64*)state)[i+6] ^= ((UINT64*)data)[i+6];
        ((UINT64*)state)[i+7] ^= ((UINT64*)data)[i+7];
    }
    for ( ; (i+4)<=laneCount; i+=4) {
        ((UINT64*)state)[i+0] ^= ((UINT64*)data)[i+0];
        ((UINT64*)state)[i+1] ^= ((UINT64*)data)[i+1];
        ((UINT64*)state)[i+2] ^= ((UINT64*)data)[i+2];
        ((UINT64*)state)[i+3] ^= ((UINT64*)data)[i+3];
    }
    for ( ; (i+2)<=laneCount; i+=2) {
        ((UINT64*)state)[i+0] ^= ((UINT64*)data)[i+0];
        ((UINT64*)state)[i+1] ^= ((UINT64*)data)[i+1];
    }
    if (i<laneCount)
        ((UINT64*)state)[i+0] ^= ((UINT64*)data)[i+0];
#else
    unsigned int i;
    UINT8 *curData = (UINT8*)data;
    for (i=0; i<laneCount; i++, curData+=8) {
        UINT64 lane = (UINT64)curData[0]
            | ((UINT64)curData[1] << 8)
            | ((UINT64)curData[2] << 16)
            | ((UINT64)curData[3] << 24)
            | ((UINT64)curData[4] <<32)
            | ((UINT64)curData[5] << 40)
            | ((UINT64)curData[6] << 48)
            | ((UINT64)curData[7] << 56);
        ((UINT64*)state)[i] ^= lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateComplementBit(void *state, unsigned int position)
{
    UINT64 lane = (UINT64)1 << (position%64);
    ((UINT64*)state)[position/64] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StatePermute(void *state)
{
    KeccakF1600_StateXORPermuteExtract(state, 0, 0, 0, 0);
}

/* ---------------------------------------------------------------- */

void KeccakF1600_StateExtractBytesInLane(const void *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
    UINT64 lane = ((UINT64*)state)[lanePosition];
#ifdef UseLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
        lane = ~lane;
#endif
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    {
        UINT64 lane1[1];
        lane1[0] = lane;
        memcpy(data, (UINT8*)lane1+offset, length);
    }
#else
    {
        unsigned int i;
        lane >>= offset*8;
        for (i=0; i<length; i++) {
            data[i] = lane & 0xFF;
            lane >>= 8;
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
void fromWordToBytes(UINT8 *bytes, const UINT64 word)
{
    unsigned int i;

    for (i=0; i<(64/8); i++)
        bytes[i] = (word >> (8*i)) & 0xFF;
}
#endif

void KeccakF1600_StateExtractLanes(const void *state, unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, state, laneCount*8);
#else
    unsigned int i;

    for (i=0; i<laneCount; i++)
        fromWordToBytes(data+(i*8), ((const UINT64*)state)[i]);
#endif
#ifdef UseLaneComplementing
    if (laneCount > 1) {
        ((UINT64*)data)[ 1] = ~((UINT64*)data)[ 1];
        if (laneCount > 2) {
            ((UINT64*)data)[ 2] = ~((UINT64*)data)[ 2];
            if (laneCount > 8) {
                ((UINT64*)data)[ 8] = ~((UINT64*)data)[ 8];
                if (laneCount > 12) {
                    ((UINT64*)data)[12] = ~((UINT64*)data)[12];
                    if (laneCount > 17) {
                        ((UINT64*)data)[17] = ~((UINT64*)data)[17];
                        if (laneCount > 20) {
                            ((UINT64*)data)[20] = ~((UINT64*)data)[20];
                        }
                    }
                }
            }
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

#ifdef ProvideFastAbsorb1344
void KeccakF1600_StateXORPermuteExtract_absorb1344(void *state, const unsigned char *inData, unsigned int inLaneCount)
{
    declareABCDE
    #if (Unrolling != 24)
    unsigned int i;
    #endif
    UINT64 *stateAsLanes = (UINT64*)state;
    UINT64 *inDataAsLanes = (UINT64*)inData;

    copyFromStateAndXOR(A, stateAsLanes, inDataAsLanes, 21)
    rounds
    copyToState(stateAsLanes, A)
}
#endif

#ifdef ProvideFastSqueeze1344
void KeccakF1600_StateXORPermuteExtract_squeeze1344(void *state, unsigned char *outData, unsigned int outLaneCount)
{
    declareABCDE
    #if (Unrolling != 24)
    unsigned int i;
    #endif
    UINT64 *stateAsLanes = (UINT64*)state;
    UINT64 *outDataAsLanes = (UINT64*)outData;

    copyFromStateAndXOR(A, stateAsLanes, outDataAsLanes, 0)
    rounds
    copyToStateAndOutput(A, stateAsLanes, outDataAsLanes, 21)
}
#endif

void KeccakF1600_StateXORPermuteExtract(void *state, const unsigned char *inData, unsigned int inLaneCount, unsigned char *outData, unsigned int outLaneCount)
{
#ifdef ProvideFastAbsorb1344
    if ((inLaneCount == 21) && (outLaneCount == 0))
        KeccakF1600_StateXORPermuteExtract_absorb1344(state, inData, inLaneCount);
    else
#endif
#ifdef ProvideFastSqueeze1344
    if ((inLaneCount == 0) && (outLaneCount == 21))
        KeccakF1600_StateXORPermuteExtract_squeeze1344(state, outData, outLaneCount);
    else
#endif
    {
        declareABCDE
        #if (Unrolling != 24)
        unsigned int i;
        #endif
        UINT64 *stateAsLanes = (UINT64*)state;
        UINT64 *inDataAsLanes = (UINT64*)inData;
        UINT64 *outDataAsLanes = (UINT64*)outData;

        copyFromStateAndXOR(A, stateAsLanes, inDataAsLanes, inLaneCount)
        rounds
        copyToStateAndOutput(A, stateAsLanes, outDataAsLanes, outLaneCount)
    }
}

/* ---------------------------------------------------------------- */
