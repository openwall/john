// NOTE: This code is based on https://password-hashing.net/submissions/POMELO-v3.tar.gz archive.

// PHC submission:  POMELO v2
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)
// This code was written by Hongjun Wu on Jan 31, 2015.

// This code gives the C implementation of POMELO using the SSE2 instructions.

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "arch.h"
#include "memdbg.h"

#if !defined(JOHN_NO_SIMD) && defined(__AVX2__)

// This code give the C implementation of POMELO using the AVX2 implementation.

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)

#include <immintrin.h>

#define XOR256(x,y)       _mm256_xor_si256((x),(y))        /*XOR256(x,y) = x ^ y, where x and y are two 256-bit word*/
#define ADD256(x,y)       _mm256_add_epi64((x), (y))
#define OR256(x,y)        _mm256_or_si256((x),(y))         /*OR(x,y)  = x | y, where x and y are two 256-bit word*/
#define SHIFTL256(x,n)    _mm256_slli_epi64((x), (n))
#define ROTL256(x,n)      OR256( _mm256_slli_epi64((x), (n)), _mm256_srli_epi64((x),(64-n)) )   /*Rotate 4 64-bit unsigned integers in x to the left by n-bit positions*/
#define ROTL256_64(x)     _mm256_permute4x64_epi64((x), _MM_SHUFFLE(2,1,0,3))  /*Rotate x by 64-bit  positions to the left*/
#define ROTL256_128(x)    _mm256_permute4x64_epi64((x), _MM_SHUFFLE(1,0,3,2))  /*Rotate x by 128-bit positions to the left*/
#define ROTL256_192(x)    _mm256_permute4x64_epi64((x), _MM_SHUFFLE(0,3,2,1))  /*Rotate x by 192-bit positions to the left*/

// Function F0 update the state using a nonlinear feedback shift register in the expansion (step 3)
#define F0(i)  {            \
    i0 = ((i) - 0)  & mask; \
    i1 = ((i) - 2)  & mask; \
    i2 = ((i) - 3)  & mask; \
    i3 = ((i) - 7)  & mask; \
    i4 = ((i) - 13) & mask; \
    S[i0] = XOR256(ADD256(XOR256(S[i1], S[i2]), S[i3]), S[i4]);  \
    S[i0] = ROTL256_64(S[i0]);  \
    S[i0] = ROTL256(S[i0],17);  \
}

// Function F update the state using a nonlinear feedback shift register
#define F(i)  {             \
    i0 = ((i) - 0)  & mask; \
    i1 = ((i) - 2)  & mask; \
    i2 = ((i) - 3)  & mask; \
    i3 = ((i) - 7)  & mask; \
    i4 = ((i) - 13) & mask; \
    S[i0] = ADD256(S[i0], XOR256(ADD256(XOR256(S[i1], S[i2]), S[i3]), S[i4]));      \
    S[i0] = ROTL256_64(S[i0]);  \
    S[i0] = ROTL256(S[i0],17); \
}

// Function G update the state using function F together with Key-INdependent random memory accesses
#define G(i,random_number)  {                                                       \
    index_global = (random_number >> 16) & mask;                                    \
    for (j = 0; j < 32; j++)                                                        \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 1) & mask;                                 \
        index_local    = (i + j - 0x1000 + (random_number & 0x1fff)) & mask;        \
        S[i0]          = ADD256(S[i0],SHIFTL256(S[index_local],1));                 \
        S[index_local] = ADD256(S[index_local],  SHIFTL256(S[i0],2));               \
        S[i0]          = ADD256(S[i0],SHIFTL256(S[index_global],1));                \
        S[index_global]= ADD256(S[index_global], SHIFTL256(S[i0],3));               \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

// Function H update the state using function F together with Key-dependent random memory accesses
#define H(i, random_number)  {                                                      \
    index_global = (random_number >> 16) & mask;                                    \
    for (j = 0; j < 32; j++)                                                        \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 1) & mask;                                 \
        index_local    = (i + j - 0x1000 + (random_number & 0x1fff)) & mask;        \
        S[i0]          = ADD256(S[i0],SHIFTL256(S[index_local],1));                 \
        S[index_local] = ADD256(S[index_local],  SHIFTL256(S[i0],2));               \
        S[i0]          = ADD256(S[i0],SHIFTL256(S[index_global],1));                \
        S[index_global]= ADD256(S[index_global], SHIFTL256(S[i0],3));               \
        random_number  = ((unsigned long long*)S)[(i3 << 2)];                       \
    }                                                                               \
}

int PHS_pomelo(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
    unsigned long long i, j;
    unsigned long long i0, i1, i2, i3, i4;
    __m256i *S;
    unsigned long long random_number, index_global, index_local;
    unsigned long long state_size, mask;

    //check the size of password, salt, and output. Password at most 256 bytes; salt at most 64 bytes; output at most 256 bytes.
    if (inlen > 256 || saltlen > 64 || outlen > 256) return 1;

    //Step 1: Initialize the state S
    state_size = 1ULL << (13+m_cost);    // state size is 2**(13+m_cost) bytes
    S = (__m256i *)mem_alloc_align(state_size, 32);   // aligned malloc is needed; otherwise it is only aligned to 16 bytes when using GCC.
    mask = (1ULL << (8+m_cost)) - 1;     // mask is used for modulation: modulo size_size/32

    //Step 2: Load the password, salt, input/output sizes into the state S
    for (i = 0; i < inlen; i++)   ((unsigned char*)S)[i] = ((unsigned char*)in)[i];         // load password into S
    for (i = 0; i < saltlen; i++) ((unsigned char*)S)[inlen+i] = ((unsigned char*)salt)[i]; // load salt into S
    for (i = inlen+saltlen; i < 384; i++) ((unsigned char*)S)[i] = 0;
    ((unsigned char*)S)[384] = inlen & 0xff;          // load password length (in bytes) into S;
    ((unsigned char*)S)[385] = (inlen >> 8) & 0xff;   // load password length (in bytes) into S;
    ((unsigned char*)S)[386] = saltlen;               // load salt length (in bytes) into S;
    ((unsigned char*)S)[387] = outlen & 0xff;         // load output length (in bytes into S)
    ((unsigned char*)S)[388] = (outlen >> 8) & 0xff;  // load output length (in bytes into S)
    ((unsigned char*)S)[389] = 0;
    ((unsigned char*)S)[390] = 0;
    ((unsigned char*)S)[391] = 0;

    ((unsigned char*)S)[392] = 1;
    ((unsigned char*)S)[393] = 1;
    for (i = 394; i < 416; i++) ((unsigned char*)S)[i] = ((unsigned char*)S)[i-1] + ((unsigned char*)S)[i-2];

    //Step 3: Expand the data into the whole state
    for (i = 13; i < (1ULL << (8+m_cost)); i=i+1)  F0(i);

    //Step 4: Update the state using function G
    random_number = 123456789ULL;
    for (i = 0; i < (1ULL << (7+m_cost+t_cost)); i=i+32)  G(i,random_number);

    //Step 5: Update the state using function H
    for (i = 1ULL << (7+m_cost+t_cost);  i < (1ULL << (8+m_cost+t_cost)); i=i+32)  H(i,random_number);

    //Step 6: Update the state using function F
    for (i = 0; i < (1ULL << (8+m_cost)); i=i+1)  F(i);

    //Step 7: Generate the output
    memcpy(out, ((unsigned char*)S)+state_size-outlen, outlen);
    MEM_FREE(S);           // free the memory

    return 0;
}

#elif !defined(JOHN_NO_SIMD) && defined(__SSE2__)

#include <emmintrin.h>

#define ADD128(x,y)       _mm_add_epi64((x), (y))
#define XOR128(x,y)       _mm_xor_si128((x),(y))     /*XOR(x,y) = x ^ y, where x and y are two 128-bit word*/
#define OR128(x,y)        _mm_or_si128((x),(y))      /*OR(x,y)  = x | y, where x and y are two 128-bit word*/
#define ROTL128(x,n)      XOR128(_mm_slli_epi64((x), (n)),  _mm_srli_epi64((x),(64-n)))  /*Rotate 2 64-bit unsigned integers in x to the left by n-bit positions*/
#define SHIFTL128(x,n)    _mm_slli_epi64((x), (n))
#define SHIFTL64(x)       _mm_slli_si128(x, 8)
#define SHIFTR64(x)       _mm_srli_si128(x, 8)

// Function F0 update the state using a nonlinear feedback shift register
#define F0(i)  {               \
    i0 = ((i) - 0*2)  & mask1; \
    i1 = ((i) - 2*2)  & mask1; \
    i2 = ((i) - 3*2)  & mask1; \
    i3 = ((i) - 7*2)  & mask1; \
    i4 = ((i) - 13*2) & mask1; \
    S[i0]   = XOR128(ADD128(XOR128(S[i1],   S[i2]),   S[i3]),   S[i4]);    \
    S[i0+1] = XOR128(ADD128(XOR128(S[i1+1], S[i2+1]), S[i3+1]), S[i4+1]);  \
    temp = S[i0];                  \
    S[i0]   = XOR128(SHIFTL64(S[i0]),   SHIFTR64(S[i0+1]));  \
    S[i0+1] = XOR128(SHIFTL64(S[i0+1]), SHIFTR64(temp));   \
    S[i0]   = ROTL128(S[i0],  17);  \
    S[i0+1] = ROTL128(S[i0+1],17);  \
}

// Function F update the state using a nonlinear feedback shift register
#define F(i)  {              \
    i0 = ((i) - 0*2)  & mask1; \
    i1 = ((i) - 2*2)  & mask1; \
    i2 = ((i) - 3*2)  & mask1; \
    i3 = ((i) - 7*2)  & mask1; \
    i4 = ((i) - 13*2) & mask1; \
    S[i0]   = ADD128(S[i0],XOR128(ADD128(XOR128(S[i1],   S[i2]),   S[i3]),   S[i4]));    \
    S[i0+1] = ADD128(S[i0+1],XOR128(ADD128(XOR128(S[i1+1], S[i2+1]), S[i3+1]), S[i4+1]));  \
    temp = S[i0];                  \
    S[i0]   = XOR128(SHIFTL64(S[i0]),   SHIFTR64(S[i0+1]));  \
    S[i0+1] = XOR128(SHIFTL64(S[i0+1]), SHIFTR64(temp));   \
    S[i0]   = ROTL128(S[i0],  17);  \
    S[i0+1] = ROTL128(S[i0+1],17);  \
}

#define G(i,random_number)  {                                                          \
    index_global = ((random_number >> 16) & mask) << 1;                                \
    for (j = 0; j < 64; j = j+2)                                                        \
    {                                                                                  \
        F(i+j);                                                                        \
        index_global     = (index_global + 2) & mask1;                                 \
        index_local      = (((i + j) >> 1) - 0x1000 + (random_number & 0x1fff)) & mask;\
        index_local      = index_local << 1;                                           \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_local],1));                \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_local+1],1));              \
        S[index_local]   = ADD128(S[index_local],   SHIFTL128(S[i0],2));               \
        S[index_local+1] = ADD128(S[index_local+1], SHIFTL128(S[i0+1],2));             \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_global],1));               \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_global+1],1));             \
        S[index_global]  = ADD128(S[index_global],  SHIFTL128(S[i0],3));               \
        S[index_global+1]= ADD128(S[index_global+1],SHIFTL128(S[i0+1],3));             \
        random_number   += (random_number << 2);                                       \
        random_number    = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                                  \
}

#define H(i, random_number)  {                                                         \
    index_global = ((random_number >> 16) & mask) << 1;                                \
    for (j = 0; j < 64; j = j+2)                                                       \
    {                                                                                  \
        F(i+j);                                                                        \
        index_global     = (index_global + 2) & mask1;                                 \
        index_local      = (((i + j) >> 1) - 0x1000 + (random_number & 0x1fff)) & mask;\
        index_local      = index_local << 1;                                           \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_local],1));                \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_local+1],1));              \
        S[index_local]   = ADD128(S[index_local],   SHIFTL128(S[i0],2));               \
        S[index_local+1] = ADD128(S[index_local+1], SHIFTL128(S[i0+1],2));             \
        S[i0]            = ADD128(S[i0],  SHIFTL128(S[index_global],1));               \
        S[i0+1]          = ADD128(S[i0+1],SHIFTL128(S[index_global+1],1));             \
        S[index_global]  = ADD128(S[index_global],  SHIFTL128(S[i0],3));               \
        S[index_global+1]= ADD128(S[index_global+1],SHIFTL128(S[i0+1],3));             \
        random_number  = ((unsigned long long*)S)[i3<<1];                                                        \
    }                                                                                     \
}

int PHS_pomelo(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
    unsigned long long i,j;
    __m128i temp;
    unsigned long long i0,i1,i2,i3,i4;
    __m128i *S;
    unsigned long long random_number, index_global, index_local;
    unsigned long long state_size, mask, mask1;

    //check the size of password, salt and output. Password is at most 256 bytes; the salt is at most 32 bytes.
    if (inlen > 256 || saltlen > 64 || outlen > 256) return 1;

    //Step 1: Initialize the state S
    state_size = 1ULL << (13+m_cost);   // state size is 2**(13+m_cost) bytes
    S = (__m128i *)mem_alloc_align(state_size, 16);
    mask  = (1ULL << (8+m_cost)) - 1;   // mask is used for modulation: modulo size_size/32;
    mask1 = (1ULL << (9+m_cost)) - 1;   // mask is used for modulation: modulo size_size/16;

    //Step 2: Load the password, salt, input/output sizes into the state S
    for (i = 0; i < inlen; i++)   ((unsigned char*)S)[i] = ((unsigned char*)in)[i];         // load password into S
    for (i = 0; i < saltlen; i++) ((unsigned char*)S)[inlen+i] = ((unsigned char*)salt)[i]; // load salt into S
    for (i = inlen+saltlen; i < 384; i++) ((unsigned char*)S)[i] = 0;
    ((unsigned char*)S)[384] = inlen & 0xff;         // load password length (in bytes) into S;
    ((unsigned char*)S)[385] = (inlen >> 8) & 0xff;  // load password length (in bytes) into S;
    ((unsigned char*)S)[386] = saltlen;              // load salt length (in bytes) into S;
    ((unsigned char*)S)[387] = outlen & 0xff;        // load output length (in bytes into S)
    ((unsigned char*)S)[388] = (outlen >> 8) & 0xff; // load output length (in bytes into S)
    ((unsigned char*)S)[389] = 0;
    ((unsigned char*)S)[390] = 0;
    ((unsigned char*)S)[391] = 0;

    ((unsigned char*)S)[392] = 1;
    ((unsigned char*)S)[393] = 1;
    for (i = 394; i < 416; i++) ((unsigned char*)S)[i] = ((unsigned char*)S)[i-1] + ((unsigned char*)S)[i-2];

    //Step 3: Expand the data into the whole state
    for (i = 13*2; i < (1ULL << (9+m_cost)); i=i+2) F0(i);

    //Step 4: Update the state using function G
    random_number = 123456789ULL;
    for (i = 0; i < (1ULL << (8+m_cost+t_cost)); i=i+64)    G(i,random_number);

    //Step 5: Update the state using function H
    for (i = 1ULL << (8+m_cost+t_cost);  i < (1ULL << (9+m_cost+t_cost)); i=i+64)  H(i,random_number);

    //Step 6: Update the state using function F
    for (i = 0; i < (1ULL << (9+m_cost)); i=i+2)  F(i);

    //Step 7: Generate the output
    memcpy(out, ((unsigned char*)S)+state_size-outlen, outlen);
    MEM_FREE(S);                   // free the memory

    return 0;
}

#else

// PHC submission:  POMELO v2
// Designed by:     Hongjun Wu (Email: wuhongjun@gmail.com)
// This code was written by Hongjun Wu on Jan 31, 2015.

// This codes gives the C implementation of POMELO on 64-bit platform (little-endian)

// m_cost is an integer, 0 <= m_cost <= 25; the memory size is 2**(13+m_cost) bytes
// t_cost is an integer, 0 <= t_cost <= 25; the number of steps is roughly:  2**(8+m_cost+t_cost)
// For the machine today, it is recommended that: 5 <= t_cost + m_cost <= 25;
// one may use the parameters: m_cost = 15; t_cost = 0; (256 MegaByte memory)

#define F0(i)  {               \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+1] = ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+2] = ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+3] = ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+0] = ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define F(i)  {                \
    i0 = ((i) - 0*4)  & mask1; \
    i1 = ((i) - 2*4)  & mask1; \
    i2 = ((i) - 3*4)  & mask1; \
    i3 = ((i) - 7*4)  & mask1; \
    i4 = ((i) - 13*4) & mask1; \
    S[i0+0] += ((S[i1+0] ^ S[i2+0]) + S[i3+0]) ^ S[i4+0];         \
    S[i0+1] += ((S[i1+1] ^ S[i2+1]) + S[i3+1]) ^ S[i4+1];         \
    S[i0+2] += ((S[i1+2] ^ S[i2+2]) + S[i3+2]) ^ S[i4+2];         \
    S[i0+3] += ((S[i1+3] ^ S[i2+3]) + S[i3+3]) ^ S[i4+3];         \
    temp = S[i0+3];         \
    S[i0+3] = S[i0+2];      \
    S[i0+2] = S[i0+1];      \
    S[i0+1] = S[i0+0];      \
    S[i0+0] = temp;         \
    S[i0+0] = (S[i0+0] << 17) | (S[i0+0] >> 47);  \
    S[i0+1] = (S[i0+1] << 17) | (S[i0+1] >> 47);  \
    S[i0+2] = (S[i0+2] << 17) | (S[i0+2] >> 47);  \
    S[i0+3] = (S[i0+3] << 17) | (S[i0+3] >> 47);  \
}

#define G(i,random_number)  {                                                       \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number += (random_number << 2);                                      \
        random_number  = (random_number << 19) ^ (random_number >> 45)  ^ 3141592653589793238ULL;   \
    }                                                                               \
}

#define H(i, random_number)  {                                                      \
    index_global = ((random_number >> 16) & mask) << 2;                             \
    for (j = 0; j < 128; j = j+4)                                                   \
    {                                                                               \
        F(i+j);                                                                     \
        index_global   = (index_global + 4) & mask1;                                      \
        index_local    = (((i + j) >> 2) - 0x1000 + (random_number & 0x1fff)) & mask;     \
        index_local    = index_local << 2;                                                \
        S[i0+0]       += (S[index_local+0] << 1);                                   \
        S[i0+1]       += (S[index_local+1] << 1);                                   \
        S[i0+2]       += (S[index_local+2] << 1);                                   \
        S[i0+3]       += (S[index_local+3] << 1);                                   \
        S[index_local+0] += (S[i0+0] << 2); \
        S[index_local+1] += (S[i0+1] << 2); \
        S[index_local+2] += (S[i0+2] << 2); \
        S[index_local+3] += (S[i0+3] << 2); \
        S[i0+0]       += (S[index_global+0] << 1);                                   \
        S[i0+1]       += (S[index_global+1] << 1);                                   \
        S[i0+2]       += (S[index_global+2] << 1);                                   \
        S[i0+3]       += (S[index_global+3] << 1);                                   \
        S[index_global+0] += (S[i0+0] << 3); \
        S[index_global+1] += (S[i0+1] << 3); \
        S[index_global+2] += (S[i0+2] << 3); \
        S[index_global+3] += (S[i0+3] << 3); \
        random_number  = S[i3];              \
    }                                        \
}

int PHS_pomelo(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost)
{
    unsigned long long i, j, temp;
    unsigned long long i0,i1,i2,i3,i4;
    unsigned long long *S;
    unsigned long long random_number, index_global, index_local;
    unsigned long long state_size, mask, mask1;

    //check the size of password, salt and output. Password is at most 256 bytes; the salt is at most 32 bytes.
    if (inlen > 256 || saltlen > 64 || outlen > 256) return 1;

    //Step 1: Initialize the state S
    state_size = 1ULL << (13+m_cost);    // state size is 2**(13+m_cost) bytes
    S = (unsigned long long *)mem_alloc_align(state_size, 16);
    mask  = (1ULL << (8+m_cost))  - 1;   // mask is used for modulation: modulo size_size/32;
    mask1 = (1ULL << (10+m_cost)) - 1;   // mask is used for modulation: modulo size_size/8;

    //Step 2: Load the password, salt, input/output sizes into the state S
    for (i = 0; i < inlen; i++)   ((unsigned char*)S)[i] = ((unsigned char*)in)[i];         // load password into S
    for (i = 0; i < saltlen; i++) ((unsigned char*)S)[inlen+i] = ((unsigned char*)salt)[i]; // load salt into S
    for (i = inlen+saltlen; i < 384; i++) ((unsigned char*)S)[i] = 0;
    ((unsigned char*)S)[384] = inlen & 0xff;         // load password length (in bytes) into S;
    ((unsigned char*)S)[385] = (inlen >> 8) & 0xff;  // load password length (in bytes) into S;
    ((unsigned char*)S)[386] = saltlen;              // load salt length (in bytes) into S;
    ((unsigned char*)S)[387] = outlen & 0xff;        // load output length (in bytes into S)
    ((unsigned char*)S)[388] = (outlen >> 8) & 0xff; // load output length (in bytes into S)
    ((unsigned char*)S)[389] = 0;
    ((unsigned char*)S)[390] = 0;
    ((unsigned char*)S)[391] = 0;

    ((unsigned char*)S)[392] = 1;
    ((unsigned char*)S)[393] = 1;
    for (i = 394; i < 416; i++) ((unsigned char*)S)[i] = ((unsigned char*)S)[i-1] + ((unsigned char*)S)[i-2];

    //Step 3: Expand the data into the whole state
    for (i = 13*4; i < (1ULL << (10+m_cost)); i=i+4)  F0(i);

    //Step 4: Update the state using function G
    random_number = 123456789ULL;
    for (i = 0; i < (1ULL << (9+m_cost+t_cost)); i=i+128) G(i,random_number);

    //Step 5: Update the state using function H
    for (i = 1ULL << (9+m_cost+t_cost);  i < (1ULL << (10+m_cost+t_cost)); i=i+128)  H(i,random_number);

    //Step 6: Update the state using function F
    for (i = 0; i < (1ULL << (10+m_cost)); i=i+4)  F(i);

    //Step 7: Generate the output
    memcpy(out, ((unsigned char*)S)+state_size-outlen, outlen);
    MEM_FREE(S);          // free the memory

    return 0;
}

#endif /* __SSE2__ */
