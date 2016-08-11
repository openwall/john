/**
 * Header file for the Lyra2 Password Hashing Scheme (PHS).
 * 
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 * 
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on June,2015.
 */
#ifndef LYRA2_H_
#define LYRA2_H_

#if defined(__XOP__)
#define LYRA2_SIMD			"Blake2 XOP"
#elif defined(__AVX__)
#define LYRA2_SIMD			"Blake2 AVX"
#elif defined(__SSSE3__)
#define	LYRA2_SIMD			"Blake2 SSSE3"
#elif defined(__SSE2__)
#define	LYRA2_SIMD			"Blake2 SSE2"
#else
#define LYRA2_SIMD			"Blake2"
#endif

#include <pthread.h>
#include "memory.h"

typedef unsigned char byte ;

extern unsigned short N_COLS;
extern int nCols_is_2_power;

struct lyra2_allocation{
    uint64_t **memMatrix;
    unsigned char **pKeys;
    region_t *threadSliceMatrix;
    unsigned char **threadKey;
    uint64_t **threadState;

    uint64_t *row0;              //row0: sequentially written during Setup; randomly picked during Wandering
    uint64_t *prev0;             //prev0: stores the previous value of row0
    uint64_t *rowP;              //rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering
    uint64_t *prevP;             //prevP: stores the previous value of rowP
    uint64_t *jP;                //Starts with threadNumber.
    uint64_t *kP;
    uint64_t **ptrWord;
};


#ifdef _OPENMP

struct lyra2_lm_allocation{
    uint64_t **memMatrix;
    unsigned char **pKeys;
    region_t *threadSliceMatrix;
    unsigned char **threadKey;
    uint64_t **threadState;
};


int LYRA2_LM_(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, unsigned int nThreads, int threadNumber,struct lyra2_lm_allocation *allocated,pthread_barrier_t *barrier);

int LYRA2_LM(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, unsigned int nThreads, int threadNumber,struct lyra2_lm_allocation *allocated, pthread_barrier_t *barrier);

int LYRA2_LM_for_nThreads1(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, struct lyra2_lm_allocation *allocated);

#endif

int LYRA2_(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, unsigned int nThreads, struct lyra2_allocation *allocated);

int LYRA2(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, unsigned int nCols, unsigned int nThreads, struct lyra2_allocation *allocated);

int LYRA2_for_nThreads1(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, struct lyra2_allocation *allocated);


#endif /* LYRA2_H_ */ 
