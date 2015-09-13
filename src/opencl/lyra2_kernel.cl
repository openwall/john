/**
 * Author: The Lyra PHC team (http://www.lyra2.net/) -- 2015.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on June/July,2015.
 */


#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_lyra2.h"
#include "opencl_Sponge_Lyra2.h"

struct lyra2_salt {
	unsigned int t_cost, m_cost;
	unsigned int nCols, nParallel;
	unsigned int hash_size;
	unsigned int salt_length;
	ulong sizeSlicedRows;
	unsigned char salt[SALT_SIZE];
};


#define glmemcpy(dst, src, size) {	\
    for(mi=0;mi<(size);mi++) 		\
	((__global char *) (dst))[mi]=((char*) (src))[mi]; \
}

#define gmemcpy(dst, src, size) {	\
    for(mi=0;mi<(size);mi++) 		\
	((__global char *) (dst))[mi]=((__global char*) (src))[mi]; \
}

#define memcpy(dst, src, size) gmemcpy(dst, src, size)

static void lyra2_initState(__global ulong * state)
{
	int threadNumber;
	ulong start;

	// Thread index:
	threadNumber = get_global_id(0);

	start = threadNumber * STATESIZE_INT64;
	//First 512 bis are zeros
	state[start + 0] = 0x0UL;
	state[start + 1] = 0x0UL;
	state[start + 2] = 0x0UL;
	state[start + 3] = 0x0UL;
	state[start + 4] = 0x0UL;
	state[start + 5] = 0x0UL;
	state[start + 6] = 0x0UL;
	state[start + 7] = 0x0UL;
	//Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
	state[start + 8] = blake2b_IV_0;
	state[start + 9] = blake2b_IV_1;
	state[start + 10] = blake2b_IV_2;
	state[start + 11] = blake2b_IV_3;
	state[start + 12] = blake2b_IV_4;
	state[start + 13] = blake2b_IV_5;
	state[start + 14] = blake2b_IV_6;
	state[start + 15] = blake2b_IV_7;
}

/**
 * Execute G function, with all 12 rounds for Blake2 and  BlaMka, and 24 round for half-round BlaMka.
 *
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's or BlaMka's G function
 */

inline static void spongeLyra(ulong * v)
{
	int i;

	for (i = 0; i < 12; i++) {
		ROUND_LYRA(i);
	}
}

inline static void absorbBlockBlake2Safe(ulong * state, __global ulong * in)
{
	//XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state
	state[0] ^= in[0];
	state[1] ^= in[1];
	state[2] ^= in[2];
	state[3] ^= in[3];
	state[4] ^= in[4];
	state[5] ^= in[5];
	state[6] ^= in[6];
	state[7] ^= in[7];

	//Applies the transformation f to the sponge's state
	spongeLyra(state);
}

static void lyra2_absorbInput(__global ulong * memMatrixGPU,
    __global ulong * stateThreadGPU_, __global ulong * stateIdxGPU,
    __global const uint * index, __global struct lyra2_salt *salt)
{
	int i;
	__global ulong *ptrWord;
	uint threadNumber = get_global_id(0);
	ulong kP;
	ulong sliceStart;

	uint inlen, saltlen;
	uint nPARALLEL = salt->nParallel;
	uint thStart = (threadNumber / nPARALLEL);

	inlen = index[thStart + 1] - index[thStart];
	saltlen = salt->salt_length;

	ulong nBlocksInput;

	ulong stateThreadGPU[STATESIZE_INT64];

	stateThreadGPU_ += threadNumber * STATESIZE_INT64;

	for (i = 0; i < STATESIZE_INT64; i++)
		stateThreadGPU[i] = stateThreadGPU_[i];

	if (nPARALLEL == 1)
		nBlocksInput =
		    ((saltlen + inlen +
			6 * sizeof(int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;

	if (nPARALLEL > 1)
		nBlocksInput =
		    ((saltlen + inlen +
			8 * sizeof(int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;

	sliceStart = threadNumber * salt->sizeSlicedRows;

	//Absorbing salt, password and params: this is the only place in which the block length is hard-coded to 512 bits, for compatibility with Blake2b and BlaMka
	ptrWord = (__global ulong *) & memMatrixGPU[sliceStart];	//threadSliceMatrix;

	for (kP = 0; kP < nBlocksInput; kP++) {
		absorbBlockBlake2Safe(stateThreadGPU, ptrWord);	//absorbs each block of pad(pwd || salt || params)
		ptrWord += BLOCK_LEN_BLAKE2_SAFE_INT64;	//BLOCK_LEN_BLAKE2_SAFE_INT64;  //goes to next block of pad(pwd || salt || params)
	}

	for (i = 0; i < STATESIZE_INT64; i++)
		stateThreadGPU_[i] = stateThreadGPU[i];
}



__kernel void lyra2_bootStrapAndAbsorb(__global ulong * memMatrixGPU,
    __global unsigned char *pkeysGPU, __global unsigned char *pwdGPU,
    __global const uint * index, __global struct lyra2_salt *salt,
    __global ulong * state, __global ulong * stateIdxGPU)
{
	uint i, mi;

	ulong threadNumber;
	uint base, inlen, saltlen;
	uint nPARALLEL = salt->nParallel;
	uint kLen = salt->hash_size;
	ulong thStart;

	// Thread index:
	threadNumber = get_global_id(0);
	thStart = (threadNumber / nPARALLEL);

	base = index[thStart];
	inlen = index[thStart + 1] - base;
	saltlen = salt->salt_length;

	// Size of each chunk that each thread will work with
	//sizeSlicedRows = (nRows / nPARALLEL) * ROW_LEN_INT64
	ulong sizeSlicedRows = salt->sizeSlicedRows;
	__global byte *ptrByte;
	__global byte *ptrByteSource;


	ulong sliceStart = threadNumber * sizeSlicedRows;

	uint nBlocksInput;

	//============= Padding (password + salt + params) with 10*1 ===============//
	//OBS.:The memory matrix will temporarily hold the password: not for saving memory,
	//but this ensures that the password copied locally will be overwritten as soon as possible
	ptrByte = (__global byte *) & memMatrixGPU[sliceStart];
	ptrByteSource = (__global byte *) & pwdGPU[base];


	if (nPARALLEL == 1)
		nBlocksInput =
		    ((saltlen + inlen +
			6 * sizeof(int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;


	if (nPARALLEL > 1)
		nBlocksInput =
		    ((saltlen + inlen +
			8 * sizeof(int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;




	//First, we clean enough blocks for the password, salt, params and padding
	for (i = 0; i < nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES; i++) {
		ptrByte[i] = (byte) 0;
	}

	//Prepends the password
	memcpy(ptrByte, ptrByteSource, inlen);
	ptrByte += inlen;

	//The indexed salt
	ptrByteSource = (__global byte *) salt->salt;

	//Concatenates the salt
	memcpy(ptrByte, ptrByteSource, saltlen);
	ptrByte += saltlen;

	//Concatenates the basil: every integer passed as parameter, in the order they are provided by the interface
	glmemcpy(ptrByte, &kLen, sizeof(int));
	ptrByte += sizeof(int);
	glmemcpy(ptrByte, &inlen, sizeof(int));
	ptrByte += sizeof(int);
	glmemcpy(ptrByte, &saltlen, sizeof(int));
	ptrByte += sizeof(int);
	memcpy(ptrByte, &(salt->t_cost), sizeof(int));
	ptrByte += sizeof(int);
	memcpy(ptrByte, &(salt->m_cost), sizeof(int));
	ptrByte += sizeof(int);
	memcpy(ptrByte, &(salt->nCols), sizeof(int));
	ptrByte += sizeof(int);

	if (nPARALLEL > 1) {
		//The difference from sequential version:
		//Concatenates the total number of threads
		glmemcpy(ptrByte, &nPARALLEL, sizeof(int));
		ptrByte += sizeof(int);
		//Concatenates thread number
		int thread = threadNumber % nPARALLEL;
		glmemcpy(ptrByte, &thread, sizeof(int));

		ptrByte += sizeof(int);
	}
	//Now comes the padding
	*ptrByte = 0x80;	//first byte of padding: right after the password

	//resets the pointer to the start of the memory matrix
	ptrByte = (__global byte *) & memMatrixGPU[sliceStart];
	ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1;	//sets the pointer to the correct position: end of incomplete block
	*ptrByte ^= 0x01;	//last byte of padding: at the end of the last incomplete block

	lyra2_initState(state);

	lyra2_absorbInput(memMatrixGPU, state, stateIdxGPU, index, salt);
}


inline static void reducedSpongeLyra(ulong * v)
{
	int i;

	for (i = 0; i < RHO; i++) {
		ROUND_LYRA(i);
	}
}

__kernel void lyra2_reducedSqueezeRow0(__global ulong * rowOut,
    __global ulong * state_, __global struct lyra2_salt *salt)
{
	int threadNumber;
	ulong sliceStart;
	uint N_COLS = salt->nCols;
	ulong state[STATESIZE_INT64];

	// Thread index:
	threadNumber = get_global_id(0);

	sliceStart = threadNumber * salt->sizeSlicedRows;

	state_ += threadNumber * STATESIZE_INT64;

	__global ulong *ptrWord = &rowOut[sliceStart + (N_COLS - 1) * BLOCK_LEN_INT64];	//In Lyra2: pointer to M[0][C-1]
	uint i, j;

	for (j = 0; j < STATESIZE_INT64; j++) {
		state[j] = state_[j];
	}
	//M[0][C-1-col] = H.reduced_squeeze()
	for (i = 0; i < N_COLS; i++) {
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWord[j] = state[j];
		}

		//Goes to next block (column) that will receive the squeezed data
		ptrWord -= BLOCK_LEN_INT64;

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);
	}

	for (j = 0; j < STATESIZE_INT64; j++) {
		state_[j] = state[j];
	}
}


__kernel void lyra2_reducedDuplexRow(__global ulong * rowIn,
    __global ulong * state_, __global struct lyra2_salt *salt)
{
	uint i, j;

	int threadNumber;
	ulong sliceStart;
	uint N_COLS = salt->nCols;

	// Thread index:
	threadNumber = get_global_id(0);

	sliceStart = threadNumber * salt->sizeSlicedRows;

	ulong ptrWordIn_copy[BLOCK_LEN_INT64];
	ulong ptrWordOut_copy[BLOCK_LEN_INT64];
	ulong state[STATESIZE_INT64];

	//Row to feed the sponge
	__global ulong *ptrWordIn = (__global ulong *) & rowIn[sliceStart + 0 * ROW_LEN_INT64];	//In Lyra2: pointer to prev
	//Row to receive the sponge's output
	__global ulong *ptrWordOut =
	    (__global ulong *) & rowIn[sliceStart + 1 * ROW_LEN_INT64 +
	    (N_COLS - 1) * BLOCK_LEN_INT64];
	//In Lyra2: pointer to row
	state_ += threadNumber * STATESIZE_INT64;

	for (j = 0; j < STATESIZE_INT64; j++) {
		state[j] = state_[j];
	}

	for (i = 0; i < N_COLS; i++) {

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn_copy[j] = ptrWordIn[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordOut[j];
		}

		//Absorbing "M[0][col]"
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			state[j] ^= (ptrWordIn_copy[j]);
		}

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);

		//M[1][C-1-col] = M[0][col] XOR rand
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordIn_copy[j] ^ state[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut[j] = ptrWordOut_copy[j];
		}

		//Input: next column (i.e., next block in sequence)
		ptrWordIn += BLOCK_LEN_INT64;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_INT64;
	}


	//Row to feed the sponge
	ptrWordIn = (__global ulong *) & rowIn[sliceStart + 1 * ROW_LEN_INT64];	//In Lyra2: pointer to prev
	//Row to receive the sponge's output
	ptrWordOut = (__global ulong *) & rowIn[sliceStart + 2 * ROW_LEN_INT64 + (N_COLS - 1) * BLOCK_LEN_INT64];	//In Lyra2: pointer to row

	for (i = 0; i < N_COLS; i++) {
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn_copy[j] = ptrWordIn[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordOut[j];
		}

		//Absorbing "M[0][col]"
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			state[j] ^= (ptrWordIn_copy[j]);
		}

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);

		//M[1][C-1-col] = M[0][col] XOR rand
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordIn_copy[j] ^ state[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut[j] = ptrWordOut_copy[j];
		}

		//Input: next column (i.e., next block in sequence)
		ptrWordIn += BLOCK_LEN_INT64;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_INT64;
	}
	for (j = 0; j < STATESIZE_INT64; j++) {
		state_[j] = state[j];
	}
}

static void reducedDuplexRowFilling(ulong * state,
    __global ulong * memMatrixGPU, ulong prev0, ulong prevP, ulong row0,
    ulong rowP, ulong jP, uint nPARALLEL, uint N_COLS, ulong sizeSlicedRows)
{
	uint i, j;
	int threadNumber;

	ulong sliceStart;
	ulong sliceStartjP;

	// Thread index:
	threadNumber = get_global_id(0);

	sliceStart = threadNumber * sizeSlicedRows;	//sizeSlicedRows = (nRows/nPARALLEL) * ROW_LEN_INT64

	ulong ptrWordInOut_copy[BLOCK_LEN_INT64];
	ulong ptrWordIn0_copy[BLOCK_LEN_INT64];
	ulong ptrWordIn1_copy[BLOCK_LEN_INT64];
	ulong ptrWordOut_copy[BLOCK_LEN_INT64];

	//jP slice must be inside the  password´s thread pool
	//The integer part of threadNumber/nPARALLEL multiplied by nPARALLEL is the Base Slice Start for the password thread pool
	sliceStartjP =
	    ((((ulong) (threadNumber / nPARALLEL)) * nPARALLEL) +
	    jP) * sizeSlicedRows;

	//Row used only as input
	__global ulong *ptrWordIn0 = (__global ulong *) & memMatrixGPU[sliceStart + prev0 * ROW_LEN_INT64];	//In Lyra2: pointer to prev0, the last row ever initialized

	//Another row used only as input
	__global ulong *ptrWordIn1 = (__global ulong *) & memMatrixGPU[sliceStartjP + (prevP * ROW_LEN_INT64)];	//In Lyra2: pointer to prev1, the last row ever revisited and updated

	//Row used as input and to receive output after rotation
	__global ulong *ptrWordInOut = (__global ulong *) & memMatrixGPU[sliceStartjP + (rowP * ROW_LEN_INT64)];	//In Lyra2: pointer to row1, to be revisited and updated

	//Row receiving the output
	__global ulong *ptrWordOut = (__global ulong *) & memMatrixGPU[sliceStart + (row0 * ROW_LEN_INT64) + ((N_COLS - 1) * BLOCK_LEN_INT64)];	//In Lyra2: pointer to row0, to be initialized

	for (i = 0; i < N_COLS; i++) {
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordOut[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut_copy[j] = ptrWordInOut[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn0_copy[j] = ptrWordIn0[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn1_copy[j] = ptrWordIn1[j];
		}

		//Absorbing "M[rowP] [+] M[prev0] [+] M[prev1]"
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			state[j] ^=
			    (ptrWordInOut_copy[j] + ptrWordIn0_copy[j] +
			    ptrWordIn1_copy[j]);
		}

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);

		//M[row0][col] = M[prev0][col] XOR rand
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordIn0_copy[j] ^ state[j];
		}

		//M[rowP][col] = M[rowP][col] XOR rot(rand)
		//rot(): right rotation by 'omega' bits (e.g., 1 or more words)
		//we rotate 2 words for compatibility with the SSE implementation
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut_copy[j] ^= state[((j + 2) % BLOCK_LEN_INT64)];	// BLOCK_LEN_INT64 = 12
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut[j] = ptrWordOut_copy[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut[j] = ptrWordInOut_copy[j];
		}

		//Inputs: next column (i.e., next block in sequence)
		ptrWordInOut += BLOCK_LEN_INT64;
		ptrWordIn0 += BLOCK_LEN_INT64;
		ptrWordIn1 += BLOCK_LEN_INT64;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_INT64;
	}
}

static void reducedDuplexRowWanderingParallel(__global ulong * memMatrixGPU,
    ulong * state, ulong prev0, ulong row0, ulong rowP, ulong window,
    ulong jP, uint nPARALLEL, uint N_COLS, ulong sizeSlicedRows)
{
	int threadNumber;
	ulong sliceStart;
	ulong sliceStartjP;
	ulong randomColumn0;	//In Lyra2: col0

	// Thread index:
	threadNumber = get_global_id(0);


	sliceStart = threadNumber * sizeSlicedRows;

	//jP slice must be inside the  password´s thread pool
	//The integer part of threadNumber/nPARALLEL multiplied by nPARALLEL is the Base Slice Start for the password thread pool
	sliceStartjP =
	    ((((ulong) (threadNumber / nPARALLEL)) * nPARALLEL) +
	    jP) * sizeSlicedRows;

	//Row used as input and to receive output after rotation
	__global ulong *ptrWordInOut0 = (__global ulong *) & memMatrixGPU[sliceStart + (row0 * ROW_LEN_INT64)];	//In Lyra2: pointer to row0
	//Row used only as input
	__global ulong *ptrWordInP = (__global ulong *) & memMatrixGPU[sliceStartjP + (rowP * ROW_LEN_INT64)];	//In Lyra2: pointer to row0_p
	//Another row used only as input
	__global ulong *ptrWordIn0;	//In Lyra2: pointer to prev0

	uint i, j;

	ulong ptrWordInOut0_copy[BLOCK_LEN_INT64];
	ulong ptrWordIn0_copy[BLOCK_LEN_INT64];
	ulong ptrWordInP_copy[BLOCK_LEN_INT64];


	for (i = 0; i < N_COLS; i++) {
		//col0 = LSW(rot^3(rand)) mod N_COLS
		//randomColumn0 = ((uint64_t)state[6] & (N_COLS-1))*BLOCK_LEN_INT64;           /*(USE THIS IF N_COLS IS A POWER OF 2)*/
		randomColumn0 = ((ulong) state[6] % N_COLS) * BLOCK_LEN_INT64;	/*(USE THIS FOR THE "GENERIC" CASE) */

		ptrWordIn0 =
		    (__global ulong *) & memMatrixGPU[sliceStart +
		    (prev0 * ROW_LEN_INT64) + randomColumn0];

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut0_copy[j] = ptrWordInOut0[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn0_copy[j] = ptrWordIn0[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInP_copy[j] = ptrWordInP[j];
		}


		//Absorbing "M[row0] [+] M[prev0] [+] M[rowP]"
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			state[j] ^=
			    (ptrWordInOut0_copy[j] + ptrWordIn0_copy[j] +
			    ptrWordInP_copy[j]);
		}

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);

		//M[rowInOut0][col] = M[rowInOut0][col] XOR rand
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut0_copy[j] ^= state[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut0[j] = ptrWordInOut0_copy[j];
		}

		//Goes to next block
		ptrWordInOut0 += BLOCK_LEN_INT64;
		ptrWordInP += BLOCK_LEN_INT64;

	}
}

static void absorbRandomColumn(__global ulong * in, ulong * state,
    ulong row0, ulong randomColumn0, uint nPARALLEL, uint N_COLS,
    ulong sizeSlicedRows)
{
	int i;
	int threadNumber;
	ulong sliceStart;

	// Thread index:
	threadNumber = get_global_id(0);

	sliceStart = threadNumber * sizeSlicedRows;

	__global ulong *ptrWordIn =
	    (__global ulong *) & in[sliceStart + (row0 * ROW_LEN_INT64) +
	    randomColumn0];

	ulong ptrWordIn_copy[BLOCK_LEN_INT64];

	for (i = 0; i < BLOCK_LEN_INT64; i++) {
		ptrWordIn_copy[i] = ptrWordIn[i];
	}

	//absorbs the column picked
	for (i = 0; i < BLOCK_LEN_INT64; i++) {
		state[i] ^= ptrWordIn_copy[i];
	}

	//Applies the full-round transformation f to the sponge's state
	spongeLyra(state);
}

static void wanderingPhaseGPU2(__global ulong * memMatrixGPU,
    ulong * stateThreadGPU, uint timeCost, ulong sizeSlice,
    ulong sqrt, ulong prev0, uint nPARALLEL, uint N_COLS, ulong sizeSlicedRows)
{
	ulong wCont;		//Time Loop iterator
	ulong window;		//Visitation window (used to define which rows can be revisited during Setup)
	ulong row0;		//row0: sequentially written during Setup; randomly picked during Wandering

	ulong rowP;		//rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering
	ulong jP;		//Index to another thread


	ulong off0;		//complementary offsets to calculate row0
	ulong offP;		//complementary offsets to calculate rowP
	ulong offTemp;

	ulong sync = sqrt;

	ulong halfSlice = sizeSlice / 2;

	// Thread index:

	window = halfSlice;
	off0 = 0;
	offP = window;

	for (wCont = 0; wCont < timeCost * sizeSlice; wCont++) {
		//Selects a pseudorandom indices row0 and rowP (row0 = LSW(rand) mod wnd and rowP = LSW(rot(rand)) mod wnd)
		//------------------------------------------------------------------------------------------
		//(USE THIS IF window IS A POWER OF 2)
		//row0  = off0 + (((ulong)stateThreadGPU[stateStart + 0]) & (window-1));
		//row0P = offP + (((ulong)stateThreadGPU[stateStart + 2]) & (window-1));
		//(USE THIS FOR THE "GENERIC" CASE)
		row0 = off0 + (((ulong) stateThreadGPU[0]) % window);
		rowP = offP + (((ulong) stateThreadGPU[2]) % window);

		//Selects a pseudorandom indices j0 (LSW(rot^2 (rand)) mod p)
		jP = ((ulong) stateThreadGPU[4]) % nPARALLEL;

		//Performs a reduced-round duplexing operation over M[row0] [+] Mj[rowP] [+] M[prev0], updating M[row0]
		//M[row0][col] = M[row0][col] XOR rand;
		reducedDuplexRowWanderingParallel(memMatrixGPU, stateThreadGPU,
		    prev0, row0, rowP, window, jP, nPARALLEL, N_COLS,
		    sizeSlicedRows);

		//update prev: they now point to the last rows ever updated
		prev0 = row0;

		if (wCont == sync) {
			sync += sqrt;
			offTemp = off0;
			off0 = offP;
			offP = offTemp;
			barrier(CLK_LOCAL_MEM_FENCE);
		}
	}
	barrier(CLK_LOCAL_MEM_FENCE);

	//============================ Wrap-up Phase ===============================//
	//Absorbs one last block of the memory matrix with the full-round sponge
	absorbRandomColumn(memMatrixGPU, stateThreadGPU, row0, 0,
	    nPARALLEL, N_COLS, sizeSlicedRows);
}

__kernel void lyra2_setupPhaseWanderingGPU(__global ulong * memMatrixGPU,
    __global ulong * stateThreadGPU_, __global byte * out,
    __global struct lyra2_salt *salt)
{
	uint i, mi;
	ulong step = 1;		//Visitation step (used during Setup and Wandering phases)
	ulong window = 2;	//Visitation window (used to define which rows can be revisited during Setup)
	long gap = 1;		//Modifier to the step, assuming the values 1 or -1

	ulong row0 = 3;		//row0: sequentially written during Setup; randomly picked during Wandering
	ulong prev0 = 2;	//prev0: stores the previous value of row0
	ulong rowP = 1;		//rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering
	ulong prevP = 0;	//prevP: stores the previous value of rowP
	ulong jP;		//Index to another thread, starts with threadNumber
	ulong sync = 4;		//Synchronize counter
	ulong sqrt = 2;		//Square of window (i.e., square(window)), when a window is a square number;
	//otherwise, sqrt = 2*square(window/2)


	// Thread index:
	int threadNumber = get_global_id(0);

	uint len = salt->hash_size;
	uint fullBlocks = len / BLOCK_LEN_BYTES;

	uint nPARALLEL = salt->nParallel;
	uint N_COLS = salt->nCols;
	uint sizeSlice = salt->m_cost / nPARALLEL;
	__global byte *ptr = (__global byte *) & out[threadNumber * len];

	ulong stateThreadGPU[STATESIZE_INT64];


	stateThreadGPU_ += threadNumber * STATESIZE_INT64;
	for (i = 0; i < STATESIZE_INT64; i++)
		stateThreadGPU[i] = stateThreadGPU_[i];

	//jP must be in the thread pool of the same password
	jP = threadNumber % nPARALLEL;

	//Filling Loop
	for (row0 = 3; row0 < sizeSlice; row0++) {
		//Performs a reduced-round duplexing operation over "Mj[rowP][col] [+] Mi[prev0][col] [+] Mj[prevP][col]", filling Mi[row0] and updating Mj[rowP]
		//Mi[row0][N_COLS-1-col] = Mi[prev0][col] XOR rand;
		//Mj[rowP][col] = Mj[rowP][col] XOR rot(rand)                    rot(): right rotation by 'omega' bits (e.g., 1 or more words)
		reducedDuplexRowFilling(stateThreadGPU, memMatrixGPU, prev0,
		    prevP, row0, rowP, jP, nPARALLEL, N_COLS,
		    salt->sizeSlicedRows);

		//Updates the "prev" indices: the rows more recently updated
		prev0 = row0;
		prevP = rowP;

		//updates the value of row1: deterministically picked, with a variable step
		rowP = (rowP + step) & (window - 1);

		//Checks if all rows in the window where visited.
		if (rowP == 0) {
			window *= 2;	//doubles the size of the re-visitation window
			step = sqrt + gap;	//changes the step
			gap = -gap;	//inverts the modifier to the step
			if (gap == -1) {
				sqrt *= 2;	//Doubles sqrt every other iteration
			}
		}
		if (row0 == sync) {
			sync += sqrt / 2;	//increment synchronize counter
			jP = (jP + 1) % nPARALLEL;	//change the visitation thread
			barrier(CLK_LOCAL_MEM_FENCE);
		}
	}

	barrier(CLK_LOCAL_MEM_FENCE);

	//Now goes to Wandering Phase and the Absorb from Wrap-up
	//============================ Wandering Phase =============================//
	//=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
	wanderingPhaseGPU2(memMatrixGPU, stateThreadGPU, salt->t_cost,
	    sizeSlice, sqrt, prev0, nPARALLEL, N_COLS, salt->sizeSlicedRows);

	//Squeezes full blocks
	for (i = 0; i < fullBlocks; i++) {
		glmemcpy(ptr, stateThreadGPU, BLOCK_LEN_BYTES);
		spongeLyra(stateThreadGPU);
		ptr += BLOCK_LEN_BYTES;
	}

	//Squeezes remaining bytes
	glmemcpy(ptr, stateThreadGPU, len % BLOCK_LEN_BYTES);
}

static void reducedDuplexRowFilling_P1(ulong * state,
    __global ulong * memMatrixGPU, ulong prev0, ulong prev1, ulong row0,
    ulong row1, uint nPARALLEL, uint N_COLS, ulong sizeSlicedRows)
{
	uint i, j;
	int threadNumber;

	ulong sliceStart;

	// Thread index:
	threadNumber = get_global_id(0);

	sliceStart = threadNumber * sizeSlicedRows;	//sizeSlicedRows = (nRows/nPARALLEL) * ROW_LEN_INT64

	ulong ptrWordInOut_copy[BLOCK_LEN_INT64];
	ulong ptrWordIn0_copy[BLOCK_LEN_INT64];
	ulong ptrWordIn1_copy[BLOCK_LEN_INT64];
	ulong ptrWordOut_copy[BLOCK_LEN_INT64];

	//Row used only as input (rowIn0 or M[prev0])
	__global ulong *ptrWordIn0 = (__global ulong *) & memMatrixGPU[sliceStart + prev0 * ROW_LEN_INT64];	//In Lyra2: pointer to prev0, the last row ever initialized

	//Another row used only as input (rowIn1 or M[prev1])
	__global ulong *ptrWordIn1 = (__global ulong *) & memMatrixGPU[sliceStart + prev1 * ROW_LEN_INT64];	//In Lyra2: pointer to prev1, the last row ever revisited and updated

	//Row used as input and to receive output after rotation (rowInOut or M[row1])
	__global ulong *ptrWordInOut = (__global ulong *) & memMatrixGPU[sliceStart + row1 * ROW_LEN_INT64];	//In Lyra2: pointer to row1, to be revisited and updated

	//Row receiving the output (rowOut or M[row0])
	__global ulong *ptrWordOut = (__global ulong *) & memMatrixGPU[sliceStart + (row0 * ROW_LEN_INT64) + ((N_COLS - 1) * BLOCK_LEN_INT64)];	//In Lyra2: pointer to row0, to be initialized

	for (i = 0; i < N_COLS; i++) {
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordOut[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut_copy[j] = ptrWordInOut[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn0_copy[j] = ptrWordIn0[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordIn1_copy[j] = ptrWordIn1[j];
		}

		//Absorbing "M[row1] [+] M[prev0] [+] M[prev1]"
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			state[j] ^=
			    (ptrWordInOut_copy[j] + ptrWordIn0_copy[j] +
			    ptrWordIn1_copy[j]);
		}

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);

		//M[row0][col] = M[prev0][col] XOR rand
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut_copy[j] = ptrWordIn0_copy[j] ^ state[j];
		}

		//M[row1][col] = M[row1][col] XOR rot(rand)
		//rot(): right rotation by 'omega' bits (e.g., 1 or more words)
		//we rotate 2 words for compatibility with the SSE implementation
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut_copy[j] ^= state[((j + 2) % BLOCK_LEN_INT64)];	// BLOCK_LEN_INT64 = 12
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordOut[j] = ptrWordOut_copy[j];
		}

		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut[j] = ptrWordInOut_copy[j];
		}

		//Inputs: next column (i.e., next block in sequence)
		ptrWordInOut += BLOCK_LEN_INT64;
		ptrWordIn0 += BLOCK_LEN_INT64;
		ptrWordIn1 += BLOCK_LEN_INT64;
		//Output: goes to previous column
		ptrWordOut -= BLOCK_LEN_INT64;
	}
}

static void reducedDuplexRowWandering_P1(__global ulong * memMatrixGPU,
    ulong * state, ulong prev0, ulong row0, ulong row1, ulong prev1,
    uint nPARALLEL, uint N_COLS, ulong sizeSlicedRows)
{
	int threadNumber;
	ulong sliceStart;
	ulong randomColumn0;	//In Lyra2: col0
	ulong randomColumn1;	//In Lyra2: col1

	// Thread index:
	threadNumber = get_global_id(0);

	sliceStart = threadNumber * sizeSlicedRows;


	__global ulong *ptrWordInOut0 = (__global ulong *) & memMatrixGPU[sliceStart + (row0 * ROW_LEN_INT64)];	//In Lyra2: pointer to row0
	__global ulong *ptrWordInOut1 = (__global ulong *) & memMatrixGPU[sliceStart + (row1 * ROW_LEN_INT64)];	//In Lyra2: pointer to row0_p
	__global ulong *ptrWordIn0;	//In Lyra2: pointer to prev0
	__global ulong *ptrWordIn1;	//In Lyra2: pointer to prev1

	uint i, j;

	for (i = 0; i < N_COLS; i++) {
		//col0 = lsw(rot^2(rand)) mod N_COLS
		//randomColumn0 = ((uint64_t)state[stateStart + 4] & (N_COLS-1))*BLOCK_LEN_INT64;           /*(USE THIS IF N_COLS IS A POWER OF 2)*/
		randomColumn0 = ((ulong) state[4] % N_COLS) * BLOCK_LEN_INT64;	/*(USE THIS FOR THE "GENERIC" CASE) */
		ptrWordIn0 =
		    (__global ulong *) & memMatrixGPU[sliceStart +
		    (prev0 * ROW_LEN_INT64) + randomColumn0];

		//col0 = LSW(rot^3(rand)) mod N_COLS
		//randomColumn1 = ((uint64_t)state[stateStart + 6] & (N_COLS-1))*BLOCK_LEN_INT64;           /*(USE THIS IF N_COLS IS A POWER OF 2)*/
		randomColumn1 = ((ulong) state[6] % N_COLS) * BLOCK_LEN_INT64;	/*(USE THIS FOR THE "GENERIC" CASE) */
		ptrWordIn1 =
		    (__global ulong *) & memMatrixGPU[sliceStart +
		    (prev1 * ROW_LEN_INT64) + randomColumn1];

		//Absorbing "M[row0] [+] M[row1] [+] M[prev0] [+] M[prev1]"
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			state[j] ^=
			    (ptrWordInOut0[j] + ptrWordInOut1[j] +
			    ptrWordIn0[j] + ptrWordIn1[j]);
		}

		//Applies the reduced-round transformation f to the sponge's state
		reducedSpongeLyra(state);

		//M[rowInOut0][col] = M[rowInOut0][col] XOR rand
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut0[j] ^= state[j];
		}

		//M[rowInOut1][col] = M[rowInOut1][col] XOR rot(rand)
		//rot(): right rotation by 'omega' bits (e.g., 1 or more words)
		//we rotate 2 words for compatibility with the SSE implementation
		for (j = 0; j < BLOCK_LEN_INT64; j++) {
			ptrWordInOut1[j] ^= state[((j + 2) % BLOCK_LEN_INT64)];
		}

		//Goes to next block
		ptrWordInOut0 += BLOCK_LEN_INT64;
		ptrWordInOut1 += BLOCK_LEN_INT64;

	}
}

static void wanderingPhaseGPU2_P1(__global ulong * memMatrixGPU,
    ulong * stateThreadGPU, uint timeCost, ulong nRows, ulong prev0,
    ulong prev1, uint nPARALLEL, uint N_COLS, ulong sizeSlicedRows)
{
	ulong wCont;		//Time Loop iterator
	ulong row0;		//row0: sequentially written during Setup; randomly picked during Wandering
	ulong row1;		//rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering

	for (wCont = 0; wCont < timeCost * nRows; wCont++) {
		//Selects a pseudorandom indices row0 and rowP (row0 = LSW(rand) mod wnd and rowP = LSW(rot(rand)) mod wnd)
		//------------------------------------------------------------------------------------------
		//(USE THIS IF window IS A POWER OF 2)
		//row0 = (((uint64_t)stateThreadGPU[stateStart + 0]) & nRows);
		//row1 = (((uint64_t)stateThreadGPU[stateStart + 2]) & nRows);
		//(USE THIS FOR THE "GENERIC" CASE)
		row0 = (((ulong) stateThreadGPU[0]) % nRows);	//row0 = lsw(rand) mod nRows
		row1 = (((ulong) stateThreadGPU[2]) % nRows);	//row1 = lsw(rot(rand)) mod nRows
		//we rotate 2 words for compatibility with the SSE implementation

		//Performs a reduced-round duplexing operation over "M[row0][col] [+] M[row1][col] [+] M[prev0][col0] [+] M[prev1][col1], updating both M[row0] and M[row1]
		//M[row0][col] = M[row0][col] XOR rand;
		//M[row1][col] = M[row1][col] XOR rot(rand)                     rot(): right rotation by 'omega' bits (e.g., 1 or more words)
		reducedDuplexRowWandering_P1(memMatrixGPU,
		    stateThreadGPU, prev0, row0, row1, prev1,
		    nPARALLEL, N_COLS, sizeSlicedRows);

		//update prev: they now point to the last rows ever updated
		prev0 = row0;
		prev1 = row1;

	}

	//============================ Wrap-up Phase ===============================//
	//Absorbs one last block of the memory matrix with the full-round sponge
	absorbRandomColumn(memMatrixGPU, stateThreadGPU, row0, 0,
	    nPARALLEL, N_COLS, sizeSlicedRows);

}

__kernel void lyra2_setupPhaseWanderingGPU_P1(__global ulong * memMatrixGPU,
    __global ulong * stateThreadGPU_, __global byte * out,
    __global struct lyra2_salt *salt)
{
	uint i, mi;
	long gap = 1;		//Modifier to the step, assuming the values 1 or -1
	ulong step = 1;		//Visitation step (used during Setup to dictate the sequence in which rows are read)
	ulong window = 2;	//Visitation window (used to define which rows can be revisited during Setup)
	ulong sqrt = 2;		//Square of window (i.e., square(window)), when a window is a square number;
	//otherwise, sqrt = 2*square(window/2)

	ulong row0 = 3;		//row0: sequentially written during Setup; randomly picked during Wandering
	ulong prev0 = 2;	//prev0: stores the previous value of row0
	ulong row1 = 1;		//row1: revisited during Setup, and then read [and written]; randomly picked during Wandering
	ulong prev1 = 0;	//prev1: stores the previous value of row1
	uint len = salt->hash_size;
	uint fullBlocks = len / BLOCK_LEN_BYTES;

	ulong stateThreadGPU[STATESIZE_INT64];

	// Thread index:
	int threadNumber = get_global_id(0);
	uint nPARALLEL = salt->nParallel;
	uint N_COLS = salt->nCols;
	uint sizeSlice = salt->m_cost / nPARALLEL;
	__global byte *ptr = (__global byte *) & out[threadNumber * len];

	stateThreadGPU_ += threadNumber * STATESIZE_INT64;
	for (i = 0; i < STATESIZE_INT64; i++)
		stateThreadGPU[i] = stateThreadGPU_[i];

	//Filling Loop
	for (row0 = 3; row0 < sizeSlice; row0++) {
		//Performs a reduced-round duplexing operation over "M[row1][col] [+] M[prev0][col] [+] M[prev1][col]", filling M[row0] and updating M[row1]
		//M[row0][N_COLS-1-col] = M[prev0][col] XOR rand;
		//M[row1][col] = M[row1][col] XOR rot(rand)                    rot(): right rotation by 'omega' bits (e.g., 1 or more words)
		reducedDuplexRowFilling_P1(stateThreadGPU, memMatrixGPU, prev0,
		    prev1, row0, row1, nPARALLEL, N_COLS,
		    salt->sizeSlicedRows);

		//Updates the "prev" indices: the rows more recently updated
		prev0 = row0;
		prev1 = row1;

		//updates the value of row1: deterministically picked, with a variable step
		row1 = (row1 + step) & (window - 1);

		//Checks if all rows in the window where visited.
		if (row1 == 0) {
			window *= 2;	//doubles the size of the re-visitation window
			step = sqrt + gap;	//changes the step
			gap = -gap;	//inverts the modifier to the step
			if (gap == -1) {
				sqrt *= 2;	//Doubles sqrt every other iteration
			}
		}
	}

	//Now goes to Wandering Phase and the Absorb from Wrap-up
	//============================ Wandering Phase =============================//
	//=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
	wanderingPhaseGPU2_P1(memMatrixGPU, stateThreadGPU, salt->t_cost,
	    sizeSlice, prev0, prev1, nPARALLEL, N_COLS, salt->sizeSlicedRows);


	//Squeezes full blocks
	for (i = 0; i < fullBlocks; i++) {
		glmemcpy(ptr, stateThreadGPU, BLOCK_LEN_BYTES);
		spongeLyra(stateThreadGPU);
		ptr += BLOCK_LEN_BYTES;
	}

	//Squeezes remaining bytes
	glmemcpy(ptr, stateThreadGPU, len % BLOCK_LEN_BYTES);
}
