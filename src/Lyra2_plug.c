 /**
 * Implementation of the Lyra2 Password Hashing Scheme (PHS).
 *
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
 * This file was modified by Agnieszka Bielec <bielecagnieszka8 at gmail.com> on June,2015.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <omp.h>
#include <pthread.h>

#include "Lyra2.h"
#include "Sponge.h"
#include "Sponge_sse.h"
#include "arch.h"

#ifdef SIMD_COEF_64
#define BUFF_TYPE __m128i
#define BLOCK_LEN_INT BLOCK_LEN_INT128
#define BLOCK_LEN_BLAKE2_SAFE_INT BLOCK_LEN_BLAKE2_SAFE_INT128
#else
#define BUFF_TYPE uint64_t
#define BLOCK_LEN_INT BLOCK_LEN_INT64
#define BLOCK_LEN_BLAKE2_SAFE_INT BLOCK_LEN_BLAKE2_SAFE_INT64
#endif

/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. The number of columns of the memory matrix is set to nCols = N_COLS.
 * This version supports salts and passwords whose combined length is smaller than the size of the memory matrix,
 * (i.e., (nRows x nCols x b) bits, where "b" is the underlying sponge's bitrate). In this implementation, the "params" 
 * is composed by all integer parameters (treated as type "unsigned int") in the order they are provided, plus the value 
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 * In case of parallel version, there are two more "params": total of threads and thread number (nThreads || threadNumber).
 *
 * @param out The derived key to be output by the algorithm
 * @param outlen Desired key length
 * @param in User password
 * @param inlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param t_cost Parameter to determine the processing time (T)
 * @param m_cost Memory cost parameter (defines the number of rows of the memory matrix, R)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */

int LYRA2(void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost, unsigned int nCols, unsigned int nThreads, struct lyra2_allocation *allocated) {
    if(nThreads==1)
        return LYRA2_for_nThreads1(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, N_COLS, allocated);
    return LYRA2_(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost, nCols, nThreads, allocated);
}

/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "params" is composed by all 
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value 
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
int LYRA2_for_nThreads1(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, struct lyra2_allocation *allocated) {
    //============================= Basic variables ============================//
    int64_t gap = 1;            //Modifier to the step, assuming the values 1 or -1
    uint64_t step = 1;          //Visitation step (used during Setup to dictate the sequence in which rows are read)
    uint64_t window = 2;        //Visitation window (used to define which rows can be revisited during Setup)
    uint64_t sqrt = 2;          //Square of window (i.e., square(window)), when a window is a square number;
                                //otherwise, sqrt = 2*square(window/2) 
    
    uint64_t row0 = 3;          //row0: sequentially written during Setup; randomly picked during Wandering
    uint64_t prev0 = 2;         //prev0: stores the previous value of row0
    uint64_t row1 = 1;          //row1: revisited during Setup, and then read [and written]; randomly picked during Wandering
    uint64_t prev1 = 0;         //prev1: stores the previous value of row1

    uint64_t i;                 //auxiliary iteration counter

    BUFF_TYPE *ptrWord;
    uint64_t nBlocksInput;
    //==========================================================================/
    //================================= Buffers ================================//
    BUFF_TYPE *wholeMatrix;
    BUFF_TYPE **memMatrix;
    byte *ptrByte;
    BUFF_TYPE *state;
    //==========================================================================/
    
    //========== Initializing the Memory Matrix and pointers to it =============//
    //Tries to allocate enough space for the whole memory matrix
    i = (uint64_t) ((uint64_t) nRows * (uint64_t) (BLOCK_LEN_INT64 * nCols * 8));
    wholeMatrix = (BUFF_TYPE*) allocated->threadSliceMatrix[0].aligned;
    //Allocates pointers to each row of the matrix
    memMatrix = (BUFF_TYPE**) allocated->memMatrix;

    //Places the pointers in the correct positions
    ptrWord = wholeMatrix;
    for (i = 0; i < nRows; i++) {
	memMatrix[i] = ptrWord;
	ptrWord += BLOCK_LEN_INT * nCols;
    }
    
    //==========================================================================/
    
    //============= Padding (password + salt + params) with 10*1 ===============//

    //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
    //but this ensures that the password copied locally will be overwritten as soon as possible

    //First, we clean enough blocks for the password, salt, params and padding
    //Change the ''6'' if different amounts of parameters were passed 
    nBlocksInput = ((saltlen + pwdlen + 6 * sizeof (int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;
    ptrByte = (byte*) wholeMatrix;
    memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES);

    //Prepends the password
    memcpy(ptrByte, pwd, pwdlen);
    ptrByte += pwdlen;

    //Concatenates the salt
    memcpy(ptrByte, salt, saltlen);
    ptrByte += saltlen;

    //Concatenates the params: every integer passed as parameter, in the order they are provided by the interface
    memcpy(ptrByte, &kLen, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &pwdlen, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &saltlen, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &timeCost, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &nRows, sizeof (int));
    ptrByte += sizeof (int);
    memcpy(ptrByte, &nCols, sizeof (int));
    ptrByte += sizeof (int);

    //Now comes the padding
    *ptrByte = 0x80;                                            //first byte of padding: right after the password
    ptrByte = (byte*) wholeMatrix;                              //resets the pointer to the start of the memory matrix
    ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1;  //sets the pointer to the correct position: end of incomplete block
    *ptrByte ^= 0x01;                                           //last byte of padding: at the end of the last incomplete block
    
    //==========================================================================/

    //======================= Initializing the Sponge State ====================//
    //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
    state = (BUFF_TYPE*) allocated->threadState[0];
    initState(state);
    
    //==========================================================================/
    
    //============= Absorbing the input data with the sponge ===============//
    
    //Absorbing salt, password and params: this is the only place in which the block length is hard-coded to 512 bits, for compatibility with Blake2b and BlaMka
    ptrWord = wholeMatrix;
    for (i = 0; i < nBlocksInput; i++) {
	absorbBlockBlake2Safe(state, ptrWord);          //absorbs each block of pad(pwd || salt || params)
	ptrWord += BLOCK_LEN_BLAKE2_SAFE_INT;         //goes to next block of pad(pwd || salt || params)
    }
    
    //================================================================================/
    
    //================================ Setup Phase ==================================//
    //==Initializes a (nRows x nCols) memory matrix, it's cells having b bits each)==//

    //Initializes M[0]
    reducedSqueezeRow0(state, memMatrix[0]);    //The locally copied password is most likely overwritten here
    //Initializes M[1]
    reducedDuplexRow1and2(state, memMatrix[0], memMatrix[1]);
    //Initializes M[2]
    reducedDuplexRow1and2(state, memMatrix[1], memMatrix[2]);
    
    //Filling Loop
    for(row0 = 3 ; row0 < nRows; row0++){
        //Performs a reduced-round duplexing operation over "M[row1][col] [+] M[prev0][col] [+] M[prev1][col]", filling M[row0] and updating M[row1]
	//M[row0][N_COLS-1-col] = M[prev0][col] XOR rand;
        //M[row1][col] = M[row1][col] XOR rot(rand)                    rot(): right rotation by 'omega' bits (e.g., 1 or more words)
	reducedDuplexRowFilling(state, memMatrix[row1], memMatrix[prev0], memMatrix[prev1], memMatrix[row0]);

        //Updates the "prev" indices: the rows more recently updated
        prev0 = row0;
        prev1 = row1;
        
        //updates the value of row1: deterministically picked, with a variable step
        row1 = (row1 + step) & (window - 1);
	
	//Checks if all rows in the window where visited.
	if (row1 == 0) {
	    window *= 2;                        //doubles the size of the re-visitation window
	    step = sqrt + gap;                  //changes the step: approximately doubles its value
	    gap = -gap;                         //inverts the modifier to the step 
            if (gap == -1){
                sqrt *= 2;                      //Doubles sqrt every other iteration
            }
	}
    }
    
    //============================ Wandering Phase =============================//
    //=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
    
    //Visitation Loop
    for (i = 0 ; i < timeCost*nRows ; i++) {            
        //Selects a pseudorandom indices row0 and row1
        //------------------------------------------------------------------------------------------
        /*(USE THIS IF nRows IS A POWER OF 2)*/
        //row0 = ((uint64_t)state[0]) & (nRows-1);	
        //row1 = ((uint64_t)state[2]) & (nRows-1);
        /*(USE THIS FOR THE "GENERIC" CASE)*/
#if SIMD_COEF_64
        row0 = ((uint64_t)(((__uint128_t *)state)[0])) % nRows;         //row0 = lsw(rand) mod nRows
        row1 = ((uint64_t)(((__uint128_t *)state)[1])) % nRows;         //row1 = lsw(rot(rand)) mod nRows
#else     
        row0 = ((uint64_t)state[0]) % nRows;            //row0 = lsw(rand) mod nRows
        row1 = ((uint64_t)state[2]) % nRows;            //row1 = lsw(rot(rand)) mod nRows 
                                                        //we rotate 2 words for compatibility with the SSE implementation
#endif

        //Performs a reduced-round duplexing operation over "M[row0][col] [+] M[row1][col] [+] M[prev0][col0] [+] M[prev1][col1], updating both M[row0] and M[row1]
        //M[row0][col] = M[row0][col] XOR rand; 
        //M[row1][col] = M[row1][col] XOR rot(rand)                     rot(): right rotation by 'omega' bits (e.g., 1 or more words)
        reducedDuplexRowWandering(state, memMatrix[row0], memMatrix[row1], memMatrix[prev0], memMatrix[prev1]);

        //update prev's: they now point to the last rows ever updated
        prev0 = row0;
        prev1 = row1;   
    }
    
    //==========================================================================/

    //============================ Wrap-up Phase ===============================//
    //========================= Output computation =============================//
    //Absorbs one last block of the memory matrix with the full-round sponge
    absorbColumn(state, memMatrix[row0]);
    
    //Squeezes the key with the full-round sponge
    squeeze(state, K, kLen);

    return 0;
}

/**
 * Executes Lyra2 based on the G function from Blake2b or BlaMka. This version supports salts and passwords
 * whose combined length is smaller than the size of the memory matrix, (i.e., (nRows x nCols x b) bits,
 * where "b" is the underlying sponge's bitrate). In this implementation, the "params" is composed by all 
 * integer parameters (treated as type "unsigned int") in the order they are provided, plus the value 
 * of nCols, (i.e., params = kLen || pwdlen || saltlen || timeCost || nRows || nCols || nPARALLEL || threadNumber).
 *
 * @param K The derived key to be output by the algorithm
 * @param kLen Desired key length
 * @param pwd User password
 * @param pwdlen Password length
 * @param salt Salt
 * @param saltlen Salt length
 * @param timeCost Parameter to determine the processing time (T)
 * @param nRows Number or rows of the memory matrix (R)
 * @param nCols Number of columns of the memory matrix (C)
 *
 * @return 0 if the key is generated correctly; -1 if there is an error (usually due to lack of memory for allocation)
 */
int LYRA2_(void *K, unsigned int kLen, const void *pwd, unsigned int pwdlen, const void *salt, unsigned int saltlen, unsigned int timeCost, unsigned int nRows, unsigned int nCols, unsigned int nThreads, struct lyra2_allocation *allocated) {
    //============================= Basic variables ============================//
    int64_t i,j;        //auxiliary iteration counter
    //==========================================================================/
    
    //================================= Buffers ================================//
    BUFF_TYPE **memMatrix;
    unsigned char **pKeys;
    unsigned char **threadKey = allocated->threadKey;
    BUFF_TYPE **threadState = (BUFF_TYPE**) allocated->threadState;
    //==========================================================================/


    //============================= Basic threads variables ============================//
    uint64_t threadNumber;
    uint64_t halfSlice ;

    int64_t gap=1;                              //Modifier to the step, assuming the values 1 or -1
    uint64_t step=1;                            //Visitation step (used during Setup and Wandering phases)
    uint64_t window=2;                          //Visitation window (used to define which rows can be revisited during Setup)
    uint64_t sync=4;                            //Synchronize counter
    uint64_t sqrt=2;                            //Square of window (i.e., square(window)), when a window is a square number;
                                                //otherwise, sqrt = 2*square(window/2) 
          

    uint64_t *row0=allocated->row0;              //row0: sequentially written during Setup; randomly picked during Wandering
    uint64_t *prev0=allocated->prev0;            //prev0: stores the previous value of row0
    uint64_t *rowP=allocated->rowP;              //rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering
    uint64_t *prevP=allocated->prevP;            //prevP: stores the previous value of rowP


    uint64_t *jP=allocated->jP;                  //Starts with threadNumber.
    uint64_t kP;
    uint64_t wCont;
        
    uint64_t sizeSlicedRows;
    uint64_t off0;
    uint64_t offP;
    uint64_t row00;

    BUFF_TYPE **ptrWord = (BUFF_TYPE**) allocated->ptrWord;


    sizeSlicedRows = nRows/nThreads;
    halfSlice = sizeSlicedRows/2;

    //========== Initializing the Memory Matrix and pointers to it =============//
    //Allocates pointers to each row of the matrix
    memMatrix = (BUFF_TYPE**) allocated->memMatrix;
   //Allocates pointers to each key
    pKeys = allocated->pKeys;	

    for(i=0;i<nThreads;i++)
    {      
	row0[i] = 3;              //row0: sequentially written during Setup; randomly picked during Wandering
	prev0[i] = 2;             //prev0: stores the previous value of row0
	rowP[i] = 1;              //rowP: revisited during Setup, and then read [and written]; randomly picked during Wandering
	prevP[i] = 0;             //prevP: stores the previous value of rowP

    }  
        //==========================================================================/

    for(threadNumber = 0; threadNumber<nThreads;threadNumber++)
    {
	uint64_t nBlocksInput;
	byte *ptrByte;
	int p;
        //========================== BootStrapping Phase ==========================//

        //Places the pointers in the correct positions
        ptrWord[threadNumber] = allocated->threadSliceMatrix[threadNumber].aligned;
        for (kP = 0; kP < sizeSlicedRows; kP++) { //to do
            memMatrix[threadNumber*sizeSlicedRows + kP] = ptrWord[threadNumber];
            ptrWord[threadNumber] += ((BLOCK_LEN_INT * nCols));
        }

        threadKey[threadNumber] =  allocated->threadKey[threadNumber];

        //Places the pointers in the correct positions
        pKeys[threadNumber] = threadKey[threadNumber];
        
        //==========================================================================/
        
        //============= Padding (password + salt + params) with 10*1 ===============//

        //OBS.:The memory matrix will temporarily hold the password: not for saving memory,
        //but this ensures that the password copied locally will be overwritten as soon as possible

        //First, we clean enough blocks for the password, salt, params and padding
        //Change the ''8'' if different amounts of parameters were passed 
        nBlocksInput = ((saltlen + pwdlen + 8 * sizeof (int)) / BLOCK_LEN_BLAKE2_SAFE_BYTES) + 1;
        ptrByte = (byte*) allocated->threadSliceMatrix[threadNumber].aligned;
        memset(ptrByte, 0, nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES);

        //Prepends the password
        memcpy(ptrByte, pwd, pwdlen);
        ptrByte += pwdlen;

        //Concatenates the salt
        memcpy(ptrByte, salt, saltlen);
        ptrByte += saltlen;

        //Concatenates the params: every integer passed as parameter, in the order they are provided by the interface
        memcpy(ptrByte, &kLen, sizeof (int));
        ptrByte += sizeof (int);
        memcpy(ptrByte, &pwdlen, sizeof (int));
        ptrByte += sizeof (int);
        memcpy(ptrByte, &saltlen, sizeof (int));
        ptrByte += sizeof (int);
        memcpy(ptrByte, &timeCost, sizeof (int));
        ptrByte += sizeof (int);
        memcpy(ptrByte, &nRows, sizeof (int));
        ptrByte += sizeof (int);
        memcpy(ptrByte, &nCols, sizeof (int));
        ptrByte += sizeof (int);
        p = nThreads;
        memcpy(ptrByte, &p, sizeof (int));
        ptrByte += sizeof (int);
        memcpy(ptrByte, &threadNumber, sizeof (int));
        ptrByte += sizeof (int);
        
        //Now comes the padding
        *ptrByte = 0x80;                                                //first byte of padding: right after the password
        ptrByte = (byte*) allocated->threadSliceMatrix[threadNumber].aligned;//resets the pointer to the start of the memory matrix
        ptrByte += nBlocksInput * BLOCK_LEN_BLAKE2_SAFE_BYTES - 1;      //sets the pointer to the correct position: end of incomplete block
        *ptrByte ^= 0x01;                                               //last byte of padding: at the end of the last incomplete block
        
        //==========================================================================/
        
        //============== Initializing the Sponge State =============/
        //Sponge state: 16 uint64_t, BLOCK_LEN_INT64 words of them for the bitrate (b) and the remainder for the capacity (c)
        //Thread State
        threadState[threadNumber] = (BUFF_TYPE*) allocated->threadState[threadNumber];
        initState(threadState[threadNumber]);

        
        //==========================================================================/
        
        //============= Absorbing the input data with the sponge ===============//

        //Absorbing salt, password and params: this is the only place in which the block length is hard-coded to 512 bits, for compatibility with Blake2b and BlaMka
        ptrWord[threadNumber] = allocated->threadSliceMatrix[threadNumber].aligned;
        for (kP = 0; kP < nBlocksInput; kP++) {
            absorbBlockBlake2Safe(threadState[threadNumber], ptrWord[threadNumber]);        //absorbs each block of pad(pwd || salt || params)
            ptrWord[threadNumber] += BLOCK_LEN_BLAKE2_SAFE_INT;             //goes to next block of pad(pwd || salt || params)
        }
        
        //================================================================================/

        //================================ Setup Phase ==================================//
        //==Initializes a (nRows x nCols) memory matrix, it's cells having b bits each)==//

        //Initializes M[0]
        reducedSqueezeRow0(threadState[threadNumber], memMatrix[threadNumber*sizeSlicedRows]);               //The locally copied password is most likely overwritten here
        //Initializes M[1]
        reducedDuplexRow1and2(threadState[threadNumber], memMatrix[threadNumber*sizeSlicedRows], memMatrix[threadNumber*sizeSlicedRows + 1]);
        //Initializes M[2]
        reducedDuplexRow1and2(threadState[threadNumber], memMatrix[threadNumber*sizeSlicedRows + 1], memMatrix[threadNumber*sizeSlicedRows + 2]);

        jP[threadNumber] = threadNumber;
	
	}
        
        //Filling Loop
        for (row00 = 3; row00 < sizeSlicedRows; row00++) {
            //Performs a reduced-round duplexing operation over "Mj[rowP][col] [+] Mi[prev0][col] [+] Mj[prevP][col]", filling Mi[row0] and updating Mj[rowP]
            //Mi[row00][N_COLS-1-col] = Mi[prev0][col] XOR rand;
            //Mj[rowP][col] = Mj[rowP][col] XOR rot(rand)                    rot(): right rotation by 'omega' bits (e.g., 1 or more words)
	    
	    for(threadNumber = 0; threadNumber<nThreads;threadNumber++)
            	reducedDuplexRowFilling(threadState[threadNumber], memMatrix[jP[threadNumber]*sizeSlicedRows + rowP[threadNumber]], memMatrix[threadNumber*sizeSlicedRows + 			prev0[threadNumber]], memMatrix[jP[threadNumber]*sizeSlicedRows + prevP[threadNumber]], memMatrix[threadNumber*sizeSlicedRows + row00]);
            
	    for(threadNumber = 0; threadNumber<nThreads;threadNumber++)
	    {
		//Updates the "prev" indices: the rows more recently updated
            	prev0[threadNumber] = row00;
            	prevP[threadNumber] = rowP[threadNumber];
		//updates the value of rowP: deterministically picked, with a variable step
		rowP[threadNumber] = (rowP[threadNumber] + step) & (window - 1);	    		
	    } 
	    //Checks if all rows in the window where visited.
	    if (rowP[0] == 0) 
	    {
	        window *= 2;                    //doubles the size of the re-visitation window
	        step = sqrt + gap;              //changes the step: approximately doubles its value
	        gap = -gap;                     //inverts the modifier to the step
	        if (gap == -1){
	            sqrt *= 2;                  //Doubles sqrt every other iteration
	        }
	    }
	    if (row00 == sync)
	    {
		 //Synchronize threads and change the slices
		 sync += sqrt/2;                 //increment synchronize counter
		 for(threadNumber = 0; threadNumber<nThreads;threadNumber++) {
		        jP[threadNumber] = (jP[threadNumber] + 1) % nThreads;      //change the visitation thread
		 }
	    } 
        } 
        
	//============================ Wandering Phase =============================//
	//=====Iteratively overwrites pseudorandom cells of the memory matrix=======//
	window = halfSlice;
	off0 = 0;
	offP = window;

	sync = sqrt;
        
        //Visitation Loop
        for (wCont = 0; wCont < timeCost*sizeSlicedRows; wCont++){                
            //Selects a pseudorandom indices row0 and rowP 
            //------------------------------------------------------------------------------------------
            /*(USE THIS IF window IS A POWER OF 2)*/
            //row0  = off0 + (((uint64_t)threadState[0]) & (window-1));
            //rowP = offP + (((uint64_t)threadState[2]) & (window-1));
            /*(USE THIS FOR THE "GENERIC" CASE)*/
            for(threadNumber = 0; threadNumber<nThreads;threadNumber++)
	    {
#ifdef SIMD_COEF_64
		    row0[threadNumber] = off0 + (((uint64_t)(((__uint128_t *)threadState[threadNumber])[0])) % window);             //row0 = off0 + (lsw(rand) mod window)
		    rowP[threadNumber] = offP + (((uint64_t)(((__uint128_t *)threadState[threadNumber])[1])) % window);             //row1 = offP + (lsw(rot(rand)) mod window)
		    //Selects a pseudorandom indices j0 (LSW(rot^2 (rand)) mod p)
		    jP[threadNumber] = ((uint64_t)(((__uint128_t *)threadState[threadNumber])[2])) % nThreads;                     //jP = lsw(rot^2(rand)) mod nPARALLEL
#else
		    row0[threadNumber] = off0 + (((uint64_t)threadState[threadNumber][0]) % window);    //row0 = off0 + (lsw(rand) mod window)
		    rowP[threadNumber] = offP + (((uint64_t)threadState[threadNumber][2]) % window);    //row1 = offP + (lsw(rot(rand)) mod window)
		    //Selects a pseudorandom indices jP 
                    jP[threadNumber] = ((uint64_t)threadState[threadNumber][4]) % nThreads;                        //jP = lsw(rot^2(rand)) mod nThreads
#endif
                                                                              
                    //Performs a reduced-round duplexing operation over "Mi[row0][col] [+] Mj[rowP][col] [+] Mi[prev0][col0]", updating Mi[row0]
                    //Mi[row0][col] = Mi[row0][col] XOR rand; 
                    reducedDuplexRowWanderingParallel(threadState[threadNumber], memMatrix[threadNumber*sizeSlicedRows + row0[threadNumber]], memMatrix[jP 
                                                      [threadNumber]*sizeSlicedRows + rowP[threadNumber]], memMatrix[threadNumber*sizeSlicedRows + prev0[threadNumber]]);

                    //update prev: they now point to the last rows ever updated
                    prev0[threadNumber] = row0[threadNumber];
            }
	    if (wCont == sync) {
		    uint64_t offTemp;
		    sync += sqrt;
	            offTemp = off0;
	            off0 = offP;
	            offP = offTemp;
	    }
        }

     for(threadNumber = 0; threadNumber<nThreads;threadNumber++)
     {
        
        //==========================================================================/

        //============================ Wrap-up Phase ===============================//
        //========================= Output computation =============================//
        //Absorbs one last block of the memory matrix with the full-round sponge
        absorbColumn(threadState[threadNumber],  memMatrix[threadNumber*sizeSlicedRows + row0[threadNumber]]);

        //Squeezes the key
        squeeze(threadState[threadNumber], threadKey[threadNumber], kLen);

    }   // Parallelism End

    // XORs all Keys
    for (i = 1; i < nThreads; i++) {
        for (j = 0; j < kLen; j++) {
            pKeys[0][j] ^= pKeys[i][j];
        }
    }

    // Returns in the correct variable
    memcpy(K, pKeys[0], kLen);

    return 0;
}
