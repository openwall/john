/**
 * Header file for Blake2b's and BlaMka's internal permutation in the form of a sponge.
 * This code is based on the original Blake2b's implementation provided by
 * Samuel Neves (https://blake2.net/)
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
#ifndef SPONGE_LYRA2_OPENCL_H_
#define SPONGE_LYRA2_OPENCL_H_


typedef unsigned char byte;

//Block length required so Blake2's Initialization Vector (IV) is not overwritten (THIS SHOULD NOT BE MODIFIED)
#define BLOCK_LEN_BLAKE2_SAFE_INT64 8                                   //512 bits (=64 bytes, =8 uint64_t)
#define BLOCK_LEN_BLAKE2_SAFE_BYTES (BLOCK_LEN_BLAKE2_SAFE_INT64 * 8)   //same as above, in bytes

//default block lenght: 768 bits
#ifndef BLOCK_LEN_INT64
        #define BLOCK_LEN_INT64 12                                      //Block length: 768 bits (=96 bytes, =12 uint64_t)
#endif

#define BLOCK_LEN_BYTES (BLOCK_LEN_INT64 * 8)                           //Block length, in bytes

#define STATESIZE_INT64 16
#define STATESIZE_BYTES (16 * sizeof (unsigned long))

#define RHO 1                                                   //Number of reduced rounds performe

#define blake2b_IV_0 0x6a09e667f3bcc908UL
#define blake2b_IV_1 0xbb67ae8584caa73bUL
#define blake2b_IV_2 0x3c6ef372fe94f82bUL
#define blake2b_IV_3 0xa54ff53a5f1d36f1UL
#define blake2b_IV_4 0x510e527fade682d1UL
#define blake2b_IV_5 0x9b05688c2b3e6c1fUL
#define blake2b_IV_6 0x1f83d9abfb41bd6bUL
#define blake2b_IV_7 0x5be0cd19137e2179UL


#define rotr64(w, c) ( (w) >> (c) ) | ( (w) << ( 64 - (c) ) )


#define DIAGONALIZE(r,v) \
    t0=v[4];                      v[4]=v[5]; v[5]=v[6]; v[6]=v[7]; v[7]=t0; \
    t0=v[8]; t1=v[9];             v[8]=v[10]; v[9]=v[11]; v[10]=t0; v[11]=t1; \
    t0=v[12]; t1=v[13]; t2=v[14]; v[12]=v[15]; v[13]=t0; v[14]=t1; v[15]=t2;

/*Blake2b's G function*/
#define G(a,b,c,d) \
    a = a + b; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \


/*One Round of the Blake2b's compression function*/
#define ROUND_LYRA(r)  \
    G(v[ 0],v[ 4],v[ 8],v[12]); \
    G(v[ 1],v[ 5],v[ 9],v[13]); \
    G(v[ 2],v[ 6],v[10],v[14]); \
    G(v[ 3],v[ 7],v[11],v[15]); \
    G(v[ 0],v[ 5],v[10],v[15]); \
    G(v[ 1],v[ 6],v[11],v[12]); \
    G(v[ 2],v[ 7],v[ 8],v[13]); \
    G(v[ 3],v[ 4],v[ 9],v[14]);

//#define USE_VECTORS 1

#endif /* SPONGE_H_ */
