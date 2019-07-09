/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2012-2016 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_rawsha512.h"
#include "opencl_mask_extras.h"

#ifndef UNROLL_LOOP
    ///	    *** UNROLL ***
    ///AMD: sometimes a bad thing(?).
    ///NVIDIA: GTX 570 don't allow full unroll.
    #if amd_vliw4(DEVICE_INFO) || amd_vliw5(DEVICE_INFO)
        #define UNROLL_LOOP    133128
    #elif amd_gcn(DEVICE_INFO) && DEV_VER_MAJOR < 2500
        #define UNROLL_LOOP    132098
    #elif amd_gcn(DEVICE_INFO) && DEV_VER_MAJOR >= 2500
        #define UNROLL_LOOP    34079748
    #elif (nvidia_sm_2x(DEVICE_INFO) || nvidia_sm_3x(DEVICE_INFO))
        #define UNROLL_LOOP    132098
    #elif nvidia_sm_5x(DEVICE_INFO)
        #define UNROLL_LOOP    33686536
    #elif nvidia_sm_6x(DEVICE_INFO)
        #define UNROLL_LOOP    132104
    #elif gpu_intel(DEVICE_INFO)
        #define UNROLL_LOOP    262658
    #else
        #define UNROLL_LOOP    0
    #endif
#endif

#if (UNROLL_LOOP & (1 << 25))
    #define VECTOR_USAGE    1
#endif

#if gpu_amd(DEVICE_INFO)
    #define USE_LOCAL       1
#endif

inline void _memcpy(               uint32_t * dest,
                    __global const uint32_t * src,
                             const uint32_t   len) {

    for (uint i = 0; i < len; i += 4)
        *dest++ = *src++;
}

inline void any_hash_cracked(
	const uint32_t iter,                        //which candidates_number is this one
	volatile __global uint32_t * const hash_id, //information about how recover the cracked password
	const uint64_t * const hash,                //the hash calculated by this kernel
	__global const uint32_t * const bitmap) {

    uint32_t bit_mask_x, bit_mask_y, found;

    SPREAD_64(hash[0], hash[1], BITMAP_SIZE_MINUS1, bit_mask_x, bit_mask_y)

    if (bitmap[bit_mask_x >> 5] & (1U << (bit_mask_x & 31))) {

	if (bitmap[bit_mask_y >> 5] & (1U << (bit_mask_y & 31))) {
	    //A possible crack have been found.
	    found = atomic_inc(&hash_id[0]);

	    {
		//Save (the probably) hashed key metadata.
		uint32_t base = get_global_id(0);

		hash_id[1 + 3 * found] = base;
		hash_id[2 + 3 * found] = iter;
		hash_id[3 + 3 * found] = (uint32_t) hash[0];
	    }
	}
    }
}

/*
 * Reverse 4 rounds more in SHA-256 and SHA-512 OpenCL kernels
 *
 * 1. To avoid data transfers from GPU to CPU, I'm using a Bloom filter;
 * 2. It can produce false positives;
 * 3. The best approach is to discard as many candidates as possible on GPU
 *    and avoid costly transfers;
 * 4. If I reverse rounds I will have less data to compare;
 * 5. So I'll face more false positives;
 * 6. That will impact performance.
 *
 * That said, for a future version, based on how many hashes were loaded to
 * crack, we can:
 * -> use a reversed sha_block() version when running a session with only a few
 *    keys.
 *
 * I tested it using a session like this one:
 *   Loaded 4000002 password hashes with no different salts (Raw-SHA256-opencl [SHA256 OpenCL])
 *
 * Using mask on a "Titan X Maxwell", JtR will hash (and discard) more than
 * 110 millions keys per crypt_all() call.
 *
 * 1. Running JtR as it is now:
 *    False positives per crypt_all() [1]: 1515: 0,0014%
 *
 * 2. When I reverse steps (less bytes to use on filtering, more data transfers):
 *    False positives per crypt_all() [1]: 208320: 0,0939%
 *    Since data transfers GPU->CPU are slow:
 *     => Result is a 300000Kp/s penalty.
 *
 * [1] Of course, one could be a crack.
 */
inline void sha512_block(	  const uint64_t * const buffer,
				  const uint32_t total, uint64_t * const H) {

    uint64_t a = H0;
    uint64_t b = H1;
    uint64_t c = H2;
    uint64_t d = H3;
    uint64_t e = H4;
    uint64_t f = H5;
    uint64_t g = H6;
    uint64_t h = H7;
    uint64_t t;
    uint64_t w[16];	//#define  w   buffer

#ifdef VECTOR_USAGE
    ulong16  w_vector;
    w_vector = vload16(0, buffer);
    w_vector = SWAP64_V(w_vector);
    vstore16(w_vector, 0, w);
#else
    #pragma unroll
    for (uint i = 0U; i < 15U; i++)
        w[i] = SWAP64(buffer[i]);
#endif
    w[15] = (total * 8UL);

#if (UNROLL_LOOP & (1 << 1))
    #pragma unroll 1
#elif (UNROLL_LOOP & (1 << 2))
    #pragma unroll 4
#elif (UNROLL_LOOP & (1 << 3))
    #pragma unroll
#endif
    for (uint i = 0U; i < 16U; i++) {
	t = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);

	h = g;
	g = f;
	f = e;
	e = d + t;
	t = t + Maj(a, b, c) + Sigma0(a);
	d = c;
	c = b;
	b = a;
	a = t;
    }

#if (UNROLL_LOOP & (1 << 9))
    #pragma unroll 1
#elif (UNROLL_LOOP & (1 << 10))
    #pragma unroll 16
#elif (UNROLL_LOOP & (1 << 11))
    #pragma unroll
#endif
    for (uint i = 16U; i < 80U; i++) {
	w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
	t = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);

	h = g;
	g = f;
	f = e;
	e = d + t;
	t = t + Maj(a, b, c) + Sigma0(a);
	d = c;
	c = b;
	b = a;
	a = t;
    }

    /* Put checksum in context given as argument. */
    H[0] = (a + H0);
    H[1] = (b + H1);
    H[2] = (c + H2);
    H[3] = (d + H3);
    H[4] = (e + H4);
    H[5] = (f + H5);
    H[6] = (g + H6);
    H[7] = (h + H7);
}

/* *****************
- index,		//keys offset and length
- int_key_loc,		//the position of the mask to apply
- int_keys,		//mask to be applied
- candidates_number,	//the number of candidates by mask mode
- hash_id,		//information about how recover the cracked password
- bitmap,		//bitmap containing all to crack hashes
***************** */
__kernel
void kernel_plaintext_raw(
	     MAYBE_CONSTANT sha512_salt  * salt,
	     __global const uint32_t *       __restrict keys_buffer,
             __global const uint32_t * const __restrict index,
	     __global const uint32_t * const __restrict int_key_loc,
	     __global const uint32_t * const __restrict int_keys,
		      const uint32_t              candidate_id,
	     __global       uint32_t * const __restrict computed_total,
	     __global       uint64_t * const __restrict computed_w) {

    //Compute buffers (on CPU and NVIDIA, better private)
    uint64_t		w[16];
    size_t gid = get_global_id(0);

#ifdef USE_LOCAL
    __local uint32_t	_ltotal[512];
    #define		total    _ltotal[get_local_id(0)]
#else
    uint32_t            _ltotal;
    #define		total    _ltotal
#endif

    {
	//Get the position and length of the target key.
	uint32_t base = index[gid];
	total = base & 63;

	//Ajust keys to it start position.
	keys_buffer += (base >> 6);
    }
    //- Differences -------------------------------
    #define		W_OFFSET    0

    //Clear the buffer.
    #pragma unroll
    for (uint i = 0; i < 15; i++)
        w[i] = 0;

    //Get password.
    _memcpy((uint32_t *) w, keys_buffer, total);
    //---------------------------------------------

    //Prepare buffer.
    CLEAR_BUFFER_64_SINGLE(w, total);
    APPEND_SINGLE(w, 0x80UL, total);

#ifdef GPU_MASK_MODE
	    //Mask Mode: keys generation/finalization.
	    MASK_KEYS_GENERATION(candidate_id)
#endif

    //save computed w[]
    computed_total[gid] = total;

    #pragma unroll
    for (uint i = 0; i < 15; i++)
        computed_w[gid * 16 + i] = w[i];
}
#undef		W_OFFSET

__kernel
void kernel_crypt(
		      const uint32_t              candidate_id,
    volatile __global       uint32_t * const __restrict hash_id,
             __global       uint32_t * const __restrict bitmap,
	     __global const uint32_t *       __restrict computed_total,
	     __global const uint64_t *       __restrict computed_w) {

    //Compute buffers (on CPU and NVIDIA, better private)
    uint64_t		w[16];
    uint64_t		H[8];
    size_t gid = get_global_id(0);

#ifdef USE_LOCAL
    __local uint32_t	_ltotal[512];
    #define		total    _ltotal[get_local_id(0)]
#else
    uint32_t            _ltotal;
    #define		total    _ltotal
#endif

    //Get w[].
    total = computed_total[gid];

    #pragma unroll
    for (uint i = 0; i < 15; i++)
        w[i] = computed_w[gid * 16 + i];

    /* Run the collected hash value through sha512. */
    sha512_block(w, total, H);

    any_hash_cracked(candidate_id, hash_id, H, bitmap);
}

__kernel
void kernel_crypt_raw(
	     MAYBE_CONSTANT sha512_salt  * salt,
	     __global const uint32_t *       __restrict keys_buffer,
             __global const uint32_t * const __restrict index,
	     __global const uint32_t * const __restrict int_key_loc,
	     __global const uint32_t * const __restrict int_keys,
		      const uint32_t              candidates_number,
    volatile __global       uint32_t * const __restrict hash_id,
             __global       uint32_t * const __restrict bitmap) {

    //Compute buffers (on CPU and NVIDIA, better private)
    uint64_t		w[16];
    uint64_t		H[8];
#ifdef USE_LOCAL
    __local uint32_t	_ltotal[512];
    #define		total    _ltotal[get_local_id(0)]
#else
    uint32_t            _ltotal;
    #define		total    _ltotal
#endif

    {
	//Get position and length of informed key.
	uint32_t base = index[get_global_id(0)];
	total = base & 63;

	//Ajust keys to it start position.
	keys_buffer += (base >> 6);
    }
    //- Differences -------------------------------
    #define		W_OFFSET    0

    //Clear the buffer.
    #pragma unroll
    for (uint i = 0; i < 15; i++)
        w[i] = 0;

    //Get password.
    _memcpy((uint32_t *) w, keys_buffer, total);
    //---------------------------------------------

    //Prepare buffer.
    CLEAR_BUFFER_64_SINGLE(w, total);
    APPEND_SINGLE(w, 0x80UL, total);

    {
	uint32_t i = 0;

#ifdef GPU_MASK_MODE
	//Handle the GPU mask mode candidates generation.
	for (; i < candidates_number; i++) {
#endif

#ifdef GPU_MASK_MODE
	    //Mask Mode: keys generation/finalization.
	    MASK_KEYS_GENERATION(i)
#endif
	    /* Run the collected hash value through sha512. */
	    sha512_block(w, total, H);

	    any_hash_cracked(i, hash_id, H, bitmap);
#ifdef GPU_MASK_MODE
	}
#endif
    }
}
#undef		W_OFFSET

__kernel
void kernel_crypt_xsha(
	     MAYBE_CONSTANT sha512_salt  * salt,
	     __global const uint32_t *       __restrict keys_buffer,
             __global const uint32_t * const __restrict index,
	     __global const uint32_t * const __restrict int_key_loc,
	     __global const uint32_t * const __restrict int_keys,
		      const uint32_t              candidates_number,
    volatile __global       uint32_t * const __restrict hash_id,
             __global       uint32_t * const __restrict bitmap) {

    //Compute buffers (on CPU and NVIDIA, better private)
    uint64_t		w[16];
    uint64_t		H[8];

#ifdef USE_LOCAL
    __local uint32_t	_ltotal[512];
    #define		total    _ltotal[get_local_id(0)]
#else
    uint32_t            _ltotal;
    #define		total    _ltotal
#endif

    {
	//Get position and length of informed key.
	uint32_t base = index[get_global_id(0)];
	total = base & 63;

	//Ajust keys to it start position.
	keys_buffer += (base >> 6);
    }
    //- Differences -------------------------------
    #define		W_OFFSET    4

    //Get salt information.
    w[0] = salt->salt;

    //Clear the buffer.
    #pragma unroll
    for (uint i = 1; i < 15; i++)
        w[i] = 0;

    //Get password.
    _memcpy(((uint32_t *) w) + 1, keys_buffer, total);
    total += SALT_SIZE_X;
    //---------------------------------------------

    //Prepare buffer.
    CLEAR_BUFFER_64_SINGLE(w, total);
    APPEND_SINGLE(w, 0x80UL, total);

    {
	uint32_t i = 0;

#ifdef GPU_MASK_MODE
	//Handle the GPU mask mode candidates generation.
	for (; i < candidates_number; i++) {
#endif

#ifdef GPU_MASK_MODE
	    //Mask Mode: keys generation/finalization.
	    MASK_KEYS_GENERATION(i)
#endif
	    /* Run the collected hash value through sha512. */
	    sha512_block(w, total, H);

	    any_hash_cracked(i, hash_id, H, bitmap);
#ifdef GPU_MASK_MODE
	}
#endif
    }
}

__kernel
void kernel_prepare(
    const    uint32_t                    candidates_number,
    __global uint32_t * const __restrict hash_id) {

    //Clean bitmap and result buffer
    if (get_global_id(0) == 0)
	hash_id[0] = 0;
}
