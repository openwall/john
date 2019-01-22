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

//Decrease plaintext length
#undef PLAINTEXT_LENGTH
#undef BUFFER_SIZE
#define PLAINTEXT_LENGTH        23  /* 23 characters + 0x80 */
#define BUFFER_SIZE             24  /* PLAINTEXT_LENGTH multiple of 4 */

#if gpu_amd(DEVICE_INFO)
    #define VECTOR_USAGE    1
#endif

#if gpu_amd(DEVICE_INFO) || nvidia_sm_5x(DEVICE_INFO) || nvidia_sm_6x(DEVICE_INFO)
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

    SPREAD_64(hash[0], hash[0], BITMAP_SIZE_MINUS1, bit_mask_x, bit_mask_y)

    if (bitmap[bit_mask_x >> 5] & (1U << (bit_mask_x & 31))) {

	{
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
    uint64_t w[16];

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

    #pragma unroll
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

    #pragma unroll
    for (uint i = 16U; i < 76U; i++) {
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
    H[0] = d;
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
    uint64_t		H[1];
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
    uint64_t		H[1];

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
