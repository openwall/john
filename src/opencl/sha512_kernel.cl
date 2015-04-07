/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_rawsha512.h"
#include "opencl_mask_extras.h"

///	    *** UNROLL ***
///AMD: sometimes a bad thing(?).
#if amd_vliw4(DEVICE_INFO) || amd_vliw5(DEVICE_INFO)
    #define UNROLL_LEVEL	2
#elif amd_gcn(DEVICE_INFO)
    #define UNROLL_LEVEL	1
#elif gpu_nvidia(DEVICE_INFO)
    #define UNROLL_LEVEL	0
#else
    #define UNROLL_LEVEL	0
#endif

inline void _memcpy(               uint32_t * dest,
                    __global const uint32_t * src,
                             const uint32_t   len) {

#if UNROLL_LEVEL > 0
    #pragma unroll
#endif
    for (uint32_t i = 0; i < 120; i += 4)
        *dest++ = select(0U, *src++, i < len);
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
    uint64_t w[16];	//#define  w   buffer

#if UNROLL_LEVEL > 0
    #pragma unroll
#endif
    for (uint64_t i = 0; i < 15; i++)
        w[i] = SWAP64(buffer[i]);
    w[15] = (total * 8UL);

    /* Do the job. */
#if UNROLL_LEVEL > 0
    #pragma unroll
#endif
    for (uint64_t i = 0U; i < 16U; i++) {
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

#if UNROLL_LEVEL > 1
    #pragma unroll
#endif
    for (uint64_t i = 16U; i < 80U; i++) {
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
- num_loaded_hashes,	//number of password hashes transfered
- loaded_hashes,	//buffer of password hashes transfered
- hash_id,		//information about how recover the cracked password
***************** */
__kernel
void kernel_crypt_raw(
	     __constant sha512_salt  * salt,
	     __global const uint32_t *       __restrict keys_buffer,
             __global const uint32_t * const __restrict index,
	     __global const uint32_t * const __restrict int_key_loc,
	     __global const uint32_t * const __restrict int_keys,
		      const uint32_t              candidates_number,
		      const uint32_t              num_loaded_hashes,
	     __global const uint64_t * const __restrict loaded_hashes,
    volatile __global       uint32_t * const __restrict hash_id,
    volatile __global       uint32_t * const __restrict bitmap) {

    //Compute buffers (on CPU and NVIDIA, better private)
    uint64_t		w[16];
    uint64_t		H[8];
    __local uint32_t	_ltotal[512];
    #define		total    _ltotal[get_local_id(0)]
    #define		W_OFFSET    0

    {
	//Get position and length of informed key.
	uint32_t base = index[get_global_id(0)];
	total = base & 63;

	//Ajust keys to it start position.
	keys_buffer += (base >> 6);
    }
    //Get password.
    _memcpy((uint32_t *) w, keys_buffer, total);

    //Prepare buffer.
    CLEAR_BUFFER_64_SINGLE(w, total);
    APPEND_SINGLE(w, 0x80UL, total);

    //Handle the candidates (candidates_number) to be produced.
    for (uint32_t i = 0; i < candidates_number; i++) {

	//Mask Mode: keys generation/finalization.
	MASK_KEYS_GENERATION

	/* Run the collected hash value through sha512. */
	sha512_block(w, total, H);

	compare_64(i, num_loaded_hashes, loaded_hashes, hash_id, H, bitmap);
    }
}
#undef		W_OFFSET

__kernel
void kernel_crypt_xsha(
	     __constant sha512_salt  * salt,
	     __global const uint32_t *       __restrict keys_buffer,
             __global const uint32_t * const __restrict index,
	     __global const uint32_t * const __restrict int_key_loc,
	     __global const uint32_t * const __restrict int_keys,
		      const uint32_t              candidates_number,
		      const uint32_t              num_loaded_hashes,
	     __global const uint64_t * const __restrict loaded_hashes,
    volatile __global       uint32_t * const __restrict hash_id,
    volatile __global       uint32_t * const __restrict bitmap) {

    //Compute buffers (on CPU and NVIDIA, better private)
    uint64_t		w[16];
    uint64_t		H[8];
    __local uint32_t	_ltotal[512];
    #define		total    _ltotal[get_local_id(0)]
    #define		W_OFFSET    4

    {
	//Get position and length of informed key.
	uint32_t base = index[get_global_id(0)];
	total = base & 63;

	//Ajust keys to it start position.
	keys_buffer += (base >> 6);
    }
    //Get salt information.
    w[0] = salt->salt;

    //Get password.
    _memcpy(((uint32_t *) w) + 1, keys_buffer, total);
    total += SALT_SIZE_X;

    //Prepare buffer.
    CLEAR_BUFFER_64_SINGLE(w, total);
    APPEND_SINGLE(w, 0x80UL, total);

    //Handle the candidates (candidates_number) to be produced.
    for (uint32_t i = 0; i < candidates_number; i++) {

	//Mask Mode: keys generation/finalization.
	MASK_KEYS_GENERATION

	/* Run the collected hash value through sha512. */
	sha512_block(w, total, H);

	compare_64(i, num_loaded_hashes, loaded_hashes, hash_id, H, bitmap);
    }
}

__kernel
void kernel_prepare(
		      const uint32_t                    num_loaded_hashes,
    volatile __global       uint32_t * const __restrict hash_id,
    volatile __global       uint32_t * const __restrict bitmap) {

    //Clean bitmap and result buffer
    if (get_global_id(0) == 0) {
	hash_id[0] = 0;

	for (uint32_t i = 0; i < (num_loaded_hashes - 1)/32 + 1; i++)
	    bitmap[i] = 0;
    }
}
