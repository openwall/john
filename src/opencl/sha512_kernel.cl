/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_rawsha512.h"

inline void _memcpy(               uint32_t * dest,
                    __global const uint32_t * src,
                             const uint32_t   len) {

    for (uint32_t i = 0; i < len; i += 4)
        *dest++ = *src++;
}

inline uint32_t sha512_block(uint64_t * buffer, int total) {
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

    #pragma unroll
    for (int i = 0; i < 15; i++)
        w[i] = SWAP64(buffer[i]);
    w[15] = (uint64_t) (total * 8);

    /* Do the job, up to 77 iterations. */
    SHA512_SHORT()

    /* Return partial hash value. */
    return d;
}

__kernel
void kernel_crypt_raw(__global   const uint32_t  * keys_buffer,
                      __global   const uint32_t  * index,
                      __global   uint32_t        * out_buffer) {

    //Compute buffers (on CPU and NVIDIA, better private)
    int		    total;
    uint64_t	    w[16];

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get position and length of informed key.
    uint32_t base = index[gid];
    total = base & 63;

    //Ajust keys to it start position.
    keys_buffer += (base >> 6);

    //Clear the buffer.
    w[0] = 0;
    w[1] = 0;
    w[2] = 0;
    w[3] = 0;
    w[4] = 0;
    w[5] = 0;
    w[6] = 0;
    w[7] = 0;
    w[8] = 0;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;

    //Get password.
    _memcpy((uint32_t *) w, keys_buffer, total);

    //Prepare buffer.
    APPEND_SINGLE(w, 0x80UL, total);
    CLEAR_BUFFER_64_SINGLE(w, total + 1);

    /* Run the collected hash value through SHA512. Return parcial results */
    out_buffer[gid] = sha512_block(w, total);
}

__kernel
void kernel_crypt_xsha(__constant sha512_salt     * salt,
                       __global   const uint32_t  * keys_buffer,
                       __global   const uint32_t  * index,
                       __global   uint32_t        * out_buffer) {

    //Compute buffers (on CPU and NVIDIA, better private)
    int		    total;
    uint64_t	    w[16];

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Get position and length of informed key.
    uint32_t base = index[gid];
    total = base & 63;

    //Ajust keys to it start position.
    keys_buffer += (base >> 6);

    //Clear the buffer.
    w[0] = 0;
    w[1] = 0;
    w[2] = 0;
    w[3] = 0;
    w[4] = 0;
    w[5] = 0;
    w[6] = 0;
    w[7] = 0;
    w[8] = 0;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;

    //Get salt information.
    w[0] = salt->salt;

    //Get password.
    _memcpy(((uint32_t *) w) + 1, keys_buffer, total);
    total += SALT_SIZE_X;

    //Prepare buffer.
    APPEND_SINGLE(w, 0x80UL, total);
    CLEAR_BUFFER_64_SINGLE(w, total + 1);

    /* Run the collected hash value through SHA512. Return parcial results */
    out_buffer[gid] = sha512_block(w, total);
}

__kernel
void kernel_cmp(__global   uint32_t        * partial_hash,
                __constant uint32_t        * partial_binary,
                __global   int             * result) {

    //Get the task to be done
    size_t gid = get_global_id(0);

    //Compare with partial computed hash.
    if (*partial_binary == partial_hash[gid]) {
        //Barrier point. FIX IT
        *result = 1;
    }
}
