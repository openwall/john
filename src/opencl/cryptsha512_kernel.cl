/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012   
 * Based on source code provided by Lukas Odzioba
 *
 * This software is:
 * Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * 
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 */

#include "opencl_cryptsha512.h"

__constant uint64_t k[] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
};

void init_ctx(__local sha512_ctx * ctx) {
    ctx->H[0] = 0x6a09e667f3bcc908UL;
    ctx->H[1] = 0xbb67ae8584caa73bUL;
    ctx->H[2] = 0x3c6ef372fe94f82bUL;
    ctx->H[3] = 0xa54ff53a5f1d36f1UL;
    ctx->H[4] = 0x510e527fade682d1UL;
    ctx->H[5] = 0x9b05688c2b3e6c1fUL;
    ctx->H[6] = 0x1f83d9abfb41bd6bUL;
    ctx->H[7] = 0x5be0cd19137e2179UL;
    ctx->total = 0;
    ctx->buflen = 0;
}

inline void memcpy_08(__local uint8_t * dest, __local const uint8_t * src, const size_t n) {
    for (int i = 0; i < n; i++)
        dest[i] = src[i];
}

inline void memcpy_64(__local uint8_t * dest, __local buffer_64 * src, const size_t n) {
    for (int i = 0; i < n; i++)
        dest[i] = src->mem_08[i];
}

void insert_to_buffer(__local sha512_ctx * ctx, 
                      __local const uint8_t * string,
                      const uint8_t len) {
    __local uint8_t *d;
    d = ctx->buffer->mem_08 + ctx->buflen;  //ctx->buffer[buflen] (in char size)

    memcpy_08(d, string, len);
    ctx->buflen += len;
}

void sha512_block(__local sha512_ctx * ctx) {
    uint64_t a = ctx->H[0];
    uint64_t b = ctx->H[1];
    uint64_t c = ctx->H[2];
    uint64_t d = ctx->H[3];
    uint64_t e = ctx->H[4];
    uint64_t f = ctx->H[5];
    uint64_t g = ctx->H[6];
    uint64_t h = ctx->H[7];

    uint64_t w[16];

    #pragma unroll 16
    for (int i = 0; i < 16; i++)
        w[i] = SWAP64(ctx->buffer->mem_64[i]);

    uint64_t t1, t2;
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
        t2 = Maj(a, b, c) + Sigma0(a);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    #pragma unroll 64
    for (int i = 16; i < 80; i++) {
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];
        t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
        t2 = Maj(a, b, c) + Sigma0(a);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    /* Put checksum in context given as argument. */
    ctx->H[0] += a;
    ctx->H[1] += b;
    ctx->H[2] += c;
    ctx->H[3] += d;
    ctx->H[4] += e;
    ctx->H[5] += f;
    ctx->H[6] += g;
    ctx->H[7] += h;
}

void ctx_append_1(__local sha512_ctx * ctx) {
    uint32_t length = ctx->buflen;
    int i = 127 - length;
    __local uint8_t *d = ctx->buffer->mem_08 + length;
    *d++ = 0x80;

    while (i--) {
        d[i] = 0;
    }
}

void ctx_add_length(__local sha512_ctx * ctx) {
    __local uint64_t *blocks = ctx->buffer->mem_64;
    blocks[15] = SWAP64((uint64_t) (ctx->total * 8));
}

void finish_ctx(__local sha512_ctx * ctx) {
    ctx_append_1(ctx);
    ctx_add_length(ctx);
    ctx->buflen = 0;
}

void ctx_update(__local sha512_ctx * ctx, __local uint8_t *string, uint8_t len) {

    ctx->total += len;
    uint8_t startpos = ctx->buflen;

    insert_to_buffer(ctx, string, (startpos + len <= 128 ? len : 128 - startpos));

    if (ctx->buflen == 128) {  //Branching.
        uint8_t offset = 128 - startpos;
        sha512_block(ctx);
        ctx->buflen = 0;
        insert_to_buffer(ctx, (string + offset), len - offset);
    }
}

void clear_ctx_buffer(__local sha512_ctx * ctx) {

    __local uint32_t *w = ctx->buffer->mem_32;

    #pragma unroll 32
    for (int i = 0; i < 32; i++)
        w[i] = 0;

    ctx->buflen = 0;
}

void sha512_digest(__local sha512_ctx * ctx, __local uint64_t * result) {

    if (ctx->buflen <= 111) { //data+0x80+datasize fits in one 1024bit block
        finish_ctx(ctx);

    } else {
        uint8_t moved = 1;

        if (ctx->buflen < 128) { //data and 0x80 fits in one block
            ctx_append_1(ctx);
            moved = 0;
        }
        sha512_block(ctx);
        clear_ctx_buffer(ctx);
        if (moved)
            ctx->buffer->mem_08[0] = 0x80; //append 1,the rest is already clean
        ctx_add_length(ctx);
    }
    sha512_block(ctx);

    #pragma unroll 8
    for (int i = 0; i < 8; i++)
        result[i] = SWAP64(ctx->H[i]);
}

void sha512crypt(__local working_memory * tmp_working,
                 __global crypt_sha512_hash * output) {

#define pass        tmp_working->pass_info.v
#define passlength  tmp_working->pass_info.length
#define salt        tmp_working->salt_info.salt
#define saltlen     tmp_working->salt_info.saltlen
#define rounds      tmp_working->salt_info.rounds
#define alt_result  tmp_working->alt_result
#define temp_result tmp_working->temp_result
#define s_sequence  tmp_working->s_sequence
#define p_sequence  tmp_working->p_sequence
#define ctx         tmp_working->ctx_info

    init_ctx(&ctx);

    ctx_update(&ctx, pass, passlength);
    ctx_update(&ctx, salt, saltlen);
    ctx_update(&ctx, pass, passlength);

    sha512_digest(&ctx, alt_result->mem_64);
    init_ctx(&ctx);

    ctx_update(&ctx, pass, passlength);
    ctx_update(&ctx, salt, saltlen);
    ctx_update(&ctx, alt_result->mem_08, passlength);

    for (int i = passlength; i > 0; i >>= 1) {
        ctx_update(&ctx, ((i & 1) != 0 ? alt_result->mem_08 : pass),
                         ((i & 1) != 0 ? 64 :                 passlength));
    }
    sha512_digest(&ctx, alt_result->mem_64);
    init_ctx(&ctx);

    for (int i = 0; i < passlength; i++)
        ctx_update(&ctx, pass, passlength);

    sha512_digest(&ctx, temp_result->mem_64);
    memcpy_64(p_sequence, temp_result, passlength);

    init_ctx(&ctx);
    
    /* For every character in the password add the entire password.  */
    for (int i = 0; i < 16 + (alt_result->mem_08)[0]; i++)
        ctx_update(&ctx, salt, saltlen);

    /* Finish the digest.  */
    sha512_digest(&ctx, temp_result->mem_64);
    memcpy_64(s_sequence, temp_result, saltlen);

    /* Repeatedly run the collected hash value through SHA512 to
       burn CPU cycles.  */
    for (int i = 0; i < rounds; i++) {
        init_ctx(&ctx);

        ctx_update(&ctx, ((i & 1) != 0 ? p_sequence : alt_result->mem_08),
                         ((i & 1) != 0 ? passlength : 64)); 

        if ((i % 3) != 0)
            ctx_update(&ctx, s_sequence, saltlen);

        if ((i % 7) != 0)
            ctx_update(&ctx, p_sequence, passlength);

        ctx_update(&ctx, ((i & 1) != 0 ? alt_result->mem_08 : p_sequence),
                         ((i & 1) != 0 ? 64 :                 passlength));
        sha512_digest(&ctx, alt_result->mem_64);
    }
    //Send results to the host.
    #pragma unroll 8
    for (int i = 0; i < 8; i++)
        output->v[i] = alt_result[i].mem_64[0];  
}
#undef salt       
#undef saltlen    
#undef rounds   

__kernel void kernel_crypt(__constant crypt_sha512_salt * hsalt,
                           __global   crypt_sha512_password * inbuffer,
                           __global   crypt_sha512_hash * outbuffer,
                           __local    working_memory * tmp_memory) {

    //Get the task to be done
    uint32_t gid = get_global_id(0);
    uint32_t lid = get_local_id(0);

    //Transfer data to faster memory
    //Password information
    tmp_memory[lid].pass_info.length = inbuffer[gid].length;

    #pragma unroll PLAINTEXT_LENGTH
    for (int i = 0; i < PLAINTEXT_LENGTH; i++)
        tmp_memory[lid].pass_info.v[i] = inbuffer[gid].v[i]; 
 
    //Salt information. 
    tmp_memory[lid].salt_info.saltlen = hsalt->saltlen;  
    tmp_memory[lid].salt_info.rounds = hsalt->rounds;

    #pragma unroll SALT_SIZE
    for (int i = 0; i < SALT_SIZE; i++)
	tmp_memory[lid].salt_info.salt[i] = hsalt->salt[i];

    //Do the job
    sha512crypt(&tmp_memory[lid], &outbuffer[gid]);
}

/***
*    To improve performance, it uses __local memory to keep working variables 
* (password, temp buffers, etc). In SHA 512 it means about 350 bytes per 
* "thread". It improves performance a lot, but, local memory is a scarce 
* resource. 
*    It means the max group size allowed in OpenCL SHA 512 is going to be 
* 128 (hardware depended).
*
* Gain   Optimizations
*  --    Basic version, private and global variables only.
*        Transfer all the working variables to local memory.
* -10%   Move salt to constant memory space. Keep others in local (saves memory).IGNORED.
*  25%   Unrool main loops.
*   5%   Unrool other loops.
* -INF   Do the compare task on GPU.
*
* Conclusions
* - Compare on GPU: CPU is more efficient for now.
* - Salt on constant memory is not good enought.
* - No register spilling happens after optimization.
***/
