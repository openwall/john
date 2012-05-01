/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012   
 * Based on source code provided by Lukas Odzioba
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 * 
 * This software is:
 * Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * 
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 */

#ifndef _CRYPTSHA512_H 
#define _CRYPTSHA512_H

//Copied from common-opencl.h
#define UNKNOWN                 0
#define CPU                     1
#define GPU                     2
#define ACCELERATOR             4
#define AMD                     64
#define NVIDIA                  128
#define INTEL                   256
#define AMD_GCN                 1024
#define AMD_VLIW4               2048
#define AMD_VLIW5               4096
        
#define cpu(n)                  ((n & CPU) == (CPU))
#define gpu(n)                  ((n & GPU) == (GPU))
#define gpu_amd(n)              ((n & AMD) && gpu(n))
#define gpu_amd_64(n)           (0)
#define gpu_nvidia(n)           ((n & NVIDIA) && gpu(n))
#define gpu_intel(n)            ((n & INTEL) && gpu(n))
#define cpu_amd(n)              ((n & AMD) && cpu(n))
#define amd_gcn(n)              ((n & AMD_GCN) && gpu_amd(n))
#define amd_vliw4(n)            ((n & AMD_VLIW4) && gpu_amd(n))
#define amd_vliw5(n)            ((n & AMD_VLIW5) && gpu_amd(n))

//Type names definition. 
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long  //Tip: unsigned long long int failed on compile (AMD).

//Functions.
#define MAX(x,y)                ((x) > (y) ? (x) : (y))
#define MIN(x,y)                ((x) < (y) ? (x) : (y))

//Constants.
#define ROUNDS_DEFAULT          5000
#define ROUNDS_MIN              1000
#define ROUNDS_MAX              999999999

#define SALT_SIZE               16
#define PLAINTEXT_LENGTH        16
#define BINARY_SIZE             (3+16+86)       ///TODO: Magic number?
#define STEP	                512

#define KEYS_PER_CORE_CPU       128
#define KEYS_PER_CORE_GPU       512
#define MIN_KEYS_PER_CRYPT	128
#define MAX_KEYS_PER_CRYPT	2048*1024

//Macros.
#if gpu_amd_64(DEVICE_INFO)
	#pragma OPENCL EXTENSION cl_amd_media_ops : enable
	#define ror(x, n) 	amd_bitalign(x, x, (uint64_t) n)
	#define Ch(x, y, z) 	amd_bytealign(x, y, z)
	#define Maj(x, y, z) 	amd_bytealign(z ^ x, y, x )
#elif gpu_amd(DEVICE_INFO)
	#define Ch(x,y,z)	bitselect(z, y, x)
	#define Maj(x,y,z)      bitselect(x, y, z ^ x)
	#define ror(x, n) 	rotate(x, (uint64_t) 64-n)
#elif gpu_nvidia(DEVICE_INFO)
        #pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
#else
	#define Ch(x,y,z)	((x & y) ^ ( (~x) & z))
	#define Maj(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))
        #define ror(x, n)       ((x >> n) | (x << (64-n)))
#endif

#define Sigma0(x)               ((ror(x,28)) ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x)               ((ror(x,14)) ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x)               ((ror(x,1))  ^ (ror(x,8))  ^ (x>>7))
#define sigma1(x)               ((ror(x,19)) ^ (ror(x,61)) ^ (x>>6))

#define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))

//Data types.
typedef union {
    uint8_t             mem_08[8];
    uint16_t            mem_16[4];
    uint32_t            mem_32[2];
    uint64_t            mem_64[1];
} buffer_64;

typedef struct {
	uint32_t        rounds;
	uint32_t        length;
	uint8_t         salt[SALT_SIZE];
} crypt_sha512_salt;

typedef struct {
	uint32_t        length;
	uint8_t         pass[PLAINTEXT_LENGTH];
} crypt_sha512_password;

typedef struct {
	uint64_t        v[8];		//512 bits
} crypt_sha512_hash;

typedef struct {
	uint64_t        H[8];           //512 bits
	uint32_t        total;
	uint32_t        buflen;
	buffer_64       buffer[16];	//1024bits  
} sha512_ctx;

typedef struct {
        sha512_ctx              ctx_data;
        crypt_sha512_password   pass_data;
        buffer_64               alt_result[8];
        buffer_64               temp_result[8];
        buffer_64               p_sequence[8];
} working_memory;
#endif
