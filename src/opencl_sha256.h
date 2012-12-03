/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 *
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifndef OPENCL_SHA256_H
#define	OPENCL_SHA256_H

//Type names definition.
#define uint8_t  unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int
#define uint64_t unsigned long  //Tip: unsigned long long int failed on compile (AMD).

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

//Macros.
#define SWAP(n) \
            (((n) << 24)               | (((n) & 0xff00) << 8) |     \
            (((n) >> 8) & 0xff00)      | ((n) >> 24))

#define SWAP32_V(n)             SWAP(n)

#if gpu_amd(DEVICE_INFO)
        #define Ch(x, y, z)     bitselect(z, y, x)
        #define Maj(x, y, z)    bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (uint32_t) 32-n)
        #define SWAP32(n)       (as_uint(as_uchar4(n).s3210))
#else
        #if gpu_nvidia(DEVICE_INFO)
            #pragma OPENCL EXTENSION cl_nv_pragma_unroll : enable
        #endif
        #define Ch(x, y, z)     ((x & y) ^ ( (~x) & z))
        #define Maj(x, y, z)    ((x & y) ^ (x & z) ^ (y & z))
        #define ror(x, n)       ((x >> n) | (x << (32-n)))
        #define SWAP32(n)       SWAP(n)
#endif
#define Sigma0(x)               ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x)               ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x)               ((ror(x,7))  ^ (ror(x,18)) ^ (x>>3))
#define sigma1(x)               ((ror(x,17)) ^ (ror(x,19)) ^ (x>>10))

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) ((buf)[(index)])
#define ATTRIB(buf, index, val) (buf)[(index)] = val
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

/* Macro for get a multiple of a given value */
#define GET_MULTIPLE(dividend, divisor) ((unsigned int) ((dividend / divisor) * divisor))

//Process macros.
#define ROUND_0_TO_15(a,b,c,d,e,f,g,h,k,w,i)  \
        t1 = h + Sigma1(e) + Ch(e, f, g) + (k) + (w[i]); \
        d += t1; h = t1 + Maj(a, b, c) + Sigma0(a)

#define ROUND_16_TO_END(a,b,c,d,e,f,g,h,k,w,i) \
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15]; \
        t1 = h + Sigma1(e) + Ch(e, f, g) + (k) + (w[i & 15]); \
        d += t1; h = t1 + Maj(a, b, c) + Sigma0(a)

//SHA256 constants.
#define H0      0x6a09e667U
#define H1      0xbb67ae85U
#define H2      0x3c6ef372U
#define H3      0xa54ff53aU
#define H4      0x510e527fU
#define H5      0x9b05688cU
#define H6      0x1f83d9abU
#define H7      0x5be0cd19U

#define k01     0x428a2f98U
#define k02     0x71374491U
#define k03     0xb5c0fbcfU
#define k04     0xe9b5dba5U
#define k05     0x3956c25bU
#define k06     0x59f111f1U
#define k07     0x923f82a4U
#define k08     0xab1c5ed5U
#define k09     0xd807aa98U
#define k10     0x12835b01U
#define k11     0x243185beU
#define k12     0x550c7dc3U
#define k13     0x72be5d74U
#define k14     0x80deb1feU
#define k15     0x9bdc06a7U
#define k16     0xc19bf174U
#define k17     0xe49b69c1U
#define k18     0xefbe4786U
#define k19     0x0fc19dc6U
#define k20     0x240ca1ccU
#define k21     0x2de92c6fU
#define k22     0x4a7484aaU
#define k23     0x5cb0a9dcU
#define k24     0x76f988daU
#define k25     0x983e5152U
#define k26     0xa831c66dU
#define k27     0xb00327c8U
#define k28     0xbf597fc7U
#define k29     0xc6e00bf3U
#define k30     0xd5a79147U
#define k31     0x06ca6351U
#define k32     0x14292967U
#define k33     0x27b70a85U
#define k34     0x2e1b2138U
#define k35     0x4d2c6dfcU
#define k36     0x53380d13U
#define k37     0x650a7354U
#define k38     0x766a0abbU
#define k39     0x81c2c92eU
#define k40     0x92722c85U
#define k41     0xa2bfe8a1U
#define k42     0xa81a664bU
#define k43     0xc24b8b70U
#define k44     0xc76c51a3U
#define k45     0xd192e819U
#define k46     0xd6990624U
#define k47     0xf40e3585U
#define k48     0x106aa070U
#define k49     0x19a4c116U
#define k50     0x1e376c08U
#define k51     0x2748774cU
#define k52     0x34b0bcb5U
#define k53     0x391c0cb3U
#define k54     0x4ed8aa4aU
#define k55     0x5b9cca4fU
#define k56     0x682e6ff3U
#define k57     0x748f82eeU
#define k58     0x78a5636fU
#define k59     0x84c87814U
#define k60     0x8cc70208U
#define k61     0x90befffaU
#define k62     0xa4506cebU
#define k63     0xbef9a3f7U
#define k64     0xc67178f2U

#endif	/* OPENCL_SHA256_H */