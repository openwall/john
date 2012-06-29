/**
This file is shared by cuda-rawsha224 and cuda-rawsha256 formats
*/
#ifndef _SHA256_H
#define _SHA256_H

#ifndef uint32_t
  #define uint32_t unsigned int
#endif

#define rol(x,n) ((x << n) | (x >> (32-n)))
#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^(x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^(x>>10))

#define THREADS 128
#define BLOCKS 256
#define KEYS_PER_CRYPT THREADS*BLOCKS
typedef struct{
  uint32_t v[16];  				///512bits
}sha256_password;

typedef struct{
  uint32_t v[8]; 				///256bits
}sha256_hash;

typedef struct{
  uint32_t v[7]; 				///224bits
}sha224_hash;
#endif