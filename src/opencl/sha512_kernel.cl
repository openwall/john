/*
* This software is Copyright (c) 2012 Myrice <qqlddg at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

#ifdef cl_khr_byte_addressable_store
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable
#endif

#define uint8_t  unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long
#define SALT_SIZE 0

#define BINARY_SIZE 8
#define FULL_BINARY_SIZE 64


#define PLAINTEXT_LENGTH 20

#define CIPHERTEXT_LENGTH 128

#define KEYS_PER_CRYPT (1024*512)
#define ITERATIONS 1

#define MIN_KEYS_PER_CRYPT	(KEYS_PER_CRYPT)
#define MAX_KEYS_PER_CRYPT	(ITERATIONS*KEYS_PER_CRYPT)


/// Warning: This version of SWAP64(n) is slow and avoid bugs on AMD GPUs(7970)
#define SWAP64(n)       as_ulong(as_uchar8(n).s76543210) 

/*#define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))
   */



#define rol(x,n) ((x << n) | (x >> (64-n)))
#define ror(x,n) ((x >> n) | (x << (64-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))



typedef struct { // notice memory align problem
	uint64_t H[8];
	uint32_t buffer[32];	//1024 bits
	uint32_t buflen;
} sha512_ctx;

typedef struct {
    uint8_t length;
    char v[PLAINTEXT_LENGTH+1];
} sha512_key;


/* Macros for reading/writing chars from int32's */
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))


__constant uint64_t k[] = {
	0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
	    0xe9b5dba58189dbbcUL,
	0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL,
	    0xab1c5ed5da6d8118UL,
	0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL,
	    0x550c7dc3d5ffb4e2UL,
	0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
	    0xc19bf174cf692694UL,
	0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL,
	    0x240ca1cc77ac9c65UL,
	0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL,
	    0x76f988da831153b5UL,
	0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
	    0xbf597fc7beef0ee4UL,
	0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL,
	    0x142929670a0e6e70UL,
	0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL,
	    0x53380d139d95b3dfUL,
	0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
	    0x92722c851482353bUL,
	0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL,
	    0xc76c51a30654be30UL,
	0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL,
	    0x106aa07032bbd1b8UL,
	0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
	    0x34b0bcb5e19b48a8UL,
	0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL,
	    0x682e6ff3d6b2b8a3UL,
	0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL,
	    0x8cc702081a6439ecUL,
	0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
	    0xc67178f2e372532bUL,
	0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL,
	    0xf57d4f7fee6ed178UL,
	0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL,
	    0x1b710b35131c471bUL,
	0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
	    0x431d67c49c100d4cUL,
	0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL,
	    0x6c44198c4a475817UL,
};

inline void sha512(__global const char* password, uint8_t pass_len, 
	__global uint64_t* hash, uint32_t offset)
{
    __private sha512_ctx ctx;
	
	uint32_t* b32 = ctx.buffer;
	
	//set password to buffer
    for (uint32_t i = 0; i < pass_len; i++) {
		PUTCHAR(b32,i,password[i]);
	}
    ctx.buflen = pass_len;

	//append 1 to ctx buffer
	uint32_t length = ctx.buflen;
	PUTCHAR(b32, length, 0x80);
	while((++length & 3) != 0)  {
		PUTCHAR(b32, length, 0);
	}

	uint32_t* buffer32 = b32+(length>>2);
	for(uint32_t i = length; i < 128; i+=4) {// append 0 to 128
		*buffer32++=0;
	}

	//append length to buffer
	uint64_t *buffer64 = (uint64_t *)ctx.buffer;
	buffer64[15] = SWAP64((uint64_t) ctx.buflen * 8); 

	// sha512 main
	int i;
	
	uint64_t a = 0x6a09e667f3bcc908UL;
	uint64_t b = 0xbb67ae8584caa73bUL;
	uint64_t c = 0x3c6ef372fe94f82bUL;
	uint64_t d = 0xa54ff53a5f1d36f1UL;
	uint64_t e = 0x510e527fade682d1UL;
	uint64_t f = 0x9b05688c2b3e6c1fUL;
	uint64_t g = 0x1f83d9abfb41bd6bUL;
	uint64_t h = 0x5be0cd19137e2179UL;

	__private uint64_t w[16];

	uint64_t *data = (uint64_t *) ctx.buffer;

	#pragma unroll 16
	for (i = 0; i < 16; i++)
		w[i] = SWAP64(data[i]);

	uint64_t t1, t2;
	#pragma unroll 16
	for (i = 0; i < 16; i++) {
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
	
	#pragma unroll 61
	for (i = 16; i < 77; i++) {

		w[i & 15] =sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i -16) & 15] + w[(i - 7) & 15];
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
	hash[offset] = SWAP64(a);
}

__kernel void kernel_sha512(
	__global const sha512_key *password, 
	__global uint64_t *hash)
{

    uint32_t idx = get_global_id(0);
	for(uint32_t it = 0; it < ITERATIONS; ++it) {		
		uint32_t offset = idx+it*KEYS_PER_CRYPT;
    	sha512(password[offset].v, password[offset].length, 
			hash, offset);
	}
}

__kernel void kernel_cmp(
	__constant uint64_t* binary, 
	__global uint64_t *hash,
	__global uint32_t* result)
{
    uint32_t idx = get_global_id(0);
	if(idx == 0)
		*result = 0;
	
	for(uint32_t it = 0; it < ITERATIONS; ++it) {		
		uint32_t offset = idx+it*KEYS_PER_CRYPT;
			if (*binary == hash[offset])
				*result = 1;
	}
}


