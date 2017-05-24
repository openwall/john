#ifndef GOST3411_2012_SSE41_H_
#define GOST3411_2012_SSE41_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined _MSC_VER
	#define ALIGN(x) __declspec(align(x))
#else
	#define ALIGN(x) __attribute__((__aligned__(x)))
#endif

union uint512_u {
	uint64_t QWORD[8];
} ALIGN(16);

ALIGN(16) typedef struct GOST34112012Context {
	ALIGN(16) unsigned char buffer[64];
	ALIGN(16) union uint512_u hash;
	ALIGN(16) union uint512_u h;
	ALIGN(16) union uint512_u N;
	ALIGN(16) union uint512_u Sigma;
	size_t bufsize;
	unsigned int digest_size;
} GOST34112012Context;

void GOST34112012Init(void *ctx, const unsigned int digest_size);
void GOST34112012Update(void *ctx, const unsigned char *data, size_t len);
void GOST34112012Final(void *ctx, unsigned char *digest);

#endif /* GOST3411_2012_SSE41_H_ */
