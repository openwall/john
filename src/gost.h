/* gost.h */
#ifndef GOST_H
#define GOST_H

#include <stdint.h>
#include <stdlib.h>

#include "arch.h"
#include "johnswap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* if x86 compatible cpu */
	// NOTE, we should get this from johnswap.h, but I have not done so 'yet'
	// A lot (all??) of the swapping code should also come from johnswap.h
#if !defined (CPU_X64) && !defined (CPU_IA32)
#if defined(i386) || defined(__i386__) || defined(__i486__) || \
	defined(__i586__) || defined(__i686__) || defined(__pentium__) || \
	defined(__pentiumpro__) || defined(__pentium4__) || \
	defined(__nocona__) || defined(prescott) || defined(__core2__) || \
	defined(__k6__) || defined(__k8__) || defined(__athlon__) || \
	defined(__amd64) || defined(__amd64__) || \
	defined(__x86_64) || defined(__x86_64__) || defined(_M_IX86) || \
	defined(_M_AMD64) || defined(_M_IA64) || defined(_M_X64)
/* detect if x86-64 instruction set is supported */
 #if defined(_LP64) || defined(__LP64__) || defined(__x86_64) || \
	defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
  #define CPU_X64
 #else
  #define CPU_IA32
 #endif
#endif
#endif

#if defined(__GNUC__) && defined(CPU_IA32) && !defined(RHASH_NO_ASM)
 #define USE_GCC_ASM_IA32
#elif defined(__GNUC__) && defined(CPU_X64) && !defined(RHASH_NO_ASM)
 #define USE_GCC_ASM_X64
#endif

#define IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))
#define IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))

#if defined(_MSC_VER) || defined(__BORLANDC__)
#define I64(x) x##ui64
#else
#define I64(x) x##LL
#endif

/* convert a hash flag to index */
#if __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4) /* GCC < 3.4 */
 #define rhash_ctz(x) __builtin_ctz(x)
#else
unsigned rhash_ctz(unsigned); /* define as function */
#endif

void rhash_u32_swap_copy(void* to, int index, const void* from, size_t length);
void rhash_u64_swap_copy(void* to, int index, const void* from, size_t length);
void rhash_u32_memswap(unsigned *p, int length_in_u32);

#if !ARCH_LITTLE_ENDIAN
 #define be2me_32(x) (x)
 #define be2me_64(x) (x)
 #define le2me_32(x) JOHNSWAP(x)
 #define le2me_64(x) JOHNSWAP64(x)

 #define be32_copy(to, index, from, length) memcpy((to) + (index), (from), (length))
 #define le32_copy(to, index, from, length) rhash_u32_swap_copy((to), (index), (from), (length))
 #define be64_copy(to, index, from, length) memcpy((to) + (index), (from), (length))
 #define le64_copy(to, index, from, length) rhash_u64_swap_copy((to), (index), (from), (length))
#else /* !ARCH_LITTLE_ENDIAN */
 #define be2me_32(x) JOHNSWAP(x)
 #define be2me_64(x) JOHNSWAP64(x)
 #define le2me_32(x) (x)
 #define le2me_64(x) (x)

 #define be32_copy(to, index, from, length) rhash_u32_swap_copy((to), (index), (from), (length))
 #define le32_copy(to, index, from, length) memcpy((to) + (index), (from), (length))
 #define be64_copy(to, index, from, length) rhash_u64_swap_copy((to), (index), (from), (length))
 #define le64_copy(to, index, from, length) memcpy((to) + (index), (from), (length))
#endif /* !ARCH_LITTLE_ENDIAN */

/* ROTL/ROTR macros rotate a 32/64-bit word left/right by n bits */
#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))
#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define ROTR64(qword, n) ((qword) >> (n) ^ ((qword) << (64 - (n))))

#define gost_block_size 32
#define gost_hash_length 32

/* algorithm context */
typedef struct gost_ctx {
	unsigned hash[8];  /* algorithm 256-bit state */
	unsigned sum[8];   /* sum of processed message blocks */
	unsigned char message[gost_block_size]; /* 256-bit buffer for leftovers */
	uint64_t length;   /* number of processed bytes */
	unsigned cryptpro; /* boolean flag, the type of sbox to use */
} gost_ctx;

typedef struct gost_hmac_ctx {
	unsigned char ipad[32];
	unsigned char opad[32];
	gost_ctx ctx;
} gost_hmac_ctx;

/* hash functions */

void john_gost_init(gost_ctx *ctx);
void john_gost_cryptopro_init(gost_ctx *ctx);
void john_gost_update(gost_ctx *ctx, const unsigned char* msg, size_t size);
void john_gost_final(gost_ctx *ctx, unsigned char result[32]);

void john_gost_hmac_starts( gost_hmac_ctx *ctx, const unsigned char *key, size_t keylen );
void john_gost_hmac_update( gost_hmac_ctx *ctx, const unsigned char *input, size_t ilen );
void john_gost_hmac_finish( gost_hmac_ctx *ctx, unsigned char *output );
void john_gost_hmac( const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char *output );

void gost_init_table(void); /* initialize algorithm static data */

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* GOST_H */
