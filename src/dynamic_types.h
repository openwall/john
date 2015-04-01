#if !defined (__Dynamic_Types__H__)
#define __Dynamic_Types__H__
/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic 'scriptable' hash cracker for JtR
 *
 * This is a 'private' include for dynamic. It is internal data structures
 * and defines.  It has been placed into a separate file, due to the huge
 * size of dynamic_fmt.c.  I am trying to split it up a bit, so that it
 * is not SOOOOO huge.
 */

typedef ARCH_WORD_32 MD5_word;

// NOTE, we will HAVE to increase this at some time.  sha512 has 128 byte hash all in itself. So you try
// to do sha512($s.sha512($p)), or even sha512(sha512($p)) we are blowing past our buffers, BAD

// Would LOVE to go to 128 bytes (would allow md5(md5($p).md5($p).md5($p).md5($p)) but
// due to other parts of john, we can only go to 128-3 as max sized plaintext.
#define PLAINTEXT_LENGTH_X86		124

// Allows us to work with up to 96 byte keys in the non-sse2 code

// this allows 2x sized buffers. 1x for pw and 1x for salt.  Was shown 'needed' by type 1014.
// NOTE, this was flushed out by the max password sized stuff in format self test code, but
// this IS the size needed to avoid overflows.  126 'would' be large enough. We go a bit over
// this.  NOTE, if we are using md5_go any more, we would need to expand this even more.
// Right now, we have type dynamic_107: WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p)) and
// dynamic_87: sha512(sha512($s).sha512($p)) which both require a 257 byte buffer.  We
// have only a 260 byte buffer, so it is barely large enough for those. This would be
// nowhere near large enough to use for md5_go code any more.
//
// reduced to exactly 256 bytes, and will be KEPT at that length. This will allow non-mmx to work up to
// dynamic_87/dynamic_107 length. Also, the original 'flat' buffers can be used for direct work, within
// the SHA2 SSE code (4x buffer size for sha256 and 2x buffer size for SHA512).
#define EX_BUF_LEN 132


typedef struct {
	union {
		double dummy;
		MD5_word w[16/sizeof(MD5_word)];
		char b[16];
		unsigned char B[16];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		MD5_word w2[16/sizeof(MD5_word)];
		char b2[16];
		unsigned char B2[16];
	}x2;
#endif
} MD5_OUT;

typedef struct {
	union {
		double dummy;
		MD5_word w[(PLAINTEXT_LENGTH_X86+EX_BUF_LEN)/sizeof(MD5_word)];
		char b[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
		unsigned char B[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		MD5_word w2[(PLAINTEXT_LENGTH_X86+EX_BUF_LEN)/sizeof(MD5_word)];
		char b2[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
		unsigned char B2[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
	}x2;
#endif
} MD5_IN;

typedef struct private_subformat_data
{
	// If compiled in SSE, AND the format allows SSE, then this will be set to 1.
	int dynamic_use_sse;
	int md5_startup_in_x86;

	// if the format is non-base16 (i.e. base-64), then this flag is set, and
	// a the hash loading function uses it.
	int dynamic_base64_inout;
	// if we want 'upper-case' in our base-16 conversions.
	int dynamic_base16_upcase;
	// if set, then we load keys directly into input1 and NOT into the saved_key buffers
	int store_keys_in_input;
	int input2_set_len32;
	int store_keys_in_input_unicode_convert;
	int store_keys_normal_but_precompute_md5_to_output2;
	int store_keys_normal_but_precompute_md5_to_output2_base16_to_input1;
	int store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32;
	int using_flat_buffers_sse2_ok;
	int dynamic_salt_as_hex;
	int force_md5_ctx;

	// This array is for the 2nd salt in the hash.  I know of no hashes with double salts,
	// but test type dynamic_16 (which is 'fake') has 2 salts, and this is the data/code to
	// handle double salts.
	int b2Salts;
	int nUserName;
	int nPassCase;
	unsigned FldMask;
	// if the external hash is sha1()  (such as sha1(md5($p)) then we want 40 byte input hashes.
	// We only 'use' 32 bytes of it to compare, but we should only run against 40byte hashes.
	int dynamic_40_byte_input;
	int dynamic_48_byte_input;
	int dynamic_56_byte_input;
	int dynamic_64_byte_input;
	int dynamic_80_byte_input;
	int dynamic_96_byte_input;
	int dynamic_128_byte_input;

	// Some formats have 'constants'.  A good example is the MD5 Post Office format dynamic_18
	// There can be 8 constants which can be put into the strings being built.  Most formats do
	// not have constants.
	unsigned char *Consts[8];
	int ConstsLen[8];
	int nConsts;

	char dynamic_WHICH_TYPE_SIG[40];
	// this 'will' be replaced, and will 'replace' FORMAT_NAME
	int init;
	int dynamic_FIXED_SALT_SIZE;
	int dynamic_SALT_OFFSET;
	int dynamic_HASH_OFFSET;
	DYNAMIC_primitive_funcp *dynamic_FUNCTIONS;
	DYNAMIC_Setup *pSetup;
	struct fmt_main *pFmtMain;
#ifdef _OPENMP
	int omp_granularity;
#endif
} private_subformat_data;

#define OMP_SCALE 1

#ifdef SIMD_COEF_32
# define MIN_KEYS_PER_CRYPT	1
# ifdef _OPENMP
// in openMP mode, we multiply everything by 24
// in openMP mode, we multiply everything by 48
// Now, we mult by 192x with OMP_SCALE=4
#  if SIMD_COEF_32 >= 4
#   define BLOCK_LOOPS		(1536*OMP_SCALE)
#   if !defined MD5_SSE_PARA || MD5_SSE_PARA==1
#    define BY_X			(1536*OMP_SCALE)
#   elif MD5_SSE_PARA==2
#    define BY_X			(768*OMP_SCALE)
#   elif MD5_SSE_PARA==3
#    define BY_X			(480*OMP_SCALE)
#   elif MD5_SSE_PARA==4
#    define BY_X			(384*OMP_SCALE)
#   elif MD5_SSE_PARA==5
#    define BY_X			(288*OMP_SCALE)
#   elif MD5_SSE_PARA==6
#    define BY_X			(240*OMP_SCALE)
#   endif
#  endif
#else
#  if SIMD_COEF_32 >= 4
#   define BLOCK_LOOPS		32
#   if !defined MD5_SSE_PARA || MD5_SSE_PARA==1
#    define BY_X			32
#   elif MD5_SSE_PARA==2
#    define BY_X			16
#   elif MD5_SSE_PARA==3
#    define BY_X			10
#   elif MD5_SSE_PARA==4
#    define BY_X			8
#   elif MD5_SSE_PARA==5
#    define BY_X			6
#   elif MD5_SSE_PARA==6
#    define BY_X			5
#   endif
# endif
# endif
# define LOOP_STR
# if SIMD_COEF_32 >= 4
#  ifdef MD5_SSE_PARA
#   define ALGORITHM_NAME		"128/128 " MD5_SSE_type  " " STRINGIZE(BY_X) "x4x" STRINGIZE(MD5_SSE_PARA)
#   define BSD_BLKS (MD5_SSE_PARA)
#  else
#   define ALGORITHM_NAME		"128/128 " MD5_SSE_type  " " STRINGIZE(BY_X) "x4"
#   define BSD_BLKS 1
#  endif
#  ifdef SHA1_SSE_PARA
#   define ALGORITHM_NAME_S		"128/128 " SHA1_SSE_type " " STRINGIZE(BY_X) "x4x" STRINGIZE(SHA1_SSE_PARA)
#  else
#   define ALGORITHM_NAME_S		"128/128 " SHA1_SSE_type " " STRINGIZE(BY_X) "x4"
#  endif
#  ifdef MD4_SSE_PARA
#   define ALGORITHM_NAME_4		"128/128 " MD4_SSE_type  " " STRINGIZE(BY_X) "x4x" STRINGIZE(MD4_SSE_PARA)
#  else
#   define ALGORITHM_NAME_4		"128/128 " MD4_SSE_type  " " STRINGIZE(BY_X) "x4"
#  endif
#  define PLAINTEXT_LENGTH	(27*3+1) // for worst-case UTF-8
#  ifdef MD5_SSE_PARA
// gives us 16 'loops' for para=2 and 10 loops for para==3 (or max of 128 for 2 and 120 for 3)
#   define MAX_KEYS_PER_CRYPT	(((SIMD_COEF_32*BLOCK_LOOPS)/(MD5_SSE_PARA*4))*(MD5_SSE_PARA*4))
#  else
#   define MAX_KEYS_PER_CRYPT	SIMD_COEF_32*BLOCK_LOOPS
#  endif
# endif
#else // !SIMD_COEF_32
# ifdef _OPENMP
#  define BLOCK_LOOPS			(6144*OMP_SCALE)
# else
#  define BLOCK_LOOPS			128
# endif
# define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " STRINGIZE(BLOCK_LOOPS) "x1"
# define ALGORITHM_NAME_S		"32/" ARCH_BITS_STR " " STRINGIZE(BLOCK_LOOPS) "x1"
# define ALGORITHM_NAME_4		"32/" ARCH_BITS_STR " " STRINGIZE(BLOCK_LOOPS) "x1"
#endif

#ifdef _OPENMP
# define X86_BLOCK_LOOPS			(6144*OMP_SCALE)
# define X86_BLOCK_LOOPSx2			(3072*OMP_SCALE)
#else
# define X86_BLOCK_LOOPS			128
# define X86_BLOCK_LOOPSx2			64
#endif

#define ALGORITHM_NAME_X86_S	ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1"
#define ALGORITHM_NAME_X86_4	ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1"

#define ALGORITHM_NAME_S2_256		"128/128 "CPU_NAME" 4x"
#define ALGORITHM_NAME_S2_512		"128/128 "CPU_NAME" 2x"
#if defined (COMMON_DIGEST_FOR_OPENSSL)
#define ALGORITHM_NAME_X86_S2_256	ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 CommonCrypto"
#define ALGORITHM_NAME_X86_S2_512	ARCH_BITS_STR"/64 "STRINGIZE(X86_BLOCK_LOOPS) "x1 CommonCrypto"
#elif defined (GENERIC_SHA2)
#define ALGORITHM_NAME_X86_S2_256	ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 sha2-generic"
#define ALGORITHM_NAME_X86_S2_512	ARCH_BITS_STR"/64 "STRINGIZE(X86_BLOCK_LOOPS) "x1 sha2-generic"
#else
#define ALGORITHM_NAME_X86_S2_256	ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 sha2-OpenSSL"
#define ALGORITHM_NAME_X86_S2_512	ARCH_BITS_STR"/64 "STRINGIZE(X86_BLOCK_LOOPS) "x1 sha2-OpenSSL"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000
#define ALGORITHM_NAME_WP2      ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 OpenSSL"
#define ALGORITHM_NAME_X86_WP2  ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 OpenSSL"
#else
#define ALGORITHM_NAME_WP2      ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 SPH_WP"
#define ALGORITHM_NAME_X86_WP2  ARCH_BITS_STR"/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 SPH_WP"
#endif

#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME_GST2     "64/64 "STRINGIZE(X86_BLOCK_LOOPS) "x1"
#define ALGORITHM_NAME_X86_GST2 "64/64 "STRINGIZE(X86_BLOCK_LOOPS) "x1"
#else
#define ALGORITHM_NAME_GST2     "32/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1"
#define ALGORITHM_NAME_X86_GST2 "32/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1"
#endif

#define ALGORITHM_NAME_TGR     "32/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 sph_tiger"
#define ALGORITHM_NAME_X86_TGR "32/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 sph_tiger"

#define ALGORITHM_NAME_RIPEMD     "32/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 sph_ripmd"
#define ALGORITHM_NAME_X86_RIPEMD "32/"ARCH_BITS_STR" "STRINGIZE(X86_BLOCK_LOOPS) "x1 sph_ripmd"

#ifdef USE_MD5_Go
#define MIN_KEYS_PER_CRYPT_X86	1
#define MAX_KEYS_PER_CRYPT_X86	X86_BLOCK_LOOPS
extern void MD5_Go2 (unsigned char *data, unsigned int len, unsigned char *result);
#if MD5_X2 && (!MD5_ASM)
#if defined(_OPENMP)
#define MD5_body(x0, x1, out0, out1) MD5_body_for_thread(0, x0, x1, out0, out1)
extern void MD5_body_for_thread(int t, MD5_word x[15], MD5_word x2[15], MD5_word out[4], MD5_word out2[4]);
#else
extern void MD5_body(MD5_word x[15], MD5_word x2[15], MD5_word out[4], MD5_word out2[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " " STRINGIZE(X86_BLOCK_LOOPSx2) "x2 (MD5_Body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L[0])<55&&(L[1])<55) {A.x1.b[L[0]]=0x80;A.x2.b2[L[1]]=0x80;A.x1.w[14]=(L[0]<<3);A.x2.w2[14]=(L[1]<<3);MD5_swap(A.x1.w,A.x1.w,(L[0]+4)>>2);MD5_swap(A.x2.w2,A.x2.w2,(L[1]+4)>>2);MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);MD5_swap2(C.x1.w,C.x2.w2,C.x1.w,C.x2.w2,4);} else {MD5_Go2(A.x1.B,L[0],C.x1.B); MD5_Go2(A.x2.B2,L[1],C.x2.B2);} }while(0)
#define DoMD5o(A,L,C) do{if((L[0])<55&&(L[1])<55) {MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);} else {MD5_Go2(A.x1.B,L[0],C.x1.B); MD5_Go2(A.x2.B2,L[1],C.x2.B2);} }while(0)
#if ARCH_LITTLE_ENDIAN
#define DoMD5a(A,L,C) MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2)
//#define DoMD5a2(A,L,C,D) MD5_body(A->x1.w,A->x2.w2, (ARCH_WORD_32*)D[0], (ARCH_WORD_32*)D[1])
#else
//static MD5_OUT tmpOut;
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2);MD5_swap2(C->x1.w,C->x2.w2,C->x1.w,C->x2.w2,4);}while(0)
//#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,A->x2.w2,tmpOut.x1.w,tmpOut.x2.w2);MD5_swap2(tmpOut.x1.w,tmpOut.x2.w2,tmpOut.x1.w,tmpOut.x2.w2,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);memcpy(&(C->x2.b2[D[1]]),tmpOut.x2.b2,16);}while(0)
#endif
#else
#if defined(_OPENMP) && !MD5_ASM
#define MD5_body(x, out) MD5_body_for_thread(0, x, out)
extern void MD5_body_for_thread(int t, ARCH_WORD_32 x[15], ARCH_WORD_32 out[4]);
#else
extern void MD5_body(ARCH_WORD_32 x[15], ARCH_WORD_32 out[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " " STRINGIZE(X86_BLOCK_LOOPS) "x1 (MD5_Body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L)<55) {A.x1.b[L]=0x80;A.x1.w[14]=(L<<3);MD5_swap(A.x1.w,A.x1.w,((L+4)>>2));MD5_body(A.x1.w,C.x1.w);MD5_swap(C.x1.w,C.x1.w,4);} else MD5_Go2(A.x1.B,L,C.x1.B); }while(0)
#define DoMD5o(A,L,C) do{if((L)<55) {MD5_body(A.x1.w,C.x1.w);} else MD5_Go2(A.x1.B,L,C.x1.B); }while(0)
#if ARCH_LITTLE_ENDIAN
#define DoMD5a(A,L,C) MD5_body(A->x1.w,C->x1.w)
//#define DoMD5a2(A,L,C,D) MD5_body(A->x1.w,(ARCH_WORD_32*)D)
#else
//static MD5_OUT tmpOut;
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,C->x1.w);MD5_swap(C->x1.w,C->x1.w,4);}while(0)
//#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,tmpOut.x1.w);MD5_swap(tmpOut.x1.w,tmpOut.x1.w,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);}while(0)
#endif
#endif
#else // !USE_MD5_Go
#ifndef SIMD_COEF_32
//static MD5_OUT tmpOut;
#endif
#define MIN_KEYS_PER_CRYPT_X86	1
#define MAX_KEYS_PER_CRYPT_X86	X86_BLOCK_LOOPS
#if MD5_X2 && (!MD5_ASM)
#if defined(_OPENMP)
#define MD5_body(x0, x1, out0, out1) MD5_body_for_thread(0, x0, x1, out0, out1)
extern void MD5_body_for_thread(int t, ARCH_WORD_32 x1[15], ARCH_WORD_32 x2[15], ARCH_WORD_32 out1[4], ARCH_WORD_32 out2[4]);
#else
extern void MD5_body(ARCH_WORD_32 x1[15], ARCH_WORD_32 x2[15], ARCH_WORD_32 out1[4], ARCH_WORD_32 out2[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " " STRINGIZE(X86_BLOCK_LOOPSx2) "x2 (MD5_body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L[0])<55&&(L[1])<55) {A.x1.b[L[0]]=0x80;A.x2.b2[L[1]]=0x80;A.x1.w[14]=(L[0]<<3);A.x2.w2[14]=(L[1]<<3);MD5_swap(A.x1.w,A.x1.w,(L[0]+4)>>2);MD5_swap(A.x2.w2,A.x2.w2,(L[1]+4)>>2);MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);MD5_swap2(C.x1.w,C.x2.w2,C.x1.w,C.x2.w2,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5o(A,L,C) do{if((L[0])<55&&(L[1])<55) {MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2);}while(0)
//#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,A->x2.w2,tmpOut.x1.w,tmpOut.x2.w2);MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);MD5_swap(C->x2.w2,C->x2.w2,(D[1]+21)>>2);MD5_swap(tmpOut.x1.w,tmpOut.x1.w,4);MD5_swap(tmpOut.x2.w2,tmpOut.x2.w2,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);memcpy(&(C->x2.b2[D[1]]),tmpOut.x2.b2,16);MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);MD5_swap(C->x2.w2,C->x2.w2,(D[1]+21)>>2);}while(0)
#else
#if defined(_OPENMP) && !MD5_ASM
#define MD5_body(x, out) MD5_body_for_thread(0, x, out)
extern void MD5_body_for_thread(int t, MD5_word x[15],MD5_word out[4]);
#else
extern void MD5_body(MD5_word x[15],MD5_word out[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " " STRINGIZE(X86_BLOCK_LOOPS) "x1 (MD5_body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L)<55) {A.x1.b[L]=0x80;A.x1.w[14]=(L<<3);MD5_swap(A.x1.w,A.x1.w,((L+4)>>2));MD5_body(A.x1.w,C.x1.w);MD5_swap(C.x1.w,C.x1.w,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L); MD5_Final((unsigned char *)(C.x1.b),&ctx); } }while(0)
#define DoMD5o(A,L,C) do{if((L)<55) {MD5_body(A.x1.w,C.x1.w);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L); MD5_Final((unsigned char *)(C.x1.b),&ctx); } }while(0)
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,C->x1.w);}while(0)
//#define DoMD5a2(A,L,C,D)  do{MD5_body(A->x1.w,tmpOut.x1.w); MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16); MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);}while(0)
#endif
#endif

// simple macro for now.  We can and will improve upon this later.
#if MD5_X2
#define DoMD4(A,L,C) do{ MD4_CTX ctx; MD4_Init(&ctx); MD4_Update(&ctx,A.x1.b,L[0]); MD4_Final(C.x1.B,&ctx); MD4_Init(&ctx); MD4_Update(&ctx,A.x2.b2,L[1]); MD4_Final(C.x2.B2,&ctx);}while(0)
#else
#define DoMD4(A,L,C) do{ MD4_CTX ctx; MD4_Init(&ctx); MD4_Update(&ctx,A.x1.b,L); MD4_Final(C.x1.B,&ctx);}while(0)
#endif


extern int large_hash_output(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int tid);
int large_hash_output_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int tid);

typedef enum { eUNK=0, eBase16=1, eBase16u=2, eBase64=3, eBase64_nte=4, eBaseRaw=5} eLargeOut_t;


#endif  // __Dynamic_Types__H__
