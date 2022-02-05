/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009-2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2009-2012 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic 'scriptable' hash cracker for JtR
 *
 * Preloaded types dynamic_0 to dynamic_999 are 'reserved' types.
 * They are loaded from this file. If someone tryes to build a 'custom'
 * type in their john.ini file using one of those, john will abort
 * the run.
 *
 * Renamed and changed from md5_gen* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 * Added SHA2 (SHA224, SHA256, SHA384, SHA512), GOST, Whirlpool crypt types.
 * Whirlpool use oSSSL if OPENSSL_VERSION_NUMBER >= 0x10000000, otherwise use sph_* code.
 */

#include <string.h>

#if AC_BUILT
#include "autoconfig.h"
#endif

#include "arch.h"

#if defined(SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	#undef SIMD_COEF_32
	#undef SIMD_COEF_64
	#undef SIMD_PARA_MD5
	#undef SIMD_PARA_MD4
	#undef SIMD_PARA_SHA1
	#undef SIMD_PARA_SHA256
	#undef SIMD_PARA_SHA512
	#define BITS ARCH_BITS_STR
#endif

#if !FAST_FORMATS_OMP
#ifdef _OPENMP
  #define FORCE_THREAD_MD5_body
#endif
#undef _OPENMP
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "dynamic.h"
#include "options.h"
#include "config.h"

#ifndef DYNAMIC_DISABLED

// This set of defines will turn on testing of the MAX_LENGTH hashes. Some of them can cause changes in
// the self test speeds. Thus, we can turn them on, to make sure that the formats ARE handling max length
// passwords properly, but then later compile differently and turn them off, so that the ST speeds are not
// shown slower than they were on prior builds.  To remove the max length tests from the self tests, simply
// comment out the #define TEST_MAX_LENGTH_DYNA line.

//#define TEST_MAX_LENGTH_DYNA
#ifdef TEST_MAX_LENGTH_DYNA
#define MTL(a,b,c) a,b,
#else
#define MTL(a,b,c)
#endif

//
// HERE is the 'official' list of dynamic_#) builtin's to John.
//
//dynamic_0 --> md5($p)
//dynamic_1 --> md5($p.$s)  (joomla)
//dynamic_2 --> md5(md5($p))
//dynamic_3 --> md5(md5(md5($p)))
//dynamic_4 --> md5($s.$p)  (osCommerce MD5 2 byte salt)
//dynamic_5 --> md5($s.$p.$s)
//dynamic_6 --> md5(md5($p).$s)
   // REMOVED! DEPRICATED  //dynamic_7 --> md5(md5($p).$s) vBulletin  (fixed 3 byte salt, colon not valid as field sep, since all chars from 0x20 to 0x7E are in the salt)
//dynamic_8 --> md5(md5($s).$p)
//dynamic_9 --> md5($s.md5($p))
//dynamic_10 --> md5($s.md5($s.$p))
//dynamic_11 --> md5($s.md5($p.$s))
//dynamic_12 --> md5(md5($s).md5($p)) (IPB)
//dynamic_13 --> md5(md5($p).md5($s)) (phpFox v3)
//dynamic_14 --> md5($s.md5($p).$s)
//dynamic_15 --> md5($u.md5($p).$s)
//dynamic_16 --> md5(md5(md5($p).$s).$s2)
//dynamic_17 --> phpass ($P$ or $H$)		// phpass OR phpbb (or WordPress, etc).  Should handle all conforming formats
//dynamic_18 --> md5($s.Y.$p.\xF7.$s)		//(Post.Office MD5) Does not workin SSE2, uses ONLY x86 md5 calls.
//dynamic_19 --> Cisco PIX (MD5)
//dynamic_20 --> Cisco ASA (MD5 salted)
//dynamic_21 --> HTTP Digest Access Auth
//dynamic_22 --> md5(sha1($p))
//dynamic_23 --> sha1(md5($p))             // requires a 40 byte hex hash
//dynamic_24 --> sha1($p.$s)               // requires a 40 byte hex hash
//dynamic_25 --> sha1($s.$p)               // requires a 40 byte hex hash
//dynamic_26 --> sha1($p)                  // MGF_RAW_SHA1_INPUT
 // REMOVED! DEPRICATED //dynamic_27 --> FreeBSD MD5
 // REMOVED! DEPRICATED //dynamic_28 --> Apache MD5
//dynamic_29 --> md5(utf16($p))			// raw-md5-unicode
//dynamic_30 --> md4($p)                    // raw-md4
//dynamic_31 --> md4($s.$p)
//dynamic_32 --> md4($p.$s)
//dynamic_33 --> md4(utf16($p))			// NT
//dynamic_34 --> md5(md4($p))
//dynamic_35 -->sha1(uc($u).:.$p) (ManGOS)
//dynamic_36 -->sha1($u.:.$p) (ManGOS2)
//dynamic_37 -->sha1(lc($u).$p) (SMF)
//dynamic_38 -->sha1($s.sha1($s.sha1($p))) (Wolt3BB)
//dynamic_39 -->md5($s.pad16($p))      (Net-md5 passed password, long salts)
//dynamic_40 -->sha1($s.pad20($p))     (Net-sha1 passed password, long salts)

	// Try to group sha224 here (from dyna-50 to dyna-59)
//dynamic_50 -->sha224($p)
//dynamic_51 -->sha224($s.$p)
//dynamic_52 -->sha224($p.$s)
//dynamic_53 -->sha224(sha224($p))
//dynamic_54 -->sha224(sha224_raw($p))
//dynamic_55 -->sha224(sha224($p).$s)
//dynamic_56 -->sha224($s.sha224($p))
//dynamic_57 -->sha224(sha224($s).sha224($p))
//dynamic_58 -->sha224(sha224($p).sha224($p))
	// Try to group sha256 here (from dyna-60 to dyna-69)
//dynamic_60 -->sha256($p)
//dynamic_61 -->sha256($s.$p)
//dynamic_62 -->sha256($p.$s)
//dynamic_63 -->sha256(sha256($p))
//dynamic_64 -->sha256(sha256_raw($p))
//dynamic_65 -->sha256(sha256($p).$s)
//dynamic_66 -->sha256($s.sha256($p))
//dynamic_67 -->sha256(sha256($s).sha256($p))
//dynamic_68 -->sha256(sha256($p).sha256($p))

  // All other LARGE hash types will have same elements as those listed above.  BUT we only include the hash($p) for documentation
//dynamic_70 -->sha384($p)
//dynamic_80 -->sha512($p)
//dynamic_90 -->GOST($p)
//dynamic_100 -->WHIRLPOOL($p)
//dynamic_110 -->Tiger($p)
//dynamic_120 -->RIPEMD128($p)
//dynamic_130 -->RIPEMD160($p)
//dynamic_140 -->RIPEMD256($p)
//dynamic_150 -->RIPEMD320($p)
//dynamic_160 -->HAVAL128_3($p)
//dynamic_170 -->HAVAL128_4($p)
//dynamic_180 -->HAVAL128_5($p)
//dynamic_190 -->HAVAL160_3($p)
//dynamic_200 -->HAVAL160_4($p)
//dynamic_210 -->HAVAL160_5($p)
//dynamic_220 -->HAVAL192_3($p)
//dynamic_230 -->HAVAL192_4($p)
//dynamic_240 -->HAVAL192_5($p)
//dynamic_250 -->HAVAL224_3($p)
//dynamic_260 -->HAVAL224_4($p)
//dynamic_270 -->HAVAL224_5($p)
//dynamic_280 -->HAVAL256_3($p)
//dynamic_290 -->HAVAL256_4($p)
//dynamic_300 -->HAVAL256_5($p)
//dynamic_310 -->MD2($p)
//dynamic_320 -->PANAMA($p)
//dynamic_330 -->SKEIN224($p)
//dynamic_340 -->SKEIN256($p)
//dynamic_350 -->SKEIN384($p)
//dynamic_360 -->SKEIN512($p)
//dynamic_370 -->SHA3_224($p)
//dynamic_380 -->SHA3_256($p)
//dynamic_390 -->SHA3_384($p)
//dynamic_400 -->SHA3_512($p)
//dynamic_410 -->KECCAK_256($p)
//dynamic_420 -->KECCAK_512($p)
//dynamic_430 -->KECCAK_224($p)
//dynamic_440 -->KECCAK_384($p)
// LARGE_HASH_EDIT_POINT

#define DYNA_PRE_DEFINE_LARGE_HASH(H,N,HS) \
	static DYNAMIC_primitive_funcp _Funcs_##N##0[] = { DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##1[] = { DynamicFunc__clean_input, DynamicFunc__append_salt, DynamicFunc__append_keys, DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##2[] = { DynamicFunc__clean_input, DynamicFunc__append_keys, DynamicFunc__append_salt, DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##3[] = { DynamicFunc__##H##_crypt_input1_overwrite_input2, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##4[] = { DynamicFunc__LargeHash_OUTMode_raw, DynamicFunc__##H##_crypt_input1_overwrite_input2, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##5[] = { DynamicFunc__set_input_len_##HS , DynamicFunc__append_salt, DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##6[] = { DynamicFunc__clean_input2, DynamicFunc__append_salt2, DynamicFunc__append_input2_from_input, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##7[] = { DynamicFunc__clean_input2_kwik, DynamicFunc__append_salt2, DynamicFunc__append_input2_from_input, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##8[] = { DynamicFunc__clean_input2_kwik, DynamicFunc__##H##_crypt_input1_append_input2, DynamicFunc__append_input2_from_input2, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL };

#define DYNA_PRE_DEFINE_LARGE_HASH_SKIP_78(H,N,HS) \
	static DYNAMIC_primitive_funcp _Funcs_##N##0[] = { DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##1[] = { DynamicFunc__clean_input, DynamicFunc__append_salt, DynamicFunc__append_keys, DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##2[] = { DynamicFunc__clean_input, DynamicFunc__append_keys, DynamicFunc__append_salt, DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##3[] = { DynamicFunc__##H##_crypt_input1_overwrite_input2, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##4[] = { DynamicFunc__LargeHash_OUTMode_raw, DynamicFunc__##H##_crypt_input1_overwrite_input2, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##5[] = { DynamicFunc__set_input_len_##HS , DynamicFunc__append_salt, DynamicFunc__##H##_crypt_input1_to_output1_FINAL, NULL }; \
	static DYNAMIC_primitive_funcp _Funcs_##N##6[] = { DynamicFunc__clean_input2, DynamicFunc__append_salt2, DynamicFunc__append_input2_from_input, DynamicFunc__##H##_crypt_input2_to_output1_FINAL, NULL };

static DYNAMIC_primitive_funcp _Funcs_0[] =
{
	//MGF_KEYS_INPUT
	//MGF_SOURCE (v9 format+)
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_0[] =
{
	{"$dynamic_0$5a105e8b9d40e1329780d62ea2265d8a","test1"},
	{"$dynamic_0$098f6bcd4621d373cade4e832627b4f6","test"},
	{"$dynamic_0$378e2c4a07968da2eca692320136433d","thatsworking"},
	{"$dynamic_0$8ad8757baa8564dc136c1e07507f4a98","test3"},
	// These next 2 do slow down self tests, so (by as much as 20%), so they are commented out, but can be uncommented
	// to validate that these max length hashes DO not cause the format to fail to work.  They MUST be able to be
	// successfully processed with no errors.  But can be commented out later, to keep same test speeds.
	// to turn on these 'max length' tests, just rebuild with -DDEBUG
#ifdef DEBUG
	{"$dynamic_0$c9ccf168914a1bcfc3229f1948e67da0","1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_0$57edf4a22be3c955ac49da2e2107b67a","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};

// dynamic_1  Joomla md5($p.$s)
static DYNAMIC_primitive_funcp _Funcs_1[] =
{
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_1[] =
{
	{"$dynamic_1$ed52af63d8ecf0c682442dfef5f36391$1aDNNojYGSc7pSzcdxKxhbqvLtEe4deG","test1"},
	{"$dynamic_1$4fa1e9d54d89bfbe48b4c0f0ca0a3756$laxcaXPjgcdKdKEbkX1SIjHKm0gfYt1c","thatsworking"},
	{"$dynamic_1$82568eeaa1fcf299662ccd59d8a12f54$BdWwFsbGtXPGc0H1TBxCrn0GasyAlJBJ","test3"},
#ifdef DEBUG
	// commented out to keep speed test 'same'.  Uncomment to make sure max lengths work, then recomment back in.
	{"$dynamic_1$ff979803ae8048aced292752c8c2cb03$12345678901234567890123456789012", "12345678901234567890123"},
  #ifndef SIMD_COEF_32
	{"$dynamic_1$2554e084ca33c249ae7105c6482dda60$12345678901234567890123456789012", "123456789012345678901234567890123456789012345678"},
  #endif
#endif
	{NULL}
};


// dynamic_2  md5(md5($p))
static DYNAMIC_primitive_funcp _Funcs_2[] =
{
	//MGF_KEYS_INPUT
	//MGF_SET_INP2LEN32
	DynamicFunc__crypt_md5,
	DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix,
#if !ARCH_LITTLE_ENDIAN
	// Not sure WHY this is needed in BE systems, BUT it is???
	// it does do a memset on last part of buffer, but 'why' is that needed???
	// we should have a fixed length of 32 bytes set, so not sure why we need
	// to continue to clear on these formats.
	DynamicFunc__set_input2_len_32_cleartop,
#endif

	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_2[] =
{
	{"$dynamic_2$418d89a45edadb8ce4da17e07f72536c","test1"},
	{"$dynamic_2$ccd3c4231a072b5e13856a2059d04fad","thatsworking"},
	{"$dynamic_2$9992295627e7e7162bdf77f14734acf8","test3"},
	{"$dynamic_2$74be16979710d4c4e7c6647856088456",""},
#ifdef DEBUG
	{"$dynamic_2$4da0b552b078998f671795b925aed4ae","1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_2$c2c683fad194ae92af02c98519b24e9f","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};
// dynamic_3  md5(md5(md5($p)))
static DYNAMIC_primitive_funcp _Funcs_3[] =
{
	//MGF_KEYS_INPUT
	//MGF_SET_INP2LEN32
	DynamicFunc__crypt_md5,
	DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix,
#if !ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input2_len_32_cleartop,
#endif
	DynamicFunc__crypt2_md5,
	DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix,
#if !ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input2_len_32_cleartop,
#endif
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_3[] =
{
	{"$dynamic_3$964c02612b2a1013ed26d46ba9a73e74","test1"},
	{"$dynamic_3$5d7e6330f69548797c07d97c915690fe","thatsworking"},
	{"$dynamic_3$2e54db8c72b312007f3f228d9d4dd34d","test3"},
#ifdef DEBUG
	{"$dynamic_3$7f1e5f4cace82433c8d63a19e1b2c413","1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_3$6129e5eb9f595f8661b889d6d95085e5","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};

//dynamic_4 --> md5($s.$p)
static DYNAMIC_primitive_funcp _Funcs_4[] =
{
	//MGF_SALTED
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_4[] =
{
	{"$dynamic_4$c02e8eef3eaa1a813c2ff87c1780f9ed$123456","test1"},
	{"$dynamic_4$4a2a1b013da3cda7f7e0625cf3dc3f4c$1234","thatsworking"},
	{"$dynamic_4$3a032e36a9609df6411b8004070431d3$aaaaa","test3"},
#ifdef DEBUG
	{"$dynamic_4$2cec94d4cfdbd3494174e0dc6c089690$123456789012345678901234","1234567890123456789012345678901"},
  #ifndef SIMD_COEF_32
	{"$dynamic_4$43801689631a0113fcb5d3cfaad0431f$123456789012345678901234","12345678901234567890123456789012345678901234567890123456"},
  #endif
#endif
	{NULL}
};

//dynamic_5 --> md5($s.$p.$s)
static DYNAMIC_primitive_funcp _Funcs_5[] =
{
	//MGF_SALTED
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_5[] =
{
	{"$dynamic_5$c1003cd39cb5523dd0923a94ab15a3c7$123456","test1"},
	{"$dynamic_5$c1c8618abfc7bdbc4a3c49c2c2c48f82$1234","thatsworking"},
	{"$dynamic_5$e7222e806a8ce5efa6d48acb3aa56dc2$aaaaa","test3"},
#ifdef DEBUG
	{"$dynamic_5$6a322a856f03abd780a9c6766a03eb79$123456789012","1234567890123456789012345678901"},
  #ifndef SIMD_COEF_32
	{"$dynamic_5$10c50d85674ff20ca34f582894bc688d$123456789012","12345678901234567890123456789012345678901234567890123456"},
  #endif
#endif
	{NULL}
};

//dynamic_6 --> md5(md5($p).$s)
static DYNAMIC_primitive_funcp _Funcs_6[] =
{
	//MGF_KEYS_BASE16_IN1_MD5
#if ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input_len_32_cleartop,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
#else
	DynamicFunc__clean_input2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__crypt_md5_in2_to_out1,
#endif
	NULL
};
static struct fmt_tests _Preloads_6[] =
{
	{"$dynamic_6$3a9ae23758f05da1fe539e55a096b03b$S111XB","test1"},
	{"$dynamic_6$9694d706d1992abf04344c1e7da1c5d3$T &222","thatsworking"},
	{"$dynamic_6$b7a7f0c374d73fac422bb01f07f5a9d4$lxxxl","test3"},
	{"$dynamic_6$9164fe53be481f811f15efd769aaf0f7$aReallyLongSaltHere","test3"},
#ifdef DEBUG
	{"$dynamic_6$22fb37a13d47d420b73cb89773764be2$12345678901234567890123", "1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_6$2099aa2c138eb97713e790b6c49012e5$12345678901234567890123", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};

#if 0
//dynamic_7 --> md5(md5($p).$s) vBulletin  (forced 3 byte salt, valid chars from 0x20 to 0x7E)
static DYNAMIC_primitive_funcp _Funcs_7[] =
{
	//MGF_KEYS_BASE16_IN1_MD5
#if ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input_len_32_cleartop,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
#else
	DynamicFunc__clean_input2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
#endif
};
static struct fmt_tests _Preloads_7[] =
{
	{"$dynamic_7$daa61d77e218e42060c2fa198ac1feaf$SXB","test1"},
	{"$dynamic_7$de56b00bb15d6db79204bd44383469bc$T &","thatsworking"},
	{"$dynamic_7$fb685c6f469f6e549c85e4c1fb5a65a6$\\H:","test3"},
	{NULL}
};
#endif

//dynamic_8 --> md5(md5($s).$p)
static DYNAMIC_primitive_funcp _Funcs_8[] =
{
	//MGF_SALT_AS_HEX
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_8[] =
{
	{"$dynamic_8$534c2fb38e757d9448315abb9822db00$aaaSXB","test1"},
	{"$dynamic_8$02547864bed278658e8f54dd6dfd69b7$123456","thatsworking"},
	{"$dynamic_8$2f6f3881972653ebcf86e5ad3071a4ca$5555hh","test3"},
#ifdef DEBUG
	{"$dynamic_8$23f865a14edba990cd1bff1f113fd0a0$12345678901234567890123456789012", "12345678901234567890123"},
  #ifndef SIMD_COEF_32
	{"$dynamic_8$a5c3893a720936da50edad336ea14f46$12345678901234567890123456789012", "123456789012345678901234567890123456789012345678"},
  #endif
#endif
	{NULL}
};

//dynamic_9 --> md5($s.md5($p))
static DYNAMIC_primitive_funcp _Funcs_9[] =
{
#if defined (SIMD_COEF_32)
	//MGF_KEYS_CRYPT_IN2
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_from_last_output2_to_input1_as_base16,
	DynamicFunc__crypt_md5,
	NULL
#else
	//MGF_KEYS_BASE16_IN1_MD5
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
#endif
};
static struct fmt_tests _Preloads_9[] =
{
	{"$dynamic_9$b38c18b5e5b676e211442bd41000b2ec$aaaSXB","test1"},
	{"$dynamic_9$4dde7cd4cbf0dc4c59b255ae77352914$123456","thatsworking"},
	{"$dynamic_9$899af20e3ebdd77aaecb0d9bc5fbbb66$5555hh","test3"},
#ifdef DEBUG
	{"$dynamic_9$1d01316a7bc597a5b2743f2da41b10ef$12345678901234567890123", "1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_9$299d55d735d64bb70f517312a2a62946$12345678901234567890123", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};

//dynamic_10 --> md5($s.md5($s.$p))
static DYNAMIC_primitive_funcp _Funcs_10[] =
{
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md5,
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_10[] =
{
	{"$dynamic_10$781f83a676f45169dcfc7f36dfcdc3d5$aaaSXB","test1"},
	{"$dynamic_10$f385748e67a2dc1f6379b9124fabc0df$123456","thatsworking"},
	{"$dynamic_10$9e3702bb13386270cd4b0bd4dbdd489e$5555hh","test3"},
#ifdef DEBUG
	{"$dynamic_10$b40b30cba281d45c54c12b1b54c6b278$12345678901234567890123", "12345678901234567890123456789012"},
  #ifndef SIMD_COEF_32
	{"$dynamic_10$0d6e0b9feace8cd90de6e2e683eba981$12345678901234567890123", "123456789012345678901234567890123456789012345678901234567"},
  #endif
#endif
	{NULL}
};

//dynamic_11 --> md5($s.md5($p.$s))
static DYNAMIC_primitive_funcp _Funcs_11[] =
{
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_11[] =
{
	{"$dynamic_11$f809a64cbd0d23e099cd5b544c8501ac$aaaSXB","test1"},
	{"$dynamic_11$979e6671535cda6db95357d8a0afd9ac$123456","thatsworking"},
	{"$dynamic_11$78a61ea73806ebf27bef2ab6a9bf5412$5555hh","test3"},
#ifdef DEBUG
	{"$dynamic_11$e2e915bd2946037165f4000b0b38aaa9$12345678901234567890123", "12345678901234567890123456789012"},
  #ifndef SIMD_COEF_32
	{"$dynamic_11$b2b3fe7e67e191782faa16d8440c1a26$12345678901234567890123", "123456789012345678901234567890123456789012345678901234567"},
  #endif
#endif
	{NULL}
};

//dynamic_12 --> md5(md5($s).md5($p))
static DYNAMIC_primitive_funcp _Funcs_12[] =
{
	//MGF_SALTED
	//MGF_SALT_AS_HEX
	//MGF_FLAT_BUFFERS  MUCH faster using flat buffers
	//MGF_KEYS_BASE16_IN1_Offset_MD5
	DynamicFunc__overwrite_salt_to_input1_no_size_fix,
	DynamicFunc__set_input_len_64,
	DynamicFunc__MD5_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_12[] =
{
	{"$dynamic_12$fbbd9532460f2d03fa8af9e75c41eefc$aaaSXB","test1"},
	{"$dynamic_12$b80eef24d1d01b61b3beff38559f9d26$123456","thatsworking"},
	{"$dynamic_12$1e5489bdca008aeed6e390ee87ce9b92$5555hh","test3"},
	{"$dynamic_12$6b9b2abc2e1c25f2eee6b771072da26c$12345678901234567890123456789012", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	{NULL}
};

//dynamic_13 --> md5(md5($p).md5($s))
static DYNAMIC_primitive_funcp _Funcs_13[] =
{
	//MGF_KEYS_BASE16_IN1_MD5
	//MGF_SALT_AS_HEX
	//MGF_FLAT_BUFFERS   MUCH faster using flat buffers
	DynamicFunc__set_input_len_32,
	DynamicFunc__append_salt,
	DynamicFunc__MD5_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_13[] =
{
	{"$dynamic_13$c6b69bec81d9ff5d0560d8f469a8efd5$aaaSXB","test1"},
	{"$dynamic_13$7abf788b3abbfc8719d900af96a3763a$123456","thatsworking"},
	{"$dynamic_13$1c55e15102ed17eabe5bf11271c7fcae$5555hh","test3"},
	{"$dynamic_13$543a505f7e8c9cdfb32743f91d904837$12345678901234567890123456789012", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},
	{NULL}
};

//dynamic_14 --> md5($s.md5($p).$s)
static DYNAMIC_primitive_funcp _Funcs_14[] =
{
#if defined (SIMD_COEF_32)
	//MGF_KEYS_CRYPT_IN2
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_from_last_output2_to_input1_as_base16,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
#else
	//MGF_KEYS_BASE16_IN1_MD5
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
#endif
};
static struct fmt_tests _Preloads_14[] =
{
	{"$dynamic_14$778e40e10d82a08f5377992330008cbe$aaaSXB","test1"},
	{"$dynamic_14$d6321956964b2d27768df71d139eabd2$123456","thatsworking"},
	{"$dynamic_14$1b3c72e16427a2f4f0819243877f7967$5555hh","test3"},
#ifdef DEBUG
	{"$dynamic_14$6aaa97fcf40c519006926520af3264fd$12345678901", "1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_14$abdb659cdc44d5fde6b238f7013f71dc$12345678901", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};

//dynamic_15 --> md5($u.md5($p).$s)
static DYNAMIC_primitive_funcp _Funcs_15[] =
{
	// MGF_SALTED|MGF_USERNAME|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_MD5
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__append_userid2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__MD5_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_15[] =
{
	{"$dynamic_15$6093d5cb3e2f99d9110eb9c4bbca5f8c$aaaSXB$$Ujoeblow","test1"},
	{"$dynamic_15$6a2dc4a6637bc5c2488f27faeead8720$123456$$Uadmin","thatsworking"},
	{"$dynamic_15$63aea4b8fe491df8545cc0099ac668d4$5555hh$$Uralph","test3"},

	// to test 'like' we would see from an 'input file' where user name would be first field
	{"$dynamic_15$6093d5cb3e2f99d9110eb9c4bbca5f8c$aaaSXB","test1",        {"joeblow"} },
	{"$dynamic_15$6a2dc4a6637bc5c2488f27faeead8720$123456","thatsworking", {"admin"} },
	{"$dynamic_15$63aea4b8fe491df8545cc0099ac668d4$5555hh","test3",        {"ralph"} },
	// at least one hash exactly like it gets stored in john.pot
	{"$dynamic_15$6093d5cb3e2f99d9110eb9c4bbca5f8c$HEX$6161615358422424556a6f65626c6f77","test1"},
#ifdef DEBUG
	{"$dynamic_15$a2609e968a7124a8ac299c5f03341b85$123456789012$$Ubarney", "1234567890123456789012345678901234567890123456789012345"},
  #ifndef SIMD_COEF_32
	{"$dynamic_15$230942ea4c6f83d50ce2498cae73a83c$123456789012$$Uripper", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
  #endif
#endif
	{NULL}
};

//dynamic_16 --> md5(md5(md5($p).$s).$s2)
static DYNAMIC_primitive_funcp _Funcs_16[] =
{
	// MGF_SALTED|MGF_SALTED2|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_MD5
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__MD5_crypt_input2_overwrite_input2,
	DynamicFunc__append_2nd_salt2,
	DynamicFunc__MD5_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_16[] =
{
	// NOTE the $ is the byte starting the salt block, and the $$2 is the
	// pattern showing where to 'split off' the
	{"$dynamic_16$5ce496c635f96ac1ccd87518d4274b49$aaaSXB$$2salt2","test1"},
	{"$dynamic_16$2f49a8804a3aee4da3c219539fc93c6d$123456$$2ssss2","thatsworking"},
	{"$dynamic_16$d8deb4f271694c7a9a6c54f5068e3825$5555hh$$2sxxx3","test3"},
	// repeat the hash in exactly the same format as it gets stored in john.pot
	{"$dynamic_16$d8deb4f271694c7a9a6c54f5068e3825$HEX$3535353568682424327378787833","test3"},
	{"$dynamic_16$0b714c79c5790c913a6e44faad39f597$12345678901234567890123$$23IJIps", "1234567890123456789012345678901234567890123456789012345"},
#ifndef SIMD_COEF_32
	{"$dynamic_16$1e27f26c540f2980809f4d74989e20e3$12345678901234567890123$$2730ZnC", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_18 --> PO  md5($s.$C1.$p.$C2.$s)
static DYNAMIC_primitive_funcp _Funcs_18[] =
{
	//DynamicFunc__clean_input_kwik,
	//DynamicFunc__append_salt,
	//DynamicFunc__append_input1_from_CONST1,
	//DynamicFunc__append_keys,
	//DynamicFunc__append_input1_from_CONST2,
	//DynamicFunc__append_salt,
	//DynamicFunc__crypt_md5,

	//MGF_POSetup
	// made a 'special' function to speed this up about 20%
	DynamicFunc__POCrypt,
	NULL
};
static struct fmt_tests _Preloads_18[] =
{
	{"$dynamic_18$0c78bdef7d5448105cfbbc9aaa490a44$550c41c11bab48f9dbd8203ed313eef0", "abc123"},
	{"$dynamic_18$550c41c11bab48f9dbd8203ed313eef0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "abc123"},
	{"$dynamic_18$9be296cf73d2f548dae3cccafaff1dd9$82916963c701200625cba2acd40d6569", "FRED"},
	{"$dynamic_18$a0e2078f0354846ec5bc4c7d7be08a46$82916963c701200625cba2acd40d6569", ""},
	{"$dynamic_18$2401086f2193f35db28c0035b27feb2a$767179c7a2bff19651ce97d294c30cfb", "12345678901234567890123456789012"},
#ifndef SIMD_COEF_32
	{"$dynamic_18$52eece2c63887509d49506254163dc48$767179c7a2bff19651ce97d294c30cfb", "123456789012345678901234567890123456789012345678"},
#endif
	{NULL}
};
static DYNAMIC_Constants _Const_18[] =
{
	// constants not needed in the DynamicFunc__POCrypt call, but left here for documentation reasons.
	{1, "Y"},
	{1, "\xF7"},
	{0, NULL}
};

//dynamic_19 --> Cisco PIX hash (same as pixMD5_fmt.c)
static DYNAMIC_primitive_funcp _Funcs_19[] =
{
	//MGF_INPBASE64_4x6
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__set_input_len_16,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_19[] =
{
	{"$dynamic_19$2KFQnbNIdI.2KYOU","cisco"},
	{"$dynamic_19$TRPEas6f/aa6JSPL","test1"},
	{"$dynamic_19$OMT6mXmAvGyzrCtp","test2"},
	{"$dynamic_19$gTC7RIy1XJzagmLm","test3"},
	{"$dynamic_19$.7nfVBEIEu4KbF/1","0123456789abcdef"},
	{"$dynamic_19$NuLKvvWGg.x9HEKO","password"},
	{"$dynamic_19$oWC1WRwqlBlbpf/O","test4"},
	{NULL}
};


//dynamic_20$ --> Salted Cisco ASA hash (same as asaMD5_fmt.c)
static DYNAMIC_primitive_funcp _Funcs_20[] =
{
	//MGF_INPBASE64_4x6
	//MGF_SALTED
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__set_input_len_16,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_20[] =
{
	{"$dynamic_20$h3mJrcH0901pqX/m$alex","ripper"},
	{"$dynamic_20$3USUcOPFUiMCO4Jk$cisc","cisco"},
	{"$dynamic_20$lZt7HSIXw3.QP7.R$admc","CscFw-ITC!"},
	{"$dynamic_20$hN7LzeyYjw12FSIU$john","cisco"},
	{"$dynamic_20$7DrfeZ7cyOj/PslD$jack","cisco"},
	{"$dynamic_20$htyHHwn05fVtrEo6$1234", "123456789012"},
	{NULL}
};

//dynamic_22 --> md5(sha1($p))
static DYNAMIC_primitive_funcp _Funcs_22[] =
{
	//MGF_StartInX86Mode
	//MGF_KEYS_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__LargeHash_OUTMode_base16,
	DynamicFunc__SHA1_crypt_input1_append_input2,
	DynamicFunc__X86toSSE_switch_input2,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL

	// This may be faster.  Found with the dyna compiler, optimizer.
//Flag=MGF_FLAT_BUFFERS
//Flag=MGF_KEYS_INPUT
//MaxInputLenX86=110
//MaxInputLen=110
//Func=DynamicFunc__SHA1_crypt_input1_overwrite_input2
//Func=DynamicFunc__MD5_crypt_input2_to_output1_FINAL
};
static struct fmt_tests _Preloads_22[] =
{
	{"$dynamic_22$a7168f0f249e3add33da11a59e228a57","test1"},
	{"$dynamic_22$067dda3ad565339fffa61ba74fab0ba3","thatsworking"},
	{"$dynamic_22$71a1083be5c288da7e57b8c2bd7cbc96","test3"},
	{"$dynamic_22$fbbd5aa600379a7964cef214c8a86b8a", "1234567890123456789012345678901234567890123456789012345"},
#ifndef SIMD_COEF_32
	{"$dynamic_22$970aa601bafc0335f2249ff43e0504ef", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_23 --> sha1(md5($p))
static DYNAMIC_primitive_funcp _Funcs_23[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_KEYS_INPUT
	DynamicFunc__crypt_md5,
	DynamicFunc__SSEtoX86_switch_output1,
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__SHA1_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_23[] =
{
	{"$dynamic_23$81d84525eb1499d518cf3cb3efcbe1d11c4ccf25","test1"},
	{"$dynamic_23$6cd62e1767b65eec58d687de6d9c08a828018254","thatsworking"},
	{"$dynamic_23$7d653cf00d747a9fbab213b6c2b335cfe8199ff3","test3"},
	{"$dynamic_23$e290c79e9584e4cd61faded848ff96f03d89e649", "1234567890123456789012345678901234567890123456789012345"},
#ifndef SIMD_COEF_32
	{"$dynamic_23$609fed73c093edfbcc9913004656f3609bd3a5be", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_24 --> sha1($p.$s)
static DYNAMIC_primitive_funcp _Funcs_24[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_24[] =
{
	{"$dynamic_24$5a12479f0a8286a832288e1dc2ea9b2eda4e382d$sG","test1"},
	{"$dynamic_24$c72b6f1caddb158831cab0b08d29243ea20fc869$xxRW","thatsworking"},
	{"$dynamic_24$b966eff1aac95e92818a7c59326cce297b935eff$s3xx","test3"},
MTL({"$dynamic_24$ac5b6b001b3920b868af5e7e35272a8856d80b10$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456"},)
	{NULL}
};

//dynamic_25 --> sha1($s.$p)
static DYNAMIC_primitive_funcp _Funcs_25[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_25[] =
{
	{"$dynamic_25$f5266f29ff7f1ea6fc30085c8347fcf6a6e36e9c$sG","test1"},
	{"$dynamic_25$a34af873d9047541b4d76ceae7b391f0664ca99e$xxRW","thatsworking"},
	{"$dynamic_25$f0058038be0e821caa3031b463aed00fbe7e3beb$s3xx","test3"},
MTL({"$dynamic_25$1b8cde0e3ecaed9abfa4deaf37addc7adcb8a932$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456"},)
	// Inno Setup, Digest::SHA1("PasswordCheckHash" . salt . password)
	{"$dynamic_25$6d29001f8a5062d7b6f5b32b30a8cf64da6567e0$HEX$50617373776f7264436865636b48617368463243d92abc14cc", "openwall"},
	{NULL}
};

// dynamic_26  raw-sha1
static DYNAMIC_primitive_funcp _Funcs_26[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_KEYS_INPUT
	//MGF_FLAT_BUFFERS
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_26[] =
{
	{"$dynamic_26$b444ac06613fc8d63795be9ad0beaf55011936ac","test1"},
	{"$dynamic_26$1068db2941b46d12f790df99d72fe8c2eb6d3aaf","thatsworking"},
	{"$dynamic_26$3ebfa301dc59196f18593c45e519287a23297589","test3"},
MTL({"$dynamic_26$e4227954acdafb57977d7dc8a19570959176fb72", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}
};

// Dyna 27/28 have been removed, Spring of 2013.  These dyna numbers should NOT be reused for any purpose.
//dynamic_27 --> FreeBSD MD5
//dynamic_28 --> Apache MD5

//dynamic_29 --> raw-md5-unicode  md5(utf16($p))
static DYNAMIC_primitive_funcp _Funcs_29[] =
{
	//MGF_UTF8
	DynamicFunc__clean_input,
	DynamicFunc__setmode_unicode,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_29[] =
{
	{"$dynamic_29$16c47151c18ac087cd12b3a70746c790","test1"},
	// these U= test strings will ONLY be loaded in --encoding=utf8 mode
	{"U=$dynamic_29$94a4e171de16580742c4d141e6607bf7","\xE2\x82\xAC"},
	{"U=$dynamic_29$03c60810f0e54d16e826aca385d776c8","\xE2\x82\xAC\xE2\x82\xAC"},
	{"U=$dynamic_29$2d554433d7cde7ec8d16aaf126c3be6b","\xE2\x82\xAC\xC3\xBC"},
	{"U=$dynamic_29$8007d9070b27db7b30433df2cd10abc1","\xC3\xBC\xE2\x82\xAC"},
	// these A= test strings will ONLY be loaded if we are NOT in --encoding=utf8 mode
	{"A=$dynamic_29$ea7ab2b5c07650badab30790d0c9b63e","\xFC"},
	{"A=$dynamic_29$f0a0b9f1dea0e458cec9a284ff434d44","\xFC\xFC"},
	{"A=$dynamic_29$d25a0b436b768777cc9a343d283dbf5a","\xFC\xFC\xFC"},
	{"A=$dynamic_29$719917322bf12168f8c55939e4fec8de","\xFC\xFC\xFC\xFC"},
	{"$dynamic_29$d41d8cd98f00b204e9800998ecf8427e",""},
	{"$dynamic_29$9c3abef89ff76f8acd80eae37b35f64f","test2"},
	{"$dynamic_29$849ee1b88b5d887bdb058180a666b450","test3"},
	{"$dynamic_29$8c4cb7e8b33b56a833cdaa8673f3b425","test4"},
	{"$dynamic_29$537e738b1ac5551f65106368dc301ece","thatsworking"},
	{"$dynamic_29$35a4af9e0a634cd450551137193da28f", "123456789012345678901234567"},
#ifndef SIMD_COEF_32
	{"$dynamic_29$002ca7054ae8657c55fb8b32008e113d", "1234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_30 --> md4($p)                    // raw-md4
static DYNAMIC_primitive_funcp _Funcs_30[] =
{
	//MGF_KEYS_INPUT
	DynamicFunc__crypt_md4,
	NULL
};
static struct fmt_tests _Preloads_30[] =
{
	{"$dynamic_30$f79e002ac163078c673fa2c321e5e66f","test1"},
	{"$dynamic_30$921c92ad4664b899470e6f5a8e37b8f8","thatsworking"},
	{"$dynamic_30$cd23914be346f8d20da217890915809c","test3"},
	{"$dynamic_30$f75ceb87e3be2cf77aca6d243716358d", "1234567890123456789012345678901234567890123456789012345"},
#ifndef SIMD_COEF_32
	{"$dynamic_30$e33b4ddc9c38f2199c3e7b164fcc0536", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};
//dynamic_31 --> md4($s.$p)
static DYNAMIC_primitive_funcp _Funcs_31[] =
{
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md4,
	NULL
};
static struct fmt_tests _Preloads_31[] =
{
	{"$dynamic_31$5f4de0716cc8e0c8ebbd20f5adbdc09f$fHyMBLzW","test1"},
	{"$dynamic_31$c2dd539797c1cdefdbdd2c83ecb8e841$x84Smbf7","thatsworking"},
	{"$dynamic_31$3a90c6e0b30cda0df2735267a2cce59c$MgTzwUaX","test3"},
	{"$dynamic_31$22748c473e37cd6fd02152cff43ade7c$123456789012345678901234", "1234567890123456789012345678901"},
#ifndef SIMD_COEF_32
	{"$dynamic_31$6ee26901bf4abd05a372988f27bd9133$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456"},
#endif
	{NULL}
};
//dynamic_32 --> md4($p.$s)
static DYNAMIC_primitive_funcp _Funcs_32[] =
{
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md4,
	NULL
};
static struct fmt_tests _Preloads_32[] =
{
	{"$dynamic_32$7587e30d68ce5d7e2d4e7d98a8f69ff5$RAkUuD88","test1"},
	{"$dynamic_32$ac41e895dcebe4b4badc4280c7bbbe21$9i6Xjysc","thatsworking"},
	{"$dynamic_32$86ea8d1ac762fe341a3c811092eda3d4$IUazKzjG","test3"},
	{"$dynamic_32$d20c883c8ea9eca7019d6795e1b2939e$123456789012345678901234", "1234567890123456789012345678901"},
#ifndef SIMD_COEF_32
	{"$dynamic_32$7f67e75ef8aead6a1b61afe9a2cb41c8$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456"},
#endif
	{NULL}
};
//dynamic_33 --> md4(utf16($p))			// NT
static DYNAMIC_primitive_funcp _Funcs_33[] =
{
	//MGF_UTF8
	DynamicFunc__clean_input,
	DynamicFunc__setmode_unicode,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md4,
	NULL
};
static struct fmt_tests _Preloads_33[] =
{
	{"$dynamic_33$aacd12d27c87cac8fc0b8538aed6f058","test1"},
	{"$dynamic_33$2a506e79bc1c0cf0e4da9c4053aa18ce","thatsworking"},
	{"$dynamic_33$ed78e4bee2001d143286284067c3be3f","test3"},
	{"$dynamic_33$c9102388a53aef8457aed9f14168e2f9", "123456789012345678901234567"},
#ifndef SIMD_COEF_32
	{"$dynamic_33$adced3e86b7af2ee3e5131bc2b0bb6cb", "1234567890123456789012345678901234567890"},
#endif
	{NULL}
};
//dynamic_34 --> md5(md4($p))
static DYNAMIC_primitive_funcp _Funcs_34[] =
{
	//MGF_KEYS_INPUT
	//MGF_SET_INP2LEN32
	DynamicFunc__crypt_md4,
	//DynamicFunc__clean_input2_kwik,
	//DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix,
#if !ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input2_len_32_cleartop,
#endif
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_34[] =
{
	{"$dynamic_34$70bd0343fde5c0ce439b8eaed1c5930d","test1"},
	{"$dynamic_34$7e716c197034cfc4dcdc1d23234bf65a","thatsworking"},
	{"$dynamic_34$68fb8e1b89e88a8d006905edf3c3207f","test3"},
	{"$dynamic_34$1af18a178e07721f618dbe6ef4340aea", "1234567890123456789012345678901234567890123456789012345"},
#ifndef SIMD_COEF_32
	{"$dynamic_34$e4f6c3f090122b8002e6d3951327926c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//$ ./pass_gen.pl  'dynamic=num=35,format=sha1($u.$c1.$p),usrname=uc,const1=:'
//dynamic_35 --> sha1(uc($u).:.$p)
static DYNAMIC_primitive_funcp _Funcs_35[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED ???
	//MGF_USERNAME_UPCASE
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_userid,
	DynamicFunc__append_input1_from_CONST1,
	DynamicFunc__append_keys,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_35[] =
{
	{"$dynamic_35$a12c6e0d8a4bcabb7f588456cbd20eac3332724d$$UELEV__CHARS","test1"},
	{"$dynamic_35$9afbe0bf4e1f24e7e2d9df322b3b284037ac6e19$$UU1","thatsworking"},
	// repeat previous hash in exactly the same format that is used for john.pot
	{"$dynamic_35$9afbe0bf4e1f24e7e2d9df322b3b284037ac6e19$HEX$24555531","thatsworking"},
	{"$dynamic_35$e01ff7a245202eb8b62a653473f078f6a71b5559$$UNINECHARS","test3"},
	{"$dynamic_35$a12c6e0d8a4bcabb7f588456cbd20eac3332724d","test1",        {"ELEV__CHARS"}},
	{"$dynamic_35$9afbe0bf4e1f24e7e2d9df322b3b284037ac6e19","thatsworking", {"U1"}},
	{"$dynamic_35$e01ff7a245202eb8b62a653473f078f6a71b5559","test3",        {"NINECHARS"}},
MTL({"$dynamic_35$982d4288d0d42c78938d19ffffcada1766f75ecf$$UDEADCAFE", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"},)
	{NULL}
};
static DYNAMIC_Constants _Const_35[] =
{
	{1, ":"},
	{0, NULL}
};

//$ ./pass_gen.pl  'dynamic=num=36,format=sha1($u.$c1.$p),usrname=true,const1=:'
//dynamic_36 --> sha1($u.:.$p)
static DYNAMIC_primitive_funcp _Funcs_36[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_USERNAME
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_userid,
	DynamicFunc__append_input1_from_CONST1,
	DynamicFunc__append_keys,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_36[] =
{
	{"$dynamic_36$9de18a2891ab0588a0b69938cda83ed9bdd99c32$$Uu3","test1"},
	{"$dynamic_36$3549e298740bb9e8148df04f43ba2fb82a052cc4$$UHank","thatsworking"},
	{"$dynamic_36$11ef4de4baf784d0a1ca33e99a7283ef6b01cdc5$$Usz110","test3"},
	{"$dynamic_36$9de18a2891ab0588a0b69938cda83ed9bdd99c32","test1",        {"u3"}},
	{"$dynamic_36$3549e298740bb9e8148df04f43ba2fb82a052cc4","thatsworking", {"Hank"}},
	{"$dynamic_36$11ef4de4baf784d0a1ca33e99a7283ef6b01cdc5","test3",        {"sz110"}},
	// repeat one hash in exactöy the same format that is used in john.pot:
	{"$dynamic_36$9de18a2891ab0588a0b69938cda83ed9bdd99c32$HEX$24557533","test1"},
MTL({"$dynamic_36$151f733540e2813ea1ef42dc879e7c243421d827$$Usevench", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"},)
	{NULL}
};
static DYNAMIC_Constants _Const_36[] =
{
	{1, ":"},
	{0, NULL}
};

//$ ./pass_gen.pl  'dynamic=num=37,format=sha1($u.$p),usrname=lc'
//dynamic_37 --> sha1(lc($u).$p)
static DYNAMIC_primitive_funcp _Funcs_37[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_USERNAME
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_userid,
	DynamicFunc__append_keys,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_37[] =
{
	{"$dynamic_37$13db5f41191e8e7ea5141b16cd58c75af5e27071$$Ujohn","test1"},
	{"$dynamic_37$b8778be2f1c510447bf6a36af8317fd068192d3d$$Ubin","thatsworking"},
	{"$dynamic_37$6ceecc888de5f3b86a12f916c750d0667046a1fd$$U2","test3"},
	{"$dynamic_37$13db5f41191e8e7ea5141b16cd58c75af5e27071","test1",        {"john"}},
	{"$dynamic_37$b8778be2f1c510447bf6a36af8317fd068192d3d","thatsworking", {"bin"}},
	{"$dynamic_37$6ceecc888de5f3b86a12f916c750d0667046a1fd","test3",        {"2"}},
	// repeat in exactly the same form that is used in john.pot
	{"$dynamic_37$6ceecc888de5f3b86a12f916c750d0667046a1fd$HEX$245532","test3"},
MTL({"$dynamic_37$398a2ef658dc374790261e6aa8e09f09586e786b$$Ujohn", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"},)
	{NULL}
};

//$ ./pass_gen.pl  'dynamic=num=38,format=sha1($s.sha1($s.sha1($p))),salt=ashex,saltlen=32'
//dynamic_38 --> sha1($s.sha1($s.sha1($p)))
static DYNAMIC_primitive_funcp _Funcs_38[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input_kwik,
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA1_crypt_input1_append_input2,
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_salt,
	DynamicFunc__SHA1_crypt_input2_append_input1,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_38[] =
{
	{"$dynamic_38$79b98004be7a360a35e69dda2d86e7720487c01e$HQfznIvQwrbwcMTTaRDG","test1"},
	{"$dynamic_38$5b5ff54803ea99f576756f047bd94132b7858f9c$3AD2Ku2yshwOp9S5bLXn","thatsworking"},
	{"$dynamic_38$9656b9adf1ec60575c965eda08a93d6150088c18$R264F5yaxjS9hfhIvc5D","test3"},
MTL({"$dynamic_38$465bdbb99f9ede3a0a85d1773ceb693ceca10629$12345678901234567890123", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"},)
	{NULL}
};


//$ ./pass_gen.pl  'dynamic=39'
//dynamic_39 -->md5($s.pad16($p))      (Net-md5 passed password, long salts)
static DYNAMIC_primitive_funcp _Funcs_39[] =
{
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys_pad16,
	DynamicFunc__MD5_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_39[] =
{
	{"$dynamic_39$7d53f3e19b84242657361938a144536a$8WCoX6IuLNNs8VGgxCwubdW5IQgNffRn93DlpDVck29B1PY8Jr7KrIWdBA9p","test"}, // from pass_gen.pl
	{"$dynamic_39$1e372a8a233c6556253a0909bc3dcce6$HEX$02020000ffff0003002c01145267d48d000000000000000000020000ac100100ffffff000000000000000001ffff0001","quagga"},
	{"$dynamic_39$ed9f940c3276afcc06d15babe8a1b61b$HEX$02020000ffff0003002c01145267d48f000000000000000000020000ac100100ffffff000000000000000001ffff0001","quagga"},
	{"$dynamic_39$4afe22cf1750d9af8775b25bcf9cfb8c$HEX$02020000ffff0003002c01145267e076000000000000000000020000ac100200ffffff000000000000000001ffff0001","abcdefghijklmnop"},
//MTL
	{"$dynamic_39$7da44f2ec836e5b6ca640fbf5dec0da5$12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890","aaaaaaaaaaaaaaaa"},
	{"$dynamic_39$9b26de1e549a57fd4e0c0071eda4f6bd$12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890","aaaaaaaa"},
	{NULL}
};

//$ ./pass_gen.pl  'dynamic=40'
//dynamic_40 -->sha1($s.pad20($p))     (Net-sha1 passed password, long salts)
static DYNAMIC_primitive_funcp _Funcs_40[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys_pad20,
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_40[] =
{
		/* Real hashes from Cisco routers ;) */
//	{"$netsha1$20440a340000000100000000000f4240000f424000000000051c010000000001$709d3307304d790f58bf0a3cefd783b438408996", "password12345"},
//	{"$netsha1$20440a340000000100000000000f4240000f424000000000051c010000000002$94bce4d9084199508669b39f044064082a093de3", "password12345"},
	{"$dynamic_40$94bce4d9084199508669b39f044064082a093de3$HEX$20440a340000000100000000000f4240000f424000000000051c010000000002","password12345"},
	// repeat in the same format that is used for john.pot
//	{"$dynamic_40$709d3307304d790f58bf0a3cefd783b438408996$HEX$4845582432303434306133343030303030303031303030303030303030303066343234303030306634323430303030303030303030353163303130303030303030303031","password12345"},
	{"$dynamic_40$709d3307304d790f58bf0a3cefd783b438408996$HEX$20440a340000000100000000000f4240000f424000000000051c010000000001","password12345"},
	{NULL}
};

/*** Large hash group for sha224 dynamic_50 to dynamic_58 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA224,5,56)
static struct fmt_tests _Preloads_50[] = {
	{"$dynamic_50$aff3c83c40e2f1ae099a0166e1f27580525a9de6acd995f21717e984","test1"},
	{"$dynamic_50$974607e8cc64c39c43ce7887ddf7cc2795d8bb3103eadb46a594cc3d","thatsworking"},
	{"$dynamic_50$d2d5c076b2435565f66649edd604dd5987163e8a8240953144ec652f","test3"},
MTL({"$dynamic_50$d6ac9c4ea51da6a5a22d4a5438008028994d811ed80c591f0c580970", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_51[] = {
	{"$dynamic_51$0b6ab0ba2c3dd88e825c465183d855322dc389396115a2b8b942552d$Zg","test1"},
	{"$dynamic_51$581c35a6ed0f5f868d622c6758b92db1f1bc5c6f6b7175eaeaf1f14f$KB","thatsworking"},
	{"$dynamic_51$e5ed27650604dc9d92db06c0bcd50dc1baac69f7edaafa2037b958a1$9m","test3"},
MTL({"$dynamic_51$d6ac9c4ea51da6a5a22d4a5438008028994d811ed80c591f0c580970$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_52[] = {
	{"$dynamic_52$c02cea6414abbb26b353ffa55380b4da38b56f93f550167460f2b2e8$d495DQCK","test1"},
	{"$dynamic_52$6e34513f8b75fdd8c01c7bc0a54aab7163a035359e1780d4413e43bd$GAa6smOZ","thatsworking"},
	{"$dynamic_52$2d796ae38a96c48ef9ad16232dd99e27af7010c46cd475bee1f7f5f3$etaOOQcf","test3"},
MTL({"$dynamic_52$d6ac9c4ea51da6a5a22d4a5438008028994d811ed80c591f0c580970$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_53[] = {
	{"$dynamic_53$9045f340c4c6cb4c9d2175d5a966cf06d1dcbbfbb59a352156a4b7c4","test1"},
	{"$dynamic_53$f3fdb63f05b1a9612a7c2745e360bc312945e19926445bb41ae92fbd","thatsworking"},
	{"$dynamic_53$56d951da2e775caff774ab31e9663cf6547f6b2bd2cd9aa449b7d225","test3"},
MTL({"$dynamic_53$168e12248189260b8b7b8fbff7d48cdaa950bf08a8b82736235b8d57", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_54[] = {
	{"$dynamic_54$dd5585fdb1252a3efa02bf9f922afabe9597ddcfe57f229e0ecd4c02","test1"},
	{"$dynamic_54$4c380c601aa89ca51958bc05c5e58cd5f6f5093de5664243ef6100a3","thatsworking"},
	{"$dynamic_54$8ffc176af75adce9c32ccc72b7ea5812f215fbc072ce5b4cc217c8e0","test3"},
MTL({"$dynamic_54$88b3fc3452f128ffec1346ce7f9fe23953ec6995d03635d0c1dd0b60", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_55[] = {
	{"$dynamic_55$aa76e5957376e31952715529cd72ec81d3c076d2152d8b5c8d0efb16$cVfR3OJX","test1"},
	{"$dynamic_55$291b35e248a51a20ef0566a647e566e38ca5081ef12a4e33c560ff8a$YCJXInfb","thatsworking"},
	{"$dynamic_55$71eb0eea12ce8ca85c35396c6e77e856dd524e96350d52a93581aaf0$eQgbWpKS","test3"},
MTL({"$dynamic_55$d7b0e740fd5eabdf3eeaa15918bf9f8bb7da8edd3bbf2a50157b0beb$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_56[] = {
	{"$dynamic_56$0c8b6bb4c29742f326aab75dacde2cba0c924f541ac8af44b7c448cb$WFJsOVXq","test1"},
	{"$dynamic_56$168ece7168c0bddb27825e22b95914bf659ce1c54784ec44a1911fa0$CScG3ful","thatsworking"},
	{"$dynamic_56$405eb278c3c0f398f4329ca751e1410b70ebe2207612d2467ae20293$UquVdi8J","test3"},
MTL({"$dynamic_56$ec2492e20c75afbd0a0d4bbd0896d826b3e4c5a85f2ef79f47b51cc9$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_57[] = {
	{"$dynamic_57$fb133d9adb3d7cd284311ec909b0168a020554e184adcaac4f018e18$w21ElJCa","test1"},
	{"$dynamic_57$0ff48e0fe0847b04175af355256e5e56492bc410b5a915a3514b67e2$hoxc5hI8","thatsworking"},
	{"$dynamic_57$b60b62b69b1754a533747d59c5d4ceb14afa55cf98ba757a407c23e4$rsA4jyVd","test3"},
MTL({"$dynamic_57$fe0cc5de50613f89dcc422a860bfd4699cd16452a1ef4916d5becf76$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_58[] = {
	{"$dynamic_58$960f782c001ed315755b7f42a6e36166b7cb580006633ef4bd6fcd10","test1"},
	{"$dynamic_58$1f0ef052ea6496a941c9d28f502cd943de8dc42222ab105d6e5584bb","thatsworking"},
	{"$dynamic_58$52fd68900d7f5e5388a0b94b6c3c68edddb98f6f4e9a9353babbf9d9","test3"},
MTL({"$dynamic_58$4f2aa3ba5700d32f58d0eb58c6c422a1efb533dbb194fae32538e88a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for sha256 dynamic_60 to dynamic_68 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA256,6,64)
static struct fmt_tests _Preloads_60[] = {
	{"$dynamic_60$1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014","test1"},
	{"$dynamic_60$d150eb0383c8ef7478248d7e6cf18db333e8753d05e15a8a83714b7cf63922b3","thatsworking"},
	{"$dynamic_60$fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13","test3"},
MTL({"$dynamic_60$75ff6bea5b0ad25171988e435c24b3ee1028f2b6fa42d330603337edfc19245f", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_61[] =
{
	{"$dynamic_61$2a4fa0bf8c6a01dd625d3141746451ba51e07f99dc9143f1e25a37f65cb02eb4$RA","test1"},
	{"$dynamic_61$ab3637d2c1f8b12eb4c297b464bac96f6055d71b51e951bfe00dc5a9db9bf864$XX","thatsworking"},
	{"$dynamic_61$a07ccf2b46550d0e7c444f987edad70f90b1b76dd64cbc04fb48c10dc5e15cff$nq","test3"},
MTL({"$dynamic_61$75ff6bea5b0ad25171988e435c24b3ee1028f2b6fa42d330603337edfc19245f$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_62[] = {
	{"$dynamic_62$ee9357332c8c09da880ae180fb2ac9a2d8841df0232ac4b2c864ece23c16d3a2$T7eBFzmv","test1"},
	{"$dynamic_62$22bfad6e017b09c8f6bbfcc1472d7ae476519654645edf8a5efd8fa141c9d74e$RZ8DFqOQ","thatsworking"},
	{"$dynamic_62$2f592058708099d79c03534c7a295bf941fc8abbea6c921dbae82a69039ca0ec$DQGjbaC7","test3"},
MTL({"$dynamic_62$75ff6bea5b0ad25171988e435c24b3ee1028f2b6fa42d330603337edfc19245f$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_63[] = {
	{"$dynamic_63$ab0ee213d0bc9b7f69411817874fdfe6550c640b5479e5111b90ccd566c1163b","test1"},
	{"$dynamic_63$fb771a17a5b2693c5a8892840ca1c2516c318e6656dc371fd9099bcc3dff6d92","thatsworking"},
	{"$dynamic_63$97b868b8503c20875cb0a0e37c418a7166d78304c9384ef0d864ece47d1803ac","test3"},
MTL({"$dynamic_63$e2fd43d1f2260265308fa3e96a3f31934044a261d47e9e8b750722200dfd79bf", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_64[] = {
	{"$dynamic_64$41455282d6faeb0b02bb6441924e07a02b5b8d31c848b3a4f2189e15ed7e9689","test1"},
	{"$dynamic_64$7ae2ef95fbd8c903ab905f007f946cbb3f83a64387af80dec403b333b8955fcf","thatsworking"},
	{"$dynamic_64$2a869eb5421bbea3e5318900a99175a272980931ccf63668950a2b1eff8fa57a","test3"},
MTL({"$dynamic_64$2841435ff3461552fce65aa11c0a6c417d89cf463745e0012f55d418edad9d5c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_65[] = {
	{"$dynamic_65$9e59ea803f5f5c0f2b7adfcb82db9654343d821230b16e123f3cb913d91cf7fa$UX6Hg9Vq","test1"},
	{"$dynamic_65$5adbcc923f2636175a4776b24ea15c8e4592c226985ebc68fb13ee1635df2fe8$mCp6NQxB","thatsworking"},
	{"$dynamic_65$ee4553fd14a4df097398fa87209b4d741b33163d9623c627215d3e3e25622f23$HoTNEE6s","test3"},
	{"$dynamic_65$ce8ebe06e45e2eeba1b19d315be040b2aa7bb862b8f65b2447d0b8207e914f60$dummysalt", "password"},
MTL({"$dynamic_65$323b53767a6fbd464073b6d197aee9aa17e0f47195ec114be23dc5722a3183f9$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_66[] = {
	{"$dynamic_66$6bb87d207be95597ad8bf29df9a983d29508ad2482ab4ceb8b9112ce3963b7f7$LAe5jTw1","test1"},
	{"$dynamic_66$754f6146edb1154774ee74e8186c702047cb82ea1f1612ab035e8d74e8eb8a31$hwFD5o3w","thatsworking"},
	{"$dynamic_66$4a24b7aaf803468f68667cc12d62649104037cd3d64c727997f95e922e35042b$RFHuAImh","test3"},
MTL({"$dynamic_66$e93a51ea4d5cb2880142b30d16fdc309e014b86e90f9768f8dbc0e86d01ba500$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_67[] = {
	{"$dynamic_67$eeda7f31366e2a3f88f727260e0a3809c81c77c46b1d199b6a00b79d13bb3748$qteXzYV0","test1"},
	{"$dynamic_67$17ac40e67cd2d092e68d29c45cb62f1257801b6a40951b0abf2738d5917b7cef$YXFCIJ33","thatsworking"},
	{"$dynamic_67$e3cb1a8b97c3510400ca7e0331b2a8e613f87207ee27cbcb6232fe2f571a4668$ujyylrp0","test3"},
MTL({"$dynamic_67$0fda3023b818360581c0172afee69205eb394aa79cb5e2bb1dec93e7e818e4a9$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_68[] = {
	{"$dynamic_68$98866d999ba299056e0e79ba9137709a181fbccd230d6d3a6cc004da6e7bce83","test1"},
	{"$dynamic_68$5ca7061b1da740429d107d42333214248a5ffa9fac9f506c3b20648c8b428c51","thatsworking"},
	{"$dynamic_68$000b7a5fc83fa7fb1e405b836daf3488d00ac42cb7fc5a917840e91ddc651661","test3"},
MTL({"$dynamic_68$917b9fb1d8752194df386f3480063c2e0b2c882c21efb771506599c8de320471", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for sha384 dynamic_70 to dynamic_78 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA384,7,96)
static struct fmt_tests _Preloads_70[] = {
	{"$dynamic_70$44accf4a6221d01de386da6d2c48b0fae47930c80d2371cd669bff5235c6c1a5ce47f863a1379829f8602822f96410c2","test1"},
	{"$dynamic_70$76f4d70f118eca6a573e20bfc9b53d90931621c1999b0f2a472d45d691c827298c7c2bf27a5a60aa6ea813a5112905d3","thatsworking"},
	{"$dynamic_70$7043bf4687defcf3f7caeb0adab933e7cc1cc2e954fea0e782099b93b43051f948e3300d3e03d126a13abf2acf2547a2","test3"},
MTL({"$dynamic_70$1335f3a1f6ab2377626104b8d44240cda5007038649c213123f9396da561bd9b766d0af252ace78a58dabaa83589bd4d", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_71[] = {
	{"$dynamic_71$2cc3894a72439a47e4558ff278076ef8f432454e18dc94f9f972c05f4c28259adaa3906551e1b30b3459c8e4c67b939d$EH","test1"},
	{"$dynamic_71$351a2849294375a83218da6d1a047df49c7f078905e31add7d8d59219ab6b01850a1bd3106fb8a03ee8df24ef9f4ca01$JQ","thatsworking"},
	{"$dynamic_71$677d64de3c5e11bcedd884dcdbab73b4914bf0196e6cff3b1e6adb835772edca3ff584b08a1fca1f18f817fe9d6b57fd$O1","test3"},
MTL({"$dynamic_71$1335f3a1f6ab2377626104b8d44240cda5007038649c213123f9396da561bd9b766d0af252ace78a58dabaa83589bd4d$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_72[] = {
	{"$dynamic_72$3bced5eee31c2ba9493bcd07e56536cc1c6f9f7709520b425a759a54fcec0d7a53680812716407a6e0b6e757631996d5$b9WL2vC8","test1"},
	{"$dynamic_72$c3122f735d9cb20cdd305e775ba841acd607e4e399563936f568ff88ad26643a1b99de4e8855c5769e18d765c8b50ff7$E6u1Qgtq","thatsworking"},
	{"$dynamic_72$2497022cab716ab1b64e4c8fda667e857819a54d88af210f8433f0d77ecfa23c1b81fac3b24bbe0bbf82a11fe9629378$XCrwOUG4","test3"},
MTL({"$dynamic_72$1335f3a1f6ab2377626104b8d44240cda5007038649c213123f9396da561bd9b766d0af252ace78a58dabaa83589bd4d$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_73[] = {
	{"$dynamic_73$d1c7baa840529e4f64dd82de1ffa6f1912b028ccab35d9cca431d50388711a65cdadb3920dc34baf696ccd972a4c7ef9","test1"},
	{"$dynamic_73$84c128713f498cd950d4cdb0cab241cbedf1d391765d6bec92c4bd0aa6ddf1398b0803de4b40146e0d5ed2cee0b9d009","thatsworking"},
	{"$dynamic_73$d26cc7a524bda031a89b0c25947772ea46121b2fe8be3802f2430c9468838b62340e7ae6df097641da3e63f248b8ef60","test3"},
MTL({"$dynamic_73$9e189929de1bcb799b5f7e05a22519802ec5c8f7a9b7bfba8a2595ed60b9c938f8105df2a0af658260fbed2e792e0ebf", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_74[] = {
	{"$dynamic_74$dbc81fc4a583f0a9e29381cc61fbc38fb1beac9057c4256a0700601f8980bb9da1856e31af5fb36d4aef3f91605ff57e","test1"},
	{"$dynamic_74$3a4a08a0f8c3d9f1a3cad7c091c9cca96766a7aaa2bbd4a9f37d7dceed917e13020b936fac8f2ed07d3dea1904abeb16","thatsworking"},
	{"$dynamic_74$4ccd6ddaf83062228bb19bddf6364ff7f0b54cf5416d33eecd5271a70c820d73312888a6cbb24dc790ce718be9a95494","test3"},
MTL({"$dynamic_74$53b669f5196c753fa5d5a4f47ef29ef51187282ecd9cf66a46a84e3069d4565dac7c16bc1bb5c213f20c41e47f962327", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_75[] = {
	{"$dynamic_75$f14c57288d45d58bb0ab24ed03209cb0b5ac57963d4a454536b4415d8e7e11753208c52ac923d54726cfd197af956fd0$W1QG1oNr","test1"},
	{"$dynamic_75$b80a91dd31512ef1a4c5773a17dc584b5871a1e80090602268044732184d8fae1ebfda7dadf493d0cdc36e7cd73b874f$HbpRzSQB","thatsworking"},
	{"$dynamic_75$a3eba61a9c4d878599e73083a55e270d1e1b96be884ef65eea9d79e9b454ea8510ffa31615819915d5077b17498ea55c$K8aXzbfU","test3"},
MTL({"$dynamic_75$e426d3a4379f33151256f4cd6f599b548ccf48db6863b286827ff6bb30a7d8f82f22ad8f22ee063b075946efa7aae534$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_76[] = {
	{"$dynamic_76$b2ae724870d28da5111060fda398c9516f04f556fccb22d819de9801a26120eaf85fe9e209fe618d6a2a8f89e30ffc5e$4uS21WR2","test1"},
	{"$dynamic_76$aa2104f1c77b01066819eca04f0678dbe0119fa78ebfada490071b029db674ab28e3c0140d812095df68ad78a178e5be$nG1Gvoon","thatsworking"},
	{"$dynamic_76$3e43e555f4167b0385947cd565bde40e785519d06c1cf3f9bc3213ab40522794bed84a2e57a68c49da74defb0a47ef04$kzw6ZI0c","test3"},
MTL({"$dynamic_76$a977ec504a3ca5263fcc89755e4f9c5c1789ac7f86db1e8b89078882ccdef613a790143af5aef5a491b461db11ea1fd1$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_77[] = {
	{"$dynamic_77$a5c0d19086b33e8751c4ed51e16b8809938d9587fbb86c21faf17acd652dd2dfb1602f0a9a92ae15dc058e6e09a69b23$6fe9QLsN","test1"},
	{"$dynamic_77$f203cc435d3181a427c455e9b5036dcfa6091acf570cb8ccf1931b4244e697e063cf86d41afe3150bc36983117775ea0$jwTEaXZB","thatsworking"},
	{"$dynamic_77$1f21e9314a745688b04b295866713c1a3a608ec09b4a3311b0a9dec95f10f627b2b21e1b4489f2e6cfd9c30adff6dda2$BUKDtfhw","test3"},
MTL({"$dynamic_77$85d10001dfa0bf76ebe23c11fdd423ba166f5974fdec7ba1cac2b8bb13e7df176e81c60f003f97479921534b453f1abc$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_78[] = {
	{"$dynamic_78$bcc4c9d333738be9668acee9859c53e137fd513185167df88eecf5cf91060a62164ea3570940a4ef4381300fcf232eba","test1"},
	{"$dynamic_78$43afcdb29a6d23492573c8f3669e0f5d88d6ca5716448cd742b3622cb020af946c273d430818831d82f1c1e89516f1f7","thatsworking"},
	{"$dynamic_78$5bf8faa92ad87edb31619442306c7652a7d1777fc1321a0cd40d91ffd7956a25be6321b606a824a3ce66dcf6de990698","test3"},
MTL({"$dynamic_78$a8c7c7d4f9824f21b1567c76cdfcde81013ca2d7e497043d0ecab87db1e0fea6e188aebe3e432cb3ceec665cda19d434", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for sha512 dynamic_80 to dynamic_88 ***/
#ifndef SIMD_COEF_64
DYNA_PRE_DEFINE_LARGE_HASH(SHA512,8,128)
#else
DYNA_PRE_DEFINE_LARGE_HASH_SKIP_78(SHA512,8,128)
#endif
static struct fmt_tests _Preloads_80[] = {
	{"$dynamic_80$b16ed7d24b3ecbd4164dcdad374e08c0ab7518aa07f9d3683f34c2b3c67a15830268cb4a56c1ff6f54c8e54a795f5b87c08668b51f82d0093f7baee7d2981181","test1"},
	{"$dynamic_80$05c1a41bc43fc4cebfeadbf3eab9b159ccb32887af0d87bfd4b71a51775444d0b4b332a50c4ca9bb9c6da6d5e22cc12e94bd095d6de60be563c3fd3077406d1a","thatsworking"},
	{"$dynamic_80$cb872de2b8d2509c54344435ce9cb43b4faa27f97d486ff4de35af03e4919fb4ec53267caf8def06ef177d69fe0abab3c12fbdc2f267d895fd07c36a62bff4bf","test3"},
MTL({"$dynamic_80$767b68910d853970a83200bec78ad8c45cf2ba8d2a6d3cb73c4c12c95c3dc6540b64351236b114588e0de553319a6e6b6c257ebe6f980bd938d1b052a84084d7", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_81[] = {
	{"$dynamic_81$3cd1ef81fc602fef15ba98d9d8e075328b0a2904ad233796ff03a9d2fc407a377112a124c153a52620471d13530ef116d1b01467e1714be55c4a95286e065dc0$VM","test1"},
	{"$dynamic_81$a8a2c09500d5519187c7be42a8feeb2f5687f2bee25c7cc3755ba75d1fe15fbac50ca248baf2418afbf6a560c6ee8b515ba384539fb5ed153b650b63ab042f84$Ge","thatsworking"},
	{"$dynamic_81$957623e5308ca9472e61985ffe7ea499e67d394fc83b417e6a00d6da778fe340c2f45cd2dea725bca7bd51a6fd223701a2ffd02dd3cb943dcc8e4053626be3fa$CP","test3"},
MTL({"$dynamic_81$767b68910d853970a83200bec78ad8c45cf2ba8d2a6d3cb73c4c12c95c3dc6540b64351236b114588e0de553319a6e6b6c257ebe6f980bd938d1b052a84084d7$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_82[] = {
	{"$dynamic_82$214eb5bb00fa9d5fb57d50dbdf126dbe08b75471c15051e31fb99f2974b170ce5affcb602056eee10f0afe6db9143438412f2a9b5729a7753e27b9fc6c1a5fa2$tZ8nE5oA","test1"},
	{"$dynamic_82$c962438ec174cc169cd425d6ed07c0211785301c6edaab2da1aff33b837a13e2df9639433bf6fd0a26c8aa654188d1528b3a7199508726a649e857eecf79125c$ugQMD6u3","thatsworking"},
	{"$dynamic_82$400c5738cf75bf9d89a20fab33bcc83c2ff9fe2429404232ed4af6d275eaf9d40aa8ab0a0c7646a990c25f9ced176839672f56e27c61da24989f3f9886d4d7a2$fdOZ9GQb","test3"},
MTL({"$dynamic_82$767b68910d853970a83200bec78ad8c45cf2ba8d2a6d3cb73c4c12c95c3dc6540b64351236b114588e0de553319a6e6b6c257ebe6f980bd938d1b052a84084d7$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_83[] = {
	{"$dynamic_83$e52e13f73a85b5fe15cea9f5a69a3eb29be31e9ce97b7e8ba1778757cfd624b4dcda4b40347ae57ff75fddae967bf6b0332d7848d0c3f2e31d380d2181f3ce38","test1"},
	{"$dynamic_83$649cd1f8ef64b87760d6fb9a2040ea65bb74b8d1f0a4d603f880a553d4d85318505659eb52077ba6f9fb24030106d32ca9adcc01ab3f45f4a1aff40167259113","thatsworking"},
	{"$dynamic_83$e803dc500bf2a24eaab1766abc35ae817788dba01b778caf41524867fec4ac804dbf498f668e20b19ba0cfc450091bb897554a7f26b8f07a753b300be1f91a1a","test3"},
MTL({"$dynamic_83$d531d9558d29f908dfa18fc9e4ed266e7e976b57af87fe6aa1e3a0e2922afe95782b63139d5fdb5a919b7cc284af0cf48733418e6abab04ef7cfc8c75beff0a8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_84[] = {
	{"$dynamic_84$5c83a5d1967a3d317daeb97a6ec6bd16d508d1f595c6f32acaa24b760556afbbf7565ee87205bf313d0e6956ff6e26121a3a454e155a5cff118f77dc78963730","test1"},
	{"$dynamic_84$eb8c9cfe799e4eb63d2bea8aad4991d3a6423ce39b7c1d1053f0cf396555040e3842e35af86b56d2542d481dba08a21d6eebc4feffb6f5667cfa4e67999f08eb","thatsworking"},
	{"$dynamic_84$03921e479a31f4c13c4ab0d50b7ab143dad0ed8e0a909cced7cd62e087e29f55534a2811148c4bb2aef43e9996b260417d0b2a9886cca34836a337adfabd7310","test3"},
MTL({"$dynamic_84$592419e9c5b56f1aee6cc03e5c5a3ea7bae17f71e42a67f584424798db45e64b2a3b39c3fcb91e3b0cfc8205b5b5711577febb47c120ebeb02e1e6355c453076", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_85[] = {
	{"$dynamic_85$be530ba78d36bfd3d5ed428b714350ed1c7ea47b3dd7f261b848df4f1b41d20fd56b9d9356bfd26b82f578cf4ae977ec676b7b8b57b59b77729bcca22ac3d20a$uRT6ZkEI","test1"},
	{"$dynamic_85$b5306565e197fa38935e3efe59f2294d6d28e7ca9c445425507923b55321f9678ab2446456a44cf3ed869c28ed719b52c43b66942e6371c07c886a4f531d3925$R55fEdYw","thatsworking"},
	{"$dynamic_85$6cb42643b44f7963019c43c13024d7486b3d806f70520df6c1b1aebdfc2f532a53250ff3bcf468ae0bdbada9daecb1b3e8677c05fbf856ac78a5ba1a322f3d0e$Lo21TUNz","test3"},
MTL({"$dynamic_85$6502c0e21305cfff28829a3bdbab3fc1d82b516f7bf1a06b40dffdbd8bac8862bb60dfe44b06638c2b4cba5196ba69281150fd5b3d925e9d561725e2ce77c0cd$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_86[] = {
	{"$dynamic_86$40928be83405d2ad3af1fd6e970dd2e5a3d0bf4caba70530895870edb65c59c219e91eb81058ac6af77f9f0dcf48c10d75763b0eb3e14e440ba41690023312fc$VXtAXAGy","test1"},
	{"$dynamic_86$a391af55568dc0a0123e148572a2f9ff22af7d603792c7f7b0af97cd42e40112c983d25fc73fe554d3595c61cf332398309b6e1d4f0b744710706d4e607025fc$lRkHcT3s","thatsworking"},
	{"$dynamic_86$c891d4c4f871ddae6b76c03c3d6108e259768b8730397510d74c114d6811acbd2bdf53d79bdfacd33b7587118edf6a11806554ccd2f7dc041d2f80a2c4eada02$aFthlASo","test3"},
MTL({"$dynamic_86$aba2ed0a61430a2eb16edc25630163f1ca217005947a120985451290f30a05695a45a9b40fcde2624fdd70231222540d731423e0f68eec2ac4d5fbc403e04205$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

#ifndef SIMD_COEF_64
static struct fmt_tests _Preloads_87[] = {
	{"$dynamic_87$64facc9742d9e55ac1f621638e240d2ac1496aa90565244ef6838acc325e5badb3949df59fc70655fe64ebb8881cbac3205dcfe399fa59046ed7a58a23f794ec$T85XJRqI","test1"},
	{"$dynamic_87$98399b8585396eeb6803e4a348c85841c85dad875d8cada05f3773fa9aabc642d51c045b1e23416c64a2690f720316de6bfcf9c6f8994a3dc477ac2145c0f5bf$bilwWWce","thatsworking"},
	{"$dynamic_87$31d13b3bbb61e5ea1decdd6051232923fe63bc9cc117fba342959dfb6863327c8a00f8d3c0770ee39b80e480db139cc8c7823f86169cb51808d04da8c2796600$GILe8AIe","test3"},
MTL({"$dynamic_87$be992a7f9fe520e366936f8755cc433cb0a67d0fea233ac8b14b8819e93a6d5a3b531d6ce3044c194581d57d69c12e8fb6c60bc080fdba82903bf1d45922af57$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_88[] = {
	{"$dynamic_88$e43a5ceccd814df1669b9f07f7f422932d5f9778cda0abbb5a169d0d5beda06744dd97b3947f288329f5f9c2db394dc2eae8c1f71e8b290c98c7e8545458aff3","test1"},
	{"$dynamic_88$82bd38d8a52db824fedd8b7506b9e36ed4854aa2d71094771c9c9c32294d080fa488b67bac5c77ca10790f058199fe324e80f73ba61ca0877df9dcdfd1c66ba8","thatsworking"},
	{"$dynamic_88$769412e26aff2ca3005ce84628d98a6681448909ced9980a0bea57ba6a1cbaa0403ac6bb213d267eeaefafad3103b0d1486e700c9521800f9d548f87046470f0","test3"},
MTL({"$dynamic_88$e72007ff2735138d15aa10f816b7244655d33e15953e579ca9bd7d4ef603e3d04bd53e4dd0f09195fa88db57cf7ef53ed1b1f70efa56051ca74f9823d88b1b5f", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
#endif

/*** Large hash group for gost dynamic_90 to dynamic_98 ***/
DYNA_PRE_DEFINE_LARGE_HASH(GOST,9,64)
static struct fmt_tests _Preloads_90[] = {
	{"$dynamic_90$3b024be97641061bdd5409b4866c26c5a965e6fcf125215d2f9857cea81c5b7c", "test1"},
	{"$dynamic_90$d4949e4ad914089d7bbb4711b08343ab7a8658599611a4ee5a91999b5c3e0388", "thatsworking"},
	{"$dynamic_90$55719211936152fbe2e1f6aa796fa866d839356e5ba9bc206ed39ab0bd07d892", "test3"},
MTL({"$dynamic_90$096dd6ff632727d682070752fbda548e69e297d97135e1d84d6357312d4046aa", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_91[] = {
	{"$dynamic_91$f515f18ca65e4c4821dba4809049f4465a933b44f3ef5b1175981fbaaa0e8cdc$VI","test1"},
	{"$dynamic_91$00acb59bb6e40ce58af4d1ecb7d5b9223c78f69bce22aab626041eca3ef69727$3p","thatsworking"},
	{"$dynamic_91$50a41b03306ac3c2922307779d30c42f2ee2fbbcd118be86b0d52b984352e444$GT","test3"},
MTL({"$dynamic_91$096dd6ff632727d682070752fbda548e69e297d97135e1d84d6357312d4046aa$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_92[] = {
	{"$dynamic_92$0544260f34f6792ec0a5333088c5f70c71b5b1d31c4d4ee960282b96e7b2040c$kaSCrmRF","test1"},
	{"$dynamic_92$f1683c8d76491639296480577d795888999c475e1de988e9e61160bdebf836ba$MH82PtXE","thatsworking"},
	{"$dynamic_92$4a5c90d92462db40ddc47f78eaa02b8d75c9f18bc30c24001dbcf83397ed8641$xPW4qUH8","test3"},
MTL({"$dynamic_92$096dd6ff632727d682070752fbda548e69e297d97135e1d84d6357312d4046aa$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_93[] = {
	{"$dynamic_93$de68edcb2422bb842323d5f1e07921237a5e61a28472fe22c36912aecd4895d5","test1"},
	{"$dynamic_93$d1459d7a9f1b79700e631905f1a6e506cd2eb6479d4d4af570cf4a3d8e12fb7c","thatsworking"},
	{"$dynamic_93$1be4da94702cd716865d710619f16a634ff7049f154b0d9679d11081f739a765","test3"},
MTL({"$dynamic_93$bdced78804aa2ff89b3321b5d6c102885376ff0771f4163ef3523f2cc4b530d1", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_94[] = {
	{"$dynamic_94$7c3c1ba038800fb4dd199120773a0236e62bc728ec1d18c91309be75b8363e1b","test1"},
	{"$dynamic_94$ab95ce3f7acf5f7ad62b3abe4086541dc2b223474d46950b5f1f0c03faf35bd1","thatsworking"},
	{"$dynamic_94$10ef1ff47724f4e07bc2265ab68171a43f83f98b4ea56966397be1dfded97df6","test3"},
MTL({"$dynamic_94$a0e0a7d7ce3b4bbff0e26cbcd0b2a7363512709052bbabf6834d904b8d55ab23", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_95[] = {
	{"$dynamic_95$26d13201ded9c417175be1a37fe16a5f0ef6615b4e2ecdbe571cc34340139ae6$zodk0FNq","test1"},
	{"$dynamic_95$64555c8e9119ebb7061156f1f76209796bb706d648608f3b454ee3fe0a4b96e9$801xxsMd","thatsworking"},
	{"$dynamic_95$dbf7b360ad9c97a16b51f8f2f0650eebabbe244d5180b8575b95dfc00af1515b$0PWhE5IH","test3"},
MTL({"$dynamic_95$9d5a646d41169aacdff0b947f4b4317f299dfa59f19eb4fa71a5251e82e9ae53$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_96[] = {
	{"$dynamic_96$b9488a9203cfcf2450a2062ec195ff68845f5ac2b945e7bd829a3a1086993b30$5SC1CcIc","test1"},
	{"$dynamic_96$7ec95e96cb5aa5e95f3fcaeccba4bb9672ae0a2a9b681e8f0b3c5934290aac47$bwZH6PJv","thatsworking"},
	{"$dynamic_96$829599885f51cfad36a43c695bba6f0e24f915547b7205a99284b31af99fb59f$gEwPE1bV","test3"},
MTL({"$dynamic_96$d81d4c3c123769edb6874938e4c61209eade1c110a9c5f74fa2dbe3d6f2f09e5$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_97[] = {
	{"$dynamic_97$a236e0eca5099cf35db2dd6d90f61f7b935fd234955480fda1b681ba2233b9b5$qLqXv6z0","test1"},
	{"$dynamic_97$a51eda198a8ccd6d1fc3ed7da2ab0d1f6df2354ca7b2347b248feaeb2c040b80$3V9Fpadk","thatsworking"},
	{"$dynamic_97$769b1838311d227b1106448f98604c0db61074aa1e7df104f69b344fe744fe6f$qhXqvwKR","test3"},
MTL({"$dynamic_97$d72e60f8abd03e762ce4818446c8ea08b820098e67d8e11c241775d8bcaa360c$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_98[] = {
	{"$dynamic_98$6d7aa908db4df2e99abbb19d646c0d8b540152b8499fee0cd73f42f7dbee800c","test1"},
	{"$dynamic_98$49571dcdde0820ac0115de5521f33e91f3fefda82bcf3a05bcc028596cfc531f","thatsworking"},
	{"$dynamic_98$9a2eb6ae6fa23ab615f1014bbcb8119be20d474495ecc2ab18d51e08852629cc","test3"},
MTL({"$dynamic_98$3bfd7682c63ba737a4209d5da416533d157cf6ce54c9b71dbe4a861f8279cc18", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for whirlpool dynamic_100 to dynamic_108 ***/
DYNA_PRE_DEFINE_LARGE_HASH(WHIRLPOOL,10,128)
static struct fmt_tests _Preloads_100[] = {
	{"$dynamic_100$7a3a0ec40f4b2be2bb40049a5fe0a83349b12d8ae6e9896ee6e490d5276bd150199e26aabb76d9af7a659f16070dc959e0393ef44529cad13f681129d8578df5", "test1"},
	{"$dynamic_100$296f0c87fe042a8f664980b2f6e2c59234683ec593175a33db662b4cdd1376ac239bef3f28e9fffd8d3ab4b049d87a8d224c7f33b92d4028242849d2e1baf41c", "thatsworking"},
	{"$dynamic_100$7d925e8503a922cbbc5d4d17eb232c790262ee0b06c33dc07f200c952ade2b2ddf8eeea7deec242282a700e6930d154f30c8b4096efe2633b860b48286703488", "test3"},
MTL({"$dynamic_100$73622582350099f45647970c0a8a2496d7dcd1b4d52213172b97e045d1cf37b3072e80a372d8c24ac118aa8e34d8e591011558e6cd6a6d7423610155aa38aa62", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_101[] = {
	{"$dynamic_101$ec4061a8201a9d60f3ee2f47b44b2356d1d15c3267c35102d3cac048254879cc20ba75dd2b56aa8872278646667c0b3c729575c1ce1c33cd1e8f6e8421ec1409$yH","test1"},
	{"$dynamic_101$f4a35e798736928804b2eef465761bd510855296b1fbb25316ac05fad5f4690578d8137c02edd889234af912b80ae603ad47a08aff0e0b6e84eda432d9da5acd$gB","thatsworking"},
	{"$dynamic_101$1f33221ae28342e78e2a90d92399029969564d19ae80a530b3b93e5336472eb056cac5d0ae0ca65fef2f46ebd3f7347d3fbb33bd2030db0916f9d25f8d4d30e4$GK","test3"},
MTL({"$dynamic_101$73622582350099f45647970c0a8a2496d7dcd1b4d52213172b97e045d1cf37b3072e80a372d8c24ac118aa8e34d8e591011558e6cd6a6d7423610155aa38aa62$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_102[] = {
	{"$dynamic_102$7aa81139e7678b70751524388e364b64a8f68d08d51ef869c7cb00597246a3a5800af869a736da110836835e67b600936e6cb98004918a8eda60b7c529d420f7$Wdw73yeZ","test1"},
	{"$dynamic_102$ec8ac0ab32650a2a9cf361b4743d0eda196868ce09c374ba59ed35122f88d184d4a4634e82579d98a54b97333e4c0333e20417b95efded39df453fb5a59f7701$MUf2c3pj","thatsworking"},
	{"$dynamic_102$94bb2261deb52f06034106e7c61fdc121cfedcab468b97683b0baf46a3047b9b3da3440a478a1059b7b95a2206bb2a51d61ccfad6a684f1d44dce2b741ebfa10$xr57dTTr","test3"},
MTL({"$dynamic_102$73622582350099f45647970c0a8a2496d7dcd1b4d52213172b97e045d1cf37b3072e80a372d8c24ac118aa8e34d8e591011558e6cd6a6d7423610155aa38aa62$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_103[] = {
	{"$dynamic_103$0f5ab9dd203c82ab38b8364c5f784c3e4b1b80cfbdd2daa353e39023730d8b24527d451529f103018f9c0852919eff60aaa275d07765f44d0b7ba3dcff981034","test1"},
	{"$dynamic_103$ef2efbdb472c549442bf4891724542f3a4662deda5e4d47f0eef176ebccff36c38acb33a57bb68b2d2c69dcdacda8fa17b5d3b453461733e6fb6d3fe5bf10299","thatsworking"},
	{"$dynamic_103$3cd1b185a0779715393126f67f80793a4890b2c0dfccdde8eb83758853d7a8c466d4d7b4552abfb6c3f3cda0d60232772f3618f2d81f2c925bb0000754d2c4f5","test3"},
MTL({"$dynamic_103$0c365d420daf99cfbcf3bd3efa721de75cc7baee7ef0187a8dd43ddb1c2435f1f8cc27cd997522a5c4c3e476d233ddd072496f88bdddca8b8dd0cf95d90ffb21", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_104[] = {
	{"$dynamic_104$1346c99ccc424a11800cf44cc37552ae00b5d95901e8a6536f0828738ed59f3a1733d2d61e8df466172de6cb1b839ad6d442910b8bc2838b3df7a48d02512963","test1"},
	{"$dynamic_104$c4d8241fc6a18d11c3359751275add6752e8e99b427b65fda4c28741c2fddbefe08751fcff36d631fea620039a9617d7edf30ab9651d49c0a42f4b242d2f5b21","thatsworking"},
	{"$dynamic_104$28a068c520ebd249c184bd00e8d46058ede551e9277283acfe110f1699a85e84873c1be74ada487e637f4e2acc0007fe5d139589485239af222edcf59b730276","test3"},
MTL({"$dynamic_104$6348a9c902cb52ceab3bd995355e77c3bb798f687fbe538d6b56d4b67a404a54a79d26703a303f5c8adfc02435ab7ab303f87584630e04525e89b2d2773e86bc", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_105[] = {
	{"$dynamic_105$63f8823cf1573956490e3e50973b1710349777412dab36887092ed9045271ad269d3e0c304bab12b2a1a04a3dac303196b0ca7be8feca2a37ee7731458c91f00$AbDlqbZO","test1"},
	{"$dynamic_105$a5e43524673714670a7c64393f1ec6d869ce366f2d2201a7a8d1f47379855be64a1e245d41f5cf67e553634a85cd48c06bfb26c621ae0e6d6e576702062fc24f$B2LbJu5x","thatsworking"},
	{"$dynamic_105$af591b1577c7f4f42814452b0b60c68d86e9eba57787c40160afbead0e4c635fc356e9bf78fcc10952143910921f3435b05856a947f83664e015bfca092da2e5$qzlnAzZw","test3"},
MTL({"$dynamic_105$4376fefad9bb78728e6ba09b9552a27207e96ddc32fa1981c4559a821d92150a361765f7e9d7ac4dce53207896495ae2a26e01968cf59d9940358164b8591418$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_106[] = {
	{"$dynamic_106$40ee08aaf3c1450a76d6dd264c5136e584ad8403ec7322da13efb3661dc8a5c47d839ecf679aea1193176b50a835e1c6ac5480e38ae6a87baf3e4d4b4cb3f2cd$uXeCSVfI","test1"},
	{"$dynamic_106$e01b66cbeeb31ec1ef2937147b2c7ab3efb6469cea01107b8c5e86e645bcfe119d3001b1c0b31ecf6c5d99e158e66d4765bcbb8502e63a82ac09fb5632ae183d$LWo9tepG","thatsworking"},
	{"$dynamic_106$13060286557ae767444cbb5d726ee522355b9c287f4dd83ad36a67aedbaa0fcde111dcb781f2aee5ccac5e84944a27f0119d2d10bd97e3b464577b8546c846b5$7bgJXjSt","test3"},
MTL({"$dynamic_106$d994020bbfa6dbd3c2ca5093d69c25a524667c81cc8ff091961e18270a04a3d069ef72aa5d0a49b9d89499529b77119bc37332dbf5d41f76c6a53f3ed23e6c6a$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_107[] = {
	{"$dynamic_107$86f1b82108b1bf3916a4edd016163348831c411cec38ed2e8f1dafc0b193edde716aae66ab7153ffcc98d968598e42559973c70a866bc8ea50c42cc929f7884e$q45a2XGl","test1"},
	{"$dynamic_107$2e5edfa44b9ae94b34c8be6d7ccb7ac9115cd9989d44a7c29db395c3ed25b169c23a55c0060dce167ae96a845dab03bda783d8381ae233eac7eb809da5af23db$jqjvWzXq","thatsworking"},
	{"$dynamic_107$721808e56a5a0a4111fb4b76652bc6b0a333356915ba50a62b420600a73fe7eb90e6751e3627bef7105a97611da40605d4d4efb6d41e21212cb6c6311a3354a6$FOpkjyZy","test3"},
MTL({"$dynamic_107$ae254314744024b18eedafb8e3de108c3683964b76baa442b4e3753d3ac590590a0dcc6c45fc757799beab87f03e29242bb21e0c5298850f3f268a7664c07d5a$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_108[] = {
	{"$dynamic_108$b1d42b3a7a285847b5d8a9124a795a9c5309ae242ead410ab7aa2de0e5f1d954cf8bdc2650aa74a28761cd4e11af44a4e97532051569c3d00dfa261483ed409b","test1"},
	{"$dynamic_108$1e61a931e292da1cf5fe665010eea990649fe19cbae9e12fb03751d0c0519ce23d154152f414df5a0a9d569e4aeca4c5bbc2f99705dd18cea22b79e4078e19ec","thatsworking"},
	{"$dynamic_108$a7d50bf71a0d5b0d2797531156fd3acae63425ef55cd461c2cf4556518dcc102f5562d24794bc200e4c91434e40179df73b9cd7334056818d2af3f0ea90bfc36","test3"},
MTL({"$dynamic_108$054e07d38eff21f60807d10e37e6d5f870e46b8c38df31d5a89dea7415ba23d8d4f67e94917f2f3326b609d2670495274b589b1a5a2709090a128d940dece1da", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for tiger dynamic_110 to dynamic_118 ***/
DYNA_PRE_DEFINE_LARGE_HASH(Tiger,11,48)
static struct fmt_tests _Preloads_110[] = {
	{"$dynamic_110$c099bbd00faf33027ab55bfb4c3a67f19ecd8eb950078ed2", "test1"},
	{"$dynamic_110$77a533a29f121450b90ce237856127b2cd47db1359758ee0", "thatsworking"},
	{"$dynamic_110$b8b9f8ab7e7b617abd37e86b89dee671f6332af9a4088497", "test3"},
MTL({"$dynamic_110$e7cdaef6a808cd3fe66b2ea9a62dc2ddcc80b2e8bc812c55", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_111[] = {
	{"$dynamic_111$b9e3062ae9047433b2d8e67fa99860ba7eea616030b7c3cd$KCh80l","test1"},
	{"$dynamic_111$0c35e8a64cd4f421b009582af6e7ecba43f27a0abb1a51f4$mAIaqQ","thatsworking"},
	{"$dynamic_111$c7d22bb594b33730852d4d20836a7b2c543c58979d7d714b$H7SkQK","test3"},
MTL({"$dynamic_111$e7cdaef6a808cd3fe66b2ea9a62dc2ddcc80b2e8bc812c55$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_112[] = {
	{"$dynamic_112$5be18dd441743f2294cb0576e4d1d1cadb45f8851cf0027f$Veo0bpD7","test1"},
	{"$dynamic_112$cca3119c158125bfe4bfc5755d5d10b6b79520b433efbcd4$7j0PHbFb","thatsworking"},
	{"$dynamic_112$b609e4d7c7d59b9e725044319052c959a5642c30b2734709$MCmH3DLI","test3"},
MTL({"$dynamic_112$e7cdaef6a808cd3fe66b2ea9a62dc2ddcc80b2e8bc812c55$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_113[] = {
	{"$dynamic_113$d9568618c46ab11a6dc07f6c7e6611aaef94f6dfb58de3f9","test1"},
	{"$dynamic_113$23694933d9a32a00bc9383f78d2e2bdeec70a6c82571233e","thatsworking"},
	{"$dynamic_113$bd13e5e842b94a278cd8c0aefb200ccb009ca17e1b3c7754","test3"},
MTL({"$dynamic_113$8f7286172dd6503d84c99f0e0219fe4583b42ed6325660ed", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_114[] = {
	{"$dynamic_114$49fd56fd6adda42abdf991816189ccbff945a9e9c4201919","test1"},
	{"$dynamic_114$e6797c7981a25e4f5b368f8700d2aea475fd7e90b4265f65","thatsworking"},
	{"$dynamic_114$550590323f8ff9d850c40ff8fe0bd6dc43faf6e65f74fef2","test3"},
MTL({"$dynamic_114$de1efc9f3d686adc3cea6cc1f0bec6dc07247fd7b1f85ceb", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_115[] = {
	{"$dynamic_115$42f07b536f64106682afa8ab891da84cfadd4d13b1074025$4SLjwS","test1"},
	{"$dynamic_115$9e0124dc691ec243afc62242eced4ebf9242ed0a1fb5a3df$WuotgU","thatsworking"},
	{"$dynamic_115$aa02d0b7d1e599fb280cfb28af9a24c349197fe385e99358$WMPmYO","test3"},
MTL({"$dynamic_115$5e08c7cfd8f72b4762758fc074db683cc409d419fe776cca$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_116[] = {
	{"$dynamic_116$949abe42a3fb02f95ea403c216707cb1b0db2e543b094afd$NW4uHL","test1"},
	{"$dynamic_116$433b70b50ea4ea05c1b920e9794f2f1a15b84d65e9997da4$UjuO0F","thatsworking"},
	{"$dynamic_116$e47227d2ad4f85f7064c7fd9dcc476c75c26c9d5d3e3d990$TI2V6w","test3"},
MTL({"$dynamic_116$c729c1ee93cd3d1a73195aba3d5c85a6196e43e2ef81ad10$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_117[] = {
	{"$dynamic_117$4a3443bc430e461236578b3a6d894543caa11dc67608f5e1$zuvXaO","test1"},
	{"$dynamic_117$c5da7cf68984d2a15bc09c79766d6d0e2715efb6aa9707bd$BhU05y","thatsworking"},
	{"$dynamic_117$137362481b7ace538d52b731564dc23b3ce20d18c985637b$Ozow4i","test3"},
MTL({"$dynamic_117$79e1f4f9a1293344e4d078238cf12a1aa92fe1e479e0e772$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_118[] =
{
	{"$dynamic_118$c4d8ae7ed634de780059f93dad2676fca5c83c2257c5bfbf","test1"},
	{"$dynamic_118$3ae1b52c145a3899c099ae8c45b159ac65f8ca54a312af84","thatsworking"},
	{"$dynamic_118$64d847ba02fb89902b9557a89a3c8c3e3474982001dc93f4","test3"},
MTL({"$dynamic_118$bdbae4c0c564cfb24a320e232fbbef4e02a2084672a72621", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for ripemd128 dynamic_120 to dynamic_128 ***/
DYNA_PRE_DEFINE_LARGE_HASH(RIPEMD128,12,32)
static struct fmt_tests _Preloads_120[] = {
	{"$dynamic_120$f9a23a637f86eda730ce9cf163632ad5", "test1"},
	{"$dynamic_120$252ad54db91c4cc15a11662a277a5f77", "thatsworking"},
	{"$dynamic_120$f6a1643123332bd035bfe354af813669", "test3"},
MTL({"$dynamic_120$e14bd54050e152744d6dea5a8739ba0b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_121[] = {
	{"$dynamic_121$0bb8ae84dde90f9f645141f6f4af3bdb$4WXiYq","test1"},
	{"$dynamic_121$58526c066590a74fad9b2a1ed96dcf86$lcSnpQ","thatsworking"},
	{"$dynamic_121$184e1f3f8faa8c0646027a61152ae42c$6aucqk","test3"},
MTL({"$dynamic_121$e14bd54050e152744d6dea5a8739ba0b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_122[] = {
	{"$dynamic_122$d6ad14f6c1903a81d4c430cfcaa19a88$NBQTeKMC","test1"},
	{"$dynamic_122$2bbe72c7b34c76026faff9373bc9a66d$3ivG1Fiq","thatsworking"},
	{"$dynamic_122$8e8d9579716cced03d472b99ab0caba2$CT7bc2vn","test3"},
MTL({"$dynamic_122$e14bd54050e152744d6dea5a8739ba0b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_123[] = {
	{"$dynamic_123$82cf6702a0086265c121e53c8ec0429b","test1"},
	{"$dynamic_123$93bb21d4f8e8810ea20a7d35f83a1a15","thatsworking"},
	{"$dynamic_123$cc13be2cf4ecaef2451288eee126b0e2","test3"},
MTL({"$dynamic_123$4f1faf5161448e356c7843b36273f770", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_124[] = {
	{"$dynamic_124$15b65cb87ea92f0664b8fba08eb8ed96","test1"},
	{"$dynamic_124$f5ee005cf57939b982008d20d2ab59be","thatsworking"},
	{"$dynamic_124$0cfa0daae0d7dd9e90bc831d0e3e4f2f","test3"},
MTL({"$dynamic_124$18ee107c3018cbe5c926d3cac3a3e2eb", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_125[] = {
	{"$dynamic_125$387e8777e5cfd291949c2597cd7b5e5e$nJQUYy","test1"},
	{"$dynamic_125$29c3b080553b93f65cde3af1acd45598$OTaKW5","thatsworking"},
	{"$dynamic_125$40e2c171ce9e1ebb86b31fb115c406e3$JFTav4","test3"},
MTL({"$dynamic_125$4e1a165cf1e17299aedf6cba844b8e0c$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_126[] = {
	{"$dynamic_126$97bb5a099b2f6e2ff1fe142f3fd5c498$qYpElZ","test1"},
	{"$dynamic_126$61efb3f51a6bc0fa30665a30e9ba608c$DXIYEQ","thatsworking"},
	{"$dynamic_126$1029b7c3f55f19126c3eaa9b7a5ddd55$mC2GcF","test3"},
MTL({"$dynamic_126$88d20140423054e77686e7dd35a1a086$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_127[] = {
	{"$dynamic_127$616b8734d328da207b9dcc98df822996$awiEMX","test1"},
	{"$dynamic_127$10a6c4d59f3b7b60371e713a1445356c$jCk0T9","thatsworking"},
	{"$dynamic_127$09c0088c0cb5b90d8076a7db1a11f868$G775MU","test3"},
MTL({"$dynamic_127$cf1a87b39b05928a0ad3f338002e25f4$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_128[] = {
	{"$dynamic_128$9fb0be59a61be9e674cf9e53de01f45a","test1"},
	{"$dynamic_128$33572aa87db2991d504f0d5b3470fabb","thatsworking"},
	{"$dynamic_128$b2a315b546b04a485f7ff925f8944494","test3"},
MTL({"$dynamic_128$db4230bf3864d3d098869427d4ceaef0", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for ripemd160 dynamic_130 to dynamic_138 ***/
DYNA_PRE_DEFINE_LARGE_HASH(RIPEMD160,13,40)
static struct fmt_tests _Preloads_130[] = {
	{"$dynamic_130$9295fac879006ff44812e43b83b515a06c2950aa", "test1"},
	{"$dynamic_130$5a8c3d2e585ae3533a25a60a40736a9644fccf70", "thatsworking"},
	{"$dynamic_130$78872e94d9e3c83e3ba17445a5f30642da51827c", "test3"},
MTL({"$dynamic_130$17f14dbaca592a2b6f0cbe4ef3d08d46d1fb786b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_131[] = {
	{"$dynamic_131$702368a38713a074cae056beed5133cf51fbb7fc$kIA09e","test1"},
	{"$dynamic_131$109490936b84898f4d525201fd6802c1250123d8$Kj5Hkq","thatsworking"},
	{"$dynamic_131$30cf4d6bf729da8b4bc90878c7b084284e302540$L4YQ0N","test3"},
MTL({"$dynamic_131$17f14dbaca592a2b6f0cbe4ef3d08d46d1fb786b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_132[] = {
	{"$dynamic_132$592cc8f4a54c9cd6739486a060c6faa54632994c$1gNbg96B","test1"},
	{"$dynamic_132$c9e74120fb3373fea1adaedda031b93de7ff38e5$8M0daSKZ","thatsworking"},
	{"$dynamic_132$89adf6af617b87736e9d4775a113d60256a147c2$ZviBFfAb","test3"},
MTL({"$dynamic_132$17f14dbaca592a2b6f0cbe4ef3d08d46d1fb786b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_133[] = {
	{"$dynamic_133$d09e375a8e6031e59861c479e892a3b169431419","test1"},
	{"$dynamic_133$69056d1cd2c2ea986c1e031a3e09cf0633d42d7f","thatsworking"},
	{"$dynamic_133$36554863e1db12d5743a21d4036f4a5b32b7aa90","test3"},
MTL({"$dynamic_133$d14269ea58e7aa906361f4b61c37406d31f1b76b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_134[] = {
	{"$dynamic_134$41a3ca6d04553f3d07bb8093a147beb4712fe293","test1"},
	{"$dynamic_134$b9f43e379172276e0255f36dba0bf61a53c1a681","thatsworking"},
	{"$dynamic_134$b21b9471406dda502265081d4e3756c3f5ed19ac","test3"},
MTL({"$dynamic_134$42faf467a4f63b499c8f946fb8f813ea5ac66d3b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_135[] = {
	{"$dynamic_135$dcfecea55e0f6bb6ae86d48bde0d390d3ec292ab$8smSN6","test1"},
	{"$dynamic_135$256ec34e20b7fc35a176002f2c12f17a12e1fcca$R5w0PU","thatsworking"},
	{"$dynamic_135$0b926db2c6926a7a20fb342f82ab5d6e7e8cce3d$fi3FOT","test3"},
MTL({"$dynamic_135$c6e8817cf2f6250511d16fdd7e15056170a5cd04$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_136[] = {
	{"$dynamic_136$b748c1a685cfc519bb364767af1272dcdc822eed$hhrFRL","test1"},
	{"$dynamic_136$7522b95c103a2c2d931ed431380c1cbb01320d88$8ZBzV9","thatsworking"},
	{"$dynamic_136$5cb245d32aeb805ceb108c0bc70b2a2bc675df81$1PIXLR","test3"},
MTL({"$dynamic_136$4e9807b6af693a7036537f05c1d8dc01fcd747c9$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_137[] = {
	{"$dynamic_137$977090a8be7b29569f16aa0df492f12de4abf580$h6SIQX","test1"},
	{"$dynamic_137$a0b89831305e33750e52119186a39d553f6d4fa7$XDiShI","thatsworking"},
	{"$dynamic_137$b45aeb16d4ce6ceb68225a5647b19d6cb8e32b4e$cMdtOm","test3"},
MTL({"$dynamic_137$1ff61e6a3a2799a6d1263aceee479e8d50ac1040$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_138[] = {
	{"$dynamic_138$d6a76d520f9f74aeca1fee22e961d74c916df334","test1"},
	{"$dynamic_138$6d9543280c7f70bc612143d3980ff99367258d63","thatsworking"},
	{"$dynamic_138$12fbe8a67372ea76ed786dc08f32a17f778ee695","test3"},
MTL({"$dynamic_138$a10d8600623f1f25d1cfec5ac635b27c658186bb", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for ripemd256 dynamic_140 to dynamic_148 ***/
DYNA_PRE_DEFINE_LARGE_HASH(RIPEMD256,14,64)
static struct fmt_tests _Preloads_140[] = {
	{"$dynamic_140$1419109aa0de60e6ba0b6d2b2f602c13b07e97b5ffc85b6be2297badc699262f", "test1"},
	{"$dynamic_140$f156e6c20042057840f3251ee041596d89fde06c2505f61764ad1c03c2fc1375", "thatsworking"},
	{"$dynamic_140$d20d9172e3ae2ade512d88eb69d548d62bdfc3d3ed3e3f0fdea12d84bc8f71a7", "test3"},
MTL({"$dynamic_140$443881c8b5bef195c91fd53f914daffb575c0829e9747f941cf42189bd16acd6", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_141[] = {
	{"$dynamic_141$305191d90a91a457b0d68c1ce30b03b44c1b5ab2bdf1cb11ae1cc28e654c16f3$VQl6tP","test1"},
	{"$dynamic_141$5d0b21f3e51781126c4dbec9e811d3d0ba6abc4a1c5ca157fedeec3b79288c4b$XXEuU5","thatsworking"},
	{"$dynamic_141$ecb2e5ba9bcbcd2750a960a80eed73729c80db526bc08854ddb400a826105328$d5GEhi","test3"},
MTL({"$dynamic_141$443881c8b5bef195c91fd53f914daffb575c0829e9747f941cf42189bd16acd6$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_142[] = {
	{"$dynamic_142$03b1ef0c912340bcdb2d54c6a090bd848eea04ca9cddd20ee0794d8bab991cf0$qsiyvyfd","test1"},
	{"$dynamic_142$c9cfe7a23fc45711008c64e503088300bf2d74661cb8270177f667104eb34910$txjvunyP","thatsworking"},
	{"$dynamic_142$38221d38279d3cbe09516db1cee712c78d68d0cb20210d21dd9bd6f6d2559fcc$xHyh3Eqo","test3"},
MTL({"$dynamic_142$443881c8b5bef195c91fd53f914daffb575c0829e9747f941cf42189bd16acd6$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_143[] = {
	{"$dynamic_143$14889a0b5d0cdfdd40d9b2b68bdf0362f76cbd405a7b389ef0c19fb4d10578c0","test1"},
	{"$dynamic_143$1ca0090ad4b4d6d251e5a453f204f3b0b1aa220bdd1b5063a3e38cc4f06a6e46","thatsworking"},
	{"$dynamic_143$a8f808b43eaad67023830d9f6d33fd36dc6c80840c49ef03d30607d86f4873ae","test3"},
MTL({"$dynamic_143$a585e3cd06c5f92044eee412676b3e8f418ad051add1a3800d9e86990d934ada", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_144[] = {
	{"$dynamic_144$6bac793b70b75cc04e0b1baae3a6aeb04c1008d0a483b2a024743902cb93b86f","test1"},
	{"$dynamic_144$d686ebcdd2f2da167ef365c5682e758788a5493b098e943ef2b6fc7dbf9be361","thatsworking"},
	{"$dynamic_144$f809ae64bbf1a5d834b0db355819f8fb166b826c0947d0e506cef331e030be4e","test3"},
MTL({"$dynamic_144$61fbcd354a11f37eaac326d850f96cfe3bc8f81c1fe256c25ad32cc929a75cd9", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_145[] = {
	{"$dynamic_145$519b7e54144c9a9d655e93df5fb0a09f07a2692fe3fc30889aa9249dff48529d$uKs6lm","test1"},
	{"$dynamic_145$ccf57a7acf5f1211d59fba187c741c05cf26e88f1bbb0ef25bbd22a6b31afb89$LsNB5N","thatsworking"},
	{"$dynamic_145$8f4527840691f40799de14fdb2b0b68c10d2e7ce4a991ee17ff0b81b63ca8924$N2lQ7c","test3"},
MTL({"$dynamic_145$ef3175d43cd48c5e4c36f0ce4163f2cab14b5038ef7541a44e77131975e5685b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_146[] = {
	{"$dynamic_146$9be0a3daed226b414ca4a8c756eeb5d26774ef2e0186721b07dc1375aad1f18e$JAap27","test1"},
	{"$dynamic_146$b130046594c8929009513dab4bcad94d616747bc05eeb5e188f2ae228221bcf4$rfnDyG","thatsworking"},
	{"$dynamic_146$13705270594ab1b9c84fddfa69816a6062f708c283b39faf46e9a5c056d652ae$CLSrX1","test3"},
MTL({"$dynamic_146$9cd0742045e9accb425b082795253af9133f3d9da850a71a65d40500b1d08fd2$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_147[] = {
	{"$dynamic_147$5862a5cbdc4bde3f314151af504565f13ac289bedc2bb75f663705fd63aea107$qg784y","test1"},
	{"$dynamic_147$aa936840f5a3476efbc990fac97ee8ad9c4391e85c79e7ed3ed8529121b2067a$nqifRw","thatsworking"},
	{"$dynamic_147$c2d89bad1ed5ddfcbdb65f44cafe54f18ee3e63e51566d407ef914585a1f2432$5bq1yI","test3"},
MTL({"$dynamic_147$bc8e3c27a4f808a62551fd76b8ba4518cc2192988eee6ace97926715dcebb6c0$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_148[] = {
	{"$dynamic_148$2ba00db7b3f6acdc55ac34fe847907d68b730c48cbfcbcb1306592653b450133","test1"},
	{"$dynamic_148$9c821fad9361d7c09df4a1191cbe22f451e1b2ebe03aa5a81c4bcc95471f484e","thatsworking"},
	{"$dynamic_148$fc25f51bbc2edd52e8a16632053de02d13066a327fe951418c5ad91b936ff4c0","test3"},
MTL({"$dynamic_148$7ec86afdd4f39cf49638334660d44103525e3f44855ed058065cb370544e1cca", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for ripemd320 dynamic_150 to dynamic_158 ***/
DYNA_PRE_DEFINE_LARGE_HASH(RIPEMD320,15,80)
static struct fmt_tests _Preloads_150[] = {
	{"$dynamic_150$303aa1dcb731cd4e4bff2a60971eb7376c6c47cb59947c804776d115470183c8cc2e487337b45412", "test1"},
	{"$dynamic_150$3c616c27aa7539c4726388c9e047aa4ea089dd739b3cfc470e964ea12e479da3cce437b9daa90214", "thatsworking"},
	{"$dynamic_150$4e44b8f67fdc48c167ff0e285350a7df5c050660b601599f2e541d8cbc44696ad1c080028f13c6e7", "test3"},
MTL({"$dynamic_150$77b0d59bd0eeb70266f484ed5157b76647e4062e0fa7bb0254601609f0ad8c41110ca49f5d9d8640", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_151[] = {
	{"$dynamic_151$883750723bb1b2c1d4be8ba6be77605885ba1ee8be4ea0f11a6b9c3d9f2dd67bfab7dc19abf6f17f$AMKTOt","test1"},
	{"$dynamic_151$feacc00098c7da4a4ee07f2938110735c3bbdf98c9d18693bfb2687bd138f5293694ff7a8e1019c4$1IUmij","thatsworking"},
	{"$dynamic_151$b7a213f281e5328e301faa67652d916bbac3187de6afd26d107db476319599e57aafd0378713a275$LqtyZa","test3"},
MTL({"$dynamic_151$77b0d59bd0eeb70266f484ed5157b76647e4062e0fa7bb0254601609f0ad8c41110ca49f5d9d8640$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_152[] = {
	{"$dynamic_152$a52d865f5443c09dd56db4f9d817248a5b338dbd899b29fecf174b2118f4e8dc823b891d1411a54b$2zU2KwSK","test1"},
	{"$dynamic_152$70f5f407eb29c213f4fb5c43ade06bdcbb9d629c806625c9aa3031ee16dedde337597f992d8cbc48$q01b45z5","thatsworking"},
	{"$dynamic_152$2062185fe9d8577deb40669482803e3f21fd5bb15091c52cbb762df5bccf730993eb87f9802694da$S4RmC4l6","test3"},
MTL({"$dynamic_152$77b0d59bd0eeb70266f484ed5157b76647e4062e0fa7bb0254601609f0ad8c41110ca49f5d9d8640$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_153[] = {
	{"$dynamic_153$a31e129221c83ef39a11df2fb35207c3836bd6db07668745dd56abb9f183b7b27fdde856868f5d38","test1"},
	{"$dynamic_153$9824e4a0d2c406cac91048824a7b5b4c81935a180325ab77e5287a9c7cfe288b8e450718709a6ab1","thatsworking"},
	{"$dynamic_153$90c18c86ece60693f7001aed9693fc1a655fc383f76cfaa9936dc922ca3de9f1a07b31e2bcf6518f","test3"},
MTL({"$dynamic_153$04a19756bcd7c471b3d9703f16b96d064e3b71456c9ff620d886dd78e5a92267a495f3756eb4d76b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_154[] = {
	{"$dynamic_154$e104a7e9c56595fbf69c528a5249279c4e100a48c5b190d46ba73315ed729930d602234d59ad078a","test1"},
	{"$dynamic_154$fb10077a7f09ffffb986fe79e9620e2645b4828a0ff6f5011d6ae7fa6ab15d56b787ee3fa7e00366","thatsworking"},
	{"$dynamic_154$dd87e05b9950ab49a399b47918db5f7057cc8e2416def762660ccd45ae9cd3fe2d26c4114504d002","test3"},
MTL({"$dynamic_154$41e5b4023ffde31f2c8220834189bc6a5fd75ed3c7ae8ca5a46259e6b13c12d7f0a09d66f9833a59", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_155[] = {
	{"$dynamic_155$c791488c72190edf6f786ad9d4501eb237acfcb867e7bbc68cf1a7e39d78de63040727bfa0b92abb$3mmjYb","test1"},
	{"$dynamic_155$365c0c4f0ee23d09fe7cf79383c3e2b9b9adeda8fa0c164c7d9e9d6a526ba31c64959d108019fbb1$wVG5YM","thatsworking"},
	{"$dynamic_155$0bc38948f67f8610dd86fcfed3f1b3bf6723ad87c6e2e3e8d5bfb336454b0b15bc1eed35edc39971$3FW422","test3"},
MTL({"$dynamic_155$a600f05895b8b69f83b11c23ddd5cdb009c7b3d1f6529deb88dee5757734a425adf815b7d1a85a24$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_156[] = {
	{"$dynamic_156$a51215627a8f32fc030601ef602b7901858852425d9c5b6bd76b15df83ac297f1d413235041a71ae$9pDFpI","test1"},
	{"$dynamic_156$f138210d758f0441e4550efd65e176c013ef626e1598c117e5e85ef9d9745dc0613d90c8a61a7769$3CJLnI","thatsworking"},
	{"$dynamic_156$da4ac2fa4e302289fc708d095dafea134b72a176c118c06df42f8c2366f9c39c779004fdefd8887c$dlof3w","test3"},
MTL({"$dynamic_156$b08a42caf1890f7ffe02fa66a7cba0c1d415dacf4c7ea47547a15100a883d15091cd58593a6a2eb1$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_157[] = {
	{"$dynamic_157$fa2614cc3b494d5280811d5e5aac0c262f8ac1efcd01378b82be9c12d1a9ac8081315df61fac7173$xHBzxu","test1"},
	{"$dynamic_157$f498579e4cfc825549023ead371460f771c2d039c9ca438b9e1889e38fb7687ab75b94ad60458f34$QuzmKD","thatsworking"},
	{"$dynamic_157$a240f21c470dc8812234326922ecab6599ba48b8163912b66fd37ada9fab39229ffc7578a0cdb843$5mq9og","test3"},
MTL({"$dynamic_157$3737c8f638a66a7e90e7d1a40cef1ef3a807fd641fe7ea2f24cec2cecd80e318e43aac9de35aa4e0$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};
static struct fmt_tests _Preloads_158[] = {
	{"$dynamic_158$083b9aed550cc2788fffbd07bd9a02b10b40edcb9357692942e2f6689c0c800005d09855d5a5a150","test1"},
	{"$dynamic_158$e1d2e0183c05d0094a9986d9dcb0add0344fd401eb255b23cf84bb6d5321cb70669eb3ef7562972b","thatsworking"},
	{"$dynamic_158$824aaade4d6e6441f8da3e8dd7549b70ece96c2d08035ed4cb71f1d5d5e2ba17db46f699bdff8b1e","test3"},
MTL({"$dynamic_158$958cce2e5b7f406366b444c6f5827655cb647a91b1fdcd31a38d276cdc7911bc3d7992de95b16dfa", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"},)
	{NULL}};

/*** Large hash group for haval128_3 dynamic_160 to dynamic_168 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL128_3,16,32)
static struct fmt_tests _Preloads_160[] = {
   {"$dynamic_160$9e40ed883fb63e985d299b40cda2b8f2","abc"},
   {"$dynamic_160$020bae785fdc5bc72fb5dbb69a0312b5","john"},
   {"$dynamic_160$8639915cda6051540ff2c62da52c9125","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_161[] = {
   {"$dynamic_161$a38c8bc89cb99b428f9f371baede4bff$93e41c6e","abc"},
   {"$dynamic_161$9f2df9b631235d70fcf73b806096548f$20911b9b","john"},
   {"$dynamic_161$f507a1baae070e31bc86793d3511fef2$36bc7ce9","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_162[] = {
   {"$dynamic_162$703326bef821b870c087cdf641d7e257$4edc677e","abc"},
   {"$dynamic_162$001343fedcf7cbeb448f72b661ea2539$32d83bb6","john"},
   {"$dynamic_162$8094a462ca16fb6608c2e842a880d667$f3ad985f","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_163[] = {
   {"$dynamic_163$e818f0ef805410cae549a5a54c9f5aee","abc"},
   {"$dynamic_163$c54929b2d677d1d97aa9fb35c64b2f7e","john"},
   {"$dynamic_163$9c5419d492569c309521e88dab8b10c3","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_164[] = {
   {"$dynamic_164$e3690cc6c9f2489957e857d3a2a6a0c8","abc"},
   {"$dynamic_164$f624d7c93c767171acd0ffad1e52e5f6","john"},
   {"$dynamic_164$8950be52b7fbef5f17ad0a794f0f49cb","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_165[] = {
   {"$dynamic_165$961afe63fd0f8d754842118334276869$d4bc655b","abc"},
   {"$dynamic_165$ed72f40ae9c94fdfbbad2ec5b90b2a35$3d9acbe2","john"},
   {"$dynamic_165$e7f5a4b6cf1427d5081f3ff9656cdaf6$0a0e086d","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_166[] = {
   {"$dynamic_166$463661686eb5f3f0ae208a201c61bf7c$2926ed9c","abc"},
   {"$dynamic_166$4dae7b57588386d1e1fd25b42ad6fbae$df424060","john"},
   {"$dynamic_166$90d39aca0491eb17e35439f2f944d34d$b4072b12","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_167[] = {
   {"$dynamic_167$843a1516b35a21d218ea51ba7e4fd044$621d1bfa","abc"},
   {"$dynamic_167$cbd33ff1e4e9120610e1ff107a196eb2$0a9292d9","john"},
   {"$dynamic_167$332f3e8a2c3014d4684fc57de07c50f4$c0e59590","passweird"},
   {NULL}};
static struct fmt_tests _Preloads_168[] = {
   {"$dynamic_168$b7c404ab576c28cc8a0db315f4cdb92d","abc"},
   {"$dynamic_168$036231ce072f084bc0687d26198cb94f","john"},
   {"$dynamic_168$5f4b9b1cbd6c2724aebac96065f4ef7b","passweird"},
   {NULL}};
/*** Large hash group for haval128_4 dynamic_170 to dynamic_178 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL128_4,17,32)
static struct fmt_tests _Preloads_170[] = {
    {"$dynamic_170$6f2132867c9648419adcd5013e532fa2","abc"},
    {"$dynamic_170$c98232b4ae6e7ef3235e838387111f23","john"},
    {"$dynamic_170$50683b38df349781b2ef29e7720eb730","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_171[] = {
    {"$dynamic_171$3f8bf5c2df932ff2db27555a8f40ae54$93e41c6e","abc"},
    {"$dynamic_171$89ac53fbfc5686f523dbb1cc8c6c2b48$20911b9b","john"},
    {"$dynamic_171$9d1962b4aa3e71e33a2ba39b8c8d69fb$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_172[] = {
    {"$dynamic_172$b20a5ab50fcd6adb7ffc7678d69d74af$4edc677e","abc"},
    {"$dynamic_172$1043030fb2d6c4ad04cbe7c67681a468$32d83bb6","john"},
    {"$dynamic_172$17eb6c4a7d1c3fe9d238a931ed282a3e$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_173[] = {
    {"$dynamic_173$f07d5524c4b58959fb7c0891889ec561","abc"},
    {"$dynamic_173$d4ef284b366191827d2901f002d60545","john"},
    {"$dynamic_173$c37e0c3ff5661e373796519a03ae6a1e","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_174[] = {
    {"$dynamic_174$c5f26f9bc7a2aefb52b172a8586af176","abc"},
    {"$dynamic_174$6c4e23a10022719cbb4713135d2176b1","john"},
    {"$dynamic_174$1c250b7bd52bc22121208be6f96c34f9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_175[] = {
    {"$dynamic_175$11d7b85d3a0390f9532bb788fc6586e5$d4bc655b","abc"},
    {"$dynamic_175$4fafcdb328b290a41bb1887a3b3685d2$3d9acbe2","john"},
    {"$dynamic_175$01bbb6a8694ea619c3f6a723e9e33198$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_176[] = {
    {"$dynamic_176$be2c6e15d853da6774f44c9c5299fe00$2926ed9c","abc"},
    {"$dynamic_176$c94ba60c03969bc471242bc2ac00aad0$df424060","john"},
    {"$dynamic_176$25e38ca26735b475ac86437bfc9e8b63$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_177[] = {
    {"$dynamic_177$99ed07338c03d375af995b95927f4f78$621d1bfa","abc"},
    {"$dynamic_177$ad6d72c11bca9d99838cca5cfd87a3e4$0a9292d9","john"},
    {"$dynamic_177$bd27c9890b6cf15ae104f21d00f10b7f$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_178[] = {
    {"$dynamic_178$62b29ab7545a0f2577768a49006f3ba4","abc"},
    {"$dynamic_178$f8c04843e043a6a074dc497561992c30","john"},
    {"$dynamic_178$33107cad7f3931c7ac8c6c137dd772fb","passweird"},
	{NULL}};

/*** Large hash group for haval128_5 dynamic_180 to dynamic_188 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL128_5,18,32)
static struct fmt_tests _Preloads_180[] = {
    {"$dynamic_180$d054232fe874d9c6c6dc8e6a853519ea","abc"},
    {"$dynamic_180$de5ab03f0528022f3f6fd39a7c20f125","john"},
    {"$dynamic_180$061980e8fa4ab224b045ceaeef407667","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_181[] = {
    {"$dynamic_181$38450c86f9fb28e939f5a6ae68ed073f$93e41c6e","abc"},
    {"$dynamic_181$c8929357061aac694065c27537611db3$20911b9b","john"},
    {"$dynamic_181$39ed022c1b28c763ba1754bb9a54bb4b$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_182[] = {
    {"$dynamic_182$65386c960ef4564a51919eb6d595d40d$4edc677e","abc"},
    {"$dynamic_182$2f3fdaab0b66334a3a86816d29a58a5e$32d83bb6","john"},
    {"$dynamic_182$aa2fdf30a11603786927abb696b4ec52$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_183[] = {
    {"$dynamic_183$ac450c71d956b0b22f7e6b0bd267ef6f","abc"},
    {"$dynamic_183$efd9ff13f6a77f2999724b6585fadc2a","john"},
    {"$dynamic_183$90068fe8aee354ad687ea0af53b70e79","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_184[] = {
    {"$dynamic_184$c9d17da4ca099cb3d2c369415ab813da","abc"},
    {"$dynamic_184$fb027d933a70aff50109e7375afb2eb1","john"},
    {"$dynamic_184$e9a2400e409e10db914afdada4b01176","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_185[] = {
    {"$dynamic_185$a153e9c9dc2609fa019aa5423f6a9f7c$d4bc655b","abc"},
    {"$dynamic_185$101385dfac70d60abbf88759512a4543$3d9acbe2","john"},
    {"$dynamic_185$bfd8c2fc30d6a8a1eae6e5d6252a678f$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_186[] = {
    {"$dynamic_186$bb62db1b01780a9433d22af31c1d8abd$2926ed9c","abc"},
    {"$dynamic_186$8a49e587dafc82607fcf6b25ee601b34$df424060","john"},
    {"$dynamic_186$88c5710b687aaa40ef81619691aba385$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_187[] = {
    {"$dynamic_187$8a5c5bac8322ba381c0438f9832235e0$621d1bfa","abc"},
    {"$dynamic_187$4f99a8941138ef8614cdfccaaed2c177$0a9292d9","john"},
    {"$dynamic_187$db273086af2a2bdc05549a3001fbf0ce$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_188[] = {
    {"$dynamic_188$4eaed0f8718ad909c572b0e427e30db5","abc"},
    {"$dynamic_188$25a4c28217adc2a5cfdce250eb86bf28","john"},
    {"$dynamic_188$a8685af0b322560655117ba9b7890efa","passweird"},
    {NULL}};

/*** Large hash group for haval160_3 dynamic_190 to dynamic_198 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL160_3,19,40)
static struct fmt_tests _Preloads_190[] = {
    {"$dynamic_190$b21e876c4d391e2a897661149d83576b5530a089","abc"},
    {"$dynamic_190$1d5fca9b3ea111f22157bbcc3b7218af6347eefe","john"},
    {"$dynamic_190$d9e36bfa4715df5886c9c7598ff22bb8ebda2cf0","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_191[] = {
    {"$dynamic_191$ededab4b87b215a548c3482f895b389f828a4e91$93e41c6e","abc"},
    {"$dynamic_191$2616598abb992ed245d201198f78cc51c55b1c7c$20911b9b","john"},
    {"$dynamic_191$3b9b52a118b0e5eec8f47b45874310d3f1a27392$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_192[] = {
    {"$dynamic_192$71459a76fccbfe4a24619807949b7e3eef12a0b0$4edc677e","abc"},
    {"$dynamic_192$4fa8a5233e3aafe9b718aae4d1c69a6dfb27ff32$32d83bb6","john"},
    {"$dynamic_192$f7208e53768b71d02acf18fa9f9d866eedfdf7db$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_193[] = {
    {"$dynamic_193$b66b73afa08d75cc148a855d0616ede367a9d145","abc"},
    {"$dynamic_193$e4578a985958138d8c2d9e5247970e53693f9ba1","john"},
    {"$dynamic_193$b0fcd7c22906b1f24f93e5e3284337f895087199","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_194[] = {
    {"$dynamic_194$354221dc88934046bf472960b6ca72b6e6813f65","abc"},
    {"$dynamic_194$4f6349aaf471631b85be5235a28e8b277e8757c4","john"},
    {"$dynamic_194$7adb676046aaa6aff010c15653b8e8b21f3071a5","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_195[] = {
    {"$dynamic_195$3d76f9a0726af93d1dc9c5184198a0b089803505$d4bc655b","abc"},
    {"$dynamic_195$12bdb22634307660d1c3a8e2fe2468d6c94e95e7$3d9acbe2","john"},
    {"$dynamic_195$4ca4384a074806dd1efc04fe3a4ff0a1dd03ca34$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_196[] = {
    {"$dynamic_196$b22f0d8e520cbce9215b10134668841d27e1cb5f$2926ed9c","abc"},
    {"$dynamic_196$e2c117b09d2359e57b54052e8b187b3e978e41f6$df424060","john"},
    {"$dynamic_196$d1cb38e8f1a9b4c4ff088d83ac1b3079358a5f13$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_197[] = {
    {"$dynamic_197$75fefee876b16f6de87158a501127544ba768fa4$621d1bfa","abc"},
    {"$dynamic_197$b8b56e5988e647f042b10f1ad0bde85233e52ece$0a9292d9","john"},
    {"$dynamic_197$6d9d02ccabb57ff7f7195063dd767c4143e6d243$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_198[] = {
    {"$dynamic_198$b44718f05345c462b772adb882bc9f913735c523","abc"},
    {"$dynamic_198$67f3c89de979363a5620e2341ec84053be9eff93","john"},
    {"$dynamic_198$edbfb77bb8d53501251b65538eb50e651f54630b","passweird"},
    {NULL}};

/*** Large hash group for haval160_4 dynamic_200 to dynamic_208 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL160_4,20,40)
static struct fmt_tests _Preloads_200[] = {
    {"$dynamic_200$77aca22f5b12cc09010afc9c0797308638b1cb9b","abc"},
    {"$dynamic_200$bac428164deb618439003b52aa3fafc89fe5ba40","john"},
    {"$dynamic_200$7d0ec1ecbd9fc2d19da448d4655e8a8f32d43f49","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_201[] = {
    {"$dynamic_201$f2d31d124556d31e5723f60b8cf981ffbfb46191$93e41c6e","abc"},
    {"$dynamic_201$172b927eba776319a65686b8b1794129f33ad0f8$20911b9b","john"},
    {"$dynamic_201$d2a3fcac4017778ba165e1dc3245359a1c544bec$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_202[] = {
    {"$dynamic_202$445ea79be2b3b3976ce655e00269aa4313957531$4edc677e","abc"},
    {"$dynamic_202$6a8e3b910116dfc708d3c275bc405d2d9a63a41a$32d83bb6","john"},
    {"$dynamic_202$9de04802b67f4c49d257ee128f560e652ea1c6e2$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_203[] = {
    {"$dynamic_203$b3044c24b2f00d60fb68c91295dff108bbde98f4","abc"},
    {"$dynamic_203$fe906e05cf85333fec24d143f12191bf4a5ecae2","john"},
    {"$dynamic_203$a7c796991dff54acbedea7e2d2ce9e75c3b082e1","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_204[] = {
    {"$dynamic_204$2d92004809e280f8fb50b308a48e0e1f5be28b57","abc"},
    {"$dynamic_204$379b871435e30b4886cd400ad9e579f062ef446f","john"},
    {"$dynamic_204$98c5b2b801445a8aee2a0a821792c0e214da0946","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_205[] = {
    {"$dynamic_205$7f7ed5cdf0d63c8090dc3f96f56f69542d7da36e$d4bc655b","abc"},
    {"$dynamic_205$dac43511734639a30f8822f043439d7466133e84$3d9acbe2","john"},
    {"$dynamic_205$487bb8947228365843bebad1fbc3a067e604a2f4$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_206[] = {
    {"$dynamic_206$f1f1f20d650dd70e099c2d02ac5a7cc9bc5d326a$2926ed9c","abc"},
    {"$dynamic_206$09370aab98366781d69e88e26f5f07d5f761a2ae$df424060","john"},
    {"$dynamic_206$8788a5b32eff36a2a45e5ae2b6043292c62b09c9$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_207[] = {
    {"$dynamic_207$1aa04bc0c26028164739a8beba522786f1f0d885$621d1bfa","abc"},
    {"$dynamic_207$a32caf8f40adca06f45349b36af3eef7c390a94e$0a9292d9","john"},
    {"$dynamic_207$e89f6bffb2661335010ddb3cd4a1f951a5f6db51$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_208[] = {
    {"$dynamic_208$47ee4837b1271c5d418279afbabc4129e9305092","abc"},
    {"$dynamic_208$53b314de2dd1b77322f9331237fc57d2b37a644c","john"},
    {"$dynamic_208$371d0626161f1884a4a6a1c226acfc9595f3d6e5","passweird"},
    {NULL}};

/*** Large hash group for haval160_5 dynamic_210 to dynamic_218 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL160_5,21,40)
static struct fmt_tests _Preloads_210[] = {
    {"$dynamic_210$ae646b04845e3351f00c5161d138940e1fa0c11c","abc"},
    {"$dynamic_210$8d6e3e94ab570c0af9bc2b825971e21d2cb90559","john"},
    {"$dynamic_210$ba4fd33a575af661f266d454b4cabba36edcc3ab","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_211[] = {
    {"$dynamic_211$7c818861794023cbc22bd72061d075777cdf8933$93e41c6e","abc"},
    {"$dynamic_211$b20ebea0f58c956e4546ecc34265f9de786cd680$20911b9b","john"},
    {"$dynamic_211$d3c946632253e1e1409fc565e66db0932a8a52a8$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_212[] = {
    {"$dynamic_212$a45c0c1e1b86a54730a0a30433f6352b800719ae$4edc677e","abc"},
    {"$dynamic_212$504c41e6a514e3d946f094409baeb9e532af2456$32d83bb6","john"},
    {"$dynamic_212$70bff305f2b593adac50fe2403b7a17d594978a5$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_213[] = {
    {"$dynamic_213$006771536e4d8e0136a0e48e070c9d46513613d5","abc"},
    {"$dynamic_213$3f8d706cbc5355f2fbd0df533c3c3ef6b32f96f8","john"},
    {"$dynamic_213$ecc0bc57c43e4290b6a86932e22a42b8a77b5170","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_214[] = {
    {"$dynamic_214$33f2f0071caf94e338aa6206b7ec82177f772cf1","abc"},
    {"$dynamic_214$af7d4ad825db12dabf206b6b219c53c5c8cf3842","john"},
    {"$dynamic_214$cdb01c68a33b212bff2d999513b8a10c0718911a","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_215[] = {
    {"$dynamic_215$b08b653f3e956ee6d07c8494a0de3c9479609117$d4bc655b","abc"},
    {"$dynamic_215$0d62343bb01d966952a64c0f016bf47ba66c253a$3d9acbe2","john"},
    {"$dynamic_215$f39fdc865febc9b578425cbf92a9d76c7efa62fb$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_216[] = {
    {"$dynamic_216$7374702cb42ef2099bd5dcc6b4fbfefffab6e50b$2926ed9c","abc"},
    {"$dynamic_216$ec39f34bbfe0ff7e95145fc6be4552143bdf5392$df424060","john"},
    {"$dynamic_216$e4891846ab6d0a9e1d69c9df44f180ce4e123fea$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_217[] = {
    {"$dynamic_217$ec4bd6ce1132c8251740c0ce044e24ef053210da$621d1bfa","abc"},
    {"$dynamic_217$cc78145d71ae9a3cf2973ef36af48dafb2c81989$0a9292d9","john"},
    {"$dynamic_217$d76c5afd432ec59c6625c329659e9278610922a8$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_218[] = {
    {"$dynamic_218$cde4af91dda23f5782397d78eee8f83939022988","abc"},
    {"$dynamic_218$457721ed3d6dfa1da5183ba9daf04b88ea0e7aeb","john"},
    {"$dynamic_218$49ffefc62ab904a5f3965008849e382343a4ac4a","passweird"},
    {NULL}};

/*** Large hash group for haval192_3 dynamic_220 to dynamic_228 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL192_3,22,48)
static struct fmt_tests _Preloads_220[] = {
    {"$dynamic_220$a7b14c9ef3092319b0e75e3b20b957d180bf20745629e8de","abc"},
    {"$dynamic_220$bc3b8251036b5c31761a2e42371af6a8a900634743d30f39","john"},
    {"$dynamic_220$4b17f57e4f5564349bc3e2ee49f1aae992521773b3381254","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_221[] = {
    {"$dynamic_221$6e3726c1cfce1859808951eea74523c597a0e78bceaf977d$93e41c6e","abc"},
    {"$dynamic_221$c48b8d8088005bd9fe911b497bc44fe02db6baeb8c24d685$20911b9b","john"},
    {"$dynamic_221$42b9cb61aa3d661779e46a187573bed89d630c8ba5bf56dd$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_222[] = {
    {"$dynamic_222$e5e607e9fb16de0dd0fc74c8cf1dc5364a1a7de365deb269$4edc677e","abc"},
    {"$dynamic_222$f9f10cdeaeb6ca21cc30967524974e03aa902350e08813ed$32d83bb6","john"},
    {"$dynamic_222$4b45d628fd1df3b344ca1142f5e34fe7e9e44fc38ca3179f$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_223[] = {
    {"$dynamic_223$fca9979c0af3134687d4d6eb12261181c737aeb0499b4be3","abc"},
    {"$dynamic_223$cc5e33e4effbe5ec28d7f38d24e277e4519678984a0fe946","john"},
    {"$dynamic_223$d6cd6156d92f76f68e5da170e2a689a716bf83850997c04a","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_224[] = {
    {"$dynamic_224$d6dd76cf065276566f88dc5482b0653772bd69e4abb6ec8e","abc"},
    {"$dynamic_224$4e1e13974603e8f54cd35a0fc5824a2d33709f070d0120ff","john"},
    {"$dynamic_224$e858b6a3afbcbea2e533f3ceabe89639764818bb86fd6751","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_225[] = {
    {"$dynamic_225$7c92e6948e3430bc465ca322e9d3cb987dd836ca64188326$d4bc655b","abc"},
    {"$dynamic_225$6e9d06d52767d6e3ef10eb77a4ac8d3a252c288bc604058f$3d9acbe2","john"},
    {"$dynamic_225$7f960e9f163ad5baa4fb865edab9374105baaaa98c7d7ee3$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_226[] = {
    {"$dynamic_226$ea4d13465a58610d4f54bc4f581464a137083f83f1abbcb1$2926ed9c","abc"},
    {"$dynamic_226$b5c77b6f8f43aafed02c45dad76c99ad2dcd105ee4799323$df424060","john"},
    {"$dynamic_226$1d2903d8876217b99c3355ea910350f0a5b6536528fe8e56$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_227[] = {
    {"$dynamic_227$19db42dd7d8311a4a1dfb7b3e9e39f35f011d5190a9f6720$621d1bfa","abc"},
    {"$dynamic_227$2a76ffd7f0dd600d40dbea9dd0a10dbcc59e8ebe5094b849$0a9292d9","john"},
    {"$dynamic_227$96e499a8fe697b40068241f5aa5c49d7d6a06a25816d5721$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_228[] = {
    {"$dynamic_228$00b4016eefa11a39d0b481a875e85adcd60a2c3ad05596c6","abc"},
    {"$dynamic_228$80ce8b74c6eef61176c83bc9456e104a35b8fe809cd991e4","john"},
    {"$dynamic_228$679a5fdeb728f9489a437c4a2b8451a1e79777796ed0c5d2","passweird"},
    {NULL}};

/*** Large hash group for haval192_4 dynamic_230 to dynamic_238 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL192_4,23,48)
static struct fmt_tests _Preloads_230[] = {
    {"$dynamic_230$7e29881ed05c915903dd5e24a8e81cde5d910142ae66207c","abc"},
    {"$dynamic_230$dbaab76706b8b5b687b3954531ba504a6d55025bbcea5d90","john"},
    {"$dynamic_230$8018ce20c51b59e183b6c556c7909461072ceccec548be36","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_231[] = {
    {"$dynamic_231$3a48af3accaedea1d1e327fd47a2bb622aae7e5849cbe6f6$93e41c6e","abc"},
    {"$dynamic_231$dda36201544e5f3fc435187f27c75de3f75c924f17290a2d$20911b9b","john"},
    {"$dynamic_231$39442af62b908bab505abf4ec1d3741f4ab37c3fa66a047e$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_232[] = {
    {"$dynamic_232$3fd7e73c0000714e77fe78b8505b82273447e60d69f42ec4$4edc677e","abc"},
    {"$dynamic_232$23fbbde5becd9f360b8aa869777e32d7f394b863b4e951b2$32d83bb6","john"},
    {"$dynamic_232$a3129f4e3d0ab4d94bfb7e1760f29051db2fc3cba8e2ec75$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_233[] = {
    {"$dynamic_233$21a8eae9cb8f25375a16a584cd7651037402464e857d89d5","abc"},
    {"$dynamic_233$05a6e9948fc3e00a9b63003d02b2d44df71a44421dc45ce8","john"},
    {"$dynamic_233$871f50ca6c04e06d39d754c961633e2d45761909e0e561cd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_234[] = {
    {"$dynamic_234$4acfd87f9958bdb636e6a007bdb7598a8a01189d07466840","abc"},
    {"$dynamic_234$166d62f71a6ae410a2aa7adaf3349adb8f50af56886dab5a","john"},
    {"$dynamic_234$4ffc77f3caa2324600a59920b3d8c342f867cfbafa6e257c","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_235[] = {
    {"$dynamic_235$bf71bad3a2e537697dfb8d1a75c2e981c011177689e8907f$d4bc655b","abc"},
    {"$dynamic_235$765835bc34c21f1094a4c2925ec590ff5c39b44688b1283d$3d9acbe2","john"},
    {"$dynamic_235$b9cb003703179a114e756964cd853fc0be24b2c53b28a681$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_236[] = {
    {"$dynamic_236$307ea61a513cdfe4d4a3f64e8f58f7f561bd385c97c89070$2926ed9c","abc"},
    {"$dynamic_236$9f6805c5005b9dc58dd44716f13a7b844fc28efd56f15300$df424060","john"},
    {"$dynamic_236$e0af29202855cd41ccfb87f14620172d66998c4f9fa22236$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_237[] = {
    {"$dynamic_237$900fce5a78fa535aa9d2e253c84fb9346120f5d1e1e83f49$621d1bfa","abc"},
    {"$dynamic_237$4352807e5deb499858f970c7ed128de2c036e30e58878681$0a9292d9","john"},
    {"$dynamic_237$a79f5bd6c69f7f877d6144a490a80b8aafada4bc5b7464b0$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_238[] = {
    {"$dynamic_238$e3ff9bd2776f92c8ba41dca61f6389d70eb55a35504a8c88","abc"},
    {"$dynamic_238$ef9dea31356a5d2cbbb4f9228148286bafdde024f96108cc","john"},
    {"$dynamic_238$75ce44b2e3ff8658f679868c512ecb61e1c168b633121692","passweird"},
    {NULL}};

/*** Large hash group for haval192_5 dynamic_240 to dynamic_248 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL192_5,24,48)
static struct fmt_tests _Preloads_240[] = {
    {"$dynamic_240$d12091104555b00119a8d07808a3380bf9e60018915b9025","abc"},
    {"$dynamic_240$342f4979461efb3fe38eb9dee0c0e009b4ec15fe4e45b81f","john"},
    {"$dynamic_240$29310c526a27db0af01f88d130c096d69f316016c23b7747","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_241[] = {
    {"$dynamic_241$0dc7b926b2430342952de5a8880b56ab6a2477a08b3f523a$93e41c6e","abc"},
    {"$dynamic_241$65d01aebb7f692b1fd65774dc745c1399b42f8dabc930006$20911b9b","john"},
    {"$dynamic_241$ad7635d3bb8db95506a5f2a32deab96f12477d09ba965b67$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_242[] = {
    {"$dynamic_242$9816e5d2bf171d826503b3c4e8023e64fc5be3d0d1277490$4edc677e","abc"},
    {"$dynamic_242$f4099e7362413363ee61ad35da66621d4c55f5286ff8ce9b$32d83bb6","john"},
    {"$dynamic_242$c617d2cd1102eebb5e39db91b6a5cf6ef14f7150a0114827$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_243[] = {
    {"$dynamic_243$4755def808c81f3e8d2d1cb855929bbd578e0e0eb045a5d4","abc"},
    {"$dynamic_243$fd8d0b2e86ed5feb215e0ebc88c65f86797b40426a4f4458","john"},
    {"$dynamic_243$69a0f5130fcc736bd2a7c9ae9aacc942b5d342e04e193370","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_244[] = {
    {"$dynamic_244$89d2d33215575f3b8acb1b38a020f1252ba5e8ef0ac793c5","abc"},
    {"$dynamic_244$9d6fcc5e2beb4ad3e570a6b1325dc0fbdb1ca7a84f2bc525","john"},
    {"$dynamic_244$f5305f6d64203997f43528e5898928c7490bc6dbc59df1ff","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_245[] = {
    {"$dynamic_245$09464d312d00619fd86a005f097dffa66589cc5bdf58dc62$d4bc655b","abc"},
    {"$dynamic_245$9e5520224a01c68c08116c1920137aa66f440cbe347890b8$3d9acbe2","john"},
    {"$dynamic_245$865ba759dea85e5fa095772ecffa35aa18b4519aa858aa12$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_246[] = {
    {"$dynamic_246$d2c6bac4907eecec404fa497d285d03188bc0cd6107d7de6$2926ed9c","abc"},
    {"$dynamic_246$22a0a7f65ece759ea8642f67eaf8eb1940379a57726d2782$df424060","john"},
    {"$dynamic_246$cde0beb84c86ccb4287fa1d06424ee1af1fcd21c2b863827$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_247[] = {
    {"$dynamic_247$c2acc62e0762cf25b04065f7767fccef02821d1ad25bac25$621d1bfa","abc"},
    {"$dynamic_247$f8b843e9ebb01143e827d18ef158436a2683168e0d322d9d$0a9292d9","john"},
    {"$dynamic_247$4ebc43f422fc6a820b92834f9681debec0c82aacea0db6ec$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_248[] = {
    {"$dynamic_248$ea35144f440532b947b80546df5f34c52a431910da029c07","abc"},
    {"$dynamic_248$4a766f3ace3220e8e97a0c55f32605ed31fb2626f74b6ea1","john"},
    {"$dynamic_248$b0f5b949b747069bf586a8869ca5b7b6525bf380224189f5","passweird"},
    {NULL}};

/*** Large hash group for haval224_3 dynamic_250 to dynamic_258 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL224_3,25,56)
static struct fmt_tests _Preloads_250[] = {
    {"$dynamic_250$5bc955220ba2346a948d2848eca37bdd5eca6ecca7b594bd32923fab","abc"},
    {"$dynamic_250$be4109ec18e83897f75a2f86619761668f2b83dc6433e164df89aae0","john"},
    {"$dynamic_250$7bc43e1be5bcd7994dda17ae3aca3f4d72537b9d778d7d2ced6c6ab6","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_251[] = {
    {"$dynamic_251$5d34cd055110ff4e0b72681c226fc87ee599385326f46dcc1129db4b$93e41c6e","abc"},
    {"$dynamic_251$6da51d1817877b8ad69dc987ded8460a4bb400d5fb697ddc52377236$20911b9b","john"},
    {"$dynamic_251$22e270132fa0aa1986c177ee6a4bf5ff8ca541a8dd7bf8010e75b880$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_252[] = {
    {"$dynamic_252$296632e926ce611fbc37ca325fd690fc00c8667772249798e909d156$4edc677e","abc"},
    {"$dynamic_252$6e206bb940ed9d2720d97888d568f024cd544a537acd874e7d0ad975$32d83bb6","john"},
    {"$dynamic_252$b591c44824d4f270c8b5ed11e90aad366c022c7bd3187fc3298c8cd3$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_253[] = {
    {"$dynamic_253$073e256efba02e8d5410918ee694d2d87ae8673eddc22150460ac21a","abc"},
    {"$dynamic_253$9237ab51190141e38c0cd2d7c1ebad1c7083c50fcb68b7f5efc6b5aa","john"},
    {"$dynamic_253$b0d217dcc7e6201150cf2a96d724e7abc2c22e6d8a83167741733e96","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_254[] = {
    {"$dynamic_254$5e2d79e24bcd82bf8d9fff07b1c24cc8178355d746590bddbce6f976","abc"},
    {"$dynamic_254$d8c171821527ed0bd7f6ea9753fb832343fe39bca322a7ca8288d1b2","john"},
    {"$dynamic_254$a8f5459d6a180d09be1d568f06a4f2ad0114b63888044f367f235de8","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_255[] = {
    {"$dynamic_255$185fcfcbff90e899c81d642e41de8889183e88263a13366cc9073a31$d4bc655b","abc"},
    {"$dynamic_255$8d1e8b3c99613f3e22d9e7114f0a30bf9920c83b8b0b5618c72651e0$3d9acbe2","john"},
    {"$dynamic_255$ec02c716a97832d38d80c91cb244015a2aa49cdc2758405f8c7487ec$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_256[] = {
    {"$dynamic_256$2f8785161d3f81f0c34871560dcb4b00cf296d882fe48bc0d025070f$2926ed9c","abc"},
    {"$dynamic_256$49479edad87773fab583ddf1913d675c84908cf24c14c14bd7d0986c$df424060","john"},
    {"$dynamic_256$3b2200e566ef62ddb11955a1594eba772ae405d14c1acb76e5a9eb13$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_257[] = {
    {"$dynamic_257$a43c25f60ad4b0d125284a2932cfc12fad5741aee5fac921b6fa3360$621d1bfa","abc"},
    {"$dynamic_257$6db88a2b20a244ef411e5ac5de0bf13179833487185c0e2ac9b7e752$0a9292d9","john"},
    {"$dynamic_257$930884c772c6438701fe60b2334807be557347e4e2a6f10ab5b717b4$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_258[] = {
    {"$dynamic_258$b484cdfc8c9630ab0413e03eeae86b7aa739bc833f560c4394317921","abc"},
    {"$dynamic_258$0c84e961a07ee9454ce87b42b29b221fb896b830414e9cd3827c4d6b","john"},
    {"$dynamic_258$8ff2016f9e2310449e8303646006f8bc237e2d1a092d4a00a2a5ad37","passweird"},
    {NULL}};

/*** Large hash group for haval224_4 dynamic_260 to dynamic_268 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL224_4,26,56)
static struct fmt_tests _Preloads_260[] = {
    {"$dynamic_260$124c43d2ba4884599d013e8c872bfea4c88b0b6bf6303974cbe04e68","abc"},
    {"$dynamic_260$7fbe61beb256284663fe0e42122895bab0e83bc5dae543a5924d1e57","john"},
    {"$dynamic_260$8d556ced1eebf41def90b94a0e3aaf9abe6a4767fb68e6c65a03b76b","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_261[] = {
    {"$dynamic_261$48c9871ecb5e02f2b9328c14198f4d3e5d82eb1673859b979b225d87$93e41c6e","abc"},
    {"$dynamic_261$6ebf8a0b810540dda6973e5e04388303674183172e59a485dca36c7e$20911b9b","john"},
    {"$dynamic_261$eb82f874a983410b94bed3c0e96cee6cf7fba20a22ad2cf531972eca$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_262[] = {
    {"$dynamic_262$484145a9d2a9558dc758c9abbe89187f47a1610beb5de462298f5842$4edc677e","abc"},
    {"$dynamic_262$78cc8f79fb8596e9790c756dea8733a77975061f119465f21952f191$32d83bb6","john"},
    {"$dynamic_262$abb3d94bb7ea5732e726b158ee79cc3cc3bd403d2878989557ec8e1e$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_263[] = {
    {"$dynamic_263$2e0bed75e751fccbff4e416509cadd2da350212d4e1d6c57adac9651","abc"},
    {"$dynamic_263$248e1138f566c102a04aaed75784a8332e1f26b9e04183e1e2234c56","john"},
    {"$dynamic_263$3b8f6f8f69b4805354d044c3d6a8526bbe4d5777308a89d92522575e","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_264[] = {
    {"$dynamic_264$a89e3861d9091003df573a215bf46830f215274333f2cf75dd5b465c","abc"},
    {"$dynamic_264$515fa6ca20d41cf3bfc4ae8e4c9539f8c742d84854f92bb33a9c7691","john"},
    {"$dynamic_264$9819818b9fbb3a9ba0da430a5fdb290f42096848d02e9da4812838b5","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_265[] = {
    {"$dynamic_265$2176a405777d9183fbd9b2543ab9bffbcea7dbd3ecf96f6b921171c5$d4bc655b","abc"},
    {"$dynamic_265$d1fc1713b8b684afa9806d1daa243da909dc8e10f828ec50550a4e83$3d9acbe2","john"},
    {"$dynamic_265$1f696a6e94442eae8aa4ac41783d32d0b9c17bda450ca8afe9ac233b$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_266[] = {
    {"$dynamic_266$0a121281360c7414b0aebf2b2e3b71da69309f4251885b53bae65abd$2926ed9c","abc"},
    {"$dynamic_266$c3ec836c6a95ffbcf02135d78689bf86dcc238887c12a265719695a3$df424060","john"},
    {"$dynamic_266$8c4e4905ab181a81cb17481d256de420ed3636a38703945d0ba39471$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_267[] = {
    {"$dynamic_267$35c1c6038f502cb117dbada09c0e7150fc00aa603048e010f9a23fd4$621d1bfa","abc"},
    {"$dynamic_267$c10e7fb43ebca738e31b9e8fee465b1e53b91b2fccd4f92a47b0b41b$0a9292d9","john"},
    {"$dynamic_267$622c92a2e242aede87bccd54e5d9400ad27c22b99cc108e24f5baad2$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_268[] = {
    {"$dynamic_268$70ffbf1e7ccc362e2c97f76329881f68b85768bbf6bd8ed725cb0f48","abc"},
    {"$dynamic_268$5ed9a17d303429ab3af5d2767f41713ef018d556dea04d55f535d179","john"},
    {"$dynamic_268$4190434474802d5356ed3821d17412d86a2b32502434999855723ef5","passweird"},
    {NULL}};

/*** Large hash group for haval224_5 dynamic_270 to dynamic_278 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL224_5,27,56)
static struct fmt_tests _Preloads_270[] = {
    {"$dynamic_270$8081027a500147c512e5f1055986674d746d92af4841abeb89da64ad","abc"},
    {"$dynamic_270$52d31a1459fa1550f9b26026cca2dee855a32b17586109f26916271b","john"},
    {"$dynamic_270$4b5d287a64b9aa54fe391c7402f3b1f700505eff0da37d4b75b11efb","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_271[] = {
    {"$dynamic_271$2e45c89c2e38ccc99e0958fdd883c181c03a4d77001d2dec3cc1ecf7$93e41c6e","abc"},
    {"$dynamic_271$68df5f7653f4615c33c3d6c242ab825c91605ec77829c8fec7fffa92$20911b9b","john"},
    {"$dynamic_271$28a173c1b85ad6f8852f9e1082ca6a2ba07961dae9f715a04326bd41$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_272[] = {
    {"$dynamic_272$bf48afa106dcd928fdf354ef9dc84f96b8039eeef54e24ffeb060bef$4edc677e","abc"},
    {"$dynamic_272$d98d5d3fdc79377e987ceb48c7c3f6d6f91e18e336ffbbe503e08632$32d83bb6","john"},
    {"$dynamic_272$33bc8469276e6cbdae938778abbdcb18d9bdf9adc60ff20f9260b672$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_273[] = {
    {"$dynamic_273$c4e867f02ab1dee9dd3949bc3f1bfbc706e4eab86e50074808b45a46","abc"},
    {"$dynamic_273$3a0d24a706b279edeb253896a5c5a0d2222b5ba27bc8914553c95881","john"},
    {"$dynamic_273$c53fa869ce292a0e738ac8e012bf1216ace991b422e6cf540b1989f6","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_274[] = {
    {"$dynamic_274$7ee991eb76bbed4ad30d8a1b90afff265a9c5fa30e8971e0ec649ec8","abc"},
    {"$dynamic_274$6796b9d0b193462999c7ab5085e02dd261572a537e1e84f1575e6133","john"},
    {"$dynamic_274$ae8b93c0e9e6dc70b0de98715a4bb1b495579e27de17c76538861772","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_275[] = {
    {"$dynamic_275$5d392f5d69f6b7d394a99ef72e6db5f04fd658d898edf482a318b73f$d4bc655b","abc"},
    {"$dynamic_275$3516d0d9c9064dbfd78731f34f8abe2f1debdc7950c6e036a9bc53fc$3d9acbe2","john"},
    {"$dynamic_275$6c62a9fcb02bad702dbeee0e88e914fadb2f2654477f719fabe2785e$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_276[] = {
    {"$dynamic_276$1b33884a9dfe0ded0545c05d628d0eac063d23de0bfff9f37b8516a2$2926ed9c","abc"},
    {"$dynamic_276$139d0152a96bbe1e6a3cf5aafeaf94cd2729e0ea79a20fa9897bca4f$df424060","john"},
    {"$dynamic_276$e1fda3778bfcecb045473aaf0cec70645eb9d0565977474522ebc3e6$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_277[] = {
    {"$dynamic_277$12ec2eacab56d690d8583f15e59553c49524c8228dfa9f4e37159044$621d1bfa","abc"},
    {"$dynamic_277$df44062329fde432209439edaf779b43c6e9902b5d6c686402daa698$0a9292d9","john"},
    {"$dynamic_277$faaaeba7e33a7c5cde9317eb15e57fddbc36ecfbb4a629478e899b27$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_278[] = {
    {"$dynamic_278$16195941da4df1e88d2a0ec39f4951221cf8248d30cdf54c420b4a5c","abc"},
    {"$dynamic_278$5bc68a8218834c30d757170a32a12cabb84f9c270effce6dd799c5ea","john"},
    {"$dynamic_278$2f20f811c0386746510391377f105debf33c742e3b03050acdde39c1","passweird"},
    {NULL}};

/*** Large hash group for haval256_3 dynamic_280 to dynamic_288 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL256_3,28,64)
static struct fmt_tests _Preloads_280[] = {
    {"$dynamic_280$8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c","abc"},
    {"$dynamic_280$cd43bec91c50e5f781fc50a78a3e9c8c48b407fa35a20c972178d63867dbe158","john"},
    {"$dynamic_280$5aa9c913463f82260071629c8ac2c54d73b3af016ffd8e8ce128558d909fab06","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_281[] = {
    {"$dynamic_281$551faf2817641b40d76680992db5f6d7108052f7ef3cd678997ce42932746242$93e41c6e","abc"},
    {"$dynamic_281$9c7049d3c7d3077d038bb5d0dba17f83f2cd0b6dad721e91912d8e25d02fbd56$20911b9b","john"},
    {"$dynamic_281$c38ca21f2d450eb2ccbdd51bb1a618abd8f140577e79b9d8bcddb0c1a84dd716$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_282[] = {
    {"$dynamic_282$fe80ac3c937e22718aead655b53c8eb3f1ff25c60882a0c30d6eb1e51468a99d$4edc677e","abc"},
    {"$dynamic_282$22c34f2f86fdf5759ff5d68fd70c1fce991927200c2bb7f843dcdf692ca595b9$32d83bb6","john"},
    {"$dynamic_282$710aeacf57681a6bf57c46a54dd63e9c180377ef4125a535eaeca28dfcfa4d0a$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_283[] = {
    {"$dynamic_283$429656f0520831021234f2a0dc89f69c6b3d06a3a87be580ae71083a304ade95","abc"},
    {"$dynamic_283$62186e67d559afe791a2ca2a64b7f79252e09bfe3420299ae3aaefc9beb34bca","john"},
    {"$dynamic_283$faa04f807fa7b7c3ed1b78bf2b5bff377092dbfba72264cf956ed5ee570d7ffb","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_284[] = {
    {"$dynamic_284$11afae5e0bb14d19b5ce7ec0294094180813f32c67ec05e08f3bbd1bde1a0734","abc"},
    {"$dynamic_284$a0d0b62d21c26b620296a3c7415598debd9bda213cf25b219f4ce7ce131cf6b3","john"},
    {"$dynamic_284$c7bf7c1a0f5945caa35dc3aa59c5d2fc3d11e8e4155668cf8dfffce71a754645","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_285[] = {
    {"$dynamic_285$eb844ebbf948a1c178d20c2fd79c38993bd1cfd95ced23e4ab92cee757ccad93$d4bc655b","abc"},
    {"$dynamic_285$12e61acf205c6a170cc8a640b049f9a4d1d1997f81f14cd62e667387a4917749$3d9acbe2","john"},
    {"$dynamic_285$aeb251159dd756c4a5ac3e0c4d8758beac3e08a5c607530c437aad19d7e9360c$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_286[] = {
    {"$dynamic_286$bb969f35f2df23278116ff95bdd676caadd0f9f2a7054f47486185e21c864b23$2926ed9c","abc"},
    {"$dynamic_286$543fa4e542b4d2ada15b0cb9e8bff5ae533d219ca461f7ec31e743dda7ac454a$df424060","john"},
    {"$dynamic_286$d049ed18342b99a5a46587e6fadb1995afb7553f50334ca9d4ee3afc687f49c3$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_287[] = {
    {"$dynamic_287$d4701acf73c8b6203e404550caa98c950614f7e8cc3ea54839d310b8d771085d$621d1bfa","abc"},
    {"$dynamic_287$ffe91231d282a0b66b0089c076cf9b149af02d49f688ff3496d131fa3855b5c6$0a9292d9","john"},
    {"$dynamic_287$e65ba64d2e754e0e1ef3f9ddf017fbdb9e607a4263d584967dcc5dbf67288f47$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_288[] = {
    {"$dynamic_288$19bbd8d1586a31243f37d46efc93b0fb6a378f3fdabd661f2704b1b78c15e0f2","abc"},
    {"$dynamic_288$632e99e04780cd36c5c972eb4a125da6010364f3e12c9c1fbbf09b2836a26500","john"},
    {"$dynamic_288$d0c97e0568d450e116013cfb42d735377ed0eda62a8c7a9a9d7d58e5b6a31b0a","passweird"},
    {NULL}};

/*** Large hash group for haval256_4 dynamic_290 to dynamic_298 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL256_4,29,64)
static struct fmt_tests _Preloads_290[] = {
    {"$dynamic_290$8f409f1bb6b30c5016fdce55f652642261575bedca0b9533f32f5455459142b5","abc"},
    {"$dynamic_290$03ac26e98b562753f9198b0f1a31c30e8b2b6cde8c1baea74a61e4a7db62c0e7","john"},
    {"$dynamic_290$e0da04fd146e10adbecb7269b5a3990a0da579915ac33d6991525d0faeaeaca1","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_291[] = {
    {"$dynamic_291$6ecf6d0370044b23c0cbef732db8d98ef643a5b20d64bce8e8f5022a7d567c65$93e41c6e","abc"},
    {"$dynamic_291$231b5ac879464d71e067019447db636b96a2ce476eae863eeccb402bc3244b54$20911b9b","john"},
    {"$dynamic_291$d740d70435e035766490f6636ec3f6ab47bbf2256b602635cee99ab5925b3a8b$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_292[] = {
    {"$dynamic_292$c4ae61ca3394f4012cc45a9e82ce6e192b760ca7f4421f9e1a65e8ca7943e187$4edc677e","abc"},
    {"$dynamic_292$24bba2b69c3f01f98fee9fecd2013c2141f2f1ecb8fad64cc2f61ad426d3a25c$32d83bb6","john"},
    {"$dynamic_292$ffcb2eddadea0fb25d837850fb6b73bfbc183f9619f8349f804257c1c011789a$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_293[] = {
    {"$dynamic_293$7e8cbab4e2f4f0d8b5eeff5974153e627ddeecfc4d050592d4e7b5b3846221ba","abc"},
    {"$dynamic_293$c58b4ae932ce965ade28127c41561bcbf72deee6d77c4b82060114c7a73eceb0","john"},
    {"$dynamic_293$cbe5dbd674a21ecf76460e25045eac425b6de25d1156ba614c23e6775a9c1bdb","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_294[] = {
    {"$dynamic_294$d7ac8e3d3bb3206a557f1cd8293e133bcae289fec9e5954ee612745a956f8493","abc"},
    {"$dynamic_294$10d616bc44eb5a76634f8fbc9579d578b78a2b229963a874d0f3d3255356c74c","john"},
    {"$dynamic_294$b984685e50627a4bde7c11e90ee1eaaa88342f3c2ef023684d4388fbd426f308","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_295[] = {
    {"$dynamic_295$2050f63080e3e38c3a667f45e538d65ef400e00cc1e354b482d87d1c4a7b881a$d4bc655b","abc"},
    {"$dynamic_295$4cc5e155730f3822fcc554b8841974c4bd9f66fa23b33068c90d781dd7206e17$3d9acbe2","john"},
    {"$dynamic_295$d557246ca7667611fa57443f32ce23f6a6cb9f09214e7492101e413b7a47011f$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_296[] = {
    {"$dynamic_296$34df60fd37088efa252ee241ee56f82f7c04915a32dbac23e63b773c8413527c$2926ed9c","abc"},
    {"$dynamic_296$4b5a4b44a4d4a144386a6fda6662e335e3583f239f33e73c1362a1f63a855e93$df424060","john"},
    {"$dynamic_296$20bb9575fe778411378850daf3806b3a85563cff0d37159a027a0528a3e48b10$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_297[] = {
    {"$dynamic_297$08b3b66319af46e4eba0b29c29f13cc9a18d2536161b32ff2376d3e162806571$621d1bfa","abc"},
    {"$dynamic_297$acf24822dec38491e136f4e3920a5b27c77d68a470bb336a3d2b84ec8a0c8674$0a9292d9","john"},
    {"$dynamic_297$aefc0eebf03efdd75a52496b23d898f87404ac112f7743d36f6d760b9cf77c9e$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_298[] = {
    {"$dynamic_298$7d980dad8e75c60e5ab0093bd3b0471a167bb2df8688a10d494fc9d4b874b9d1","abc"},
    {"$dynamic_298$51914d16fb7e79cb0629745f164241628e5ae5e67ea1b64408a96696b1ed704d","john"},
    {"$dynamic_298$74c00538b032042ad26d9de38fd5b053083ee8ffcd2cc4dae341ecc6d763d93a","passweird"},
    {NULL}};

/*** Large hash group for haval256_5 dynamic_300 to dynamic_308 ***/
DYNA_PRE_DEFINE_LARGE_HASH(HAVAL256_5,30,64)
static struct fmt_tests _Preloads_300[] = {
    {"$dynamic_300$976cd6254c337969e5913b158392a2921af16fca51f5601d486e0a9de01156e7","abc"},
    {"$dynamic_300$6a691d78298657f9c21946da14374ccf7e30bc795afa0ea672f312515255c18f","john"},
    {"$dynamic_300$9be7ad5564fb60bc26faffdde707c38c5fe68603a780651c9f8b8a8a4e06b1e0","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_301[] = {
    {"$dynamic_301$2c89c1ab9b43b0fada3d53975399c07e7a98ed2e45af90429f731a8b2038fdf4$93e41c6e","abc"},
    {"$dynamic_301$8396ae46a31e85f6768165d33c06ad6f48c9d4a784c8e37fa07940899dd073d4$20911b9b","john"},
    {"$dynamic_301$a5d67ba2c8e09f085e920c4b140fb6862d62ef9d5e9181aafcf1d61cbc74eda6$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_302[] = {
    {"$dynamic_302$f344dec579f55b9e9bea9f369a639126123baa6c9ded6fc0684ed7bed846b215$4edc677e","abc"},
    {"$dynamic_302$2398fafd6e8f64b559393706d994ad775d8b2c75f3d9d60dcfe2fa130f3d71e5$32d83bb6","john"},
    {"$dynamic_302$ae42377e055be504d73ed0fbcef71cd19ed7dfc677465aef4603c4d60c459de5$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_303[] = {
    {"$dynamic_303$fc56fb488da4f820a8b9f78a51192a1cd4a45acbcafce8311c397e897cd5c7f5","abc"},
    {"$dynamic_303$4714f647ae2c208f35a36d6486a9115bacae7659a26a2b174b497614bcd34f03","john"},
    {"$dynamic_303$0e20e0a161999dc80648b7e90b090afb27a54dafff888c4ee757cb60719df873","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_304[] = {
    {"$dynamic_304$1edd56f0eeef99d42f52fe5932551d01a96f74f72b6d6cef1b8d16df72dda29b","abc"},
    {"$dynamic_304$89eaddea5890340bdf9affe6d1e7d187cf6614693317a0254f2c20b2a0d3a172","john"},
    {"$dynamic_304$1863e0cf5bacfeaa1dbd3eae292a729360b099b4f7081c7fc712a1139f078cae","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_305[] = {
    {"$dynamic_305$e7b44b237f69c727adaa1bdc862f4a3c88d170d0b554f70b46e116af2e871ef8$d4bc655b","abc"},
    {"$dynamic_305$6a0d54b9fa4e0393be31245aacf179dd1ebf2e1c2f4f54141228b494da6a5f20$3d9acbe2","john"},
    {"$dynamic_305$586923c77c9b76a64dc276c744481384871d630d82738f4a8ad17ac711cf5eb6$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_306[] = {
    {"$dynamic_306$808e8faaa8d99f3520a339a3ff50f25f8cbebe48dd50a0951a1021df37f10eb2$2926ed9c","abc"},
    {"$dynamic_306$5bf64e0c282285b64adac3ea81a212d95177dfcf4025d0776f23fcca45294658$df424060","john"},
    {"$dynamic_306$9041d147e04fc127aa29e06fe900c25102981dc1703614fbcb13f1931b16ac95$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_307[] = {
    {"$dynamic_307$9b92b43513358bcd99cdf893199aef1f3e2c065576d2aef1568ece96ab165824$621d1bfa","abc"},
    {"$dynamic_307$a5ffe778a6e48841f300f1f45060be63c93bba20e1b1bf7b675b5706bce6f66b$0a9292d9","john"},
    {"$dynamic_307$563958c26f81cce08904509db39e1119e50a679c1789b7f78e3dea4e371cd3d1$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_308[] = {
    {"$dynamic_308$cceb64712724b814717c865e43ce34bf01d5610f9bd0f3171b60a7a1860a320c","abc"},
    {"$dynamic_308$2c8b036c19f6d492c10fdc08141da6f5b5483d62fd7398f25c4c80502e3f7daf","john"},
    {"$dynamic_308$7de20406c1cecdf31ba4b2869f93e6881a428fc378a12c38f98f25baa5992853","passweird"},
    {NULL}};

/*** Large hash group for md2 dynamic_310 to dynamic_318 ***/
DYNA_PRE_DEFINE_LARGE_HASH(MD2,31,32)
static struct fmt_tests _Preloads_310[] = {
    {"$dynamic_310$da853b0d3f88d99b30283a69e6ded6bb","abc"},
    {"$dynamic_310$8b2daae3b7faa890168cf89d37ac1145","john"},
    {"$dynamic_310$4c92ac300da7abac2ae3e5dfa72747b9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_311[] = {
    {"$dynamic_311$201ab10fdfaebcaf9d413421ffddff71$93e41c6e","abc"},
    {"$dynamic_311$74036b09c14e9f6c6d2960f03413fdba$20911b9b","john"},
    {"$dynamic_311$15cda5c4267071dc4b90f3d78f1999b9$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_312[] = {
    {"$dynamic_312$fcfd934bb9e5fceb79fd23c4b4acca70$4edc677e","abc"},
    {"$dynamic_312$50c6484b828686f11b23539689f3d289$32d83bb6","john"},
    {"$dynamic_312$5beec103932e8562085d35ab99664b7f$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_313[] = {
    {"$dynamic_313$d0a46dadd25a94feb62b13bd28b9796d","abc"},
    {"$dynamic_313$3841353c3e20178634a57a1202005582","john"},
    {"$dynamic_313$23ce7c2b464fb4fe2d3c08b9d0702bfc","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_314[] = {
    {"$dynamic_314$fad5f475815318232a96748d18de92ed","abc"},
    {"$dynamic_314$af77e3e193c146ee432ec3901c73ea14","john"},
    {"$dynamic_314$ffb4b5ada8c59277c22b65237c434f99","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_315[] = {
    {"$dynamic_315$f9becab53308a164972a3834397f09bd$d4bc655b","abc"},
    {"$dynamic_315$7fada1e90a9c81b70acbf4d15d23b16b$3d9acbe2","john"},
    {"$dynamic_315$af55679c0aa3967e76a7fd2a720497cc$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_316[] = {
    {"$dynamic_316$731ca636968eada78a5417e2e4c2c55a$2926ed9c","abc"},
    {"$dynamic_316$6e53368b83dc6ec4500d6fda832d675c$df424060","john"},
    {"$dynamic_316$b0b2070bdd0ad08dfe6506e309ec8db0$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_317[] = {
    {"$dynamic_317$a62b2e66f91173d123862667d531af41$621d1bfa","abc"},
    {"$dynamic_317$eaf4a6e8f5a85228e6655ac5f3fbb6f1$0a9292d9","john"},
    {"$dynamic_317$d4136ff1a6d3c101c6e2083240dff5d0$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_318[] = {
    {"$dynamic_318$b47f97846f2881e024eadd13d6071a3a","abc"},
    {"$dynamic_318$20a39b672ce1bb7c9a5fc7012a09ff64","john"},
    {"$dynamic_318$c7f378fbd3eb87940ebdb545b008116a","passweird"},
    {NULL}};

/*** Large hash group for panama dynamic_320 to dynamic_328 ***/
DYNA_PRE_DEFINE_LARGE_HASH(PANAMA,32,64)
static struct fmt_tests _Preloads_320[] = {
    {"$dynamic_320$a2a70386b81fb918be17f00ff3e3b376a0462c4dc2eec7f2c63202c8874c037d","abc"},
    {"$dynamic_320$017686a23c4af3b9c074888ec76f893945d541cd17ee8011b2bd0ee2d581db34","john"},
    {"$dynamic_320$3919248ab4c8dea4843663c532db9823169a71d03b0f918082c9f53748dea1e8","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_321[] = {
    {"$dynamic_321$eb30e869f289cc6afa5e9e5717135669512cb7161892a6ccbea2a2fd6e7a041f$93e41c6e","abc"},
    {"$dynamic_321$097d55bfee109333db2b1204890251ca034bb6fb953a7628dd7ece142d8c677c$20911b9b","john"},
    {"$dynamic_321$5602de363742b73ac0815672bacf161e5baf772b1c7e1ca210a2bdaa83c25782$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_322[] = {
    {"$dynamic_322$a3d04ccfdb8c1b34b1dd4532610398242876b8d56180e352d00e60b12179433f$4edc677e","abc"},
    {"$dynamic_322$9960f81ed812d012dafffeb9ae771238cd803625489b01128d7b4380df1ebe44$32d83bb6","john"},
    {"$dynamic_322$d725c50ddfadd68cf1d3cb95d8ce9a16b19689c372fa0439a27025b0bffa8344$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_323[] = {
    {"$dynamic_323$053ae91a95d18c8434bdd6994a17760017985af325ba4cc7dff6966dc8e145b8","abc"},
    {"$dynamic_323$d2235719502f655badee66a5034de4bb5b1cc2e607dca022bed7904b7bc66ee8","john"},
    {"$dynamic_323$b41349532b0e1bb09f04d5e110c716cbbf1bccecd79297b0da1536fe96cb8e88","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_324[] = {
    {"$dynamic_324$63588871552b21f15ef16f78f551e2be1bff2bd2847884da0d0bc2b419931e31","abc"},
    {"$dynamic_324$0ab23a46b2744696756512100dc6c6428a861dbc58cb093e055df0b817ac48a8","john"},
    {"$dynamic_324$a11099fed51a5389f996f39950df9a61982ce2e41cd1ae924c0375a9da02dbd5","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_325[] = {
    {"$dynamic_325$8c629db146934f8e64a33401e278862caf2970e31305964ad0eab19debc85be0$d4bc655b","abc"},
    {"$dynamic_325$6f76e56e34daabfa2062cf66e10e5b1378ba25801cebeba04a4d19077494d4b7$3d9acbe2","john"},
    {"$dynamic_325$50e3e96a23bf46ba68cab9256f3568dd76941b8566cb874fd9eb8b6b06ff7b71$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_326[] = {
    {"$dynamic_326$d1ecdfc2b8706c4de3fa0836676d38bffd26651760bdcc7887980e1433abb7bc$2926ed9c","abc"},
    {"$dynamic_326$01396cc960f08de0effb6ef9d92b6a2e4a83504578998e4b0d6ca0b996cd2ac0$df424060","john"},
    {"$dynamic_326$bd540a932cc8a96c1740be1527cac93adf24206d97e5d04f2c52d0ee06352d9d$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_327[] = {
    {"$dynamic_327$7f13e55a564f648ef7236afd696ab8758cb48fd1d5db9fae06ddf59583c34a54$621d1bfa","abc"},
    {"$dynamic_327$294402122a5203d5d9d60302e2ee6a0e70ab4140837e908f9bd141e4d6527a4e$0a9292d9","john"},
    {"$dynamic_327$fad704b5a091c67e2f732d3bc8e0452cf7708fd295f523b0ecf0d1a549cffe17$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_328[] = {
    {"$dynamic_328$d2d5257417b423434fe5889cca489bf62059724b0efd75a6fca54250d5041a01","abc"},
    {"$dynamic_328$713c5dbe92054cdb5834c6106557285bb085b13d3659bf06cd1e2155037ac600","john"},
    {"$dynamic_328$61b426e79d5c9eec7dc2198ff41bd15e6c50e395e4d8564bec4d3cfd8d96e555","passweird"},
    {NULL}};

/*** Large hash group for skein224 dynamic_330 to dynamic_338 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SKEIN224,33,56)
static struct fmt_tests _Preloads_330[] = {
    {"$dynamic_330$0c71f7dda7e1fb752544c93e821c2a0a1f991a694db5f60fd48de904","abc"},
    {"$dynamic_330$0ee22811766234259bcc3086f5a43d004f32e475ad83e4d5d1fe7d81","john"},
    {"$dynamic_330$e86f1c07ea58725fbe43f60d93675836fb368fe7b11840bb967e6963","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_331[] = {
    {"$dynamic_331$51716e8a1fa9b815e3970d7371af36d89c6b2737d0fbedea072dc93d$93e41c6e","abc"},
    {"$dynamic_331$d5ecf9f782d05ec8d8288d0ff2ae63af75ea67258abca774159303b8$20911b9b","john"},
    {"$dynamic_331$fcf85f2311a464f8825667d3aabedf1881aa1631d3eb3990e55a6fdd$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_332[] = {
    {"$dynamic_332$4e328fd97d54b5f693cb9887c9b0204ca41cc93e2788d7c918c4f6e8$4edc677e","abc"},
    {"$dynamic_332$271e6dac536a807a510af4a98a02a47093dbdefefd702bd3e4765e8f$32d83bb6","john"},
    {"$dynamic_332$74aa239f542a89ab9cbd94eb3cd23ee2fea7314472e3a969d7a770c1$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_333[] = {
    {"$dynamic_333$b4da8bc772b8fc9df3fa4aa10f6519f82dcefdd7f3bde8f3d05fb4f9","abc"},
    {"$dynamic_333$bebeaaf7d99657c6194178e1222bac6d32814a2922749c48d38aa885","john"},
    {"$dynamic_333$76d82d9ea349ca65d96cb56ca11222599e152d02d5b9200a2a8d1013","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_334[] = {
    {"$dynamic_334$b07543ab3b03089af70ae0a9cb5bc4fe61a2ca19c35e67692c31072d","abc"},
    {"$dynamic_334$f91893ee6bf4d96df59373f1c98aed00aec148317bee028ff5172198","john"},
    {"$dynamic_334$1ed4a50c24e9b552ae6b2d2c4423fde4557b7807b769e2a21d049f01","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_335[] = {
    {"$dynamic_335$1a892e23754d48115ce91ed5385b0ac21ffdad2d0ced54db3545e96b$d4bc655b","abc"},
    {"$dynamic_335$3bd6ca426396b0fff497ae6cb8ae435f5955cf8b32796a06e6820c20$3d9acbe2","john"},
    {"$dynamic_335$cb5ad0cbb8bfc2ba875732cb274eafc27d79cf7ae16afdb2ba53736f$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_336[] = {
    {"$dynamic_336$67def28813361c534a6fe2ee07975b34af1afba7585470ea44401fe2$2926ed9c","abc"},
    {"$dynamic_336$f451a55edae507d1d093409c2758c97d10b5cacfbc09f923ae9ebc68$df424060","john"},
    {"$dynamic_336$0a9c7c9ddc850ef4e975d4168dcee2143ef6799dced5ef274c16cdfa$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_337[] = {
    {"$dynamic_337$af98852dfdb711b1749805674c9371c4382b61a14758774113e135b5$621d1bfa","abc"},
    {"$dynamic_337$5886d40137a589800cbe65e48912e90a7d71de9b013b5c7ba59ac395$0a9292d9","john"},
    {"$dynamic_337$69d1b151a3c22f3b376e00f7bd951afc4cea0908ca946baf24427e6f$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_338[] = {
    {"$dynamic_338$a6ff151f176173c2b1d842efed347ae9dcdf649543639e269875435e","abc"},
    {"$dynamic_338$58eb69c4050158ba334fc63fb743983088e490d578846cafc67011f7","john"},
    {"$dynamic_338$bcbdf76a99d93a7cb7a1f1a4cb014dda759cf7bc1306af0c4109bc35","passweird"},
    {NULL}};

/*** Large hash group for skein256 dynamic_340 to dynamic_348 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SKEIN256,34,64)
static struct fmt_tests _Preloads_340[] = {
    {"$dynamic_340$0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527","abc"},
    {"$dynamic_340$8adf4f8a6fabd34384c661e6c0f91efe9750a18ec6c4d02bcaf05b8246a10dcc","john"},
    {"$dynamic_340$f2bf66b04f3e3e234d59f8126e52ba60baf2b0bca9aff437d87a6cf3675fe41a","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_341[] = {
    {"$dynamic_341$0175249ca6a8dc0fa3508ea4acf24f55d76aee9cbeb1dfce805a512b5f720c32$93e41c6e","abc"},
    {"$dynamic_341$6e523217af0435673aad98480bb48f5ecf4210568bd5ddb8bbc6649a38a018e6$20911b9b","john"},
    {"$dynamic_341$fd7786d4569c163128623b148ba6ca0a28f85ae86e9ff1ee6afb8f2da5a58dfc$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_342[] = {
    {"$dynamic_342$df366c0cd0b05807df0ea15bd22714a21e91c7e16798d7bc65819dc30027e579$4edc677e","abc"},
    {"$dynamic_342$d2d249a9e35fd310f7847355a8a805345855eb508e61c58291c6a9d180640402$32d83bb6","john"},
    {"$dynamic_342$e0ececb8e19b16743347b531936aa4328196312f6570dae1845f1adac9b3f8df$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_343[] = {
    {"$dynamic_343$b7e95a973ee079c765b76192a76270f5f272ce7f0874f2adcebb741b3ae78a19","abc"},
    {"$dynamic_343$58d10a9a049610e822f85d13e609e7cb08950e48c1fba47f2dabe61630accf9c","john"},
    {"$dynamic_343$e4ad91bde0bb3ba6e2d148f9a50ea7f9b41eb2c725ac4010f94f0d2d9a90c7f9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_344[] = {
    {"$dynamic_344$9bf9d0760c6b7b1c3865055590dbade8b8e06d75feeb1f851ca4d228be2f6416","abc"},
    {"$dynamic_344$e3cc7a46027087f1b32d9daad3b6d581c15192963d9c4fe12f862aac894d1b74","john"},
    {"$dynamic_344$db01fd692f5c983577397a32a1a6a733289b1f0a191f5d03946a1848efca70c9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_345[] = {
    {"$dynamic_345$7e566eb5627fd15a501439f39180f812d291612e37212fe27941327a511a80a6$d4bc655b","abc"},
    {"$dynamic_345$0bc38db13f8f27fc2b00d4637ea859e336a61548494a84dc0577dcbeb7868640$3d9acbe2","john"},
    {"$dynamic_345$c850e795e945278c18f0d135f1486d667a669fc69714a26ffa5bb310487a1003$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_346[] = {
    {"$dynamic_346$63483eace39579bc02414485ae267e8d3bc4c6a18358b386fa010047f8a116ab$2926ed9c","abc"},
    {"$dynamic_346$88cc1f39a1c4b6c09796270d126cd78d3b08fafbfbec17591ff23b819eefe33e$df424060","john"},
    {"$dynamic_346$fa256c95bd5f5724597664bf543f28d4871ecfe81ff14081b785a1d8a2769691$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_347[] = {
    {"$dynamic_347$a233b796c3f7810583115b8cf283029993891d676ef210097cfa87714487ac96$621d1bfa","abc"},
    {"$dynamic_347$c44250d607b6160c631f87a8dfad7efa0f292ca5b7f8350fa8bc8f3d2c63bcec$0a9292d9","john"},
    {"$dynamic_347$f1387805c89f250dc55e4e08e3aade9942b5b10771687721926e0bd9ce41fca4$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_348[] = {
    {"$dynamic_348$8098fee181523f103d0675c9f207148b6a0d739925dc4a8c1718197f68e14b28","abc"},
    {"$dynamic_348$42feee6365f76dec4de2e7dfa62261add28813e523959402fc3687158e32dc27","john"},
    {"$dynamic_348$1eb77fa3bdf4f46ac23858752fd1e631fa64ce48afef9de38a9fd6bf7e6510eb","passweird"},
    {NULL}};

/*** Large hash group for skein384 dynamic_350 to dynamic_358 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SKEIN384,35,96)
static struct fmt_tests _Preloads_350[] = {
    {"$dynamic_350$b4329745321c8f6b788a04526dad856b4a87f510ee496b743f61b048209fc3261c1ebbb8a35040a7ff58c34378c4536c","abc"},
    {"$dynamic_350$a76de4157d3f7bf373566973c75845e7397bfe98856531186f50759c3b226fa982a42aebf60e3b2afb5d6e03d601d44a","john"},
    {"$dynamic_350$40fce4b7fa45f29c4737771e6dc26508edfca01f65f6afd589178f9991d9f7dd90da3d18d77c849faf6e9949dc54c141","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_351[] = {
    {"$dynamic_351$11bef39dc2a4251024b43c125082f74dbc72e1a2e95fc8e8091ebd1398a8758839eb521495cad2b95b6f2c896771731d$93e41c6e","abc"},
    {"$dynamic_351$e52b73cce582df4f9e517eea1397e4a06363b1a4b089fcbdae45a81d306bf4879e30e4aa104528e643804063e6b1e9bf$20911b9b","john"},
    {"$dynamic_351$17ee66fc76d40028b003af1e0b750a95173e57d14a6d02107e538128fc0344183f3c8f5b00088de3d48506badc1150c4$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_352[] = {
    {"$dynamic_352$b08f64b3a3ab3d5303b0f19ee42dfbf86eb4fd79957b088b9cdc7d98b964ff40f26565bd8c313db3cc1750187f230475$4edc677e","abc"},
    {"$dynamic_352$97b7854e9cdac36b322e081ebb51eefc0c07beb4f84f36b838ec4b71864a10d92e3bbdf8edc89c65ddeeb2f71a511398$32d83bb6","john"},
    {"$dynamic_352$3d2c4be7f4f3ac48e6239a5f20f8cd673943a23642b047f30776eb4151b699997404acd074f675b37818e1cae9a109ed$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_353[] = {
    {"$dynamic_353$6abd3c1d1662aec380d4327ad445d899929ccdc1a3d722877fe5eb428684afef4e57280bd688fe66ff248024f9cdfca2","abc"},
    {"$dynamic_353$3a4ee0fd505dcd6d8d258b3729b59c901f72d70639c0020817f61b427dcb68792a19c049db4a8d4734e442ccd275a995","john"},
    {"$dynamic_353$ca90a0d690ec3a556bd938c8a83886c444829d5ef6d9a2d9931f7e99b30a64c740fae57e12bc5456ae05040594b0defa","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_354[] = {
    {"$dynamic_354$aa12c875f5ec957ff6b0460080458d2b9b31e9c1beb77e2c7497c5ce763ccec4386932494c761b2e2705d2497dc28efa","abc"},
    {"$dynamic_354$4b845d7e7890d40119d44f597a8c7317a2a3a248305537746c5f4ce6f8262537ccb74d03176c95df4bcba7218cda7891","john"},
    {"$dynamic_354$bbd949217db03512660aa0849ec7acab93405c4e9582eae5469aa0327120d21e4b1705fd75ef88e23a0475244ef4f197","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_355[] = {
    {"$dynamic_355$45117441009fe83568cdc671c08072ca4f926f75ca575799272627125c082000ab5fe10218e2c92039e19503d4cf2fba$d4bc655b","abc"},
    {"$dynamic_355$5845a7d4fd0f08f9f7835057b0e3dfbbe77a0f75f8e1478b44d916018bbea34aa2a1c984bc8bd7bb6bf1d12c5729d34c$3d9acbe2","john"},
    {"$dynamic_355$0f411c5c4fb0b249cc151407ead710eeb5348c22b5fa3199bbe2ae8ca7640da72c95c0d24ec9c92bb5083b027d209a57$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_356[] = {
    {"$dynamic_356$def45cfda1d49f1b76708aaa3bd4011da9f5467779356a152f29eefa137157349e0302835c3014378c2d928864d80c50$2926ed9c","abc"},
    {"$dynamic_356$6a364fc2835d7378ffcc8f7d65ab56bc7eec150e686105adfe671097eed15797f51e7617d704cb27ffd79563c95bbca6$df424060","john"},
    {"$dynamic_356$31595e31e454c2ba456d66681b64ace605fba2fff6d24ac4ef3e2729b210551aa56f16b5cd01771102d58e1d2b813307$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_357[] = {
    {"$dynamic_357$c31e9c22a468869eb3779cdc07e1aa035e2228562a09225dab6f5c356864cdde51bd3e9f89e146b3be51c5f0f6b2c7dd$621d1bfa","abc"},
    {"$dynamic_357$35517136ff5c65c085daf7bbd2523e59e1b9e1c412c369076e08ae79624eb57cb15df0e3dbb620ccd8463ef7c69c1eea$0a9292d9","john"},
    {"$dynamic_357$0d01613f50b857c5ed3181c577567f66f8a2db21d0c172c312dd042fb15dcb5bde3526b281ef563b6766a76d4aeff809$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_358[] = {
    {"$dynamic_358$3dc891be7783afb77f538b783267d71a8dc3aec25b3475ea1ffd1b370abb9a53159cf36ada8a5d247c99e9e3940aad82","abc"},
    {"$dynamic_358$a8d3dbfa2ad67be122d6b97ef6bad469fb899db92a16d26da1b2f6ea6bc51a07871a825e8ab3aaca2ea8b170b4aeedcb","john"},
    {"$dynamic_358$5745788e3eb79c6f6b6f1df48a540a75266cbf7497a0732f22611882e4f22b5358dc604375ec553d1920c94b3322ff74","passweird"},
    {NULL}};

/*** Large hash group for skein512 dynamic_360 to dynamic_368 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SKEIN512,36,128)
static struct fmt_tests _Preloads_360[] = {
    {"$dynamic_360$8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f93893ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75","abc"},
    {"$dynamic_360$a2f4cbc67def0c97b3b47deeab86e116293db0220ad9953064d40fc4aeabf243d41040efb4e02b4b4883ae19b5c40129926cb5282ad450e1267f126de40224b7","john"},
    {"$dynamic_360$88fcd3b1d6b019c74b8853798b1fa7a1b92314748b79d4a8cf822646104b4aefedb7af721ec07bf1302df031411af55bda48d2177a69537f3e0bfb5d2fb1d656","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_361[] = {
    {"$dynamic_361$de0cdac782c94e8fb0bfa1a1e37881af89bbba100bc0d6b05a79f322115bd5b4c499b372c1405d185e723f3fa7a9be5462922800b67a78fff571a9d805e15c25$93e41c6e","abc"},
    {"$dynamic_361$fbf7a2c648e0f86d008586a20fb93d7b837688300bdfa7b8b7af8ae63f8d32fb14e81fb7341d9cb68c85d9712b8775a18f28910e5499ba0ad425b2962d2eedfc$20911b9b","john"},
    {"$dynamic_361$bbd516b7ae0199d5e123541242a5f424f10b01b744f99873255ee7bc0e2e03ca372786c7b3c822d54a30b1d662c7aef2debadde756680869c68b6dc54e946ae2$36bc7ce9","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_362[] = {
    {"$dynamic_362$a218baac56167e067eda090215bd9818f13d9d06ac6f5f9edcfcf021059eaeb3fd10ddd3680071b1184bf9bbd83efeb5fede3ee97c21afd249b069929ccb5694$4edc677e","abc"},
    {"$dynamic_362$891a51c2fe34be54fc97e8f009e3c37ac243f24572ecbd2d6631a979fd4a14dbe21b3ae8ec3fed658cf387b64d7a69d3ec9f74f44056ea9f63f2919610f0b4ae$32d83bb6","john"},
    {"$dynamic_362$c4fcd52ed072f74fa39eff1820162c48ad0ccf2b8eb0ec79a632c1d841e39792a6b86fae4fb18cb9bda99d180423b3748e156f87dcb80e9dcbe93159974c6eca$f3ad985f","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_363[] = {
    {"$dynamic_363$6011f8f10461d74660410453a128b28de21fdce13522e465cc7e26ce510290ff7cf48be989aa4c711af73f2be61decfd970206891c065314170c7ffa3a40511d","abc"},
    {"$dynamic_363$7da2cd6e212bcac60f3cb8034afbe99441556248edd476ed9d1c5c545fdb4b282b5125b452c17976876902186a0bffb328e45b3c03780b7a7006d187e536cef0","john"},
    {"$dynamic_363$c755ad8b117d07565e49093aefe1ea5cbb280d1b7e1233dc76b67d28e32761b8dc27cc1866ee33782ae13a3a11cb2e1789d6971536c2c31d5a64ac4103409c80","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_364[] = {
    {"$dynamic_364$75cea5c7289168210eb105921b13f5cb499952b3aa2d35c09520667e2e18a45a713aff316acbd892bd0ca30725d087c4a2ce2b64f3b5552ff35b4f45d1caedc1","abc"},
    {"$dynamic_364$9056543c9822504c64f6063a6ca2980fcabfb36d197fa10fef855e7bf7e366793ab17fffd4e8c484a58df2ec2f70b87f9d3224931f05030d20cdf03cfc05b928","john"},
    {"$dynamic_364$53dc4a45f20be108a5a84a0de2795a7b32860501b92517bb19d516cf407ab4906c581b9cb6726e74b0c666b77a64bf3341d44cfdacf1e0f517a0b9894c09115c","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_365[] = {
    {"$dynamic_365$d6ec9f2a4d6110000338ee8a35b4234f9d093351b19eebe17b0302a6f70f814d3a8d06af86946240ea1ba980b51ede33834185f6ba2f7df4bc8a0819f4532efd$d4bc655b","abc"},
    {"$dynamic_365$6e53cbbb333e6222ccab83285e7d8d2fc2a155531a3e2abe057d8befe2bc3fa44d2d30296ff48ab39ba4471c2934fb8314d9dbcb51487c1573439534420838c8$3d9acbe2","john"},
    {"$dynamic_365$ff649ab3257f4e44fea8a6dfe1ff8ff48a8467a564eae74d107fff539a53a3e34ec893559b58badbb2253c7f3d8f85b8cfc7cdfc748927552fe0b19aea7ce34c$0a0e086d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_366[] = {
    {"$dynamic_366$cef0c4a13c8aa3101fe103d0ce3c18899b5285bfb88c2259d9dd8fe635fe6c31baf97918a3e15468b3d02bded77c802cf557d4c50ad279238bdbb4e2e78827a2$2926ed9c","abc"},
    {"$dynamic_366$6f986de865a5f984d4b9b9f43ca7a503be504668e24855f772e04d7dca26af944ea2b3da87461a99bc4445fac6711c505c97ca22a89cfe7fb4a58ab4b2daaba4$df424060","john"},
    {"$dynamic_366$076053f2397aa3fa7c87e76ebd3cfcd79668a038273c61ec2a914e2fe9c72bbe72c568cade34318f9db5d69bc59e6d6a4a6c07fe101523135205b9a8d5c46837$b4072b12","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_367[] = {
    {"$dynamic_367$d7c9b1e057b079b2838f8ba429b3f8a08b18d9dd3f4cebfbc07d029f1145f8b60315e138b6e3dc6b3dcd8e003bbe8c7c0e6ab44d890c1b28b669958d2e53cf19$621d1bfa","abc"},
    {"$dynamic_367$949085cd3471def796242af6313a21c0c980f93db1905321634f813276d77d1a3b7364269f33fb8306f50582b6707ddf91646babea5f0612f00cc69e729b3c26$0a9292d9","john"},
    {"$dynamic_367$0950b405c04ac09e98edf9bb5487b20ccaef9847f574ca2970f5b152dc4e848248ef2f505d15474ec17d9a350e44e8cf580bfc9f56e441ef31749cc939fea148$c0e59590","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_368[] = {
    {"$dynamic_368$97419b932e4f31425a14c6b4246a5f55238f532bde9051997b1602c6997c3195f55f936451d83295a0922bbc6b65976ca7a1b56708956f1d114050ba9569c55c","abc"},
    {"$dynamic_368$ac159f594c2a8551300ba142918d1bd00b1c6ed1805de16ac5dc0008a8614e056c504c44fbaff8f4cad80705923eb416c92345c0b7f3d084a39c3ebe8609705e","john"},
    {"$dynamic_368$adc4ba0c2266513b97222409c04d00acb7e77b7cfc2b518218a5b7c49451cb0e8bc35951809b1bd116ffcaece3fcfc3d7ea04f7fb7e4bac92216702acb324b18","passweird"},
    {NULL}};

/*** Large hash group for sha3_224 dynamic_370 to dynamic_378 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA3_224,37,56)
static struct fmt_tests _Preloads_370[] = {
    {"$dynamic_370$e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf","abc"},
    {"$dynamic_370$d0ee234a67aa36ec9a12199a708b1e70494ab9ae4a5d5892a7582bf5","john"},
    {"$dynamic_370$02b3de87c02dce7ffb10394cf034a39c7d71e546fe4e915a8852b82e","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_371[] = {
    {"$dynamic_371$8ea3b462a8c97cf38939a6263cb7b98d717b99e5647803ce74b2d72b$df694488","abc"},
    {"$dynamic_371$32c65675ab72395587a05392027ecd61820e524b881cb586f4e98352$87ffb1c9","john"},
    {"$dynamic_371$7271c50c19bdf5b540fa50d6cda76fa9a1dff58d5543eb3e7935d505$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_372[] = {
    {"$dynamic_372$f5e41e1125170912521ec07c7b15306d66fedc7b6d8b35d73f43f4fc$4f58497b","abc"},
    {"$dynamic_372$87b57912aaa3defecc1bee60a629dcdad083c1e4cfed737a8aa8b644$e0b88e64","john"},
    {"$dynamic_372$117479e04cb805a6a40b531519aba8d9a7c538cc30ab835f54faf06d$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_373[] = {
    {"$dynamic_373$ef958759593fdcecc8b4fce78701b4d22983adba34c5da9ba9807268","abc"},
    {"$dynamic_373$bcd4c682bd9d794f48e2b2884488caa890b23f514904394b3f32f81b","john"},
    {"$dynamic_373$b8af03f35f51bf9c20d75e63b467178f704e2562b0c8e2641a149285","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_374[] = {
    {"$dynamic_374$c18edd254284eee2ac9b82f293cc6a535f66c21059d49074f29361cb","abc"},
    {"$dynamic_374$012aef01ba163115a6f6058147a3f847e435d2663d4af5726bbe9526","john"},
    {"$dynamic_374$3980df515498b7558886fd37e6ee62dfbeb02aca58bda2e11c550985","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_375[] = {
    {"$dynamic_375$9a40d705e0bc0d30bc45e3ecafc9bb8bc3ceae78a7ef78ec97f66648$3be069de","abc"},
    {"$dynamic_375$fa5f84cdd0bd2d896320525df165b5b3878ce7aa22ae67267d9cc4ec$76f68854","john"},
    {"$dynamic_375$d6fea38aaf49ccfb4a5c8243d75b7bc5c18f8b13d15ce5cd22b2c657$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_376[] = {
    {"$dynamic_376$a4b6e8ac4be0b359ea1bc52fb55b4465284bb38b4e650d759c4a9b45$f17f9849","abc"},
    {"$dynamic_376$5488c18e84d2deddc53f9ac1fcd55c170f8ce7b3e987c08386a02f76$c855fad2","john"},
    {"$dynamic_376$6eb6c089c92a48e80c316fd5525d8869eca7bd25724028a96e1a2746$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_377[] = {
    {"$dynamic_377$46d53efa18ef9e6c73d71d85b921a605be1325132eb5ecb3208eb821$30bb3a28","abc"},
    {"$dynamic_377$525b39cc05395c7c14c989b52e59b2bfbb1391ffd24826f4f9581843$49e02b3e","john"},
    {"$dynamic_377$71e4ca188c666c4167b2d6942913d8ad7f412ed56aa7c890eb02dc5b$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_378[] = {
    {"$dynamic_378$96764729f0cef18848b46aa9ff40fcde47f579aca275e5dfbb140302","abc"},
    {"$dynamic_378$14d4b1a67a657584faf7b1d5a26b83540299b8418dcd868e8edfeb7a","john"},
    {"$dynamic_378$eae0898cadf20f4b8600d64193d545b970aeaee7fc74afe3d2401615","passweird"},
    {NULL}};

/*** Large hash group for sha3_256 dynamic_380 to dynamic_388 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA3_256,38,64)
static struct fmt_tests _Preloads_380[] = {
    {"$dynamic_380$3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532","abc"},
    {"$dynamic_380$7a6b339492a1fbf446f53eaef2231cd084ec4d93eff9e53f946ab5cb06ce926b","john"},
    {"$dynamic_380$3b47fe80a0628cb61075874bce2e3c995a58afd95d305b6007c8de834d8ce18e","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_381[] = {
    {"$dynamic_381$50e1f3e7fed9c56587ef9005a0c091881ccc7f29cffb17a50d529a9315f0c8de$df694488","abc"},
    {"$dynamic_381$a81b0e5343b7b64e7df7f352b1844950de6fb394d54c6dd9345118a02ea50f52$87ffb1c9","john"},
    {"$dynamic_381$912c6c8640f1e53b459ce9bbc9b8ad58dd3c36e139f296f53e68c67ac7598aa8$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_382[] = {
    {"$dynamic_382$d9a072ab23946c43fd9dc5e6dd54516cba0ddd648a7e1407d810b2d29613ccb7$4f58497b","abc"},
    {"$dynamic_382$ec06d94847fe73f22eb1fac5e0cdbe8ca3b21dc9bd2af61f8cd1ab1547fa3bb8$e0b88e64","john"},
    {"$dynamic_382$43d7ed6e1081013d52a807b048639fbb353ae4a0da8f97ee0b45ab29b5aff5d7$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_383[] = {
    {"$dynamic_383$49a87f9078fe45b5fc410eba4562cb9f23ff7acbdce6793dc1772d200ca1fdf3","abc"},
    {"$dynamic_383$44651515f29a59e163b669eb53392f51bece78a3ce41c5c301f40b05479cd484","john"},
    {"$dynamic_383$50bbe009f8873dc4ac42d230908da06012f081bba91d2dd88785208b38d8f1db","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_384[] = {
    {"$dynamic_384$f6362cbb9fb8a60f03c2f0d8124d2c6a1a828e2db8e8b05a6f699735b4492cbc","abc"},
    {"$dynamic_384$dd1f19d13a5e4214731995d0066c908235f43720d60ac2a242cd79f9fd8a86ee","john"},
    {"$dynamic_384$7f83552168397b2da29400b7385b55a043a6c9b90e2cf61e0299f7b702eebd92","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_385[] = {
    {"$dynamic_385$b99e665b80b801243cd0266112d541f10adf5de38135c85d3704e34550e783be$3be069de","abc"},
    {"$dynamic_385$b49a78e80dd743ee248981197dd4a7d6c805fd001bf8fb415b938306eddcac1a$76f68854","john"},
    {"$dynamic_385$7765d869777372badd63a516fd382a6ffaae93ed1412634d629f46b77dc72086$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_386[] = {
    {"$dynamic_386$8c3d0bfa5093e4aa8d6955a986ae8faec01541458dab0bdfab6298d70794ed9d$f17f9849","abc"},
    {"$dynamic_386$4d81f05a02774ee013a6d44dad4e2fbb9f563b19b857fc8ee6cfe127fb73127f$c855fad2","john"},
    {"$dynamic_386$94951bc26b3d59a26b8f4fa01ab46a92f34ec8673b70cf46e161b3671d1ecb26$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_387[] = {
    {"$dynamic_387$094adb48086e7394292bbe388776d5a01bda4986d3f7f8d3b94c953c6375909f$30bb3a28","abc"},
    {"$dynamic_387$c04e23bc29dbfe9430a749b94e37f071d30354ee48cc9b4b6d79221924628f15$49e02b3e","john"},
    {"$dynamic_387$cab36637f1a557cdce4d5add27a122b1e25f18e60f88958b3e04625b945d69da$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_388[] = {
    {"$dynamic_388$adcf9aeade27928531b830f8f2137bafb36bedeae6d6f0ece273c5f90d09712c","abc"},
    {"$dynamic_388$0112609460b8037f979f83b3d9886debac5ef188581bab497e8b990abac14d6a","john"},
    {"$dynamic_388$c754da737899cd58804bc0b16e885b9ca2e9660140d11b2fc8432adbab217b64","passweird"},
    {NULL}};

/*** Large hash group for sha3_384 dynamic_390 to dynamic_398 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA3_384,39,96)
static struct fmt_tests _Preloads_390[] = {
    {"$dynamic_390$ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25","abc"},
    {"$dynamic_390$7d8adaa8d0c1507fd780b39d7ba2edc16876b8c677b7cf2660e02d0277c29159c366a0f4cd5184b7a47858d88835ab88","john"},
    {"$dynamic_390$5e293ca60625536151883199057eab17e74e60b1ea4dbe0b66f883d254e99e04a7b685f34dd1cce8a453df85b18fe0b3","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_391[] = {
    {"$dynamic_391$84a21991f734c824f3c91fc0f3d9a32b7b539be1daf7778e611646bdc15e537d7f667e37e37544f4b7fd7adb04a65d07$df694488","abc"},
    {"$dynamic_391$4012e40b8986407a94da597bbfcfe3882376ca8fd37d820fda27d904f85a9a3537deb6df3123a1c8ed1a924e633d85f7$87ffb1c9","john"},
    {"$dynamic_391$a56112330376faa84190887bf8adecbddb78f2ce43a96f00ff92852f64f468b743a5ab507a0211f41f778af26f111176$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_392[] = {
    {"$dynamic_392$033993ebd2ac3deb16480f22c555a4bf7cd14b19434fbdbec44ca285d03623ff02b29c40be332d87eb09d1d17572afc6$4f58497b","abc"},
    {"$dynamic_392$8d0970a593297cd1da66565dcfec947aa00be4aca9bea4a9ab850db3e362bd4df05fc4e2ec6c1fe0e5b25e89cb176ef1$e0b88e64","john"},
    {"$dynamic_392$c4b1d1a34dfe50c17466ed7536ad5d3ee82b709c1c9d2290840ea0a94a15e8995cc46d739d1bb3d2eaa742c32212d3cf$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_393[] = {
    {"$dynamic_393$84d02482ce8d21bd8f757367dafd81cd772d1cbc05a447d1862983e6a8090d9513130d7c7aa2449cfd4924a39011da9d","abc"},
    {"$dynamic_393$ba52b0527551acc500b66c81931df6f910516e97036de11e43bad8b8b4736105c7f3fd468f15bb6a933d80f9e39aadec","john"},
    {"$dynamic_393$ede7e55fd51ce399a8c8ee69a8b35e492027a84a2e2668bc031e4bf6d7f75ca37ec8d8bb19cb834d7b65deb80b2cae30","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_394[] = {
    {"$dynamic_394$7365d226caddaa8ec62faa1537886da61396b7507c2b99d4a244a17a3ad8174a6ee92c191ac2f6da78d4b5990c026195","abc"},
    {"$dynamic_394$f79dc70f5d8b8a18a2a257d5441a91819cff44e76e0bc5bd0e97944f9fed810b13cbbffff348395282ac0e8cc4614771","john"},
    {"$dynamic_394$5529892e23fc2a28b8b06650ff4d838029ab5ca7b6ff85a5391dccd7437cb4988ec57cd7e6d0dd91b4c68dfd1538305d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_395[] = {
    {"$dynamic_395$e6b04caa7b5ee97a8a54d3bdf7fd3a5df5e4088548c4c255c433b5de901f71d4cdb56c1986825cc1b0f9adbb5b210862$3be069de","abc"},
    {"$dynamic_395$e15fe1ae33e75d6c5c16b1784a0c25fd2f2af83bb6fab59d8fed3b8e832c871df3c43db2bd74d0068733d67116cc633f$76f68854","john"},
    {"$dynamic_395$2685de1656e91e70447aa741ef4d453b6da6f957fb8f5f97bee988d22e2ed73a45fc54bca2750f384580f6060d2eb57f$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_396[] = {
    {"$dynamic_396$e9fba4b7bb28f60f36febd9cd164ff83bf46871827a9e5c557bf41d4b295086d319a8c443abd24fb8daf9eb86a995560$f17f9849","abc"},
    {"$dynamic_396$5b067a0c67505c4e427302ea9a733be262dda91b0aae93e314b894b17cdec6c326fe0f54b6ec1fd7f246d2b0df286453$c855fad2","john"},
    {"$dynamic_396$6a3b4c009cac4bffb3bc6dabc507b3cbd4cb97b2f2cbae6b59edaa342d8b757b082a207894a8b0a7fd2a30a0075946b6$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_397[] = {
    {"$dynamic_397$e5a2e6dd42828e0a3bcce0dba035b44e44d0533a39f0825a64d9db044447cd09c9794f77729577cfc346ff6ec87dafd2$30bb3a28","abc"},
    {"$dynamic_397$908215dac9bc466c62c6f08c90eafa47de4ac99f1de952006e2891c56b2982ed34b5dd145bc4844c9bfd3abf115b9ab7$49e02b3e","john"},
    {"$dynamic_397$92733a0ce1413b6c21fae6f28e241264d150caad5a37791db16e90f7219df7c80d857ff175e3738e61e1b79b1adc09ba$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_398[] = {
    {"$dynamic_398$98ce05fa59df50d130ba790bbce24217392424ff3880e5ff2e41148556fe5c376778b2d5276e24d6d63321b910b86f3c","abc"},
    {"$dynamic_398$fd413494ceec13651a1765ec5e78baa6b27d2e9c3039062d7b28e075e1b976caad48ced91de43fbb5fb214b18bfbc3ec","john"},
    {"$dynamic_398$c22d51fc8c84e50337cbb8de223c9a4e7fb46be9944f2c69571e07d4b984b3159480486d2b08644c0f60bb4e9b5aa5ba","passweird"},
    {NULL}};

/*** Large hash group for sha3_512 dynamic_400 to dynamic_408 ***/
DYNA_PRE_DEFINE_LARGE_HASH(SHA3_512,40,128)
static struct fmt_tests _Preloads_400[] = {
    {"$dynamic_400$b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0","abc"},
    {"$dynamic_400$0430c0ebb2398fda098d1acc0372de9b4c73a0e52bad59385a691cf61520f7dcb808fd75789d7094dbf4b452c3b1c9bc8f741cd2cbde2ec354b34a22e22be745","john"},
    {"$dynamic_400$a31fd6a24a79e1141763b9098391bcd916437fee5b85664933a85fb41f58c113092bf36f6a271ca4b3c0e3bbd9ebd1852f2ae54fa4ba58a566c13734ff85128b","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_401[] = {
    {"$dynamic_401$5f226b96ff7153635fd4d01e183d65d9eac951a042189ed6416b52482020dd717e4bbc21475b056767a339d2fb4cf1e580930ae5f0ad541609636441dc4e6c3f$df694488","abc"},
    {"$dynamic_401$e4f4db12c361320c2344e8002b479fc0994f0c934ef58df9e78be639ab038f063418339f22fc8c6cc5b832a5763b4efe0508bde6cc86ce1712f47822fb404e32$87ffb1c9","john"},
    {"$dynamic_401$a8fa0a6913c619076e648a5b50da2dd033f238507ec288951919574ef97436ce4947b1a17c1553fcc130490bf7500f5d732697d5953b977b3497426b197456e5$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_402[] = {
    {"$dynamic_402$97df8a02c0d2d2bf639d2677ce2dfe9bcec065bb3d0d8f3db63e50ed79fb717b5c416777177dee0fd57dbab552764e7867684e3eab0d734e04dae012d0d5beca$4f58497b","abc"},
    {"$dynamic_402$4b5f1447326e823d59470cedb187aa68c119b9d2db0aa90d066ddf8ad6231cc0578a7faa108a0c7aa1bc70058157a902d6d7a0ac980b23e170f8194404750e17$e0b88e64","john"},
    {"$dynamic_402$5232d6e3c62de6d0e66938374d5923897a77535b7f546aa6185eafeb2075db78c7ed9a904851e1ac617723836399c5f8b2a7b6ff5431ff51aab22256ca1e61ef$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_403[] = {
    {"$dynamic_403$0fcda938dd7382fa650ae1931a6e9d6fa6643fa3361de87a97a022b6444e03fb39497316dd0fb0bb5947506d7e1f50a6ccfea47e14a9f5a8513e64419c6a5997","abc"},
    {"$dynamic_403$9e8252f9ecbd5f7987b13709c495a03719560abbce63d94765a1d0082292fd5126391b49e598baa00ea4bc0a887bd48e579ef3bb9ada6ad597ec2ff2c28c1e63","john"},
    {"$dynamic_403$082249ce3ed86706f26fbaa9388b6c1de2a284eb2366b2c963aaf207a4c41b8d13c67a237d07ac32ed408f8b85a9c419e852247ebbab00711e6e8205aca5e843","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_404[] = {
    {"$dynamic_404$465558b627e37552639af5d20d59fdfe150016d40b97b7d0cb66420d86585d82461e2eda3295903357bcb0a5b67c07aaf561d7e9ee193480095291af9b2132e1","abc"},
    {"$dynamic_404$32851c36c98543b07b894ca772a3de2f6cef6d9b20e4cbe4d99abba369b6f71f38a7dc9674f225cc9f2120185133ec3c59ed3c6a3e7ddebdd60411c924f64482","john"},
    {"$dynamic_404$99af2f301454e9d95ca8a3247cc94e7502b0e07232f64437d6eef5fb18b39b0fd97780c46ed915c077dd1d862e2815912b98c951d138b4313be0c24cd32b6932","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_405[] = {
    {"$dynamic_405$f838c244fe7859d23e518184759a5baa7635ca69bdb7388354a7bebf92ae00c2d2c31001fe5ca5dc6afd1fe09003c6762dc66c761615b644f50927727dfac077$3be069de","abc"},
    {"$dynamic_405$e3fcdfebbffa74f5432b86430d4277dc238829d2570a7b94dc89c2356c1df764748e6198334b18f61d54ae343c9c72dfce46ed0965e9077f535ad97d07c3e2cd$76f68854","john"},
    {"$dynamic_405$dae6b2af20efa86f34ee7624c6fb3fdcfe9147e5fa2c566ef4ba02d3764608454be5f971e827bb80a18871945f680bd79f61c66589c506a2f7916ea8d339e135$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_406[] = {
    {"$dynamic_406$0c36b701fc15909e2c6730a1a6b521b9c268abdf73c41fa4cc4152b3f81f07c3a844d2ede7004a2a0a016d7bb6de519cd7714c19cedc0eff5bcd9a4ab430550f$f17f9849","abc"},
    {"$dynamic_406$14f40ab1750d10be89d8ed6373c365ecde1108699dac365802447bd572d84f69e49504086a74ea2ad9215d33bdb7e364ce4fc78683952352498049bc10f0bab5$c855fad2","john"},
    {"$dynamic_406$52606de707b043fb81b3e7000318e70123651a230fb5dc4ce11fa5efb50e0427a4b25404cf0cac407c72761b986d72e386768a8d9bcb5f648d30c1be5a5ec915$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_407[] = {
    {"$dynamic_407$d66cfdf53daf471db9f159edbe95688d3f2c4ee0cf43f5168f7b501ebb5233220627214c5a1aaf9e1590a9c181c8185bd31fefed753539317444e685ad09ade1$30bb3a28","abc"},
    {"$dynamic_407$9c6dfd6ee8da9c6a429956127a111fad4a0f1872ea10345de57555aedd8f27a1b88f8a1899122947a307d809c49a84a5a02626d6e26596424e9c0417fca42751$49e02b3e","john"},
    {"$dynamic_407$cfe649a05ef4730e09e253aadefc54688ec2100a26a6825b64cb17c291baeb49bbbb068bbb37b8944326948e0a68715219e725fa9242a5f40f81798c256ceef1$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_408[] = {
    {"$dynamic_408$e8633f62db8a1e1a6b599e0bef7135a6363b8b749041602700d8d43ec4a086335d9384b0f6ea33f473d36e6a46e1249abafee55f3a7cc25c14fef43d3b1ec6fc","abc"},
    {"$dynamic_408$f845720fc8024e36169296a24358328bffcef26d16ce18f0bb302e6f0b085cc9c5a80fcdc12997052b2a9fc1e82b49313e6935473ed7e637a68c33604a17a143","john"},
    {"$dynamic_408$043c4a01bd45722d0ecc61cb307b0737f07ddc8484072821034a711ad989f36c7c05971c7601c73567deeb6572659fda44fb3391a6c0f4223bbf3ea272d4fdbc","passweird"},
    {NULL}};

/*** Large hash group for keccak_256 dynamic_410 to dynamic_418 ***/
DYNA_PRE_DEFINE_LARGE_HASH(KECCAK_256,41,64)
static struct fmt_tests _Preloads_410[] = {
    {"$dynamic_410$4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45","abc"},
    {"$dynamic_410$9c4b7a6b4af91b44be8d9bb66d41e82589f01974702d3bf1d9b4407a55593c3c","john"},
    {"$dynamic_410$9f73e862d1d46ec9a80f1474ad755d34b8dfb21c60d758e2b2f23bdf61986b52","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_411[] = {
    {"$dynamic_411$a3dbf9b5fec02f3ba8075aaacad33d430904fadf6a34406d488be5f7fb5e51d9$df694488","abc"},
    {"$dynamic_411$3c6faa90cfae73775684b3cecbfd048b6c1dd8ab4b49007798e7a8e974714f95$87ffb1c9","john"},
    {"$dynamic_411$4ac178ea06e0d3b7cbd207fd18149c8e0c34843b2f4435d3a6100273e59a7966$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_412[] = {
    {"$dynamic_412$8ff88eab9c2f81d42091ab1b5da1e99ddb3a2a0a719e0344287366d3cb5e3a8f$4f58497b","abc"},
    {"$dynamic_412$7ec3682186dfc6fe35fff50405a5458f5cff897032a3d9f495fe1c9418182a0a$e0b88e64","john"},
    {"$dynamic_412$f623d581d3fb1b4219f19231886c276b044a363efc3ed5346479aae24049cea4$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_413[] = {
    {"$dynamic_413$fc4b2e93d9ec97f3942d6c2532d5953555b2748c679b25c26956a91622fdb3d0","abc"},
    {"$dynamic_413$0ece183803c572e8670da37c1af889d1fa18e1c9df8b1449b12bc5c07cfb49dc","john"},
    {"$dynamic_413$edf89c311428933ad6826972f8405dfc7574041cf4c3c62fc631374d5e691f20","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_414[] = {
    {"$dynamic_414$b8e12eedbb60e5321db47f5a3bfeb8ec0ff6ae9af10020cc61bb8c82ae0b7b66","abc"},
    {"$dynamic_414$e95a2f35a82dce1c35c5cd5a97dc77a2b83866f5ec68a4585a89e87a0e5c0cf1","john"},
    {"$dynamic_414$31b9edfcd3f608bdf174ecbfa7b976e94915e34840d8518f984cb513b97a90e5","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_415[] = {
    {"$dynamic_415$ddf8eb55220c174d706d36d94fd3d610a40324aa9ad697625b910dab50588bbc$3be069de","abc"},
    {"$dynamic_415$0769fdee9d7bb32b43eba38e1b8a98bb654a73fbd10a157a077fac8a2cd5667b$76f68854","john"},
    {"$dynamic_415$29207188500f32cf5bd8287e4ca25160b3611bf5385ea3fe327918c30ad5e046$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_416[] = {
    {"$dynamic_416$fde215a52d3a693739e36e16681f6db050f9983ad50bdae9a370a8984076d78f$f17f9849","abc"},
    {"$dynamic_416$f91ffe3280246ea04d9a8d8f524e9e0ac202ae192c0149485aa2e653788f783a$c855fad2","john"},
    {"$dynamic_416$2b6b1be3234b4973e7e64beb1390fc23ff1668a569a7c6d7088438c028289a0b$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_417[] = {
    {"$dynamic_417$d9b7844beec47157a665a255b4deae1ddd4b96178d970f466e4ba4300facbafd$30bb3a28","abc"},
    {"$dynamic_417$e69becdca2fbdfb670acf28facbcdb13016742b866d3b951cacd55fc3517e5d0$49e02b3e","john"},
    {"$dynamic_417$d4d8126e9b9a249ea72962e0ed6fe48679c2a522e59bc87a01da6765f891d64a$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_418[] = {
    {"$dynamic_418$9d416d06f14b22885424a5c945fdf456aceedf789f7c4273f6a0b4c975a4c764","abc"},
    {"$dynamic_418$2b431bee5a73dd299b499200cadc8079775b4cd461f461d0af4fd244f57bcce5","john"},
    {"$dynamic_418$ca91b07923cb1e840a4f5abd4747471afef605e45d8220096f2ffb25cd19b11a","passweird"},
    {NULL}};

/*** Large hash group for keccak_512 dynamic_420 to dynamic_428 ***/
DYNA_PRE_DEFINE_LARGE_HASH(KECCAK_512,42,128)
static struct fmt_tests _Preloads_420[] = {
    {"$dynamic_420$18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96","abc"},
    {"$dynamic_420$c409c9548388c21c37f79adb7d9bc864a2ed28437f55a011c4df011b0cd0fa59fb312625b69adf64459fbf61666372d0f6d62dbae609158d826d71b473b520dd","john"},
    {"$dynamic_420$60da1514391dfa2d5896f9341d47a5dbcf2ae5d0c6df05b93cea63cd527459eed9ca2cf0cd2011ef0efef6558910d6504ac6ed7e06d013bf2461d14c1f2ae334","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_421[] = {
    {"$dynamic_421$cedab01e6df09c323785c2ea08b682b7f525eceda88d28ad9e21f716c402ab7e914a18aaaf700ebdf640141a62eb5655873844f1e20496a36e9743508c7e7bc7$df694488","abc"},
    {"$dynamic_421$66ed29facbc871f5be63938ccd6034c7334ace4617873dd859b8a80d45198f4b9bd2ea12050ac9de5ee25a3692731cf0db0c2ef3737b575c7269072d2cbaf80b$87ffb1c9","john"},
    {"$dynamic_421$6ce8158aa4a1a910776ff78d8ea7b6587df97feebbf57dd3fe37c52ea544edd3d686577175a263bd84856781af4aaafd6dcaab219e8dc3517de772ba51120e12$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_422[] = {
    {"$dynamic_422$1b99ca4a0d0b9f93a29a1be11888562adba67f0e63f07eb318c4c5d20e2de716739d75f93bb7442084f62bc6827b11fec3739e3ef07814ceb0e3a7afcaefa8a3$4f58497b","abc"},
    {"$dynamic_422$d63e1f91f57311f58f31f716bedf259646ab446998a800de91c835f507cb6dc44aeec0322b53d8ad98250b26af2a53b9802c8a2f18aad1954d06742745d069c2$e0b88e64","john"},
    {"$dynamic_422$60c766f9e848da4f0400df81883d0d1bce81650c431041b1682c6b4564cb2ed62f04c583ee953522ab0957b49d5b148f3c8ebf3031107752190898dc94a222a3$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_423[] = {
    {"$dynamic_423$c09a72223b5e3950fa5a31db971213565aa833ca238570fa7cb909ca826321c08f0027bb185b52eac64efd6dd6f6cf16694802f108dc9bb8f400ef9fc5241c95","abc"},
    {"$dynamic_423$0cbd17f32da7d0b7c0ea583e9ca97da233e4d9520f24c06743313d8aee9034ce9fc2ed880e841455e35e8978a306f1e188545111a7383cd3733eca68b365036c","john"},
    {"$dynamic_423$f2d59e40945901e487534cf2823ed0c0706038e64796fe2c80f47d52084152617ba6a9ce60fe10e40eaecfe9fb9bcc31f2e6f1eea394eaf4f7cc6b5ab145e013","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_424[] = {
    {"$dynamic_424$b22e3fcf38a1be5b0ec582192fb27ca4afd41113e1000a39bf287141e04fa6e13625603f2c63f33f1c7ae6967aaaf323ed7f3a3b33e7c74f1294ecab0ef3f2cc","abc"},
    {"$dynamic_424$3e11cbc6a03c7093fed883b0be3fcd70c1626b6907c6d281c1b2097fcf00bcbaa878b51ed09719a1892363053b74e27db83aca95f2d1f17539c6bf96db11eaa1","john"},
    {"$dynamic_424$dec8d37813ed126f5c85f935a6d077e3d094f8663a2b31f757e94427231f1f232518628fe1346e2fee8c2d5bb99d2b67919b7e39d02b67c3f2b5448b8ac0e0c6","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_425[] = {
    {"$dynamic_425$68ec6d7e65391851ff0d417047efda502909b90a096425d177583b3f6cb1eb1ad124832de04e7a498333690431431fdc2cbef431271b60b898fba7e80950bcc6$3be069de","abc"},
    {"$dynamic_425$fbf3429d7a3d7b545111e94af95e46be4416205b674163ac0685becd56c6fd4d2778b7444c84e023f6f1f2bc406e83b4bcc31d45c4f27f7aa721d3a059ac77d6$76f68854","john"},
    {"$dynamic_425$bf09b943b01b483236f0dc27af444c2c77dcf5e94743c277cbf882bd0882fa1457086e72647a31764f99b9a62b8f75923ec4c0490713dbbd743ab666f3345f40$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_426[] = {
    {"$dynamic_426$fa5c4745a0ff5a524957cce6f532a509eafae853210f569fa03f5ab1c98925ea0844398c98e64af28b8927f7a2fd7b0161e51755cffa1e6ed8c2817d0c90abb7$f17f9849","abc"},
    {"$dynamic_426$6c96b52bed51ef0d5bc709b54416a20d6b6bb682422c1baad2753cc2df2d68bbb56eb159e6d218c85df2e7fe326a25ec66e0b7102fa5785d1910fbe2b06bdd2b$c855fad2","john"},
    {"$dynamic_426$1555ad87b1b0ecdfc0963df43a06dca1a9f2e8b3dbe33b26a7364e6ee8ec6178a8109c413160d4d8193b8341c215c6a6b6f469d30e7192fe41e27cb9c11a0c99$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_427[] = {
    {"$dynamic_427$cf1bb43b39f9eab4050fefce2cfe4a4af1326b76365b1d9d69177e57bf2f4450a29e793a24569f2899a7e5c35b5e2df85f7634354b025c87891d507e3c32342a$30bb3a28","abc"},
    {"$dynamic_427$661cb2de051d46f92e89b2480702e8738fdaa6b6d04397d8e0ff84355bf006bd22ac1c59e0c6d8ac9dc9313e369e093ae94b484556b7366e4a0192446c4c5357$49e02b3e","john"},
    {"$dynamic_427$c30fbba0fbc41875b2ad807ea64601fd37e69f3b636ebb414350c7a1e01107fc3e77f1d03003e178d7b19a15407b11df59e7ca98309cdd066b773a707ec69450$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_428[] = {
    {"$dynamic_428$6fba5f8c574e46429537adf17d77e230f8db4be1521cac1f18df1222c3c2090a973b8e1d494b7e533efd338b0db78fc4c5b61b133a5fa24c2295329c72ff92da","abc"},
    {"$dynamic_428$b1c9070e2af221437a9b951f05412c177a69c65648767babbc325fe294e209c6dfdd675264f9f04cac4aa195c0de58af97ef3e797187239b586e11e90f2f7537","john"},
    {"$dynamic_428$6fc38138fcf53366b2b372c44cdd2f2489576ea1d619e9fa608696ac43a3be21cb4a0cc534ca9df8606402c60adb0bba0705443f4d4fa7909d18e3395d126dad","passweird"},
    {NULL}};

/*** Large hash group for keccak_224 dynamic_430 to dynamic_438 ***/
DYNA_PRE_DEFINE_LARGE_HASH(KECCAK_224,43,56)
static struct fmt_tests _Preloads_430[] = {
    {"$dynamic_430$c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8","abc"},
    {"$dynamic_430$18d7e621deddc738d076023e13995e47da96655a9faf6a41057cdf9f","john"},
    {"$dynamic_430$398bb454b8a1c0bf6c3f2ee72777ac79b2b7fdd527d4e9a2a5761f48","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_431[] = {
    {"$dynamic_431$04e5b1a7b4471ab0efe64ea15a6ab45aa135206454afd8237fcc7cfd$df694488","abc"},
    {"$dynamic_431$5cb8f34f83b8cdd78ac72beb636a2175bb4b729f635144e05681dfb6$87ffb1c9","john"},
    {"$dynamic_431$df807dba5ce57f188f6cd6c18f96df77aa1e107dc9e5f408a05a4629$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_432[] = {
    {"$dynamic_432$0f5b4cc853981297040ee777793690e29f06cb15fdd2b0925b595d94$4f58497b","abc"},
    {"$dynamic_432$c2a7ec629120f5f78acb1e6029479d05d0d5dd57127e1b809ddc1ff9$e0b88e64","john"},
    {"$dynamic_432$2c8808b03bf8587b01177491d7e2ba1918c16ded0c14702bb8cf6c6a$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_433[] = {
    {"$dynamic_433$5b48bd026d3d85e37633181f54c345650a9bd69783b8f51cf0069c0d","abc"},
    {"$dynamic_433$2b9bc86d9cb67b419c25dbe45a4ac0565d19cce5ccb528967b975bb2","john"},
    {"$dynamic_433$9454d9e6145fbd7075523513485c2dbd2ada1f9d9608e21fb9d51819","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_434[] = {
    {"$dynamic_434$274b41172987283664c38f44493f7edefa79a2d59d5f6b01cf8d12bb","abc"},
    {"$dynamic_434$0699030c3ef880ab373cb843b246752a5bc3ef8ac1893537a7add0d6","john"},
    {"$dynamic_434$8831ece9ef672d00b4e6cbeb486fed0a17ad402e463102fe59496bb6","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_435[] = {
    {"$dynamic_435$4243ed2e5f95206f56a55335a3319dadf878b32e1c38196a34ca7a01$3be069de","abc"},
    {"$dynamic_435$e9bdc27db576f3d88428c45ddc59f4006e31e9664b734e8bdc1e65a7$76f68854","john"},
    {"$dynamic_435$e724ffc649d1d7fcd222ed3be27d035345bce084004b9e703fc07fe7$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_436[] = {
    {"$dynamic_436$27767ce9511142537af6411ade7cf785881b21e91046c3177dea9464$f17f9849","abc"},
    {"$dynamic_436$26cabd7a4c28c596c5b7b2baa0bd8b978a2ad4bb6a988c3b9a40f4fb$c855fad2","john"},
    {"$dynamic_436$5e5a4c27429fe39bdad04fbe6aa7d70658b15dc502ade8df023f9524$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_437[] = {
    {"$dynamic_437$8ccdc098eed8f72353f5c5299faf2e0b0fce7637fc21b78257cc0d98$30bb3a28","abc"},
    {"$dynamic_437$b186831a3fbf696e9ce3ccfde695a9430113241c3230662feeb3a6a0$49e02b3e","john"},
    {"$dynamic_437$e42516c5b33759f8ddd87b8fd175c01d6abe930ded1fb8c3c734026f$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_438[] = {
    {"$dynamic_438$b5d75dbcc8bc3f947cd09323efa9eb7af7d2a8c44262d37ebe0b9ab9","abc"},
    {"$dynamic_438$ad0e1bc54e9ced608b84d70ca85f06b46786fee6a5c81b641eb3e796","john"},
    {"$dynamic_438$a520066a7ac099a2331400d7f5472b6b76869e461c40bfe23bbceec0","passweird"},
    {NULL}};

/*** Large hash group for keccak_384 dynamic_440 to dynamic_448 ***/
DYNA_PRE_DEFINE_LARGE_HASH(KECCAK_384,44,96)
static struct fmt_tests _Preloads_440[] = {
    {"$dynamic_440$f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e","abc"},
    {"$dynamic_440$f973411064de49d05da4c1b97c1f1eb128812e06076a7086261fda8c0b4ee792d1ae740117d1c80caca0fded3fe6f8ed","john"},
    {"$dynamic_440$b26764d7425d200dbbcef583d7ee81a53a98a61858b85e3098d6703c2e4c132fd25e2004c4f6a89912983bf6512e7e1b","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_441[] = {
    {"$dynamic_441$f41a88e23cd6096146a8909f1b2a722922a172904458dad9b0b8da5bb2008a19b51fc18b53aff152a141269e14dc24e3$df694488","abc"},
    {"$dynamic_441$56d351e1f4dac967646e471c840b7101cda487640ba6a772a8c7f6edbc546feeadfc3db2bb2d15d4cd6b3026c67afb90$87ffb1c9","john"},
    {"$dynamic_441$592749875104764d2192a7cbbc02df9c3bbf0a01b9c804c78f4554ed82dc7283981875c44d0b4e7ac58c52c1f6be5fa0$a69c5744","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_442[] = {
    {"$dynamic_442$2c3df573e83e95352e9ecc98fded4e769ae8fe63c8f23cadd4a0e53a0b264a5da8fa445ab56e7bac34f4946ed0a94008$4f58497b","abc"},
    {"$dynamic_442$c8d4d1b2851aa6f4b2ce8b5151158a56ee106052a6f837917bbb8d1178a5b8a2e86adb78b5290a60163dc542e2b7ad46$e0b88e64","john"},
    {"$dynamic_442$efa0d10a71d632b2fc4909b41fb730406ef4c2e455b1e8c5c99872a844a16b12a11005db90829e2997beb8b75a947feb$35644f9d","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_443[] = {
    {"$dynamic_443$8bf35819303514360d4ca660dcd6388dc0fbdf5f98f43d30877ffa012befb538098dd2cf01329827c4ddd24b3487d6b6","abc"},
    {"$dynamic_443$74699553ce7cb8b7c7ee62e237681f472fc3b37c6480573bee84d858508e7ae8c38b451d3721d18625e8146aafda3e46","john"},
    {"$dynamic_443$5535c959e2f36466144780ff6eb888525082700d38a9511773f74581eda8587f63fef866cb07e96a7b7b4c9ce9af51e6","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_444[] = {
    {"$dynamic_444$061145922b5cd49b7532f7682b8a2b82ae033bf874d89432295f75572ce2f098e28c663cd0920f6e9bf01f77ad8a255f","abc"},
    {"$dynamic_444$9b415c22d33e329f97975543f521e41a5a5a1120e10ad2933b66c2c1481c01ad5974cb5e4e0613eed37da5482d7a10dd","john"},
    {"$dynamic_444$a065a9ec9d679d63c9ce80ead40bc396e571a0a8bb2c1b4c7d3a758617d9797a87189f51ad28294c3a5be181f234cc74","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_445[] = {
    {"$dynamic_445$f2e83e232cb2bbbd304289f615c8b1dddfd19768c0402055d0fe65bf3d43cff0d7f810227a7124d3cac32602e21591ff$3be069de","abc"},
    {"$dynamic_445$66033ca81f3a26a4d4887a791cabb32369c2b3616cd06ac7837dea275f585f219cd403e7ba16c8a4a3856074f1b6e211$76f68854","john"},
    {"$dynamic_445$a2839c94340757af5902d6529ecdc2b386a7385d62151c692a0f4c98246e093ff48f8b9f1196376d90b5a2c97a46ac56$044dadfd","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_446[] = {
    {"$dynamic_446$1ff6015ae625f740dde498a20d662e2413c0c9d19ae9355ff70de75c8dba0f98db987a8fb914bb7e3df638a5897cd89f$f17f9849","abc"},
    {"$dynamic_446$2191a9c392a0227a2054210466b2af1e5bc448cdb2252ca4c238b85b7e31581aeaee28b43445b4e1b192895caef282a1$c855fad2","john"},
    {"$dynamic_446$8600bc84a3691fe6e4972680b6761987bfdf420f04b246bf3dc0958c67cc50f1ef7de23c5f1420df44796b264769d299$01f21a29","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_447[] = {
    {"$dynamic_447$a35bcd5f30fa04bb83f8b4b3bfb11d9d51c20d84310598e55a9ec2a8e4009581652a046efba53e0f9ccf21dfb200a7c6$30bb3a28","abc"},
    {"$dynamic_447$24c8f419ac0a3b897d4431589efc2d66ba64f05de414207bd0516713d0cf6e16fcbfc3ceb3f7cd6f73f3944e8758e90b$49e02b3e","john"},
    {"$dynamic_447$c7ec9b69882095562209e538933abc10d8a68aaed81a4d36ec341ca3059da9291966f8f544e244541d9626c79108882f$f4d96327","passweird"},
    {NULL}};
static struct fmt_tests _Preloads_448[] = {
    {"$dynamic_448$68615c3c8fd71e454f7fe21a610b5246e0e5cfed4dd4a010629362b467d9ad02a2ef4659832a33f4e376f1c1ea098c33","abc"},
    {"$dynamic_448$73dfc0513d81ebbe8d04888088fd174cdf50e0ac1677ee1c8556c916a1596240197be24c7076710c1d44bb94a18bdb08","john"},
    {"$dynamic_448$1a943f96264813d8143a4171d49e63f1fa675730715899c7e010b5abd6f1dde36a96057f72c2b48ad308e4c4e7c6a3da","passweird"},
    {NULL}};
// LARGE_HASH_EDIT_POINT

// Here is a 'dummy' constant array. This will be 'linked' to any dynamic format that does not have any constants.
static DYNAMIC_Constants _ConstDefault[] =
{
	{0, NULL}
};

// As long as the setup for the large hash is 'default', then we can use this macro. This one is for hashes which there is NO possible SIMD code in JtR
#define SETUP_LARGE_HASH(ALGO,KBHIN1,SAH,NUM,INPB) \
	{ "dynamic_" #NUM "0: " #ALGO "($p)",                            _Funcs_##NUM##0,_Preloads_##NUM##0,_ConstDefault,MGF_NOTSSE2Safe,MGF_KEYS_INPUT|INPB}, \
	{ "dynamic_" #NUM "1: " #ALGO "($s.$p)",                         _Funcs_##NUM##1,_Preloads_##NUM##1,_ConstDefault,MGF_SALTED|MGF_NOTSSE2Safe,MGF_NO_FLAG|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "2: " #ALGO "($p.$s)",                         _Funcs_##NUM##2,_Preloads_##NUM##2,_ConstDefault,MGF_SALTED|MGF_NOTSSE2Safe,MGF_NO_FLAG|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "3: " #ALGO "(" #ALGO "($p))",                 _Funcs_##NUM##3,_Preloads_##NUM##3,_ConstDefault,MGF_NOTSSE2Safe,MGF_KEYS_INPUT|INPB}, \
	{ "dynamic_" #NUM "4: " #ALGO "(" #ALGO "_raw($p))",             _Funcs_##NUM##4,_Preloads_##NUM##4,_ConstDefault,MGF_NOTSSE2Safe,MGF_KEYS_INPUT|INPB}, \
	{ "dynamic_" #NUM "5: " #ALGO "(" #ALGO "($p).$s)",              _Funcs_##NUM##5,_Preloads_##NUM##5,_ConstDefault,MGF_SALTED|MGF_NOTSSE2Safe,KBHIN1|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "6: " #ALGO "($s." #ALGO "($p))",              _Funcs_##NUM##6,_Preloads_##NUM##6,_ConstDefault,MGF_SALTED|MGF_NOTSSE2Safe,KBHIN1|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "7: " #ALGO "(" #ALGO "($s)." #ALGO "($p))",  _Funcs_##NUM##7,_Preloads_##NUM##7,_ConstDefault,SAH|MGF_NOTSSE2Safe,KBHIN1|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "8: " #ALGO "(" #ALGO "($p)." #ALGO "($p))",  _Funcs_##NUM##8,_Preloads_##NUM##8,_ConstDefault,MGF_NOTSSE2Safe,MGF_KEYS_INPUT|INPB},

// As long as the setup for the large hash is 'default', then we can use this macro. This one is for hashes which there is possible SIMD code in JtR
#define SETUP_LARGE_HASH_SIMD(ALGO,KBHIN1,SAH,NUM,INPB) \
	{ "dynamic_" #NUM "0: " #ALGO "($p)",                           _Funcs_##NUM##0,_Preloads_##NUM##0,_ConstDefault,MGF_FLAT_BUFFERS,MGF_KEYS_INPUT|INPB}, \
	{ "dynamic_" #NUM "1: " #ALGO "($s.$p)",                        _Funcs_##NUM##1,_Preloads_##NUM##1,_ConstDefault,MGF_SALTED|MGF_FLAT_BUFFERS,MGF_NO_FLAG|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "2: " #ALGO "($p.$s)",                        _Funcs_##NUM##2,_Preloads_##NUM##2,_ConstDefault,MGF_SALTED|MGF_FLAT_BUFFERS,MGF_NO_FLAG|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "3: " #ALGO "(" #ALGO "($p))",                _Funcs_##NUM##3,_Preloads_##NUM##3,_ConstDefault,MGF_FLAT_BUFFERS,MGF_KEYS_INPUT|INPB}, \
	{ "dynamic_" #NUM "4: " #ALGO "(" #ALGO "_raw($p))",            _Funcs_##NUM##4,_Preloads_##NUM##4,_ConstDefault,MGF_FLAT_BUFFERS,MGF_KEYS_INPUT|INPB}, \
	{ "dynamic_" #NUM "5: " #ALGO "(" #ALGO "($p).$s)",             _Funcs_##NUM##5,_Preloads_##NUM##5,_ConstDefault,MGF_SALTED|MGF_FLAT_BUFFERS,KBHIN1|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "6: " #ALGO "($s." #ALGO "($p))",             _Funcs_##NUM##6,_Preloads_##NUM##6,_ConstDefault,MGF_SALTED|MGF_FLAT_BUFFERS,KBHIN1|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "7: " #ALGO "(" #ALGO "($s)." #ALGO "($p))",  _Funcs_##NUM##7,_Preloads_##NUM##7,_ConstDefault,SAH|MGF_FLAT_BUFFERS,KBHIN1|INPB,-64,110,110}, \
	{ "dynamic_" #NUM "8: " #ALGO "(" #ALGO "($p)." #ALGO "($p))",  _Funcs_##NUM##8,_Preloads_##NUM##8,_ConstDefault,MGF_FLAT_BUFFERS,MGF_KEYS_INPUT|INPB},

// Here are the 'prebuilt' dynamic objects, ready to be 'loaded'
static DYNAMIC_Setup Setups[] =
{
	{ "dynamic_0: md5($p) (raw-md5)",           _Funcs_0, _Preloads_0, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SOURCE },
	{ "dynamic_1: md5($p.$s) (joomla)",         _Funcs_1, _Preloads_1, _ConstDefault, MGF_SALTED, MGF_NO_FLAG, -32 },
	{ "dynamic_2: md5(md5($p)) (e107)",         _Funcs_2, _Preloads_2, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_3: md5(md5(md5($p)))",           _Funcs_3, _Preloads_3, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_4: md5($s.$p) (OSC)",            _Funcs_4, _Preloads_4, _ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24  },
	{ "dynamic_5: md5($s.$p.$s)",               _Funcs_5, _Preloads_5, _ConstDefault, MGF_SALTED, MGF_NO_FLAG, -12, 31, 56  },
	{ "dynamic_6: md5(md5($p).$s)",             _Funcs_6, _Preloads_6, _ConstDefault, MGF_SALTED, MGF_KEYS_BASE16_IN1_MD5, -23, 55, 110 },
#if 0
	// this format is deprecated. If someone WANTS it to work, then it can be uncommented.
	// however it is MUCH better to use dyanamic_6, and if there are any bad characters in
	// the salts (like ':'), then use $HEX$ for that candidate's salt value.
	{ "dynamic_7: md5(md5($p).$s) (vBulletin)", _Funcs_7, _Preloads_7, _ConstDefault, MGF_SALTED|MGF_ColonNOTValid, MGF_KEYS_BASE16_IN1_MD5, 3, 52 },
#endif
	{ "dynamic_8: md5(md5($s).$p)",             _Funcs_8, _Preloads_8, _ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX, MGF_NO_FLAG, -32,  23},
#if defined (SIMD_COEF_32)
	{ "dynamic_9: md5($s.md5($p))",             _Funcs_9, _Preloads_9, _ConstDefault, MGF_SALTED, MGF_KEYS_CRYPT_IN2, -23, 55, 80 },
#else
	{ "dynamic_9: md5($s.md5($p))",             _Funcs_9, _Preloads_9, _ConstDefault, MGF_SALTED, MGF_KEYS_BASE16_IN1_MD5, -23, 55, 80 },
#endif
	{ "dynamic_10: md5($s.md5($s.$p))",         _Funcs_10,_Preloads_10,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -23 },
	{ "dynamic_11: md5($s.md5($p.$s))",         _Funcs_11,_Preloads_11,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -23 },

	{ "dynamic_12: md5(md5($s).md5($p)) (IPB)", _Funcs_12,_Preloads_12,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_Offset_MD5, -32, 110, 110 },
	{ "dynamic_13: md5(md5($p).md5($s))",       _Funcs_13,_Preloads_13,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_MD5, -32, 110, 110 },
#if defined (SIMD_COEF_32)
	{ "dynamic_14: md5($s.md5($p).$s)",         _Funcs_14,_Preloads_14,_ConstDefault, MGF_SALTED,MGF_KEYS_CRYPT_IN2, -11, 55, 80, -24 },
#else
	{ "dynamic_14: md5($s.md5($p).$s)",          _Funcs_14,_Preloads_14,_ConstDefault, MGF_SALTED, MGF_KEYS_BASE16_IN1_MD5, -11, 55, 80, -24},
#endif
	{ "dynamic_15: md5($u.md5($p).$s)",         _Funcs_15,_Preloads_15,_ConstDefault, MGF_SALTED|MGF_USERNAME|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_MD5, -32, 110, 110 },
	{ "dynamic_16: md5(md5(md5($p).$s).$s2)",   _Funcs_16,_Preloads_16,_ConstDefault, MGF_SALTED|MGF_SALTED2|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_MD5, -32, 110, 110 },
#if 0
	// this format has been removed. It has served its purpose. Now, the
	// phpass 'fat' format is back, as fast as this, and does OMP properly.
	// Also the fat phpass handled all dynamic_17 in input and in .pot
	// files, converting them back into proper phpass (with $P$ signature).
	// this format has been removed from dynamic.
	#if !ARCH_LITTLE_ENDIAN
	{ "dynamic_17: phpass ($P$ or $H$)",        _Funcs_17,_Preloads_17,_ConstDefault, MGF_SALTED|MGF_INPBASE64, MGF_phpassSetup, 9, 38, 38 },
	#else
	{ "dynamic_17: phpass ($P$ or $H$)",        _Funcs_17,_Preloads_17,_ConstDefault, MGF_SALTED|MGF_INPBASE64, MGF_phpassSetup, 9, 38 },
	#endif
#endif
	{ "dynamic_18: md5($s.Y.$p.0xF7.$s) (Post.Office MD5)",  _Funcs_18,_Preloads_18,_Const_18,     MGF_SALTED|MGF_NOTSSE2Safe, MGF_POSetup, 32, 110, 110 },
	{ "dynamic_19: md5($p) (Cisco PIX)",        _Funcs_19,_Preloads_19,_ConstDefault, MGF_INPBASE64_4x6, MGF_NO_FLAG, 0, 16, 16 },
	{ "dynamic_20: md5($p.$s) (Cisco ASA)",     _Funcs_20,_Preloads_20,_ConstDefault, MGF_INPBASE64_4x6|MGF_SALTED, MGF_NO_FLAG, -4, 12, 12 },
#if 0
	// this format has been removed. It has served its purpose. Now, the HDAA
	// format does SIMD, and is much faster and better than this format.
	// BUT do not ever re-use dynamic_21 for other formats....
	{ "dynamic_21: HTTP Digest Access Auth",    _Funcs_21,_Preloads_21,_Const_21,     MGF_HDAA_SALT|MGF_USERNAME|MGF_FLD2|MGF_FLD3|MGF_FLD4|MGF_SALTED, MGF_NO_FLAG, 0, 26, 26 },
#endif
	{ "dynamic_22: md5(sha1($p))",              _Funcs_22,_Preloads_22,_ConstDefault, MGF_StartInX86Mode, MGF_KEYS_INPUT },
	{ "dynamic_23: sha1(md5($p))",              _Funcs_23,_Preloads_23,_ConstDefault, MGF_NO_FLAG, MGF_INPUT_20_BYTE|MGF_KEYS_INPUT },
	{ "dynamic_24: sha1($p.$s)",                _Funcs_24,_Preloads_24,_ConstDefault, MGF_FLAT_BUFFERS|MGF_SALTED, MGF_NO_FLAG|MGF_INPUT_20_BYTE, -64, 110, 110 },
	{ "dynamic_25: sha1($s.$p)",                _Funcs_25,_Preloads_25,_ConstDefault, MGF_FLAT_BUFFERS|MGF_SALTED, MGF_NO_FLAG|MGF_INPUT_20_BYTE, -64, 110, 110 },
	{ "dynamic_26: sha1($p) raw-sha1",          _Funcs_26,_Preloads_26,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE },
// Dyna 27/28 have been removed, Spring of 2013.  These dyna numbers should NOT be reused for any purpose.
//dynamic_27 --> FreeBSD MD5
//dynamic_28 --> Apache MD5
	{ "dynamic_29: md5(utf16($p))",             _Funcs_29,_Preloads_29,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_30: md4($p) (raw-md4)",          _Funcs_30,_Preloads_30,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT },
	{ "dynamic_31: md4($s.$p)",                 _Funcs_31,_Preloads_31,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_32: md4($p.$s)",                 _Funcs_32,_Preloads_32,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_33: md4(utf16($p))",             _Funcs_33,_Preloads_33,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_34: md5(md4($p))",               _Funcs_34,_Preloads_34,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_35: sha1(uc($u).:.$p) (ManGOS)", _Funcs_35,_Preloads_35,_Const_35,     MGF_FLAT_BUFFERS|MGF_USERNAME_UPCASE, MGF_INPUT_20_BYTE, -64, 110, 110 },
	{ "dynamic_36: sha1($u.:.$p) (ManGOS2)",    _Funcs_36,_Preloads_36,_Const_36,     MGF_FLAT_BUFFERS|MGF_USERNAME, MGF_INPUT_20_BYTE, -64, 110, 110 },
	{ "dynamic_37: sha1(lc($u).$p) (SMF)",      _Funcs_37,_Preloads_37,_ConstDefault,MGF_FLAT_BUFFERS| MGF_USERNAME_LOCASE, MGF_INPUT_20_BYTE, -64, 110, 110 },
	{ "dynamic_38: sha1($s.sha1($s.sha1($p))) (Wolt3BB)",  _Funcs_38,_Preloads_38,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_20_BYTE, -64, 110, 110 },
	{ "dynamic_39: md5($s.pad16($p)) (net-md5)",  _Funcs_39,_Preloads_39,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_NO_FLAG, -230, 16, 16 },
	{ "dynamic_40: sha1($s.pad20($p)) (net-sha1)",  _Funcs_40,_Preloads_40,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_20_BYTE, -230, 20, 20 },

	SETUP_LARGE_HASH_SIMD(sha224,MGF_KEYS_BASE16_IN1_SHA224,MGF_SALT_AS_HEX_SHA224,5,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH_SIMD(sha256,MGF_KEYS_BASE16_IN1_SHA256,MGF_SALT_AS_HEX_SHA256,6,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH_SIMD(sha384,MGF_KEYS_BASE16_IN1_SHA384,MGF_SALT_AS_HEX_SHA384,7,MGF_INPUT_48_BYTE)
	{ "dynamic_80: sha512($p)",                  _Funcs_80,_Preloads_80,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_81: sha512($s.$p)",               _Funcs_81,_Preloads_81,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_64_BYTE, -64, 110, 110 },
	{ "dynamic_82: sha512($p.$s)",               _Funcs_82,_Preloads_82,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_64_BYTE, -64, 110, 110 },
	{ "dynamic_83: sha512(sha512($p))",          _Funcs_83,_Preloads_83,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_84: sha512(sha512_raw($p))",      _Funcs_84,_Preloads_84,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_85: sha512(sha512($p).$s)",       _Funcs_85,_Preloads_85,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_SHA512|MGF_INPUT_64_BYTE, -64, 110, 110 },
	{ "dynamic_86: sha512($s.sha512($p))",       _Funcs_86,_Preloads_86,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_BASE16_IN1_SHA512|MGF_INPUT_64_BYTE, -64, 110, 110 },
#ifndef SIMD_COEF_64
	{ "dynamic_87: sha512(sha512($s).sha512($p))",_Funcs_87,_Preloads_87,_ConstDefault, MGF_SALT_AS_HEX_SHA512|MGF_NOTSSE2Safe, MGF_KEYS_BASE16_IN1_SHA512|MGF_INPUT_64_BYTE, -64, 110, 110 },
	{ "dynamic_88: sha512(sha512($p).sha512($p))",_Funcs_88,_Preloads_88,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
#endif
	SETUP_LARGE_HASH(gost,      MGF_KEYS_BASE16_IN1_GOST,      MGF_SALT_AS_HEX_GOST,       9,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(whirlpool, MGF_KEYS_BASE16_IN1_WHIRLPOOL, MGF_SALT_AS_HEX_WHIRLPOOL, 10,MGF_INPUT_64_BYTE)
	SETUP_LARGE_HASH(tiger,     MGF_KEYS_BASE16_IN1_Tiger,     MGF_SALT_AS_HEX_Tiger,     11,MGF_INPUT_24_BYTE)
	SETUP_LARGE_HASH(ripemd128, MGF_KEYS_BASE16_IN1_RIPEMD128, MGF_SALT_AS_HEX_RIPEMD128, 12,0)
	SETUP_LARGE_HASH(ripemd160, MGF_KEYS_BASE16_IN1_RIPEMD160, MGF_SALT_AS_HEX_RIPEMD160, 13,MGF_INPUT_20_BYTE)
	SETUP_LARGE_HASH(ripemd256, MGF_KEYS_BASE16_IN1_RIPEMD256, MGF_SALT_AS_HEX_RIPEMD256, 14,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(ripemd320, MGF_KEYS_BASE16_IN1_RIPEMD320, MGF_SALT_AS_HEX_RIPEMD320, 15,MGF_INPUT_40_BYTE)
	SETUP_LARGE_HASH(haval128_3,MGF_KEYS_BASE16_IN1_HAVAL128_3,MGF_SALT_AS_HEX_HAVAL128_3,16,0)
	SETUP_LARGE_HASH(haval128_4,MGF_KEYS_BASE16_IN1_HAVAL128_4,MGF_SALT_AS_HEX_HAVAL128_4,17,0)
	SETUP_LARGE_HASH(haval128_5,MGF_KEYS_BASE16_IN1_HAVAL128_5,MGF_SALT_AS_HEX_HAVAL128_5,18,0)
	SETUP_LARGE_HASH(haval160_3,MGF_KEYS_BASE16_IN1_HAVAL160_3,MGF_SALT_AS_HEX_HAVAL160_3,19,MGF_INPUT_20_BYTE)
	SETUP_LARGE_HASH(haval160_4,MGF_KEYS_BASE16_IN1_HAVAL160_4,MGF_SALT_AS_HEX_HAVAL160_4,20,MGF_INPUT_20_BYTE)
	SETUP_LARGE_HASH(haval160_5,MGF_KEYS_BASE16_IN1_HAVAL160_5,MGF_SALT_AS_HEX_HAVAL160_5,21,MGF_INPUT_20_BYTE)
	SETUP_LARGE_HASH(haval192_3,MGF_KEYS_BASE16_IN1_HAVAL192_3,MGF_SALT_AS_HEX_HAVAL192_3,22,MGF_INPUT_24_BYTE)
	SETUP_LARGE_HASH(haval192_4,MGF_KEYS_BASE16_IN1_HAVAL192_4,MGF_SALT_AS_HEX_HAVAL192_4,23,MGF_INPUT_24_BYTE)
	SETUP_LARGE_HASH(haval192_5,MGF_KEYS_BASE16_IN1_HAVAL192_5,MGF_SALT_AS_HEX_HAVAL192_5,24,MGF_INPUT_24_BYTE)
	SETUP_LARGE_HASH(haval224_3,MGF_KEYS_BASE16_IN1_HAVAL224_3,MGF_SALT_AS_HEX_HAVAL224_3,25,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH(haval224_4,MGF_KEYS_BASE16_IN1_HAVAL224_4,MGF_SALT_AS_HEX_HAVAL224_4,26,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH(haval224_5,MGF_KEYS_BASE16_IN1_HAVAL224_5,MGF_SALT_AS_HEX_HAVAL224_5,27,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH(haval256_3,MGF_KEYS_BASE16_IN1_HAVAL256_3,MGF_SALT_AS_HEX_HAVAL256_3,28,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(haval256_4,MGF_KEYS_BASE16_IN1_HAVAL256_4,MGF_SALT_AS_HEX_HAVAL256_4,29,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(haval256_5,MGF_KEYS_BASE16_IN1_HAVAL256_5,MGF_SALT_AS_HEX_HAVAL256_5,30,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(md2,       MGF_KEYS_BASE16_IN1_MD2,       MGF_SALT_AS_HEX_MD2,       31,0)
	SETUP_LARGE_HASH(panama,    MGF_KEYS_BASE16_IN1_PANAMA,    MGF_SALT_AS_HEX_PANAMA,    32,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(skein224,  MGF_KEYS_BASE16_IN1_SKEIN224,  MGF_SALT_AS_HEX_SKEIN224,  33,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH(skein256,  MGF_KEYS_BASE16_IN1_SKEIN256,  MGF_SALT_AS_HEX_SKEIN256,  34,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(skein384,  MGF_KEYS_BASE16_IN1_SKEIN384,  MGF_SALT_AS_HEX_SKEIN384,  35,MGF_INPUT_48_BYTE)
	SETUP_LARGE_HASH(skein512,  MGF_KEYS_BASE16_IN1_SKEIN512,  MGF_SALT_AS_HEX_SKEIN512,  36,MGF_INPUT_64_BYTE)
	SETUP_LARGE_HASH(sha3_224,  MGF_KEYS_BASE16_IN1_SHA3_224,  MGF_SALT_AS_HEX_SHA3_224,  37,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH(sha3_256,  MGF_KEYS_BASE16_IN1_SHA3_256,  MGF_SALT_AS_HEX_SHA3_256,  38,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(sha3_384,  MGF_KEYS_BASE16_IN1_SHA3_384,  MGF_SALT_AS_HEX_SHA3_384,  39,MGF_INPUT_48_BYTE)
	SETUP_LARGE_HASH(sha3_512,  MGF_KEYS_BASE16_IN1_SHA3_512,  MGF_SALT_AS_HEX_SHA3_512,  40,MGF_INPUT_64_BYTE)
	SETUP_LARGE_HASH(keccak_256,  MGF_KEYS_BASE16_IN1_KECCAK_256,  MGF_SALT_AS_HEX_KECCAK_256,  41,MGF_INPUT_32_BYTE)
	SETUP_LARGE_HASH(keccak_512,  MGF_KEYS_BASE16_IN1_KECCAK_512,  MGF_SALT_AS_HEX_KECCAK_512,  42,MGF_INPUT_64_BYTE)
	SETUP_LARGE_HASH(keccak_224,  MGF_KEYS_BASE16_IN1_KECCAK_224,  MGF_SALT_AS_HEX_KECCAK_224,  43,MGF_INPUT_28_BYTE)
	SETUP_LARGE_HASH(keccak_384,  MGF_KEYS_BASE16_IN1_KECCAK_384,  MGF_SALT_AS_HEX_KECCAK_384,  44,MGF_INPUT_48_BYTE)
	// LARGE_HASH_EDIT_POINT
};

char *dynamic_PRELOAD_SIGNATURE(int cnt)
{
	if (cnt >= 0 && cnt < ARRAY_COUNT(Setups))
		return Setups[cnt].szFORMAT_NAME;
	return NULL;
}

int dynamic_RESERVED_PRELOAD_SETUP(int cnt, struct fmt_main *pFmt)
{
	char Type[20];
	int len;
	sprintf(Type, "dynamic_%d:", cnt);
	len = strlen(Type);
	if (cnt < 0 || cnt > 1000)
		return 0;
	if (cnt >= ARRAY_COUNT(Setups) || strncmp(Type, Setups[cnt].szFORMAT_NAME, len)) {
		int j,bGood=0;
		len=strlen(Type);
		for (j = 0; j < ARRAY_COUNT(Setups); ++j) {
			if (!strncmp(Type, Setups[j].szFORMAT_NAME, len)) {
				bGood = 1;
				break;
			}
		}
		if (!bGood)
		return 0;
		return dynamic_SETUP(&Setups[j], pFmt);
	}
	return dynamic_SETUP(&Setups[cnt], pFmt);
}

// -1 is NOT valid  ( num >= 5000 is 'hidden' values )
// 0 is valid, but NOT usable by this build (i.e. no SSE2).
//   NOTE, now only a couple things are not valid. We build ALL formats
//   even SSE problem functions under OMP. We turn off OMP for these formats
//   but the format is INCLUDED in the build.  A couple things are still left
//   in the parser as invalid (such as non-colon separators, etc).
// 1 is valid.
int dynamic_IS_VALID(int i, int single_lookup_only)
{
	static signed char valid[5001];
	static int init=0;
	int j;

	if (single_lookup_only) {
		// if only loading a single dyna format, then do NOT load the valid array
		if (i < 1000) {
			for (j = 0; j < ARRAY_COUNT(Setups); ++j) {
				if (atoi(&Setups[j].szFORMAT_NAME[8]) == i)
					return 1;
			}
			return 0;
		}
		if (!dynamic_IS_PARSER_VALID(i, 1))
			return 0;
		return 1;
	}
	if (!init) {
		memset(valid, -1, sizeof(valid));
		for (j = 0; j < ARRAY_COUNT(Setups); ++j) {
			int k = atoi(&Setups[j].szFORMAT_NAME[8]);
			if (k >= 0 && k < 1000)
				valid[k] = 1;
		}
		for (j = 1000; j < 5000; ++j) {
			if (dynamic_IS_PARSER_VALID(j, 0) != -1)
				valid[j] = 1;
		}
		init = 1;
	}
	if (i < 0 || i >= 5000)
		return -1;
	return valid[i];
}

#endif /* DYNAMIC_DISABLED */
