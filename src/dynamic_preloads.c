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

#include "arch.h"
#if defined (MMX_COEF) && MMX_COEF==2 && defined (_OPENMP)
#undef _OPENMP
#endif
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "dynamic.h"

#ifdef MD5_SSE_PARA
#undef MMX_COEF
#define MMX_COEF 4
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
//dynamic_13 --> md5(md5($p).md5($s))
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
//dynamic_29 --> md5(unicode($p))			// raw-md5-unicode
//dynamic_30 --> md4($p)                    // raw-md4
//dynamic_31 --> md4($s.$p)
//dynamic_32 --> md4($p.$s)
//dynamic_33 --> md4(unicode($p))			// NT
//dynamic_34 --> md5(md4($p))
//dynamic_35 -->sha1(uc($u).:.$p) (ManGOS)
//dynamic_36 -->sha1($u.:.$p) (ManGOS2)
//dynamic_37 -->sha1(lc($u).$p) (SMF)
//dynamic_38 -->sha1($s.sha1($s.sha1($p))) (Wolt3BB)
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
	// Try to group sha384 here (from dyna-70 to dyna-79)
//dynamic_70 -->sha384($p)
//dynamic_71 -->sha384($s.$p)
//dynamic_72 -->sha384($p.$s)
//dynamic_73 -->sha384(sha384($p))
//dynamic_74 -->sha384(sha384_raw($p))
//dynamic_75 -->sha384(sha384($p).$s)
//dynamic_76 -->sha384($s.sha384($p))
//dynamic_77 -->sha384(sha384($s).sha384($p))
//dynamic_78 -->sha384(sha384($p).sha384($p))
	// Try to group sha512 here (from dyna-80 to dyna-89)
//dynamic_80 -->sha512($p)
//dynamic_81 -->sha512($s.$p)
//dynamic_82 -->sha512($p.$s)
//dynamic_83 -->sha512(sha512($p))
//dynamic_84 -->sha512(sha512_raw($p))
//dynamic_85 -->sha512(sha512($p).$s)
//dynamic_86 -->sha512($s.sha512($p))
//dynamic_87 -->sha512(sha512($s).sha512($p))
//dynamic_88 -->sha512(sha512($p).sha512($p))
	// Try to group GOST here (from dyna-90 to dyna-99)
//dynamic_90 -->GOST($p)
//dynamic_91 -->GOST($s.$p)
//dynamic_92 -->GOST($p.$s)
//dynamic_93 -->GOST(GOST($p))
//dynamic_94 -->GOST(GOST_raw($p))
//dynamic_95 -->GOST(GOST($p).$s)
//dynamic_96 -->GOST($s.GOST($p))
//dynamic_97 -->GOST(GOST($s).GOST($p))
//dynamic_98 -->GOST(GOST($p).GOST($p))
	// Try to group WHIRLPOOL here (from dyna-100 to dyna-109)
//dynamic_100 -->WHIRLPOOL($p)
//dynamic_101 -->WHIRLPOOL($s.$p)
//dynamic_102 -->WHIRLPOOL($p.$s)
//dynamic_103 -->WHIRLPOOL(WHIRLPOOL($p))
//dynamic_104 -->WHIRLPOOL(WHIRLPOOL_raw($p))
//dynamic_105 -->WHIRLPOOL(WHIRLPOOL($p).$s)
//dynamic_106 -->WHIRLPOOL($s.WHIRLPOOL($p))
//dynamic_107 -->WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p))
//dynamic_108 -->WHIRLPOOL(WHIRLPOOL($p).WHIRLPOOL($p))
	// Try to group Tiger here (from dyna-110 to dyna-119)
//dynamic_110 -->Tiger($p)
//dynamic_111 -->Tiger($s.$p)
//dynamic_112 -->Tiger($p.$s)
//dynamic_113 -->Tiger(Tiger($p))
//dynamic_114 -->Tiger(Tiger_raw($p))
//dynamic_115 -->Tiger(Tiger($p).$s)
//dynamic_116 -->Tiger($s.Tiger($p))
//dynamic_117 -->Tiger(Tiger($s).Tiger($p))
//dynamic_118 -->Tiger(Tiger($p).Tiger($p))
	// Try to group RIPEMD128 here (from dyna-120 to dyna-129)
//dynamic_120 -->RIPEMD128($p)
//dynamic_121 -->RIPEMD128($s.$p)
//dynamic_122 -->RIPEMD128($p.$s)
//dynamic_123 -->RIPEMD128(RIPEMD128($p))
//dynamic_124 -->RIPEMD128(RIPEMD128_raw($p))
//dynamic_125 -->RIPEMD128(RIPEMD128($p).$s)
//dynamic_126 -->RIPEMD128($s.RIPEMD128($p))
//dynamic_127 -->RIPEMD128(RIPEMD128($s).RIPEMD128($p))
//dynamic_128 -->RIPEMD128(RIPEMD128($p).RIPEMD128($p))
	// Try to group RIPEMD160 here (from dyna-130 to dyna-139)
//dynamic_130 -->RIPEMD160($p)
//dynamic_131 -->RIPEMD160($s.$p)
//dynamic_132 -->RIPEMD160($p.$s)
//dynamic_133 -->RIPEMD160(RIPEMD160($p))
//dynamic_134 -->RIPEMD160(RIPEMD160_raw($p))
//dynamic_135 -->RIPEMD160(RIPEMD160($p).$s)
//dynamic_136 -->RIPEMD160($s.RIPEMD160($p))
//dynamic_137 -->RIPEMD160(RIPEMD160($s).RIPEMD160($p))
//dynamic_138 -->RIPEMD160(RIPEMD160($p).RIPEMD160($p))
	// Try to group RIPEMD256 here (from dyna-140 to dyna-149)
//dynamic_140 -->RIPEMD256($p)
//dynamic_141 -->RIPEMD256($s.$p)
//dynamic_142 -->RIPEMD256($p.$s)
//dynamic_143 -->RIPEMD256(RIPEMD256($p))
//dynamic_144 -->RIPEMD256(RIPEMD256_raw($p))
//dynamic_145 -->RIPEMD256(RIPEMD256($p).$s)
//dynamic_146 -->RIPEMD256($s.RIPEMD256($p))
//dynamic_147 -->RIPEMD256(RIPEMD256($s).RIPEMD256($p))
//dynamic_148 -->RIPEMD256(RIPEMD256($p).RIPEMD256($p))
	// Try to group RIPEMD320 here (from dyna-150 to dyna-159)
//dynamic_150 -->RIPEMD320($p)
//dynamic_151 -->RIPEMD320($s.$p)
//dynamic_152 -->RIPEMD320($p.$s)
//dynamic_153 -->RIPEMD320(RIPEMD320($p))
//dynamic_154 -->RIPEMD320(RIPEMD320_raw($p))
//dynamic_155 -->RIPEMD320(RIPEMD320($p).$s)
//dynamic_156 -->RIPEMD320($s.RIPEMD320($p))
//dynamic_157 -->RIPEMD320(RIPEMD320($s).RIPEMD320($p))
//dynamic_158 -->RIPEMD320(RIPEMD320($p).RIPEMD320($p))


static DYNAMIC_primitive_funcp _Funcs_0[] =
{
	//MGF_KEYS_INPUT
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_0[] =
{
	{"$dynamic_0$5a105e8b9d40e1329780d62ea2265d8a","test1"},
	{"$dynamic_0$378e2c4a07968da2eca692320136433d","thatsworking"},
	{"$dynamic_0$8ad8757baa8564dc136c1e07507f4a98","test3"},
	{"$dynamic_0$c9ccf168914a1bcfc3229f1948e67da0","1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_0$57edf4a22be3c955ac49da2e2107b67a","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
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
	{"$dynamic_1$ff979803ae8048aced292752c8c2cb03$12345678901234567890123456789012", "12345678901234567890123"},
#ifndef MMX_COEF
	{"$dynamic_1$2554e084ca33c249ae7105c6482dda60$12345678901234567890123456789012", "123456789012345678901234567890123456789012345678"},
#endif
	{NULL}
};


// dynamic_2  md5(md5($p))
static DYNAMIC_primitive_funcp _Funcs_2[] =
{
	//MGF_KEYS_INPUT
	DynamicFunc__crypt_md5,
	//DynamicFunc__clean_input2_kwik,
	//DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix,
	DynamicFunc__set_input2_len_32,

	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_2[] =
{
	{"$dynamic_2$418d89a45edadb8ce4da17e07f72536c","test1"},
	{"$dynamic_2$ccd3c4231a072b5e13856a2059d04fad","thatsworking"},
	{"$dynamic_2$9992295627e7e7162bdf77f14734acf8","test3"},
	{"$dynamic_2$4da0b552b078998f671795b925aed4ae","1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_2$c2c683fad194ae92af02c98519b24e9f","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};
// dynamic_3  md5(md5(md5($p)))
static DYNAMIC_primitive_funcp _Funcs_3[] =
{
	//MGF_KEYS_INPUT
	DynamicFunc__crypt_md5,
	//DynamicFunc__clean_input2_kwik,
	//DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix,
	DynamicFunc__set_input2_len_32,

	DynamicFunc__crypt2_md5,
	//DynamicFunc__clean_input2_kwik,
	//DynamicFunc__append_from_last_output2_as_base16,
	DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix,
	DynamicFunc__set_input2_len_32,

	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_3[] =
{
	{"$dynamic_3$964c02612b2a1013ed26d46ba9a73e74","test1"},
	{"$dynamic_3$5d7e6330f69548797c07d97c915690fe","thatsworking"},
	{"$dynamic_3$2e54db8c72b312007f3f228d9d4dd34d","test3"},
	{"$dynamic_3$7f1e5f4cace82433c8d63a19e1b2c413","1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_3$6129e5eb9f595f8661b889d6d95085e5","12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_4 --> md5($s.$p)
static DYNAMIC_primitive_funcp _Funcs_4[] =
{
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
	{"$dynamic_4$2cec94d4cfdbd3494174e0dc6c089690$123456789012345678901234","1234567890123456789012345678901"},
#ifndef MMX_COEF
	{"$dynamic_4$43801689631a0113fcb5d3cfaad0431f$123456789012345678901234","12345678901234567890123456789012345678901234567890123456"},
#endif
	{NULL}
};

//dynamic_5 --> md5($s.$p.$s)
static DYNAMIC_primitive_funcp _Funcs_5[] =
{
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
	{"$dynamic_5$6a322a856f03abd780a9c6766a03eb79$123456789012","1234567890123456789012345678901"},
#ifndef MMX_COEF
	{"$dynamic_5$10c50d85674ff20ca34f582894bc688d$123456789012","12345678901234567890123456789012345678901234567890123456"},
#endif
	{NULL}
};

//dynamic_6 --> md5(md5($p).$s)
static DYNAMIC_primitive_funcp _Funcs_6[] =
{
	//MGF_KEYS_BASE16_IN1
#if ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input_len_32,
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
static struct fmt_tests _Preloads_6[] =
{
	{"$dynamic_6$3a9ae23758f05da1fe539e55a096b03b$S111XB","test1"},
	{"$dynamic_6$9694d706d1992abf04344c1e7da1c5d3$T &222","thatsworking"},
	{"$dynamic_6$b7a7f0c374d73fac422bb01f07f5a9d4$lxxxl","test3"},
	{"$dynamic_6$9164fe53be481f811f15efd769aaf0f7$aReallyLongSaltHere","test3"},
	{"$dynamic_6$22fb37a13d47d420b73cb89773764be2$12345678901234567890123", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_6$2099aa2c138eb97713e790b6c49012e5$12345678901234567890123", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

#if 0
//dynamic_7 --> md5(md5($p).$s) vBulletin  (forced 3 byte salt, valid chars from 0x20 to 0x7E)
static DYNAMIC_primitive_funcp _Funcs_7[] =
{
	//MGF_KEYS_BASE16_IN1
#if ARCH_LITTLE_ENDIAN
	DynamicFunc__set_input_len_32,
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
	{"$dynamic_8$23f865a14edba990cd1bff1f113fd0a0$12345678901234567890123456789012", "12345678901234567890123"},
#ifndef MMX_COEF
	{"$dynamic_8$a5c3893a720936da50edad336ea14f46$12345678901234567890123456789012", "123456789012345678901234567890123456789012345678"},
#endif
	{NULL}
};

//dynamic_9 --> md5($s.md5($p))
static DYNAMIC_primitive_funcp _Funcs_9[] =
{
#if defined (MMX_COEF)
	//MGF_KEYS_CRYPT_IN2
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_from_last_output2_to_input1_as_base16,
	DynamicFunc__crypt_md5,
	NULL
#else
	//MGF_KEYS_BASE16_IN1
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
	{"$dynamic_9$1d01316a7bc597a5b2743f2da41b10ef$12345678901234567890123", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_9$299d55d735d64bb70f517312a2a62946$12345678901234567890123", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
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
	{"$dynamic_10$b40b30cba281d45c54c12b1b54c6b278$12345678901234567890123", "12345678901234567890123456789012"},
#ifndef MMX_COEF
	{"$dynamic_10$0d6e0b9feace8cd90de6e2e683eba981$12345678901234567890123", "123456789012345678901234567890123456789012345678901234567"},
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
	{"$dynamic_11$e2e915bd2946037165f4000b0b38aaa9$12345678901234567890123", "12345678901234567890123456789012"},
#ifndef MMX_COEF
	{"$dynamic_11$b2b3fe7e67e191782faa16d8440c1a26$12345678901234567890123", "123456789012345678901234567890123456789012345678901234567"},
#endif
	{NULL}
};

//dynamic_12 --> md5(md5($s).md5($p))
static DYNAMIC_primitive_funcp _Funcs_12[] =
{
#if defined (MMX_COEF) && defined (_OPENMP)
	//MGF_NOTSSE2Safe
	//MGF_KEYS_BASE16_IN1_Offset32
	//MGF_SALT_AS_HEX
	DynamicFunc__overwrite_salt_to_input1_no_size_fix,
	DynamicFunc__set_input_len_64,
	DynamicFunc__crypt_md5,
	NULL
#else
	//MGF_KEYS_BASE16_X86_IN1_Offset32
	//MGF_SALT_AS_HEX
	DynamicFunc__ToX86,
	DynamicFunc__overwrite_salt_to_input1_no_size_fix,
	DynamicFunc__set_input_len_64,
	DynamicFunc__crypt_md5,
	NULL
#endif
};
static struct fmt_tests _Preloads_12[] =
{
	{"$dynamic_12$fbbd9532460f2d03fa8af9e75c41eefc$aaaSXB","test1"},
	{"$dynamic_12$b80eef24d1d01b61b3beff38559f9d26$123456","thatsworking"},
	{"$dynamic_12$1e5489bdca008aeed6e390ee87ce9b92$5555hh","test3"},
	{"$dynamic_12$c007ee1aa43f0a8450e575517e7b4ef5$12345678901234567890123456789012", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_12$e66a3b5b2b9370e0fa9bc4cfe7047b83$12345678901234567890123456789012", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_13 --> md5(md5($p).md5($s))
static DYNAMIC_primitive_funcp _Funcs_13[] =
{
#if defined (MMX_COEF) && defined (_OPENMP)
	//MGF_NOTSSE2Safe
	//MGF_KEYS_BASE16_IN1
	//MGF_SALT_AS_HEX
	DynamicFunc__set_input_len_32,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
#else
	//MGF_KEYS_BASE16_X86_IN1
	//MGF_SALT_AS_HEX
	DynamicFunc__ToX86,
	DynamicFunc__set_input_len_32,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
#endif
};
static struct fmt_tests _Preloads_13[] =
{
	{"$dynamic_13$c6b69bec81d9ff5d0560d8f469a8efd5$aaaSXB","test1"},
	{"$dynamic_13$7abf788b3abbfc8719d900af96a3763a$123456","thatsworking"},
	{"$dynamic_13$1c55e15102ed17eabe5bf11271c7fcae$5555hh","test3"},
	{"$dynamic_13$9526ec2544b7bfbf4d9cb6ee0e885ac8$12345678901234567890123456789012", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_13$29cee0e036f35db11b93efd784eb5932$12345678901234567890123456789012", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_14 --> md5($s.md5($p).$s)
static DYNAMIC_primitive_funcp _Funcs_14[] =
{
#if defined (MMX_COEF)
	//MGF_KEYS_CRYPT_IN2
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_from_last_output2_to_input1_as_base16,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL
#else
	//MGF_KEYS_BASE16_IN1
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
	{"$dynamic_14$6aaa97fcf40c519006926520af3264fd$12345678901", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_14$abdb659cdc44d5fde6b238f7013f71dc$12345678901", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_15 --> md5($u.md5($p).$s)
static DYNAMIC_primitive_funcp _Funcs_15[] =
{
//#if defined (MMX_COEF)
//	// -any    Many salts: 3264K Only one salt:  1677K
//	// -sse2i  Many salts: 3195K Only one salt:  1638K  (md5_asm 1, md5_x2 0  md5_imm 1)
//  // generic Many salts: 3539K Only one salt:  1843K  (md5_asm 0, md5_x2 1  md5_imm 1)
//	// MGF_KEYS_CRYPT_IN2
//	DynamicFunc__clean_input,
//	DynamicFunc__append_userid,
//	DynamicFunc__append_from_last_output2_to_input1_as_base16,
//	DynamicFunc__append_salt,
//	DynamicFunc__crypt_md5,
//	NULL
//#else
	// -any    Many salts: 3401K Only one salt:  1515K
	// -sse2i  Many salts: 3412K Only one salt:  1510K  (md5_asm 1, md5_x2 0  md5_imm 1)
	// generic Many salts: 3688K Only one salt:  1666K  (md5_asm 0, md5_x2 1  md5_imm 1)
	// MGF_KEYS_BASE16_IN1
	DynamicFunc__clean_input2,
	DynamicFunc__append_userid2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
//#endif
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
	{"$dynamic_15$a2609e968a7124a8ac299c5f03341b85$123456789012$$Ubarney", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_15$230942ea4c6f83d50ce2498cae73a83c$123456789012$$Uripper", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_16 --> md5(md5(md5($p).$s).$s2)
static DYNAMIC_primitive_funcp _Funcs_16[] =
{
	//MGF_KEYS_BASE16_IN1
	DynamicFunc__clean_input2,
	DynamicFunc__append_input2_from_input,
	DynamicFunc__append_salt2,
	DynamicFunc__crypt2_md5,
	DynamicFunc__clean_input2,
	DynamicFunc__append_from_last_output2_as_base16,
	DynamicFunc__append_2nd_salt2,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_16[] =
{
	// NOTE the $ is the byte starting the salt block, and the $$2 is the
	// pattern showing where to 'split off' the
	{"$dynamic_16$5ce496c635f96ac1ccd87518d4274b49$aaaSXB$$2salt2","test1"},
	{"$dynamic_16$2f49a8804a3aee4da3c219539fc93c6d$123456$$2ssss2","thatsworking"},
	{"$dynamic_16$d8deb4f271694c7a9a6c54f5068e3825$5555hh$$2sxxx3","test3"},
	{"$dynamic_16$0b714c79c5790c913a6e44faad39f597$12345678901234567890123$$23IJIps", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_16$1e27f26c540f2980809f4d74989e20e3$12345678901234567890123$$2730ZnC", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//dynamic_17$ --> $P$9 phpass (or $H$7, $P$A, ... )
static DYNAMIC_primitive_funcp _Funcs_17[] =
{
	//MGF_PHPassSetup
	DynamicFunc__PHPassCrypt,
	NULL
};
static struct fmt_tests _Preloads_17[] =
{
	// format:  dynamic_17)hash$Xssssssss
	// Xssssssss is the 9 bytes immediately following the standard
	// signature of $P$  So $P$912345678jgypwqm.JsMssPLiS8YQ00 the
	// 912345678 will be inserted into $Xssssssss
	// ssssssss is the salt, and X is a byte used to count how many
	// times we do the inner md5 crypt packing.
	{"$dynamic_17$jgypwqm.JsMssPLiS8YQ00$9aaaaaSXB","test1"},
	{"$dynamic_17$5R3ueot5zwV.7MyzAItyg/$912345678","thatsworking"},
	{"$dynamic_17$JSe8S8ufpLrsNE7utOpWc/$BaaaaaSXB","test1"},
	{"$dynamic_17$mwulIMWPGe6RPXG1/R8l50$712345678","thatsworking"},

	// Place last, so this is the 'timing' test for 'single salt'
	{"$dynamic_17$Y5RwgMij0xFsUIrr33lM1/$9555555hh","test3"},

	{"$dynamic_17$JyPbSuePnNXiY9336yq0R1$9Auz3pFS7", "12345678901234567890123456789012345678"},
#ifndef MMX_COEF
	{"$dynamic_17$tGuFea/ssk7VS3TBfuokh/$9WCK6e/dw", "12345678901234567890123456789012345678901234567890123456789012345678901"},
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
#ifndef MMX_COEF
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

//dynamic_21 --> HDAA HTTP Digest access authentication
static DYNAMIC_primitive_funcp _Funcs_21[] =
{
	//MGF_HDAA_SALT
	//MGF_FLD2
	//MGF_FLD3
	DynamicFunc__clean_input,
	DynamicFunc__append_userid,
	DynamicFunc__append_input1_from_CONST1,
	DynamicFunc__append_fld2,
	DynamicFunc__append_input1_from_CONST1,
	DynamicFunc__append_keys,
	DynamicFunc__crypt_md5,
	DynamicFunc__SSEtoX86_switch_output1,
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_salt,
	DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_21[] =
{
	{"$dynamic_21$679066476e67b5c7c4e88f04be567f8b$8c12bd8f728afe56d45a0ce846b70e5a$$Uuser$$F2myrealm$$F3GET$/$$F400000001$4b61913cec32e2c9$auth","nocode"},
	{"$dynamic_21$faa6cb7d676e5b7c17fcbf966436aa0c$af32592775d27b1cd06356b3a0db9ddf$$Umoi$$F2myrealm$$F3GET$/$$F400000001$8e1d49754a25aea7$auth","kikou"},
	{NULL}
};
static DYNAMIC_Constants _Const_21[] =
{
	// constants not needed in the DynamicFunc__POCrypt call, but left here for documentation reasons.
	{1, ":"},
	{0, NULL}
};

//dynamic_22 --> md5(sha1($p))
static DYNAMIC_primitive_funcp _Funcs_22[] =
{
	//MGF_StartInX86Mode
	//MGF_KEYS_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__SHA1_crypt_input1_append_input2_base16,
	DynamicFunc__X86toSSE_switch_input2,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_22[] =
{
	{"$dynamic_22$a7168f0f249e3add33da11a59e228a57","test1"},
	{"$dynamic_22$067dda3ad565339fffa61ba74fab0ba3","thatsworking"},
	{"$dynamic_22$71a1083be5c288da7e57b8c2bd7cbc96","test3"},
	{"$dynamic_22$fbbd5aa600379a7964cef214c8a86b8a", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
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
#ifndef MMX_COEF
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
	{"$dynamic_24$25a4840cd23e8094be9941ce0b0fe540d431f981$123456789012345678901234", "1234567890123456789012345678901"},
#ifndef MMX_COEF
	{"$dynamic_24$a38177e70fd9befd978924fa91f69454505c7044$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456"},
#endif
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
	{"$dynamic_25$5801df8089598fdca031b9797b593ea5c82ef13c$123456789012345678901234", "1234567890123456789012345678901"},
#ifndef MMX_COEF
	{"$dynamic_25$15dacaa0504af11934470e0ff654b89a0cfa2397$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456"},
#endif
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
	{"$dynamic_26$827a683fdfdbef225a2421078b7789b134c7eafa", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_26$50abf5706a150990a08b2c5ea40fa0e585554732", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

#if 0
#if !defined (_OPENMP)  && defined (MMX_COEF)
#if ARCH_LITTLE_ENDIAN
//dynamic_27 --> FreeBSD MD5
static DYNAMIC_primitive_funcp _Funcs_27[] =
{
	//MGF_FreeBSDMD5Setup
	//MGF_INPBASE64
	//MGF_SALTED
	//MGF_StartInX86Mode
	DynamicFunc__FreeBSDMD5Crypt,
	NULL
};
static struct fmt_tests _Preloads_27[] =
{
	{"$dynamic_27$C02xyp4O8Wi6/LAEkwVoT1$vjfazyg4","test1"},
	{"$dynamic_27$BdIMOAWFOV2AQlLsrN/Sw.$1234","1234"},
	{"$dynamic_27$Nv.tUZO7PmHiGOEIkp8.2.$kh4r/VjF","test2"},
	{"$dynamic_27$KU7So6H/HpTU32hTZgWz80$KOFeLHvp","john ripper"},
	{"$dynamic_27$TM9iK9z9bFUd8hfd4uEoU1$VD7.Lfhq","LongerPassword"},
	{NULL}
};
static DYNAMIC_Constants _Const_27[] =
{
	{3, "$1$"},
	{0, NULL}
};

//dynamic_28 --> Apache MD5
static DYNAMIC_primitive_funcp _Funcs_28[] =
{
	//MGF_FreeBSDMD5Setup
	//MGF_INPBASE64
	//MGF_SALTED
	//MGF_StartInX86Mode
	DynamicFunc__FreeBSDMD5Crypt,
	NULL
};
static struct fmt_tests _Preloads_28[] =
{
	{"$dynamic_28$z63aHLt/0wBGomn09h6cE0$PmeWFwRA","test1"},
	{"$dynamic_28$E5dH18qiSyTSoU.HqVFvD1$aSEuolRV","test2"},
	{"$dynamic_28$JW5QhVWf5KPMBMXKK.mu10$VnTS8fM5","john ripper"},
	{"$dynamic_28$oIetaUvUng.EN8U6Px6f/.$jdJFaVdA","LongerPassword"},
	{NULL}
};
static DYNAMIC_Constants _Const_28[] =
{
	{6, "$apr1$"},
	{0, NULL}
};
#endif
#endif
#endif

//dynamic_29 --> raw-md5-unicode  md5(unicode($p))
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
#ifndef MMX_COEF
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
#ifndef MMX_COEF
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
#ifndef MMX_COEF
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
#ifndef MMX_COEF
	{"$dynamic_32$7f67e75ef8aead6a1b61afe9a2cb41c8$123456789012345678901234", "12345678901234567890123456789012345678901234567890123456"},
#endif
	{NULL}
};
//dynamic_33 --> md4(unicode($p))			// NT
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
#ifndef MMX_COEF
	{"$dynamic_33$adced3e86b7af2ee3e5131bc2b0bb6cb", "1234567890123456789012345678901234567890"},
#endif
/*
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
*/
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
	DynamicFunc__set_input2_len_32,
	DynamicFunc__crypt_md5_in2_to_out1,
	NULL
};
static struct fmt_tests _Preloads_34[] =
{
	{"$dynamic_34$70bd0343fde5c0ce439b8eaed1c5930d","test1"},
	{"$dynamic_34$7e716c197034cfc4dcdc1d23234bf65a","thatsworking"},
	{"$dynamic_34$68fb8e1b89e88a8d006905edf3c3207f","test3"},
	{"$dynamic_34$1af18a178e07721f618dbe6ef4340aea", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_34$e4f6c3f090122b8002e6d3951327926c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

/* Request from Dhiru Kholia, July 9, 2012
  1. SHA-1(ManGOS) = sha1(strtoupper($username).':'.$pass)
  Works for all private server projects that use the same hashing
  method: trinity, ascent and others.  (Done, Dyna-35)

  2. SHA-1(ManGOS2) = sha1($username.':'.$pass) # already supported?
     (Done, Dyna-36)

  3. sha1(strtolower($username).$pass)
  Example: Admin:6c7ca345f63f835cb353ff15bd6c5e052ec08e7a
  Used in SMF.
  Length: 20 bytes.

  4. sha1($salt.sha1($salt.sha1($pass))) # thick format already exits
  Used in Woltlab BB.
  Length: 20 bytes.
*/

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
	{"$dynamic_35$e01ff7a245202eb8b62a653473f078f6a71b5559$$UNINECHARS","test3"},
	{"$dynamic_35$a12c6e0d8a4bcabb7f588456cbd20eac3332724d","test1",        {"ELEV__CHARS"}},
	{"$dynamic_35$9afbe0bf4e1f24e7e2d9df322b3b284037ac6e19","thatsworking", {"U1"}},
	{"$dynamic_35$e01ff7a245202eb8b62a653473f078f6a71b5559","test3",        {"NINECHARS"}},
	{"$dynamic_35$070f7c0bb6e13e12fc6f777fbc56fc9aeae6cf61$$UADMIN", "12345678901234567890123456789012"},
#ifndef MMX_COEF
	{"$dynamic_35$b591df0f7e3b8fabb7f67666aa7c8d0b422ec960$$U1", "123456789012345678901234567890123456789012345678901234567"},
#endif
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
	{"$dynamic_36$2d74c846591c5822e0832c053a976a1c6f07e89d$$Uuser", "12345678901234567890123456789012"},
#ifndef MMX_COEF
	{"$dynamic_36$ff5acef1d686cf3ee20f6d3aece0bfbd6266aa55$$Uninechars", "123456789012345678901234567890123456789012345678901234567"},
#endif
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
	{"$dynamic_37$11b4d0b68b9fb0b48214e6b7c1cac42d0c9acdec$$U3", "12345678901234567890123456789012"},
#ifndef MMX_COEF
	{"$dynamic_37$155829d3a45ff846deffd529f9b82309ab0bdf25$$Uten__chars", "123456789012345678901234567890123456789012345678901234567"},
#endif
	{NULL}
};

//$ ./pass_gen.pl  'dynamic=num=38,format=sha1($s.sha1($s.sha1($p))),salt=ashex,saltlen=32'
//dynamic_38 --> sha1($salt.sha1($salt.sha1($pass)))
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
	{"$dynamic_38$d4153e87afe49f83554a52581dd33409b9c7eb05$12345678901234567890123", "12345678901234567890123456789012"},
#ifndef MMX_COEF
	{"$dynamic_38$019fad88e769f91e3c43fce2e709184edbd63041$12345678901234567890123", "123456789012345678901234567890123456789012345678901234567"},
#endif
	{NULL}
};


//	dynamic_50: sha224($p)
static DYNAMIC_primitive_funcp _Funcs_50[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	DynamicFunc__SHA224_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_50[] =
{
	{"$dynamic_50$aff3c83c40e2f1ae099a0166e1f27580525a9de6acd995f21717e984","test1"},
	{"$dynamic_50$974607e8cc64c39c43ce7887ddf7cc2795d8bb3103eadb46a594cc3d","thatsworking"},
	{"$dynamic_50$d2d5c076b2435565f66649edd604dd5987163e8a8240953144ec652f","test3"},
	{"$dynamic_50$b11b9a2ade6dd0679e5266d03912c8a1543efbe5c5eea44425ba60fd", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_50$b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_51: sha224($s.$p)
static DYNAMIC_primitive_funcp _Funcs_51[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__SHA224_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_51[] =
{
	{"$dynamic_51$0b6ab0ba2c3dd88e825c465183d855322dc389396115a2b8b942552d$Zg","test1"},
	{"$dynamic_51$581c35a6ed0f5f868d622c6758b92db1f1bc5c6f6b7175eaeaf1f14f$KB","thatsworking"},
	{"$dynamic_51$e5ed27650604dc9d92db06c0bcd50dc1baac69f7edaafa2037b958a1$9m","test3"},
	{"$dynamic_51$b11b9a2ade6dd0679e5266d03912c8a1543efbe5c5eea44425ba60fd$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_51$b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_52: sha224($s.$p)
static DYNAMIC_primitive_funcp _Funcs_52[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__SHA224_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_52[] =
{
	{"$dynamic_52$c02cea6414abbb26b353ffa55380b4da38b56f93f550167460f2b2e8$d495DQCK","test1"},
	{"$dynamic_52$6e34513f8b75fdd8c01c7bc0a54aab7163a035359e1780d4413e43bd$GAa6smOZ","thatsworking"},
	{"$dynamic_52$2d796ae38a96c48ef9ad16232dd99e27af7010c46cd475bee1f7f5f3$etaOOQcf","test3"},
	{"$dynamic_52$d98679c5f48303073e6f4a9c34073ee385f1640c1531c74cadd04db3$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_52$b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_53: sha224(sha224($p))
static DYNAMIC_primitive_funcp _Funcs_53[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__SHA224_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__SHA224_crypt_input1_overwrite_input2,
	DynamicFunc__SHA224_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_53[] =
{
	{"$dynamic_53$9045f340c4c6cb4c9d2175d5a966cf06d1dcbbfbb59a352156a4b7c4","test1"},
	{"$dynamic_53$f3fdb63f05b1a9612a7c2745e360bc312945e19926445bb41ae92fbd","thatsworking"},
	{"$dynamic_53$56d951da2e775caff774ab31e9663cf6547f6b2bd2cd9aa449b7d225","test3"},
	{"$dynamic_53$bd973ae9977ab6cdc99aebddd6aa46efe6fa06b64805006a8b5be674", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_53$201eb56a00c9ca5886768bfb88f4445842329881f12b1fc21330dc4b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_54: sha224(sha224_raw($p))
static DYNAMIC_primitive_funcp _Funcs_54[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__SHA224_crypt_input1_overwrite_input2,
	DynamicFunc__SHA224_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_54[] =
{
	{"$dynamic_54$dd5585fdb1252a3efa02bf9f922afabe9597ddcfe57f229e0ecd4c02","test1"},
	{"$dynamic_54$4c380c601aa89ca51958bc05c5e58cd5f6f5093de5664243ef6100a3","thatsworking"},
	{"$dynamic_54$8ffc176af75adce9c32ccc72b7ea5812f215fbc072ce5b4cc217c8e0","test3"},
	{"$dynamic_54$630b161aefc2030cb73a5e14916de96ff8d033b951c3e520980e0c4a", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_54$42e8cbc71f0e3260515928c4af4f19290ef800d3f981f1ea2bc8e36f", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_55: sha224(sha224($p).$s)
static DYNAMIC_primitive_funcp _Funcs_55[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__SHA224_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA224_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_55[] =
{
	{"$dynamic_55$aa76e5957376e31952715529cd72ec81d3c076d2152d8b5c8d0efb16$cVfR3OJX","test1"},
	{"$dynamic_55$291b35e248a51a20ef0566a647e566e38ca5081ef12a4e33c560ff8a$YCJXInfb","thatsworking"},
	{"$dynamic_55$71eb0eea12ce8ca85c35396c6e77e856dd524e96350d52a93581aaf0$eQgbWpKS","test3"},
	{"$dynamic_55$a84cef5fe10dfe1f29ec2ae11651f76ce1be265bd3b075387b823c4c$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_55$327b8d33b8864840d3541983df08efff5fc4750f75563eb83bf048f2$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_56: sha224($s.sha224($p))
static DYNAMIC_primitive_funcp _Funcs_56[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA224_crypt_input1_append_input2,
	DynamicFunc__SHA224_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_56[] =
{
	{"$dynamic_56$0c8b6bb4c29742f326aab75dacde2cba0c924f541ac8af44b7c448cb$WFJsOVXq","test1"},
	{"$dynamic_56$168ece7168c0bddb27825e22b95914bf659ce1c54784ec44a1911fa0$CScG3ful","thatsworking"},
	{"$dynamic_56$405eb278c3c0f398f4329ca751e1410b70ebe2207612d2467ae20293$UquVdi8J","test3"},
	{"$dynamic_56$d1a895c777e84290430161bfed2a8e54ee5bb7b6efed60c1a0415ad1$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_56$6382895ed5b6cf031d2df81798cbb5825c5a7f402b19039a6117c263$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_57: sha224(sha224($s).sha224($p))
static DYNAMIC_primitive_funcp _Funcs_57[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA224_crypt_input2_overwrite_input2,
	DynamicFunc__SHA224_crypt_input1_append_input2,
	DynamicFunc__SHA224_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_57[] =
{
	{"$dynamic_57$fb133d9adb3d7cd284311ec909b0168a020554e184adcaac4f018e18$w21ElJCa","test1"},
	{"$dynamic_57$0ff48e0fe0847b04175af355256e5e56492bc410b5a915a3514b67e2$hoxc5hI8","thatsworking"},
	{"$dynamic_57$b60b62b69b1754a533747d59c5d4ceb14afa55cf98ba757a407c23e4$rsA4jyVd","test3"},
	{"$dynamic_57$aec9164e433121841be0ad243ea270312c2d724ef4e065da38fddc61$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_57$5645ad99487eab2af1af3a12a89cbf3f83a1ac81af1679cef5d82c8e$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_58: sha224(sha224($p).sha224($p))
static DYNAMIC_primitive_funcp _Funcs_58[] =
{
	//MGF_INPUT_28_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__SHA224_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__SHA224_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_58[] =
{
	{"$dynamic_58$960f782c001ed315755b7f42a6e36166b7cb580006633ef4bd6fcd10","test1"},
	{"$dynamic_58$1f0ef052ea6496a941c9d28f502cd943de8dc42222ab105d6e5584bb","thatsworking"},
	{"$dynamic_58$52fd68900d7f5e5388a0b94b6c3c68edddb98f6f4e9a9353babbf9d9","test3"},
	{"$dynamic_58$edf15d2431929ee6e819dec395db9901e6e5ca66a2d5c9e4fb2eda5b", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_58$2872477e9c935a6083f38f81082e47038d275ce2e17a4426381ca425", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_60: sha256($p)
static DYNAMIC_primitive_funcp _Funcs_60[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	DynamicFunc__SHA256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_60[] =
{
	{"$dynamic_60$1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014","test1"},
	{"$dynamic_60$d150eb0383c8ef7478248d7e6cf18db333e8753d05e15a8a83714b7cf63922b3","thatsworking"},
	{"$dynamic_60$fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13","test3"},
	{"$dynamic_60$03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_60$f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_61: sha256($s.$p)
static DYNAMIC_primitive_funcp _Funcs_61[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__SHA256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_61[] =
{
	{"$dynamic_61$2a4fa0bf8c6a01dd625d3141746451ba51e07f99dc9143f1e25a37f65cb02eb4$RA","test1"},
	{"$dynamic_61$ab3637d2c1f8b12eb4c297b464bac96f6055d71b51e951bfe00dc5a9db9bf864$XX","thatsworking"},
	{"$dynamic_61$a07ccf2b46550d0e7c444f987edad70f90b1b76dd64cbc04fb48c10dc5e15cff$nq","test3"},
	{"$dynamic_61$03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_61$f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_62: sha256($s.$p)
static DYNAMIC_primitive_funcp _Funcs_62[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_SALTED
	//MGF_FLAT_BUFFERS
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__SHA256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_62[] =
{
	{"$dynamic_62$ee9357332c8c09da880ae180fb2ac9a2d8841df0232ac4b2c864ece23c16d3a2$T7eBFzmv","test1"},
	{"$dynamic_62$22bfad6e017b09c8f6bbfcc1472d7ae476519654645edf8a5efd8fa141c9d74e$RZ8DFqOQ","thatsworking"},
	{"$dynamic_62$2f592058708099d79c03534c7a295bf941fc8abbea6c921dbae82a69039ca0ec$DQGjbaC7","test3"},
	{"$dynamic_62$2b57f2011dd6fedef8bbcc5a2097e336d1887e1c60f7949adf64ea0644a7cc16$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_62$f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};
//	dynamic_63: SHA256(SHA256($p))
static DYNAMIC_primitive_funcp _Funcs_63[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__SHA256_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__SHA256_crypt_input1_overwrite_input2,
	DynamicFunc__SHA256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_63[] =
{
	{"$dynamic_63$ab0ee213d0bc9b7f69411817874fdfe6550c640b5479e5111b90ccd566c1163b","test1"},
	{"$dynamic_63$fb771a17a5b2693c5a8892840ca1c2516c318e6656dc371fd9099bcc3dff6d92","thatsworking"},
	{"$dynamic_63$97b868b8503c20875cb0a0e37c418a7166d78304c9384ef0d864ece47d1803ac","test3"},
	{"$dynamic_63$013d72c8c8331a91d0b95a4cc882f35981fd9472eacc920ccef558ee6e14ff49", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_63$c8b1003e8a35ae1c10e6f9c4e8b951d7114a51710c09c0f5d073b15a83ecefe7", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_64: SHA256(SHA256_raw($p))
static DYNAMIC_primitive_funcp _Funcs_64[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__SHA256_crypt_input1_overwrite_input2,
	DynamicFunc__SHA256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_64[] =
{
	{"$dynamic_64$41455282d6faeb0b02bb6441924e07a02b5b8d31c848b3a4f2189e15ed7e9689","test1"},
	{"$dynamic_64$7ae2ef95fbd8c903ab905f007f946cbb3f83a64387af80dec403b333b8955fcf","thatsworking"},
	{"$dynamic_64$2a869eb5421bbea3e5318900a99175a272980931ccf63668950a2b1eff8fa57a","test3"},
	{"$dynamic_64$6d24536db78fe3db2ff4235a6486e636994724882db6567bfe7037f8a5bca0a3", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_64$37222523dc0f0b26ccfc58cf4627c0a8ab0b0bd3eac0e550ddc901cab912ea58", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_65: SHA256(SHA256($p).$s)
static DYNAMIC_primitive_funcp _Funcs_65[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__SHA256_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_65[] =
{
	{"$dynamic_65$9e59ea803f5f5c0f2b7adfcb82db9654343d821230b16e123f3cb913d91cf7fa$UX6Hg9Vq","test1"},
	{"$dynamic_65$5adbcc923f2636175a4776b24ea15c8e4592c226985ebc68fb13ee1635df2fe8$mCp6NQxB","thatsworking"},
	{"$dynamic_65$ee4553fd14a4df097398fa87209b4d741b33163d9623c627215d3e3e25622f23$HoTNEE6s","test3"},
	{"$dynamic_65$dff4f1f2e79fd0e9a8afe585125ec08ebc1d3cd2a6e95fdec156871671a50535$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_65$f5da2be3bdd6d5e5023c9c5da158db5de49a0f9ae33994d19478568c478f13de$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_66: SHA256($s.SHA256($p))
static DYNAMIC_primitive_funcp _Funcs_66[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA256_crypt_input1_append_input2,
	DynamicFunc__SHA256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_66[] =
{
	{"$dynamic_66$6bb87d207be95597ad8bf29df9a983d29508ad2482ab4ceb8b9112ce3963b7f7$LAe5jTw1","test1"},
	{"$dynamic_66$754f6146edb1154774ee74e8186c702047cb82ea1f1612ab035e8d74e8eb8a31$hwFD5o3w","thatsworking"},
	{"$dynamic_66$4a24b7aaf803468f68667cc12d62649104037cd3d64c727997f95e922e35042b$RFHuAImh","test3"},
	{"$dynamic_66$d202b5b455a3fb356f86eaf3d44642c19a797d9c33919387c52f6ecff9500c8d$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_66$86cfc8c1a7d3ae308d2ec0c22fd445559eddcfe97c9b31f798e900098fd54514$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_67: SHA256(SHA256($s).SHA256($p))
static DYNAMIC_primitive_funcp _Funcs_67[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA256_crypt_input2_overwrite_input2,
	DynamicFunc__SHA256_crypt_input1_append_input2,
	DynamicFunc__SHA256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_67[] =
{
	{"$dynamic_67$eeda7f31366e2a3f88f727260e0a3809c81c77c46b1d199b6a00b79d13bb3748$qteXzYV0","test1"},
	{"$dynamic_67$17ac40e67cd2d092e68d29c45cb62f1257801b6a40951b0abf2738d5917b7cef$YXFCIJ33","thatsworking"},
	{"$dynamic_67$e3cb1a8b97c3510400ca7e0331b2a8e613f87207ee27cbcb6232fe2f571a4668$ujyylrp0","test3"},
	{"$dynamic_67$e10445e132f5a6bacda088fef7d2fd5584b84304c079c5c559e4876b6cf12576$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_67$3290298e47ba87dbdfb284649e662ab8069c61662a82aa187cf21efbee7a46c9$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_68: sha256(sha256($p).sha256($p))
static DYNAMIC_primitive_funcp _Funcs_68[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_FLAT_BUFFERS
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__SHA256_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__SHA256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_68[] =
{
	{"$dynamic_68$98866d999ba299056e0e79ba9137709a181fbccd230d6d3a6cc004da6e7bce83","test1"},
	{"$dynamic_68$5ca7061b1da740429d107d42333214248a5ffa9fac9f506c3b20648c8b428c51","thatsworking"},
	{"$dynamic_68$000b7a5fc83fa7fb1e405b836daf3488d00ac42cb7fc5a917840e91ddc651661","test3"},
	{"$dynamic_68$1f5a492ea3ca9a1d9e1d7cb830ac22b4f96abc39c261b84522fac1c22787926b", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_68$4b16c7dadc5c3ef6dcfd11942a225cfc0c4c849771d5c12fb790f6b151c6bf2b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_70: sha384($p)
static DYNAMIC_primitive_funcp _Funcs_70[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__SHA384_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_70[] =
{
	{"$dynamic_70$44accf4a6221d01de386da6d2c48b0fae47930c80d2371cd669bff5235c6c1a5ce47f863a1379829f8602822f96410c2","test1"},
	{"$dynamic_70$76f4d70f118eca6a573e20bfc9b53d90931621c1999b0f2a472d45d691c827298c7c2bf27a5a60aa6ea813a5112905d3","thatsworking"},
	{"$dynamic_70$7043bf4687defcf3f7caeb0adab933e7cc1cc2e954fea0e782099b93b43051f948e3300d3e03d126a13abf2acf2547a2","test3"},
	{"$dynamic_70$3ad707a025ff81980a50fba5f9cfca5bad1b99d6877ec7cb479116f664681706213f07cc24faa79a870ed93276d7b01d", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_70$b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_71: sha384($s.$p)
static DYNAMIC_primitive_funcp _Funcs_71[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__SHA384_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_71[] =
{
	{"$dynamic_71$2cc3894a72439a47e4558ff278076ef8f432454e18dc94f9f972c05f4c28259adaa3906551e1b30b3459c8e4c67b939d$EH","test1"},
	{"$dynamic_71$351a2849294375a83218da6d1a047df49c7f078905e31add7d8d59219ab6b01850a1bd3106fb8a03ee8df24ef9f4ca01$JQ","thatsworking"},
	{"$dynamic_71$677d64de3c5e11bcedd884dcdbab73b4914bf0196e6cff3b1e6adb835772edca3ff584b08a1fca1f18f817fe9d6b57fd$O1","test3"},
	{"$dynamic_71$3ad707a025ff81980a50fba5f9cfca5bad1b99d6877ec7cb479116f664681706213f07cc24faa79a870ed93276d7b01d$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_71$b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_72: sha384($s.$p)
static DYNAMIC_primitive_funcp _Funcs_72[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__SHA384_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_72[] =
{
	{"$dynamic_72$3bced5eee31c2ba9493bcd07e56536cc1c6f9f7709520b425a759a54fcec0d7a53680812716407a6e0b6e757631996d5$b9WL2vC8","test1"},
	{"$dynamic_72$c3122f735d9cb20cdd305e775ba841acd607e4e399563936f568ff88ad26643a1b99de4e8855c5769e18d765c8b50ff7$E6u1Qgtq","thatsworking"},
	{"$dynamic_72$2497022cab716ab1b64e4c8fda667e857819a54d88af210f8433f0d77ecfa23c1b81fac3b24bbe0bbf82a11fe9629378$XCrwOUG4","test3"},
	{"$dynamic_72$c80b64ef31beea5fd718d480a5cd4a0bee0c9b02791c9774b41a27d121e96a5b2c3f9102219e38eae6aa9ea43ae6190b$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_72$b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};
//	dynamic_73: SHA384(SHA384($p))
static DYNAMIC_primitive_funcp _Funcs_73[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__SHA384_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__SHA384_crypt_input1_overwrite_input2,
	DynamicFunc__SHA384_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_73[] =
{
	{"$dynamic_73$d1c7baa840529e4f64dd82de1ffa6f1912b028ccab35d9cca431d50388711a65cdadb3920dc34baf696ccd972a4c7ef9","test1"},
	{"$dynamic_73$84c128713f498cd950d4cdb0cab241cbedf1d391765d6bec92c4bd0aa6ddf1398b0803de4b40146e0d5ed2cee0b9d009","thatsworking"},
	{"$dynamic_73$d26cc7a524bda031a89b0c25947772ea46121b2fe8be3802f2430c9468838b62340e7ae6df097641da3e63f248b8ef60","test3"},
	{"$dynamic_73$0b0d77ad57cdf1e48c40dd6609fb3a67edecdb5867a765d44f7bdc40897986b359b1945f81fe337b1c37bfe3d15d5088", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_73$8e1c38aa8e285f2a1049ae1b41ed547cda524a870498e89c4a8acc252b6e7085df4882c264e3e9e5fbc48f1fda10783f", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_74: SHA384(SHA384_raw($p))
static DYNAMIC_primitive_funcp _Funcs_74[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__SHA384_crypt_input1_overwrite_input2,
	DynamicFunc__SHA384_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_74[] =
{
	{"$dynamic_74$dbc81fc4a583f0a9e29381cc61fbc38fb1beac9057c4256a0700601f8980bb9da1856e31af5fb36d4aef3f91605ff57e","test1"},
	{"$dynamic_74$3a4a08a0f8c3d9f1a3cad7c091c9cca96766a7aaa2bbd4a9f37d7dceed917e13020b936fac8f2ed07d3dea1904abeb16","thatsworking"},
	{"$dynamic_74$4ccd6ddaf83062228bb19bddf6364ff7f0b54cf5416d33eecd5271a70c820d73312888a6cbb24dc790ce718be9a95494","test3"},
	{"$dynamic_74$084e614573d564cf1cd6d8817b3b5e5e7432527d0a5e6319c7e678925d18a46b965885eb27f4de9997ba2bc6e3664ec8", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_74$0ce3e9992d9819d5b910f0fec2e6e532c3ab2cf03e34fb1bf059b0bdd554c0eb7b1e02de84512c590019ca558d929972", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_75: SHA384(SHA384($p).$s)
static DYNAMIC_primitive_funcp _Funcs_75[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__SHA384_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA384_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_75[] =
{
	{"$dynamic_75$f14c57288d45d58bb0ab24ed03209cb0b5ac57963d4a454536b4415d8e7e11753208c52ac923d54726cfd197af956fd0$W1QG1oNr","test1"},
	{"$dynamic_75$b80a91dd31512ef1a4c5773a17dc584b5871a1e80090602268044732184d8fae1ebfda7dadf493d0cdc36e7cd73b874f$HbpRzSQB","thatsworking"},
	{"$dynamic_75$a3eba61a9c4d878599e73083a55e270d1e1b96be884ef65eea9d79e9b454ea8510ffa31615819915d5077b17498ea55c$K8aXzbfU","test3"},
	{"$dynamic_75$d5170eb69b06c6890e2b989e42b52fffb3770ac684e3c67ba5296a902a5a98cf549ff4abc7c98b263ddb59fbfda684a3$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_75$a7c317014431c4bdd823b400eeda1d099523737cc4fc527d68c1e44cf065cf38109ebeafea5e5a206e496335a38e037d$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_76: SHA384($s.SHA384($p))
static DYNAMIC_primitive_funcp _Funcs_76[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA384_crypt_input1_append_input2,
	DynamicFunc__SHA384_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_76[] =
{
	{"$dynamic_76$b2ae724870d28da5111060fda398c9516f04f556fccb22d819de9801a26120eaf85fe9e209fe618d6a2a8f89e30ffc5e$4uS21WR2","test1"},
	{"$dynamic_76$aa2104f1c77b01066819eca04f0678dbe0119fa78ebfada490071b029db674ab28e3c0140d812095df68ad78a178e5be$nG1Gvoon","thatsworking"},
	{"$dynamic_76$3e43e555f4167b0385947cd565bde40e785519d06c1cf3f9bc3213ab40522794bed84a2e57a68c49da74defb0a47ef04$kzw6ZI0c","test3"},
	{"$dynamic_76$f97943d81c08731e036b08404e68baa04f295778261bc704a24b8a40bd3bac12049316d0a1473e313870c86d6ceae41f$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_76$c7ba5655fe437645b71c57924e2ee8248b06c643bfe56e7895511ff6e199b6af7ee1686b8545990ce128d204425a1586$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_77: SHA384(SHA384($s).SHA384($p))
static DYNAMIC_primitive_funcp _Funcs_77[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA384_crypt_input2_overwrite_input2,
	DynamicFunc__SHA384_crypt_input1_append_input2,
	DynamicFunc__SHA384_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_77[] =
{
	{"$dynamic_77$a5c0d19086b33e8751c4ed51e16b8809938d9587fbb86c21faf17acd652dd2dfb1602f0a9a92ae15dc058e6e09a69b23$6fe9QLsN","test1"},
	{"$dynamic_77$f203cc435d3181a427c455e9b5036dcfa6091acf570cb8ccf1931b4244e697e063cf86d41afe3150bc36983117775ea0$jwTEaXZB","thatsworking"},
	{"$dynamic_77$1f21e9314a745688b04b295866713c1a3a608ec09b4a3311b0a9dec95f10f627b2b21e1b4489f2e6cfd9c30adff6dda2$BUKDtfhw","test3"},
	{"$dynamic_77$3419d3f932a5dac7323745feccb810fd98b147d18a03017b939eed2c640e5076004c115335230c8db95266451b571807$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_77$d859555dfbc0ead8d7bc3b2d853dfec265352993d1409f81fc87fbc1762b8b1ed8efe39767b18d3879f1925b5c6e65c6$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_78: sha384(sha384($p).sha384($p))
static DYNAMIC_primitive_funcp _Funcs_78[] =
{
	//MGF_INPUT_48_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__SHA384_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__SHA384_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_78[] =
{
	{"$dynamic_78$bcc4c9d333738be9668acee9859c53e137fd513185167df88eecf5cf91060a62164ea3570940a4ef4381300fcf232eba","test1"},
	{"$dynamic_78$43afcdb29a6d23492573c8f3669e0f5d88d6ca5716448cd742b3622cb020af946c273d430818831d82f1c1e89516f1f7","thatsworking"},
	{"$dynamic_78$5bf8faa92ad87edb31619442306c7652a7d1777fc1321a0cd40d91ffd7956a25be6321b606a824a3ce66dcf6de990698","test3"},
	{"$dynamic_78$9f4be01eca02be351929a24d38638f30f372e13f03273a69450280be3caccc6e27335e17007ef8e8b9570ad93ea6335c", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_78$c2d53be0562af5b8cd52cfd888c5991cef4bc59e87e7c212b1fa42fb220dc2b94a010b2b31a8190f016ebd840adcf818", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_80: sha512($p)
static DYNAMIC_primitive_funcp _Funcs_80[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__SHA512_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_80[] =
{
	{"$dynamic_80$b16ed7d24b3ecbd4164dcdad374e08c0ab7518aa07f9d3683f34c2b3c67a15830268cb4a56c1ff6f54c8e54a795f5b87c08668b51f82d0093f7baee7d2981181","test1"},
	{"$dynamic_80$05c1a41bc43fc4cebfeadbf3eab9b159ccb32887af0d87bfd4b71a51775444d0b4b332a50c4ca9bb9c6da6d5e22cc12e94bd095d6de60be563c3fd3077406d1a","thatsworking"},
	{"$dynamic_80$cb872de2b8d2509c54344435ce9cb43b4faa27f97d486ff4de35af03e4919fb4ec53267caf8def06ef177d69fe0abab3c12fbdc2f267d895fd07c36a62bff4bf","test3"},
	{"$dynamic_80$35ea7bc1d848db0f7ff49178392bf58acfae94bf74d77ae2d7e978df52aac250ff2560f9b98dc7726f0b8e05b25e5132074b470eb461c4ebb7b4d8bf9ef0d93f", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_80$72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_81: sha512($s.$p)
static DYNAMIC_primitive_funcp _Funcs_81[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__SHA512_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_81[] =
{
	{"$dynamic_81$3cd1ef81fc602fef15ba98d9d8e075328b0a2904ad233796ff03a9d2fc407a377112a124c153a52620471d13530ef116d1b01467e1714be55c4a95286e065dc0$VM","test1"},
	{"$dynamic_81$a8a2c09500d5519187c7be42a8feeb2f5687f2bee25c7cc3755ba75d1fe15fbac50ca248baf2418afbf6a560c6ee8b515ba384539fb5ed153b650b63ab042f84$Ge","thatsworking"},
	{"$dynamic_81$957623e5308ca9472e61985ffe7ea499e67d394fc83b417e6a00d6da778fe340c2f45cd2dea725bca7bd51a6fd223701a2ffd02dd3cb943dcc8e4053626be3fa$CP","test3"},
	{"$dynamic_81$35ea7bc1d848db0f7ff49178392bf58acfae94bf74d77ae2d7e978df52aac250ff2560f9b98dc7726f0b8e05b25e5132074b470eb461c4ebb7b4d8bf9ef0d93f$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_81$72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_82: sha512($s.$p)
static DYNAMIC_primitive_funcp _Funcs_82[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__SHA512_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_82[] =
{
	{"$dynamic_82$214eb5bb00fa9d5fb57d50dbdf126dbe08b75471c15051e31fb99f2974b170ce5affcb602056eee10f0afe6db9143438412f2a9b5729a7753e27b9fc6c1a5fa2$tZ8nE5oA","test1"},
	{"$dynamic_82$c962438ec174cc169cd425d6ed07c0211785301c6edaab2da1aff33b837a13e2df9639433bf6fd0a26c8aa654188d1528b3a7199508726a649e857eecf79125c$ugQMD6u3","thatsworking"},
	{"$dynamic_82$400c5738cf75bf9d89a20fab33bcc83c2ff9fe2429404232ed4af6d275eaf9d40aa8ab0a0c7646a990c25f9ced176839672f56e27c61da24989f3f9886d4d7a2$fdOZ9GQb","test3"},
	{"$dynamic_82$c8247e0c90ea675059973cc4950b95ca26fa4e8e0ac9f2e803cb83e7655a8ee9cafb2765d09f87fa0db54c087607ca40340e78a0a8e4e6be9c81b714a1df5596$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_82$72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};
//	dynamic_83: SHA512(SHA512($p))
static DYNAMIC_primitive_funcp _Funcs_83[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__SHA512_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__SHA512_crypt_input1_overwrite_input2,
	DynamicFunc__SHA512_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_83[] =
{
	{"$dynamic_83$e52e13f73a85b5fe15cea9f5a69a3eb29be31e9ce97b7e8ba1778757cfd624b4dcda4b40347ae57ff75fddae967bf6b0332d7848d0c3f2e31d380d2181f3ce38","test1"},
	{"$dynamic_83$649cd1f8ef64b87760d6fb9a2040ea65bb74b8d1f0a4d603f880a553d4d85318505659eb52077ba6f9fb24030106d32ca9adcc01ab3f45f4a1aff40167259113","thatsworking"},
	{"$dynamic_83$e803dc500bf2a24eaab1766abc35ae817788dba01b778caf41524867fec4ac804dbf498f668e20b19ba0cfc450091bb897554a7f26b8f07a753b300be1f91a1a","test3"},
	{"$dynamic_83$61a2eee1a0182877adb4d3dd3fb23cd6994fedfb9d21bebd64282ebe5d1bc19f3b8138e7e0de4a0263dd6b00786c51510a43173b537db70e93150b85740de5ba", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_83$8cfae6bbcbc7e550a8ef985f4fcf8821cb9c1545b7dd10914e56e6350a551070bbc617ed91ff0a7052f4cc5054fde577e81452bfd87d205bbb019ec7b9506836", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_84: SHA512(SHA512_raw($p))
static DYNAMIC_primitive_funcp _Funcs_84[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__SHA512_crypt_input1_overwrite_input2,
	DynamicFunc__SHA512_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_84[] =
{
	{"$dynamic_84$5c83a5d1967a3d317daeb97a6ec6bd16d508d1f595c6f32acaa24b760556afbbf7565ee87205bf313d0e6956ff6e26121a3a454e155a5cff118f77dc78963730","test1"},
	{"$dynamic_84$eb8c9cfe799e4eb63d2bea8aad4991d3a6423ce39b7c1d1053f0cf396555040e3842e35af86b56d2542d481dba08a21d6eebc4feffb6f5667cfa4e67999f08eb","thatsworking"},
	{"$dynamic_84$03921e479a31f4c13c4ab0d50b7ab143dad0ed8e0a909cced7cd62e087e29f55534a2811148c4bb2aef43e9996b260417d0b2a9886cca34836a337adfabd7310","test3"},
	{"$dynamic_84$89db217fa8a1796981fef7498c3ddb3225eec62f74a847a6fe2a1f1697c0a1a2b55b509c6991384f721d6a74b98ec1a6f78b28c32c060466bd617c13c3e913bf", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_84$37ec05bfe2d5e12807564b82d8e58c75a9533697b34325088fba46848d3cfeb9ad32f906eb0fa14aceb22626bee97ed88765792596393614f97b476ef71bf8d8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_85: SHA512(SHA512($p).$s)
static DYNAMIC_primitive_funcp _Funcs_85[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__SHA512_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA512_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_85[] =
{
	{"$dynamic_85$be530ba78d36bfd3d5ed428b714350ed1c7ea47b3dd7f261b848df4f1b41d20fd56b9d9356bfd26b82f578cf4ae977ec676b7b8b57b59b77729bcca22ac3d20a$uRT6ZkEI","test1"},
	{"$dynamic_85$b5306565e197fa38935e3efe59f2294d6d28e7ca9c445425507923b55321f9678ab2446456a44cf3ed869c28ed719b52c43b66942e6371c07c886a4f531d3925$R55fEdYw","thatsworking"},
	{"$dynamic_85$6cb42643b44f7963019c43c13024d7486b3d806f70520df6c1b1aebdfc2f532a53250ff3bcf468ae0bdbada9daecb1b3e8677c05fbf856ac78a5ba1a322f3d0e$Lo21TUNz","test3"},
	{"$dynamic_85$cf0cfc79326c12c67afaefc97a2279bd89f781cb5ad21068a1b184bec58ecdc746ded08d039653d2baf3c83f9884128294c380b832c394c66a7481613bd2e386$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_85$b79aa9ff54425571ba215f551b3caf80840bfa436233459c6d40744cb9ea5b2021996f8ba08972791a0d7c6c8a83a77dea8e8e9cc0857aaebf02452177b548cc$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_86: SHA512($s.SHA512($p))
static DYNAMIC_primitive_funcp _Funcs_86[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA512_crypt_input1_append_input2,
	DynamicFunc__SHA512_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_86[] =
{
	{"$dynamic_86$40928be83405d2ad3af1fd6e970dd2e5a3d0bf4caba70530895870edb65c59c219e91eb81058ac6af77f9f0dcf48c10d75763b0eb3e14e440ba41690023312fc$VXtAXAGy","test1"},
	{"$dynamic_86$a391af55568dc0a0123e148572a2f9ff22af7d603792c7f7b0af97cd42e40112c983d25fc73fe554d3595c61cf332398309b6e1d4f0b744710706d4e607025fc$lRkHcT3s","thatsworking"},
	{"$dynamic_86$c891d4c4f871ddae6b76c03c3d6108e259768b8730397510d74c114d6811acbd2bdf53d79bdfacd33b7587118edf6a11806554ccd2f7dc041d2f80a2c4eada02$aFthlASo","test3"},
	{"$dynamic_86$a4c8a398b9594011803cc12712f74c02e6e2a4f49373c3165d7513ea4f09b461fa9f9fa3d1d37ecc61359b3ad7b686f7da4e647f22de3c60e57bf05acf245895$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_86$5ce7ecb0fc132a0c489352441bd599a8dd449c48c4ab519d372b3207979ad3974cc15d5549819bd75e59254142740f186645883912c7124d9b934a1d608cd74b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_87: SHA512(SHA512($s).SHA512($p))
static DYNAMIC_primitive_funcp _Funcs_87[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__SHA512_crypt_input2_overwrite_input2,
	DynamicFunc__SHA512_crypt_input1_append_input2,
	DynamicFunc__SHA512_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_87[] =
{
	{"$dynamic_87$64facc9742d9e55ac1f621638e240d2ac1496aa90565244ef6838acc325e5badb3949df59fc70655fe64ebb8881cbac3205dcfe399fa59046ed7a58a23f794ec$T85XJRqI","test1"},
	{"$dynamic_87$98399b8585396eeb6803e4a348c85841c85dad875d8cada05f3773fa9aabc642d51c045b1e23416c64a2690f720316de6bfcf9c6f8994a3dc477ac2145c0f5bf$bilwWWce","thatsworking"},
	{"$dynamic_87$31d13b3bbb61e5ea1decdd6051232923fe63bc9cc117fba342959dfb6863327c8a00f8d3c0770ee39b80e480db139cc8c7823f86169cb51808d04da8c2796600$GILe8AIe","test3"},
	{"$dynamic_87$a00a83e6d51b90391bcf856609308fe70192275436c40ff10d5e2e98794cc673303ec68021e16ac5e49ac6dae41f987781c556e727d9e3fe3c5a8d57e6554097$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_87$dc0cc8ff511299824f5998e0cec936c479792cc635ae40b47414e7fd3ed90afcc85bc2b6ae7ce94c2fb8c7ec91e5456b7a4b1a23029069910b04ca3acc10b84b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_88: sha512(sha512($p).sha512($p))
static DYNAMIC_primitive_funcp _Funcs_88[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__SHA512_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__SHA512_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_88[] =
{
	{"$dynamic_88$e43a5ceccd814df1669b9f07f7f422932d5f9778cda0abbb5a169d0d5beda06744dd97b3947f288329f5f9c2db394dc2eae8c1f71e8b290c98c7e8545458aff3","test1"},
	{"$dynamic_88$82bd38d8a52db824fedd8b7506b9e36ed4854aa2d71094771c9c9c32294d080fa488b67bac5c77ca10790f058199fe324e80f73ba61ca0877df9dcdfd1c66ba8","thatsworking"},
	{"$dynamic_88$769412e26aff2ca3005ce84628d98a6681448909ced9980a0bea57ba6a1cbaa0403ac6bb213d267eeaefafad3103b0d1486e700c9521800f9d548f87046470f0","test3"},
	{"$dynamic_88$994b1af05e8cdcdb3d02b767e52ecafd46c387449117c8706a320db452821d561cf37eedac84a6c44ca6427f9f2c37572d0f76b2eeac137c0ab218eafb43a5d8", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_88$95dce69641c4029f859ac7e963430d93a9b8e45d503d15b9c8547d16e4d76800aaaaa1dc1b6092b624ef9ac9eebd25876579c3d5ede95232b2395193378d9d5c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_90: GOST($p)
static DYNAMIC_primitive_funcp _Funcs_90[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__GOST_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_90[] =
{
	{"$dynamic_90$3b024be97641061bdd5409b4866c26c5a965e6fcf125215d2f9857cea81c5b7c", "test1"},
	{"$dynamic_90$d4949e4ad914089d7bbb4711b08343ab7a8658599611a4ee5a91999b5c3e0388", "thatsworking"},
	{"$dynamic_90$55719211936152fbe2e1f6aa796fa866d839356e5ba9bc206ed39ab0bd07d892", "test3"},
	{"$dynamic_90$0bdbe8d8e334389587ad5f1cd30f050dd3d639134f20570fe74588a9c5127ea0", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_90$cc178dcad4df619dcaa00aac79ca355c00144e4ada2793d7bd9b3518ead3ccd3", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_91: GOST($s.$p)
static DYNAMIC_primitive_funcp _Funcs_91[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__GOST_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_91[] =
{
	{"$dynamic_91$f515f18ca65e4c4821dba4809049f4465a933b44f3ef5b1175981fbaaa0e8cdc$VI","test1"},
	{"$dynamic_91$00acb59bb6e40ce58af4d1ecb7d5b9223c78f69bce22aab626041eca3ef69727$3p","thatsworking"},
	{"$dynamic_91$50a41b03306ac3c2922307779d30c42f2ee2fbbcd118be86b0d52b984352e444$GT","test3"},
	{"$dynamic_91$0bdbe8d8e334389587ad5f1cd30f050dd3d639134f20570fe74588a9c5127ea0$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_91$cc178dcad4df619dcaa00aac79ca355c00144e4ada2793d7bd9b3518ead3ccd3$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_92: GOST($s.$p)
static DYNAMIC_primitive_funcp _Funcs_92[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__GOST_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_92[] =
{
	{"$dynamic_92$0544260f34f6792ec0a5333088c5f70c71b5b1d31c4d4ee960282b96e7b2040c$kaSCrmRF","test1"},
	{"$dynamic_92$f1683c8d76491639296480577d795888999c475e1de988e9e61160bdebf836ba$MH82PtXE","thatsworking"},
	{"$dynamic_92$4a5c90d92462db40ddc47f78eaa02b8d75c9f18bc30c24001dbcf83397ed8641$xPW4qUH8","test3"},
	{"$dynamic_92$9ab7a4c5cefc2034462122bb6b78718d128ff8032aa1f0434d8f29aaf1e45a34$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_92$cc178dcad4df619dcaa00aac79ca355c00144e4ada2793d7bd9b3518ead3ccd3$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};
//	dynamic_93: GOST(GOST($p))
static DYNAMIC_primitive_funcp _Funcs_93[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__GOST_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__GOST_crypt_input1_overwrite_input2,
	DynamicFunc__GOST_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_93[] =
{
	{"$dynamic_93$de68edcb2422bb842323d5f1e07921237a5e61a28472fe22c36912aecd4895d5","test1"},
	{"$dynamic_93$d1459d7a9f1b79700e631905f1a6e506cd2eb6479d4d4af570cf4a3d8e12fb7c","thatsworking"},
	{"$dynamic_93$1be4da94702cd716865d710619f16a634ff7049f154b0d9679d11081f739a765","test3"},
	{"$dynamic_93$f7ee0f6de00f8778ae0c985fac199e0f3adfe025eaf108d219b1f0d1dc47cf34", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_93$4399ef8f19a687a863e90968d070e4462331eb59b895b835ab8179b1bf4eeac3", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_94: GOST(GOST_raw($p))
static DYNAMIC_primitive_funcp _Funcs_94[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__GOST_crypt_input1_overwrite_input2,
	DynamicFunc__GOST_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_94[] =
{
	{"$dynamic_94$7c3c1ba038800fb4dd199120773a0236e62bc728ec1d18c91309be75b8363e1b","test1"},
	{"$dynamic_94$ab95ce3f7acf5f7ad62b3abe4086541dc2b223474d46950b5f1f0c03faf35bd1","thatsworking"},
	{"$dynamic_94$10ef1ff47724f4e07bc2265ab68171a43f83f98b4ea56966397be1dfded97df6","test3"},
	{"$dynamic_94$d9db5f1cf9c3dbe773effdc431a66ce12430b46f314bcce8f52aefbbf7faafee", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_94$5e83e3ea93481d7224121edd9b341ed1f26caef817bd09260a37c25417aff907", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_95: GOST(GOST($p).$s)
static DYNAMIC_primitive_funcp _Funcs_95[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__GOST_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__GOST_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_95[] =
{
	{"$dynamic_95$26d13201ded9c417175be1a37fe16a5f0ef6615b4e2ecdbe571cc34340139ae6$zodk0FNq","test1"},
	{"$dynamic_95$64555c8e9119ebb7061156f1f76209796bb706d648608f3b454ee3fe0a4b96e9$801xxsMd","thatsworking"},
	{"$dynamic_95$dbf7b360ad9c97a16b51f8f2f0650eebabbe244d5180b8575b95dfc00af1515b$0PWhE5IH","test3"},
	{"$dynamic_95$566bc206ed77e46f31dc4e5fb441684a62db45d4f2c54b57fb723537bc7046f5$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_95$af301b042fcf4897d19d5348794bb20b37cab4762ea4df2ece00a0cc790d661c$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_96: GOST($s.GOST($p))
static DYNAMIC_primitive_funcp _Funcs_96[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__GOST_crypt_input1_append_input2,
	DynamicFunc__GOST_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_96[] =
{
	{"$dynamic_96$b9488a9203cfcf2450a2062ec195ff68845f5ac2b945e7bd829a3a1086993b30$5SC1CcIc","test1"},
	{"$dynamic_96$7ec95e96cb5aa5e95f3fcaeccba4bb9672ae0a2a9b681e8f0b3c5934290aac47$bwZH6PJv","thatsworking"},
	{"$dynamic_96$829599885f51cfad36a43c695bba6f0e24f915547b7205a99284b31af99fb59f$gEwPE1bV","test3"},
	{"$dynamic_96$3b8d35e84f391a5b1f1b632ee2bd60ce72648c2b5318b2d912ab167456dfc1a1$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_96$6e41c364501bcb472f1593ca89b4d5b1c6e0aff2fa2a62ba3b887b565c48487e$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_97: GOST(GOST($s).GOST($p))
static DYNAMIC_primitive_funcp _Funcs_97[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__GOST_crypt_input2_overwrite_input2,
	DynamicFunc__GOST_crypt_input1_append_input2,
	DynamicFunc__GOST_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_97[] =
{
	{"$dynamic_97$a236e0eca5099cf35db2dd6d90f61f7b935fd234955480fda1b681ba2233b9b5$qLqXv6z0","test1"},
	{"$dynamic_97$a51eda198a8ccd6d1fc3ed7da2ab0d1f6df2354ca7b2347b248feaeb2c040b80$3V9Fpadk","thatsworking"},
	{"$dynamic_97$769b1838311d227b1106448f98604c0db61074aa1e7df104f69b344fe744fe6f$qhXqvwKR","test3"},
	{"$dynamic_97$6432c52e3ba45c269e6297aee96eea4ba0b2543e5787ff1861f313ab6aa7f3bd$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_97$83a582ac635d0fa5afb10ebc02bcf228782987a19c93dd0f65b56e3dc43351e8$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_98: GOST(GOST($p).GOST($p))
static DYNAMIC_primitive_funcp _Funcs_98[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__GOST_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__GOST_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_98[] =
{
	{"$dynamic_98$6d7aa908db4df2e99abbb19d646c0d8b540152b8499fee0cd73f42f7dbee800c","test1"},
	{"$dynamic_98$49571dcdde0820ac0115de5521f33e91f3fefda82bcf3a05bcc028596cfc531f","thatsworking"},
	{"$dynamic_98$9a2eb6ae6fa23ab615f1014bbcb8119be20d474495ecc2ab18d51e08852629cc","test3"},
	{"$dynamic_98$f7bd4e1db5d0ea619ebf0412dfab4487345ca8f1925459bece5f8a5f6b49255a", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_98$fac88491e9eea209da3d24e90c9848fc3d226897ddc47e3be1a95e30359eefc8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_100: WHIRLPOOL($p)
static DYNAMIC_primitive_funcp _Funcs_100[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_100[] =
{
	{"$dynamic_100$7a3a0ec40f4b2be2bb40049a5fe0a83349b12d8ae6e9896ee6e490d5276bd150199e26aabb76d9af7a659f16070dc959e0393ef44529cad13f681129d8578df5", "test1"},
	{"$dynamic_100$296f0c87fe042a8f664980b2f6e2c59234683ec593175a33db662b4cdd1376ac239bef3f28e9fffd8d3ab4b049d87a8d224c7f33b92d4028242849d2e1baf41c", "thatsworking"},
	{"$dynamic_100$7d925e8503a922cbbc5d4d17eb232c790262ee0b06c33dc07f200c952ade2b2ddf8eeea7deec242282a700e6930d154f30c8b4096efe2633b860b48286703488", "test3"},
	{"$dynamic_100$a8b6e2b02c5bab563f66d7a905d69ab9feb8741fca84c79645a717fbeef77de26cad194fd3875773f586452382391b4f47e26acf0341dfcd7add500bfe025f9d", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_100$466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_101: WHIRLPOOL($s.$p)
static DYNAMIC_primitive_funcp _Funcs_101[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_101[] =
{
	{"$dynamic_101$ec4061a8201a9d60f3ee2f47b44b2356d1d15c3267c35102d3cac048254879cc20ba75dd2b56aa8872278646667c0b3c729575c1ce1c33cd1e8f6e8421ec1409$yH","test1"},
	{"$dynamic_101$f4a35e798736928804b2eef465761bd510855296b1fbb25316ac05fad5f4690578d8137c02edd889234af912b80ae603ad47a08aff0e0b6e84eda432d9da5acd$gB","thatsworking"},
	{"$dynamic_101$1f33221ae28342e78e2a90d92399029969564d19ae80a530b3b93e5336472eb056cac5d0ae0ca65fef2f46ebd3f7347d3fbb33bd2030db0916f9d25f8d4d30e4$GK","test3"},
	{"$dynamic_101$a8b6e2b02c5bab563f66d7a905d69ab9feb8741fca84c79645a717fbeef77de26cad194fd3875773f586452382391b4f47e26acf0341dfcd7add500bfe025f9d$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_101$466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_102: WHIRLPOOL($s.$p)
static DYNAMIC_primitive_funcp _Funcs_102[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_102[] =
{
	{"$dynamic_102$7aa81139e7678b70751524388e364b64a8f68d08d51ef869c7cb00597246a3a5800af869a736da110836835e67b600936e6cb98004918a8eda60b7c529d420f7$Wdw73yeZ","test1"},
	{"$dynamic_102$ec8ac0ab32650a2a9cf361b4743d0eda196868ce09c374ba59ed35122f88d184d4a4634e82579d98a54b97333e4c0333e20417b95efded39df453fb5a59f7701$MUf2c3pj","thatsworking"},
	{"$dynamic_102$94bb2261deb52f06034106e7c61fdc121cfedcab468b97683b0baf46a3047b9b3da3440a478a1059b7b95a2206bb2a51d61ccfad6a684f1d44dce2b741ebfa10$xr57dTTr","test3"},
	{"$dynamic_102$4427553ca03981d4a0b7722557bd14198839d1bcc917e983e772c43de4c1c98037797698b97f2a52b8d603b91afc4c4d90234f4bcd363150bc21888b00df2e21$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_102$466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_103: WHIRLPOOL(WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_103[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__WHIRLPOOL_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2,
	DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_103[] =
{
	{"$dynamic_103$0f5ab9dd203c82ab38b8364c5f784c3e4b1b80cfbdd2daa353e39023730d8b24527d451529f103018f9c0852919eff60aaa275d07765f44d0b7ba3dcff981034","test1"},
	{"$dynamic_103$ef2efbdb472c549442bf4891724542f3a4662deda5e4d47f0eef176ebccff36c38acb33a57bb68b2d2c69dcdacda8fa17b5d3b453461733e6fb6d3fe5bf10299","thatsworking"},
	{"$dynamic_103$3cd1b185a0779715393126f67f80793a4890b2c0dfccdde8eb83758853d7a8c466d4d7b4552abfb6c3f3cda0d60232772f3618f2d81f2c925bb0000754d2c4f5","test3"},
	{"$dynamic_103$a3f730320468a1b048c7b541f9d1c62ab369c0d2688fce129221243b35874cc58cebf6fcc4efc3897078088535c4e5256985a3b03193a87be6f253df3ba1bd64", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_103$c82951e42e87ba2a5aee6a69916fcc9e441688116b3ed866f25fec459dfe84ae674c2a4c19792cc787223cd3588b6c3a1fa402c6624b0c597e13843e791857ca", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_104: WHIRLPOOL(WHIRLPOOL_raw($p))
static DYNAMIC_primitive_funcp _Funcs_104[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2,
	DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_104[] =
{
	{"$dynamic_104$1346c99ccc424a11800cf44cc37552ae00b5d95901e8a6536f0828738ed59f3a1733d2d61e8df466172de6cb1b839ad6d442910b8bc2838b3df7a48d02512963","test1"},
	{"$dynamic_104$c4d8241fc6a18d11c3359751275add6752e8e99b427b65fda4c28741c2fddbefe08751fcff36d631fea620039a9617d7edf30ab9651d49c0a42f4b242d2f5b21","thatsworking"},
	{"$dynamic_104$28a068c520ebd249c184bd00e8d46058ede551e9277283acfe110f1699a85e84873c1be74ada487e637f4e2acc0007fe5d139589485239af222edcf59b730276","test3"},
	{"$dynamic_104$f639a3c001de250afb52f9f9f18468e9a1de7b7c1a0811b2fa191e11c0017cbe3329baf92efc54893c83d371f72c726892dc17ef1f0b49dbb2dfbd7193a22898", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_104$d69ed37255c4e217c799c086722672aae91b5e4067f675ec5e689f857c3338298754fc2b9d29bf28ac626490f2977dcc4203acf461ee974e9130a4484dc9c46a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_105: WHIRLPOOL(WHIRLPOOL($p).$s)
static DYNAMIC_primitive_funcp _Funcs_105[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_105[] =
{
	{"$dynamic_105$63f8823cf1573956490e3e50973b1710349777412dab36887092ed9045271ad269d3e0c304bab12b2a1a04a3dac303196b0ca7be8feca2a37ee7731458c91f00$AbDlqbZO","test1"},
	{"$dynamic_105$a5e43524673714670a7c64393f1ec6d869ce366f2d2201a7a8d1f47379855be64a1e245d41f5cf67e553634a85cd48c06bfb26c621ae0e6d6e576702062fc24f$B2LbJu5x","thatsworking"},
	{"$dynamic_105$af591b1577c7f4f42814452b0b60c68d86e9eba57787c40160afbead0e4c635fc356e9bf78fcc10952143910921f3435b05856a947f83664e015bfca092da2e5$qzlnAzZw","test3"},
	{"$dynamic_105$f2c0800458cd653a8fbbc3f3daae48cf6f5895bf0429bf30703dfaf3e1ef221038fa9f89dff0880c0c9b07a9d2f6eea613955671d7570d7f3d5d78d6ed930fc9$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_105$078fd4cf15c7f49a3c0a7de222f609db0190f0f99bd8fdd676423b7ef427cb479a755220697ae34dcc9f951a6631bf939e64a7479e2bcfa953f04085e34d77fc$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_106: WHIRLPOOL($s.WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_106[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__WHIRLPOOL_crypt_input1_append_input2,
	DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_106[] =
{
	{"$dynamic_106$40ee08aaf3c1450a76d6dd264c5136e584ad8403ec7322da13efb3661dc8a5c47d839ecf679aea1193176b50a835e1c6ac5480e38ae6a87baf3e4d4b4cb3f2cd$uXeCSVfI","test1"},
	{"$dynamic_106$e01b66cbeeb31ec1ef2937147b2c7ab3efb6469cea01107b8c5e86e645bcfe119d3001b1c0b31ecf6c5d99e158e66d4765bcbb8502e63a82ac09fb5632ae183d$LWo9tepG","thatsworking"},
	{"$dynamic_106$13060286557ae767444cbb5d726ee522355b9c287f4dd83ad36a67aedbaa0fcde111dcb781f2aee5ccac5e84944a27f0119d2d10bd97e3b464577b8546c846b5$7bgJXjSt","test3"},
	{"$dynamic_106$25efdf7e907b0bdc00cf9b2fd81b24a27e0439104b8515e7c1e25404ff3939b15f2cb19f9bf208d9b2405d78640af69abe0587726f9f18572820b557185b2891$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_106$2b83b606ae98e9c54081518a5cc685c21cbe6f1a3e5fe2055f726b97a7cfdb464f0724534207671bcef559fc2dd14c7ee8aa540aec4af59c710e7f8220fac0ce$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_107: WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_107[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2,
	DynamicFunc__WHIRLPOOL_crypt_input1_append_input2,
	DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_107[] =
{
	{"$dynamic_107$86f1b82108b1bf3916a4edd016163348831c411cec38ed2e8f1dafc0b193edde716aae66ab7153ffcc98d968598e42559973c70a866bc8ea50c42cc929f7884e$q45a2XGl","test1"},
	{"$dynamic_107$2e5edfa44b9ae94b34c8be6d7ccb7ac9115cd9989d44a7c29db395c3ed25b169c23a55c0060dce167ae96a845dab03bda783d8381ae233eac7eb809da5af23db$jqjvWzXq","thatsworking"},
	{"$dynamic_107$721808e56a5a0a4111fb4b76652bc6b0a333356915ba50a62b420600a73fe7eb90e6751e3627bef7105a97611da40605d4d4efb6d41e21212cb6c6311a3354a6$FOpkjyZy","test3"},
	{"$dynamic_107$3bf78d6f61d8987795f39a210b3ceee4de8b0a6845a93cb2c56d52e4c1efe5bad699390d98142b4f0fbabff7568770b55ccde7bfdbae8444c6e2a1700cf8b83f$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_107$a0869b8ca75c1b0c24a8b8b3de87736c4665dcdfd16c806ce2a8267e6a41dd6bf44e1013f0235e79e579892510d76c337b0ccb38aac44983577e8a59477fea5c$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_108: WHIRLPOOL(WHIRLPOOL($p).WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_108[] =
{
	//MGF_INPUT_64_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__WHIRLPOOL_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_108[] =
{
	{"$dynamic_108$b1d42b3a7a285847b5d8a9124a795a9c5309ae242ead410ab7aa2de0e5f1d954cf8bdc2650aa74a28761cd4e11af44a4e97532051569c3d00dfa261483ed409b","test1"},
	{"$dynamic_108$1e61a931e292da1cf5fe665010eea990649fe19cbae9e12fb03751d0c0519ce23d154152f414df5a0a9d569e4aeca4c5bbc2f99705dd18cea22b79e4078e19ec","thatsworking"},
	{"$dynamic_108$a7d50bf71a0d5b0d2797531156fd3acae63425ef55cd461c2cf4556518dcc102f5562d24794bc200e4c91434e40179df73b9cd7334056818d2af3f0ea90bfc36","test3"},
	{"$dynamic_108$e68d193eaee1ec4dda147c5d0f7ece95e32ea24b555243f8c52bfc264d931c6c236388e6c7f21ea3cb15f1c28c0b2ceced2508da810a5e3cbc20476cc51e90b5", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_108$106f833a7d09e939eb04b63d92f587637450708c46c4b3ba923d56f7e04fc54ea00fd860d86b7d0ec87e43b6a1fe647265eddfcb816fe50974af21888a4a34ef", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_110: Tiger($p)
static DYNAMIC_primitive_funcp _Funcs_110[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__Tiger_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_110[] =
{
	{"$dynamic_110$c099bbd00faf33027ab55bfb4c3a67f19ecd8eb950078ed2", "test1"},
	{"$dynamic_110$77a533a29f121450b90ce237856127b2cd47db1359758ee0", "thatsworking"},
	{"$dynamic_110$b8b9f8ab7e7b617abd37e86b89dee671f6332af9a4088497", "test3"},
	{"$dynamic_110$983a0475c22b1d0c9c717a262febb2bc06e2ca3f0e446f49", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_110$1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_111: Tiger($s.$p)
static DYNAMIC_primitive_funcp _Funcs_111[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__Tiger_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_111[] =
{
	{"$dynamic_111$b9e3062ae9047433b2d8e67fa99860ba7eea616030b7c3cd$KCh80l","test1"},
	{"$dynamic_111$0c35e8a64cd4f421b009582af6e7ecba43f27a0abb1a51f4$mAIaqQ","thatsworking"},
	{"$dynamic_111$c7d22bb594b33730852d4d20836a7b2c543c58979d7d714b$H7SkQK","test3"},
	{"$dynamic_111$983a0475c22b1d0c9c717a262febb2bc06e2ca3f0e446f49$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_111$1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_112: Tiger($s.$p)
static DYNAMIC_primitive_funcp _Funcs_112[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__Tiger_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_112[] =
{
	{"$dynamic_112$5be18dd441743f2294cb0576e4d1d1cadb45f8851cf0027f$Veo0bpD7","test1"},
	{"$dynamic_112$cca3119c158125bfe4bfc5755d5d10b6b79520b433efbcd4$7j0PHbFb","thatsworking"},
	{"$dynamic_112$b609e4d7c7d59b9e725044319052c959a5642c30b2734709$MCmH3DLI","test3"},
	{"$dynamic_112$2867b48e35bd288f3a607a1a6e3211234a7771ecf6680913$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_112$1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_113: Tiger(Tiger($p))
static DYNAMIC_primitive_funcp _Funcs_113[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__Tiger_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__Tiger_crypt_input1_overwrite_input2,
	DynamicFunc__Tiger_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_113[] =
{
	{"$dynamic_113$d9568618c46ab11a6dc07f6c7e6611aaef94f6dfb58de3f9","test1"},
	{"$dynamic_113$23694933d9a32a00bc9383f78d2e2bdeec70a6c82571233e","thatsworking"},
	{"$dynamic_113$bd13e5e842b94a278cd8c0aefb200ccb009ca17e1b3c7754","test3"},
	{"$dynamic_113$d358475d1a635867cf8e8b44b00ace1dabfd234c989ce9b5", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_113$1d89a501247bb149f4a4b9c5ba5975f0d9f1bb9b30198d0b", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_114: Tiger(Tiger_raw($p))
static DYNAMIC_primitive_funcp _Funcs_114[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__Tiger_crypt_input1_overwrite_input2,
	DynamicFunc__Tiger_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_114[] =
{
	{"$dynamic_114$49fd56fd6adda42abdf991816189ccbff945a9e9c4201919","test1"},
	{"$dynamic_114$e6797c7981a25e4f5b368f8700d2aea475fd7e90b4265f65","thatsworking"},
	{"$dynamic_114$550590323f8ff9d850c40ff8fe0bd6dc43faf6e65f74fef2","test3"},
	{"$dynamic_114$3ea4f388eed3773a775be8b5fc1ad5af9c4ce2717d95121c", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_114$d924e23e81d3655da23946296f8b9f2d7c8619f0c7098693", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_115: Tiger(Tiger($p).$s)
static DYNAMIC_primitive_funcp _Funcs_115[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__Tiger_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__Tiger_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_115[] =
{
	{"$dynamic_115$42f07b536f64106682afa8ab891da84cfadd4d13b1074025$4SLjwS","test1"},
	{"$dynamic_115$9e0124dc691ec243afc62242eced4ebf9242ed0a1fb5a3df$WuotgU","thatsworking"},
	{"$dynamic_115$aa02d0b7d1e599fb280cfb28af9a24c349197fe385e99358$WMPmYO","test3"},
	{"$dynamic_115$50657aa67219d6f00aea485a8763eb102d89cf52f1dc9f3e$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_115$df485fbc502ce4af0f7439bc428352d00c8cb56bbb09d4de$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_116: Tiger($s.Tiger($p))
static DYNAMIC_primitive_funcp _Funcs_116[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__Tiger_crypt_input1_append_input2,
	DynamicFunc__Tiger_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_116[] =
{
	{"$dynamic_116$949abe42a3fb02f95ea403c216707cb1b0db2e543b094afd$NW4uHL","test1"},
	{"$dynamic_116$433b70b50ea4ea05c1b920e9794f2f1a15b84d65e9997da4$UjuO0F","thatsworking"},
	{"$dynamic_116$e47227d2ad4f85f7064c7fd9dcc476c75c26c9d5d3e3d990$TI2V6w","test3"},
	{"$dynamic_116$f6591748c68bcadd197a766f87266f5b1ff7e84dc39fcb3b$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_116$47293f200817e14dbb2d76b4298f7d4eafa05538104b6f95$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_117: Tiger(Tiger($s).Tiger($p))
static DYNAMIC_primitive_funcp _Funcs_117[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__Tiger_crypt_input2_overwrite_input2,
	DynamicFunc__Tiger_crypt_input1_append_input2,
	DynamicFunc__Tiger_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_117[] =
{
	{"$dynamic_117$4a3443bc430e461236578b3a6d894543caa11dc67608f5e1$zuvXaO","test1"},
	{"$dynamic_117$c5da7cf68984d2a15bc09c79766d6d0e2715efb6aa9707bd$BhU05y","thatsworking"},
	{"$dynamic_117$137362481b7ace538d52b731564dc23b3ce20d18c985637b$Ozow4i","test3"},
	{"$dynamic_117$28ae4af45dba63a93cd0c5668cb9f9ed2d9901e2bff9c60c$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_117$708f87d2172ea92bf3ec78408afe9d2272a9400082a0a6d2$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_118: Tiger(Tiger($p).Tiger($p))
static DYNAMIC_primitive_funcp _Funcs_118[] =
{
	//MGF_INPUT_24_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__Tiger_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__Tiger_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_118[] =
{
	{"$dynamic_118$c4d8ae7ed634de780059f93dad2676fca5c83c2257c5bfbf","test1"},
	{"$dynamic_118$3ae1b52c145a3899c099ae8c45b159ac65f8ca54a312af84","thatsworking"},
	{"$dynamic_118$64d847ba02fb89902b9557a89a3c8c3e3474982001dc93f4","test3"},
	{"$dynamic_118$f605e96ed1ee857617a60802801e52d334b26f8ca0e2b0b5", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_118$0ca3f36b42ce0c2eaa236ded2a4f5cce15fcab859840f8d5", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_120: RIPEMD128($p)
static DYNAMIC_primitive_funcp _Funcs_120[] =
{
	//MGF_KEYS_INPUT
	//MGF_NOTSSE2Safe
	DynamicFunc__RIPEMD128_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_120[] =
{
	{"$dynamic_120$f9a23a637f86eda730ce9cf163632ad5", "test1"},
	{"$dynamic_120$252ad54db91c4cc15a11662a277a5f77", "thatsworking"},
	{"$dynamic_120$f6a1643123332bd035bfe354af813669", "test3"},
	{"$dynamic_120$8581f04ea4cfac47ee6c9256bf46f536", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_120$3f45ef194732c2dbb2c4a2c769795fa3", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_121: RIPEMD128($s.$p)
static DYNAMIC_primitive_funcp _Funcs_121[] =
{
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__RIPEMD128_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_121[] =
{
	{"$dynamic_121$0bb8ae84dde90f9f645141f6f4af3bdb$4WXiYq","test1"},
	{"$dynamic_121$58526c066590a74fad9b2a1ed96dcf86$lcSnpQ","thatsworking"},
	{"$dynamic_121$184e1f3f8faa8c0646027a61152ae42c$6aucqk","test3"},
	{"$dynamic_121$8581f04ea4cfac47ee6c9256bf46f536$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_121$3f45ef194732c2dbb2c4a2c769795fa3$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_122: RIPEMD128($s.$p)
static DYNAMIC_primitive_funcp _Funcs_122[] =
{
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__RIPEMD128_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_122[] =
{
	{"$dynamic_122$d6ad14f6c1903a81d4c430cfcaa19a88$NBQTeKMC","test1"},
	{"$dynamic_122$2bbe72c7b34c76026faff9373bc9a66d$3ivG1Fiq","thatsworking"},
	{"$dynamic_122$8e8d9579716cced03d472b99ab0caba2$CT7bc2vn","test3"},
	{"$dynamic_122$63f895dbde38d4b7046a1892a1632599$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_122$3f45ef194732c2dbb2c4a2c769795fa3$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_123: RIPEMD128(RIPEMD128($p))
static DYNAMIC_primitive_funcp _Funcs_123[] =
{
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__RIPEMD128_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_123[] =
{
	{"$dynamic_123$82cf6702a0086265c121e53c8ec0429b","test1"},
	{"$dynamic_123$93bb21d4f8e8810ea20a7d35f83a1a15","thatsworking"},
	{"$dynamic_123$cc13be2cf4ecaef2451288eee126b0e2","test3"},
	{"$dynamic_123$b65db9c5e4322459d450331af900a994", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_123$903d41ccc67182b8b6ff599c0a0851af", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_124: RIPEMD128(RIPEMD128_raw($p))
static DYNAMIC_primitive_funcp _Funcs_124[] =
{
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_124[] =
{
	{"$dynamic_124$15b65cb87ea92f0664b8fba08eb8ed96","test1"},
	{"$dynamic_124$f5ee005cf57939b982008d20d2ab59be","thatsworking"},
	{"$dynamic_124$0cfa0daae0d7dd9e90bc831d0e3e4f2f","test3"},
	{"$dynamic_124$48db142c01371618cbbc9e828ca407b4", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_124$0317cec776308824607d4e20e81203a3", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_125: RIPEMD128(RIPEMD128($p).$s)
static DYNAMIC_primitive_funcp _Funcs_125[] =
{
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_125[] =
{
	{"$dynamic_125$387e8777e5cfd291949c2597cd7b5e5e$nJQUYy","test1"},
	{"$dynamic_125$29c3b080553b93f65cde3af1acd45598$OTaKW5","thatsworking"},
	{"$dynamic_125$40e2c171ce9e1ebb86b31fb115c406e3$JFTav4","test3"},
	{"$dynamic_125$92961d6f105b871bf5c1ed43a4631594$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_125$99079c9dd6cfcf600e83b0c135eb9e3c$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_126: RIPEMD128($s.RIPEMD128($p))
static DYNAMIC_primitive_funcp _Funcs_126[] =
{
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD128_crypt_input1_append_input2,
	DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_126[] =
{
	{"$dynamic_126$97bb5a099b2f6e2ff1fe142f3fd5c498$qYpElZ","test1"},
	{"$dynamic_126$61efb3f51a6bc0fa30665a30e9ba608c$DXIYEQ","thatsworking"},
	{"$dynamic_126$1029b7c3f55f19126c3eaa9b7a5ddd55$mC2GcF","test3"},
	{"$dynamic_126$c1cba4ed97845153618256021f8cf505$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_126$b6dd8f96fcbd17489df2459a156f8ef9$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_127: RIPEMD128(RIPEMD128($s).RIPEMD128($p))
static DYNAMIC_primitive_funcp _Funcs_127[] =
{
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD128_crypt_input2_overwrite_input2,
	DynamicFunc__RIPEMD128_crypt_input1_append_input2,
	DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_127[] =
{
	{"$dynamic_127$616b8734d328da207b9dcc98df822996$awiEMX","test1"},
	{"$dynamic_127$10a6c4d59f3b7b60371e713a1445356c$jCk0T9","thatsworking"},
	{"$dynamic_127$09c0088c0cb5b90d8076a7db1a11f868$G775MU","test3"},
	{"$dynamic_127$e8d40059586f40fa4e5b35b93efa1f64$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_127$c0aed7e633b83628c3e43d8dfdc0ad42$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_128: RIPEMD128(RIPEMD128($p).RIPEMD128($p))
static DYNAMIC_primitive_funcp _Funcs_128[] =
{
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__RIPEMD128_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_128[] =
{
	{"$dynamic_128$9fb0be59a61be9e674cf9e53de01f45a","test1"},
	{"$dynamic_128$33572aa87db2991d504f0d5b3470fabb","thatsworking"},
	{"$dynamic_128$b2a315b546b04a485f7ff925f8944494","test3"},
	{"$dynamic_128$98b8babb0c766a48efd102c1eb3dc739", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_128$9f1ffff733fa1f1196dd5bfccaa75e09", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_130: RIPEMD160($p)
static DYNAMIC_primitive_funcp _Funcs_130[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__RIPEMD160_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_130[] =
{
	{"$dynamic_130$9295fac879006ff44812e43b83b515a06c2950aa", "test1"},
	{"$dynamic_130$5a8c3d2e585ae3533a25a60a40736a9644fccf70", "thatsworking"},
	{"$dynamic_130$78872e94d9e3c83e3ba17445a5f30642da51827c", "test3"},
	{"$dynamic_130$c8d39332bf00115e2fb86f76e2fbab9953b94ff9", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_130$9b752e45573d4b39f4dbd3323cab82bf63326bfb", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_131: RIPEMD160($s.$p)
static DYNAMIC_primitive_funcp _Funcs_131[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__RIPEMD160_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_131[] =
{
	{"$dynamic_131$702368a38713a074cae056beed5133cf51fbb7fc$kIA09e","test1"},
	{"$dynamic_131$109490936b84898f4d525201fd6802c1250123d8$Kj5Hkq","thatsworking"},
	{"$dynamic_131$30cf4d6bf729da8b4bc90878c7b084284e302540$L4YQ0N","test3"},
	{"$dynamic_131$c8d39332bf00115e2fb86f76e2fbab9953b94ff9$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_131$9b752e45573d4b39f4dbd3323cab82bf63326bfb$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_132: RIPEMD160($s.$p)
static DYNAMIC_primitive_funcp _Funcs_132[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__RIPEMD160_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_132[] =
{
	{"$dynamic_132$592cc8f4a54c9cd6739486a060c6faa54632994c$1gNbg96B","test1"},
	{"$dynamic_132$c9e74120fb3373fea1adaedda031b93de7ff38e5$8M0daSKZ","thatsworking"},
	{"$dynamic_132$89adf6af617b87736e9d4775a113d60256a147c2$ZviBFfAb","test3"},
	{"$dynamic_132$c9b51d626fe670bf87a4d27745134047a6c5f9d8$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_132$9b752e45573d4b39f4dbd3323cab82bf63326bfb$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_133: RIPEMD160(RIPEMD160($p))
static DYNAMIC_primitive_funcp _Funcs_133[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__RIPEMD160_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_133[] =
{
	{"$dynamic_133$d09e375a8e6031e59861c479e892a3b169431419","test1"},
	{"$dynamic_133$69056d1cd2c2ea986c1e031a3e09cf0633d42d7f","thatsworking"},
	{"$dynamic_133$36554863e1db12d5743a21d4036f4a5b32b7aa90","test3"},
	{"$dynamic_133$1d1bff1ade0e70374857c3c11a7c5f6652335059", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_133$1f29f86842dae387d6c20f348a68fccd02125ac3", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_134: RIPEMD160(RIPEMD160_raw($p))
static DYNAMIC_primitive_funcp _Funcs_134[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_134[] =
{
	{"$dynamic_134$41a3ca6d04553f3d07bb8093a147beb4712fe293","test1"},
	{"$dynamic_134$b9f43e379172276e0255f36dba0bf61a53c1a681","thatsworking"},
	{"$dynamic_134$b21b9471406dda502265081d4e3756c3f5ed19ac","test3"},
	{"$dynamic_134$ec09764740f0a00ff78b4ad1c3714600d7da9e09", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_134$b1fa3529aceec6a64c7019db6408bbcff9ef541e", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_135: RIPEMD160(RIPEMD160($p).$s)
static DYNAMIC_primitive_funcp _Funcs_135[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_135[] =
{
	{"$dynamic_135$dcfecea55e0f6bb6ae86d48bde0d390d3ec292ab$8smSN6","test1"},
	{"$dynamic_135$256ec34e20b7fc35a176002f2c12f17a12e1fcca$R5w0PU","thatsworking"},
	{"$dynamic_135$0b926db2c6926a7a20fb342f82ab5d6e7e8cce3d$fi3FOT","test3"},
	{"$dynamic_135$6cd8554117d717a008bb133a2fb03b985f62b892$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_135$30074d946000a735a78be5348449c8f0dc7bd929$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_136: RIPEMD160($s.RIPEMD160($p))
static DYNAMIC_primitive_funcp _Funcs_136[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD160_crypt_input1_append_input2,
	DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_136[] =
{
	{"$dynamic_136$b748c1a685cfc519bb364767af1272dcdc822eed$hhrFRL","test1"},
	{"$dynamic_136$7522b95c103a2c2d931ed431380c1cbb01320d88$8ZBzV9","thatsworking"},
	{"$dynamic_136$5cb245d32aeb805ceb108c0bc70b2a2bc675df81$1PIXLR","test3"},
	{"$dynamic_136$7e65afbd57ded9497a93116cd808110f64ba3824$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_136$2b129efd86b042ef938197bcc4f53872400e14be$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_137: RIPEMD160(RIPEMD160($s).RIPEMD160($p))
static DYNAMIC_primitive_funcp _Funcs_137[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD160_crypt_input2_overwrite_input2,
	DynamicFunc__RIPEMD160_crypt_input1_append_input2,
	DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_137[] =
{
	{"$dynamic_137$977090a8be7b29569f16aa0df492f12de4abf580$h6SIQX","test1"},
	{"$dynamic_137$a0b89831305e33750e52119186a39d553f6d4fa7$XDiShI","thatsworking"},
	{"$dynamic_137$b45aeb16d4ce6ceb68225a5647b19d6cb8e32b4e$cMdtOm","test3"},
	{"$dynamic_137$e2a1cd823b6390711708203dc38774e369af7056$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_137$a1779ee6b3fada8425f4417cb7b0fe0f2c58a759$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_138: RIPEMD160(RIPEMD160($p).RIPEMD160($p))
static DYNAMIC_primitive_funcp _Funcs_138[] =
{
	//MGF_INPUT_20_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__RIPEMD160_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_138[] =
{
	{"$dynamic_138$d6a76d520f9f74aeca1fee22e961d74c916df334","test1"},
	{"$dynamic_138$6d9543280c7f70bc612143d3980ff99367258d63","thatsworking"},
	{"$dynamic_138$12fbe8a67372ea76ed786dc08f32a17f778ee695","test3"},
	{"$dynamic_138$3330fc3c867dcc5f3921019afa5b6c64f23d0ec2", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_138$ecae9dccf4352d4220a73dbb8ff54de3227e9a94", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_140: RIPEMD256($p)
static DYNAMIC_primitive_funcp _Funcs_140[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__RIPEMD256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_140[] =
{
	{"$dynamic_140$1419109aa0de60e6ba0b6d2b2f602c13b07e97b5ffc85b6be2297badc699262f", "test1"},
	{"$dynamic_140$f156e6c20042057840f3251ee041596d89fde06c2505f61764ad1c03c2fc1375", "thatsworking"},
	{"$dynamic_140$d20d9172e3ae2ade512d88eb69d548d62bdfc3d3ed3e3f0fdea12d84bc8f71a7", "test3"},
	{"$dynamic_140$dcf8bee089763999c60a127ee6291b5047a7544c101b7a075a29835b3b804eec", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_140$06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_141: RIPEMD256($s.$p)
static DYNAMIC_primitive_funcp _Funcs_141[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__RIPEMD256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_141[] =
{
	{"$dynamic_141$305191d90a91a457b0d68c1ce30b03b44c1b5ab2bdf1cb11ae1cc28e654c16f3$VQl6tP","test1"},
	{"$dynamic_141$5d0b21f3e51781126c4dbec9e811d3d0ba6abc4a1c5ca157fedeec3b79288c4b$XXEuU5","thatsworking"},
	{"$dynamic_141$ecb2e5ba9bcbcd2750a960a80eed73729c80db526bc08854ddb400a826105328$d5GEhi","test3"},
	{"$dynamic_141$dcf8bee089763999c60a127ee6291b5047a7544c101b7a075a29835b3b804eec$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_141$06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_142: RIPEMD256($s.$p)
static DYNAMIC_primitive_funcp _Funcs_142[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__RIPEMD256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_142[] =
{
	{"$dynamic_142$03b1ef0c912340bcdb2d54c6a090bd848eea04ca9cddd20ee0794d8bab991cf0$qsiyvyfd","test1"},
	{"$dynamic_142$c9cfe7a23fc45711008c64e503088300bf2d74661cb8270177f667104eb34910$txjvunyP","thatsworking"},
	{"$dynamic_142$38221d38279d3cbe09516db1cee712c78d68d0cb20210d21dd9bd6f6d2559fcc$xHyh3Eqo","test3"},
	{"$dynamic_142$fd14664a2ba9b3dabb810d7112d5812464cf061ac931017c639c60955748d3df$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_142$06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_143: RIPEMD256(RIPEMD256($p))
static DYNAMIC_primitive_funcp _Funcs_143[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_143[] =
{
	{"$dynamic_143$14889a0b5d0cdfdd40d9b2b68bdf0362f76cbd405a7b389ef0c19fb4d10578c0","test1"},
	{"$dynamic_143$1ca0090ad4b4d6d251e5a453f204f3b0b1aa220bdd1b5063a3e38cc4f06a6e46","thatsworking"},
	{"$dynamic_143$a8f808b43eaad67023830d9f6d33fd36dc6c80840c49ef03d30607d86f4873ae","test3"},
	{"$dynamic_143$0ba7ec5169e21c6607133112135093c4e26be3f0ca1c0c71eba2c33ab67affd0", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_143$bd526ec1d3ba56beee0bb75586136dacdc9335158b4bbc0d2871360a5b23477c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_144: RIPEMD256(RIPEMD256_raw($p))
static DYNAMIC_primitive_funcp _Funcs_144[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_144[] =
{
	{"$dynamic_144$6bac793b70b75cc04e0b1baae3a6aeb04c1008d0a483b2a024743902cb93b86f","test1"},
	{"$dynamic_144$d686ebcdd2f2da167ef365c5682e758788a5493b098e943ef2b6fc7dbf9be361","thatsworking"},
	{"$dynamic_144$f809ae64bbf1a5d834b0db355819f8fb166b826c0947d0e506cef331e030be4e","test3"},
	{"$dynamic_144$a7cf9330fe966552b2023b81baa2a04aa2b9d6924d1103a0204947933e91fa0b", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_144$02f2870ef7e25a82a583252594a20d65b90a10d81d9ac1ce400b8445bb24a051", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_145: RIPEMD256(RIPEMD256($p).$s)
static DYNAMIC_primitive_funcp _Funcs_145[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_145[] =
{
	{"$dynamic_145$519b7e54144c9a9d655e93df5fb0a09f07a2692fe3fc30889aa9249dff48529d$uKs6lm","test1"},
	{"$dynamic_145$ccf57a7acf5f1211d59fba187c741c05cf26e88f1bbb0ef25bbd22a6b31afb89$LsNB5N","thatsworking"},
	{"$dynamic_145$8f4527840691f40799de14fdb2b0b68c10d2e7ce4a991ee17ff0b81b63ca8924$N2lQ7c","test3"},
	{"$dynamic_145$93be5067e7574462f1a07e862c8ce8072b133ba535970f8bc23bf4f6d9add3a3$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_145$26c2680be2a7feb5b1171657e65f8d2e399f59b20fef5cc5ca1756b58c56620d$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_146: RIPEMD256($s.RIPEMD256($p))
static DYNAMIC_primitive_funcp _Funcs_146[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD256_crypt_input1_append_input2,
	DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_146[] =
{
	{"$dynamic_146$9be0a3daed226b414ca4a8c756eeb5d26774ef2e0186721b07dc1375aad1f18e$JAap27","test1"},
	{"$dynamic_146$b130046594c8929009513dab4bcad94d616747bc05eeb5e188f2ae228221bcf4$rfnDyG","thatsworking"},
	{"$dynamic_146$13705270594ab1b9c84fddfa69816a6062f708c283b39faf46e9a5c056d652ae$CLSrX1","test3"},
	{"$dynamic_146$45819624c0530cd7f21139230f5c72c4f223e64089ef67648fb54960a4357941$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_146$523ce04992f839dd1b599a565f527f6b226111441faa6aff6d35727b4dad5eed$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_147: RIPEMD256(RIPEMD256($s).RIPEMD256($p))
static DYNAMIC_primitive_funcp _Funcs_147[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD256_crypt_input2_overwrite_input2,
	DynamicFunc__RIPEMD256_crypt_input1_append_input2,
	DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_147[] =
{
	{"$dynamic_147$5862a5cbdc4bde3f314151af504565f13ac289bedc2bb75f663705fd63aea107$qg784y","test1"},
	{"$dynamic_147$aa936840f5a3476efbc990fac97ee8ad9c4391e85c79e7ed3ed8529121b2067a$nqifRw","thatsworking"},
	{"$dynamic_147$c2d89bad1ed5ddfcbdb65f44cafe54f18ee3e63e51566d407ef914585a1f2432$5bq1yI","test3"},
	{"$dynamic_147$321b6e5f5911eb74649d14fd105524166a7c9726c62d2ff5a7745a45a7f72da6$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_147$2b3a2bf4336ee10500a51d67ca497a83869d090e64c41c3a516ac2c4fb117ca7$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_148: RIPEMD256(RIPEMD256($p).RIPEMD256($p))
static DYNAMIC_primitive_funcp _Funcs_148[] =
{
	//MGF_INPUT_32_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__RIPEMD256_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_148[] =
{
	{"$dynamic_148$2ba00db7b3f6acdc55ac34fe847907d68b730c48cbfcbcb1306592653b450133","test1"},
	{"$dynamic_148$9c821fad9361d7c09df4a1191cbe22f451e1b2ebe03aa5a81c4bcc95471f484e","thatsworking"},
	{"$dynamic_148$fc25f51bbc2edd52e8a16632053de02d13066a327fe951418c5ad91b936ff4c0","test3"},
	{"$dynamic_148$4912a0eeb3d8c487800f5fa0e32689e73dca08726607f3236ea44b80d36a88c1", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_148$7b66671df56b57001cccfa607ca57f723b760052055f41b1101ce3c8c2b72fcd", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_150: RIPEMD320($p)
static DYNAMIC_primitive_funcp _Funcs_150[] =
{
	//MGF_KEYS_INPUT
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	DynamicFunc__RIPEMD320_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_150[] =
{
	{"$dynamic_150$303aa1dcb731cd4e4bff2a60971eb7376c6c47cb59947c804776d115470183c8cc2e487337b45412", "test1"},
	{"$dynamic_150$3c616c27aa7539c4726388c9e047aa4ea089dd739b3cfc470e964ea12e479da3cce437b9daa90214", "thatsworking"},
	{"$dynamic_150$4e44b8f67fdc48c167ff0e285350a7df5c050660b601599f2e541d8cbc44696ad1c080028f13c6e7", "test3"},
	{"$dynamic_150$3f2cccbdf900f2d07cca145d93f4dff42928bf2dae045edeb2b2a5cc348c83248d55791eb4949264", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_150$557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};


//	dynamic_151: RIPEMD320($s.$p)
static DYNAMIC_primitive_funcp _Funcs_151[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_salt,
	DynamicFunc__append_keys,
	DynamicFunc__RIPEMD320_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_151[] =
{
	{"$dynamic_151$883750723bb1b2c1d4be8ba6be77605885ba1ee8be4ea0f11a6b9c3d9f2dd67bfab7dc19abf6f17f$AMKTOt","test1"},
	{"$dynamic_151$feacc00098c7da4a4ee07f2938110735c3bbdf98c9d18693bfb2687bd138f5293694ff7a8e1019c4$1IUmij","thatsworking"},
	{"$dynamic_151$b7a213f281e5328e301faa67652d916bbac3187de6afd26d107db476319599e57aafd0378713a275$LqtyZa","test3"},
	{"$dynamic_151$3f2cccbdf900f2d07cca145d93f4dff42928bf2dae045edeb2b2a5cc348c83248d55791eb4949264$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_151$557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_152: RIPEMD320($s.$p)
static DYNAMIC_primitive_funcp _Funcs_152[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__append_salt,
	DynamicFunc__RIPEMD320_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_152[] =
{
	{"$dynamic_152$a52d865f5443c09dd56db4f9d817248a5b338dbd899b29fecf174b2118f4e8dc823b891d1411a54b$2zU2KwSK","test1"},
	{"$dynamic_152$70f5f407eb29c213f4fb5c43ade06bdcbb9d629c806625c9aa3031ee16dedde337597f992d8cbc48$q01b45z5","thatsworking"},
	{"$dynamic_152$2062185fe9d8577deb40669482803e3f21fd5bb15091c52cbb762df5bccf730993eb87f9802694da$S4RmC4l6","test3"},
	{"$dynamic_152$ca5a9845c7a8fcd29318842cc3faa2b00b7389e642fd33e002548ddb9d603581bc1c32b5f1e95044$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_152$557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_153: RIPEMD320(RIPEMD320($p))
static DYNAMIC_primitive_funcp _Funcs_153[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT

	//DynamicFunc__clean_input2,
	//DynamicFunc__RIPEMD320_crypt_input1_append_input2,
	// both appand and overwrite tested.  Since we have a fixed size, overwrite, with no clean2 works fine and faster.
	DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL,
	NULL
};

static struct fmt_tests _Preloads_153[] =
{
	{"$dynamic_153$a31e129221c83ef39a11df2fb35207c3836bd6db07668745dd56abb9f183b7b27fdde856868f5d38","test1"},
	{"$dynamic_153$9824e4a0d2c406cac91048824a7b5b4c81935a180325ab77e5287a9c7cfe288b8e450718709a6ab1","thatsworking"},
	{"$dynamic_153$90c18c86ece60693f7001aed9693fc1a655fc383f76cfaa9936dc922ca3de9f1a07b31e2bcf6518f","test3"},
	{"$dynamic_153$8a68741f93d5e56f3ce5c066a6be6202eee0cb12d190e5e5c1603e7398ec3a605531c995204c0c3e", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_153$008f3f29a8bae0893e11f4272d035bdc81cf62e575ceb302b539b2a99961e4979379dfba1ed3a9ff", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_154: RIPEMD320(RIPEMD320_raw($p))
static DYNAMIC_primitive_funcp _Funcs_154[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__LargeHash_OUTMode_raw,
	DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2,
	DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_154[] =
{
	{"$dynamic_154$e104a7e9c56595fbf69c528a5249279c4e100a48c5b190d46ba73315ed729930d602234d59ad078a","test1"},
	{"$dynamic_154$fb10077a7f09ffffb986fe79e9620e2645b4828a0ff6f5011d6ae7fa6ab15d56b787ee3fa7e00366","thatsworking"},
	{"$dynamic_154$dd87e05b9950ab49a399b47918db5f7057cc8e2416def762660ccd45ae9cd3fe2d26c4114504d002","test3"},
	{"$dynamic_154$c056cc34132cec0bafc359fa8ade3e23e49ecc9c05d864d9290940adadffa8c05e48181fe97aa895", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_154$a10135bba09a2927dfc0255204b1ac235702d7d461131e20ab6d65b953f1fd838201b220143f1ad2", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_155: RIPEMD320(RIPEMD320($p).$s)
static DYNAMIC_primitive_funcp _Funcs_155[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_155[] =
{
	{"$dynamic_155$c791488c72190edf6f786ad9d4501eb237acfcb867e7bbc68cf1a7e39d78de63040727bfa0b92abb$3mmjYb","test1"},
	{"$dynamic_155$365c0c4f0ee23d09fe7cf79383c3e2b9b9adeda8fa0c164c7d9e9d6a526ba31c64959d108019fbb1$wVG5YM","thatsworking"},
	{"$dynamic_155$0bc38948f67f8610dd86fcfed3f1b3bf6723ad87c6e2e3e8d5bfb336454b0b15bc1eed35edc39971$3FW422","test3"},
	{"$dynamic_155$eff665499667effd8669b608dfc2b41c77a93eb6809b9fa59aef224e48129814df0c4added25eb17$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_155$228b2504d891987d63eff905dda4ad18e6f8999f7dccf2e39f732553dc29a45867324b6d6b74818a$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_156: RIPEMD320($s.RIPEMD320($p))
static DYNAMIC_primitive_funcp _Funcs_156[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD320_crypt_input1_append_input2,
	DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_156[] =
{
	{"$dynamic_156$a51215627a8f32fc030601ef602b7901858852425d9c5b6bd76b15df83ac297f1d413235041a71ae$9pDFpI","test1"},
	{"$dynamic_156$f138210d758f0441e4550efd65e176c013ef626e1598c117e5e85ef9d9745dc0613d90c8a61a7769$3CJLnI","thatsworking"},
	{"$dynamic_156$da4ac2fa4e302289fc708d095dafea134b72a176c118c06df42f8c2366f9c39c779004fdefd8887c$dlof3w","test3"},
	{"$dynamic_156$8dde451f4c52a5ff19129f5309b741c59d4f5f9812ab23b2746ef2364138bc63d7d62c16a3d44a1d$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_156$ddfb59ed0a2f52c8f4a19dd42eb9555b067531924cbb61a1575ceed374381771d5e1918bf1e69536$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_157: RIPEMD320(RIPEMD320($s).RIPEMD320($p))
static DYNAMIC_primitive_funcp _Funcs_157[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	//MGF_SALTED
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2,
	DynamicFunc__append_salt2,
	DynamicFunc__RIPEMD320_crypt_input2_overwrite_input2,
	DynamicFunc__RIPEMD320_crypt_input1_append_input2,
	DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_157[] =
{
	{"$dynamic_157$fa2614cc3b494d5280811d5e5aac0c262f8ac1efcd01378b82be9c12d1a9ac8081315df61fac7173$xHBzxu","test1"},
	{"$dynamic_157$f498579e4cfc825549023ead371460f771c2d039c9ca438b9e1889e38fb7687ab75b94ad60458f34$QuzmKD","thatsworking"},
	{"$dynamic_157$a240f21c470dc8812234326922ecab6599ba48b8163912b66fd37ada9fab39229ffc7578a0cdb843$5mq9og","test3"},
	{"$dynamic_157$860a03b8dea138678d0f977cc63e73b2723f1c5e2a15ee9074b94f44d31d14addf8ec86adc5965cf$12345678901234567890", "12345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_157$08c8d658dc0e480f23a48b9aa1be2a7dd25fddb5dda56f6ce02706306eb2873721df54142f8e07e4$12345678901234567890", "123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

//	dynamic_158: RIPEMD320(RIPEMD320($p).RIPEMD320($p))
static DYNAMIC_primitive_funcp _Funcs_158[] =
{
	//MGF_INPUT_40_BYTE
	//MGF_NOTSSE2Safe
	//MGF_KEYS_IN_INPUT
	DynamicFunc__clean_input2_kwik,
	DynamicFunc__RIPEMD320_crypt_input1_append_input2,
	DynamicFunc__append_input2_from_input2,
	DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_158[] =
{
	{"$dynamic_158$083b9aed550cc2788fffbd07bd9a02b10b40edcb9357692942e2f6689c0c800005d09855d5a5a150","test1"},
	{"$dynamic_158$e1d2e0183c05d0094a9986d9dcb0add0344fd401eb255b23cf84bb6d5321cb70669eb3ef7562972b","thatsworking"},
	{"$dynamic_158$824aaade4d6e6441f8da3e8dd7549b70ece96c2d08035ed4cb71f1d5d5e2ba17db46f699bdff8b1e","test3"},
	{"$dynamic_158$bb9620632ac9326748df91e8f569d1b33673a9f8bc4e3255d4d1b3b90d4237fcc16a8cd24661e6f0", "1234567890123456789012345678901234567890123456789012345"},
#ifndef MMX_COEF
	{"$dynamic_158$bef8d92d1528a774902d49d3a21a1da9c8e8d91a80bc4a2028822dbd5656d8e99714ed8eba78a045", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
#endif
	{NULL}
};

// Here is a 'dummy' constant array. This will be 'linked' to any dynamic format that does not have any constants.
static DYNAMIC_Constants _ConstDefault[] =
{
	{0, NULL}
};

// Here are the 'prebuilt' dynamic objects, ready to be 'loaded'
static DYNAMIC_Setup Setups[] =
{
#if FMT_MAIN_VERSION > 9
	{ "dynamic_0: md5($p) (raw-md5)",           _Funcs_0, _Preloads_0, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SOURCE },
#else
	{ "dynamic_0: md5($p) (raw-md5)",           _Funcs_0, _Preloads_0, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT },
#endif
	{ "dynamic_1: md5($p.$s) (joomla)",         _Funcs_1, _Preloads_1, _ConstDefault, MGF_SALTED, MGF_NO_FLAG, -32 },
	{ "dynamic_2: md5(md5($p)) (e107)",         _Funcs_2, _Preloads_2, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_3: md5(md5(md5($p)))",           _Funcs_3, _Preloads_3, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_4: md5($s.$p) (OSC)",            _Funcs_4, _Preloads_4, _ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24  },
	{ "dynamic_5: md5($s.$p.$s)",               _Funcs_5, _Preloads_5, _ConstDefault, MGF_SALTED, MGF_NO_FLAG, -12, 31, 56  },
	{ "dynamic_6: md5(md5($p).$s)",             _Funcs_6, _Preloads_6, _ConstDefault, MGF_SALTED, MGF_KEYS_BASE16_IN1, -23, 55, 80 },
#if 0
	// this format is deprecated. If someone WANTS it to work, then it can be uncommented.
	// however it is MUCH better to use dyanamic_6, and if there are any bad characters in
	// the salts (like ':'), then use %HEX$ for that candidate's salt value.
	{ "dynamic_7: md5(md5($p).$s) (vBulletin)", _Funcs_7, _Preloads_7, _ConstDefault, MGF_SALTED|MGF_ColonNOTValid, MGF_KEYS_BASE16_IN1, 3, 52 },
#endif
	{ "dynamic_8: md5(md5($s).$p)",             _Funcs_8, _Preloads_8, _ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX, MGF_NO_FLAG, -32,  23},
	{ "dynamic_9: md5($s.md5($p))",             _Funcs_9, _Preloads_9, _ConstDefault, MGF_SALTED, MGF_KEYS_BASE16_IN1, -23, 55, 80 },
	{ "dynamic_10: md5($s.md5($s.$p))",         _Funcs_10,_Preloads_10,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -23 },
	{ "dynamic_11: md5($s.md5($p.$s))",         _Funcs_11,_Preloads_11,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -23 },
#if defined (MMX_COEF) && defined (_OPENMP)
	{ "dynamic_12: md5(md5($s).md5($p)) (IPB)", _Funcs_12,_Preloads_12,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX|MGF_NOTSSE2Safe, MGF_KEYS_BASE16_IN1_Offset32, -32, 55, 80 },
	{ "dynamic_13: md5(md5($p).md5($s))",       _Funcs_13,_Preloads_13,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX|MGF_NOTSSE2Safe, MGF_KEYS_BASE16_IN1, -32, 55, 80 },
#else
	{ "dynamic_12: md5(md5($s).md5($p)) (IPB)", _Funcs_12,_Preloads_12,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX, MGF_KEYS_BASE16_X86_IN1_Offset32, -32, 55, 80 },
	{ "dynamic_13: md5(md5($p).md5($s))",       _Funcs_13,_Preloads_13,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX, MGF_KEYS_BASE16_X86_IN1, -32, 55, 80 },
#endif
#if defined (MMX_COEF)
	{ "dynamic_14: md5($s.md5($p).$s)",         _Funcs_14,_Preloads_14,_ConstDefault, MGF_SALTED,MGF_KEYS_CRYPT_IN2, -11, 55, 80, -24 },
#else
	{ "dynamic_14: md5($s.md5($p).$s)",          _Funcs_14,_Preloads_14,_ConstDefault, MGF_SALTED, MGF_KEYS_BASE16_IN1, -11, 55, 80, -24},
#endif
	{ "dynamic_15: md5($u.md5($p).$s)",         _Funcs_15,_Preloads_15,_ConstDefault, MGF_SALTED|MGF_USERNAME|MGF_NOTSSE2Safe|MGF_FULL_CLEAN_REQUIRED, MGF_KEYS_BASE16_IN1, -12, 55, 80 }, // 26 is 12+12+2 so 24+52 'fits
	{ "dynamic_16: md5(md5(md5($p).$s).$s2)",   _Funcs_16,_Preloads_16,_ConstDefault, MGF_SALTED|MGF_SALTED2|MGF_NOTSSE2Safe, MGF_KEYS_BASE16_IN1, -23, 55, 80 },
	#if !ARCH_LITTLE_ENDIAN
	{ "dynamic_17: phpass ($P$ or $H$)",        _Funcs_17,_Preloads_17,_ConstDefault, MGF_SALTED|MGF_INPBASE64, MGF_PHPassSetup, 9, 38, 38 },
	#else
	{ "dynamic_17: phpass ($P$ or $H$)",        _Funcs_17,_Preloads_17,_ConstDefault, MGF_SALTED|MGF_INPBASE64, MGF_PHPassSetup, 9, 38 },
	#endif
	{ "dynamic_18: md5($s.Y.$p.0xF7.$s)(Post.Office MD5)",  _Funcs_18,_Preloads_18,_Const_18,     MGF_SALTED|MGF_NOTSSE2Safe, MGF_POSetup, 32, 32 },
	{ "dynamic_19: Cisco PIX (MD5)",            _Funcs_19,_Preloads_19,_ConstDefault, MGF_INPBASE64_4x6, MGF_NO_FLAG, 0, 16, 16 },
	{ "dynamic_20: Cisco ASA (MD5 salted)",     _Funcs_20,_Preloads_20,_ConstDefault, MGF_INPBASE64_4x6|MGF_SALTED, MGF_NO_FLAG, 4, 12, 12 },
	{ "dynamic_21: HTTP Digest Access Auth",    _Funcs_21,_Preloads_21,_Const_21,     MGF_HDAA_SALT|MGF_USERNAME|MGF_FLD2|MGF_FLD3|MGF_FLD4|MGF_SALTED, MGF_NO_FLAG, 0, 26, 26 },
	{ "dynamic_22: md5(sha1($p))",              _Funcs_22,_Preloads_22,_ConstDefault, MGF_StartInX86Mode, MGF_KEYS_INPUT },
	{ "dynamic_23: sha1(md5($p))",              _Funcs_23,_Preloads_23,_ConstDefault, MGF_NO_FLAG, MGF_INPUT_20_BYTE|MGF_KEYS_INPUT, },
	{ "dynamic_24: sha1($p.$s)",                _Funcs_24,_Preloads_24,_ConstDefault, MGF_FLAT_BUFFERS|MGF_SALTED, MGF_NO_FLAG|MGF_INPUT_20_BYTE, -24 },
	{ "dynamic_25: sha1($s.$p)",                _Funcs_25,_Preloads_25,_ConstDefault, MGF_FLAT_BUFFERS|MGF_SALTED, MGF_NO_FLAG|MGF_INPUT_20_BYTE, -24 },
	{ "dynamic_26: sha1($p) raw-sha1",          _Funcs_26,_Preloads_26,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE, 0, 80 },

#if 0
  #if !defined (_OPENMP) && defined (MMX_COEF)
    #if ARCH_LITTLE_ENDIAN
	{ "dynamic_27: FreeBSD MD5",                _Funcs_27,_Preloads_27,_Const_27,     MGF_SALTED|MGF_INPBASE64a|MGF_StartInX86Mode, MGF_FreeBSDMD5Setup, -8, 15, 15 },
	{ "dynamic_28: Apache MD5",                 _Funcs_28,_Preloads_28,_Const_28,     MGF_SALTED|MGF_INPBASE64a|MGF_StartInX86Mode, MGF_FreeBSDMD5Setup, -8, 15, 15 },
    #endif
  #endif
#endif
	{ "dynamic_29: md5(unicode($p))",           _Funcs_29,_Preloads_29,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_30: md4($p) (raw-md4)",          _Funcs_30,_Preloads_30,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT },
	{ "dynamic_31: md4($s.$p)",                 _Funcs_31,_Preloads_31,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_32: md4($p.$s)",                 _Funcs_32,_Preloads_32,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_33: md4(unicode($p))",           _Funcs_33,_Preloads_33,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_34: md5(md4($p))",               _Funcs_34,_Preloads_34,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_35: sha1(uc($u).:.$p) (ManGOS)", _Funcs_35,_Preloads_35,_Const_35,     MGF_FLAT_BUFFERS|MGF_USERNAME_UPCASE, MGF_INPUT_20_BYTE, -23, 32 },
	{ "dynamic_36: sha1($u.:.$p) (ManGOS2)",    _Funcs_36,_Preloads_36,_Const_36,     MGF_FLAT_BUFFERS|MGF_USERNAME, MGF_INPUT_20_BYTE, -23, 32 },
	{ "dynamic_37: sha1(lc($u).$p) (SMF)",      _Funcs_37,_Preloads_37,_ConstDefault,MGF_FLAT_BUFFERS| MGF_USERNAME, MGF_INPUT_20_BYTE, -23, 32 },
	{ "dynamic_38: sha1($s.sha1($s.sha1($p))) (Wolt3BB)",  _Funcs_38,_Preloads_38,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_20_BYTE, -23, 40 },
	// Try to group sha224 here (from dyna-50 to dyna-59)
	{ "dynamic_50: sha224($p)",                  _Funcs_50,_Preloads_50,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE },
	{ "dynamic_51: sha224($s.$p)",               _Funcs_51,_Preloads_51,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_28_BYTE, -20 },
	{ "dynamic_52: sha224($p.$s)",               _Funcs_52,_Preloads_52,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_28_BYTE, -20 },
	{ "dynamic_53: sha224(sha224($p))",          _Funcs_53,_Preloads_53,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE },
	{ "dynamic_54: sha224(sha224_raw($p))",      _Funcs_54,_Preloads_54,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE },
	{ "dynamic_55: sha224(sha224($p).$s)",       _Funcs_55,_Preloads_55,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE, -20, 55, 80 },
	{ "dynamic_56: sha224($s.sha224($p))",       _Funcs_56,_Preloads_56,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE, -20, 55, 80 },
	{ "dynamic_57: sha224(sha224($s).sha224($p))",_Funcs_57,_Preloads_57,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE, -20 },
	{ "dynamic_58: sha224(sha224($p).sha224($p))",_Funcs_58,_Preloads_58,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_28_BYTE },
	// Try to group sha256 here (from dyna-60 to dyna-69)
	{ "dynamic_60: sha256($p)",                  _Funcs_60,_Preloads_60,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_61: sha256($s.$p)",               _Funcs_61,_Preloads_61,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_62: sha256($p.$s)",               _Funcs_62,_Preloads_62,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_63: sha256(sha256($p))",          _Funcs_63,_Preloads_63,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_64: sha256(sha256_raw($p))",      _Funcs_64,_Preloads_64,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_65: sha256(sha256($p).$s)",       _Funcs_65,_Preloads_65,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 55, 80 },
	{ "dynamic_66: sha256($s.sha256($p))",       _Funcs_66,_Preloads_66,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 55, 80 },
	{ "dynamic_67: sha256(sha256($s).sha256($p))",_Funcs_67,_Preloads_67,_ConstDefault, MGF_SALTED|MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20 },
	{ "dynamic_68: sha256(sha256($p).sha256($p))",_Funcs_68,_Preloads_68,_ConstDefault, MGF_FLAT_BUFFERS, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	// Try to group sha384 here (from dyna-70 to dyna-79)
	{ "dynamic_70: sha384($p)",                  _Funcs_70,_Preloads_70,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE },
	{ "dynamic_71: sha384($s.$p)",               _Funcs_71,_Preloads_71,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_48_BYTE, -20, 35 },
	{ "dynamic_72: sha384($p.$s)",               _Funcs_72,_Preloads_72,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_48_BYTE, -20, 35 },
	{ "dynamic_73: sha384(sha384($p))",          _Funcs_73,_Preloads_73,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE },
	{ "dynamic_74: sha384(sha384_raw($p))",      _Funcs_74,_Preloads_74,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE },
	{ "dynamic_75: sha384(sha384($p).$s)",       _Funcs_75,_Preloads_75,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE, -20, 35 },
	{ "dynamic_76: sha384($s.sha384($p))",       _Funcs_76,_Preloads_76,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE, -20, 35 },
	{ "dynamic_77: sha384(sha384($s).sha384($p))",_Funcs_77,_Preloads_77,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE, -20, 35 },
	{ "dynamic_78: sha384(sha384($p).sha384($p))",_Funcs_78,_Preloads_78,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_48_BYTE },
	// Try to group sha512 here (from dyna-80 to dyna-89)
	{ "dynamic_80: sha512($p)",                  _Funcs_80,_Preloads_80,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_81: sha512($s.$p)",               _Funcs_81,_Preloads_81,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_82: sha512($p.$s)",               _Funcs_82,_Preloads_82,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_83: sha512(sha512($p))",          _Funcs_83,_Preloads_83,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_84: sha512(sha512_raw($p))",      _Funcs_84,_Preloads_84,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_85: sha512(sha512($p).$s)",       _Funcs_85,_Preloads_85,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_86: sha512($s.sha512($p))",       _Funcs_86,_Preloads_86,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_87: sha512(sha512($s).sha512($p))",_Funcs_87,_Preloads_87,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_88: sha512(sha512($p).sha512($p))",_Funcs_88,_Preloads_88,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	// Try to group GOST here (from dyna-90 to dyna-99)
	{ "dynamic_90: GOST($p)",                    _Funcs_90,_Preloads_90,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_91: GOST($s.$p)",                 _Funcs_91,_Preloads_91,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_92: GOST($p.$s)",                 _Funcs_92,_Preloads_92,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_93: GOST(GOST($p))",              _Funcs_93,_Preloads_93,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_94: GOST(GOST_raw($p))",          _Funcs_94,_Preloads_94,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_95: GOST(GOST($p).$s)",           _Funcs_95,_Preloads_95,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_96: GOST($s.GOST($p))",           _Funcs_96,_Preloads_96,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_97: GOST(GOST($s).GOST($p))",     _Funcs_97,_Preloads_97,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_98: GOST(GOST($p).GOST($p))",     _Funcs_98,_Preloads_98,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	// Try to group WHIRLPOOL here (from dyna-100 to dyna-109)
	{ "dynamic_100: WHIRLPOOL($p)",              _Funcs_100,_Preloads_100,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_101: WHIRLPOOL($s.$p)",           _Funcs_101,_Preloads_101,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_102: WHIRLPOOL($p.$s)",           _Funcs_102,_Preloads_102,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_103: WHIRLPOOL(WHIRLPOOL($p))",   _Funcs_103,_Preloads_103,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_104: WHIRLPOOL(WHIRLPOOL_raw($p))",_Funcs_104,_Preloads_104,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	{ "dynamic_105: WHIRLPOOL(WHIRLPOOL($p).$s)",_Funcs_105,_Preloads_105,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_106: WHIRLPOOL($s.WHIRLPOOL($p))",_Funcs_106,_Preloads_106,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_107: WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p))",_Funcs_107,_Preloads_107,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE, -20, 35 },
	{ "dynamic_108: WHIRLPOOL(WHIRLPOOL($p).WHIRLPOOL($p))",_Funcs_108,_Preloads_108,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_64_BYTE },
	// Try to group Tiger here (from dyna-110 to dyna-119)
	{ "dynamic_110: Tiger($p)",                  _Funcs_110,_Preloads_110,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE },
	{ "dynamic_111: Tiger($s.$p)",               _Funcs_111,_Preloads_111,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_24_BYTE, -20, 35 },
	{ "dynamic_112: Tiger($p.$s)",               _Funcs_112,_Preloads_112,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_24_BYTE, -20, 35 },
	{ "dynamic_113: Tiger(Tiger($p))",           _Funcs_113,_Preloads_113,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE },
	{ "dynamic_114: Tiger(Tiger_raw($p))",       _Funcs_114,_Preloads_114,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE },
	{ "dynamic_115: Tiger(Tiger($p).$s)",        _Funcs_115,_Preloads_115,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE, -20, 35 },
	{ "dynamic_116: Tiger($s.Tiger($p))",        _Funcs_116,_Preloads_116,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE, -20, 35 },
	{ "dynamic_117: Tiger(Tiger($s).Tiger($p))", _Funcs_117,_Preloads_117,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE, -20, 35 },
	{ "dynamic_118: Tiger(Tiger($p).Tiger($p))", _Funcs_118,_Preloads_118,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_24_BYTE },
	// Try to group RIPEMD128 here (from dyna-120 to dyna-129)
	{ "dynamic_120: RIPEMD128($p)",                  _Funcs_120,_Preloads_120,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT },
	{ "dynamic_121: RIPEMD128($s.$p)",               _Funcs_121,_Preloads_121,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_NO_FLAG, -20, 35 },
	{ "dynamic_122: RIPEMD128($p.$s)",               _Funcs_122,_Preloads_122,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_NO_FLAG, -20, 35 },
	{ "dynamic_123: RIPEMD128(RIPEMD128($p))",           _Funcs_123,_Preloads_123,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_NO_FLAG },
	{ "dynamic_124: RIPEMD128(RIPEMD128_raw($p))",       _Funcs_124,_Preloads_124,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_NO_FLAG },
	{ "dynamic_125: RIPEMD128(RIPEMD128($p).$s)",        _Funcs_125,_Preloads_125,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_NO_FLAG, -20, 35 },
	{ "dynamic_126: RIPEMD128($s.RIPEMD128($p))",        _Funcs_126,_Preloads_126,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_NO_FLAG, -20, 35 },
	{ "dynamic_127: RIPEMD128(RIPEMD128($s).RIPEMD128($p))", _Funcs_127,_Preloads_127,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_NO_FLAG, -20, 35 },
	{ "dynamic_128: RIPEMD128(RIPEMD128($p).RIPEMD128($p))", _Funcs_128,_Preloads_128,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_NO_FLAG },
	// Try to group RIPEMD160 here (from dyna-130 to dyna-139)
	{ "dynamic_130: RIPEMD160($p)",                  _Funcs_130,_Preloads_130,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE },
	{ "dynamic_131: RIPEMD160($s.$p)",               _Funcs_131,_Preloads_131,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_20_BYTE, -20, 35 },
	{ "dynamic_132: RIPEMD160($p.$s)",               _Funcs_132,_Preloads_132,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_20_BYTE, -20, 35 },
	{ "dynamic_133: RIPEMD160(RIPEMD160($p))",           _Funcs_133,_Preloads_133,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE },
	{ "dynamic_134: RIPEMD160(RIPEMD160_raw($p))",       _Funcs_134,_Preloads_134,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE },
	{ "dynamic_135: RIPEMD160(RIPEMD160($p).$s)",        _Funcs_135,_Preloads_135,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE, -20, 35 },
	{ "dynamic_136: RIPEMD160($s.RIPEMD160($p))",        _Funcs_136,_Preloads_136,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE, -20, 35 },
	{ "dynamic_137: RIPEMD160(RIPEMD160($s).RIPEMD160($p))", _Funcs_137,_Preloads_137,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE, -20, 35 },
	{ "dynamic_138: RIPEMD160(RIPEMD160($p).RIPEMD160($p))", _Funcs_138,_Preloads_138,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_20_BYTE },
	// Try to group RIPEMD256 here (from dyna-140 to dyna-149)
	{ "dynamic_140: RIPEMD256($p)",                  _Funcs_140,_Preloads_140,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_141: RIPEMD256($s.$p)",               _Funcs_141,_Preloads_141,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_142: RIPEMD256($p.$s)",               _Funcs_142,_Preloads_142,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_143: RIPEMD256(RIPEMD256($p))",           _Funcs_143,_Preloads_143,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_144: RIPEMD256(RIPEMD256_raw($p))",       _Funcs_144,_Preloads_144,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	{ "dynamic_145: RIPEMD256(RIPEMD256($p).$s)",        _Funcs_145,_Preloads_145,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_146: RIPEMD256($s.RIPEMD256($p))",        _Funcs_146,_Preloads_146,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_147: RIPEMD256(RIPEMD256($s).RIPEMD256($p))", _Funcs_147,_Preloads_147,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE, -20, 35 },
	{ "dynamic_148: RIPEMD256(RIPEMD256($p).RIPEMD256($p))", _Funcs_148,_Preloads_148,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_32_BYTE },
	// Try to group RIPEMD320 here (from dyna-150 to dyna-159)
	{ "dynamic_150: RIPEMD320($p)",                  _Funcs_150,_Preloads_150,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE },
	{ "dynamic_151: RIPEMD320($s.$p)",               _Funcs_151,_Preloads_151,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_40_BYTE, -20, 35 },
	{ "dynamic_152: RIPEMD320($p.$s)",               _Funcs_152,_Preloads_152,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_INPUT_40_BYTE, -20, 35 },
	{ "dynamic_153: RIPEMD320(RIPEMD320($p))",           _Funcs_153,_Preloads_153,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE },
	{ "dynamic_154: RIPEMD320(RIPEMD320_raw($p))",       _Funcs_154,_Preloads_154,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE },
	{ "dynamic_155: RIPEMD320(RIPEMD320($p).$s)",        _Funcs_155,_Preloads_155,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE, -20, 35 },
	{ "dynamic_156: RIPEMD320($s.RIPEMD320($p))",        _Funcs_156,_Preloads_156,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE, -20, 35 },
	{ "dynamic_157: RIPEMD320(RIPEMD320($s).RIPEMD320($p))", _Funcs_157,_Preloads_157,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE, -20, 35 },
	{ "dynamic_158: RIPEMD320(RIPEMD320($p).RIPEMD320($p))", _Funcs_158,_Preloads_158,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_INPUT_40_BYTE },
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

// Certain functions are NOT compatible with OMP, because they require a
// global modification to the state.  Things like into and out of SSE/nonSSE
// are examples. Same code as in dynamic_IS_PARSER_VALID() in dynamic_parser.c
int IsOMP_Valid(int j) {
#ifdef _OPENMP
	int i;
	for (i = 0; Setups[j].pFuncs[i]; ++i) {
		if (Setups[j].pFuncs[i] == DynamicFunc__SSEtoX86_switch_input1) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__SSEtoX86_switch_input2) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__SSEtoX86_switch_output1) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__SSEtoX86_switch_output2) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__X86toSSE_switch_input1) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__X86toSSE_switch_input2) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__X86toSSE_switch_output1) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__X86toSSE_switch_output2) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__ToSSE) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__ToX86) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__base16_convert_locase) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__base16_convert_upcase) return 0;
#ifdef MMX_COEF
		if (Setups[j].pFuncs[i] == DynamicFunc__SHA1_crypt_input2_to_output1_FINAL) return 0;
		if (Setups[j].pFuncs[i] == DynamicFunc__SHA1_crypt_input1_to_output1_FINAL) return 0;
#endif
	}
#endif
	return 1;
}

// -1 is NOT valid  ( num > 5000 is 'hidden' values )
// 0 is valid, but NOT usable by this build (i.e. no SSE2)
// 1 is valid.
int dynamic_IS_VALID(int i)
{
	char Type[20];
	sprintf(Type, "dynamic_%d", i);
	if (i < 0 || i > 5000)
		return -1;
	if (i < 1000) {
		int j,len;
		len=strlen(Type);
		for (j = 0; j < ARRAY_COUNT(Setups); ++j) {
			if (!strncmp(Type, Setups[j].szFORMAT_NAME, len))
				return IsOMP_Valid(j);
		}
		return -1;
	}
	if (!dynamic_IS_PARSER_VALID(i))
		return 0;
	return 1;
}
