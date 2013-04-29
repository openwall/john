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
 * Whirlpool only if OPENSSL_VERSION_NUMBER >= 0x10000000
 */

#include <string.h>

#include "arch.h"
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
   // DEPRICATED  //dynamic_7 --> md5(md5($p).$s) vBulletin  (fixed 3 byte salt, colon not valid as field sep, since all chars from 0x20 to 0x7E are in the salt)
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
//dynamic_27 --> FreeBSD MD5
//dynamic_28 --> Apache MD5
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
	// Try to group sha256 here (from dyna-60 to dyna-69)
//dynamic_60 -->sha256($p)
//dynamic_61 -->sha256($s.$p)
//dynamic_62 -->sha256($p.$s)
	// Try to group sha384 here (from dyna-70 to dyna-79)
//dynamic_70 -->sha384($p)
//dynamic_71 -->sha384($s.$p)
//dynamic_72 -->sha384($p.$s)
	// Try to group sha512 here (from dyna-80 to dyna-89)
//dynamic_80 -->sha512($p)
//dynamic_81 -->sha512($s.$p)
//dynamic_82 -->sha512($p.$s)
	// Try to group GOST here (from dyna-90 to dyna-100)
//dynamic_90 -->GOST($p)
//dynamic_91 -->GOST($s.$p)
//dynamic_92 -->GOST($p.$s)
	// Try to group WHIRLPOOL here (from dyna-100 to dyna-110)
//dynamic_100 -->WHIRLPOOL($p)
//dynamic_101 -->WHIRLPOOL($s.$p)
//dynamic_102 -->WHIRLPOOL($p.$s)

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
	{NULL}
};

//dynamic_12 --> md5(md5($s).md5($p))
static DYNAMIC_primitive_funcp _Funcs_12[] =
{
	//MGF_KEYS_BASE16_X86_IN1_Offset32
	//MGF_SALT_AS_HEX
	DynamicFunc__ToX86,
	DynamicFunc__overwrite_salt_to_input1_no_size_fix,
	DynamicFunc__set_input_len_64,
	DynamicFunc__crypt_md5,
	NULL
};
static struct fmt_tests _Preloads_12[] =
{
	{"$dynamic_12$fbbd9532460f2d03fa8af9e75c41eefc$aaaSXB","test1"},
	{"$dynamic_12$b80eef24d1d01b61b3beff38559f9d26$123456","thatsworking"},
	{"$dynamic_12$1e5489bdca008aeed6e390ee87ce9b92$5555hh","test3"},
	{NULL}
};

//dynamic_13 --> md5(md5($p).md5($s))
static DYNAMIC_primitive_funcp _Funcs_13[] =
{
	//MGF_KEYS_BASE16_X86_IN1
	//MGF_SALT_AS_HEX
	DynamicFunc__ToX86,
	DynamicFunc__set_input_len_32,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
	NULL

};
static struct fmt_tests _Preloads_13[] =
{
	{"$dynamic_13$c6b69bec81d9ff5d0560d8f469a8efd5$aaaSXB","test1"},
	{"$dynamic_13$7abf788b3abbfc8719d900af96a3763a$123456","thatsworking"},
	{"$dynamic_13$1c55e15102ed17eabe5bf11271c7fcae$5555hh","test3"},
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
	//MGF_KEYS_INPUT_BE_SAFE
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
	{NULL}
};

//dynamic_23 --> sha1(md5($p))
static DYNAMIC_primitive_funcp _Funcs_23[] =
{
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_KEYS_INPUT
	DynamicFunc__crypt_md5,
	DynamicFunc__SSEtoX86_switch_output1,
	DynamicFunc__clean_input2,
	DynamicFunc__append_from_last_output_to_input2_as_base16,
	DynamicFunc__SHA1_crypt_input2_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_23[] =
{
	{"$dynamic_23$81d84525eb1499d518cf3cb3efcbe1d11c4ccf25","test1"},
	{"$dynamic_23$6cd62e1767b65eec58d687de6d9c08a828018254","thatsworking"},
	{"$dynamic_23$7d653cf00d747a9fbab213b6c2b335cfe8199ff3","test3"},
	{NULL}
};

//dynamic_24 --> sha1($p.$s)
static DYNAMIC_primitive_funcp _Funcs_24[] =
{
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_SALTED
	DynamicFunc__clean_input,
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
	{NULL}
};

//dynamic_25 --> sha1($s.$p)
static DYNAMIC_primitive_funcp _Funcs_25[] =
{
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_SALTED
	DynamicFunc__clean_input,
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
	{NULL}
};

// dynamic_26  raw-sha1
static DYNAMIC_primitive_funcp _Funcs_26[] =
{
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_RAW_SHA1_INPUT
	DynamicFunc__SHA1_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_26[] =
{
	{"$dynamic_26$b444ac06613fc8d63795be9ad0beaf55011936ac","test1"},
	{"$dynamic_26$1068db2941b46d12f790df99d72fe8c2eb6d3aaf","thatsworking"},
	{"$dynamic_26$3ebfa301dc59196f18593c45e519287a23297589","test3"},
	{NULL}
};

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
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_SALTED ???
	//MGF_USERNAME_UPCASE
	DynamicFunc__clean_input,
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
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_USERNAME
	DynamicFunc__clean_input,
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
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_USERNAME
	DynamicFunc__clean_input,
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
	{NULL}
};

//$ ./pass_gen.pl  'dynamic=num=38,format=sha1($s.sha1($s.sha1($p))),salt=ashex,saltlen=32'
//dynamic_38 --> sha1($salt.sha1($salt.sha1($pass)))
static DYNAMIC_primitive_funcp _Funcs_38[] =
{
	//MGF_SHA1_40_BYTE_FINISH
	//MGF_SALTED
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__clean_input2,
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
	{NULL}
};


//	dynamic_50: sha224($p)
static DYNAMIC_primitive_funcp _Funcs_50[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__SHA224_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_50[] =
{
	{"$dynamic_50$aff3c83c40e2f1ae099a0166e1f27580525a9de6acd995f21717e984","test1"},
	{"$dynamic_50$974607e8cc64c39c43ce7887ddf7cc2795d8bb3103eadb46a594cc3d","thatsworking"},
	{"$dynamic_50$d2d5c076b2435565f66649edd604dd5987163e8a8240953144ec652f","test3"},
	{NULL}
};

//	dynamic_51: sha224($s.$p)
static DYNAMIC_primitive_funcp _Funcs_51[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_SALTED
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_52: sha224($s.$p)
static DYNAMIC_primitive_funcp _Funcs_52[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_SALTED
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_53: sha224(sha224($p))
static DYNAMIC_primitive_funcp _Funcs_53[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_54: sha224(sha224_raw($p))
static DYNAMIC_primitive_funcp _Funcs_54[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_55: sha224(sha224($p).$s)
static DYNAMIC_primitive_funcp _Funcs_55[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_56: sha224($s.sha224($p))
static DYNAMIC_primitive_funcp _Funcs_56[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_57: sha224(sha224($s).sha224($p))
static DYNAMIC_primitive_funcp _Funcs_57[] =
{
	//MGF_SHA224_56_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_60: sha256($p)
static DYNAMIC_primitive_funcp _Funcs_60[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__SHA256_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_60[] =
{
	{"$dynamic_60$1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014","test1"},
	{"$dynamic_60$d150eb0383c8ef7478248d7e6cf18db333e8753d05e15a8a83714b7cf63922b3","thatsworking"},
	{"$dynamic_60$fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13","test3"},
	{NULL}
};

//	dynamic_61: sha256($s.$p)
static DYNAMIC_primitive_funcp _Funcs_61[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_SALTED
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_62: sha256($s.$p)
static DYNAMIC_primitive_funcp _Funcs_62[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_SALTED
	//MGF_NOTSSE2Safe
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
	{NULL}
};
//	dynamic_63: SHA256(SHA256($p))
static DYNAMIC_primitive_funcp _Funcs_63[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_64: SHA256(SHA256_raw($p))
static DYNAMIC_primitive_funcp _Funcs_64[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_65: SHA256(SHA256($p).$s)
static DYNAMIC_primitive_funcp _Funcs_65[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_66: SHA256($s.SHA256($p))
static DYNAMIC_primitive_funcp _Funcs_66[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};

//	dynamic_67: SHA256(SHA256($s).SHA256($p))
static DYNAMIC_primitive_funcp _Funcs_67[] =
{
	//MGF_SHA256_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
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
	{NULL}
};


//	dynamic_70: sha384($p)
static DYNAMIC_primitive_funcp _Funcs_70[] =
{
	//MGF_SHA384_96_BYTE_FINISH
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__SHA384_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_70[] =
{
	{"$dynamic_70$44accf4a6221d01de386da6d2c48b0fae47930c80d2371cd669bff5235c6c1a5ce47f863a1379829f8602822f96410c2","test1"},
	{"$dynamic_70$76f4d70f118eca6a573e20bfc9b53d90931621c1999b0f2a472d45d691c827298c7c2bf27a5a60aa6ea813a5112905d3","thatsworking"},
	{"$dynamic_70$7043bf4687defcf3f7caeb0adab933e7cc1cc2e954fea0e782099b93b43051f948e3300d3e03d126a13abf2acf2547a2","test3"},
	{NULL}
};

//	dynamic_71: sha384($s.$p)
static DYNAMIC_primitive_funcp _Funcs_71[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};

//	dynamic_72: sha384($s.$p)
static DYNAMIC_primitive_funcp _Funcs_72[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};
//	dynamic_73: SHA384(SHA384($p))
static DYNAMIC_primitive_funcp _Funcs_73[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};

//	dynamic_74: SHA384(SHA384_raw($p))
static DYNAMIC_primitive_funcp _Funcs_74[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};

//	dynamic_75: SHA384(SHA384($p).$s)
static DYNAMIC_primitive_funcp _Funcs_75[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};

//	dynamic_76: SHA384($s.SHA384($p))
static DYNAMIC_primitive_funcp _Funcs_76[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};

//	dynamic_77: SHA384(SHA384($s).SHA384($p))
static DYNAMIC_primitive_funcp _Funcs_77[] =
{
	//MGF_SHA384_96_BYTE_FINISH
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
	{NULL}
};


//	dynamic_80: sha512($p)
static DYNAMIC_primitive_funcp _Funcs_80[] =
{
	//MGF_SHA512_128_BYTE_FINISH
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__SHA512_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_80[] =
{
	{"$dynamic_80$b16ed7d24b3ecbd4164dcdad374e08c0ab7518aa07f9d3683f34c2b3c67a15830268cb4a56c1ff6f54c8e54a795f5b87c08668b51f82d0093f7baee7d2981181","test1"},
	{"$dynamic_80$05c1a41bc43fc4cebfeadbf3eab9b159ccb32887af0d87bfd4b71a51775444d0b4b332a50c4ca9bb9c6da6d5e22cc12e94bd095d6de60be563c3fd3077406d1a","thatsworking"},
	{"$dynamic_80$cb872de2b8d2509c54344435ce9cb43b4faa27f97d486ff4de35af03e4919fb4ec53267caf8def06ef177d69fe0abab3c12fbdc2f267d895fd07c36a62bff4bf","test3"},
	{NULL}
};

//	dynamic_81: sha512($s.$p)
static DYNAMIC_primitive_funcp _Funcs_81[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_82: sha512($s.$p)
static DYNAMIC_primitive_funcp _Funcs_82[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};
//	dynamic_83: SHA512(SHA512($p))
static DYNAMIC_primitive_funcp _Funcs_83[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_84: SHA512(SHA512_raw($p))
static DYNAMIC_primitive_funcp _Funcs_84[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_85: SHA512(SHA512($p).$s)
static DYNAMIC_primitive_funcp _Funcs_85[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_86: SHA512($s.SHA512($p))
static DYNAMIC_primitive_funcp _Funcs_86[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_87: SHA512(SHA512($s).SHA512($p))
static DYNAMIC_primitive_funcp _Funcs_87[] =
{
	//MGF_SHA512_128_BYTE_FINISH
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
	{NULL}
};


//	dynamic_90: GOST($p)
static DYNAMIC_primitive_funcp _Funcs_90[] =
{
	//MGF_GOST_64_BYTE_FINISH
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__GOST_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_90[] =
{
	{"$dynamic_90$3b024be97641061bdd5409b4866c26c5a965e6fcf125215d2f9857cea81c5b7c", "test1"},
	{"$dynamic_90$d4949e4ad914089d7bbb4711b08343ab7a8658599611a4ee5a91999b5c3e0388", "thatsworking"},
	{"$dynamic_90$55719211936152fbe2e1f6aa796fa866d839356e5ba9bc206ed39ab0bd07d892", "test3"},
	{NULL}
};

//	dynamic_91: GOST($s.$p)
static DYNAMIC_primitive_funcp _Funcs_91[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};

//	dynamic_92: GOST($s.$p)
static DYNAMIC_primitive_funcp _Funcs_92[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};
//	dynamic_93: GOST(GOST($p))
static DYNAMIC_primitive_funcp _Funcs_93[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};

//	dynamic_94: GOST(GOST_raw($p))
static DYNAMIC_primitive_funcp _Funcs_94[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};

//	dynamic_95: GOST(GOST($p).$s)
static DYNAMIC_primitive_funcp _Funcs_95[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};

//	dynamic_96: GOST($s.GOST($p))
static DYNAMIC_primitive_funcp _Funcs_96[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};

//	dynamic_97: GOST(GOST($s).GOST($p))
static DYNAMIC_primitive_funcp _Funcs_97[] =
{
	//MGF_GOST_64_BYTE_FINISH
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
	{NULL}
};


#if OPENSSL_VERSION_NUMBER >= 0x10000000
//	dynamic_100: WHIRLPOOL($p)
static DYNAMIC_primitive_funcp _Funcs_100[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
	//MGF_NOTSSE2Safe
	DynamicFunc__clean_input,
	DynamicFunc__append_keys,
	DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL,
	NULL
};
static struct fmt_tests _Preloads_100[] =
{
	{"$dynamic_100$7a3a0ec40f4b2be2bb40049a5fe0a83349b12d8ae6e9896ee6e490d5276bd150199e26aabb76d9af7a659f16070dc959e0393ef44529cad13f681129d8578df5", "test1"},
	{"$dynamic_100$296f0c87fe042a8f664980b2f6e2c59234683ec593175a33db662b4cdd1376ac239bef3f28e9fffd8d3ab4b049d87a8d224c7f33b92d4028242849d2e1baf41c", "thatsworking"},
	{"$dynamic_100$7d925e8503a922cbbc5d4d17eb232c790262ee0b06c33dc07f200c952ade2b2ddf8eeea7deec242282a700e6930d154f30c8b4096efe2633b860b48286703488", "test3"},
	{NULL}
};

//	dynamic_101: WHIRLPOOL($s.$p)
static DYNAMIC_primitive_funcp _Funcs_101[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_102: WHIRLPOOL($s.$p)
static DYNAMIC_primitive_funcp _Funcs_102[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};
//	dynamic_103: WHIRLPOOL(WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_103[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_104: WHIRLPOOL(WHIRLPOOL_raw($p))
static DYNAMIC_primitive_funcp _Funcs_104[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_105: WHIRLPOOL(WHIRLPOOL($p).$s)
static DYNAMIC_primitive_funcp _Funcs_105[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_106: WHIRLPOOL($s.WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_106[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};

//	dynamic_107: WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p))
static DYNAMIC_primitive_funcp _Funcs_107[] =
{
	//MGF_WHIRLPOOL_128_BYTE_FINISH
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
	{NULL}
};
#endif

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
	{ "dynamic_12: md5(md5($s).md5($p)) (IPB)", _Funcs_12,_Preloads_12,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX, MGF_KEYS_BASE16_X86_IN1_Offset32, -32, 55, 80 },
	{ "dynamic_13: md5(md5($p).md5($s))",       _Funcs_13,_Preloads_13,_ConstDefault, MGF_SALTED|MGF_SALT_AS_HEX, MGF_KEYS_BASE16_X86_IN1, -32, 55, 80 },
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
	{ "dynamic_22: md5(sha1($p))",              _Funcs_22,_Preloads_22,_ConstDefault, MGF_StartInX86Mode, MGF_KEYS_INPUT_BE_SAFE },
	{ "dynamic_23: sha1(md5($p))",              _Funcs_23,_Preloads_23,_ConstDefault, MGF_NO_FLAG, MGF_SHA1_40_BYTE_FINISH|MGF_KEYS_INPUT, },
	{ "dynamic_24: sha1($p.$s)",                _Funcs_24,_Preloads_24,_ConstDefault, MGF_SALTED, MGF_NO_FLAG|MGF_SHA1_40_BYTE_FINISH, -24 },
	{ "dynamic_25: sha1($s.$p)",                _Funcs_25,_Preloads_25,_ConstDefault, MGF_SALTED, MGF_NO_FLAG|MGF_SHA1_40_BYTE_FINISH, -24 },
	{ "dynamic_26: sha1($p) raw-sha1",          _Funcs_26,_Preloads_26,_ConstDefault, MGF_NO_FLAG, MGF_RAW_SHA1_INPUT|MGF_SHA1_40_BYTE_FINISH },
#if ARCH_LITTLE_ENDIAN
	{ "dynamic_27: FreeBSD MD5",                _Funcs_27,_Preloads_27,_Const_27,     MGF_SALTED|MGF_INPBASE64a|MGF_StartInX86Mode, MGF_FreeBSDMD5Setup, -8, 15, 15 },
	{ "dynamic_28: Apache MD5",                 _Funcs_28,_Preloads_28,_Const_28,     MGF_SALTED|MGF_INPBASE64a|MGF_StartInX86Mode, MGF_FreeBSDMD5Setup, -8, 15, 15 },
#endif
	{ "dynamic_29: md5(unicode($p))",           _Funcs_29,_Preloads_29,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_30: md4($p) (raw-md4)",          _Funcs_30,_Preloads_30,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT },
	{ "dynamic_31: md4($s.$p)",                 _Funcs_31,_Preloads_31,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_32: md4($p.$s)",                 _Funcs_32,_Preloads_32,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_33: md4(unicode($p))",           _Funcs_33,_Preloads_33,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_34: md5(md4($p))",               _Funcs_34,_Preloads_34,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
	{ "dynamic_35: sha1(uc($u).:.$p) (ManGOS)", _Funcs_35,_Preloads_35,_Const_35,     MGF_USERNAME_UPCASE, MGF_SHA1_40_BYTE_FINISH, -23, 32 },
	{ "dynamic_36: sha1($u.:.$p) (ManGOS2)",    _Funcs_36,_Preloads_36,_Const_36,     MGF_USERNAME, MGF_SHA1_40_BYTE_FINISH, -23, 32 },
	{ "dynamic_37: sha1(lc($u).$p) (SMF)",      _Funcs_37,_Preloads_37,_ConstDefault, MGF_USERNAME, MGF_SHA1_40_BYTE_FINISH, -23, 32 },
	{ "dynamic_38: sha1($s.sha1($s.sha1($p))) (Wolt3BB)",  _Funcs_38,_Preloads_38,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA1_40_BYTE_FINISH|MGF_NO_FLAG, -23, 40 },
	// Try to group sha224 here (from dyna-50 to dyna-59)
	{ "dynamic_50: sha224($p)",                  _Funcs_50,_Preloads_50,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA224_56_BYTE_FINISH },
	{ "dynamic_51: sha224($s.$p)",               _Funcs_51,_Preloads_51,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA224_56_BYTE_FINISH, -20, 35 },
	{ "dynamic_52: sha224($p.$s)",               _Funcs_52,_Preloads_52,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA224_56_BYTE_FINISH, -20, 35 },
	{ "dynamic_53: sha224(sha224($p))",          _Funcs_53,_Preloads_53,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA224_56_BYTE_FINISH, },
	{ "dynamic_54: sha224(sha224_raw($p))",      _Funcs_54,_Preloads_54,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA224_56_BYTE_FINISH, },
	{ "dynamic_55: sha224(sha224($p).$s)",       _Funcs_55,_Preloads_55,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA224_56_BYTE_FINISH, -20, 35 },
	{ "dynamic_56: sha224($s.sha224($p))",       _Funcs_56,_Preloads_56,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA224_56_BYTE_FINISH, -20, 35 },
	{ "dynamic_57: sha224(sha224($s).sha224($p))",_Funcs_57,_Preloads_57,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA224_56_BYTE_FINISH, -20, 35 },
	// Try to group sha256 here (from dyna-60 to dyna-69)
	{ "dynamic_60: sha256($p)",                  _Funcs_60,_Preloads_60,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA256_64_BYTE_FINISH },
	{ "dynamic_61: sha256($s.$p)",               _Funcs_61,_Preloads_61,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_62: sha256($p.$s)",               _Funcs_62,_Preloads_62,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_63: sha256(sha256($p))",          _Funcs_63,_Preloads_63,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA256_64_BYTE_FINISH, },
	{ "dynamic_64: sha256(sha256_raw($p))",      _Funcs_64,_Preloads_64,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA256_64_BYTE_FINISH, },
	{ "dynamic_65: sha256(sha256($p).$s)",       _Funcs_65,_Preloads_65,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_66: sha256($s.sha256($p))",       _Funcs_66,_Preloads_66,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_67: sha256(sha256($s).sha256($p))",_Funcs_67,_Preloads_67,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	// Try to group sha384 here (from dyna-70 to dyna-79)
	{ "dynamic_70: sha384($p)",                  _Funcs_70,_Preloads_70,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA384_96_BYTE_FINISH },
	{ "dynamic_71: sha384($s.$p)",               _Funcs_71,_Preloads_71,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	{ "dynamic_72: sha384($p.$s)",               _Funcs_72,_Preloads_72,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	{ "dynamic_73: sha384(sha384($p))",          _Funcs_73,_Preloads_73,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA384_96_BYTE_FINISH, },
	{ "dynamic_74: sha384(sha384_raw($p))",      _Funcs_74,_Preloads_74,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA384_96_BYTE_FINISH, },
	{ "dynamic_75: sha384(sha384($p).$s)",       _Funcs_75,_Preloads_75,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	{ "dynamic_76: sha384($s.sha384($p))",       _Funcs_76,_Preloads_76,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	{ "dynamic_77: sha384(sha384($s).sha384($p))",_Funcs_77,_Preloads_77,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	// Try to group sha512 here (from dyna-80 to dyna-89)
	{ "dynamic_80: sha512($p)",                  _Funcs_80,_Preloads_80,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA512_128_BYTE_FINISH },
	{ "dynamic_81: sha512($s.$p)",               _Funcs_81,_Preloads_81,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_82: sha512($p.$s)",               _Funcs_82,_Preloads_82,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_83: sha512(sha512($p))",          _Funcs_83,_Preloads_83,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA512_128_BYTE_FINISH, },
	{ "dynamic_84: sha512(sha512_raw($p))",      _Funcs_84,_Preloads_84,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA512_128_BYTE_FINISH, },
	{ "dynamic_85: sha512(sha512($p).$s)",       _Funcs_85,_Preloads_85,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_86: sha512($s.sha512($p))",       _Funcs_86,_Preloads_86,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_87: sha512(sha512($s).sha512($p))",_Funcs_87,_Preloads_87,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	// Try to group GOST here (from dyna-90 to dyna-100)
	{ "dynamic_90: GOST($p)",                    _Funcs_90,_Preloads_90,_ConstDefault, MGF_NOTSSE2Safe, MGF_GOST_64_BYTE_FINISH },
	{ "dynamic_91: GOST($s.$p)",                 _Funcs_91,_Preloads_91,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_GOST_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_92: GOST($p.$s)",                 _Funcs_92,_Preloads_92,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_GOST_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_93: GOST(GOST($p))",              _Funcs_93,_Preloads_93,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_GOST_64_BYTE_FINISH, },
	{ "dynamic_94: GOST(GOST_raw($p))",          _Funcs_94,_Preloads_94,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_GOST_64_BYTE_FINISH, },
	{ "dynamic_95: GOST(GOST($p).$s)",           _Funcs_95,_Preloads_95,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_GOST_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_96: GOST($s.GOST($p))",           _Funcs_96,_Preloads_96,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_GOST_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_97: GOST(GOST($s).GOST($p))",     _Funcs_97,_Preloads_97,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_GOST_64_BYTE_FINISH, -20, 35 },
#if OPENSSL_VERSION_NUMBER >= 0x10000000
	// Try to group WHIRLPOOL here (from dyna-100 to dyna-110)
	{ "dynamic_100: WHIRLPOOL($p)",              _Funcs_100,_Preloads_100,_ConstDefault, MGF_NOTSSE2Safe, MGF_WHIRLPOOL_128_BYTE_FINISH },
	{ "dynamic_101: WHIRLPOOL($s.$p)",           _Funcs_101,_Preloads_101,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_WHIRLPOOL_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_102: WHIRLPOOL($p.$s)",           _Funcs_102,_Preloads_102,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_WHIRLPOOL_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_103: WHIRLPOOL(WHIRLPOOL($p))",   _Funcs_103,_Preloads_103,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_WHIRLPOOL_128_BYTE_FINISH, },
	{ "dynamic_104: WHIRLPOOL(WHIRLPOOL_raw($p))",_Funcs_104,_Preloads_104,_ConstDefault, MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_WHIRLPOOL_128_BYTE_FINISH, },
	{ "dynamic_105: WHIRLPOOL(WHIRLPOOL($p).$s)",_Funcs_105,_Preloads_105,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_WHIRLPOOL_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_106: WHIRLPOOL($s.WHIRLPOOL($p))",_Funcs_106,_Preloads_106,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_WHIRLPOOL_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_107: WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p))",_Funcs_107,_Preloads_107,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_KEYS_INPUT|MGF_WHIRLPOOL_128_BYTE_FINISH, -20, 35 },
#endif
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
				return 1;
		}
		return -1;
	}
	if (!dynamic_IS_PARSER_VALID(i))
		return 0;
	return 1;
}
