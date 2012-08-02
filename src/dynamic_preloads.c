/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009-2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright © 2009-2012 Jim Fougeron
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
 *
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
//dynamic_20 --> Cisco PIX (MD5 salted)
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
	DynamicFunc__clean_input2_kwik,
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
	DynamicFunc__clean_input2_kwik,
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


//dynamic_20$ --> Salted Cisco PIX hash
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
	DynamicFunc__SHA1_crypt_input1_append_input2_base16,
	DynamicFunc__clean_input_kwik,
	DynamicFunc__append_salt,
	DynamicFunc__SHA1_crypt_input2_append_input1_base16,
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


//	{ "dynamic_50: sha224($p)"
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

//	{ "dynamic_51: sha224($s.$p)"
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

//	{ "dynamic_52: sha224($s.$p)"
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

//	{ "dynamic_60: sha256($p)"
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

//	{ "dynamic_61: sha256($s.$p)"
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

//	{ "dynamic_62: sha256($s.$p)"
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


//	{ "dynamic_70: sha384($p)"
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

//	{ "dynamic_71: sha384($s.$p)"
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

//	{ "dynamic_72: sha384($s.$p)"
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



//	{ "dynamic_80: sha512($p)"
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

//	{ "dynamic_81: sha512($s.$p)"
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

//	{ "dynamic_82: sha512($s.$p)"
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


//	{ "dynamic_90: GOST($p)"
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

//	{ "dynamic_91: GOST($s.$p)"
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

//	{ "dynamic_92: GOST($s.$p)"
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

// Here is a 'dummy' constant array. This will be 'linked' to any dynamic format that does not have any constants.
static DYNAMIC_Constants _ConstDefault[] =
{
	{0, NULL}
};

// Here are the 'prebuilt' dynamic objects, ready to be 'loaded'
static DYNAMIC_Setup Setups[] =
{
	{ "dynamic_0: md5($p) (raw-md5)",           _Funcs_0, _Preloads_0, _ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT },
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
	{ "dynamic_17: phpass ($P$ or $H$)",        _Funcs_17,_Preloads_17,_ConstDefault, MGF_SALTED|MGF_INPBASE64, MGF_PHPassSetup, 9, 38 },
	{ "dynamic_18: md5($s.Y.$p.0xF7.$s)(Post.Office MD5)",  _Funcs_18,_Preloads_18,_Const_18,     MGF_SALTED|MGF_NOTSSE2Safe, MGF_POSetup, 32, 32 },
	{ "dynamic_19: Cisco PIX (MD5)",            _Funcs_19,_Preloads_19,_ConstDefault, MGF_INPBASE64_4x6, MGF_NO_FLAG, 0, 16, 16 },
	{ "dynamic_20: Cisco PIX (MD5 salted)",     _Funcs_20,_Preloads_20,_ConstDefault, MGF_INPBASE64_4x6|MGF_SALTED, MGF_NO_FLAG, 4, 12, 12 },
	{ "dynamic_21: HTTP Digest Access Auth",    _Funcs_21,_Preloads_21,_Const_21,     MGF_HDAA_SALT|MGF_FLD2|MGF_FLD3|MGF_SALTED, MGF_NO_FLAG, 0, 26, 26 },
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
	// Try to group sha256 here (from dyna-60 to dyna-69)
	{ "dynamic_60: sha256($p)",                  _Funcs_60,_Preloads_60,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA256_64_BYTE_FINISH },
	{ "dynamic_61: sha256($s.$p)",               _Funcs_61,_Preloads_61,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_62: sha256($p.$s)",               _Funcs_62,_Preloads_62,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA256_64_BYTE_FINISH, -20, 35 },
	// Try to group sha384 here (from dyna-70 to dyna-79)
	{ "dynamic_70: sha384($p)",                  _Funcs_70,_Preloads_70,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA384_96_BYTE_FINISH },
	{ "dynamic_71: sha384($s.$p)",               _Funcs_71,_Preloads_71,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	{ "dynamic_72: sha384($p.$s)",               _Funcs_72,_Preloads_72,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA384_96_BYTE_FINISH, -20, 35 },
	// Try to group sha512 here (from dyna-80 to dyna-89)
	{ "dynamic_80: sha512($p)",                  _Funcs_80,_Preloads_80,_ConstDefault, MGF_NOTSSE2Safe, MGF_SHA512_128_BYTE_FINISH },
	{ "dynamic_81: sha512($s.$p)",               _Funcs_81,_Preloads_81,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	{ "dynamic_82: sha512($p.$s)",               _Funcs_82,_Preloads_82,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_SHA512_128_BYTE_FINISH, -20, 35 },
	// Try to group GOST here (from dyna-90 to dyna-100)
	{ "dynamic_90: GOST($p)",                    _Funcs_90,_Preloads_90,_ConstDefault, MGF_NOTSSE2Safe, MGF_GOST_64_BYTE_FINISH },
	{ "dynamic_91: GOST($s.$p)",                 _Funcs_91,_Preloads_91,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_GOST_64_BYTE_FINISH, -20, 35 },
	{ "dynamic_92: GOST($p.$s)",                 _Funcs_92,_Preloads_92,_ConstDefault, MGF_SALTED|MGF_NOTSSE2Safe, MGF_GOST_64_BYTE_FINISH, -20, 35 },
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
