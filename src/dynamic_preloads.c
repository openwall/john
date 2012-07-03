/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright © 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic MD5 hashes cracker
 *
 * Preloaded types md5gen(0) to md5gen(100) are 'reserved' types.
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
	// MGF_KEYS_CRYPT_IN2
	DynamicFunc__clean_input,
	DynamicFunc__append_userid,
	DynamicFunc__append_from_last_output2_to_input1_as_base16,
	DynamicFunc__append_salt,
	DynamicFunc__crypt_md5,
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
	{ "dynamic_15: md5($u.md5($p).$s)",         _Funcs_15,_Preloads_15,_ConstDefault, MGF_SALTED|MGF_USERNAME|MGF_NOTSSE2Safe|MGF_FULL_CLEAN_REQUIRED, MGF_KEYS_CRYPT_IN2, -12, 55, 80 }, // 26 is 12+12+2 so 24+52 'fits
	{ "dynamic_16: md5(md5(md5($p).$s).$s2)",   _Funcs_16,_Preloads_16,_ConstDefault, MGF_SALTED|MGF_SALTED2|MGF_NOTSSE2Safe, MGF_KEYS_BASE16_IN1, -23, 55, 80 },
	{ "dynamic_17: phpass ($P$ or $H$)",        _Funcs_17,_Preloads_17,_ConstDefault, MGF_SALTED|MGF_INPBASE64, MGF_PHPassSetup, 9, 38 },
	{ "dynamic_18: md5($s.Y.$p.0xF7.$s)(Post.Office MD5)",  _Funcs_18,_Preloads_18,_Const_18,     MGF_SALTED|MGF_NOTSSE2Safe, MGF_POSetup, 32, 32 },
	{ "dynamic_19: Cisco PIX (MD5)",            _Funcs_19,_Preloads_19,_ConstDefault, MGF_INPBASE64_4x6, MGF_NO_FLAG, 0, 16, 16 },
	{ "dynamic_20: Cisco PIX (MD5 salted)",     _Funcs_20,_Preloads_20,_ConstDefault, MGF_INPBASE64_4x6|MGF_SALTED, MGF_NO_FLAG, 4, 12, 12 },
	{ "dynamic_21: HTTP Digest Access Auth",    _Funcs_21,_Preloads_21,_Const_21,     MGF_HDAA_SALT|MGF_FLD2|MGF_FLD3|MGF_SALTED, MGF_NO_FLAG, 0, 26, 26 },
	{ "dynamic_22: md5(sha1($p))",              _Funcs_22,_Preloads_22,_ConstDefault, MGF_StartInX86Mode, MGF_KEYS_INPUT_BE_SAFE },
	{ "dynamic_23: sha1(md5($p))",              _Funcs_23,_Preloads_23,_ConstDefault, MGF_SHA1_40_BYTE_FINISH, MGF_KEYS_INPUT, },
	{ "dynamic_24: sha1($p.$s)",                _Funcs_24,_Preloads_24,_ConstDefault, MGF_SALTED|MGF_SHA1_40_BYTE_FINISH, MGF_NO_FLAG, -24 },
	{ "dynamic_25: sha1($s.$p)",                _Funcs_25,_Preloads_25,_ConstDefault, MGF_SALTED|MGF_SHA1_40_BYTE_FINISH, MGF_NO_FLAG, -24 },
	{ "dynamic_26: sha1($p) raw-sha1",          _Funcs_26,_Preloads_26,_ConstDefault, MGF_SHA1_40_BYTE_FINISH, MGF_RAW_SHA1_INPUT },
#if ARCH_LITTLE_ENDIAN
	{ "dynamic_27: FreeBSD MD5",                _Funcs_27,_Preloads_27,_Const_27,     MGF_SALTED|MGF_INPBASE64a|MGF_StartInX86Mode, MGF_FreeBSDMD5Setup, -8, 15, 32 },
	{ "dynamic_28: Apache MD5",                 _Funcs_28,_Preloads_28,_Const_28,     MGF_SALTED|MGF_INPBASE64a|MGF_StartInX86Mode, MGF_FreeBSDMD5Setup, -8, 15, 32 },
#endif
	{ "dynamic_29: md5(unicode($p))",           _Funcs_29,_Preloads_29,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_30: md4($p) (raw-md4)",          _Funcs_30,_Preloads_30,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT },
	{ "dynamic_31: md4($s.$p)",                 _Funcs_31,_Preloads_31,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_32: md4($p.$s)",                 _Funcs_32,_Preloads_32,_ConstDefault, MGF_SALTED, MGF_NO_FLAG, -24 },
	{ "dynamic_33: md4(unicode($p))",           _Funcs_33,_Preloads_33,_ConstDefault, MGF_UTF8, MGF_NO_FLAG, 0, 27, 40 }, // if we are in utf8 mode, we triple this in the init() call
	{ "dynamic_34: md5(md4($p))",               _Funcs_34,_Preloads_34,_ConstDefault, MGF_NO_FLAG, MGF_KEYS_INPUT|MGF_SET_INP2LEN32 },
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

// -1 is NOT valid
// 0 is valid, but NOT usable by this build (i.e. no SSE2)
// 1 is valid.
int dynamic_IS_VALID(int i)
{
	char Type[20];
	sprintf(Type, "dynamic_%d", i);
	if (i < 0 || (i > 100 && i < 1000) || i > 2000)
		return -1;
	if (i < 1000 && i >= ARRAY_COUNT(Setups)) {
		int j,len;
		len=strlen(Type);
		for (j = 0; j < ARRAY_COUNT(Setups); ++j) {
			if (!strncmp(Type, Setups[j].szFORMAT_NAME, len))
				return 1;
		}
		return -1;
	}
	if (i >= 1000) {
		if (!dynamic_IS_PARSER_VALID(i))
			return 0;
		return 1;
	}

	return 1;
}

