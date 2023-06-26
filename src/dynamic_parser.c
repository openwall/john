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
 * This file implements code that allows 'dynamic' building of
 * generic MD5 functions.  john.conf is used to store the 'script'
 * and supporting data (like the expression, or 'flags' needed to
 * make the format work).
 *
 * To make this work, you simply add a "section" to the dynamic.conf,
 * or better yet, to the john.local.conf file of this format:
 *
 *  [List.Generic:dynamic_NUM   ( [List.Generic:md5_gen(NUM)] deprecated but 'works')
 *
 * Num has to be replaced with a number, greater than 999, since
 * dynamic_0 to dynamic_999 are reserved for 'built-in' and any
 * user defined dynamic_# functions need to start at 1000 or more.
 *
 * Then under the new section, add the script.  There are 2 required
 * data types, and 2 optional.  The required are a list of Func=
 * and a list of Test=    Then there is an optional Expression=
 * and an optional list of Flag= items.
 *
 * Here is an example, showing processing for md5(md5(md5(md5($p))))
 *
 * [List.Generic:dynamic_1001]
 * Expression=md5(md5(md5(md5($p))))
 * Flag=MGF_KEYS_INPUT
 * Func=DynamicFunc__crypt_md5
 * Func=DynamicFunc__clean_input2
 * Func=DynamicFunc__append_from_last_output_to_input2_as_base16
 * Func=DynamicFunc__crypt2_md5
 * Func=DynamicFunc__clean_input2_kwik
 * Func=DynamicFunc__append_from_last_output2_as_base16
 * Func=DynamicFunc__crypt2_md5
 * Func=DynamicFunc__clean_input2_kwik
 * Func=DynamicFunc__append_from_last_output2_as_base16
 * Func=DynamicFunc__crypt_md5_in2_to_out1
 * Test=$dynamic_1001$57200e13b490d4ae47d5e19be026b057:test1
 * Test=$dynamic_1001$c6cc44f9e7fb7efcde62ba2e627a49c6:thatsworking
 * Test=$dynamic_1001$0ae9549604e539a249c1fa9f5e5fb73b:test3
 *
 * Renamed and changed from md5_gen* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 * Added SHA2 (SHA224, SHA256, SHA384, SHA512), GOST, Whirlpool crypt types.
 * Whirlpool use oSSSL if OPENSSL_VERSION_NUMBER >= 0x10000000, otherwise use sph_* code.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#include <string.h>
#include <ctype.h>

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
#include "config.h"
#include "md5.h"
#include "options.h"
#include "john.h"
#include "unicode.h"

#include "dynamic.h"

typedef struct Dynamic_Predicate_t
{
	char *name;
	DYNAMIC_primitive_funcp func;
} Dynamic_Predicate_t;

typedef struct Dynamic_Str_Flag_t
{
	char *name;
	uint64_t flag_bit;
} Dynamic_Str_Flag_t;

#define LARGE_HASH_FUNCS(HASH) \
	{ "DynamicFunc__" #HASH "_crypt_input1_append_input2", DynamicFunc__##HASH##_crypt_input1_append_input2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_append_input1", DynamicFunc__##HASH##_crypt_input2_append_input1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_at_offset_input2", DynamicFunc__##HASH##_crypt_input1_at_offset_input2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_at_offset_input1", DynamicFunc__##HASH##_crypt_input2_at_offset_input1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_at_offset_input1", DynamicFunc__##HASH##_crypt_input1_at_offset_input1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_at_offset_input2", DynamicFunc__##HASH##_crypt_input2_at_offset_input2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_overwrite_input1", DynamicFunc__##HASH##_crypt_input1_overwrite_input1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_overwrite_input2", DynamicFunc__##HASH##_crypt_input2_overwrite_input2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_overwrite_input2", DynamicFunc__##HASH##_crypt_input1_overwrite_input2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_overwrite_input1", DynamicFunc__##HASH##_crypt_input2_overwrite_input1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_to_output1", DynamicFunc__##HASH##_crypt_input1_to_output1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_to_output2", DynamicFunc__##HASH##_crypt_input1_to_output2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_to_output3", DynamicFunc__##HASH##_crypt_input1_to_output3 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_to_output4", DynamicFunc__##HASH##_crypt_input1_to_output4 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_to_output1", DynamicFunc__##HASH##_crypt_input2_to_output1 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_to_output2", DynamicFunc__##HASH##_crypt_input2_to_output2 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_to_output3", DynamicFunc__##HASH##_crypt_input2_to_output3 }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_to_output4", DynamicFunc__##HASH##_crypt_input2_to_output4 }, \
	{ "DynamicFunc__" #HASH "_crypt_input1_to_output1_FINAL", DynamicFunc__##HASH##_crypt_input1_to_output1_FINAL }, \
	{ "DynamicFunc__" #HASH "_crypt_input2_to_output1_FINAL", DynamicFunc__##HASH##_crypt_input2_to_output1_FINAL },

static Dynamic_Predicate_t Dynamic_Predicate[] =  {
	{ "DynamicFunc__clean_input",  DynamicFunc__clean_input },
	{ "DynamicFunc__clean_input_kwik", DynamicFunc__clean_input_kwik },
	{ "DynamicFunc__clean_input_full", DynamicFunc__clean_input_full },
	{ "DynamicFunc__append_keys", DynamicFunc__append_keys },
	{ "DynamicFunc__append_keys_pad16", DynamicFunc__append_keys_pad16 },
	{ "DynamicFunc__append_keys_pad20", DynamicFunc__append_keys_pad20 },
	{ "DynamicFunc__crypt", DynamicFunc__crypt_md5 },  // legacy name.  Now the function is explicit to md5, but we still handle deprecated format
	{ "DynamicFunc__crypt_md5", DynamicFunc__crypt_md5 },
	{ "DynamicFunc__crypt_md4", DynamicFunc__crypt_md4 },
	{ "DynamicFunc__append_from_last_output_as_base16", DynamicFunc__append_from_last_output_as_base16 },
	{ "DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix },
	{ "DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE },
	{ "DynamicFunc__crypt_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE }, // support deprecated function
	{ "DynamicFunc__append_salt", DynamicFunc__append_salt },
	{ "DynamicFunc__clean_input2", DynamicFunc__clean_input2 },
	{ "DynamicFunc__clean_input2_kwik", DynamicFunc__clean_input2_kwik },
	{ "DynamicFunc__clean_input2_full", DynamicFunc__clean_input2_full },
	{ "DynamicFunc__append_keys2", DynamicFunc__append_keys2 },
	{ "DynamicFunc__crypt2", DynamicFunc__crypt2_md5 },  // support deprecated legacy function
	{ "DynamicFunc__crypt2_md5", DynamicFunc__crypt2_md5 },
	{ "DynamicFunc__crypt2_md4", DynamicFunc__crypt2_md4 },
	{ "DynamicFunc__append_from_last_output2_as_base16", DynamicFunc__append_from_last_output2_as_base16 },
	{ "DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix },
	{ "DynamicFunc__append_from_last_output_to_input2_as_base16", DynamicFunc__append_from_last_output_to_input2_as_base16 },
	{ "DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix },
	{ "DynamicFunc__overwrite_from_last_output2_to_input2_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output2_to_input2_as_base16_no_size_fix },
	{ "DynamicFunc__append_from_last_output2_to_input1_as_base16", DynamicFunc__append_from_last_output2_to_input1_as_base16 },
	{ "DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix },
	{ "DynamicFunc__append_salt2", DynamicFunc__append_salt2 },
	{ "DynamicFunc__append_input_from_input2", DynamicFunc__append_input_from_input2 },
	{ "DynamicFunc__append_input2_from_input", DynamicFunc__append_input2_from_input },
	{ "DynamicFunc__append_input_from_input", DynamicFunc__append_input_from_input },
	{ "DynamicFunc__append_input2_from_input2", DynamicFunc__append_input2_from_input2 },
	{ "DynamicFunc__append_2nd_salt", DynamicFunc__append_2nd_salt },
	{ "DynamicFunc__append_2nd_salt2", DynamicFunc__append_2nd_salt2 },
	{ "DynamicFunc__append_userid", DynamicFunc__append_userid },
	{ "DynamicFunc__append_userid2", DynamicFunc__append_userid2 },
	{ "DynamicFunc__crypt_in1_to_out2", DynamicFunc__crypt_md5_in1_to_out2 }, // support deprecated function
	{ "DynamicFunc__crypt_in2_to_out1", DynamicFunc__crypt_md5_in2_to_out1 }, // support deprecated function
	{ "DynamicFunc__crypt_md5_in1_to_out2", DynamicFunc__crypt_md5_in1_to_out2 },
	{ "DynamicFunc__crypt_md5_in2_to_out1", DynamicFunc__crypt_md5_in2_to_out1 },
	{ "DynamicFunc__crypt_md4_in1_to_out2", DynamicFunc__crypt_md4_in1_to_out2 },
	{ "DynamicFunc__crypt_md4_in2_to_out1", DynamicFunc__crypt_md4_in2_to_out1 },
	{ "DynamicFunc__crypt_to_input_raw_Overwrite_NoLen", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen }, // support deprecated function
	{ "DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen },
	{ "DynamicFunc__crypt_to_input_raw", DynamicFunc__crypt_md5_to_input_raw }, // support deprecated function
	{ "DynamicFunc__crypt_md5_to_input_raw", DynamicFunc__crypt_md5_to_input_raw },
	{ "DynamicFunc__POCrypt", DynamicFunc__POCrypt },
	{ "DynamicFunc__set_input_len_16", DynamicFunc__set_input_len_16},
	{ "DynamicFunc__set_input2_len_16", DynamicFunc__set_input2_len_16},
	{ "DynamicFunc__set_input_len_20", DynamicFunc__set_input_len_20},
	{ "DynamicFunc__set_input2_len_20", DynamicFunc__set_input2_len_20},
	{ "DynamicFunc__set_input_len_32", DynamicFunc__set_input_len_32 },
	{ "DynamicFunc__set_input_len_32_cleartop", DynamicFunc__set_input_len_32_cleartop },
	{ "DynamicFunc__set_input2_len_32", DynamicFunc__set_input2_len_32 },
	{ "DynamicFunc__set_input_len_24", DynamicFunc__set_input_len_24 },
	{ "DynamicFunc__set_input2_len_24", DynamicFunc__set_input2_len_24 },
	{ "DynamicFunc__set_input_len_28", DynamicFunc__set_input_len_28 },
	{ "DynamicFunc__set_input2_len_28", DynamicFunc__set_input2_len_28 },
	{ "DynamicFunc__set_input_len_40", DynamicFunc__set_input_len_40 },
	{ "DynamicFunc__set_input2_len_40", DynamicFunc__set_input2_len_40 },
	{ "DynamicFunc__set_input2_len_32_cleartop", DynamicFunc__set_input2_len_32_cleartop },
	{ "DynamicFunc__set_input2_len_40_cleartop", DynamicFunc__set_input2_len_40_cleartop },
	{ "DynamicFunc__set_input_len_48", DynamicFunc__set_input_len_48 },
	{ "DynamicFunc__set_input2_len_48", DynamicFunc__set_input2_len_48 },
	{ "DynamicFunc__set_input_len_56", DynamicFunc__set_input_len_56 },
	{ "DynamicFunc__set_input2_len_56", DynamicFunc__set_input2_len_56 },
	{ "DynamicFunc__set_input_len_64", DynamicFunc__set_input_len_64 },
	{ "DynamicFunc__set_input2_len_64", DynamicFunc__set_input2_len_64 },
	{ "DynamicFunc__set_input_len_80", DynamicFunc__set_input_len_80 },
	{ "DynamicFunc__set_input2_len_80", DynamicFunc__set_input2_len_80 },
	{ "DynamicFunc__set_input_len_96", DynamicFunc__set_input_len_96 },
	{ "DynamicFunc__set_input2_len_96", DynamicFunc__set_input2_len_96 },

	{ "DynamicFunc__set_input_len_100", DynamicFunc__set_input_len_100 },

	{ "DynamicFunc__set_input_len_112", DynamicFunc__set_input_len_112 },
	{ "DynamicFunc__set_input2_len_112", DynamicFunc__set_input2_len_112 },
	{ "DynamicFunc__set_input_len_128", DynamicFunc__set_input_len_128 },
	{ "DynamicFunc__set_input2_len_128", DynamicFunc__set_input2_len_128 },
	{ "DynamicFunc__set_input_len_160", DynamicFunc__set_input_len_160 },
	{ "DynamicFunc__set_input2_len_160", DynamicFunc__set_input2_len_160 },
	{ "DynamicFunc__set_input_len_192", DynamicFunc__set_input_len_192 },
	{ "DynamicFunc__set_input2_len_192", DynamicFunc__set_input2_len_192 },
	{ "DynamicFunc__set_input_len_256", DynamicFunc__set_input_len_256 },
	{ "DynamicFunc__set_input2_len_256", DynamicFunc__set_input2_len_256 },
	{ "DynamicFunc__LargeHash_set_offset_saltlen", DynamicFunc__LargeHash_set_offset_saltlen },

	{ "DynamicFunc__LargeHash_set_offset_16", DynamicFunc__LargeHash_set_offset_16 },
	{ "DynamicFunc__LargeHash_set_offset_20", DynamicFunc__LargeHash_set_offset_20 },
	{ "DynamicFunc__LargeHash_set_offset_24", DynamicFunc__LargeHash_set_offset_24 },
	{ "DynamicFunc__LargeHash_set_offset_28", DynamicFunc__LargeHash_set_offset_28 },
	{ "DynamicFunc__LargeHash_set_offset_32", DynamicFunc__LargeHash_set_offset_32 },
	{ "DynamicFunc__LargeHash_set_offset_40", DynamicFunc__LargeHash_set_offset_40 },
	{ "DynamicFunc__LargeHash_set_offset_48", DynamicFunc__LargeHash_set_offset_48 },
	{ "DynamicFunc__LargeHash_set_offset_56", DynamicFunc__LargeHash_set_offset_56 },
	{ "DynamicFunc__LargeHash_set_offset_64", DynamicFunc__LargeHash_set_offset_64 },
	{ "DynamicFunc__LargeHash_set_offset_80", DynamicFunc__LargeHash_set_offset_80 },
	{ "DynamicFunc__LargeHash_set_offset_96", DynamicFunc__LargeHash_set_offset_96 },
	{ "DynamicFunc__LargeHash_set_offset_100",DynamicFunc__LargeHash_set_offset_100 },
	{ "DynamicFunc__LargeHash_set_offset_112",DynamicFunc__LargeHash_set_offset_112 },
	{ "DynamicFunc__LargeHash_set_offset_128",DynamicFunc__LargeHash_set_offset_128 },
	{ "DynamicFunc__LargeHash_set_offset_160",DynamicFunc__LargeHash_set_offset_160 },
	{ "DynamicFunc__LargeHash_set_offset_192",DynamicFunc__LargeHash_set_offset_192 },

	{ "DynamicFunc__overwrite_salt_to_input1_no_size_fix", DynamicFunc__overwrite_salt_to_input1_no_size_fix },
	{ "DynamicFunc__overwrite_salt_to_input2_no_size_fix", DynamicFunc__overwrite_salt_to_input2_no_size_fix },
	{ "DynamicFunc__append_input1_from_CONST1", DynamicFunc__append_input1_from_CONST1 },
	{ "DynamicFunc__append_input1_from_CONST2", DynamicFunc__append_input1_from_CONST2 },
	{ "DynamicFunc__append_input1_from_CONST3", DynamicFunc__append_input1_from_CONST3 },
	{ "DynamicFunc__append_input1_from_CONST4", DynamicFunc__append_input1_from_CONST4 },
	{ "DynamicFunc__append_input1_from_CONST5", DynamicFunc__append_input1_from_CONST5 },
	{ "DynamicFunc__append_input1_from_CONST6", DynamicFunc__append_input1_from_CONST6 },
	{ "DynamicFunc__append_input1_from_CONST7", DynamicFunc__append_input1_from_CONST7 },
	{ "DynamicFunc__append_input1_from_CONST8", DynamicFunc__append_input1_from_CONST8 },
	{ "DynamicFunc__append_input2_from_CONST1", DynamicFunc__append_input2_from_CONST1 },
	{ "DynamicFunc__append_input2_from_CONST2", DynamicFunc__append_input2_from_CONST2 },
	{ "DynamicFunc__append_input2_from_CONST3", DynamicFunc__append_input2_from_CONST3 },
	{ "DynamicFunc__append_input2_from_CONST4", DynamicFunc__append_input2_from_CONST4 },
	{ "DynamicFunc__append_input2_from_CONST5", DynamicFunc__append_input2_from_CONST5 },
	{ "DynamicFunc__append_input2_from_CONST6", DynamicFunc__append_input2_from_CONST6 },
	{ "DynamicFunc__append_input2_from_CONST7", DynamicFunc__append_input2_from_CONST7 },
	{ "DynamicFunc__append_input2_from_CONST8", DynamicFunc__append_input2_from_CONST8 },
	{ "DynamicFunc__SSEtoX86_switch_input1", DynamicFunc__SSEtoX86_switch_input1 },
	{ "DynamicFunc__SSEtoX86_switch_input2", DynamicFunc__SSEtoX86_switch_input2 },
	{ "DynamicFunc__SSEtoX86_switch_output1", DynamicFunc__SSEtoX86_switch_output1 },
	{ "DynamicFunc__SSEtoX86_switch_output2", DynamicFunc__SSEtoX86_switch_output2 },
	{ "DynamicFunc__X86toSSE_switch_input1", DynamicFunc__X86toSSE_switch_input1 },
	{ "DynamicFunc__X86toSSE_switch_input2", DynamicFunc__X86toSSE_switch_input2 },
	{ "DynamicFunc__X86toSSE_switch_output1", DynamicFunc__X86toSSE_switch_output1 },
	{ "DynamicFunc__X86toSSE_switch_output2", DynamicFunc__X86toSSE_switch_output2 },
	{ "DynamicFunc__ToSSE", DynamicFunc__ToSSE },
	{ "DynamicFunc__ToX86", DynamicFunc__ToX86 },
	{ "DynamicFunc__setmode_unicode", DynamicFunc__setmode_unicode },
	{ "DynamicFunc__setmode_unicodeBE", DynamicFunc__setmode_unicodeBE },
	{ "DynamicFunc__setmode_normal", DynamicFunc__setmode_normal },
	{ "DynamicFunc__base16_convert_locase", DynamicFunc__base16_convert_locase },
	{ "DynamicFunc__base16_convert_upcase", DynamicFunc__base16_convert_upcase },
	{ "DynamicFunc__append_fld0", DynamicFunc__append_fld0 },
	{ "DynamicFunc__append_fld1", DynamicFunc__append_fld1 },
	{ "DynamicFunc__append_fld2", DynamicFunc__append_fld2 },
	{ "DynamicFunc__append_fld3", DynamicFunc__append_fld3 },
	{ "DynamicFunc__append_fld4", DynamicFunc__append_fld4 },
	{ "DynamicFunc__append_fld5", DynamicFunc__append_fld5 },
	{ "DynamicFunc__append_fld6", DynamicFunc__append_fld6 },
	{ "DynamicFunc__append_fld7", DynamicFunc__append_fld7 },
	{ "DynamicFunc__append_fld8", DynamicFunc__append_fld8 },
	{ "DynamicFunc__append_fld9", DynamicFunc__append_fld9 },
	{ "DynamicFunc__append2_fld0", DynamicFunc__append2_fld0 },
	{ "DynamicFunc__append2_fld1", DynamicFunc__append2_fld1 },
	{ "DynamicFunc__append2_fld2", DynamicFunc__append2_fld2 },
	{ "DynamicFunc__append2_fld3", DynamicFunc__append2_fld3 },
	{ "DynamicFunc__append2_fld4", DynamicFunc__append2_fld4 },
	{ "DynamicFunc__append2_fld5", DynamicFunc__append2_fld5 },
	{ "DynamicFunc__append2_fld6", DynamicFunc__append2_fld6 },
	{ "DynamicFunc__append2_fld7", DynamicFunc__append2_fld7 },
	{ "DynamicFunc__append2_fld8", DynamicFunc__append2_fld8 },
	{ "DynamicFunc__append2_fld9", DynamicFunc__append2_fld9 },
	{ "DynamicFunc__append_from_last_output2_as_raw", DynamicFunc__append_from_last_output2_as_raw },
	{ "DynamicFunc__append2_from_last_output2_as_raw", DynamicFunc__append2_from_last_output2_as_raw },
	{ "DynamicFunc__append_from_last_output1_as_raw", DynamicFunc__append_from_last_output1_as_raw },
	{ "DynamicFunc__append2_from_last_output1_as_raw", DynamicFunc__append2_from_last_output1_as_raw },

	{ "DynamicFunc__LargeHash_OUTMode_base16", DynamicFunc__LargeHash_OUTMode_base16 },
	{ "DynamicFunc__LargeHash_OUTMode_base16u", DynamicFunc__LargeHash_OUTMode_base16u },
	{ "DynamicFunc__LargeHash_OUTMode_base64", DynamicFunc__LargeHash_OUTMode_base64 },
	{ "DynamicFunc__LargeHash_OUTMode_base64_nte", DynamicFunc__LargeHash_OUTMode_base64_nte },
	{ "DynamicFunc__LargeHash_OUTMode_base64c", DynamicFunc__LargeHash_OUTMode_base64c },
	{ "DynamicFunc__LargeHash_OUTMode_raw", DynamicFunc__LargeHash_OUTMode_raw },

	LARGE_HASH_FUNCS(MD5)
	LARGE_HASH_FUNCS(MD4)
	LARGE_HASH_FUNCS(SHA1)
	LARGE_HASH_FUNCS(SHA224)
	LARGE_HASH_FUNCS(SHA256)
	LARGE_HASH_FUNCS(SHA384)
	LARGE_HASH_FUNCS(SHA512)
	LARGE_HASH_FUNCS(GOST)
	LARGE_HASH_FUNCS(WHIRLPOOL)
	LARGE_HASH_FUNCS(Tiger)
	LARGE_HASH_FUNCS(RIPEMD128)
	LARGE_HASH_FUNCS(RIPEMD160)
	LARGE_HASH_FUNCS(RIPEMD256)
	LARGE_HASH_FUNCS(RIPEMD320)
	LARGE_HASH_FUNCS(HAVAL128_3)
	LARGE_HASH_FUNCS(HAVAL128_4)
	LARGE_HASH_FUNCS(HAVAL128_5)
	LARGE_HASH_FUNCS(HAVAL160_3)
	LARGE_HASH_FUNCS(HAVAL160_4)
	LARGE_HASH_FUNCS(HAVAL160_5)
	LARGE_HASH_FUNCS(HAVAL192_3)
	LARGE_HASH_FUNCS(HAVAL192_4)
	LARGE_HASH_FUNCS(HAVAL192_5)
	LARGE_HASH_FUNCS(HAVAL224_3)
	LARGE_HASH_FUNCS(HAVAL224_4)
	LARGE_HASH_FUNCS(HAVAL224_5)
	LARGE_HASH_FUNCS(HAVAL256_3)
	LARGE_HASH_FUNCS(HAVAL256_4)
	LARGE_HASH_FUNCS(HAVAL256_5)
	LARGE_HASH_FUNCS(MD2)
	LARGE_HASH_FUNCS(PANAMA)
	LARGE_HASH_FUNCS(SKEIN224)
	LARGE_HASH_FUNCS(SKEIN256)
	LARGE_HASH_FUNCS(SKEIN384)
	LARGE_HASH_FUNCS(SKEIN512)
	LARGE_HASH_FUNCS(SHA3_224)
	LARGE_HASH_FUNCS(SHA3_256)
	LARGE_HASH_FUNCS(SHA3_384)
	LARGE_HASH_FUNCS(SHA3_512)
	LARGE_HASH_FUNCS(KECCAK_224)
	LARGE_HASH_FUNCS(KECCAK_256)
	LARGE_HASH_FUNCS(KECCAK_384)
	LARGE_HASH_FUNCS(KECCAK_512)
	// LARGE_HASH_EDIT_POINT
	{ NULL, NULL }};


#define SALT_AS_HEX_FLAG(HASH) \
	{ "MGF_SALT_AS_HEX_" #HASH,             MGF_SALT_AS_HEX_##HASH },

static Dynamic_Str_Flag_t Dynamic_Str_Flag[] =  {
	{ "MGF_NOTSSE2Safe",                  MGF_NOTSSE2Safe },
	{ "MGF_FLAT_BUFFERS",                 MGF_FLAT_BUFFERS },
	{ "MGF_StartInX86Mode",               MGF_StartInX86Mode },
	{ "MGF_ColonNOTValid",                MGF_ColonNOTValid },
	{ "MGF_SALTED",                       MGF_SALTED },
	{ "MGF_SALTED2",                      MGF_SALTED2 },
	{ "MGF_USERNAME",                     MGF_USERNAME },
	{ "MGF_USERNAME_UPCASE",              MGF_USERNAME_UPCASE },
	{ "MGF_USERNAME_LOCASE",              MGF_USERNAME_LOCASE },
	{ "MGF_INPBASE64",                    MGF_INPBASE64 },
	{ "MGF_INPBASE64b",                   MGF_INPBASE64b },
	{ "MGF_INPBASE64m",                   MGF_INPBASE64m },
	{ "MGF_INPBASE64a",                   MGF_INPBASE64a },
	{ "MGF_SALT_AS_HEX",                  MGF_SALT_AS_HEX },  // Deprecated (use the _MD5 version.
	{ "MFG_SALT_AS_HEX",                  MGF_SALT_AS_HEX },  // Deprecated misspelling
	SALT_AS_HEX_FLAG(MD5)
	SALT_AS_HEX_FLAG(MD4)
	SALT_AS_HEX_FLAG(SHA1)
	SALT_AS_HEX_FLAG(SHA224)
	SALT_AS_HEX_FLAG(SHA256)
	SALT_AS_HEX_FLAG(SHA384)
	SALT_AS_HEX_FLAG(SHA512)
	SALT_AS_HEX_FLAG(GOST)
	SALT_AS_HEX_FLAG(WHIRLPOOL)
	SALT_AS_HEX_FLAG(Tiger)
	SALT_AS_HEX_FLAG(TIGER)
	SALT_AS_HEX_FLAG(RIPEMD128)
	SALT_AS_HEX_FLAG(RIPEMD160)
	SALT_AS_HEX_FLAG(RIPEMD256)
	SALT_AS_HEX_FLAG(RIPEMD320)
	SALT_AS_HEX_FLAG(HAVAL128_3)
	SALT_AS_HEX_FLAG(HAVAL128_4)
	SALT_AS_HEX_FLAG(HAVAL128_5)
	SALT_AS_HEX_FLAG(HAVAL160_3)
	SALT_AS_HEX_FLAG(HAVAL160_4)
	SALT_AS_HEX_FLAG(HAVAL160_5)
	SALT_AS_HEX_FLAG(HAVAL192_3)
	SALT_AS_HEX_FLAG(HAVAL192_4)
	SALT_AS_HEX_FLAG(HAVAL192_5)
	SALT_AS_HEX_FLAG(HAVAL224_3)
	SALT_AS_HEX_FLAG(HAVAL224_4)
	SALT_AS_HEX_FLAG(HAVAL224_5)
	SALT_AS_HEX_FLAG(HAVAL256_3)
	SALT_AS_HEX_FLAG(HAVAL256_4)
	SALT_AS_HEX_FLAG(HAVAL256_5)
	SALT_AS_HEX_FLAG(MD2)
	SALT_AS_HEX_FLAG(PANAMA)
	SALT_AS_HEX_FLAG(SKEIN224)
	SALT_AS_HEX_FLAG(SKEIN256)
	SALT_AS_HEX_FLAG(SKEIN384)
	SALT_AS_HEX_FLAG(SKEIN512)
	SALT_AS_HEX_FLAG(SHA3_224)
	SALT_AS_HEX_FLAG(SHA3_256)
	SALT_AS_HEX_FLAG(SHA3_384)
	SALT_AS_HEX_FLAG(SHA3_512)
	SALT_AS_HEX_FLAG(KECCAK_224)
	SALT_AS_HEX_FLAG(KECCAK_256)
	SALT_AS_HEX_FLAG(KECCAK_384)
	SALT_AS_HEX_FLAG(KECCAK_512)
	// LARGE_HASH_EDIT_POINT

	{ "MGF_SALT_AS_HEX_TO_SALT2",         MGF_SALT_AS_HEX_TO_SALT2 },
	{ "MGF_INPBASE64_4x6",				  MGF_INPBASE64_4x6 },
	{ "MGF_SALT_UNICODE_B4_CRYPT",        MGF_SALT_UNICODE_B4_CRYPT },
	{ "MGF_BASE_16_OUTPUT_UPCASE",        MGF_BASE_16_OUTPUT_UPCASE },
	{ "MGF_FLD0",                         MGF_FLD0 },
	{ "MGF_FLD1",                         MGF_FLD1 },
	{ "MGF_FLD2",                         MGF_FLD2 },
	{ "MGF_FLD3",                         MGF_FLD3 },
	{ "MGF_FLD4",                         MGF_FLD4 },
	{ "MGF_FLD5",                         MGF_FLD5 },
	{ "MGF_FLD6",                         MGF_FLD6 },
	{ "MGF_FLD7",                         MGF_FLD7 },
	{ "MGF_FLD8",                         MGF_FLD8 },
	{ "MGF_FLD9",                         MGF_FLD9 },
	{ "MGF_UTF8",                         MGF_UTF8 },
	{ "MGF_PASSWORD_UPCASE",              MGF_PASSWORD_UPCASE },
	{ "MGF_PASSWORD_LOCASE",              MGF_PASSWORD_LOCASE },
	{ "MGF_FULL_CLEAN_REQUIRED",          MGF_FULL_CLEAN_REQUIRED },
	{ "MGF_FULL_CLEAN_REQUIRED2",         MGF_FULL_CLEAN_REQUIRED2 },
	{ NULL, 0 }};

#define SALT_AS_HEX_FLAG2(HASH) \
	{ "MGF_KEYS_BASE16_IN1_" #HASH,              MGF_KEYS_BASE16_IN1_##HASH }, \
	{ "MGF_KEYS_BASE16_IN1_Offset_" #HASH,       MGF_KEYS_BASE16_IN1_Offset_##HASH },

static Dynamic_Str_Flag_t Dynamic_Str_sFlag[] =  {
	{ "MGF_KEYS_INPUT",                       MGF_KEYS_INPUT },
	{ "MGF_KEYS_CRYPT_IN2",                   MGF_KEYS_CRYPT_IN2 },
	{ "MGF_KEYS_BASE16_IN1",                  MGF_KEYS_BASE16_IN1 }, // deprecated (use the _MD5 version)
	{ "MGF_KEYS_BASE16_IN1_Offset32",         MGF_KEYS_BASE16_IN1_Offset32 },  // deprecated (use the _MD5 version)
	SALT_AS_HEX_FLAG2(MD5)
	SALT_AS_HEX_FLAG2(MD4)
	SALT_AS_HEX_FLAG2(SHA1)
	SALT_AS_HEX_FLAG2(SHA224)
	SALT_AS_HEX_FLAG2(SHA256)
	SALT_AS_HEX_FLAG2(SHA384)
	SALT_AS_HEX_FLAG2(SHA512)
	SALT_AS_HEX_FLAG2(GOST)
	SALT_AS_HEX_FLAG2(WHIRLPOOL)
	SALT_AS_HEX_FLAG2(Tiger)
	SALT_AS_HEX_FLAG2(TIGER)
	SALT_AS_HEX_FLAG2(RIPEMD128)
	SALT_AS_HEX_FLAG2(RIPEMD160)
	SALT_AS_HEX_FLAG2(RIPEMD256)
	SALT_AS_HEX_FLAG2(RIPEMD320)
	SALT_AS_HEX_FLAG2(HAVAL128_3)
	SALT_AS_HEX_FLAG2(HAVAL128_4)
	SALT_AS_HEX_FLAG2(HAVAL128_5)
	SALT_AS_HEX_FLAG2(HAVAL160_3)
	SALT_AS_HEX_FLAG2(HAVAL160_4)
	SALT_AS_HEX_FLAG2(HAVAL160_5)
	SALT_AS_HEX_FLAG2(HAVAL192_3)
	SALT_AS_HEX_FLAG2(HAVAL192_4)
	SALT_AS_HEX_FLAG2(HAVAL192_5)
	SALT_AS_HEX_FLAG2(HAVAL224_3)
	SALT_AS_HEX_FLAG2(HAVAL224_4)
	SALT_AS_HEX_FLAG2(HAVAL224_5)
	SALT_AS_HEX_FLAG2(HAVAL256_3)
	SALT_AS_HEX_FLAG2(HAVAL256_4)
	SALT_AS_HEX_FLAG2(HAVAL256_5)
	SALT_AS_HEX_FLAG2(MD2)
	SALT_AS_HEX_FLAG2(PANAMA)
	SALT_AS_HEX_FLAG2(SKEIN224)
	SALT_AS_HEX_FLAG2(SKEIN256)
	SALT_AS_HEX_FLAG2(SKEIN384)
	SALT_AS_HEX_FLAG2(SKEIN512)
	SALT_AS_HEX_FLAG2(SHA3_224)
	SALT_AS_HEX_FLAG2(SHA3_256)
	SALT_AS_HEX_FLAG2(SHA3_384)
	SALT_AS_HEX_FLAG2(SHA3_512)
	SALT_AS_HEX_FLAG2(KECCAK_224)
	SALT_AS_HEX_FLAG2(KECCAK_256)
	SALT_AS_HEX_FLAG2(KECCAK_384)
	SALT_AS_HEX_FLAG2(KECCAK_512)
	// LARGE_HASH_EDIT_POINT

	{ "MGF_KEYS_UNICODE_B4_CRYPT",        MGF_KEYS_UNICODE_B4_CRYPT },
	{ "MGF_POSetup",                      MGF_POSetup },
	{ "MGF_POOR_OMP",                     MGF_POOR_OMP },
	{ "MGF_RAW_SHA1_INPUT",               MGF_RAW_SHA1_INPUT },
	{ "MGF_KEYS_INPUT_BE_SAFE",           MGF_KEYS_INPUT_BE_SAFE },  // big endian safe, i.e. the input will NEVER get swapped.  Only SHA1 is 'safe'.
	{ "MGF_SET_INP2LEN32",                MGF_SET_INP2LEN32 }, // this sets the input2 lens (in SSE2) to 32 bytes long, but only in init() call
	{ "MGF_SOURCE",                       MGF_SOURCE },
	{ "MGF_INPUT_20_BYTE",                MGF_INPUT_20_BYTE },
	{ "MGF_INPUT_24_BYTE",                MGF_INPUT_24_BYTE },
	{ "MGF_INPUT_28_BYTE",                MGF_INPUT_28_BYTE },
	{ "MGF_INPUT_32_BYTE",                MGF_INPUT_32_BYTE },
	{ "MGF_INPUT_40_BYTE",                MGF_INPUT_40_BYTE },
	{ "MGF_INPUT_48_BYTE",                MGF_INPUT_48_BYTE },
	{ "MGF_INPUT_64_BYTE",                MGF_INPUT_64_BYTE },
	{ NULL, 0 }};

static DYNAMIC_Setup *pSetup;
static int nPreloadCnt;
static int nFuncCnt;
static char SetupName[128], SetupNameID[128];
static struct cfg_list *gen_source;
static int ngen_source;
static char *cp_local_source;
static char *(*Thin_Convert)(char *Buf, char *ciphertext, int in_load);

extern struct options_main options;

static void add_line(char *cp) {
	struct cfg_line *pln, *p;
	int len;

	pln = mem_calloc_tiny(sizeof(struct cfg_line), sizeof(struct cfg_line*));
	if (gen_source->head == NULL)
		gen_source->head = pln;
	p = gen_source->head;
	while (p->next)
		p = p->next;
	if (pln != p)
		p->next = pln;
	pln->data = str_alloc_copy(cp);
	len = strlen(cp);
	while (len>0) {
		if (pln->data[len-1] != ' ')
			break;
		pln->data[--len] = 0;
	}
}
static void load_script_from_string(int which) {
	char *cp;
	if (ngen_source == which)
		return;
	gen_source = NULL;
	if (!cp_local_source || !strlen(cp_local_source))
		return;
	cp = strtok(cp_local_source, "\n");
	if (!cp)
		return;
	gen_source = mem_calloc_tiny(sizeof(struct cfg_list), sizeof(struct cfg_list*));
	while (cp) {
		add_line(cp);
		cp = strtok(NULL, "\n");
	}
}
static int load_config(int which) {
	char SubSection[32];
	if (which >= 6000) {
		load_script_from_string(which);
	} else {
		ngen_source = 0;
		sprintf(SubSection, ":dynamic_%d", which);
		gen_source = cfg_get_list("list.generic", SubSection);
	}
	return !!gen_source;
}

static char *GetFld(char **out, char *in)
{
	char *cp;
	if (!in || !*in) return "";
	cp = strchr(in, options.loader.field_sep_char);
	if (cp)
		*cp++ = 0;
	*out = in;
	return cp;
}

static char *convert_old_name_if_needed(char *cpI) {
	if (!strncmp(cpI, "md5_gen(", 8)) {
		char *cp = mem_alloc_tiny(strlen(cpI)+6, MEM_ALIGN_NONE);
		char *cpo = &cp[sprintf(cp, "$dynamic_")];
		cpI += 8;
		while (*cpI >= '0' && *cpI <= '9')
			*cpo++ = *cpI++;
		++cpI;
		*cpo++ = '$';
		strcpy(cpo, cpI);
		return cp;
	}
	return str_alloc_copy(cpI);
}

int dynamic_LOAD_PARSER_FUNCTIONS_LoadLINE(struct cfg_line *_line)
{
	int nConst, j;
	char *Line = _line->data;
	char c = *Line;
	if (c >= 'A' && c <= 'Z')
		c ^= 0x20; // lower case.
	if (c == 't' && !strncasecmp(Line, "Test=", 5))
	{
		char *cp;
		cp = convert_old_name_if_needed(&Line[5]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (pSetup->pPreloads[nPreloadCnt].ciphertext && Thin_Convert &&
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, "$dynamic_", 9)) {
				static char Buf[1024];
				pSetup->pPreloads[nPreloadCnt].ciphertext = Thin_Convert(Buf, pSetup->pPreloads[nPreloadCnt].ciphertext, 1);
		}
		if (pSetup->pPreloads[nPreloadCnt].ciphertext &&
		    !strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, "$dynamic_6xxx$", 14)) {
			memmove(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName));
		}
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].fields[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].fields[j]), cp);
		}
		++nPreloadCnt;
		return 1;
	}
	if (c == 't' && !strncasecmp(Line, "TestU=", 6))
	{
		char *cp;
		if (options.target_enc != UTF_8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].fields[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].fields[j]), cp);
		}
		++nPreloadCnt;
		return 1;
	}
	if (c == 't' && !strncasecmp(Line, "TestA=", 6))
	{
		char *cp;
		if (options.target_enc == UTF_8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].fields[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].fields[j]), cp);
		}
		++nPreloadCnt;
		return 1;
	}

	if (c == 't' && !strncasecmp(Line, "TestM=", 6))
	{
#ifdef SIMD_COEF_32
		char *cp;
		if (options.target_enc == UTF_8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].fields[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].fields[j]), cp);
		}
		++nPreloadCnt;
#endif
		return 1;
	}

	if (c == 't' && !strncasecmp(Line, "TestF=", 6))
	{
#ifndef SIMD_COEF_32
		char *cp;
		if (options.target_enc == UTF_8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].fields[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].fields[j]), cp);
		}
		++nPreloadCnt;
#endif
		return 1;
	}

	if (c == 't' && !strncasecmp(Line, "TestD=", 6))
	{
#ifdef DEBUG
		char *cp;
		if (options.target_enc == UTF_8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].fields[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].fields[j]), cp);
		}
		++nPreloadCnt;
#endif
		return 1;
	}
	if (c == 'c' && !strncasecmp(Line, "ColonChar=", 10))
	{
		char *tmp = dynamic_Demangle(&Line[10], NULL);
		if (!tmp)
			return !fprintf(stderr, "Error, invalid test line: %s\n", Line);
		options.loader.field_sep_char = *tmp;
		return 1;
	}
	if (c == 'f' && !strncasecmp(Line, "Func=", 5))
	{
		int i;
		for (i = 0; Dynamic_Predicate[i].name; ++i)
		{
			if (!strcmp(Dynamic_Predicate[i].name, &Line[5]))
			{
				pSetup->pFuncs[nFuncCnt++] = Dynamic_Predicate[i].func;
				return 1;
			}
		}
		return !fprintf(stderr, "Error, unknown function:  %s\n", Line);
	}
	if (c == 'f' && !strncasecmp(Line, "Flag=", 5))
	{
		int i;
		for (i = 0; Dynamic_Str_Flag[i].name; ++i)
		{
			if (!strcmp(Dynamic_Str_Flag[i].name, &Line[5]))
			{
				pSetup->flags |= Dynamic_Str_Flag[i].flag_bit;
				return 1;
			}
		}
		for (i = 0; Dynamic_Str_sFlag[i].name; ++i)
		{
			if (!strcmp(Dynamic_Str_sFlag[i].name, &Line[5]))
			{
				pSetup->startFlags |= Dynamic_Str_sFlag[i].flag_bit;
				return 1;
			}
		}
		return !fprintf(stderr, "Error, unknown flag:  %s\n", Line);
	}
	if (c == 's' && !strncasecmp(Line, "SaltLen=", 8))
	{
		if (sscanf(&Line[7], "=%d", &pSetup->SaltLen) == 1)
			return 1;
		return !fprintf(stderr, "Error, Invalid SaltLen= line:  %s  \n", Line);
	}
	if (c == 's' && !strncasecmp(Line, "SaltLenX86=", 11))
	{
		if (sscanf(&Line[10], "=%d", &pSetup->SaltLenX86) == 1)
			return 1;
		return !fprintf(stderr, "Error, Invalid SaltLenX86= line:  %s  \n", Line);
	}
	if (c == 'm' && !strncasecmp(Line, "MaxInputLen=", 12))
	{
		if (sscanf(&Line[11], "=%d", &pSetup->MaxInputLen) == 1)
			return 1;
		return !fprintf(stderr, "Error, Invalid MaxInputLen= line:  %s  \n", Line);
	}
	if (c == 'm' && !strncasecmp(Line, "MaxInputLenX86=", 15))
	{
		if (sscanf(&Line[14], "=%d", &pSetup->MaxInputLenX86) == 1)
			return 1;
		return !fprintf(stderr, "Error, Invalid MaxInputLenX86= line:  %s  \n", Line);
	}
	if (c == 'e' && !strncasecmp(Line, "Expression=", 11))
	{
		char tmp[256];
		sprintf(tmp, "%s %s", SetupNameID, &Line[11]);
		pSetup->szFORMAT_NAME = str_alloc_copy(tmp);
		return 1;
	}
	if (c == 'c' && !strncasecmp(Line, "const", 5))
	{
		if (sscanf(&Line[5], "%d=", &nConst)!=1)
			return !fprintf(stderr, "Error, invalid const line.   Line: %s\n", Line);
		if (nConst < 1 || nConst > 8)
			return !fprintf(stderr, "Error, only constants from 1 to 8 are valid.   Line: %s\n", Line);
		if (strlen(Line) == 7)
			return !fprintf(stderr, "Error, a 'blank' constant is not valid.   Line: %s\n", Line);
		if (pSetup->pConstants[nConst-1].Const)
			return !fprintf(stderr, "Error, this constant has already entered.   Line: %s\n", Line);
		// we want to know the length here.
		pSetup->pConstants[nConst-1].Const = dynamic_Demangle(&Line[7], &(pSetup->pConstants[nConst-1].len));
		return 1;
	}
	return !fprintf(stderr, "Error, unknown line:   %s\n", Line);
}

const char *dynamic_Find_Function_Name(DYNAMIC_primitive_funcp p) {
	int i;
	for (i = 0; Dynamic_Predicate[i].name; ++i)
	{
		if (Dynamic_Predicate[i].func == p)
			return Dynamic_Predicate[i].name;
	}
	return "Error, unknown function";
}

char *dynamic_LOAD_PARSER_SIGNATURE(int which)
{
	struct cfg_line *gen_line = NULL;
	static char Sig[256];
	if (which < 1000)
		return NULL;

	if (!load_config(which))
		return NULL;

	// Setup the 'default' format name
	sprintf(Sig, "dynamic_%d: ", which);

	if (gen_source)
		gen_line = gen_source->head;
	while (gen_line)
	{
		if (!strncasecmp(gen_line->data, "Expression=", 11))
		{
			char SigApp[241];
			strncpy(SigApp, &gen_line->data[11], 240);
			SigApp[240] = 0;
			strcat(Sig, SigApp);
			break;
		}
		gen_line = gen_line->next;
	}
	return Sig;
}

int dynamic_IS_PARSER_VALID(int which, int single_lookup_only)
{
	static signed char valid[5001];
	static int init=0;

	if (which < 1000 || which > 5000)
		return -1;
	if (single_lookup_only) {
		// if only loading a single dyna format, then do NOT load the valid array
		if (!dynamic_LOAD_PARSER_SIGNATURE(which))
			return 0;
		return 1;
	}
	if (!init) {
		extern const struct cfg_section *get_cfg_db();
		const struct cfg_section *cfg_db;

		cfg_db = get_cfg_db();
		memset(valid, -1, sizeof(valid));
		while (cfg_db) {
			if (!strncasecmp(cfg_db->name, "list.generic:dynamic_", 21)) {
				int i = atoi(&cfg_db->name[21]);
				if (i >= 1000 && i < 5000)
					valid[i] = 1;
			}
			cfg_db = cfg_db->next;
		}
		init = 1;
	}
	return valid[which];
}

static int Count_Items(char *Key)
{
	struct cfg_line *gen_line = NULL;
	int Cnt=0, len=strlen(Key);

	if (gen_source)
		gen_line = gen_source->head;
	while (gen_line)
	{
		if (!strncasecmp(gen_line->data, Key, len))
			++Cnt;
		gen_line = gen_line->next;
	}
	return Cnt;
}

struct fmt_main *dynamic_LOCAL_FMT_FROM_PARSER_FUNCTIONS(const char *Script, int *type, struct fmt_main *pFmt, char *(*Convert)(char *Buf, char *ciphertext, int in_load))
{
	nPreloadCnt = 0;
	nFuncCnt = 0;

	cp_local_source = str_alloc_copy((char*)Script);
	Thin_Convert = Convert;
	pFmt = dynamic_Register_local_format(type);
	Thin_Convert = NULL;
	return pFmt;
}

int dynamic_LOAD_PARSER_FUNCTIONS(int which, struct fmt_main *pFmt)
{
	int ret, cnt;
	struct cfg_line *gen_line = NULL;
	char tmp = options.loader.field_sep_char;

	nPreloadCnt = 0;
	nFuncCnt = 0;

	// since we switched flags to this size, we need to align to 64 bit,
	// or we crash on !ALLOW_UNALIGNED
	pSetup = mem_calloc_tiny(sizeof(DYNAMIC_Setup), sizeof(uint64_t));

	options.loader.field_sep_char = ':';
	if (!dynamic_LOAD_PARSER_SIGNATURE(which))
	{
		if (john_main_process)
			fprintf(stderr, "Could not find section [List.Generic"
			        ":dynamic_%d] in the john.ini/conf file\n",
			        which);
		//error();
	}

	// Setup the 'default' format name
	sprintf(SetupName, "$dynamic_%d$", which);
	sprintf(SetupNameID, "dynamic_%d", which);
	pSetup->szFORMAT_NAME = str_alloc_copy(SetupNameID);

	// allocate (and set null) enough file pointers
	cnt = Count_Items("Func=");
	pSetup->pFuncs = mem_alloc_tiny((cnt+1)*sizeof(DYNAMIC_primitive_funcp), MEM_ALIGN_WORD);
	memset(pSetup->pFuncs, 0, (cnt+1)*sizeof(DYNAMIC_primitive_funcp));

	// allocate (and set null) enough Preloads
	cnt = Count_Items("Test=");
	cnt += Count_Items("TestU=");
	cnt += Count_Items("TestA=");
#ifdef DEBUG
	cnt += Count_Items("TestD=");
#endif
#ifdef SIMD_COEF_32
	cnt += Count_Items("TestM=");
#else
	cnt += Count_Items("TestF=");
#endif
	pSetup->pPreloads = mem_alloc_tiny((cnt+1)*sizeof(struct fmt_tests), MEM_ALIGN_WORD);
	memset(pSetup->pPreloads, 0, (cnt+1)*sizeof(struct fmt_tests));

	// allocate (and set null) enough constants (if we have 8, we still need a null to specify the end of the list)
	cnt = Count_Items("CONST");
	pSetup->pConstants = mem_alloc_tiny((cnt+1)*sizeof(DYNAMIC_Constants), MEM_ALIGN_WORD);
	memset(pSetup->pConstants, 0, (cnt+1)*sizeof(DYNAMIC_Constants));

	pSetup->flags = 0;
	pSetup->startFlags = 0;
	pSetup->SaltLen = 0;
	pSetup->MaxInputLen = 0;

	// Ok, now 'grind' through the data  I do know know how to use
	// the config stuff too much, so will grind for now, and later
	// go back over this, and do it 'right', if there is a right way
	if (gen_source)
		gen_line = gen_source->head;

	while (gen_line)
	{
		if (!dynamic_LOAD_PARSER_FUNCTIONS_LoadLINE(gen_line))
		{
			if (john_main_process)
				fprintf(stderr, "Error parsing section [List."
				        "Generic:dynamic_%d]\nError in line %d"
				        " file is %s\n",
				        which, gen_line->number,
				        gen_line->cfg_name);
			//error();
		}
		gen_line = gen_line->next;
	}

	ret = dynamic_SETUP(pSetup, pFmt);

	options.loader.field_sep_char = tmp;
	return ret;
}

#endif /* DYNAMIC_DISABLED */
