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
 * This file implements code that allows 'dynamic' building of
 * generic MD5 functions.  john.conf is used to store the 'script'
 * and supporting data (like the expression, or 'flags' needed to
 * make the format work).
 *
 * To make this work, you simply add a "section" to the john.conf
 * file of this format:
 *
 *  [List.Generic:dynamic_NUM   ( [List.Generic:md5_gen(NUM)] depricated but 'works')
 *
 * Num has to be replaced with a number, greater than 1000, since
 * dynamic_0 to dynamic_1000 are reserved for 'built-in' and any
 * user defined dynamic_# functions need to start at 1001 or more.
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
 * Func=DynamicFunc__crypt
 * Func=DynamicFunc__clean_input2
 * Func=DynamicFunc__append_from_last_output_to_input2_as_base16
 * Func=DynamicFunc__crypt2
 * Func=DynamicFunc__clean_input2_kwik
 * Func=DynamicFunc__append_from_last_output2_as_base16
 * Func=DynamicFunc__crypt2
 * Func=DynamicFunc__clean_input2_kwik
 * Func=DynamicFunc__append_from_last_output2_as_base16
 * Func=DynamicFunc__crypt_in2_to_out1
 * Test=$dynamic_1001$57200e13b490d4ae47d5e19be026b057:test1
 * Test=$dynamic_1001$c6cc44f9e7fb7efcde62ba2e627a49c6:thatsworking
 * Test=$dynamic_1001$0ae9549604e539a249c1fa9f5e5fb73b:test3
 *
 * Renamed and changed from md5_gen* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 *
 */

#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "md5.h"
#include "options.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

#define DEFINE_MD5_PREDICATE_POINTERS
#include "dynamic.h"

typedef struct MD5Gen_Predicate_t
{
	char *name;
	void(*func)();
} MD5Gen_Predicate_t;

typedef struct MD5Gen_Str_Flag_t
{
	char *name;
	unsigned flag_bit;
} MD5Gen_Str_Flag_t;


static MD5Gen_Predicate_t MD5Gen_Predicate[] =  {
	{ "DynamicFunc__clean_input",  DynamicFunc__clean_input },
	{ "DynamicFunc__clean_input_kwik", DynamicFunc__clean_input_kwik },
	{ "DynamicFunc__clean_input_full", DynamicFunc__clean_input_full },
	{ "DynamicFunc__append_keys", DynamicFunc__append_keys },
	{ "DynamicFunc__crypt", DynamicFunc__crypt_md5 },  // legacy name.  Now the function is explicit to md5, but we still handle deprecated format
	{ "DynamicFunc__crypt_md5", DynamicFunc__crypt_md5 },
	{ "DynamicFunc__crypt_md4", DynamicFunc__crypt_md4 },
	{ "DynamicFunc__append_from_last_output_as_base16", DynamicFunc__append_from_last_output_as_base16 },
	{ "DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix },
	{ "DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE },
	{ "DynamicFunc__crypt_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE }, // support deprecated function
	{ "DynamicFunc__append_salt", DynamicFunc__append_salt },
	{ "DynamicFunc__set_input_len_32", DynamicFunc__set_input_len_32 },
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
	{ "DynamicFunc__append_from_last_output2_to_input1_as_base16", DynamicFunc__append_from_last_output2_to_input1_as_base16 },
	{ "DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix },
	{ "DynamicFunc__append_salt2", DynamicFunc__append_salt2 },
	{ "DynamicFunc__set_input2_len_32", DynamicFunc__set_input2_len_32 },
	{ "DynamicFunc__append_input_from_input2", DynamicFunc__append_input_from_input2 },
	{ "DynamicFunc__append_input2_from_input", DynamicFunc__append_input2_from_input },
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
	{ "DynamicFunc__PHPassCrypt", DynamicFunc__PHPassCrypt },
	{ "DynamicFunc__FreeBSDMD5Crypt", DynamicFunc__FreeBSDMD5Crypt },
	{ "DynamicFunc__POCrypt", DynamicFunc__POCrypt },
	{ "DynamicFunc__set_input_len_16", DynamicFunc__set_input_len_16},
	{ "DynamicFunc__set_input2_len_16", DynamicFunc__set_input2_len_16},
	{ "DynamicFunc__set_input_len_64", DynamicFunc__set_input_len_64 },
	{ "DynamicFunc__set_input_len_100", DynamicFunc__set_input_len_100 },
	{ "DynamicFunc__set_input2_len_64", DynamicFunc__set_input2_len_64 },
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
	{ "DynamicFunc__SHA1_crypt_input1_append_input2_base16", DynamicFunc__SHA1_crypt_input1_append_input2_base16 },
	{ "DynamicFunc__SHA1_crypt_input2_append_input1_base16", DynamicFunc__SHA1_crypt_input2_append_input1_base16 },
	{ "DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16", DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16 },
	{ "DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16", DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16 },
	{ "DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16", DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16 },
	{ "DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16", DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16 },
	{ "DynamicFunc__SHA1_crypt_input1_to_output1_FINAL", DynamicFunc__SHA1_crypt_input1_to_output1_FINAL },
	{ "DynamicFunc__SHA1_crypt_input2_to_output1_FINAL", DynamicFunc__SHA1_crypt_input2_to_output1_FINAL },

	// Depricated.  These are the 'original' md5_gen version. We have changed to using Dynamic_Func__ but still 'parse'
	// and use the MD5GenBaseFunc__ script files.
	{ "MD5GenBaseFunc__clean_input",  DynamicFunc__clean_input },
	{ "MD5GenBaseFunc__clean_input_kwik", DynamicFunc__clean_input_kwik },
	{ "MD5GenBaseFunc__clean_input_full", DynamicFunc__clean_input_full },
	{ "MD5GenBaseFunc__append_keys", DynamicFunc__append_keys },
	{ "MD5GenBaseFunc__crypt", DynamicFunc__crypt_md5 },
	{ "MD5GenBaseFunc__append_from_last_output_as_base16", DynamicFunc__append_from_last_output_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE },
	{ "MD5GenBaseFunc__append_salt", DynamicFunc__append_salt },
	{ "MD5GenBaseFunc__set_input_len_32", DynamicFunc__set_input_len_32 },
	{ "MD5GenBaseFunc__clean_input2", DynamicFunc__clean_input2 },
	{ "MD5GenBaseFunc__clean_input2_kwik", DynamicFunc__clean_input2_kwik },
	{ "MD5GenBaseFunc__clean_input2_full", DynamicFunc__clean_input2_full },
	{ "MD5GenBaseFunc__append_keys2", DynamicFunc__append_keys2 },
	{ "MD5GenBaseFunc__crypt2", DynamicFunc__crypt2_md5 },
	{ "MD5GenBaseFunc__append_from_last_output2_as_base16", DynamicFunc__append_from_last_output2_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output2_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_from_last_output_to_input2_as_base16", DynamicFunc__append_from_last_output_to_input2_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_from_last_output2_to_input1_as_base16", DynamicFunc__append_from_last_output2_to_input1_as_base16 },
	{ "MD5GenBaseFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix", DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix },
	{ "MD5GenBaseFunc__append_salt2", DynamicFunc__append_salt2 },
	{ "MD5GenBaseFunc__set_input2_len_32", DynamicFunc__set_input2_len_32 },
	{ "MD5GenBaseFunc__append_input_from_input2", DynamicFunc__append_input_from_input2 },
	{ "MD5GenBaseFunc__append_input2_from_input", DynamicFunc__append_input2_from_input },
	{ "MD5GenBaseFunc__append_2nd_salt", DynamicFunc__append_2nd_salt },
	{ "MD5GenBaseFunc__append_2nd_salt2", DynamicFunc__append_2nd_salt2 },
	{ "MD5GenBaseFunc__append_userid", DynamicFunc__append_userid },
	{ "MD5GenBaseFunc__append_userid2", DynamicFunc__append_userid2 },
	{ "MD5GenBaseFunc__crypt_in1_to_out2", DynamicFunc__crypt_md5_in1_to_out2 },
	{ "MD5GenBaseFunc__crypt_in2_to_out1", DynamicFunc__crypt_md5_in2_to_out1 },
	{ "MD5GenBaseFunc__crypt_to_input_raw_Overwrite_NoLen", DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen },
	{ "MD5GenBaseFunc__crypt_to_input_raw", DynamicFunc__crypt_md5_to_input_raw },
	{ "MD5GenBaseFunc__PHPassCrypt", DynamicFunc__PHPassCrypt },
	{ "MD5GenBaseFunc__FreeBSDMD5Crypt", DynamicFunc__FreeBSDMD5Crypt },
	{ "MD5GenBaseFunc__POCrypt", DynamicFunc__POCrypt },
	{ "MD5GenBaseFunc__set_input_len_16", DynamicFunc__set_input_len_16},
	{ "MD5GenBaseFunc__set_input2_len_16", DynamicFunc__set_input2_len_16},
	{ "MD5GenBaseFunc__set_input_len_64", DynamicFunc__set_input_len_64 },
	{ "MD5GenBaseFunc__set_input2_len_64", DynamicFunc__set_input2_len_64 },
	{ "MD5GenBaseFunc__overwrite_salt_to_input1_no_size_fix", DynamicFunc__overwrite_salt_to_input1_no_size_fix },
	{ "MD5GenBaseFunc__overwrite_salt_to_input2_no_size_fix", DynamicFunc__overwrite_salt_to_input2_no_size_fix },
	{ "MD5GenBaseFunc__append_input1_from_CONST1", DynamicFunc__append_input1_from_CONST1 },
	{ "MD5GenBaseFunc__append_input1_from_CONST2", DynamicFunc__append_input1_from_CONST2 },
	{ "MD5GenBaseFunc__append_input1_from_CONST3", DynamicFunc__append_input1_from_CONST3 },
	{ "MD5GenBaseFunc__append_input1_from_CONST4", DynamicFunc__append_input1_from_CONST4 },
	{ "MD5GenBaseFunc__append_input1_from_CONST5", DynamicFunc__append_input1_from_CONST5 },
	{ "MD5GenBaseFunc__append_input1_from_CONST6", DynamicFunc__append_input1_from_CONST6 },
	{ "MD5GenBaseFunc__append_input1_from_CONST7", DynamicFunc__append_input1_from_CONST7 },
	{ "MD5GenBaseFunc__append_input1_from_CONST8", DynamicFunc__append_input1_from_CONST8 },
	{ "MD5GenBaseFunc__append_input2_from_CONST1", DynamicFunc__append_input2_from_CONST1 },
	{ "MD5GenBaseFunc__append_input2_from_CONST2", DynamicFunc__append_input2_from_CONST2 },
	{ "MD5GenBaseFunc__append_input2_from_CONST3", DynamicFunc__append_input2_from_CONST3 },
	{ "MD5GenBaseFunc__append_input2_from_CONST4", DynamicFunc__append_input2_from_CONST4 },
	{ "MD5GenBaseFunc__append_input2_from_CONST5", DynamicFunc__append_input2_from_CONST5 },
	{ "MD5GenBaseFunc__append_input2_from_CONST6", DynamicFunc__append_input2_from_CONST6 },
	{ "MD5GenBaseFunc__append_input2_from_CONST7", DynamicFunc__append_input2_from_CONST7 },
	{ "MD5GenBaseFunc__append_input2_from_CONST8", DynamicFunc__append_input2_from_CONST8 },
	{ "MD5GenBaseFunc__SSEtoX86_switch_input1", DynamicFunc__SSEtoX86_switch_input1 },
	{ "MD5GenBaseFunc__SSEtoX86_switch_input2", DynamicFunc__SSEtoX86_switch_input2 },
	{ "MD5GenBaseFunc__SSEtoX86_switch_output1", DynamicFunc__SSEtoX86_switch_output1 },
	{ "MD5GenBaseFunc__SSEtoX86_switch_output2", DynamicFunc__SSEtoX86_switch_output2 },
	{ "MD5GenBaseFunc__X86toSSE_switch_input1", DynamicFunc__X86toSSE_switch_input1 },
	{ "MD5GenBaseFunc__X86toSSE_switch_input2", DynamicFunc__X86toSSE_switch_input2 },
	{ "MD5GenBaseFunc__X86toSSE_switch_output1", DynamicFunc__X86toSSE_switch_output1 },
	{ "MD5GenBaseFunc__X86toSSE_switch_output2", DynamicFunc__X86toSSE_switch_output2 },
	{ "MD5GenBaseFunc__ToSSE", DynamicFunc__ToSSE },
	{ "MD5GenBaseFunc__ToX86", DynamicFunc__ToX86 },
	{ "MD5GenBaseFunc__setmode_unicode", DynamicFunc__setmode_unicode },
	{ "MD5GenBaseFunc__setmode_normal", DynamicFunc__setmode_normal },
	{ "MD5GenBaseFunc__base16_convert_locase", DynamicFunc__base16_convert_locase },
	{ "MD5GenBaseFunc__base16_convert_upcase", DynamicFunc__base16_convert_upcase },
	{ "MD5GenBaseFunc__append_fld0", DynamicFunc__append_fld0 },
	{ "MD5GenBaseFunc__append_fld1", DynamicFunc__append_fld1 },
	{ "MD5GenBaseFunc__append_fld2", DynamicFunc__append_fld2 },
	{ "MD5GenBaseFunc__append_fld3", DynamicFunc__append_fld3 },
	{ "MD5GenBaseFunc__append_fld4", DynamicFunc__append_fld4 },
	{ "MD5GenBaseFunc__append_fld5", DynamicFunc__append_fld5 },
	{ "MD5GenBaseFunc__append_fld6", DynamicFunc__append_fld6 },
	{ "MD5GenBaseFunc__append_fld7", DynamicFunc__append_fld7 },
	{ "MD5GenBaseFunc__append_fld8", DynamicFunc__append_fld8 },
	{ "MD5GenBaseFunc__append_fld9", DynamicFunc__append_fld9 },
	{ "MD5GenBaseFunc__append2_fld0", DynamicFunc__append2_fld0 },
	{ "MD5GenBaseFunc__append2_fld1", DynamicFunc__append2_fld1 },
	{ "MD5GenBaseFunc__append2_fld2", DynamicFunc__append2_fld2 },
	{ "MD5GenBaseFunc__append2_fld3", DynamicFunc__append2_fld3 },
	{ "MD5GenBaseFunc__append2_fld4", DynamicFunc__append2_fld4 },
	{ "MD5GenBaseFunc__append2_fld5", DynamicFunc__append2_fld5 },
	{ "MD5GenBaseFunc__append2_fld6", DynamicFunc__append2_fld6 },
	{ "MD5GenBaseFunc__append2_fld7", DynamicFunc__append2_fld7 },
	{ "MD5GenBaseFunc__append2_fld8", DynamicFunc__append2_fld8 },
	{ "MD5GenBaseFunc__append2_fld9", DynamicFunc__append2_fld9 },
	{ "MD5GenBaseFunc__SHA1_crypt_input1_append_input2_base16", DynamicFunc__SHA1_crypt_input1_append_input2_base16 },
	{ "MD5GenBaseFunc__SHA1_crypt_input2_append_input1_base16", DynamicFunc__SHA1_crypt_input2_append_input1_base16 },
	{ "MD5GenBaseFunc__SHA1_crypt_input1_overwrite_input1_base16", DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16 },
	{ "MD5GenBaseFunc__SHA1_crypt_input2_overwrite_input2_base16", DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16 },
	{ "MD5GenBaseFunc__SHA1_crypt_input1_overwrite_input2_base16", DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16 },
	{ "MD5GenBaseFunc__SHA1_crypt_input2_overwrite_input1_base16", DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16 },
	{ "MD5GenBaseFunc__SHA1_crypt_input1_to_output1_FINAL", DynamicFunc__SHA1_crypt_input1_to_output1_FINAL },
	{ "MD5GenBaseFunc__SHA1_crypt_input2_to_output1_FINAL", DynamicFunc__SHA1_crypt_input2_to_output1_FINAL },
	{ "MD5GenBaseFunc__PHPassSetup", DynamicFunc__PHPassSetup },
	{ "MD5GenBaseFunc__InitialLoadKeysToInput", DynamicFunc__InitialLoadKeysToInput },
	{ "MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2", DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2 },
	{ "MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1", DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1 },
	{ "MD5GenBaseFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32", DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32 },

	{ NULL, NULL }};

static MD5Gen_Str_Flag_t MD5Gen_Str_Flag[] =  {
	{ "MGF_NOTSSE2Safe",                  MGF_NOTSSE2Safe },
	{ "MGF_StartInX86Mode",               MGF_StartInX86Mode },
	{ "MGF_ColonNOTValid",                MGF_ColonNOTValid },
	{ "MGF_SALTED",                       MGF_SALTED },
	{ "MGF_SALTED2",                      MGF_SALTED2 },
	{ "MGF_USERNAME",                     MGF_USERNAME },
	{ "MGF_USERNAME_UPCASE",              MGF_USERNAME_UPCASE },
	{ "MGF_USERNAME_LOCASE",              MGF_USERNAME_LOCASE },
	{ "MGF_INPBASE64",                    MGF_INPBASE64 },
	{ "MGF_INPBASE64a",                   MGF_INPBASE64a },
	{ "MGF_SALT_AS_HEX",                  MGF_SALT_AS_HEX },
	{ "MFG_SALT_AS_HEX",                  MGF_SALT_AS_HEX },  // Deprecated misspelling
	{ "MGF_SALT_AS_HEX_TO_SALT2",         MGF_SALT_AS_HEX_TO_SALT2 },
	{ "MGF_INPBASE64_4x6",				  MGF_INPBASE64_4x6 },
	{ "MGF_SALT_UNICODE_B4_CRYPT",        MGF_SALT_UNICODE_B4_CRYPT },
	{ "MGF_BASE_16_OUTPUT_UPCASE",        MGF_BASE_16_OUTPUT_UPCASE },
	{ "MGF_HDAA_SALT",                    MGF_HDAA_SALT },
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
	{ "MGF_SHA1_40_BYTE_FINISH",          MGF_SHA1_40_BYTE_FINISH },
	{ "MGF_UTF8",                         MGF_UTF8 },
	{ "MGF_PASSWORD_UPCASE",              MGF_PASSWORD_UPCASE },
	{ "MGF_PASSWORD_LOCASE",              MGF_PASSWORD_LOCASE },
	{ "MGF_FULL_CLEAN_REQUIRED",          MGF_FULL_CLEAN_REQUIRED },
	{ NULL, 0 }};

static MD5Gen_Str_Flag_t MD5Gen_Str_sFlag[] =  {
	{ "MGF_KEYS_INPUT",                   MGF_KEYS_INPUT },
	{ "MGF_KEYS_CRYPT_IN2",               MGF_KEYS_CRYPT_IN2 },
	{ "MGF_KEYS_BASE16_IN1",              MGF_KEYS_BASE16_IN1 },
	{ "MGF_KEYS_BASE16_X86_IN1",          MGF_KEYS_BASE16_X86_IN1 },
	{ "MGF_KEYS_BASE16_IN1_Offset32",     MGF_KEYS_BASE16_IN1_Offset32 },
	{ "MGF_KEYS_BASE16_X86_IN1_Offset32", MGF_KEYS_BASE16_X86_IN1_Offset32 },
	{ "MGF_KEYS_UNICODE_B4_CRYPT",        MGF_KEYS_UNICODE_B4_CRYPT },
	{ "MGF_PHPassSetup",                  MGF_PHPassSetup },
	{ "MGF_POSetup",                      MGF_POSetup },
	{ "MGF_FreeBSDMD5Setup",              MGF_FreeBSDMD5Setup },
	{ "MGF_RAW_SHA1_INPUT",               MGF_RAW_SHA1_INPUT },
	{ "MGF_KEYS_INPUT_BE_SAFE",           MGF_KEYS_INPUT_BE_SAFE },  // big endian safe, i.e. the input will NEVER get swapped.  Only SHA1 is 'safe'.
	{ "MGF_SET_INP2LEN32",                MGF_SET_INP2LEN32 }, // this sets the input2 lens (in SSE2) to 32 bytes long, but only in init() call
	{ NULL, 0 }};

static DYNAMIC_Setup *pSetup;
static int nPreloadCnt;
static int nFuncCnt;
static char SetupName[128], SetupNameID[128];
static struct cfg_list *gen_source;

extern struct options_main options;

static int load_config(int which) {
	char SubSection[32];
	sprintf(SubSection, ":dynamic_%d", which);

	gen_source = cfg_get_list("list.generic", SubSection);
	if (!gen_source) {
		sprintf(SubSection, ":md5_gen(%d)", which);
		gen_source = cfg_get_list("list.generic", SubSection);
	}
	return !!gen_source;
}

char *GetFld(char **out, char *in)
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
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].flds[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].flds[j]), cp);
		}
		++nPreloadCnt;
		return 1;
	}
	if (c == 't' && !strncasecmp(Line, "TestU=", 6))
	{
		char *cp;
		if (!options.utf8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].flds[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].flds[j]), cp);
		}
		++nPreloadCnt;
		return 1;
	}
	if (c == 't' && !strncasecmp(Line, "TestA=", 6))
	{
		char *cp;
		if (options.utf8)
			return 1;
		cp = convert_old_name_if_needed(&Line[6]);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].ciphertext), cp);
		if (!pSetup->pPreloads[nPreloadCnt].ciphertext ||
			strncmp(pSetup->pPreloads[nPreloadCnt].ciphertext, SetupName, strlen(SetupName)))
			return !fprintf(stderr, "Error, invalid test line (wrong generic type):  %s\n", Line);
		cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].plaintext), cp);
		pSetup->pPreloads[nPreloadCnt].plaintext = dynamic_Demangle(pSetup->pPreloads[nPreloadCnt].plaintext, NULL);
		pSetup->pPreloads[nPreloadCnt].flds[1] = str_alloc_copy(pSetup->pPreloads[nPreloadCnt].ciphertext);
		for (j = 0; j < 10; ++j) {
			if (j==1) continue;
			cp = GetFld(&(pSetup->pPreloads[nPreloadCnt].flds[j]), cp);
		}
		++nPreloadCnt;
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
		for (i = 0; MD5Gen_Predicate[i].name; ++i)
		{
			if (!strcmp(MD5Gen_Predicate[i].name, &Line[5]))
			{
				pSetup->pFuncs[nFuncCnt++] = MD5Gen_Predicate[i].func;
				return 1;
			}
		}
		return !fprintf(stderr, "Error, unknown function:  %s\n", Line);
	}
	if (c == 'f' && !strncasecmp(Line, "Flag=", 5))
	{
		int i;
		for (i = 0; MD5Gen_Str_Flag[i].name; ++i)
		{
			if (!strcmp(MD5Gen_Str_Flag[i].name, &Line[5]))
			{
				pSetup->flags |= MD5Gen_Str_Flag[i].flag_bit;
				return 1;
			}
		}
		for (i = 0; MD5Gen_Str_sFlag[i].name; ++i)
		{
			if (!strcmp(MD5Gen_Str_sFlag[i].name, &Line[5]))
			{
				pSetup->startFlags |= MD5Gen_Str_sFlag[i].flag_bit;
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

char *dynamic_LOAD_PARSER_SIGNATURE(int which)
{
	struct cfg_line *gen_line;
	static char Sig[256];
	if (which < 1000)
		return NULL;

	if (!load_config(which))
		return NULL;

	// Setup the 'default' format name
	sprintf(Sig, "dynamic_%d: ", which);

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

int dynamic_IS_PARSER_VALID(int which)
{
	struct cfg_line *gen_line;
	if (!dynamic_LOAD_PARSER_SIGNATURE(which))
		return 0;

	gen_line = gen_source->head;
	while (gen_line)
	{
		if (!strncasecmp(gen_line->data, "ColonChar", 9))
		{
			// not sse2, but we do not handle this in the long bench.
			// we can still bench if we specify JUST this one.
			return 0;
		}
		if (strstr(gen_line->data, "MGF_ColonNOTValid"))
			return 0;  // same as above, ColonChar.
		gen_line = gen_line->next;
	}
	return 1;
}

static int Count_Items(char *Key)
{
	struct cfg_line *gen_line;
	int Cnt=0, len=strlen(Key);

	gen_line = gen_source->head;
	while (gen_line)
	{
		if (!strncasecmp(gen_line->data, Key, len))
			++Cnt;
		gen_line = gen_line->next;
	}
	return Cnt;
}

int dynamic_LOAD_PARSER_FUNCTIONS(int which, struct fmt_main *pFmt)
{
	int ret, cnt;
	struct cfg_line *gen_line;

	nPreloadCnt = 0;
	nFuncCnt = 0;

	pSetup = mem_calloc_tiny(sizeof(DYNAMIC_Setup), MEM_ALIGN_NONE);

	if (!dynamic_LOAD_PARSER_SIGNATURE(which))
	{
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Could not find section [List.Generic:dynamic_%d] in the john.ini/conf file\n", which);
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
	gen_line = gen_source->head;

	while (gen_line)
	{
		if (!dynamic_LOAD_PARSER_FUNCTIONS_LoadLINE(gen_line))
		{
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "Error parsing section [List.Generic:dynamic_%d]\nError in line %d file is %s\n", which, gen_line->number, gen_line->cfg_name);
			//error();
		}
		gen_line = gen_line->next;
	}

	ret = dynamic_SETUP(pSetup, pFmt);

	return ret;
}
