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
 * Interface functions and data structures required to make this
 * work, since it is split over multiple .c source files.
 *
 * Renamed and changed from md5_gen* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 * Added SHA2 (SHA224, SHA256, SHA384, SHA512), GOST, Whirlpool crypt types.
 * Whirlpool use oSSSL if OPENSSL_VERSION_NUMBER >= 0x10000000, otherwise use sph_* code.
 */

#if !defined (__DYNAMIC___H)
#define __DYNAMIC___H

#include "arch.h"
#ifndef DYNAMIC_DISABLED

#include "sse-intrinsics.h"
#include <openssl/opensslv.h>

#ifdef _OPENMP
#define DYNA_OMP_PARAMS unsigned int first, unsigned int last, unsigned int tid
#define DYNA_OMP_PARAMSm unsigned int first, unsigned int last, unsigned int tid,
#define DYNA_OMP_PARAMSd first, last, tid
#define DYNA_OMP_PARAMSdm first, last, tid,
#else
#define DYNA_OMP_PARAMS
#define DYNA_OMP_PARAMSm
#define DYNA_OMP_PARAMSd
#define DYNA_OMP_PARAMSdm
#endif

typedef void(*DYNAMIC_primitive_funcp)(DYNA_OMP_PARAMS);

typedef struct DYNAMIC_Constants_t
{
	int len;
	char *Const;
} DYNAMIC_Constants;

// These are the 'flags' that specify certain characterstics of the format.
// Things like salted, not sse2, and special 'loading' of the keys.
#define MGF_NO_FLAG                  0x00000000
#define MGF_NOTSSE2Safe              0x00000001
#define MGF_ColonNOTValid            0x00000002
#define MGF_SALTED                   0x00000004
#define MGF_SALTED2                 (0x00000008|MGF_SALTED)
#define MGF_USERNAME                (0x00000010|MGF_SALTED)
#define MGF_USERNAME_UPCASE         (0x00000020|MGF_USERNAME)
#define MGF_USERNAME_LOCASE         (0x00000040|MGF_USERNAME)
// MGF_INPBASE64 uses e_b64_cryptBS from base64_convert.h
#define MGF_INPBASE64		         0x00000080
#define MGF_SALT_AS_HEX		        (0x00000100|MGF_SALTED)
#define MGF_INPBASE64_4x6			 0x00000200
#define MGF_StartInX86Mode           0x00000400
#define MGF_SALT_AS_HEX_TO_SALT2    (0x00000800|MGF_SALTED)
#define MGF_SALT_UNICODE_B4_CRYPT   (0x00001000|MGF_SALTED)
#define MGF_BASE_16_OUTPUT_UPCASE    0x00002000
// MGF_INPBASE64b uses e_b64_crypt from base64_convert.h
#define MGF_INPBASE64b		         0x00004000
#define MGF_FLDx_BIT                 0x00008000
#define MGF_FLD0                    (0x00008000|MGF_SALTED)
#define MGF_FLD1                    (0x00010000|MGF_SALTED)
#define MGF_FLD2                    (0x00020000|MGF_SALTED)
#define MGF_FLD3                    (0x00040000|MGF_SALTED)
#define MGF_FLD4                    (0x00080000|MGF_SALTED)
#define MGF_FLD5                    (0x00100000|MGF_SALTED)
#define MGF_FLD6                    (0x00200000|MGF_SALTED)
#define MGF_FLD7                    (0x00400000|MGF_SALTED)
#define MGF_FLD8                    (0x00800000|MGF_SALTED)
#define MGF_FLD9                    (0x01000000|MGF_SALTED)
#define MGF_INPBASE64a               0x00000000 // no longer used.
#define MGF_INPBASE64m               0x02000000
#define MGF_UTF8                     0x04000000
#define MGF_PASSWORD_UPCASE          0x08000000
#define MGF_PASSWORD_LOCASE          0x10000000
#define MGF_FULL_CLEAN_REQUIRED      0x20000000
#define MGF_FLAT_BUFFERS             0x40000000
// open                              0x80000000

// These are special loader flags.  They specify that keys loads are 'special', and
// do MORE than simply load keys into the keys[] array.  They may preload the keys
// into input, may load keys into keys, but call crypt, may do that and call base16
// convert, and may even point different functions than 'defalt' (such as phpass).
// If high bit of flags is set, then at least ONE of these flags has been used
#define MGF_KEYS_INPUT                   0x00000001
#define MGF_KEYS_CRYPT_IN2               0x00000002
#define MGF_KEYS_BASE16_IN1              0x00000004
#define MGF_KEYS_BASE16_IN1_Offset32     0x00000008
#define MGF_KEYS_BASE16_X86_IN1          0x00000010
#define MGF_KEYS_BASE16_X86_IN1_Offset32 0x00000020
#define MGF_PHPassSetup                  0x00000040
#define MGF_POSetup                      0x00000080
#define MGF_POOR_OMP                     0x00000100
#define MGF_FreeBSDMD5Setup              0x00000000
//#define MGF_RAW_SHA1_INPUT             0x00000200 // no longer 'used'
#define MGF_RAW_SHA1_INPUT               0x00000000
// open                                  0x00000200
#define MGF_KEYS_INPUT_BE_SAFE           0x00000400
#define MGF_SET_INP2LEN32                0x00000800
// the unicode_b4_crypt does a unicode convert, prior to crypt_in2, base16-in1, etc.  It can NOT be used with KEYS_INPUT.
#define MGF_KEYS_UNICODE_B4_CRYPT        0x00001000
#define MGF_SOURCE                       0x00002000
#define MGF_KEYS_BASE16_IN1_SHA1         0x00004000
#define MGF_KEYS_BASE16_IN1_SHA256       0x00008000
// open                                  0x00010000
// open                                  0x00020000
// open                                  0x00040000
// open                                  0x00080000
#define MGF_INPUT_20_BYTE                0x00100000
#define MGF_INPUT_24_BYTE                0x00200000
#define MGF_INPUT_28_BYTE                0x00400000
#define MGF_INPUT_32_BYTE                0x00800000
#define MGF_INPUT_40_BYTE                0x01000000
#define MGF_INPUT_48_BYTE                0x02000000
#define MGF_INPUT_64_BYTE                0x04000000
// open                                  0x08000000
// open                                  0x10000000
// open                                  0x20000000
// open                                  0x40000000
// open                                  0x80000000

typedef struct DYNAMIC_Setup_t
{
	char *szFORMAT_NAME;  // md5(md5($p).$s) etc

	// Ok, this will be the functions to 'use'.
	// This should be a 'null' terminated list.  5000 is MAX.
	DYNAMIC_primitive_funcp *pFuncs;
	struct fmt_tests *pPreloads;
	DYNAMIC_Constants *pConstants;
	unsigned flags;
	unsigned startFlags;
	int SaltLen;			// these are SSE lengths
	int MaxInputLen;		// SSE length.  If 0, then set to 55-abs(SaltLen)
	int MaxInputLenX86;		// if zero, then use PW len set to 110-abs(SaltLen) (or 110-abs(SaltLenX86), if it is not 0)
	int SaltLenX86;			// if zero, then use salt len of SSE
} DYNAMIC_Setup;

/* See dynamic_fmt.c for description */
extern int dynamic_allow_rawhash_fixup;

int dynamic_SETUP(DYNAMIC_Setup *, struct fmt_main *pFmt);
int dynamic_IS_VALID(int i, int force);
int dynamic_real_salt_length(struct fmt_main *pFmt);
void dynamic_DISPLAY_ALL_FORMATS();
char *RemoveHEX(char *output, char *input);
const char *dynamic_Find_Function_Name(DYNAMIC_primitive_funcp p);

// Function used to 'link' a thin format into dynamic.  See PHPS_fmt.c for an example.
struct fmt_main *dynamic_THIN_FORMAT_LINK(struct fmt_main *pFmt, char *ciphertext, char *orig_sig, int bInitAlso);
int text_in_dynamic_format_already(struct fmt_main *pFmt, char *ciphertext);

int dynamic_Register_formats(struct fmt_main **ptr);
struct fmt_main * dynamic_Register_local_format();

int dynamic_RESERVED_PRELOAD_SETUP(int cnt, struct fmt_main *pFmt);
char *dynamic_PRELOAD_SIGNATURE(int cnt);
int dynamic_IS_PARSER_VALID(int which);

// This one is called in the .pot writing.  We 'fixup' salts which contain ':' chars, or other
// chars which cause problems (like the $ char).
char *dynamic_FIX_SALT_TO_HEX(char *ciphertext);

// Here are the 'parser' functions (i.e. user built stuff in john.conf)
int  dynamic_LOAD_PARSER_FUNCTIONS(int which, struct fmt_main *pFmt);
char *dynamic_LOAD_PARSER_SIGNATURE(int which);
struct fmt_main *dynamic_LOCAL_FMT_FROM_PARSER_FUNCTIONS(const char *Script, int *type, struct fmt_main *pFmt,  char *(*Convert)(char *Buf, char *ciphertext, int in_load));

// extern demange.  Turns \xF7 into 1 char.  Turns \x1BCA into "esc C A" string (3 bytes).  Turns abc\\123 into abc\123, etc.
// NOTE, return the length here.  Since we may have this line:  \x1BCA\x00\x01  we have an embedded NULL.  Thus strlen type
// functions can not be used, and this demangle MUST be used to set the length.
char *dynamic_Demangle(char *Line, int *Len);

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(a[0]))

//
// These functions MUST be of type:   void function() (or void function(int,int) for OMP builds)
// these are the 'base' predicate functions used in
// building a generic MD5 attack algorithm.
//

extern void DynamicFunc__clean_input(DYNA_OMP_PARAMS);
extern void DynamicFunc__clean_input_kwik(DYNA_OMP_PARAMS);
extern void DynamicFunc__clean_input_full(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_keys(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_keys_pad16(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_keys_pad20(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt_md5(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt_md4(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_from_last_output_as_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_salt(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input_len_16(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input_len_20(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input_len_32(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input_len_40(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input_len_64(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input_len_100(DYNA_OMP_PARAMS);

extern void DynamicFunc__clean_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__clean_input2_kwik(DYNA_OMP_PARAMS);
extern void DynamicFunc__clean_input2_full(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_keys2(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt2_md5(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt2_md4(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_from_last_output2_as_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_from_last_output_to_input2_as_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_from_last_output2_to_input1_as_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_salt2(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input2_len_16(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input2_len_20(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input2_len_32(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input2_len_40(DYNA_OMP_PARAMS);
extern void DynamicFunc__set_input2_len_64(DYNA_OMP_PARAMS);

extern void DynamicFunc__append_from_last_output2_as_raw(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_from_last_output2_as_raw(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_from_last_output1_as_raw(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_from_last_output1_as_raw(DYNA_OMP_PARAMS);

extern void DynamicFunc__overwrite_salt_to_input1_no_size_fix(DYNA_OMP_PARAMS);
extern void DynamicFunc__overwrite_salt_to_input2_no_size_fix(DYNA_OMP_PARAMS);

extern void DynamicFunc__append_input_from_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_input(DYNA_OMP_PARAMS);

// NOTE, these are input=input+input and input2=input2+input2
// (must be careful to not use strcat type stuff).  Added for types like
// sha256(sha256($p).sha256($p)) so that we can still keep keys in input1,
// and simply double the output of input2, without having to double compute
// sha256($p)
extern void DynamicFunc__append_input_from_input(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_input2(DYNA_OMP_PARAMS);

extern void DynamicFunc__append_2nd_salt(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_2nd_salt2(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_userid(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_userid2(DYNA_OMP_PARAMS);

extern void DynamicFunc__crypt_md5_in1_to_out2(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt_md5_in2_to_out1(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt_md4_in1_to_out2(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt_md4_in2_to_out1(DYNA_OMP_PARAMS);

extern void DynamicFunc__append_input1_from_CONST1(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST2(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST3(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST4(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST5(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST6(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST7(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input1_from_CONST8(DYNA_OMP_PARAMS);

extern void DynamicFunc__append_input2_from_CONST1(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST2(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST3(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST4(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST5(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST6(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST7(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_input2_from_CONST8(DYNA_OMP_PARAMS);

extern void DynamicFunc__append_fld0(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld1(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld2(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld3(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld4(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld5(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld6(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld7(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld8(DYNA_OMP_PARAMS);
extern void DynamicFunc__append_fld9(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld0(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld1(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld2(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld3(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld4(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld5(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld6(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld7(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld8(DYNA_OMP_PARAMS);
extern void DynamicFunc__append2_fld9(DYNA_OMP_PARAMS);

// These are no-ops if built in x86 mode.  But in SSE2 builds, they do
// allow us to switch back and forth from SSE to X86 mode (and back again)
// they also convert data (only convert the NEEDED) stored data.  Additional
// fields will cost time, and are not needed.
extern void DynamicFunc__SSEtoX86_switch_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SSEtoX86_switch_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SSEtoX86_switch_output1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SSEtoX86_switch_output2(DYNA_OMP_PARAMS);
extern void DynamicFunc__X86toSSE_switch_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__X86toSSE_switch_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__X86toSSE_switch_output1(DYNA_OMP_PARAMS);
extern void DynamicFunc__X86toSSE_switch_output2(DYNA_OMP_PARAMS);
extern void DynamicFunc__ToSSE(DYNA_OMP_PARAMS);
extern void DynamicFunc__ToX86(DYNA_OMP_PARAMS);
// set unicode mode.
extern void DynamicFunc__setmode_unicode(DYNA_OMP_PARAMS);
extern void DynamicFunc__setmode_normal(DYNA_OMP_PARAMS);
// Changing upper case and lower case base-16 conversion routines
extern void DynamicFunc__base16_convert_locase(DYNA_OMP_PARAMS);
extern void DynamicFunc__base16_convert_upcase(DYNA_OMP_PARAMS);

extern void DynamicFunc__LargeHash_OUTMode_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__LargeHash_OUTMode_base16u(DYNA_OMP_PARAMS);
extern void DynamicFunc__LargeHash_OUTMode_base64(DYNA_OMP_PARAMS);
extern void DynamicFunc__LargeHash_OUTMode_base64_nte(DYNA_OMP_PARAMS); // no trailing = chars, for non length%3 !=0
extern void DynamicFunc__LargeHash_OUTMode_raw(DYNA_OMP_PARAMS);

extern void DynamicFunc__SHA1_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__SHA224_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__SHA256_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__SHA384_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__SHA512_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__GOST_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__WHIRLPOOL_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__Tiger_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__MD5_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__MD4_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__RIPEMD128_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__RIPEMD160_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__RIPEMD256_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);

extern void DynamicFunc__RIPEMD320_crypt_input1_append_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_append_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input1_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_overwrite_input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input1_to_output1_FINAL(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_to_output1_FINAL(DYNA_OMP_PARAMS);


// These 3 dump the raw crypt back into input (only at the head of it).
// they are for phpass, wordpress, etc.
extern void DynamicFunc__crypt_md5_to_input_raw(DYNA_OMP_PARAMS);
extern void DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen(DYNA_OMP_PARAMS);
// NOTE, the below line is called 'one' time.  It calls the 'normal' intrinsic loading
// for the lengths.  The lengths are not modified, but are need to be set ONCE.  From that point on,
// we simply call the DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen and the intrincs do NOT
// call SSE_Intrinsics_LoadLens within the
// DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen function)   Splitting this up into 2, gives
// us a 1 or 2% speed increase.
extern void DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE(DYNA_OMP_PARAMS);

// special for phpass
extern void DynamicFunc__PHPassCrypt(DYNA_OMP_PARAMS);
// special for PO
extern void DynamicFunc__POCrypt(DYNA_OMP_PARAMS);
// special for OpenBSD MD5 and Apache MD5
extern void DynamicFunc__FreeBSDMD5Crypt(DYNA_OMP_PARAMS);

// End of generic md5 'types' and helpers

// Depricated 'functions'  These are now 'flags'. We handle them by 'adding' the proper flags, but allow the script
// to run IF the user has these fake functions as the first function.
extern void DynamicFunc__PHPassSetup(DYNA_OMP_PARAMS);
extern void DynamicFunc__InitialLoadKeysToInput(DYNA_OMP_PARAMS);
extern void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2(DYNA_OMP_PARAMS);
extern void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1(DYNA_OMP_PARAMS);
extern void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32(DYNA_OMP_PARAMS);


// These are actually NOW depricated.  We have left 'thin' version in dynamic_fmt.c
// that call the 2 'thick' functions needed. However, These should NOT be used any more.
extern void DynamicFunc__SHA1_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA224_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA256_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA384_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__SHA512_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__GOST_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__Tiger_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD128_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD160_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD256_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__RIPEMD320_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD5_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input1_append_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_append_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input1_overwrite_input1_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input1_overwrite_input2_base16(DYNA_OMP_PARAMS);
extern void DynamicFunc__MD4_crypt_input2_overwrite_input1_base16(DYNA_OMP_PARAMS);

#endif /* DYNAMIC_DISABLED */

#endif // __DYNAMIC___H
