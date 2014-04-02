/*
 * Copyright 2001-2004 Unicode, Inc.
 *
 * Disclaimer
 *
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 *
 * Limitations on Rights to Redistribute This Code
 *
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

/* ---------------------------------------------------------------------

    Conversion from UTF-8 to UTF-16.  Header file.

	Stripped and modified for John the Ripper ; see ConvertUTF.h.original
	for the original content. magnum, 2009

    Author: Mark E. Davis, 1994.
    Rev History: Rick McGowan, fixes & updates May 2001.
		 Fixes & updates, Sept 2001.

------------------------------------------------------------------------ */

/* ---------------------------------------------------------------------
    The following definitions are compiler-specific.
    The C standard does not guarantee that wchar_t has at least
    16 bits, so wchar_t is no less portable than unsigned short!
    All should be unsigned values to avoid sign extension during
    bit mask & shift operations.
------------------------------------------------------------------------ */

#ifndef _CONVERTUTF_H
#define _CONVERTUTF_H

#include "options.h"
#include "common.h"

#ifdef _MSC_VER
#define inline _inline
#endif

/* Load the 'case-conversion' tables. */
#define UNICODE_MS_OLD  1
#define UNICODE_MS_NEW  2
#define UNICODE_UNICODE 3

/* Arbitrary CP-to-integer mapping, for switches, arrays etc. */
#define AUTO           -1 /* try to auto-detect UTF-8 */
#define CP_UNDEF        0
#define ASCII           1
#define CP437           2
#define CP737           3
#define CP850           4
#define CP852           5
#define CP858           6
#define CP866           7
#define CP1250          8
#define CP1251          9
#define CP1252          10
#define CP1253          11
#define ISO_8859_1      12
#define ISO_8859_2      13
#define ISO_8859_7      14
#define ISO_8859_15     15
#define KOI8_R          16
#define UTF_8           17
#define CP_ARRAY        18 /* always highest, may specify array sizes */

#define CP_DOS          1
#define CP_WIN          2
#define CP_ISO          3

#define CP_DOS_LO       2
#define CP_DOS_HI       7
#define CP_WIN_LO	8
#define CP_WIN_HI	11
#define CP_ISO_LO	12
#define CP_ISO_HI	15

typedef ARCH_WORD_32 UTF32;	/* at least 32 bits */
typedef unsigned short UTF16;	/* at least 16 bits */
typedef unsigned char UTF8;	/* typically 8 bits */

/* Some fundamental constants */
#define UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
#define UNI_MAX_BMP (UTF32)0x0000FFFF
#define UNI_MAX_UTF16 (UTF32)0x0010FFFF
#define UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
#define UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF

/* These are used in NT_fmt.c */
extern const UTF32 offsetsFromUTF8[];
extern const char opt_trailingBytesUTF8[64];

/*
 * Convert to UTF-16LE from UTF-8.
 * 'maxtargetlen' is max. number of characters (as opposed to bytes) in output,
 * eg. PLAINTEXT_LENGTH.
 * 'sourcelen' can be strlen(source).
 * Returns number of UTF16 characters (as opposed to bytes) of resulting
 * output. If return is negative, eg. -32, it means 32 characters of INPUT were
 * used and then we had to truncate. Either because we ran out of maxtargetlen,
 * or because input was not valid after that point (eg. illegal UTF-8 sequence).
 * To get the length of output in that case, use strlen16(target).
 */
extern int utf8_to_utf16(UTF16 *target, unsigned int maxtargetlen,
                         const UTF8 *source, unsigned int sourcelen);

/*
 * Convert to UTF-16LE from whatever encoding is used (--encoding aware).
 * 'maxdstlen' is max. number of characters (as opposed to bytes) in output,
 * eg. PLAINTEXT_LENGTH.
 * 'srclen' can be strlen(src).
 * Returns number of UTF16 characters (as opposed to bytes) of resulting
 * output. If return is negative, eg. -32, it means 32 characters of INPUT were
 * used and then we had to truncate. Either because we ran out of maxdstlen, or
 * because input was not valid after that point (eg. illegal UTF-8 sequence).
 * To get the length of output in that case, use strlen16(dst).
 */
extern int enc_to_utf16(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src,
                        unsigned int srclen);

/*
 * Convert to UTF-16BE, otherwise like above.
 */
extern int enc_to_utf16_be(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src,
                           unsigned int srclen);

/* Thread-safe conversion from codepage to UTF-8 */
UTF8 * enc_to_utf8_r (char *src, UTF8* dst, int dstlen);

/* Thread-safe conversion from UTF-8 to codepage */
char * utf8_to_enc_r (UTF8 *src, char* dst, int dstlen);

/* Convert back to UTF-8 (for get_key without a saved_plain) */
extern UTF8 * utf16_to_utf8 (const UTF16* source);
extern UTF8 * utf16_to_utf8_r (UTF8 *dst, int dst_len, const UTF16* source);

/* Convert back to UTF-8 or codepage (for get_key without a saved_plain)
   from UTF-16LE (regardless of host architecture) */
extern UTF8 * utf16_to_enc (const UTF16* source);
extern UTF8 * utf16_to_enc_r (UTF8 *dst, int dst_len, const UTF16* source);

// Even after initializing for UTF-8 we still have some codepage that
// we can opt to convert to/from.
extern char *utf16_to_cp (const UTF16* source);
extern char *utf8_to_cp_r (char *src, char* dst, int dstlen);
extern char *cp_to_utf8_r (char *src, char* dst, int dstlen);

/* Return length (in characters) of a UTF-16 string */
/* Number of octets is the result * sizeof(UTF16)  */
extern unsigned int strlen16(const UTF16 * str);

/* Return length (in characters) of a UTF-8 string */
/* Will return a "truncated" length if fed with invalid data. */
extern unsigned int strlen8(const UTF8 *source);

/* Check if a string is valid UTF-8 */
extern int valid_utf8(const UTF8 *source);

/* Create an NT hash from a ISO-8859 or UTF-8 string (--encoding= aware) */
extern int E_md4hash(const UTF8 * passwd, unsigned int len, unsigned char *p16);

extern void listEncodings(void);
extern void initUnicode(int type);
extern UTF16 ucs2_upcase[0x10000];   /* NOTE, for multi-char converts, we put a 1 into these */
extern UTF16 ucs2_downcase[0x10000]; /* array. The 1 is not valid, just an indicator to check the multi-char */

/* single char conversion inlines. Inlines vs macros, so that we get type 'safety'           */
/* NOTE these functions do NOT return multi UTF16 conversion characters, so they are         */
/* only 'partly' proper.  The enc_to_utf16_uc() and  enc_to_utf16_lc() do full conversions as    */
/* does the utf16_lc() and utf16_uc().  Full conversion uses the utc_*case[] arrays, but  it */
/* also uses the 1 UTC2 to multi UTC2 lookup table to do things 'properly'.                  */
/* NOTE low2up_ansi() does not handle 0xDF to "SS" conversion, since it is 1 to many.       */
static inline unsigned char low2up_ansi(unsigned char c) {if ((ucs2_upcase[c]&0xFFFE)&&ucs2_upcase[c]<0x100) return (unsigned char)ucs2_upcase[c]; return c; }
static inline unsigned char up2low_ansi(unsigned char c) {if ((ucs2_downcase[c]&0xFFFE)&&ucs2_downcase[c]<0x100) return (unsigned char)ucs2_downcase[c]; return c; }
static inline UTF16 low2up_u16(UTF16 w) {if (ucs2_upcase[w]&0xFFFE) return ucs2_upcase[w]; return w; }
static inline UTF16 up2low_u16(UTF16 w) {if (ucs2_downcase[w]&0xFFFE) return ucs2_downcase[w]; return w; }

/* Convert to UTF-16LE from UTF-8 or ISO-8859-1 depending on --encoding= flag, and upcase/lowcase at same time */
//extern int enc_to_utf16_uc(UTF16 * dst, unsigned int maxdstlen, const UTF8 * src, unsigned int srclen);
//extern int enc_to_utf16_lc(UTF16 * dst, unsigned int maxdstlen, const UTF8 * src, unsigned int srclen);

// Lowercase UTF-16 string
extern int utf16_lc(UTF16 *dst, unsigned dst_len, const UTF16 *src, unsigned src_len);

// Uppercase UTF-16 string
extern int utf16_uc(UTF16 *dst, unsigned dst_len, const UTF16 *src, unsigned src_len);

// Lowercase UTF-8 or codepage string
extern int enc_lc(UTF8 *dst, unsigned dst_len, const UTF8 *src, unsigned src_len);

// Uppercase UTF-8 or codepage string
extern int enc_uc(UTF8 *dst, unsigned dst_len, const UTF8 *src, unsigned src_len);

// Encoding-aware strlwr(): in-place lowercase of string
extern char *enc_strlwr(char *s);

// Encoding-aware in-place uppercase of string
extern char *enc_strupper(char *s);

// Used by NT's inline set_key_helper_encoding()
extern UTF16 CP_to_Unicode[0x100];

// Used by various formats uc/lc
extern UTF8  CP_up[0x100];
extern UTF8  CP_down[0x100];

// Used by single.c and loader.c
extern UTF8 CP_isLetter[0x100];
extern UTF8 CP_isSeparator[0x100];

// Conversion between encoding names and integer id
extern int cp_name2id(char *encoding);
extern char *cp_id2name(int encoding);
extern char *cp_id2macro(int encoding);
//
// NOTE! Please read the comments in formats.h for FMT_UNICODE and FMT_UTF8
//

/* --------------------------------------------------------------------- */
#endif				/* _CONVERTUTF_H */
