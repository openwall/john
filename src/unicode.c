/*
    Conversion from UTF-8 to UTF-16.  Source code file.

	Stripped and modified for John the Ripper ; see ConvertUTF.[ch].original
	for the original content. magnum, 2009, 2010, 2011

	What was left in smbencrypt.c is now moved to these files too.
*/
/*
   (from smbencrypt.c)

   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Modified by Jeremy Allison 1995.
   (and hacked further by others)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/*
 * (from ConvertUTF.c)
 *
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

    Author: Mark E. Davis, 1994.
    Rev History: Rick McGowan, fixes & updates May 2001.
    Sept 2001: fixed const & error conditions per
	mods suggested by S. Parent & A. Lillich.
    June 2002: Tim Dodd added detection and handling of incomplete
	source sequences, enhanced error detection, added casts
	to eliminate compiler warnings.
    July 2003: slight mods to back out aggressive FFFE detection.
    Jan 2004: updated switches in from-UTF8 conversions.
    Oct 2004: updated to use UNI_MAX_LEGAL_UTF32 in UTF-32 conversions.

    See the header file "ConvertUTF.h" for complete documentation.


------------------------------------------------------------------------ */

#include <string.h>

#include "common.h"
#include "arch.h"
#include "byteorder.h"
#include "unicode.h"
#include "UnicodeData.h"
#include "encoding_data.h"
#include "misc.h"
#include "config.h"
#include "md4.h"
#if !defined (NOT_JOHN)
#include "options.h"
#else
struct opts { int flags; };
#define FLG_UTF8 1
struct opts options;
#endif

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

#if !defined(int16) && !defined(HAVE_INT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define int16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define int16 short
#endif /* SIZEOF_SHORT != 4 */
#endif

UTF16 ucs2_upcase[0x10000];
UTF16 ucs2_downcase[0x10000];

/*
 * These are used to convert from an encoding, into unicode.  iso-8859-1 is trivial
 * (it is a simple direct 1 to 1 conversion.  however, the others are not quite
 * that trivial. Thus to keep the code 'simple', we simply use an array lookup
 * for ALL encoding translations.
 * There is a 'to' unicode
 *          a 'from' unicode
 *          a toUP  and a todown array
 * These array values are properly filled in at init() once we know the proper code page the user is using.
 */
UTF16 CP_to_Unicode[0x100];
static UTF8 CP_from_Unicode[0x10000];
UTF8 CP_up[0x100];
UTF8 CP_down[0x100];
static int UnicodeType = -1;

/*
 * This is used by single.c for determining that a character is a letter
 */
UTF8 CP_isLetter[0x100];
UTF8 CP_isSeparator[0x100];

#if ARCH_LITTLE_ENDIAN
#define BE_FIX(a) a
#else
#define BE_FIX(a) ( ((a&0xFF00)>>8) | ((a&0xFF)<<8) )
#endif

//Init values for NT hashing
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

/*
 * Once the bits are split out into bytes of UTF-8, this is a mask OR-ed
 * into the first byte, depending on how many bytes follow. There are
 * as many entries in this table as there are UTF-8 sequence types.
 * (I.e., one byte sequence, two byte... etc.). Remember that sequencs
 * for *legal* UTF-8 will be 4 or fewer bytes total.
 */
static const UTF8 firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };

/*
 * Magic values subtracted from a buffer value during UTF8 conversion.
 * This table contains as many values as there might be trailing bytes
 * in a UTF-8 sequence. (Cut-down version, 4 and 5 are illegal).
 */
const UTF32 offsetsFromUTF8[6] = { 0x00000000UL, 0x00003080UL, 0x000E2080UL,
		     0x03C82080UL, 0xFA082080UL, 0x82082080UL };

/*
 * Index into the table below with the first byte of a UTF-8 sequence to
 * get the number of trailing bytes that are supposed to follow it.
 * Note that *legal* UTF-8 values can't have 4 or 5-bytes. The table is
 * left as-is for anyone who may want to do such conversion, which was
 * allowed in earlier algorithms.
 *
 * Cut-down version for speed. Use with [c & 0x3f]
 */
const char opt_trailingBytesUTF8[64] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
};

static const int halfShift  = 10; /* used for shifting by 10 bits */

static const UTF32 halfBase = 0x0010000UL;
static const UTF32 halfMask = 0x3FFUL;

#define UNI_SUR_HIGH_START  (UTF32)0xD800
#define UNI_SUR_HIGH_END    (UTF32)0xDBFF
#define UNI_SUR_LOW_START   (UTF32)0xDC00
#define UNI_SUR_LOW_END     (UTF32)0xDFFF

/* Convert UTF-8 string to UTF-16LE, regardless of arch
 *
 * This code is optimised for speed. Errors result in truncation.
 *
 * Normally returns number of UTF16 characters converted. If truncated,
 * the number of UTF8 characters that was successfully read is returned
 * instead (negated), so we can truncate our saved_plain or whatever
 * accordingly.
 *
 * The original function in ConvertUTF.c is called ConvertUTF8toUTF16() */
inline int utf8_to_utf16(UTF16 *target, unsigned int len, const UTF8 *source,
                         unsigned int sourceLen)
{
	const UTF16 *targetStart = target;
	const UTF16 *targetEnd = target + len;
	const UTF8 *sourceStart = source;
	const UTF8 *sourceEnd = source + sourceLen;
	UTF32 ch;
	unsigned int extraBytesToRead;

	while (source < sourceEnd) {
		if (*source < 0xC0) {
#if ARCH_LITTLE_ENDIAN
			*target++ = (UTF16)*source++;
#else
			UTF8 val = *source++;
			SSVAL(target, 0, val);
			++target;
#endif
			if (*source == 0)
				break;
			if (target >= targetEnd) {
				*target = 0;
				return -1 * (source - sourceStart);
			}
			continue;
		}
		ch = *source;
		// The original code in ConvertUTF.c has a much larger (slower)
		// lookup table including zeros. This point must not be reached
		// with *source < 0xC0
		extraBytesToRead =
		    opt_trailingBytesUTF8[ch & 0x3f];
		if (source + extraBytesToRead >= sourceEnd) {
			*target = 0;
			return -1 * (source - sourceStart);
		}
		switch (extraBytesToRead) {
		case 3:
			ch <<= 6;
			ch += *++source;
		case 2:
			ch <<= 6;
			ch += *++source;
		case 1:
			ch <<= 6;
			ch += *++source;
			++source;
			break;
		default:
			*target = 0;
			return -1 * (source - sourceStart);
		}
		ch -= offsetsFromUTF8[extraBytesToRead];
#if 0 /* This only supports UCS-2 */
#if ARCH_LITTLE_ENDIAN
		*target++ = (UTF16)ch;
#else
		SSVAL(target, 0, ch);
		++target;
#endif
#else /* This supports full UTF-16 with surrogate pairs */
		if (ch <= UNI_MAX_BMP) {  /* Target is a character <= 0xFFFF */
#if ARCH_LITTLE_ENDIAN
			*target++ = (UTF16)ch;
#else
			SSVAL(target, 0, ch);
			++target;
#endif
		} else {  /* target is a character in range 0xFFFF - 0x10FFFF. */
			if (target + 1 >= targetEnd) {
				source -= (extraBytesToRead+1); /* Back up source pointer! */
				*target = 0;
				return -1 * (source - sourceStart);
			}
			ch -= halfBase;
#if ARCH_LITTLE_ENDIAN
			*target++ = (UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START);
			*target++ = (UTF16)((ch & halfMask) + UNI_SUR_LOW_START);
#else
			SSVAL(target, 0, (UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START));
			++target;
			SSVAL(target, 0, (UTF16)((ch & halfMask) + UNI_SUR_LOW_START));
			++target;
#endif
		}
#endif
		if (*source == 0)
			break;
		if (target >= targetEnd) {
			*target = 0;
			return -1 * (source - sourceStart);
		}
	}
	*target = 0;		// Null-terminate
	return (target - targetStart);
}

/* Convert to UTF-16BE instead, regardless of arch */
static
#ifndef __SUNPRO_C
inline
#endif
int utf8_to_utf16_be(UTF16 *target, unsigned int len, const UTF8 *source,
                            unsigned int sourceLen)
{
	const UTF16 *targetStart = target;
	const UTF16 *targetEnd = target + len;
	const UTF8 *sourceStart = source;
	const UTF8 *sourceEnd = source + sourceLen;
	UTF32 ch;
	unsigned int extraBytesToRead;

	while (source < sourceEnd) {
		if (*source < 0xC0) {
#if ARCH_LITTLE_ENDIAN
			*target++ = (UTF16)*source++ << 8;
#else
			*target++ = (UTF16)*source++;
#endif
			if (*source == 0)
				break;
			if (target >= targetEnd) {
				*target = 0;
				return -1 * (source - sourceStart);
			}
			continue;
		}
		ch = *source;
		// The original code in ConvertUTF.c has a much larger (slower)
		// lookup table including zeros. This point must not be reached
		// with *source < 0xC0
		extraBytesToRead =
		    opt_trailingBytesUTF8[ch & 0x3f];
		if (source + extraBytesToRead >= sourceEnd) {
			*target = 0;
			return -1 * (source - sourceStart);
		}
		switch (extraBytesToRead) {
		case 3:
			ch <<= 6;
			ch += *++source;
		case 2:
			ch <<= 6;
			ch += *++source;
		case 1:
			ch <<= 6;
			ch += *++source;
			++source;
			break;
		default:
			*target = 0;
			return -1 * (source - sourceStart);
		}
		ch -= offsetsFromUTF8[extraBytesToRead];
#if 0 /* This only supports UCS-2 */
#if ARCH_LITTLE_ENDIAN
		*target++ = (UTF16)ch << 8 | (UTF16)ch >> 8;
#else
		*target++ = (UTF16)ch;
#endif
#else /* This supports full UTF-16 with surrogate pairs */
		if (ch <= UNI_MAX_BMP) {  /* Target is a character <= 0xFFFF */
#if ARCH_LITTLE_ENDIAN
			*target++ = (UTF16)ch << 8 | (UTF16)ch >> 8;
#else
			*target++ = (UTF16)ch;
#endif
		} else {  /* target is a character in range 0xFFFF - 0x10FFFF. */
			if (target + 1 >= targetEnd) {
				source -= (extraBytesToRead+1); /* Back up source pointer! */
				*target = 0;
				return -1 * (source - sourceStart);
			}
			ch -= halfBase;
#if ARCH_LITTLE_ENDIAN
			*target = (UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START);
			*target = *target << 8 | *target >> 8;
			target++;
			*target = (UTF16)((ch & halfMask) + UNI_SUR_LOW_START);
			*target = *target << 8 | *target >> 8;
			target++;
#else
			*target++ = (UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START);
			*target++ = (UTF16)((ch & halfMask) + UNI_SUR_LOW_START);
#endif
		}
#endif
		if (*source == 0)
			break;
		if (target >= targetEnd) {
			*target = 0;
			return -1 * (source - sourceStart);
		}
	}
	*target = 0;		// Null-terminate
	return (target - targetStart);
}

/* Convert from current encoding to UTF-16LE regardless of system arch
 *
 * This version converts from UTF-8 if the --encoding=utf8 option was given to
 * John and from the other character sets otherwise which is faster, since it
 * is a simple table lookup, vs computing wide characters. */
#ifndef __SUNPRO_C
inline
#endif
int enc_to_utf16(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src,
                 unsigned int srclen)
{
	if (!(options.utf8)) {
		int i, trunclen = (int)srclen;
		if (trunclen > maxdstlen)
			trunclen = maxdstlen;

		for (i = 0; i < trunclen; i++) {
#if ARCH_LITTLE_ENDIAN
			*dst++ = CP_to_Unicode[*src++];
#else
			UTF16 val = CP_to_Unicode[*src++];
			SSVAL(dst, 0, val);
			++dst;
#endif
		}
		*dst = 0;
		if (i < srclen)
			return -i;
		else
			return i;
	} else {		// Convert from UTF-8
		return utf8_to_utf16(dst, maxdstlen, src, srclen);
	}
}

/* Convert from current codepage to UTF-16BE regardless of arch
 * NOTE, Solaris did not build properly with this function inlined. Thus
 * the inline was conditioned */
#ifndef __SUNPRO_C
inline
#endif
int enc_to_utf16_be(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src,
                    unsigned int srclen) {
	if (!(options.utf8)) {
		int i, trunclen = (int)srclen;
		if (trunclen > maxdstlen)
			trunclen = maxdstlen;

		for (i = 0; i < trunclen; i++) {
#if ARCH_LITTLE_ENDIAN
			*dst++ = CP_to_Unicode[*src] >> 8 | CP_to_Unicode[*src] << 8;
			src++;
#else
			*dst++ = CP_to_Unicode[*src++];
#endif
		}
		*dst = 0;
		if (i < srclen)
			return -i;
		else
			return i;
	} else {		// Convert from UTF-8
		return utf8_to_utf16_be(dst, maxdstlen, src, srclen);
	}
}

// Strlen of UTF-16 (in 16-bit words, not octets)
// Characters > U+FFFF are two 16-bit words
inline unsigned int strlen16(const UTF16 *str)
{
	unsigned int len = 0;
	while (*str++ != 0)
		len++;
	return len;
}

// strlen of UTF-8 (in characters, not octets)
// Will return a "truncated" length if fed with bad data.
inline unsigned int strlen8(const UTF8 *source)
{
	int targetLen = 0;
	const UTF8 *sourceEnd = source + strlen((char*)source);
	unsigned int extraBytesToRead;

	while (source < sourceEnd) {
		if (*source < 0xC0) {
			source++;
			targetLen++;
			if (*source == 0)
				break;
			continue;
		}
		// The original code in ConvertUTF.c has a much larger (slower)
		// lookup table including zeros. This point must not be reached
		// with *source < 0xC0
		extraBytesToRead =
		    opt_trailingBytesUTF8[*source & 0x3f];
		if ((source + extraBytesToRead >= sourceEnd) ||
		    (extraBytesToRead > 3)) {
			return targetLen;
		}
		source += extraBytesToRead + 1;
		targetLen++;
		if (*source == 0 || source >= sourceEnd)
			break;
	}
	return targetLen;
}

/*
 * Creates an MD4 Hash of the user's password in NT UNICODE.
 * This version honours the --encoding=utf8 flag and makes a couple
 * of formats utf8-aware with few further modifications.
 *
 * Now using Alain's fast NTLM up to 27 characters of plaintext (54 bytes
 * of UTF-16) and a generic one (Solar's MD4) otherwise.
 *
 * MD4 compress function
 * Written by Alain Espinosa <alainesp@gmail.com> in 2008
 * and placed in the public domain.
 *
 * This is now thread-safe
 */
int E_md4hash(const UTF8 *passwd, unsigned int len, unsigned char *p16)
{
	int trunclen;
	UTF16 wpwd[PLAINTEXT_BUFFER_SIZE + 1];

	// Quick work around. We may want to port the else{} into BE code,
	// and do it without impacting LE speed. The boost is not huge though.
#if ARCH_ALLOWS_UNALIGNED
	if (len > 27) {
#endif
		MD4_CTX ctx;

		/* Password is converted to UTF-16LE */
		trunclen = enc_to_utf16(wpwd, PLAINTEXT_BUFFER_SIZE, passwd, len);
		if(trunclen < 0)
			len = strlen16(wpwd); // From UTF-8 you can't know
		else
			len = trunclen;

		MD4_Init(&ctx);
		MD4_Update(&ctx, (unsigned char *)wpwd, len * sizeof(UTF16));
		MD4_Final(p16, &ctx);
#if ARCH_ALLOWS_UNALIGNED
	} else {
		unsigned int nt_buffer[16];
		unsigned int a = INIT_A;
		unsigned int b = INIT_B;
		unsigned int c = INIT_C;
		unsigned int d = INIT_D;
		unsigned int i = 0, md4_size = 0;

		memset(nt_buffer, 0, sizeof(nt_buffer));

		/* Password is converted to UTF-16LE */
		trunclen = enc_to_utf16(wpwd, 27, passwd, len);
		// We need to check this because it's not just a matter of truncating
		// length, it can be malformed UTF-8
		if (trunclen < 0)
			len = strlen16(wpwd);	/* From UTF-8 you can't know */
		else
			len = trunclen;

		/* Key setup */
		for (; md4_size + 1 < len; i++, md4_size += 2)
			nt_buffer[i] = wpwd[md4_size] | (wpwd[md4_size + 1] << 16);
		if (md4_size < len)
			nt_buffer[i] = wpwd[md4_size++] | 0x800000;
		else
			nt_buffer[i] = 0x80;

		nt_buffer[14] = md4_size << 4;

		/* Round 1 */
		a += (d ^ (b & (c ^ d)))  +  nt_buffer[0]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  +  nt_buffer[1]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  +  nt_buffer[2]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  +  nt_buffer[3]  ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d)))  +  nt_buffer[4]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  +  nt_buffer[5]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  +  nt_buffer[6]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  +  nt_buffer[7]  ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d)))  +  nt_buffer[8]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  +  nt_buffer[9]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  +  nt_buffer[10] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  +  nt_buffer[11] ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d)))  +  nt_buffer[12] ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  +  nt_buffer[13] ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  +  nt_buffer[14] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) ;b = (b << 19) | (b >> 13);

		/* Round 2 */
		a += ((b & (c | d)) | (c & d)) + nt_buffer[0] +SQRT_2; a = (a<<3 ) | (a>>29);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[4] +SQRT_2; d = (d<<5 ) | (d>>27);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[8] +SQRT_2; c = (c<<9 ) | (c>>23);
		b += ((c & (d | a)) | (d & a)) + nt_buffer[12]+SQRT_2; b = (b<<13) | (b>>19);

		a += ((b & (c | d)) | (c & d)) + nt_buffer[1] +SQRT_2; a = (a<<3 ) | (a>>29);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[5] +SQRT_2; d = (d<<5 ) | (d>>27);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[9] +SQRT_2; c = (c<<9 ) | (c>>23);
		b += ((c & (d | a)) | (d & a)) + nt_buffer[13]+SQRT_2; b = (b<<13) | (b>>19);

		a += ((b & (c | d)) | (c & d)) + nt_buffer[2] +SQRT_2; a = (a<<3 ) | (a>>29);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[6] +SQRT_2; d = (d<<5 ) | (d>>27);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[10]+SQRT_2; c = (c<<9 ) | (c>>23);
		b += ((c & (d | a)) | (d & a)) + nt_buffer[14]+SQRT_2; b = (b<<13) | (b>>19);

		a += ((b & (c | d)) | (c & d)) + nt_buffer[3] +SQRT_2; a = (a<<3 ) | (a>>29);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[7] +SQRT_2; d = (d<<5 ) | (d>>27);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[11]+SQRT_2; c = (c<<9 ) | (c>>23);
		b += ((c & (d | a)) | (d & a)) +SQRT_2; b = (b<<13) | (b>>19);

		/* Round 3 */
		a += (d ^ c ^ b) + nt_buffer[0]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (c ^ b ^ a) + nt_buffer[8]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (b ^ a ^ d) + nt_buffer[4]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (a ^ d ^ c) + nt_buffer[12] +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (d ^ c ^ b) + nt_buffer[2]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (c ^ b ^ a) + nt_buffer[10] +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (b ^ a ^ d) + nt_buffer[6]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (a ^ d ^ c) + nt_buffer[14] +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (d ^ c ^ b) + nt_buffer[1]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (c ^ b ^ a) + nt_buffer[9]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (b ^ a ^ d) + nt_buffer[5]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (a ^ d ^ c) + nt_buffer[13] +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (d ^ c ^ b) + nt_buffer[3]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (c ^ b ^ a) + nt_buffer[11] +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (b ^ a ^ d) + nt_buffer[7]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (a ^ d ^ c) +  SQRT_3; b = (b << 15) | (b >> 17);

		((unsigned int *)p16)[0] = a + INIT_A;
		((unsigned int *)p16)[1] = b + INIT_B;
		((unsigned int *)p16)[2] = c + INIT_C;
		((unsigned int *)p16)[3] = d + INIT_D;
	}
#endif
	return trunclen;
}

// Convert UTF-16LE to UTF-8. This is not optimised as it's
// only used in get_key() as of now.
// Non thread-safe version
UTF8 *utf16_to_utf8 (const UTF16 *source) {
	static UTF8 ret_Key[PLAINTEXT_BUFFER_SIZE + 1];
	return utf16_to_utf8_r(ret_Key, PLAINTEXT_BUFFER_SIZE, source);
}

// Thread-safe version
UTF8 *utf16_to_utf8_r (UTF8 *dst, int dst_len, const UTF16 *source) {
	UTF8 *tpt = dst;
	UTF8 *targetEnd = tpt + dst_len;
	while (*source) {
		UTF32 ch;
		unsigned short bytesToWrite = 0;
		const UTF32 byteMask = 0xBF;
		const UTF32 byteMark = 0x80;
		const UTF16 *oldSource = source; /* In case we have to back out */
		ch = *source++;
		/* If we have a surrogate pair, convert to UTF32 first. */
		if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
			/* If the 16 bits following the high surrogate are in the source buffer... */
			if (*source) {
				UTF32 ch2 = *source;
				/* If it's a low surrogate, convert to UTF32. */
				if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
					ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
						+ (ch2 - UNI_SUR_LOW_START) + halfBase;
					++source;
//				} else { /* it's an unpaired high surrogate */
//					--source; /* return to the illegal value itself */
//					fprintf(stderr, "warning, utf16toutf8 failed (illegal) - this is a bug in JtR\n");
//					break;
				}
//			} else { /* We don't have the 16 bits following the high surrogate. */
//				--source; /* return to the high surrogate */
//				fprintf(stderr, "warning, utf16toutf8 failed (no surrogate) - this is a bug in JtR\n");
//				break;
			}
		}
		/* Figure out how many bytes the result will require */
		if (ch < (UTF32)0x80) {	     bytesToWrite = 1;
		} else if (ch < (UTF32)0x800) {     bytesToWrite = 2;
		} else if (ch < (UTF32)0x10000) {   bytesToWrite = 3;
		} else if (ch < (UTF32)0x110000) {  bytesToWrite = 4;
		} else {			    bytesToWrite = 3;
			ch = UNI_REPLACEMENT_CHAR;
		}

		tpt += bytesToWrite;
		if (tpt > targetEnd) {
			source = oldSource; /* Back up source pointer! */
			tpt -= bytesToWrite; break;
		}
		switch (bytesToWrite) { /* note: everything falls through. */
		case 4: *--tpt = (UTF8)((ch | byteMark) & byteMask); ch >>= 6;
		case 3: *--tpt = (UTF8)((ch | byteMark) & byteMask); ch >>= 6;
		case 2: *--tpt = (UTF8)((ch | byteMark) & byteMask); ch >>= 6;
		case 1: *--tpt =  (UTF8)(ch | firstByteMark[bytesToWrite]);
		}
		tpt += bytesToWrite;
	}
	*tpt = 0;
	return dst;
}

/* Thread-safe conversion from codepage to UTF-8 */
UTF8 *enc_to_utf8_r (char *src, UTF8 *dst, int dstlen)
{
	UTF16 tmp16[LINE_BUFFER_SIZE + 1];
	enc_to_utf16(tmp16, LINE_BUFFER_SIZE, (unsigned char*)src,
	             strlen((char*)src));
	dst = utf16_to_utf8_r(dst, dstlen, tmp16);
	return dst;
}

/* Thread-safe conversion from UTF-8 to codepage */
char * utf8_to_enc_r (UTF8 *src, char* dst, int dstlen)
{
	UTF16 tmp16[LINE_BUFFER_SIZE + 1];
	utf8_to_utf16(tmp16, LINE_BUFFER_SIZE, (unsigned char*)src,
	              strlen((char*)src));
	dst = (char*)utf16_to_enc_r((UTF8*)dst, dstlen, tmp16);
	return dst;
}

// Convert UTF-16LE to UTF-8 or ISO-8859-1 depending on --encoding=utf8 flag.
// This is not optimised as it's only used in get_key() as of now.
// Non thread-safe version
UTF8 *utf16_to_enc (const UTF16 *source) {
	static UTF8 ret_Key[PLAINTEXT_BUFFER_SIZE + 1];
	return utf16_to_enc_r(ret_Key, PLAINTEXT_BUFFER_SIZE, source);
}

// Thread-safe version
UTF8 *utf16_to_enc_r (UTF8 *dst, int dst_len, const UTF16 *source) {
	if (options.utf8)
		return utf16_to_utf8_r(dst, dst_len, source);
	else {
		UTF8 *tgt = dst;
		UTF8 *targetEnd = tgt + dst_len;

		while (*source && tgt < targetEnd)
			*tgt++ = CP_from_Unicode[*source++];
		*tgt = 0;
	}
	return dst;
}

void listEncodings(void) {
	printf("utf-8, iso-8859-1 (or ansi)"
	        ", iso-8859-2"
	        ", iso-8859-7"
	        ", iso-8859-15"
	        ",\nkoi8-r"
	        ", cp437"
	        ", cp737"
	        ", cp850"
	        ", cp852"
	        ", cp858"
	        ", cp866"
	        ", cp1250"
	        ", cp1251"
	        ",\ncp1252"
	        ", cp1253"
	        "\n");
}

/* Load the 'case-conversion' tables, and other translation table. */
int initUnicode(int type) {
	unsigned i;
	unsigned char *cpU, *cpL;
	char *encTemp;
	char *pos;

	if (UnicodeType==type) return 0;

	UnicodeType = type;

	options.utf8 = options.iso8859_1 = options.iso8859_2 = options.iso8859_7 =
	  options.iso8859_15 = options.koi8_r = options.cp437 =
	  options.cp737 = options.cp850 = options.cp852 = options.cp858 = options.cp866 =
	  options.cp1251 = options.cp1250 = options.cp1252 = options.cp1253 = 0;
	// by 'default' we are setup in 7 bit ascii mode (for rules).
	options.ascii = 1;
	options.encodingStr = "";
	if (options.encoding) {
		// Ok, check a 'few' valid things for utf8
		options.ascii = 0;
		if (!strcasecmp(options.encoding, "utf8")||!strcasecmp(options.encoding, "utf-8")) {
			options.utf8 = 1;
			options.encodingStr = "UTF-8";
		} else
		if (!strcasecmp(options.encoding, "ansi")||!strcasecmp(options.encoding, "iso-8859-1")||!strcasecmp(options.encoding, "8859-1")||!strcasecmp(options.encoding, "iso8859-1")) {
			options.iso8859_1 = 1;
			options.encodingStr = "ISO-8859-1";
		} else
		if (!strcasecmp(options.encoding, "iso-8859-2")||!strcasecmp(options.encoding, "8859-2")||!strcasecmp(options.encoding, "iso8859-2")) {
			options.iso8859_2 = 1;
			options.encodingStr = "ISO-8859-2";
		} else
		if (!strcasecmp(options.encoding, "iso-8859-7")||!strcasecmp(options.encoding, "8859-7")||!strcasecmp(options.encoding, "iso8859-7")) {
			options.iso8859_7 = 1;
			options.encodingStr = "ISO-8859-7";
		} else
		if (!strcasecmp(options.encoding, "iso-8859-15")||!strcasecmp(options.encoding, "8859-15")||!strcasecmp(options.encoding, "iso8859-15")) {
			options.iso8859_15 = 1;
			options.encodingStr = "ISO-8859-15";
		} else
		if (!strcasecmp(options.encoding, "koi8-r")||!strcasecmp(options.encoding, "koi8r")) {
			options.koi8_r = 1;
			options.encodingStr = "KOI8-R";
		} else
		if (!strcasecmp(options.encoding, "cp437")||!strcasecmp(options.encoding, "cp-437")) {
			options.cp437 = 1;
			options.encodingStr = "CP437";
		} else
		if (!strcasecmp(options.encoding, "cp737")||!strcasecmp(options.encoding, "cp-737")) {
			options.cp737 = 1;
			options.encodingStr = "CP737";
		} else
		if (!strcasecmp(options.encoding, "cp850")||!strcasecmp(options.encoding, "cp-850")) {
			options.cp850 = 1;
			options.encodingStr = "CP850";
		} else
		if (!strcasecmp(options.encoding, "cp852")||!strcasecmp(options.encoding, "cp-852")) {
			options.cp852 = 1;
			options.encodingStr = "CP852";
		} else
		if (!strcasecmp(options.encoding, "cp858")||!strcasecmp(options.encoding, "cp-858")) {
			options.cp858 = 1;
			options.encodingStr = "CP858";
		} else
		if (!strcasecmp(options.encoding, "cp866")||!strcasecmp(options.encoding, "cp-866")) {
			options.cp866 = 1;
			options.encodingStr = "CP866";
		} else
		if (!strcasecmp(options.encoding, "cp1250")||!strcasecmp(options.encoding, "cp-1250")) {
			options.cp1250 = 1;
			options.encodingStr = "CP1250";
		} else
		if (!strcasecmp(options.encoding, "cp1251")||!strcasecmp(options.encoding, "cp-1251")) {
			options.cp1251 = 1;
			options.encodingStr = "CP1251";
		} else
		if (!strcasecmp(options.encoding, "cp1252")||!strcasecmp(options.encoding, "cp-1252")) {
			options.cp1252 = 1;
			options.encodingStr = "CP1252";
		} else
		if (!strcasecmp(options.encoding, "cp1253")||!strcasecmp(options.encoding, "cp-1253")) {
			options.cp1253 = 1;
			options.encodingStr = "CP1253";
		} else
		if (!strcasecmp(options.encoding, "raw")||!strcasecmp(options.encoding, "ascii")||!strcasecmp(options.encoding, "default")) {
			options.ascii = 1;
			options.encodingStr = "raw";
		} else {
			fprintf (stderr, "Invalid encoding. ");
			listEncodings();
			error();
		}
	}

	options.log_passwords = cfg_get_bool(SECTION_OPTIONS,
	    NULL, "LogCrackedPasswords", 0);
	options.report_utf8 = cfg_get_bool(SECTION_OPTIONS,
	    NULL, "AlwaysReportUTF8", 0);

	memset(ucs2_upcase, 0, sizeof(ucs2_upcase));
	memset(ucs2_downcase, 0, sizeof(ucs2_downcase));

	// If we are handling MSSQL format (the old upper case, then we MUST use arTo[UL]CDat_WinXP arrays,
	// and NOTE use the multi-char stuff.

	// I know this may 'not' be right, but for now, I will be doing all unicode in the
	// MSSQL-2000 way.   When initUnicode gets called, we do not know what format we are 'testing'
	// against. We may have to split up the initialzation into 2 parts.  One part done early, and
	// the 2nd part done, when we know what format we are using.
	// This is still TBD on how best to do it.
	if (type==UNICODE_MS_OLD) {
		if (options.ascii) {
			// The 'proper' default encoding for mssql IS 8859-1 the test suite will have a TON of failures, unless this
			// is set this way.  All of the data IN that test suite, was made using MSSQL.
			options.ascii = 0;
			options.iso8859_1 = 1;
			options.encodingStr = "ISO-8859-1";
		}
		for (i = 0; arToUCDat_WinXP[i]; i += 2)
			ucs2_upcase[arToUCDat_WinXP[i]] = arToUCDat_WinXP[i+1];
		for (i = 0; arToLCDat_WinXP[i]; i += 2)
			ucs2_downcase[arToLCDat_WinXP[i]] = arToLCDat_WinXP[i+1];

		// Required for cp737, MSSQL_old
		ucs2_upcase[0x03C2] = 0x03C2; //U+03C2 -> U+03A3 was not cased
		ucs2_downcase[0x03A3] = 0x03A3; //U+03A3 -> U+03C2  was not cased
	} else if (type==UNICODE_MS_NEW) {
		for (i = 0; arToUCDat_WinVista[i]; i += 2)
			ucs2_upcase[arToUCDat_WinVista[i]] = arToUCDat_WinVista[i+1];
		for (i = 0; arToLCDat_WinVista[i]; i += 2)
			ucs2_downcase[arToLCDat_WinVista[i]] = arToLCDat_WinVista[i+1];
	} else {
		for (i = 0; arToUCDat_UCData_txt[i]; i += 2)
			ucs2_upcase[arToUCDat_UCData_txt[i]] = arToUCDat_UCData_txt[i+1];
		for (i = 0; arToLCDat_UCData_txt[i]; i += 2)
			ucs2_downcase[arToLCDat_UCData_txt[i]] = arToLCDat_UCData_txt[i+1];

		// set a 1 for any 'multi-char' converts.
		for (i = 0; uniMultiCase[i].Val; ++i)
			if (uniMultiCase[i].bIsUp2Low)
				ucs2_downcase[uniMultiCase[i].Val] = 1;
			else
				ucs2_upcase[uniMultiCase[i].Val] = 1;
	}

	// Here we setup the 8-bit codepages we handle, and setup the mapping values into Unicode.
	for (i = 0; i < 128; ++i) {
		CP_to_Unicode[i] = i;
	}
	for (i = 128; i < 256; ++i) {
		if (options.iso8859_2)
			CP_to_Unicode[i] = ISO_8859_2_to_unicode_high128[i-128];
		if (options.iso8859_7)
			CP_to_Unicode[i] = ISO_8859_7_to_unicode_high128[i-128];
		else if (options.iso8859_15)
			CP_to_Unicode[i] = ISO_8859_15_to_unicode_high128[i-128];
		else if (options.koi8_r)
			CP_to_Unicode[i] = KOI8_R_to_unicode_high128[i-128];
		else if (options.cp437)
			CP_to_Unicode[i] = CP437_to_unicode_high128[i-128];
		else if (options.cp737)
			CP_to_Unicode[i] = CP737_to_unicode_high128[i-128];
		else if (options.cp850)
			CP_to_Unicode[i] = CP850_to_unicode_high128[i-128];
		else if (options.cp852)
			CP_to_Unicode[i] = CP852_to_unicode_high128[i-128];
		else if (options.cp858)
			CP_to_Unicode[i] = CP858_to_unicode_high128[i-128];
		else if (options.cp866)
			CP_to_Unicode[i] = CP866_to_unicode_high128[i-128];
		else if (options.cp1250)
			CP_to_Unicode[i] = CP1250_to_unicode_high128[i-128];
		else if (options.cp1251)
			CP_to_Unicode[i] = CP1251_to_unicode_high128[i-128];
		else if (options.cp1252)
			CP_to_Unicode[i] = CP1252_to_unicode_high128[i-128];
		else if (options.cp1253)
			CP_to_Unicode[i] = CP1253_to_unicode_high128[i-128];
		else
			CP_to_Unicode[i] = ISO_8859_1_to_unicode_high128[i-128]; // 8859-1
	}
	for (i = 0; i < 0x10000; ++i)
		CP_from_Unicode[i] = i;  // will truncate to lower 8 bits.
	for (i = 0; i < 128; ++i) {
		if (options.iso8859_2)
			CP_from_Unicode[ISO_8859_2_to_unicode_high128[i]] = i+128;
		if (options.iso8859_7)
			CP_from_Unicode[ISO_8859_7_to_unicode_high128[i]] = i+128;
		else if (options.iso8859_15)
			CP_from_Unicode[ISO_8859_15_to_unicode_high128[i]] = i+128;
		else if (options.koi8_r)
			CP_from_Unicode[KOI8_R_to_unicode_high128[i]] = i+128;
		else if (options.cp437)
			CP_from_Unicode[CP437_to_unicode_high128[i]] = i+128;
		else if (options.cp737)
			CP_from_Unicode[CP737_to_unicode_high128[i]] = i+128;
		else if (options.cp850)
			CP_from_Unicode[CP850_to_unicode_high128[i]] = i+128;
		else if (options.cp852)
			CP_from_Unicode[CP852_to_unicode_high128[i]] = i+128;
		else if (options.cp858)
			CP_from_Unicode[CP858_to_unicode_high128[i]] = i+128;
		else if (options.cp866)
			CP_from_Unicode[CP866_to_unicode_high128[i]] = i+128;
		else if (options.cp1250)
			CP_from_Unicode[CP1250_to_unicode_high128[i]] = i+128;
		else if (options.cp1251)
			CP_from_Unicode[CP1251_to_unicode_high128[i]] = i+128;
		else if (options.cp1252)
			CP_from_Unicode[CP1252_to_unicode_high128[i]] = i+128;
		else if (options.cp1253)
			CP_from_Unicode[CP1253_to_unicode_high128[i]] = i+128;
		else {
			CP_from_Unicode[ISO_8859_1_to_unicode_high128[i]] = i+128;
			if (!i)
				CP_from_Unicode[0x39C] = 0xB5;
		}
	}

	// first set ALL characters to have NO conversion.
	for (i = 0; i < 256; ++i)
		CP_up[i] = CP_down[i] = i;
	// standard case change for 7 bit characters (lower 128 bytes), for character sets.
	for (i = 'a'; i <= 'z'; ++i)
		CP_up[i] = (i^0x20);
	for (i = 'A'; i <= 'Z'; ++i)
		CP_down[i] = (i^0x20);

	// now handle upper 128 byte values for casing.  CHARS_LOW_ONLY_xxxx is not needed.
	if (options.iso8859_1) {
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_1; cpL = (unsigned char*)CHARS_LOWER_ISO_8859_1;
	} else if (options.iso8859_2) {
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_2; cpL = (unsigned char*)CHARS_LOWER_ISO_8859_2;
	} else if (options.iso8859_7) {
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_7; cpL = (unsigned char*)CHARS_LOWER_ISO_8859_7;
	} else if (options.iso8859_15) {
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_15; cpL = (unsigned char*)CHARS_LOWER_ISO_8859_15;
	} else if (options.koi8_r) {
		cpU = (unsigned char*)CHARS_UPPER_KOI8_R; cpL = (unsigned char*)CHARS_LOWER_KOI8_R;
	} else if (options.cp437) {
		cpU = (unsigned char*)CHARS_UPPER_CP437; cpL = (unsigned char*)CHARS_LOWER_CP437;
	} else if (options.cp737) {
		cpU = (unsigned char*)CHARS_UPPER_CP737; cpL = (unsigned char*)CHARS_LOWER_CP737;
	} else if (options.cp850) {
		cpU = (unsigned char*)CHARS_UPPER_CP850; cpL = (unsigned char*)CHARS_LOWER_CP850;
	} else if (options.cp852) {
		cpU = (unsigned char*)CHARS_UPPER_CP852; cpL = (unsigned char*)CHARS_LOWER_CP852;
	} else if (options.cp858) {
		cpU = (unsigned char*)CHARS_UPPER_CP858; cpL = (unsigned char*)CHARS_LOWER_CP858;
	} else if (options.cp866) {
		cpU = (unsigned char*)CHARS_UPPER_CP866; cpL = (unsigned char*)CHARS_LOWER_CP866;
	} else if (options.cp1250) {
		cpU = (unsigned char*)CHARS_UPPER_CP1250; cpL = (unsigned char*)CHARS_LOWER_CP1250;
	} else if (options.cp1251) {
		cpU = (unsigned char*)CHARS_UPPER_CP1251; cpL = (unsigned char*)CHARS_LOWER_CP1251;
	} else if (options.cp1252) {
		cpU = (unsigned char*)CHARS_UPPER_CP1252; cpL = (unsigned char*)CHARS_LOWER_CP1252;
	} else if (options.cp1253) {
		cpU = (unsigned char*)CHARS_UPPER_CP1253; cpL = (unsigned char*)CHARS_LOWER_CP1253;
	} else {  // old-style ASCII-only
		cpU = (unsigned char*)""; cpL = (unsigned char*)"";
	}
	for (i = 0; cpU[i]; ++i) {
		CP_down[(unsigned)cpU[i]] = cpL[i];
		CP_up[(unsigned)cpL[i]] = cpU[i];
	}

	if (type==UNICODE_MS_OLD && options.cp850) {
		// We 'do' have allow uc of U+0131 into U+0049  (but there is NO reverse of this
		//CP_up[0xD5] = 0x49; (this is 'default' in encoding_data.h right now.

		// for mssql, we HAVE to leave this one 100% alone!
		CP_up[0xD5] = 0xD5;
	}
	if (type==UNICODE_MS_OLD && options.cp737) {
		// Required for cp737, MSSQL_old
		//ucs2_upcase[0x03C2] = 0x03C2; //U+03C2 -> U+03A3 was not cased
		CP_up[0xAA] = 0xAA;
		CP_down[0x91] = 0x91;
	}

	// CP_isSeparator[c] will return true if c is a separator
	memset(CP_isSeparator, 0, sizeof(CP_isSeparator));

	// Original separator list from loader.c
#define CP_issep \
	"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\177"

	if (options.iso8859_1)
		encTemp = CP_issep CHARS_PUNCTUATION_ISO_8859_1 CHARS_SPECIALS_ISO_8859_1 CHARS_WHITESPACE_ISO_8859_1 CHARS_CONTROL_ISO_8859_1 CHARS_INVALID_ISO_8859_1;
	else if (options.iso8859_2 )
		encTemp = CP_issep CHARS_PUNCTUATION_ISO_8859_2 CHARS_SPECIALS_ISO_8859_2 CHARS_WHITESPACE_ISO_8859_2 CHARS_CONTROL_ISO_8859_2 CHARS_INVALID_ISO_8859_2;
	else if (options.iso8859_7 )
		encTemp = CP_issep CHARS_PUNCTUATION_ISO_8859_7 CHARS_SPECIALS_ISO_8859_7 CHARS_WHITESPACE_ISO_8859_7 CHARS_CONTROL_ISO_8859_7 CHARS_INVALID_ISO_8859_7;
	else if (options.iso8859_15)
		encTemp = CP_issep CHARS_PUNCTUATION_ISO_8859_15 CHARS_SPECIALS_ISO_8859_15 CHARS_WHITESPACE_ISO_8859_15 CHARS_CONTROL_ISO_8859_15 CHARS_INVALID_ISO_8859_15;
	else if (options.koi8_r)
		encTemp = CP_issep CHARS_PUNCTUATION_KOI8_R CHARS_SPECIALS_KOI8_R CHARS_WHITESPACE_KOI8_R CHARS_CONTROL_KOI8_R CHARS_INVALID_KOI8_R;
	else if (options.cp437)
		encTemp = CP_issep CHARS_PUNCTUATION_CP437 CHARS_SPECIALS_CP437 CHARS_WHITESPACE_CP437 CHARS_CONTROL_CP437 CHARS_INVALID_CP437;
	else if (options.cp737)
		encTemp = CP_issep CHARS_PUNCTUATION_CP737 CHARS_SPECIALS_CP737 CHARS_WHITESPACE_CP737 CHARS_CONTROL_CP737 CHARS_INVALID_CP737;
	else if (options.cp850)
		encTemp = CP_issep CHARS_PUNCTUATION_CP850 CHARS_SPECIALS_CP850 CHARS_WHITESPACE_CP850 CHARS_CONTROL_CP850 CHARS_INVALID_CP850;
	else if (options.cp852)
		encTemp = CP_issep CHARS_PUNCTUATION_CP852 CHARS_SPECIALS_CP852 CHARS_WHITESPACE_CP852 CHARS_CONTROL_CP852 CHARS_INVALID_CP852;
	else if (options.cp858)
		encTemp = CP_issep CHARS_PUNCTUATION_CP858 CHARS_SPECIALS_CP858 CHARS_WHITESPACE_CP858 CHARS_CONTROL_CP858 CHARS_INVALID_CP858;
	else if (options.cp866)
		encTemp = CP_issep CHARS_PUNCTUATION_CP866 CHARS_SPECIALS_CP866 CHARS_WHITESPACE_CP866 CHARS_CONTROL_CP866 CHARS_INVALID_CP866;
	else if (options.cp1250)
		encTemp = CP_issep CHARS_PUNCTUATION_CP1250 CHARS_SPECIALS_CP1250 CHARS_WHITESPACE_CP1250 CHARS_CONTROL_CP1250 CHARS_INVALID_CP1250;
	else if (options.cp1251)
		encTemp = CP_issep CHARS_PUNCTUATION_CP1251 CHARS_SPECIALS_CP1251 CHARS_WHITESPACE_CP1251 CHARS_CONTROL_CP1251 CHARS_INVALID_CP1251;
	else if (options.cp1252)
		encTemp = CP_issep CHARS_PUNCTUATION_CP1252 CHARS_SPECIALS_CP1252 CHARS_WHITESPACE_CP1252 CHARS_CONTROL_CP1252 CHARS_INVALID_CP1252;
	else if (options.cp1253)
		encTemp = CP_issep CHARS_PUNCTUATION_CP1253 CHARS_SPECIALS_CP1253 CHARS_WHITESPACE_CP1253 CHARS_CONTROL_CP1253 CHARS_INVALID_CP1253;
	else  // old-style ASCII-only
		encTemp = CP_issep;

	memset(CP_isSeparator, 1, 33);
	for (pos = encTemp; *pos; pos++)
		CP_isSeparator[ARCH_INDEX(*pos)] = 1;

	// CP_isLetter[c] will return true if c is a letter
	memset(CP_isLetter, 0, sizeof(CP_isLetter));

	if (options.iso8859_1)
		encTemp = CHARS_ALPHA_ISO_8859_1;
	else if (options.iso8859_2)
		encTemp = CHARS_ALPHA_ISO_8859_2;
	else if (options.iso8859_7)
		encTemp = CHARS_ALPHA_ISO_8859_7;
	else if (options.iso8859_15)
		encTemp = CHARS_ALPHA_ISO_8859_15;
	else if (options.koi8_r)
		encTemp = CHARS_ALPHA_KOI8_R;
	else if (options.cp437)
		encTemp = CHARS_ALPHA_CP437;
	else if (options.cp737)
		encTemp = CHARS_ALPHA_CP737;
	else if (options.cp850)
		encTemp = CHARS_ALPHA_CP850;
	else if (options.cp852)
		encTemp = CHARS_ALPHA_CP852;
	else if (options.cp858)
		encTemp = CHARS_ALPHA_CP858;
	else if (options.cp866)
		encTemp = CHARS_ALPHA_CP866;
	else if (options.cp1250)
		encTemp = CHARS_ALPHA_CP1250;
	else if (options.cp1251)
		encTemp = CHARS_ALPHA_CP1251;
	else if (options.cp1252)
		encTemp = CHARS_ALPHA_CP1252;
	else if (options.cp1253)
		encTemp = CHARS_ALPHA_CP1253;
	else
		encTemp = "";

	for (i = 'a'; i <= 'z'; i++)
		CP_isLetter[i] = 1;
	for (i = 'A'; i <= 'Z'; i++)
		CP_isLetter[i] = 1;
	for (pos = encTemp; *pos; pos++)
		CP_isLetter[ARCH_INDEX(*pos)] = 1;

	return 0;
}

/* single char conversion inlines. Inlines vs macros, so that we get type 'safety'           */
/* NOTE these functions do NOT return multi UTF16 conversion characters, so they are         */
/* only 'partly' proper.  The enc_to_utf16_uc() and  enc_to_utf16_lc() do full conversions as    */
/* does the utf16_lc() and utf16_uc().  Full conversion uses the utc_*case[] arrays, but  it */
/* also uses the 1 UTC2 to multi UTC2 lookup table to do things 'properly'.                  */
//_inline unsigned char low2up_ansi(unsigned char c) {if (ucs2_upcase[c]) {return ucs2_upcase[c]; return c; }
//_inline unsigned char up2low_ansi(unsigned char c) {if (ucs2_downcase[c]) return ucs2_downcase[c]; return c; }
//_inline UTF16 low2up_u16(UTF16 w) {if (ucs2_upcase[w]) return ucs2_upcase[w]; return w; }
//_inline UTF16 up2low_u16(UTF16 w) {if (ucs2_downcase[w]) return ucs2_downcase[w]; return w; }

/* Convert to UTF-16LE from UTF-8 or ISO-8859-1 depending on --encoding=utf8 flag, and upcase/lowcase at same time */
//int enc_to_utf16_uc(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src, unsigned int srclen) {
//	return 0;
//}
//int enc_to_utf16_lc(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src, unsigned int srclen) {
//	return 0;
//}

// Lowercase UTF-16
int utf16_lc(UTF16 *dst, unsigned dst_len, const UTF16 *src, unsigned src_len) {
	int i, j = 0;
	UTF16 cur_src;
	for (i = 0; i < src_len; ++i, ++j, ++src, ++dst) {
		if (j == dst_len) {
			*dst = 0;
			return -j;
		}
		cur_src = BE_FIX(*src);
		if (ucs2_downcase[ cur_src ] == 0)
			*dst = cur_src;
		else {
			if (ucs2_downcase[ cur_src ] & 0xFFFE) {
				*dst = ucs2_downcase[ cur_src ];
			}
			else {
				// multi-byte.
				int k, l;
				for (k = 0; uniMultiCase[k].Val; ++k) {
					if (uniMultiCase[k].Val == cur_src) {
						if (j + uniMultiCase[k].Cnt >= dst_len) {
							*dst = 0;
							return -j;
						}
						for (l = 0; l < uniMultiCase[k].Cnt; ++l)
							dst[l] = uniMultiCase[k].ToVals[l];
						dst += uniMultiCase[k].Cnt-1;
						j += uniMultiCase[k].Cnt-1;
						break;
					}
				}
			}
		}
	}
	*dst = 0;
	return j;
}

// Uppercase UTF-16
int utf16_uc(UTF16 *dst, unsigned dst_len, const UTF16 *src, unsigned src_len) {
	int i, j = 0;
	UTF16 cur_src;
	for (i = 0; i < src_len; ++i, ++j, ++src, ++dst) {
		if (j == dst_len) {
			*dst = 0;
			return -j;
		}
		cur_src = BE_FIX(*src);
		if (ucs2_upcase[ cur_src ] == 0)
			*dst = cur_src;
		else {
			if (ucs2_upcase[ cur_src ] & 0xFFFE) {
				*dst = ucs2_upcase[ cur_src ];
			}
			else {
				// multi-byte.
				int k, l;
				for (k = 0; uniMultiCase[k].Val; ++k) {
					if (uniMultiCase[k].Val == cur_src) {
						if (j + uniMultiCase[k].Cnt >= dst_len) {
							*dst = 0;
							return -j;
						}
						for (l = 0; l < uniMultiCase[k].Cnt; ++l)
							dst[l] = uniMultiCase[k].ToVals[l];
						dst += uniMultiCase[k].Cnt-1;
						j += uniMultiCase[k].Cnt-1;
						break;
					}
				}
			}
		}
	}
	*dst = 0;
	return j;
}

// Lowercase UTF-8 or codepage encoding
int enc_lc(UTF8 *dst, unsigned dst_len, const UTF8 *src, unsigned src_len) {
	UTF16 tmp16[512+1], tmp16l[512+1]; // yes, short, but this is 'long enough' for john.
	int utf16len, i;

	if (!options.utf8) {
		if (dst_len <= src_len)
			src_len = dst_len - 1;
		for (i = 0; i < src_len; ++i) {
			*dst++ = CP_down[*src++];
		}
		*dst = 0;
		return src_len;
	}
	utf16len = utf8_to_utf16(tmp16, 512, src, src_len);
	if (utf16len <= 0)
		goto lcFallback;
	utf16len = utf16_lc(tmp16l, 512, tmp16, utf16len);
	if (utf16len <= 0)
		goto lcFallback;
	utf16_to_enc_r(dst, dst_len, tmp16l);
	return strlen((char*)dst);

	// Limp-home mode: If we failed doing the right thing (garbage data) we
	// just do ASCII lc
lcFallback:
	if (dst_len <= src_len)
		src_len = dst_len - 1;
	for (i = 0; i < src_len; ++i)
		if (*src >= 'A' && *src <= 'Z')
			*dst++ = *src++ | 0x20;
		else
			*dst++ = *src++;
	*dst = 0;
	return src_len;
}

// Uppercase UTF-8 or codepage encoding
int enc_uc(UTF8 *dst, unsigned dst_len, const UTF8 *src, unsigned src_len) {
	UTF16 tmp16[512+1], tmp16u[512+1]; // yes, short, but this is 'long enough' for john.
	int utf16len, i;

	if (!options.utf8) {
		int len;
		if (dst_len < src_len)
			src_len = dst_len;
		len=src_len;
#if 0  // Defined out until we need it
		if (UnicodeType==UNICODE_UNICODE) {
			for (i = 0; i < src_len; ++i) {
				if (*src == 0xDF) { // this goes out as 2 characters.
					++len;
					if (len > dst_len) {
						return 0;
					}
					*dst++ = 'S';
					*dst++ = 'S';
					++src;
				}
				else
					*dst++ = CP_up[*src++];
			}
		}
		else
#endif
		{
			for (i = 0; i < src_len; ++i)
				*dst++ = CP_up[*src++];
		}
		*dst = 0;
		return len;
	}
	utf16len = utf8_to_utf16(tmp16, 512, src, src_len);
	if (utf16len <= 0)
		goto ucFallback;
	utf16len = utf16_uc(tmp16u, 512, tmp16, utf16len);
	if (utf16len <= 0)
		goto ucFallback;
	utf16_to_enc_r(dst, dst_len, tmp16u);
	return strlen((char*)dst);

	// Limp-home mode: If we failed doing the right thing (garbage data) we
	// just do ASCII uc
ucFallback:
	if (dst_len <= src_len)
		src_len = dst_len - 1;
	for (i = 0; i < src_len; ++i)
		if (*src >= 'a' && *src <= 'z')
			*dst++ = *src++ | 0x20;
		else
			*dst++ = *src++;
	*dst = 0;
	return src_len;
}

// Encoding-aware strlwr(): Simple in-place lowercasing
char *enc_strlwr(char *s)
{
	unsigned char *ptr = (unsigned char *)s;
	int srclen = strlen(s);
	enc_lc(ptr, srclen + 1, ptr, srclen);
	return s;
}

// Simple in-place uppercasing
char *enc_strupper(char *s)
{
	unsigned char *ptr = (unsigned char *)s;
	int srclen = strlen(s);
	enc_uc(ptr, srclen + 1, ptr, srclen);
	return s;
}
