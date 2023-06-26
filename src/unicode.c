/*
 * This file is Copyright (c) 2009-2015 magnum and JimF,
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 *
 * Original files "ConvertUTF.[ch]"
 * Author: Mark E. Davis, 1994.
 * Rev History: Rick McGowan, fixes & updates May 2001.
 * Fixes & updates, Sept 2001.
 * Copyright 2001-2004 Unicode, Inc.
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

#include <string.h>
#include <stdint.h>

#include "common.h"
#include "arch.h"
#include "byteorder.h"
#include "unicode.h"
#include "UnicodeData.h"
#define JTR_UNICODE_C	1
#include "encoding_data.h"
#include "misc.h"
#include "config.h"
#include "md4.h"
#include "john.h"

UTF16 ucs2_upcase[0x10000];
UTF16 ucs2_downcase[0x10000];

UTF16 CP_to_Unicode[0x100];
static UTF8 CP_from_Unicode[0x10000];

UTF8 CP_up[0x100];
UTF8 CP_ups[0x100];
UTF8 CP_down[0x100];
UTF8 CP_lows[0x100];

#ifndef UNICODE_NO_OPTIONS
static int UnicodeType = -1;
static int UnicodeInited = 0;
#endif

UTF8 CP_isLetter[0x100];
UTF8 CP_isSeparator[0x100];
UTF8 CP_isUpper[0x100];
UTF8 CP_isLower[0x100];
UTF8 CP_isDigit[0x100];

#if ARCH_LITTLE_ENDIAN
#define BE_FIX(a) a
#else
#define BE_FIX(a) ( (((a)&0xFF00)>>8) | (((a)&0xFF)<<8) )
#endif

/*
 * Once the bits are split out into bytes of UTF-8, this is a mask OR-ed
 * into the first byte, depending on how many bytes follow. There are
 * as many entries in this table as there are UTF-8 sequence types.
 * (I.e., one byte sequence, two byte... etc.). Remember that sequencs
 * for *legal* UTF-8 will be 4 or fewer bytes total.
 */
static const UTF8 firstByteMark[7] = {
	0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC
};

/*
 * Magic values subtracted from a buffer value during UTF8 conversion.
 * This table contains as many values as there might be trailing bytes
 * in a UTF-8 sequence. (Cut-down version, 4 and 5 are illegal).
 */
const UTF32 offsetsFromUTF8[6] = {
	0x00000000UL, 0x00003080UL, 0x000E2080UL,
	0x03C82080UL, 0xFA082080UL, 0x82082080UL
};

/*
 * Index into the table below with the first byte of a UTF-8 sequence to
 * get the number of trailing bytes that are supposed to follow it.
 *
 * Note that legal UTF-8 values can't have 4 or 5-bytes.
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

/*
 * Convert UTF-8 string to UTF-16LE, regardless of arch
 *
 * Optimized for speed, errors result in truncation.
 *
 * Normally returns number of UTF16 characters converted. If truncated,
 * the number of UTF8 characters that was successfully read is returned
 * instead (negated), so we can truncate our saved_plain or whatever
 * accordingly.
 */
int utf8_to_utf16(UTF16 *target, unsigned int len, const UTF8 *source,
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
/*
 * The original code in ConvertUTF.c has a much larger (slower) lookup table
 * including zeros. This point must not be reached with *source < 0xC0
 */
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
#if 0
		/* This only supports UCS-2 */
#if ARCH_LITTLE_ENDIAN
		*target++ = (UTF16)ch;
#else
		SSVAL(target, 0, ch);
		++target;
#endif
#else
		/* This supports full UTF-16 with surrogate pairs */
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
	*target = 0;
	return (target - targetStart);
}

/* Convert to UTF-16BE instead, regardless of arch */
static
#ifndef __SUNPRO_C
inline
#endif
int _utf8_to_utf16_be(UTF16 *target, unsigned int len, const UTF8 *source,
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
/*
 * The original code in ConvertUTF.c has a much larger (slower) lookup table
 * including zeros. This point must not be reached with *source < 0xC0
 */
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
#if 0
		/* This only supports UCS-2 */
#if ARCH_LITTLE_ENDIAN
		*target++ = (UTF16)ch << 8 | (UTF16)ch >> 8;
#else
		*target++ = (UTF16)ch;
#endif
#else
		/* This supports full UTF-16 with surrogate pairs */
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
	*target = 0;
	return (target - targetStart);
}

/* external function */
int utf8_to_utf16_be(UTF16 *target, unsigned int len, const UTF8 *source,
                            unsigned int sourceLen) {
	return _utf8_to_utf16_be(target, len, source, sourceLen);
}
/*
 * Convert from current encoding to UTF-16LE regardless of system arch
 *
 * This version converts from UTF-8 if the --encoding=utf8 option was given to
 * John and from the other character sets otherwise which is faster, since it
 * is a simple table lookup, vs computing wide characters.
 */
int enc_to_utf16(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src,
                 unsigned int srclen)
{
#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) != UTF_8) {
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
	} else {
#endif
		return utf8_to_utf16(dst, maxdstlen, src, srclen);
#ifndef UNICODE_NO_OPTIONS
	}
#endif
}

inline static int cp_to_utf16(UTF16 *dst, unsigned int maxdstlen,
                              const UTF8 *src, unsigned int srclen)
{
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
}

/*
 * Convert from current codepage to UTF-16BE regardless of arch
 */
int enc_to_utf16_be(UTF16 *dst, unsigned int maxdstlen, const UTF8 *src,
                    unsigned int srclen)
{
#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) != UTF_8) {
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
	} else {
#endif
		return _utf8_to_utf16_be(dst, maxdstlen, src, srclen);
#ifndef UNICODE_NO_OPTIONS
	}
#endif
}

/*
 * Strlen of UTF-32 (in 32-bit words, not octets).
 */
inline unsigned int strlen32(const UTF32 *str)
{
	unsigned int len = 0;
	while (*str++ != 0)
		len++;
	return len;
}

/*
 * Strlen of UTF-16 (in 16-bit words, not octets).
 * Characters > U+FFFF are two 16-bit words (surrogates).
 */
inline unsigned int strlen16(const UTF16 *str)
{
	unsigned int len = 0;
	while (*str++ != 0)
		len++;
	return len;
}

/*
 * Strlen of UTF-8 (in characters, not octets).
 * Will return a "truncated" length (negative) if fed with bad data.
 */
inline int strlen8(const UTF8 *source)
{
	int targetLen = 0;
	const UTF8 *sourceEnd = source + strlen((char*)source);
	unsigned int extraBytesToRead;

	while (*source && source < sourceEnd) {
		if (*source < 0xC0) {
			source++;
			targetLen++;
			if (*source == 0)
				break;
			continue;
		}
		extraBytesToRead = opt_trailingBytesUTF8[*source & 0x3f];
		if ((source + extraBytesToRead >= sourceEnd) || (extraBytesToRead > 3))
			return -targetLen;
		source += extraBytesToRead + 1;
		targetLen++;
		if (source >= sourceEnd)
			break;
	}
	return targetLen;
}
/*
 * Truncate (in place) a UTF-8 string at position 'len' (in characters, not octets), or when
 * invalid UTF-8 is seen (using the same Q'n'D logic that the kernels do).
 */
inline void truncate_utf8(UTF8 *string, int len)
{
	int targetLen = 0;
	const UTF8 *stringEnd = string + strlen((char*)string);
	unsigned int extraBytesToRead;

	while (*string && string < stringEnd && *string && targetLen < len) {
		if (*string < 0xC0) {
			string++;
			targetLen++;
			continue;
		}
		extraBytesToRead = opt_trailingBytesUTF8[*string & 0x3f];
		if ((string + extraBytesToRead >= stringEnd) || (extraBytesToRead > 3)) {
			*string = 0;
			return;
		}
		string += extraBytesToRead + 1;
		targetLen++;
		if (string >= stringEnd)
			break;
	}
	if (targetLen >= len)
		*string = 0;
}

/*
 * Return length (in characters) of a string, best-effort.
 * For a fully valid UTF-8 string, return number of characters.
 * If the string contains invalid UTF-8, just count bytes from that point.
 */
inline size_t strlen_any(const void *source)
{
	const UTF8 *src = source;
	int len;

	len = strlen8(src);
	if (len < 0) {
		size_t extra;
		len = -len;
		extra = strlen(&((char*)source)[len + 1]);
		len += extra;
	}
	return len;
}

/* Check if a string is valid UTF-8 */
int valid_utf8(const UTF8 *source)
{
	UTF8 a;
	int length, ret = 1;
	const UTF8 *srcptr;

	while (*source) {
		if (*source < 0x80) {
			source++;
			continue;
		}

		length = opt_trailingBytesUTF8[*source & 0x3f] + 1;
		srcptr = source + length;

		switch (length) {
		default:
			return 0;
			/* Everything else falls through when valid */
		case 4:
			if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return 0;
		case 3:
			if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return 0;
		case 2:
			if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return 0;

			switch (*source) {
				/* no fall-through in this inner switch */
			case 0xE0: if (a < 0xA0) return 0; break;
			case 0xED: if (a > 0x9F) return 0; break;
			case 0xF0: if (a < 0x90) return 0; break;
			case 0xF4: if (a > 0x8F) return 0;
			}

		case 1:
			if (*source >= 0x80 && *source < 0xC2) return 0;
		}
		if (*source > 0xF4)
			return 0;

		source += length;
		ret++;
	}
	return ret;
}

/*
 * Creates an MD4 Hash of the user's password in NT UNICODE.
 * This version honours the --encoding=utf8 flag and makes a couple
 * of formats utf8-aware with few further modifications.
 *
 * This is now thread-safe
 */
#ifndef NOT_JOHN
int E_md4hash(const UTF8 *passwd, unsigned int len, unsigned char *p16)
{
	int trunclen;
	UTF16 wpwd[PLAINTEXT_BUFFER_SIZE + 1];
	MD4_CTX ctx;

	/* Password is converted to UTF-16LE */
	trunclen = enc_to_utf16(wpwd, PLAINTEXT_BUFFER_SIZE, passwd, len);
	if (trunclen < 0)
		len = strlen16(wpwd); /* From UTF-8 you can't know */
	else
		len = trunclen;

	MD4_Init(&ctx);
	MD4_Update(&ctx, (unsigned char*)wpwd, len * sizeof(UTF16));
	MD4_Final(p16, &ctx);

	return trunclen;
}
#endif

/*
 * Convert UTF-16LE to UTF-8. This is not optimized as it's only used in
 * get_key() as of now. NOTE this is from LE regardless of architecture!
 * Non thread-safe version.
 */
UTF8 *utf16_to_utf8(const UTF16 *source)
{
	static UTF8 ret_Key[PLAINTEXT_BUFFER_SIZE + 1];
	return utf16_to_utf8_r(ret_Key, PLAINTEXT_BUFFER_SIZE, source);
}

/* Thread-safe version. NOTE this is from LE regardless of arch. */
UTF8 *utf16_to_utf8_r(UTF8 *dst, int dst_len, const UTF16 *source)
{
	UTF8 *tpt = dst;
	UTF8 *targetEnd = tpt + dst_len;
	while (*source) {
		UTF32 ch;
		unsigned short bytesToWrite = 0;
		const UTF32 byteMask = 0xBF;
		const UTF32 byteMark = 0x80;

		ch = *source++;
#if !ARCH_LITTLE_ENDIAN
		ch = (ch >> 8) | (UTF16)(ch << 8);
#endif
		/* If we have a surrogate pair, convert to UTF32 first. */
		if (ch >= UNI_SUR_HIGH_START && ch <= UNI_SUR_HIGH_END) {
			/*
			 * If the 16 bits following the high surrogate are
			 * in the source buffer...
			 */
			if (*source) {
				UTF32 ch2 = *source;
				/* If it's a low surrogate, convert to UTF32. */
				if (ch2 >= UNI_SUR_LOW_START && ch2 <= UNI_SUR_LOW_END) {
					ch = ((ch - UNI_SUR_HIGH_START) << halfShift)
						+ (ch2 - UNI_SUR_LOW_START) + halfBase;
					++source;
				}
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
			tpt -= bytesToWrite;
			break;
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
UTF8 *enc_to_utf8_r(char *src, UTF8 *dst, int dstlen)
{
	UTF16 tmp16[LINE_BUFFER_SIZE + 1];
	enc_to_utf16(tmp16, LINE_BUFFER_SIZE, (unsigned char*)src,
	             strlen((char*)src));
	dst = utf16_to_utf8_r(dst, dstlen, tmp16);
	return dst;
}

/* Thread-safe conversion from UTF-8 to codepage */
char *utf8_to_enc_r(UTF8 *src, char *dst, int dstlen)
{
	UTF16 tmp16[LINE_BUFFER_SIZE + 1];
	utf8_to_utf16(tmp16, LINE_BUFFER_SIZE, (unsigned char*)src,
	              strlen((char*)src));
	dst = (char*)utf16_to_enc_r((UTF8*)dst, dstlen, tmp16);
	return dst;
}

/*
 * Thread-safe conversion from codepage to UTF-8.
 */
char *cp_to_utf8_r(const char *src, char *dst, int dstlen)
{
	UTF16 tmp16[LINE_BUFFER_SIZE + 1];

	cp_to_utf16(tmp16, LINE_BUFFER_SIZE, (unsigned char*)src, strlen(src));
	return (char*)utf16_to_utf8_r((UTF8*)dst, dstlen, tmp16);
}

inline static UTF8 *utf16_to_cp_r(UTF8 *dst, int dst_len, const UTF16 *source)
{
	UTF8 *tgt = dst;
	UTF8 *targetEnd = tgt + dst_len;

	while (*source && tgt < targetEnd) {
#if ARCH_LITTLE_ENDIAN
		if ((*tgt = CP_from_Unicode[*source++]))
			tgt++;
#else
		if ((*tgt = CP_from_Unicode[(*source >> 8) |
		                            (UTF16)(*source << 8)]))
			tgt++;
		source++;
#endif
	}
	*tgt = 0;

	return dst;
}

/*
 * Thread-safe conversion from UTF-8 to codepage
 */
char *utf8_to_cp_r(const char *src, char *dst, int dstlen)
{
	UTF16 tmp16[LINE_BUFFER_SIZE + 1];

	utf8_to_utf16(tmp16, LINE_BUFFER_SIZE, (UTF8*)src, strlen(src));
	utf16_to_cp_r((UTF8*)dst, dstlen, tmp16);
	return (char*)dst;
}

/*
 * Convert UTF-16LE to codepage.
 * This variant will never convert to UTF-8 but the initialized codepage.
 */
char *utf16_to_cp(const UTF16 *source)
{
	static UTF8 ret_Key[LINE_BUFFER_SIZE + 1];

	utf16_to_cp_r(ret_Key, LINE_BUFFER_SIZE, source);
	return (char*)ret_Key;
}

/*
 * Convert UTF-16BE to codepage.
 * This is not optimized as it's only used in get_key() as of now.
 * Non thread-safe version.
 */
UTF8 *utf16_be_to_enc(const UTF16 *source)
{
	static UTF8 ret_Key[PLAINTEXT_BUFFER_SIZE + 1];
	UTF16 swapped[PLAINTEXT_BUFFER_SIZE + 1];
	const UTF16 *s = source;
	UTF16 c, *d = swapped;

	do {
		c = *s++;
#if ARCH_LITTLE_ENDIAN
		c = (c >> 8) | (UTF16)(c << 8);
#endif
		*d++ = c;
	} while (c);

	return utf16_to_enc_r(ret_Key, PLAINTEXT_BUFFER_SIZE, swapped);
}

/*
 * Convert UTF-16LE to codepage.
 * This is not optimized as it's only used in get_key() as of now.
 * Non thread-safe version.
 */
UTF8 *utf16_to_enc(const UTF16 *source)
{
	static UTF8 ret_Key[PLAINTEXT_BUFFER_SIZE + 1];
	return utf16_to_enc_r(ret_Key, PLAINTEXT_BUFFER_SIZE, source);
}

/* Thread-safe version. */
UTF8 *utf16_to_enc_r(UTF8 *dst, int dst_len, const UTF16 *source)
{
#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) == UTF_8)
#endif
		return utf16_to_utf8_r(dst, dst_len, source);
#ifndef UNICODE_NO_OPTIONS
	else
		return utf16_to_cp_r(dst, dst_len, source);
#endif
}

/* UTF-32 functions */
inline static UTF8 *utf32_to_utf8(UTF8 *dst, int dst_len, const UTF32 *source)
{
	UTF8 *tpt = dst;
	UTF8 *targetEnd = tpt + dst_len;
	while (*source) {
		UTF32 ch;
		unsigned short bytesToWrite = 0;
		const UTF32 byteMask = 0xBF;
		const UTF32 byteMark = 0x80;

		ch = *source++;

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
			tpt -= bytesToWrite;
			break;
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

inline int utf8_to_utf32(UTF32 *target, unsigned int len,
                         const UTF8 *source, unsigned int sourceLen)
{
	const UTF32 *targetStart = target;
	const UTF32 *targetEnd = target + len;
	const UTF8 *sourceStart = source;
	const UTF8 *sourceEnd = source + sourceLen;
	UTF32 ch;
	unsigned int extraBytesToRead;

	while (source < sourceEnd) {
		if (*source < 0xC0) {
			*target++ = (UTF32)*source++;
			if (*source == 0)
				break;
			if (target >= targetEnd) {
				*target = 0;
				return -1 * (source - sourceStart);
			}
			continue;
		}
		ch = *source;
/*
 * The original code in ConvertUTF.c has a much larger (slower) lookup table
 * including zeros. This point must not be reached with *source < 0xC0
 */
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

		*target++ = (UTF32)ch;

		if (*source == 0)
			break;
		if (target >= targetEnd) {
			*target = 0;
			return -1 * (source - sourceStart);
		}
	}
	*target = 0;
	return (target - targetStart);
}

inline static UTF8 *utf32_to_cp(UTF8 *dst, int dst_len, const UTF32 *source)
{
	UTF8 *tgt = dst;
	UTF8 *targetEnd = tgt + dst_len;

	while (*source && tgt < targetEnd) {
		if ((*tgt = CP_from_Unicode[*source++ & 0xffff]))
			tgt++;
	}
	*tgt = 0;

	return dst;
}

inline static int cp_to_utf32(UTF32 *dst, unsigned int maxdstlen, const UTF8 *src,
                              unsigned int srclen)
{
	int i, trunclen = (int)srclen;
	if (trunclen > maxdstlen)
		trunclen = maxdstlen;

	for (i = 0; i < trunclen; i++)
		*dst++ = CP_to_Unicode[*src++];
	*dst = 0;
	if (i < srclen)
		return -i;
	else
		return i;
}

int enc_to_utf32(UTF32 *dst, unsigned int maxdstlen, const UTF8 *src,
                 unsigned int srclen)
{
#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) != UTF_8)
		return cp_to_utf32(dst, maxdstlen, src, srclen);
	else
#endif
		return utf8_to_utf32(dst, maxdstlen, src, srclen);
}

UTF8 *utf32_to_enc(UTF8 *dst, int dst_len, const UTF32 *source)
{
#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) == UTF_8)
#endif
		return utf32_to_utf8(dst, dst_len, source);
#ifndef UNICODE_NO_OPTIONS
	else
		return utf32_to_cp(dst, dst_len, source);
#endif
}

char *wcs_to_enc(char *dest, size_t dst_sz, const wchar_t *src)
{
#if SIZEOF_WCHAR_T == 4
	utf32_to_enc((UTF8*)dest, dst_sz, (UTF32*)src);
#elif SIZEOF_WCHAR_T == 2 && ARCH_LITTLE_ENDIAN
	utf16_to_enc_r((UTF8*)dest, dst_sz, (UTF16*)src);
#else
	wcstombs(dest, src, dst_sz);
#endif
	return dest;
}

int enc_to_wcs(wchar_t *dest, size_t dst_sz, const char *src)
{
#if SIZEOF_WCHAR_T == 4
	return enc_to_utf32((UTF32*)dest, dst_sz, (UTF8*)src, strlen(src));
#elif SIZEOF_WCHAR_T == 2 && ARCH_LITTLE_ENDIAN
	return enc_to_utf16((UTF16*)dest, dst_sz, (UTF8*)src, strlen(src));
#else
	return mbstowcs(dest, src, dst_sz);
#endif
}

int cp_to_wcs(wchar_t *dest, size_t dst_sz, const char *src)
{
#if SIZEOF_WCHAR_T == 4
	return cp_to_utf32((UTF32*)dest, dst_sz, (UTF8*)src, strlen(src));
#elif SIZEOF_WCHAR_T == 2 && ARCH_LITTLE_ENDIAN
	return cp_to_utf16((UTF16*)dest, dst_sz, (UTF8*)src, strlen(src));
#else
	return mbstowcs(dest, src, dst_sz);
#endif
}

void listEncodings(FILE *fd)
{
	fprintf(fd, "ASCII (or RAW), UTF-8, ISO-8859-1 (or Latin1 or ANSI),\n"
	        "ISO-8859-2, ISO-8859-7, ISO-8859-15, KOI8-R,\n"
	        "CP437, CP720, CP737, CP850, CP852, CP858, CP866, CP868,\n"
	        "CP1250, CP1251, CP1252, CP1253, CP1254, CP1255, CP1256\n");
}

static char *enc_name[] = { "UNDEF", "RAW", "CP437", "CP720", "CP737",
                            "CP850", "CP852", "CP858", "CP866", "CP868",
                            "CP1250", "CP1251", "CP1252", "CP1253", "CP1254",
                            "CP1255", "CP1256", "ISO-8859-1",
                            "ISO-8859-2", "ISO-8859-7", "ISO-8859-15",
                            "KOI8-R", "UTF-8" };

/* Convert numerical encoding ID to canonical name */
char *cp_id2name(int encoding)
{
	if (encoding >= 0 && encoding <= CP_ARRAY)
		return enc_name[encoding];

	fprintf(stderr, "ERROR: %s(%d)\n", __FUNCTION__, encoding);
	error();
}

static char *enc_macro[] = { "UNDEF", "ENC_RAW", "CP437", "CP720", "CP737",
                             "CP850", "CP852", "CP858", "CP866", "CP868",
                             "CP1250", "CP1251", "CP1252", "CP1253", "CP1254",
                             "CP1255", "CP1256", "ISO_8859_1",
                             "ISO_8859_2", "ISO_8859_7", "ISO_8859_15",
                             "KOI8_R", "UTF_8" };

/* Convert numerical encoding ID to name that can be used in macros */
char *cp_id2macro(int encoding)
{
	if (encoding >= 0 && encoding <= CP_ARRAY)
		return enc_macro[encoding];

	fprintf(stderr, "ERROR: %s(%d)\n", __FUNCTION__, encoding);
	error();
}

/* Convert encoding name to numerical ID */
int cp_name2id(const char *encoding, int error_exit)
{
	const char *orig_arg = encoding;
	char enc[16] = "";
	char *d = enc;

	if (!encoding || !encoding[0])
		return CP_UNDEF;
	if (strlen(encoding) > sizeof(enc))
		goto err;

	/* Strip iso prefix */
	if (!strncasecmp(encoding, "iso-", 4))
		encoding += 4;
	else if (!strncasecmp(encoding, "iso", 3))
		encoding += 3;
	/* Strip cp prefix */
	else if (!strncasecmp(encoding, "cp", 2))
		encoding += 2;

	/* Lowercase */
	do {
		if (*encoding >= 'A' && *encoding <= 'Z')
			*d++ = *encoding++ | 0x20;
		else
			*d++ = *encoding++;
	} while (*encoding);

	/* Now parse this canonical format */
	if (!strcmp(enc, "utf8") || !strcmp(enc, "utf-8"))
		return UTF_8;
	else
	if (!strcmp(enc, "8859-1") || !strcmp(enc, "ansi") ||
	    !strcmp(enc, "latin1"))
		return ISO_8859_1;
	else
	if (!strcmp(enc, "8859-2"))
		return ISO_8859_2;
	else
	if (!strcmp(enc, "8859-7"))
		return ISO_8859_7;
	else
	if (!strcmp(enc, "8859-15"))
		return ISO_8859_15;
	else
	if (!strcmp(enc, "koi8r") || !strcmp(enc, "koi8-r"))
		return KOI8_R;
	else
	if (!strcmp(enc, "437"))
		return CP437;
	else
	if (!strcmp(enc, "720"))
		return CP720;
	else
	if (!strcmp(enc, "737"))
		return CP737;
	else
	if (!strcmp(enc, "850"))
		return CP850;
	else
	if (!strcmp(enc, "852"))
		return CP852;
	else
	if (!strcmp(enc, "858"))
		return CP858;
	else
	if (!strcmp(enc, "866"))
		return CP866;
	else
	if (!strcmp(enc, "868"))
		return CP868;
	else
	if (!strcmp(enc, "1250"))
		return CP1250;
	else
	if (!strcmp(enc, "1251"))
		return CP1251;
	else
	if (!strcmp(enc, "1252"))
		return CP1252;
	else
	if (!strcmp(enc, "1253"))
		return CP1253;
	else
	if (!strcmp(enc, "1254"))
		return CP1254;
	else
	if (!strcmp(enc, "1255"))
		return CP1255;
	else
	if (!strcmp(enc, "1256"))
		return CP1256;
	else
	if (!strcmp(enc, "raw") || !strcmp(enc, "ascii"))
		return ENC_RAW;

 err:
	if (error_exit) {
		fprintf(stderr, "Invalid encoding '%s'. Supported encodings:\n", orig_arg);
		listEncodings(stderr);
		error();
	} else
		return CP_UNDEF;
}

int cp_class(int encoding)
{
	if (encoding >= CP_DOS_LO && encoding <= CP_DOS_HI)
		return CP_DOS;
	else if (encoding >= CP_WIN_LO && encoding <= CP_WIN_HI)
		return CP_WIN;
	else if (encoding >= CP_ISO_LO && encoding <= CP_ISO_HI)
		return CP_ISO;
	else
		return CP_UNDEF;
}

/* Load the 'case-conversion' and other translation tables. */
void initUnicode(int type)
{
	unsigned i, j;
#ifndef UNICODE_NO_OPTIONS
	unsigned char *cpU, *cpL, *Sep, *Letter, *Digit;
	unsigned char *pos;
	int encoding;

	/* Default to core John's behavior */
	if (!options.input_enc) {
		options.input_enc = ENC_RAW;
		options.default_enc = 1;
	}

	if (!options.target_enc)
		options.target_enc = options.input_enc;

	if (!options.internal_cp)
		options.internal_cp = options.target_enc;

	if (options.internal_cp != options.target_enc)
		encoding = options.internal_cp;
	else if (options.target_enc != options.input_enc)
		encoding = options.target_enc;
	else
		encoding = options.input_enc;

	if (encoding != UTF_8)
		options.unicode_cp = encoding;
	else
		options.unicode_cp = ISO_8859_1;

	if (UnicodeType == type && UnicodeInited == options.unicode_cp)
		return;

	if (options.verbosity >= VERB_MAX) {
		fprintf(stderr, "%s(%s, %s/%s)\n", __FUNCTION__,
		        type == 1 ? "MS_OLD" :
		        type == 2 ? "MS_NEW" : "UNICODE",
		        cp_id2name(encoding), cp_id2name(options.unicode_cp));
		fprintf(stderr, "%s -> %s -> %s\n",
		        cp_id2name(options.input_enc),
		        cp_id2name(options.internal_cp),
		        cp_id2name(options.target_enc));
	}

	UnicodeType = type;
	UnicodeInited = options.unicode_cp;
	memset(ucs2_upcase, 0, sizeof(ucs2_upcase));
	memset(ucs2_downcase, 0, sizeof(ucs2_downcase));

/*
 * If we are handling MSSQL format (the old upper case, then we MUST use
 * arTo[UL]CDat_WinXP arrays, and NOTE use the multi-char stuff. I know this
 * may 'not' be right, but for now, I will be doing all unicode in the
 * MSSQL-2000 way. When initUnicode gets called, we do not know what format we
 * are 'testing' against. We may have to split up the initialzation into 2
 * parts.  One part done early, and the 2nd part done, when we know what
 * format we are using. This is still TBD on how best to do it.
 */
	if (type == UNICODE_MS_OLD) {
		if (encoding == ENC_RAW) {
/*
 * The 'proper' default encoding for mssql IS CP1252. The test suite will have
 * a TON of failures, unless this is set this way.  All of the data IN that
 * test suite, was made using MSSQL.
 */
			UnicodeInited = encoding = CP1252;
		}
		for (i = 0; arToUCDat_WinXP[i]; i += 2)
			ucs2_upcase[arToUCDat_WinXP[i]] = arToUCDat_WinXP[i+1];
		for (i = 0; arToLCDat_WinXP[i]; i += 2)
			ucs2_downcase[arToLCDat_WinXP[i]] =
				arToLCDat_WinXP[i+1];

		/* Required for cp737, MSSQL_old */
		ucs2_upcase[0x03C2] = 0x03C2; /* U+03C2 -> U+03A3 was not cased */
		ucs2_downcase[0x03A3] = 0x03A3; /* U+03A3 -> U+03C2 was not cased */
	} else if (type == UNICODE_MS_NEW) {
		for (i = 0; arToUCDat_WinVista[i]; i += 2)
			ucs2_upcase[arToUCDat_WinVista[i]] =
				arToUCDat_WinVista[i+1];
		for (i = 0; arToLCDat_WinVista[i]; i += 2)
			ucs2_downcase[arToLCDat_WinVista[i]] =
				arToLCDat_WinVista[i+1];
	} else {
		for (i = 0; arToUCDat_UCData_txt[i]; i += 2)
			ucs2_upcase[arToUCDat_UCData_txt[i]] =
				arToUCDat_UCData_txt[i+1];
		for (i = 0; arToLCDat_UCData_txt[i]; i += 2)
			ucs2_downcase[arToLCDat_UCData_txt[i]] =
				arToLCDat_UCData_txt[i+1];

		/* set a 1 for any 'multi-char' converts. */
		for (i = 0; uniMultiCase[i].Val; ++i)
			if (uniMultiCase[i].bIsUp2Low)
				ucs2_downcase[uniMultiCase[i].Val] = 1;
			else
				ucs2_upcase[uniMultiCase[i].Val] = 1;
	}

/*
 * Here we setup the 8-bit codepages we handle, and setup the mapping values
 * into Unicode.
 */
	for (i = 0; i < 128; ++i) {
		CP_to_Unicode[i] = i;
	}
	for (i = 128; i < 256; ++i) {
		switch(encoding) {
		case ISO_8859_2:
			CP_to_Unicode[i] = ISO_8859_2_to_unicode_high128[i-128];
			break;
		case ISO_8859_7:
			CP_to_Unicode[i] = ISO_8859_7_to_unicode_high128[i-128];
			break;
		case ISO_8859_15:
			CP_to_Unicode[i] =
				ISO_8859_15_to_unicode_high128[i-128];
			break;
		case KOI8_R:
			CP_to_Unicode[i] = KOI8_R_to_unicode_high128[i-128];
			break;
		case CP437:
			CP_to_Unicode[i] = CP437_to_unicode_high128[i-128];
			break;
		case CP720:
			CP_to_Unicode[i] = CP720_to_unicode_high128[i-128];
			break;
		case CP737:
			CP_to_Unicode[i] = CP737_to_unicode_high128[i-128];
			break;
		case CP850:
			CP_to_Unicode[i] = CP850_to_unicode_high128[i-128];
			break;
		case CP852:
			CP_to_Unicode[i] = CP852_to_unicode_high128[i-128];
			break;
		case CP858:
			CP_to_Unicode[i] = CP858_to_unicode_high128[i-128];
			break;
		case CP866:
			CP_to_Unicode[i] = CP866_to_unicode_high128[i-128];
			break;
		case CP868:
			CP_to_Unicode[i] = CP868_to_unicode_high128[i-128];
			break;
		case CP1250:
			CP_to_Unicode[i] = CP1250_to_unicode_high128[i-128];
			break;
		case CP1251:
			CP_to_Unicode[i] = CP1251_to_unicode_high128[i-128];
			break;
		case CP1252:
			CP_to_Unicode[i] = CP1252_to_unicode_high128[i-128];
			break;
		case CP1253:
			CP_to_Unicode[i] = CP1253_to_unicode_high128[i-128];
			break;
		case CP1254:
			CP_to_Unicode[i] = CP1254_to_unicode_high128[i-128];
			break;
		case CP1255:
			CP_to_Unicode[i] = CP1255_to_unicode_high128[i-128];
			break;
		case CP1256:
			CP_to_Unicode[i] = CP1256_to_unicode_high128[i-128];
			break;
		default: /* 8859-1 */
			CP_to_Unicode[i] = ISO_8859_1_to_unicode_high128[i-128];
		}
	}
	memset(CP_from_Unicode, options.replacement_character, sizeof(CP_from_Unicode));
	for (i = 0; i < 128; ++i)
		CP_from_Unicode[i] = i;

	/* Now our actual selected codepage */
	for (i = 0; i < 128; ++i) {
		switch(encoding) {
		case ISO_8859_2:
			CP_from_Unicode[ISO_8859_2_to_unicode_high128[i]] =
				i+128;
			break;
		case ISO_8859_7:
			CP_from_Unicode[ISO_8859_7_to_unicode_high128[i]] =
				i+128;
			break;
		case ISO_8859_15:
			CP_from_Unicode[ISO_8859_15_to_unicode_high128[i]] =
				i+128;
			break;
		case KOI8_R:
			CP_from_Unicode[KOI8_R_to_unicode_high128[i]] = i+128;
			break;
		case CP437:
			CP_from_Unicode[CP437_to_unicode_high128[i]] = i+128;
			break;
		case CP720:
			CP_from_Unicode[CP720_to_unicode_high128[i]] = i+128;
			break;
		case CP737:
			CP_from_Unicode[CP737_to_unicode_high128[i]] = i+128;
			break;
		case CP850:
			CP_from_Unicode[CP850_to_unicode_high128[i]] = i+128;
			break;
		case CP852:
			CP_from_Unicode[CP852_to_unicode_high128[i]] = i+128;
			break;
		case CP858:
			CP_from_Unicode[CP858_to_unicode_high128[i]] = i+128;
			break;
		case CP866:
			CP_from_Unicode[CP866_to_unicode_high128[i]] = i+128;
			break;
		case CP868:
			CP_from_Unicode[CP868_to_unicode_high128[i]] = i+128;
			break;
		case CP1250:
			CP_from_Unicode[CP1250_to_unicode_high128[i]] = i+128;
			break;
		case CP1251:
			CP_from_Unicode[CP1251_to_unicode_high128[i]] = i+128;
			break;
		case CP1252:
			CP_from_Unicode[CP1252_to_unicode_high128[i]] = i+128;
			break;
		case CP1253:
			CP_from_Unicode[CP1253_to_unicode_high128[i]] = i+128;
			break;
		case CP1254:
			CP_from_Unicode[CP1254_to_unicode_high128[i]] = i+128;
			break;
		case CP1255:
			CP_from_Unicode[CP1255_to_unicode_high128[i]] = i+128;
			break;
		case CP1256:
			CP_from_Unicode[CP1256_to_unicode_high128[i]] = i+128;
			break;
		default:
			CP_from_Unicode[ISO_8859_1_to_unicode_high128[i]] =
				i+128;
			if (!i)
				CP_from_Unicode[0x39C] = 0xB5;
		}
	}

	/* First set ALL characters to have NO conversion. */
	for (i = 0; i < 256; ++i)
		CP_up[i] = CP_down[i] = i;

	/*
	 * Standard case change for 7 bit characters (lower 128 bytes),
	 * for all codepages.
	 */
	for (i = 'a'; i <= 'z'; ++i) {
		CP_up[i] = (i ^ 0x20);
		CP_down[i ^ 0x20] = (i);
	}

	/* Original separator list from loader.c */
#define CP_issep \
	"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\177"

	/*
	 * Now handle upper 128 byte values for casing.
	 * CHARS_LOW_ONLY_xxxx is not needed.
	 */
	switch(encoding) {
	case ISO_8859_1:
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_1;
		cpL = (unsigned char*)CHARS_LOWER_ISO_8859_1;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_ISO_8859_1
			CHARS_SPECIALS_ISO_8859_1 CHARS_WHITESPACE_ISO_8859_1
			CHARS_CONTROL_ISO_8859_1 CHARS_INVALID_ISO_8859_1;
		Letter = (unsigned char*)CHARS_ALPHA_ISO_8859_1;
		Digit = (unsigned char*)CHARS_DIGITS_ISO_8859_1;
		break;
	case ISO_8859_2:
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_2;
		cpL = (unsigned char*)CHARS_LOWER_ISO_8859_2;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_ISO_8859_2
			CHARS_SPECIALS_ISO_8859_2 CHARS_WHITESPACE_ISO_8859_2
			CHARS_CONTROL_ISO_8859_2 CHARS_INVALID_ISO_8859_2;
		Letter = (unsigned char*)CHARS_ALPHA_ISO_8859_2;
		Digit = (unsigned char*)CHARS_DIGITS_ISO_8859_2;
		break;
	case ISO_8859_7:
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_7;
		cpL = (unsigned char*)CHARS_LOWER_ISO_8859_7;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_ISO_8859_7
			CHARS_SPECIALS_ISO_8859_7 CHARS_WHITESPACE_ISO_8859_7
			CHARS_CONTROL_ISO_8859_7 CHARS_INVALID_ISO_8859_7;
		Letter = (unsigned char*)CHARS_ALPHA_ISO_8859_7;
		Digit = (unsigned char*)CHARS_DIGITS_ISO_8859_7;
		break;
	case ISO_8859_15:
		cpU = (unsigned char*)CHARS_UPPER_ISO_8859_15;
		cpL = (unsigned char*)CHARS_LOWER_ISO_8859_15;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_ISO_8859_15
			CHARS_SPECIALS_ISO_8859_15 CHARS_WHITESPACE_ISO_8859_15
			CHARS_CONTROL_ISO_8859_15 CHARS_INVALID_ISO_8859_15;
		Letter = (unsigned char*)CHARS_ALPHA_ISO_8859_15;
		Digit = (unsigned char*)CHARS_DIGITS_ISO_8859_15;
		break;
	case KOI8_R:
		cpU = (unsigned char*)CHARS_UPPER_KOI8_R;
		cpL = (unsigned char*)CHARS_LOWER_KOI8_R;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_KOI8_R
			CHARS_SPECIALS_KOI8_R CHARS_WHITESPACE_KOI8_R
			CHARS_CONTROL_KOI8_R CHARS_INVALID_KOI8_R;
		Letter = (unsigned char*)CHARS_ALPHA_KOI8_R;
		Digit = (unsigned char*)CHARS_DIGITS_KOI8_R;
		break;
	case CP437:
		cpU = (unsigned char*)CHARS_UPPER_CP437;
		cpL = (unsigned char*)CHARS_LOWER_CP437;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP437
			CHARS_SPECIALS_CP437 CHARS_WHITESPACE_CP437
			CHARS_CONTROL_CP437 CHARS_INVALID_CP437;
		Letter = (unsigned char*)CHARS_ALPHA_CP437;
		Digit = (unsigned char*)CHARS_DIGITS_CP437;
		break;
	case CP720:
		cpU = (unsigned char*)CHARS_UPPER_CP720;
		cpL = (unsigned char*)CHARS_LOWER_CP720;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP720
			CHARS_SPECIALS_CP720 CHARS_WHITESPACE_CP720
			CHARS_CONTROL_CP720 CHARS_INVALID_CP720;
		Letter = (unsigned char*)CHARS_ALPHA_CP720;
		Digit = (unsigned char*)CHARS_DIGITS_CP720;
		break;
	case CP737:
		cpU = (unsigned char*)CHARS_UPPER_CP737;
		cpL = (unsigned char*)CHARS_LOWER_CP737;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP737
			CHARS_SPECIALS_CP737 CHARS_WHITESPACE_CP737
			CHARS_CONTROL_CP737 CHARS_INVALID_CP737;
		Letter = (unsigned char*)CHARS_ALPHA_CP737;
		Digit = (unsigned char*)CHARS_DIGITS_CP737;
		break;
	case CP850:
		cpU = (unsigned char*)CHARS_UPPER_CP850;
		cpL = (unsigned char*)CHARS_LOWER_CP850;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP850
			CHARS_SPECIALS_CP850 CHARS_WHITESPACE_CP850
			CHARS_CONTROL_CP850 CHARS_INVALID_CP850;
		Letter = (unsigned char*)CHARS_ALPHA_CP850;
		Digit = (unsigned char*)CHARS_DIGITS_CP850;
		break;
	case CP852:
		cpU = (unsigned char*)CHARS_UPPER_CP852;
		cpL = (unsigned char*)CHARS_LOWER_CP852;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP852
			CHARS_SPECIALS_CP852 CHARS_WHITESPACE_CP852
			CHARS_CONTROL_CP852 CHARS_INVALID_CP852;
		Letter = (unsigned char*)CHARS_ALPHA_CP852;
		Digit = (unsigned char*)CHARS_DIGITS_CP852;
		break;
	case CP858:
		cpU = (unsigned char*)CHARS_UPPER_CP858;
		cpL = (unsigned char*)CHARS_LOWER_CP858;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP858
			CHARS_SPECIALS_CP858 CHARS_WHITESPACE_CP858
			CHARS_CONTROL_CP858 CHARS_INVALID_CP858;
		Letter = (unsigned char*)CHARS_ALPHA_CP858;
		Digit = (unsigned char*)CHARS_DIGITS_CP858;
		break;
	case CP866:
		cpU = (unsigned char*)CHARS_UPPER_CP866;
		cpL = (unsigned char*)CHARS_LOWER_CP866;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP866
			CHARS_SPECIALS_CP866 CHARS_WHITESPACE_CP866
			CHARS_CONTROL_CP866 CHARS_INVALID_CP866;
		Letter = (unsigned char*)CHARS_ALPHA_CP866;
		Digit = (unsigned char*)CHARS_DIGITS_CP866;
		break;
	case CP868:
		cpU = (unsigned char*)CHARS_UPPER_CP868;
		cpL = (unsigned char*)CHARS_LOWER_CP868;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP868
			CHARS_SPECIALS_CP868 CHARS_WHITESPACE_CP868
			CHARS_CONTROL_CP868 CHARS_INVALID_CP868;
		Letter = (unsigned char*)CHARS_ALPHA_CP868;
		Digit = (unsigned char*)CHARS_DIGITS_CP868;
		break;
	case CP1250:
		cpU = (unsigned char*)CHARS_UPPER_CP1250;
		cpL = (unsigned char*)CHARS_LOWER_CP1250;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1250
			CHARS_SPECIALS_CP1250 CHARS_WHITESPACE_CP1250
			CHARS_CONTROL_CP1250 CHARS_INVALID_CP1250;
		Letter = (unsigned char*)CHARS_ALPHA_CP1250;
		Digit = (unsigned char*)CHARS_DIGITS_CP1250;
		break;
	case CP1251:
		cpU = (unsigned char*)CHARS_UPPER_CP1251;
		cpL = (unsigned char*)CHARS_LOWER_CP1251;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1251
			CHARS_SPECIALS_CP1251 CHARS_WHITESPACE_CP1251
			CHARS_CONTROL_CP1251 CHARS_INVALID_CP1251;
		Letter = (unsigned char*)CHARS_ALPHA_CP1251;
		Digit = (unsigned char*)CHARS_DIGITS_CP1251;
		break;
	case CP1252:
		cpU = (unsigned char*)CHARS_UPPER_CP1252;
		cpL = (unsigned char*)CHARS_LOWER_CP1252;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1252
			CHARS_SPECIALS_CP1252 CHARS_WHITESPACE_CP1252
			CHARS_CONTROL_CP1252 CHARS_INVALID_CP1252;
		Letter = (unsigned char*)CHARS_ALPHA_CP1252;
		Digit = (unsigned char*)CHARS_DIGITS_CP1252;
		break;
	case CP1253:
		cpU = (unsigned char*)CHARS_UPPER_CP1253;
		cpL = (unsigned char*)CHARS_LOWER_CP1253;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1253
			CHARS_SPECIALS_CP1253 CHARS_WHITESPACE_CP1253
			CHARS_CONTROL_CP1253 CHARS_INVALID_CP1253;
		Letter = (unsigned char*)CHARS_ALPHA_CP1253;
		Digit = (unsigned char*)CHARS_DIGITS_CP1253;
		break;
	case CP1254:
		cpU = (unsigned char*)CHARS_UPPER_CP1254;
		cpL = (unsigned char*)CHARS_LOWER_CP1254;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1254
			CHARS_SPECIALS_CP1254 CHARS_WHITESPACE_CP1254
			CHARS_CONTROL_CP1254 CHARS_INVALID_CP1254;
		Letter = (unsigned char*)CHARS_ALPHA_CP1254;
		Digit = (unsigned char*)CHARS_DIGITS_CP1254;
		break;
	case CP1255:
		cpU = (unsigned char*)CHARS_UPPER_CP1255;
		cpL = (unsigned char*)CHARS_LOWER_CP1255;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1255
			CHARS_SPECIALS_CP1255 CHARS_WHITESPACE_CP1255
			CHARS_CONTROL_CP1255 CHARS_INVALID_CP1255;
		Letter = (unsigned char*)CHARS_ALPHA_CP1255;
		Digit = (unsigned char*)CHARS_DIGITS_CP1255;
		break;
	case CP1256:
		cpU = (unsigned char*)CHARS_UPPER_CP1256;
		cpL = (unsigned char*)CHARS_LOWER_CP1256;
		Sep = (unsigned char*)CP_issep CHARS_PUNCTUATION_CP1256
			CHARS_SPECIALS_CP1256 CHARS_WHITESPACE_CP1256
			CHARS_CONTROL_CP1256 CHARS_INVALID_CP1256;
		Letter = (unsigned char*)CHARS_ALPHA_CP1256;
		Digit = (unsigned char*)CHARS_DIGITS_CP1256;
		break;
	default:
		cpU = (unsigned char*)"";
		cpL = (unsigned char*)"";
		Sep = (unsigned char*)CP_issep;
		Letter = (unsigned char*)"";
		Digit = (unsigned char*)"";
	}

	for (i = 0; cpU[i]; ++i) {
		CP_down[(unsigned)cpU[i]] = cpL[i];
		CP_up[(unsigned)cpL[i]] = cpU[i];
	}

	/* CP_isSeparator[c] will return true if c is a separator */
	memset(CP_isSeparator, 0, sizeof(CP_isSeparator));
	memset(CP_isSeparator, 1, 33);
	for (pos = Sep; *pos; pos++)
		CP_isSeparator[ARCH_INDEX(*pos)] = 1;

	/* CP_isDigit[c] will return true if c is a digit */
	memset(CP_isDigit, 0, sizeof(CP_isDigit));
	for (i = '0'; i <= '9'; i++)
		CP_isDigit[i] = 1;
	for (pos = Digit; *pos; pos++)
		CP_isDigit[ARCH_INDEX(*pos)] = 1;

	/* CP_isLetter[c] will return true if c is a letter */
	memset(CP_isLetter, 0, sizeof(CP_isLetter));
	memset(CP_isLower, 0, sizeof(CP_isLower));
	memset(CP_isUpper, 0, sizeof(CP_isUpper));
	for (i = 'a'; i <= 'z'; i++) {
		CP_isLetter[i] = 1;
		CP_isLower[i] = 1;
	}
	for (i = 'A'; i <= 'Z'; i++) {
		CP_isLetter[i] = 1;
		CP_isUpper[i] = 1;
	}
	for (pos = Letter; *pos; pos++)
		CP_isLetter[ARCH_INDEX(*pos)] = 1;
	for (pos = cpL; *pos; pos++)
		CP_isLower[ARCH_INDEX(*pos)] = 1;
	for (pos = cpU; *pos; pos++)
		CP_isUpper[ARCH_INDEX(*pos)] = 1;

	if (type == UNICODE_MS_OLD && encoding == CP850) {
/*
 * We 'do' have allow uc of U+0131 into U+0049 (but there is NO reverse of this
 * CP_up[0xD5] = 0x49; this is 'default' in encoding_data.h right now.
 *
 * for mssql, we HAVE to leave this one 100% alone!
 */
		CP_up[0xD5] = 0xD5;
	}

	if (type == UNICODE_MS_OLD && encoding == CP737) {
		/* Required for cp737, MSSQL_old */
		//ucs2_upcase[0x03C2] = 0x03C2; //U+03C2 -> U+03A3 was not cased
		CP_up[0xAA] = 0xAA;
		CP_down[0x91] = 0x91;
	}
#endif
	j = 0;
	for (i = 0; i < 256; i++) {
		if (CP_up[i] != CP_down[i]) {
			CP_ups[j] = CP_up[i];
			CP_lows[j++] = CP_down[i];
		}
	}
	return;
}

/* Lowercase UTF-16 LE (regardless of arch) */
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
			*dst = BE_FIX(cur_src);
		else {
			if (ucs2_downcase[ cur_src ] & 0xFFFE) {
				*dst = BE_FIX(ucs2_downcase[ cur_src ]);
			}
			else {
				/* multi-byte. */
				int k, l;
				for (k = 0; uniMultiCase[k].Val; ++k) {
					if (uniMultiCase[k].Val == cur_src) {
						if (j + uniMultiCase[k].Cnt >= dst_len) {
							*dst = 0;
							return -j;
						}
						for (l = 0; l < uniMultiCase[k].Cnt; ++l)
							dst[l] = BE_FIX(uniMultiCase[k].ToVals[l]);
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

/* Uppercase UTF-16 LE (regardless of arch) */
int utf16_uc(UTF16 *dst, unsigned dst_len, const UTF16 *src, unsigned src_len)
{
	int i, j = 0;
	UTF16 cur_src;
	for (i = 0; i < src_len; ++i, ++j, ++src, ++dst) {
		if (j == dst_len) {
			*dst = 0;
			return -j;
		}
		cur_src = BE_FIX(*src);
		if (ucs2_upcase[ cur_src ] == 0)
			*dst = BE_FIX(cur_src);
		else {
			if (ucs2_upcase[ cur_src ] & 0xFFFE) {
				*dst = BE_FIX(ucs2_upcase[ cur_src ]);
			}
			else {
				/* multi-byte. */
				int k, l;
				for (k = 0; uniMultiCase[k].Val; ++k) {
					if (uniMultiCase[k].Val == cur_src) {
						if (j + uniMultiCase[k].Cnt >= dst_len) {
							*dst = 0;
							return -j;
						}
						for (l = 0; l < uniMultiCase[k].Cnt; ++l)
							dst[l] = BE_FIX(uniMultiCase[k].ToVals[l]);
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

/* Lowercase UTF-8 or codepage encoding */
int enc_lc(UTF8 *dst, unsigned dst_bufsize, const UTF8 *src, unsigned src_len)
{
	UTF16 tmp16[512+1], tmp16l[512+1];
	int utf16len, i;

#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) != UTF_8) {
		if (dst_bufsize <= src_len)
			src_len = dst_bufsize - 1;
		for (i = 0; i < src_len; ++i) {
			*dst++ = CP_down[*src++];
		}
		*dst = 0;
		return src_len;
	}
#endif
	utf16len = utf8_to_utf16(tmp16, 512, src, src_len);
	if (utf16len <= 0)
		goto lcFallback;
	utf16len = utf16_lc(tmp16l, 512, tmp16, utf16len);
	if (utf16len <= 0)
		goto lcFallback;
	utf16_to_enc_r(dst, dst_bufsize, tmp16l);
	return strlen((char*)dst);

/* If we failed doing the right thing (garbage data) we just do ASCII lc */
lcFallback:
	if (dst_bufsize <= src_len)
		src_len = dst_bufsize - 1;
	for (i = 0; i < src_len; ++i)
		if (*src >= 'A' && *src <= 'Z')
			*dst++ = *src++ | 0x20;
		else
			*dst++ = *src++;
	*dst = 0;
	return src_len;
}

/* Uppercase UTF-8 or codepage encoding */
int enc_uc(UTF8 *dst, unsigned dst_bufsize, const UTF8 *src, unsigned src_len)
{
	UTF16 tmp16[512+1], tmp16u[512+1];
	int utf16len, i;

#ifndef UNICODE_NO_OPTIONS
	if ((options.target_enc ? options.target_enc : options.input_enc) != UTF_8) {
		int len;
		if (dst_bufsize <= src_len)
			src_len = dst_bufsize - 1;
		len=src_len;
#if 0  // Defined out until we need it
		if (UnicodeType == UNICODE_UNICODE) {
			for (i = 0; i < src_len; ++i) {
				if (*src == 0xDF) { /* this goes out as 2 chars. */
					++len;
					if (len > dst_bufsize) {
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
#endif

	utf16len = utf8_to_utf16(tmp16, 512, src, src_len);
	if (utf16len <= 0)
		goto ucFallback;
	utf16len = utf16_uc(tmp16u, 512, tmp16, utf16len);
	if (utf16len <= 0)
		goto ucFallback;
	utf16_to_enc_r(dst, dst_bufsize, tmp16u);
	return strlen((char*)dst);

/* If we failed doing the right thing (garbage data) we just do ASCII uc */
ucFallback:
	if (dst_bufsize <= src_len)
		src_len = dst_bufsize - 1;
	for (i = 0; i < src_len; ++i)
		if (*src >= 'a' && *src <= 'z')
			*dst++ = *src++ ^ 0x20;
		else
			*dst++ = *src++;
	*dst = 0;
	return src_len;
}

/* Encoding-aware strlwr(): Simple in-place lowercasing */
char *enc_strlwr(char *s)
{
	unsigned char *ptr = (unsigned char*)s;
	int srclen = strlen(s);
	enc_lc(ptr, srclen + 1, ptr, srclen);
	return s;
}

/* Simple in-place uppercasing */
char *enc_strupper(char *s)
{
	unsigned char *ptr = (unsigned char*)s;
	int srclen = strlen(s);
	enc_uc(ptr, srclen + 1, ptr, srclen);
	return s;
}

int enc_hasupper(char *s)
{
	while (*s)
		if (enc_isupper(*s))
			return 1;
		else
			s++;
	return 0;
}

int enc_haslower(char *s)
{
	while (*s)
		if (enc_islower(*s))
			return 1;
		else
			s++;
	return 0;
}

int enc_hasdigit(char *s)
{
	while (*s)
		if (enc_isdigit(*s))
			return 1;
		else
			s++;
	return 0;
}

/*
 * The concept of UTF-8-32 and associated code was first mentioned at
 * https://github.com/openwall/john/issues/3510
 *
 * Char| Unicode |    UTF-8    |   UTF-32   | UTF-8-32
 * ----|---------|-------------|------------|-----------
 *  A  |  U+0041 |          41 | 0x00000041 | 0x00000041
 *  £  |  U+00A3 |       c2 a3 | 0x000000a3 | 0x0000a3c2
 *  €  |  U+20AC |    e2 82 ac | 0x000020ac | 0x00ac82e2
 * :-) | U+1F600 | f0 9f 98 80 | 0x0001f600 | 0x80989ff0
 *
 * The UTF-8-32 concept and code is Copyright (c) magnum 2018 and is
 * hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/*
 * Source is a UTF-8-32 string, destination is a normal UTF-8 string.
 */
UTF8 *utf8_32_to_utf8(UTF8 *dst, UTF32 *src)
{
	UTF8 *ret = dst;
	UTF32 c;

	while ((c = *src++))
	do
		*dst++ = c & 0xff;
	while ((c >>= 8));

	*dst = 0;

	return ret;
}

/*
 * Convert a UTF-8 string to UTF-8-32. Not much error checking.
 */
void utf8_to_utf8_32(UTF32 *dst, UTF8 *src)
{
	UTF32 c;

	while ((c = *src++)) {
		if (c >= 0xC0) {
			unsigned int eb;
			eb = opt_trailingBytesUTF8[c & 0x3f];

			if (eb > 3) /* invalid */
				continue;
			c += (UTF32)*src++ << 8;
			if (eb > 1)
				c += (UTF32)*src++ << 16;
			if (eb > 2)
				c += (UTF32)*src++ << 24;
		}
		*dst++ = c;
	}
	*dst = 0;
}

/* Convert UTF-32 to UTF-8-32, in place */
void utf32_to_utf8_32(UTF32 *in_place_string)
{
	UTF32 *src = in_place_string;
	UTF32 *dst = in_place_string;

	while (*src) {
		UTF32 ch, u8_32 = 0;
		unsigned short bytesToWrite = 0;
		const UTF32 byteMask = 0xBF;
		const UTF32 byteMark = 0x80;

		ch = *src++;

		/* Figure out how many bytes the result will require */
		if (ch < (UTF32)0x80) {	     bytesToWrite = 1;
		} else if (ch < (UTF32)0x800) {     bytesToWrite = 2;
		} else if (ch < (UTF32)0x10000) {   bytesToWrite = 3;
		} else if (ch < (UTF32)0x110000) {  bytesToWrite = 4;
		} else {			    bytesToWrite = 3;
			ch = UNI_REPLACEMENT_CHAR;
		}

		switch (bytesToWrite) { /* note: everything falls through. */
		case 4: u8_32 |= ((ch | byteMark) & byteMask) << 24; ch >>= 6;
		case 3: u8_32 |= ((ch | byteMark) & byteMask) << 16; ch >>= 6;
		case 2: u8_32 |= ((ch | byteMark) & byteMask) << 8; ch >>= 6;
		case 1: u8_32 |= (ch | firstByteMark[bytesToWrite]);
		}
		*dst++ = u8_32;
	}
}
