/*
 * This is Base64 conversion code. It will convert between raw and base64
 * all flavors, hex and base64 (all flavors), and between 3 flavors of
 * base64.  Conversion happens either direction (to or from).
 *
 * Coded Fall 2014 by Jim Fougeron.  Code placed in public domain.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted, as long an unmodified copy of this
 * license/disclaimer accompanies the source.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  currently handles these conversions (to and from any to any)
 *     raw      (binary)
 *     hex
 *     mime     (A..Za..z0..1+/   The == for null trails may be optional, removed for now)
 *     crypt    (./0..9A..Za..z   Similar to encoding used by crypt)
 *     cryptBS  like crypt, but bit swapped encoding order
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _MSC_VER
#include "missing_getopt.h"
#include <io.h>
#else
#include <unistd.h>
#endif
#include "memory.h"
#include "misc.h"
#include "common.h"
#include "jumbo.h"
#include "base64_convert.h"

/*
 * once we switched to size_t, we can no longer use - values to return an error.
 * We had to add an error field, and use that for return.
 */
#define ERR_base64_no_error		0
#define ERR_base64_unk_from_type	-1
#define ERR_base64_unk_to_type		-2
#define ERR_base64_to_buffer_sz		-3
#define ERR_base64_unhandled		-4

/* mime variant of base64, like crypt version in common.c */
static const char *itoa64m = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char atoi64m[0x100];
static char atoi64md[0x100];   // the atoi64md[] array maps value for '+' into '.'
static char atoi64mdu[0x100];  // the atoi64mdu[] array maps value for '+' into '-' and '/' into '_'
static int mime_setup=0;

/*********************************************************************
 * NOTE: Decode functions for mime base-64 (found in base64.c)
 *********************************************************************/

/*********************************************************************
 * Decode functions for crypt base-64
 *********************************************************************/
static const unsigned char crypt_decode_tab[256] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x10
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x20
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,   // 0x30
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x40
  0x00, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,   // 0x50
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x60
  0x00, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,   // 0x70
  0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x80
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x90
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xa0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xb0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xc0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xd0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xe0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xf0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00    // 0xff
};

static void base64_decode_i(const char *in, size_t inlen, unsigned char *out) {
	size_t i, done=0;
	// assert inlen%4==0

	for (i=0; i<inlen; i+=4) {
		unsigned char t0 = crypt_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t1 = crypt_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t2 = crypt_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t3 = crypt_decode_tab[ARCH_INDEX(*in++)];
		out[0] = ((t0<<2) & 0xfc) | ((t1>>4) & 3);
		done += 2;
		if (done >= inlen) return;
		out[1] = ((t1<<4) & 0xf0) | ((t2>>2) & 0xf);
		if (++done >= inlen) return;
		out[2] = ((t2<<6) & 0xc0) | ((t3   ) & 0x3f);
		++done;
		out += 3;
		in += 4;
	}
}
/*********************************************************************
 * Decode function for byte swapped crypt base-64 (usas the same
 * base64_unmap_i function as is used for crypt)
 *********************************************************************/
static void base64_decode_iBS(const char *in, size_t inlen, unsigned char *out) {
	size_t i, done=0;
	// assert inlen%4==0

	for (i=0; i<inlen; i+=4) {
		unsigned char t0 = crypt_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t1 = crypt_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t2 = crypt_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t3 = crypt_decode_tab[ARCH_INDEX(*in++)];
		out[0] = ((t0   ) & 0x3f) | ((t1<<6) & 0xc0);
		done += 2;
		if (done >= inlen) return;
		out[1] = ((t1>>2) & 0x0f) | ((t2<<4) & 0xf0);
		if (++done >= inlen) return;
		out[2] = ((t2>>4) & 0x03) | ((t3<<2) & 0xfc);

		++done;
		out += 3;
		in += 4;
	}
}
/*********************************************************************
 * Encode functions for byte swapped crypt base-64
 *********************************************************************/
static void enc_base64_1_iBS(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = val & 0x3f;
		val >>= 6;
		*out++ = itoa64[v];
	}
}
static void base64_encode_iBS(const unsigned char *in, size_t len, char *outy, unsigned flags) {
	size_t mod = len%3, i;
	unsigned u;
	for (i = 0; i*3 < len; ++i) {
		u = (in[i*3] | (((unsigned)in[i*3+1])<<8)  | (((unsigned)in[i*3+2])<<16));
		if ((i+1)*3 >= len) {
			switch (mod) {
				case 0:
					enc_base64_1_iBS(outy, u, 4); outy[4] = 0; break;
				case 1:
					enc_base64_1_iBS(outy, u, 2); outy[2] = 0; break;
				case 2:
					enc_base64_1_iBS(outy, u, 3); outy[3] = 0; break;
			}
		}
		else
			enc_base64_1_iBS(outy, u, 4);
		outy += 4;
	}
	if ( mod && len && (flags&flg_Base64_CRYPT_TRAIL_DOTS) == flg_Base64_CRYPT_TRAIL_DOTS) {
		outy -= 4;
		switch(mod)
		{
			case 1: strcpy(&outy[2], ".."); break;
			case 2: strcpy(&outy[3], "."); break;
		}
	}
}
/*********************************************************************
 * Encode functions for crypt base-64
 *********************************************************************/
static void enc_base64_1_i(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = (val & 0xFC0000)>>18;
		val <<= 6;
		*out++ = itoa64[v];
	}
}
static void base64_encode_i(const unsigned char *in, size_t len, char *outy, unsigned flags) {
	size_t mod = len%3, i;
	unsigned u;
	for (i = 0; i*3 < len; ++i) {
		u = ((((unsigned)in[i*3])<<16) | (((unsigned)in[i*3+1])<<8)  | (((unsigned)in[i*3+2])));
		if ((i+1)*3 >= len) {
			switch (mod) {
				case 0:
					enc_base64_1_i(outy, u, 4); outy[4] = 0; break;
				case 1:
					enc_base64_1_i(outy, u, 2); outy[2] = 0; break;
				case 2:
					enc_base64_1_i(outy, u, 3); outy[3] = 0; break;
			}
		}
		else
			enc_base64_1_i(outy, u, 4);
		outy += 4;
	}
	if ( mod && len && (flags&flg_Base64_CRYPT_TRAIL_DOTS) == flg_Base64_CRYPT_TRAIL_DOTS) {
		outy -= 4;
		switch(mod)
		{
			case 1: strcpy(&outy[2], ".."); break;
			case 2: strcpy(&outy[3], "."); break;
		}
	}
}
/*********************************************************************
 * Encode functions for mime base-64
 *********************************************************************/
static void enc_base64_1(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = (val & 0xFC0000)>>18;
		val <<= 6;
		*out++ = itoa64m[v];
	}
}
static void base64_encode(const unsigned char *in, size_t len, char *outy, unsigned flags) {
	size_t mod = len%3, i;
	unsigned u;
	for (i = 0; i*3 < len; ++i) {
		u = ((((unsigned)in[i*3])<<16) | (((unsigned)in[i*3+1])<<8)  | (((unsigned)in[i*3+2])));
		if ((i+1)*3 >= len) {
			switch (mod) {
				case 0:
					enc_base64_1(outy, u, 4); outy[4] = 0; break;
				case 1:
					enc_base64_1(outy, u, 2); outy[2] = 0; break;
				case 2:
					enc_base64_1(outy, u, 3); outy[3] = 0; break;
			}
		}
		else
			enc_base64_1(outy, u, 4);
		outy += 4;
	}
	if ( mod && len && (flags&flg_Base64_MIME_TRAIL_EQ) == flg_Base64_MIME_TRAIL_EQ) {
		outy -= 4;
		switch(mod)
		{
			case 1: strcpy(&outy[2], "=="); break;
			case 2: strcpy(&outy[3], "="); break;
		}
	}
}

/* mime decoding */
static const unsigned char mime_decode_tab[256] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x10
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x20
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,   // 0x30
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x40
  0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,   // 0x50
  0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x60
  0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,   // 0x70
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x80
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0x90
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xa0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xb0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xc0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xd0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xe0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // 0xf0
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00    // 0xff
};

/* mime decoding */
static void base64_Decode(const char *in, size_t inlen, unsigned char *out) {
	size_t i, done=0;

	for (i=0; i<inlen; i+=4) {
		unsigned char t0 = mime_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t1 = mime_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t2 = mime_decode_tab[ARCH_INDEX(*in++)];
		unsigned char t3 = mime_decode_tab[ARCH_INDEX(*in++)];
		out[0] = ((t0<<2) & 0xfc) | ((t1>>4) & 3);
		done += 2;
		if (done >= inlen) return;
		out[1] = ((t1<<4) & 0xf0) | ((t2>>2) & 0xf);
		if (++done >= inlen) return;
		out[2] = ((t2<<6) & 0xc0) | ((t3   ) & 0x3f);

		++done;
		out += 3;
		in += 4;
	}
}
/*********************************************************************
 * functions for HEX to mem and mem to HEX
 *********************************************************************/
static void raw_to_hex(const unsigned char *from, size_t len, char *to, unsigned flags) {
	size_t i;
	for (i = 0; i < len; ++i) {
		*to++ = itoa16[(*from)>>4];
		*to++ = itoa16[(*from)&0xF];
		++from;
	}
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		*to = 0;
}
static void hex_to_raw(const char *from, size_t len, unsigned char *to) {
	size_t i;
	for (i = 0; i < len; i += 2)
		*to++ = (atoi16[(ARCH_INDEX(from[i]))]<<4)|atoi16[(ARCH_INDEX(from[i+1]))];
}

/******************************************************************************************
 * these functions should allow us to convert 4 base64 bytes at a time, and not
 * have to allocate a large buffer, decrypt to one, and re-encrypt just to do a
 * conversion.  With these functions we should be able to walk through a buffer
 ******************************************************************************************/
typedef void (*b64_decode_f)(const char *in, size_t inlen, unsigned char *out);
typedef void (*b64_encode_f)(const unsigned char *in, size_t len, char *outy, unsigned flags);

static size_t actual_base64_to_base64_conv(const char *cpi, char *cpo, size_t to_len, unsigned flags, char *func_name, b64_decode_f decode, b64_encode_f encode) {
	char Tmp2[5], *cpo_o = cpo;
	unsigned char Tmp[3];
	size_t len_left = strlen(cpi);
	size_t use_bytes=3;
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) && to_len == len_left)
		++to_len;
	if (to_len < len_left)
		error_msg("ERROR, %s, output buffer not large enough\n", func_name);
	while (len_left > 0) {
		char tmp[4];
		if (len_left<4) {
			--use_bytes;
			if (len_left < 3)
				--use_bytes;
			memset(tmp, 0, 4);
			memcpy(tmp, cpi, len_left);
			cpi = tmp;
			memset(Tmp, 0, 3);
		}
		decode(cpi, len_left < 4 ? len_left : 4, Tmp);
		encode(Tmp, use_bytes, Tmp2, flags);
		if (len_left < 4) {
			memcpy(cpo, Tmp2, len_left);
			cpo += len_left;
			len_left = 0;
		}
		else {
			memcpy(cpo, Tmp2, 4);
			cpo += 4;
			cpi += 4;
			if (len_left < 4)
				len_left = 0;
			else
				len_left -= 4;
		}
	}
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		*cpo = 0;
	return cpo-cpo_o;
}
/******************************************************************************************
 * these functions should allow us to convert 4 base64 bytes against 6 hex bytes at a
 * time, and not have to allocate a large buffer, decrypt to one, and re-encrypt just
 * to do a conversion.  With these functions we should be able to walk through a buffer
 ******************************************************************************************/
static size_t actual_hex_to_base64_conv(const char *cpi, char *cpo, size_t to_len, unsigned flags, b64_encode_f encode) {
	char Tmp2[5], *cpo_o = cpo;
	unsigned char Tmp[3];
	size_t len_left = strlen(cpi), use_bytes=3, this_len=4;
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		--to_len;
	while (len_left > 0) {
		if (len_left < 6) {
			--this_len;
			--use_bytes;
			if (len_left < 4) {
				--this_len;
				--use_bytes;
			}
			memset(Tmp,0,3);
		}
		hex_to_raw(cpi, len_left < 6 ? len_left : 6, Tmp);
		encode(Tmp, use_bytes, Tmp2, flags);
		if (to_len < 4) {
			memcpy(cpo, Tmp2, to_len);
			cpo += to_len;
			len_left = 0;
		}
		else {
			memcpy(cpo, Tmp2, this_len);
			cpo += this_len;
			cpi += 6;
			if (len_left < 6)
				len_left = 0;
			else
				len_left -= 6;
			to_len -= this_len;
		}
	}
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		*cpo = 0;
	return cpo-cpo_o;
}
static size_t actual_base64_to_hex_conv(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags, b64_decode_f decode) {
	char Tmp[3], Tmp2[7], *cpo_o = cpo;
	size_t this_len=3;
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		--to_len;
	while (len_left > 0) {
		char tmp[4];
		if (len_left<4) {
			if (len_left<=2)this_len=1;else this_len=2;
			memset(tmp, 0, 4);
			memcpy(tmp, cpi, len_left);
			cpi = tmp;
		}
		decode((char*)cpi, len_left < 4 ? len_left : 4, (unsigned char*)Tmp);
		raw_to_hex((const unsigned char*)Tmp, this_len, (char*)Tmp2, flags);
		if (to_len < 6) {
			memcpy(cpo, Tmp2, to_len);
			cpo += to_len;
			len_left = 0;
		}
		else {
			memcpy(cpo, Tmp2, this_len*2);
			cpo += this_len*2;
			cpi += 4;
			if (len_left < 4)
				len_left = 0;
			else
				len_left -= 4;
			to_len -= this_len*2;
		}
	}
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		*cpo = 0;
	return cpo-cpo_o;
}

static size_t actual_base64_to_raw_conv(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags, b64_decode_f decode) {
	size_t this_len=3;
	char *cpo_o = cpo;
	while (len_left > 0) {
		char tmp[4];
		unsigned char Tmp[3];
		if (len_left<4) {
			if (len_left<=2)this_len=1;else this_len=2;
			memset(tmp, 0, 4);
			memcpy(tmp, cpi, len_left);
			cpi = tmp;
		}
		decode((char*)cpi, len_left < 4 ? len_left : 4, Tmp);
		if (to_len < 3) {
			memcpy(cpo, Tmp, to_len);
			cpo += to_len;
			len_left = 0;
		}
		else {
			memcpy(cpo, Tmp, this_len);
			cpi += 4;
			cpo += this_len;
			if (len_left < 4)
				len_left = 0;
			else
				len_left -= 4;
			to_len -= 3;
		}
	}
	return cpo-cpo_o;
}

static size_t actual_raw_to_base64_conv(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags, b64_encode_f encode) {
	char Tmp[3], Tmp2[5], *cpo_o = cpo;
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		--to_len;
	while (len_left > 0) {
		if (len_left<3) {
			memset(Tmp, 0, 3);
			memcpy(Tmp, cpi, len_left);
			cpi = Tmp;
		}
		encode((const unsigned char*)cpi, (len_left>3?3:len_left), Tmp2, flags);
		if (to_len < 4) {
			memcpy(cpo, Tmp2, to_len);
			cpo += to_len;
			len_left = 0;
		}
		else {
			memcpy(cpo, Tmp2, 4);
			cpo += 4;
			cpi += 3;
			if (len_left < 3)
				len_left = 0;
			else
				len_left -= 3;
			to_len -= 4;
		}

	}
	if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
		*cpo = 0;
	return cpo-cpo_o;
}

inline static size_t mime_to_cryptBS(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_base64_conv(cpi, cpo, to_len, flags, "mime_to_cryptBS", base64_Decode, base64_encode_iBS);
}
inline static size_t mime_to_crypt(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_base64_conv(cpi, cpo, to_len, flags, "mime_to_crypt", base64_Decode, base64_encode_i);
}
inline static size_t crypt_to_cryptBS(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_base64_conv(cpi, cpo, to_len, flags, "crypt_to_cryptBS", base64_decode_i, base64_encode_iBS);
}
inline static size_t crypt_to_mime(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_base64_conv(cpi, cpo, to_len, flags, "crypt_to_mime", base64_decode_i, base64_encode);
}
inline static size_t cryptBS_to_mime(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_base64_conv(cpi, cpo, to_len, flags, "cryptBS_to_mime", base64_decode_iBS, base64_encode);
}
inline static size_t cryptBS_to_crypt(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_base64_conv(cpi, cpo, to_len, flags, "cryptBS_to_crypt", base64_decode_iBS, base64_encode_i);
}


inline static size_t hex_to_cryptBS(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_hex_to_base64_conv(cpi, cpo, to_len, flags, base64_encode_iBS);
}
inline static size_t  hex_to_crypt(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_hex_to_base64_conv(cpi, cpo, to_len, flags, base64_encode_i);
}
inline static size_t hex_to_mime(const char *cpi, char *cpo, size_t to_len, unsigned flags) {
	return actual_hex_to_base64_conv(cpi, cpo, to_len, flags, base64_encode);
}

inline static size_t cryptBS_to_hex(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_hex_conv(cpi, len_left, cpo, to_len, flags, base64_decode_iBS);
}
inline static size_t crypt_to_hex(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_hex_conv(cpi, len_left, cpo, to_len, flags, base64_decode_i);
}
inline static size_t mime_to_hex(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_hex_conv(cpi, len_left, cpo, to_len, flags, base64_Decode);
}

inline static size_t cryptBS_to_raw(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_raw_conv(cpi, len_left, cpo, to_len, flags, base64_decode_iBS);
}
inline static size_t crypt_to_raw(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_raw_conv(cpi, len_left, cpo, to_len, flags, base64_decode_i);
}
inline static size_t mime_to_raw(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_base64_to_raw_conv(cpi, len_left, cpo, to_len, flags, base64_Decode);
}

inline static size_t raw_to_mime(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_raw_to_base64_conv(cpi, len_left, cpo, to_len, flags, base64_encode);
}
inline static size_t raw_to_crypt(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_raw_to_base64_conv(cpi, len_left, cpo, to_len, flags, base64_encode_i);
}
inline static size_t raw_to_cryptBS(const char *cpi, size_t len_left, char *cpo, size_t to_len, unsigned flags) {
	return actual_raw_to_base64_conv(cpi, len_left, cpo, to_len, flags, base64_encode_iBS);
}

/******************************************************************************************
 * This function will initialize our base64 conversion data. We also call common_init, in
 * case it was not called before (it is safe to call multiple times). When we execute the
 * base64conv tool common_init has not been called by JtR core code, so we HAVE to do it.
 ******************************************************************************************/
static void setup_mime() {
	const char *pos;
	mime_setup=1;
	memset(atoi64m, 0x7F, sizeof(atoi64m));
	for (pos = itoa64m; pos <= &itoa64m[63]; pos++)
		atoi64m[ARCH_INDEX(*pos)] = pos - itoa64m;
	// passlib encoding uses . and not + BUT they mean the same thing.
	memcpy(atoi64md, atoi64m, 0x100);
	atoi64md[ARCH_INDEX('.')] = atoi64md[ARCH_INDEX('+')];
	atoi64md[ARCH_INDEX('+')] = 0x7f;
	memcpy(atoi64mdu, atoi64m, 0x100);
	atoi64mdu[ARCH_INDEX('-')] = atoi64mdu[ARCH_INDEX('+')];
	atoi64mdu[ARCH_INDEX('+')] = 0x7f;
	atoi64mdu[ARCH_INDEX('_')] = atoi64mdu[ARCH_INDEX('/')];
	atoi64mdu[ARCH_INDEX('/')] = 0x7f;
	common_init();
}

void mime_deplus(char *to) {
	char *cp = strchr(to, '+');
	while (cp) {
		*cp = '.';
		cp = strchr(cp, '+');
	}
}

void mime_dash_under(char *to) {
	char *cp = strchr(to, '+');
	while (cp) {
		*cp = '-';
		cp = strchr(cp, '+');
	}
	cp = strchr(to, '/');
	while (cp) {
		*cp = '_';
		cp = strchr(cp, '/');
	}
}

/******************************************************************************************
 ******************************************************************************************
 *
 * These are the main 2 external conversion functions. There also is error functions after
 * these 2, but these are the main ones.
 *
 ******************************************************************************************
 ******************************************************************************************/
char *base64_convert_cp(const void *from, b64_convert_type from_t, size_t from_len, void *to, b64_convert_type to_t, size_t to_len, unsigned flags, int *err)
{
	base64_convert(from, from_t, from_len, to, to_t, to_len, flags, err);
	if (err && *err < 0) {
		base64_convert_error_exit(*err);
	}
	return (char*)to;
}
size_t base64_convert(const void *from, b64_convert_type from_t, size_t from_len, void *to, b64_convert_type to_t, size_t to_len, unsigned flags, int *err)
{
	if (!mime_setup)
		setup_mime();

	if (from_t != e_b64_raw)
		from_len = strnlen((char*)from, from_len);

	if (err) *err = ERR_base64_no_error;
	switch (from_t) {
		case e_b64_raw:		/* raw memory */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					if (from_t > to_t) {
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					memcpy(to, from, from_len);
					return from_len;
				}
				case e_b64_hex:		/* hex */
				{
					if ((from_t*2+1) > to_t) {
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					raw_to_hex((unsigned char*)from, from_len, (char*)to, flags);
					if ( (flags&flg_Base64_HEX_UPCASE) == flg_Base64_HEX_UPCASE)
						strupr((char*)to);
					return from_len<<1;
				}
				case e_b64_mime:	/* mime */
				{
					size_t len = raw_to_mime((const char *)from, from_len, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_MIME_PLUS_TO_DOT) == flg_Base64_MIME_PLUS_TO_DOT)
						mime_deplus((char*)to);
					if ( (flags&flg_Base64_MIME_DASH_UNDER) == flg_Base64_MIME_DASH_UNDER)
						mime_dash_under((char*)to);
					return len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					size_t len = raw_to_crypt((const char *)from, from_len, (char *)to, to_len, flags);
					return len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					size_t len = raw_to_cryptBS((const char *)from, from_len, (char *)to, to_len, flags);
					return len;
				}
				default:
					if (err) *err = ERR_base64_unk_to_type;
					return 0;
			}
		}
		case e_b64_hex:		/* hex */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					if (to_len * 2 < from_len) {
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					hex_to_raw((const char*)from, from_len, (unsigned char*)to);
					return from_len / 2;
				}
				case e_b64_hex:		/* hex */
				{
					if (to_len < from_len+1) {
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					strcpy((char*)to, (const char*)from);
					if ( (flags&flg_Base64_HEX_UPCASE) == flg_Base64_HEX_UPCASE)
						strupr((char*)to);
					else
						strlwr((char*)to);
					return from_len;
				}
				case e_b64_mime:	/* mime */
				{
					size_t len = hex_to_mime((const char *)from, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_MIME_PLUS_TO_DOT) == flg_Base64_MIME_PLUS_TO_DOT)
						mime_deplus((char*)to);
					if ( (flags&flg_Base64_MIME_DASH_UNDER)  == flg_Base64_MIME_DASH_UNDER)
						mime_dash_under((char*)to);
					return len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					size_t len = hex_to_crypt((const char *)from, (char *)to, to_len, flags);
					return len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					size_t len = hex_to_cryptBS((const char *)from, (char *)to, to_len, flags);
					return len;
				}
				default:
					if (err) *err = ERR_base64_unk_to_type;
					return 0;
			}
		}
		case e_b64_mime:	/* mime */
		{
			char *fromWrk = (char*)from, fromTmp[256];
			int alloced=0;
			while (fromWrk[from_len-1]=='=')
				from_len--;

			/* autohandle the reverse of mime deplus code on input, i.e. auto convert . into + */
			if (strchr(fromWrk, '.')) {
				char *cp;
				if (from_len<sizeof(fromTmp)-3)
					fromWrk=fromTmp;
				else {
					alloced = 1;
					fromWrk = (char*)mem_calloc(1, from_len+3);
				}
				strnzcpy(fromWrk, (const char*)from, from_len+1);
				fromWrk[from_len+1] = fromWrk[from_len+2] = 0;
				cp = strchr(fromWrk, '.');
				while (cp) {
					*cp = '+';
					cp = strchr(cp, '.');
				}
			}
			if (strchr(fromWrk, '-')) {
				char *cp;
				if (fromWrk == from) {
					if (from_len<sizeof(fromTmp)-3)
						fromWrk=fromTmp;
					else {
						alloced = 1;
						fromWrk = (char*)mem_calloc(1, from_len+3);
					}
					strnzcpy(fromWrk, (const char*)from, from_len+1);
					fromWrk[from_len+1] = fromWrk[from_len+2] = 0;
				}
				cp = strchr(fromWrk, '-');
				while (cp) {
					*cp = '+';
					cp = strchr(cp, '-');
				}
			}
			if (strchr(fromWrk, '_')) {
				char *cp;
				if (fromWrk == from) {
					if (from_len<sizeof(fromTmp)-3)
						fromWrk=fromTmp;
					else {
						alloced = 1;
						fromWrk = (char*)mem_calloc(1, from_len+3);
					}
					strnzcpy(fromWrk, (const char*)from, from_len+1);
					fromWrk[from_len+1] = fromWrk[from_len+2] = 0;
				}
				cp = strchr(fromWrk, '_');
				while (cp) {
					*cp = '/';
					cp = strchr(cp, '_');
				}
			}

			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					size_t len = mime_to_raw((const char *)fromWrk, from_len, (char *)to, to_len, flags);
					if (alloced) MEM_FREE(fromWrk);
					return len;
				}
				case e_b64_hex:		/* hex */
				{
					size_t len = mime_to_hex((const char *)fromWrk, from_len, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_HEX_UPCASE) == flg_Base64_HEX_UPCASE)
						strupr((char*)to);
					if (alloced) MEM_FREE(fromWrk);
					return len;
				}
				case e_b64_mime:	/* mime */
				{
					if (to_len < from_len+1) {
						if (alloced) MEM_FREE(fromWrk);
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					memcpy(to, fromWrk, from_len);
					((char*)to)[from_len] = 0;
					if ( (flags&flg_Base64_MIME_PLUS_TO_DOT) == flg_Base64_MIME_PLUS_TO_DOT)
						mime_deplus((char*)to);
					if ( (flags&flg_Base64_MIME_DASH_UNDER) == flg_Base64_MIME_DASH_UNDER)
						mime_dash_under((char*)to);
					if (alloced) MEM_FREE(fromWrk);
					return from_len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					size_t len = mime_to_crypt((const char *)fromWrk, (char *)to, to_len, flags);
					if (alloced) MEM_FREE(fromWrk);
					return len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					size_t len = mime_to_cryptBS((const char *)fromWrk, (char *)to, to_len, flags);
					if (alloced) MEM_FREE(fromWrk);
					return len;
				}
				default:
					if (alloced) MEM_FREE(fromWrk);
					if (err) *err = ERR_base64_unk_to_type;
					return 0;
			}
		}
		case e_b64_crypt:	/* crypt encoding */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{

					size_t len = crypt_to_raw((const char *)from, from_len, (char *)to, to_len, flags);
					return len;
				}
				case e_b64_hex:		/* hex */
				{
					size_t len = crypt_to_hex((const char *)from, from_len, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_HEX_UPCASE) == flg_Base64_HEX_UPCASE)
						strupr((char*)to);
					return len;
				}
				case e_b64_mime:	/* mime */
				{
					size_t len = crypt_to_mime((const char *)from, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_MIME_PLUS_TO_DOT) == flg_Base64_MIME_PLUS_TO_DOT)
						mime_deplus((char*)to);
					if ( (flags&flg_Base64_MIME_DASH_UNDER) == flg_Base64_MIME_DASH_UNDER)
						mime_dash_under((char*)to);
					return len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					if (to_len < from_len+1) {
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					memcpy(to, from, from_len);
					((char*)to)[from_len]=0;
					return from_len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					size_t len = crypt_to_cryptBS((const char *)from, (char *)to, to_len, flags);
					return len;
				}
				default:
					if (err) *err = ERR_base64_unk_to_type;
					return 0;
			}
		}
		case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					size_t len = cryptBS_to_raw((const char *)from, from_len, (char *)to, to_len, flags);
					return len;
				}
				case e_b64_hex:		/* hex */
				{
					size_t len = cryptBS_to_hex((const char *)from, from_len, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_HEX_UPCASE) == flg_Base64_HEX_UPCASE)
						strupr((char*)to);
					return len;
				}
				case e_b64_mime:	/* mime */
				{
					size_t len = cryptBS_to_mime((const char *)from, (char *)to, to_len, flags);
					if ( (flags&flg_Base64_MIME_PLUS_TO_DOT) == flg_Base64_MIME_PLUS_TO_DOT)
						mime_deplus((char*)to);
					if ( (flags&flg_Base64_MIME_DASH_UNDER) == flg_Base64_MIME_DASH_UNDER)
						mime_dash_under((char*)to);
					return len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					size_t len = cryptBS_to_crypt((const char *)from, (char *)to, to_len, flags);
					return len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					if (to_len < from_len+1) {
						if (err) *err = ERR_base64_to_buffer_sz;
						return 0;
					}
					memcpy(to, from, from_len);
					if ((flags&flg_Base64_DONOT_NULL_TERMINATE) == 0)
						((char*)to)[from_len] = 0;
					return from_len;
				}
				default:
					if (err) *err = ERR_base64_unk_to_type;
					return 0;
			}
		}
		default:
			if (err) *err = ERR_base64_unk_from_type;
	}
	return 0;
}
void base64_convert_error_exit(int err) {
	switch (err) {
		case ERR_base64_no_error:	fprintf(stderr, "base64_convert no error\n"); break;
		case ERR_base64_unk_from_type:	fprintf(stderr, "base64_convert error-%d, Unknown From Type\n", err); break;
		case ERR_base64_unk_to_type:	fprintf(stderr, "base64_convert error-%d, Unknown To Type\n", err); break;
		case ERR_base64_to_buffer_sz:	fprintf(stderr, "base64_convert error-%d, *to buffer too small\n", err); break;
		case ERR_base64_unhandled:	fprintf(stderr, "base64_convert error-%d, currently unhandled conversion\n", err); break;
		default:			fprintf(stderr, "base64_convert_error_exit(%d)\n", err);
	}
	exit(1);
}
char *base64_convert_error(int err) {
	char *p = (char*)mem_calloc(1, 256);
	switch (err) {
		case ERR_base64_no_error:	sprintf(p, "base64_convert no error\n"); break;
		case ERR_base64_unk_from_type:	sprintf(p, "base64_convert error-%d, Unknown From Type\n", err); break;
		case ERR_base64_unk_to_type:	sprintf(p, "base64_convert error-%d, Unknown To Type\n", err); break;
		case ERR_base64_to_buffer_sz:	sprintf(p, "base64_convert error-%d, *to buffer too small\n", err); break;
		case ERR_base64_unhandled:	sprintf(p, "base64_convert error-%d, currently unhandled conversion\n", err); break;
		default:			sprintf(p, "base64_convert_error_exit(%d)\n", err);
	}
	return p;
}

size_t base64_valid_length(const char *from, b64_convert_type from_t, unsigned flags, int *err) {
	size_t len=0;
	if (!mime_setup)
		setup_mime();

	if (err) *err = ERR_base64_no_error;

	switch (from_t) {
		case e_b64_hex:		/* hex */
			if ( (flags & flg_Base64_HEX_UPCASE) == flg_Base64_HEX_UPCASE) {
				while (atoi16[ARCH_INDEX(*from)] != 0x7f) {
					if (*from >= 'a' && *from <= 'f')
						break;
					++len;
					++from;
				}
			} if ( (flags & flg_Base64_HEX_LOCASE) == flg_Base64_HEX_LOCASE) {
				while (atoi16[ARCH_INDEX(*from)] != 0x7f) {
					if (*from >= 'A' && *from <= 'F')
						break;
					++len;
					++from;
				}
			} else {
				while (atoi16[ARCH_INDEX(*from++)] != 0x7f)
					++len;
			}
			break;
		case e_b64_mime:	/* mime */
			if ( (flags&flg_Base64_MIME_PLUS_TO_DOT) == flg_Base64_MIME_PLUS_TO_DOT) {
				while (atoi64md[ARCH_INDEX(*from++)] != 0x7f)
					++len;
			} else if ( (flags&flg_Base64_MIME_DASH_UNDER) == flg_Base64_MIME_DASH_UNDER) {
				while (atoi64mdu[ARCH_INDEX(*from++)] != 0x7f)
					++len;
			} else {
				while (atoi64m[ARCH_INDEX(*from++)] != 0x7f)
					++len;
			}
			--from;
			if ( (flags&flg_Base64_MIME_TRAIL_EQ_CNT) == flg_Base64_MIME_TRAIL_EQ_CNT) {
				while (*from++ == '=')
					++len;
			}
			break;
		case e_b64_crypt:	/* crypt encoding */
		case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
			while (atoi64[ARCH_INDEX(*from++)] != 0x7f)
				++len;
			break;
		default:
			if (err) *err = ERR_base64_unk_from_type;
			return 0;
	}
//	// we need to check from[-1] first.  We could be at null, or 1 byte past null at this point
//	// so both need to be checked, checking [-1] first to avoid ASAN overflow errors.
//	if ((flags&flg_Base64_RET_NEG_IF_NOT_PURE) == flg_Base64_RET_NEG_IF_NOT_PURE && len && from[-1] && *from)
//		return -len;
	return len;
}

/*************************************************************************
 * Here are the 'main' function and helper functions that make up the
 * base64_covert application (a JtR symlink).  This test app will allow
 * conversions to and from for all types, and allows testing the routines
 * along with is very useful for developers.
 *************************************************************************/
/* used by base64conv 'main()' function */
static int usage(char *name)
{
	fprintf(stderr, "Usage: %s [-l] [-i intype] [-o outtype] [-q] [-w] [-e] [-f flag] [data[data ...] | < stdin]\n"
	        " - data must match input_type i.e. if hex, then data should be in hex\n"
	        " - if data is not present, then base64conv will read data from std input)\n"
	        " - if data read from stdin, max size of any line is 256k\n"
	        "\n"
	        "  -q will only output resultant string. No extra junk text\n"
	        "  -e turns on buffer overwrite error checking logic\n"
	        "  -l performs a 'length' test\n"
			"\n"
			"  -r ifname  process whole file ifname (this is the input file)\n"
			"  -w ofname  The output filename for whole file processing\n"
			"             NOTE, -r and -w have to be used as a pair\n"
	        "\n"
	        "Input/Output types:\n"
	        "  raw      raw data byte\n"
	        "  hex      hexidecimal string (for input, case does not matter)\n"
	        "  mime     base64 mime encoding\n"
	        "  crypt    base64 crypt character set encoding\n"
	        "  cryptBS  base64 crypt encoding, byte swapped\n"
	        "\n"
	        "Flags (note more than 1 -f command switch can be given at one time):\n"
	        "  HEX_UPCASE         output or length UPCASED (input case auto handled)\n"
	        "  HEX_LOCASE         output or length locased (input case auto handled)\n"
	        "  MIME_TRAIL_EQ      output mime adds = chars (input = auto handled)\n"
	        "  CRYPT_TRAIL_DOTS   output crypt adds . chars (input . auto handled)\n"
	        "  MIME_PLUS_TO_DOT   mime converts + to . (passlib encoding)\n"
	        "  MIME_DASH_UNDER    mime convert +/ into -_ (passlib encoding)\n"
	        "",
	        name);
	return EXIT_FAILURE;
}

/* used by base64conv 'main()' function */
static b64_convert_type str2convtype(const char *in) {
	if (!strcmp(in, "raw")) return e_b64_raw;
	if (!strcmp(in, "hex")) return e_b64_hex;
	if (!strcmp(in, "mime")) return e_b64_mime;
	if (!strcmp(in, "crypt")) return e_b64_crypt;
	if (!strcmp(in, "cryptBS")) return e_b64_cryptBS;
	return e_b64_unk;
}
static int handle_flag_type(const char *pflag) {
	if (!strcasecmp(pflag, "HEX_UPCASE"))       return flg_Base64_HEX_UPCASE;
	if (!strcasecmp(pflag, "HEX_LOCASE"))       return flg_Base64_HEX_LOCASE;
	if (!strcasecmp(pflag, "MIME_TRAIL_EQ"))    return flg_Base64_MIME_TRAIL_EQ;
	if (!strcasecmp(pflag, "CRYPT_TRAIL_DOTS")) return flg_Base64_CRYPT_TRAIL_DOTS;
	if (!strcasecmp(pflag, "MIME_PLUS_TO_DOT")) return flg_Base64_MIME_PLUS_TO_DOT;
	if (!strcasecmp(pflag, "MIME_DASH_UNDER"))  return flg_Base64_MIME_DASH_UNDER;

	return 0;
}

static void do_convert_wholefile(char *fname, char *outfname, b64_convert_type in_t,
                       b64_convert_type out_t, int quiet,
                       int err_chk, unsigned flags)
{
	char *po;
	size_t i, len, in_len;
	char *in_str;
	FILE *fp;

	fp = fopen(fname, "rb");
	if (!fp) {
		fprintf(stderr, "Error, could not find file [%s]\n", fname);
		exit(-1);
	}
	fseek(fp, 0, SEEK_END);
	in_len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (in_len == 0)
		return;
	in_str = (char*)mem_calloc(1, in_len+4);
	if (fread(in_str, 1, in_len, fp) != in_len) {
		MEM_FREE(in_str);
		fprintf(stderr, "Error, reading file [%s]\n", fname);
		fclose(fp);
		exit(-1);
	}
	fclose(fp);
	fp = fopen(outfname, "wb");

	if (!quiet)
		printf("%s  -->  %s", in_str, in_len ? "" : "\n");

	po = (char*)mem_calloc(3, in_len+2);
	if (err_chk)
		memset(po, 2, in_len*3+6);
	len=base64_convert(in_str, in_t, in_len, po, out_t, in_len*3, flags, 0);
	fwrite(po, 1, len, fp);
	fclose(fp);
	/* check for overwrite problems */
	if (err_chk) {
		size_t tot = in_len*3;
		i=len;
		if (po[i]) {
			fprintf(stderr, "OverwriteLogic: Null byte missing\n");
		}
		for (++i; i < tot; ++i)
		{
			if (((unsigned char)po[i]) != 2) {
				/* we ignore overwrites that are 1 or 2 bytes over.  The way the */
				/* functions are written, we expect some 1 and 2 byte overflows, */
				/* and the caller MUST be aware of that fact                     */
				if (i-len > 2)
					fprintf(stderr, "OverwriteLogic: byte %c (%02X) located at offset %zd (%+zd)\n", (unsigned char)po[i], (unsigned char)po[i], i, i-len);
			}
		}
	}
	MEM_FREE(in_str);
	MEM_FREE(po);
}

static void do_convert(char *in_str, b64_convert_type in_t,
                       b64_convert_type out_t, int quiet,
                       int err_chk, unsigned flags)
{
	char *po;
	size_t i, len, in_len = strlen(in_str);

	if (!quiet)
		printf("%s  -->  %s", in_str, in_len ? "" : "\n");

	if (in_len == 0)
		return;

	po = (char*)mem_calloc(3, in_len);
	if (err_chk)
		memset(po, 2, in_len*3);
	len=base64_convert(in_str, in_t, in_len, po, out_t, in_len*3, flags, 0);
	po[len] = 0;
	printf("%s\n", po);
	fflush(stdout);
	/* check for overwrite problems */
	if (err_chk) {
		size_t  tot = in_len*3;
		i=len;
		if (po[i]) {
			fprintf(stderr, "OverwriteLogic: Null byte missing\n");
		}
		for (++i; i < tot; ++i)
		{
			if (((unsigned char)po[i]) != 2) {
				/* we ignore overwrites that are 1 or 2 bytes over.  The way the */
				/* functions are written, we expect some 1 and 2 byte overflows, */
				/* and the caller MUST be aware of that fact                     */
				if (i-len > 2)
					fprintf(stderr, "OverwriteLogic: byte %c (%02X) located at offset %zd (%+zd)\n", (unsigned char)po[i], (unsigned char)po[i], i, i-len);
			}
		}
	}
	MEM_FREE(po);
}

void length_test() {
	/* this test is to see if the length returned is correct, even if we
	 * list more input data than we have. */
	char out[256];
	size_t len;
	char *d = "dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==";
	len = base64_convert(d, e_b64_mime, strlen(d),
	                     out, e_b64_raw,
	                     sizeof(out),
	                     flg_Base64_MIME_TRAIL_EQ, 0);
	printf("len=%zd  data = %s\n", len, out);
	len = base64_convert(d, e_b64_mime, strlen(d)+1,
	                     out, e_b64_raw,
	                     sizeof(out),
	                     flg_Base64_MIME_TRAIL_EQ, 0);
	printf("len=%zd  data = %s\n", len, out);
	len = base64_convert(d, e_b64_mime, strlen(d)+2,
	                     out, e_b64_raw,
	                     sizeof(out),
	                     flg_Base64_MIME_TRAIL_EQ, 0);
	printf("len=%zd  data = %s\n", len, out);
	len = base64_convert(d, e_b64_mime, strlen(d)+3,
	                     out, e_b64_raw,
	                     sizeof(out),
	                     flg_Base64_MIME_TRAIL_EQ, 0);
	printf("len=%zd  data = %s\n", len, out);
	len = base64_convert(d, e_b64_mime, strlen(d)+8,
	                     out, e_b64_raw,
	                     sizeof(out),
	                     flg_Base64_MIME_TRAIL_EQ, 0);
	printf("len=%zd  data = %s\n", len, out);
}

/* simple conerter of strings or raw memory     */
/* this is a main() function for john, and      */
/* the program created is ../run/base64_convert */
#ifdef _MSC_VER
#define isatty _isatty
#endif
int base64conv(int argc, char **argv) {
	int c;
	b64_convert_type in_t=e_b64_unk, out_t=e_b64_unk;
	int quiet=0,err_chk=0,did_len_check=0,wholefile=0;
	char *fname=NULL, *outfname=NULL;
	int flags=flg_Base64_NO_FLAGS;

	/* Parse command line */
	if (argc == 1)
		return usage(argv[0]);
	while ((c = getopt(argc, argv, "i:o:q!e!f:l!w:r:")) != -1) {
		switch (c) {
		case 'i':
			in_t = str2convtype(optarg);
			if (in_t == e_b64_unk) {
				fprintf(stderr, "%s error: invalid input type %s\n", argv[0], optarg);
				return usage(argv[0]);
			}
			break;
		case 'l':
			length_test();
			did_len_check=1;
			break;
		case 'f':
			flags |= handle_flag_type(optarg);
			break;
		case 'o':
			out_t = str2convtype(optarg);
			if (out_t == e_b64_unk) {
				fprintf(stderr, "%s error: invalid output type %s\n", argv[0], optarg);
				return usage(argv[0]);
			}
			break;
		case 'q':
			quiet=1;
			break;
		case 'w':
			wholefile=1;
			outfname=optarg;
			break;
		case 'r':
			wholefile=1;
			fname=optarg;
			break;
		case 'e':
			err_chk=1;
			break;
		case '?':
		default:
			return usage(argv[0]);
		}
	}
	if (in_t == e_b64_unk || out_t == e_b64_unk) {
		if (did_len_check) return 0;
		return usage(argv[0]);
	}
	argc -= optind;
	argv += optind;
	if (wholefile) {
		if (!fname || !outfname) {
			fprintf(stderr, "Error, -r and -w have to be used as a pair\n");
			exit(-1);
		}
		do_convert_wholefile(fname, outfname, in_t, out_t, quiet, err_chk, flags);
		return 0;
	}
	if (!argc) {
		// if we are out of params, then read from stdin
		char *buf;
		if (isatty(fileno(stdin))) {
			fprintf(stderr, "Enter lines of data to be converted\n");
		}
		buf = (char*)mem_alloc(256*1024);
		fgetl(buf, 256*1024-1, stdin);
		while (!feof(stdin)) {
			buf[256*1024-1] = 0;
			do_convert(buf, in_t, out_t, quiet, err_chk, flags);
			fgetl(buf, 256*1024-1, stdin);
		}
		MEM_FREE(buf);
	} else
	while(argc--)
		do_convert(*argv++, in_t, out_t, quiet, err_chk, flags);
	return 0;
}
