/*
 * This is Base64 conversion code. It will convert between raw and base64
 * all flavors, hex and base64 (all flavors), and between 2 flavors of
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
 *     hex      (and hexU for uppercase output)
 *     mime     (A..Za..z0..1+/   The == for null trails may be optional, removed for now)
 *     crypt    (./0..9A..Za..Z   Similar to encoding used by crypt)
 *     cryptBS  like crypt, but bit swapped encoding order
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _MSC_VER
#include "missing_getopt.h"
#endif
#include "memory.h"
#include "common.h"
#include "jumbo.h"
#include "base64.h"
#include "base64_convert.h"
#include "memdbg.h"

#define ERR_base64_unk_from_type	-1
#define ERR_base64_unk_to_type		-2
#define ERR_base64_to_buffer_sz		-3
#define ERR_base64_unhandled		-4

/* mime variant of base64, like crypt version in common.c */
static const char *itoa64m = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char atoi64m[0x100];
static int mime_setup=0;

static char *mime64_to_crypt64(const char *in, char *out, int len) {
	int i;
	const char *cp;
	for (i = 0; i < len; ++i) {
		cp = strchr(itoa64m, in[i]);
		if (!cp) {
			out[i] = 0;
			return out;
		}
		out[i] = itoa64[cp-itoa64m];
	}
	out[i] = 0;
	return out;
}

static char *crypt64_to_mime64(const char *in, char *out, int len) {
	int i;
	const char *cp;
	for (i = 0; i < len; ++i) {
		cp = strchr(itoa64, in[i]);
		if (!cp) {
			out[i] = 0;
			return out;
		}
		out[i] = itoa64m[cp-itoa64];
	}
	out[i] = 0;
	return out;
}

static void base64_unmap_i(char *in_block) {
	int i;
	char *c;

	for(i=0; i<4; i++) {
		c = in_block + i;
		if(*c == '.') { *c = 0; continue; }
		if(*c == '/') { *c = 1; continue; }
		if(*c>='0' && *c<='9') { *c -= '0'; *c += 2; continue; }
		if(*c>='A' && *c<='Z') { *c -= 'A'; *c += 12; continue; }
		*c -= 'a'; *c += 38;
	}
}
static void base64_decode_i(const char *in, int inlen, unsigned char *out) {
	int i, done=0;
	unsigned char temp[4];

	for(i=0; i<inlen; i+=4) {
		memcpy(temp, in, 4);
		memset(out, 0, 3);
		base64_unmap_i((char*)temp);
		out[0] = ((temp[0]<<2) & 0xfc) | ((temp[1]>>4) & 3);
		done += 2;
		if (done >= inlen) return;
		out[1] = ((temp[1]<<4) & 0xf0) | ((temp[2]>>2) & 0xf);
		if (++done >= inlen) return;
		out[2] = ((temp[2]<<6) & 0xc0) | ((temp[3]   ) & 0x3f);
		++done;
		out += 3;
		in += 4;
	}
}
static void base64_decode_i_bs(const char *in, int inlen, unsigned char *out) {
	int i, done=0;
	unsigned char temp[4];

	for(i=0; i<inlen; i+=4) {
		memcpy(temp, in, 4);
		memset(out, 0, 3);
		base64_unmap_i((char*)temp);
		out[0] = ((temp[0]   ) & 0x3f) | ((temp[1]<<6) & 0xc0);
		done += 2;
		if (done >= inlen) return;
		out[1] = ((temp[1]>>2) & 0x0f) | ((temp[2]<<4) & 0xf0);
		if (++done >= inlen) return;
		out[2] = ((temp[2]>>4) & 0x03) | ((temp[3]<<2) & 0xfc);

		++done;
		out += 3;
		in += 4;
	}
}
static void enc_base64_1_iBS(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = val & 0x3f;
		val >>= 6;
		*out++ = itoa64[v];
	}
}
static void base64_encode_iBS(const unsigned char *in, int len, char *outy) {
	int mod = len%3, i;
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
}
static void enc_base64_1_i(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = (val & 0xFC0000)>>18;
		val <<= 6;
		*out++ = itoa64[v];
	}
}
static void base64_encode_i(const unsigned char *in, int len, char *outy) {
	int mod = len%3, i;
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
}
static void enc_base64_1(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = (val & 0xFC0000)>>18;
		val <<= 6;
		*out++ = itoa64m[v];
	}
}
/* mime char set */
static void base64_encode(const unsigned char *in, int len, char *outy) {
	int mod = len%3, i;
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
}
static char *crypt64_to_crypt64_bs(const char *in, char *out, int len) {
	unsigned char *Tmp;
	Tmp = (unsigned char*)mem_alloc(len*2);
	base64_decode_i(in, len, Tmp);
	base64_encode_iBS(Tmp, (len*3)/4+1, out);
	out[len] = 0;
	MEM_FREE(Tmp);
	return out;
}
static void raw_to_hex(const unsigned char *from, int len, char *to) {
	int i;
	for (i = 0; i < len; ++i) {
		*to++ = itoa16[(*from)>>4];
		*to++ = itoa16[(*from)&0xF];
		++from;
	}
	*to = 0;
}
static void hex_to_raw(const char *from, int len, unsigned char *to) {
	int i;
	for (i = 0; i < len; i += 2)
		*to++ = (atoi16[(ARCH_INDEX(from[i]))]<<4)|atoi16[(ARCH_INDEX(from[i+1]))];
	*to = 0;
}

char *base64_convert_cp(const void *from, b64_convert_type from_t, int from_len, void *to, b64_convert_type to_t, int to_len)
{
	int err = base64_convert(from, from_t, from_len, to, to_t, to_len);
	if (err < 0) {
		base64_convert_error_exit(err);
	}
	return (char*)to;
}
static void setup_mime() {
	const char *pos;
	mime_setup=1;
	memset(atoi64m, 0x7F, sizeof(atoi64m));
	for (pos = itoa64m; pos <= &itoa64m[63]; pos++)
		atoi64m[ARCH_INDEX(*pos)] = pos - itoa64m;
	/* base64conv tool does not have common_init called by JtR. We have to do it ourselves */
	common_init();
}
int base64_convert(const void *from, b64_convert_type from_t, int from_len, void *to, b64_convert_type to_t, int to_len)
{
	unsigned char *tmp;
	if (!mime_setup)
		setup_mime();

	switch (from_t) {
		case e_b64_raw:		/* raw memory */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					if (from_t > to_t)
						return ERR_base64_to_buffer_sz;
					memcpy(to, from, from_len);
					return from_len;
				}
				case e_b64_hex:		/* hex */
				case e_b64_hexU:	/* hex, but if used for convertTO param, will uppercase the hex */
				{
					if ((from_t*2+1) > to_t)
						return ERR_base64_to_buffer_sz;
					raw_to_hex((unsigned char*)from, from_len, (char*)to);
					if (to_t == e_b64_hexU)
						strupr((char*)to);
					return from_len<<1;
				}
				case e_b64_mime:	/* mime */
				{
					base64_encode((unsigned char*)from, from_len, (char*)to);
					return strlen((char*)to);
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					base64_encode_i((unsigned char*)from, from_len, (char*)to);
					return strlen((char*)to);
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					base64_encode_iBS((unsigned char*)from, from_len, (char*)to);
					return strlen((char*)to);
				}
				default:
					return ERR_base64_unk_to_type;
			}
		}
		case e_b64_hex:		/* hex */
		case e_b64_hexU:	/* same meaning on input side */
		{
			from_len = strlen((char*)from);
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					if (to_len * 2 < from_len)
						return ERR_base64_to_buffer_sz;
					hex_to_raw((const char*)from, from_len, (unsigned char*)to);
					return from_len / 2;
				}
				case e_b64_hex:		/* hex */
				case e_b64_hexU:	/* hex, but if used for convertTO param, will uppercase the hex */
				{
					from_len = strlen((char*)from);
					if (to_len < strlen((char*)from)+1)
						return ERR_base64_to_buffer_sz;
					strcpy((char*)to, (const char*)from);
					if (to_t != from_t) {
						if (to_t == e_b64_hex)
							strlwr((char*)to);
						else
							strlwr((char*)to);
					}
					return from_len;
				}
				case e_b64_mime:	/* mime */
				{
					tmp = (unsigned char*)mem_alloc(from_len/2);
					hex_to_raw((const char*)from, from_len, tmp);
					base64_encode((unsigned char*)tmp, from_len/2, (char*)to);
					MEM_FREE(tmp);
					return strlen((char*)to);
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					tmp = (unsigned char*)mem_alloc(from_len/2);
					hex_to_raw((const char*)from, from_len, tmp);
					base64_encode_i((unsigned char*)tmp, from_len/2, (char*)to);
					MEM_FREE(tmp);
					return strlen((char*)to);
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					tmp = (unsigned char*)mem_alloc(from_len/2);
					hex_to_raw((const char*)from, from_len, tmp);
					base64_encode_iBS((unsigned char*)tmp, from_len/2, (char*)to);
					MEM_FREE(tmp);
					return strlen((char*)to);
				}
				default:
					return ERR_base64_unk_to_type;
			}
		}
		case e_b64_mime:	/* mime */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					// TODO, validate to_len
					base64_decode((char*)from, from_len, (char*)to);
					return from_len/4*3;
				}
				case e_b64_hex:		/* hex */
				case e_b64_hexU:
				{
					// TODO, validate to_len
					tmp = (unsigned char*)mem_alloc(from_len);
					base64_decode((char*)from, from_len, (char*)tmp);
					raw_to_hex(tmp, from_len/4*3, (char*)to);
					MEM_FREE(tmp);
					if (to_t == e_b64_hexU)
						strupr((char*)to);
					return strlen((char*)to);
				}
				case e_b64_mime:	/* mime */
				{
					if (to_len < from_len+1)
						return ERR_base64_to_buffer_sz;
					memcpy(to, from, from_len);
					((char*)to)[from_len] = 0;
					return from_len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					if (to_len < from_len+1)
						return ERR_base64_to_buffer_sz;
					return strlen(mime64_to_crypt64((const char*)from, (char*)to, from_len));
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					unsigned char *tmp = (unsigned char*)mem_alloc(from_len);
					base64_decode((char*)from, from_len, (char*)tmp);
					base64_encode_iBS(tmp, (from_len*3)/4+1, (char*)to);
					((char*)to)[from_len] = 0;
					MEM_FREE(tmp);
					return from_len;
				}
				default:
					return ERR_base64_unk_to_type;
			}
		}
		case e_b64_crypt:	/* crypt encoding */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					// TODO, validate to_len
					base64_decode_i((char*)from, from_len, (unsigned char*)to);
					return from_len/4*3;
				}
				case e_b64_hex:		/* hex */
				case e_b64_hexU:	/* hex, but if used for convertTO param, will uppercase the hex */
				{
					// TODO, validate to_len
					tmp = (unsigned char*)mem_alloc(from_len);
					base64_decode_i((char*)from, from_len, (unsigned char*)tmp);
					raw_to_hex(tmp, from_len/4*3, (char*)to);
					MEM_FREE(tmp);
					if (to_t == e_b64_hexU)
						strupr((char*)to);
					return strlen((char*)to);
				}
				case e_b64_mime:	/* mime */
				{
					if (to_len < from_len+1)
						return ERR_base64_to_buffer_sz;
					return strlen(crypt64_to_mime64((const char*)from, (char*)to, from_len));
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					if (to_len < from_len+1)
						return ERR_base64_to_buffer_sz;
					memcpy(to, from, from_len);
					((char*)to)[from_len]=0;
					return from_len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					if (to_len < from_len+1)
						return ERR_base64_to_buffer_sz;
					if (to_len < from_len+1)
						return ERR_base64_to_buffer_sz;
					return strlen(crypt64_to_crypt64_bs((const char*)from, (char*)to, from_len));
				}
				default:
					return ERR_base64_unk_to_type;
			}
		}
		case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
		{
			switch(to_t) {
				case e_b64_raw:		/* raw memory */
				{
					 // TODO, validate to_len
					base64_decode_i_bs((char*)from, from_len, (unsigned char*)to);
					return from_len/4*3;
				}
				case e_b64_hex:		/* hex */
				case e_b64_hexU:	/* hex, but if used for convertTO param, will uppercase the hex */
				{
					// TODO, validate to_len
					unsigned char *tmp = (unsigned char*)mem_alloc(from_len);
					base64_decode_i_bs((char*)from, from_len, (unsigned char*)tmp);
					raw_to_hex(tmp, from_len/4*3, (char*)to);
					MEM_FREE(tmp);
					if (to_t == e_b64_hexU)
						strupr((char*)to);
					return strlen((char*)to);
				}
				case e_b64_mime:	/* mime */
				{
					unsigned char *tmp = (unsigned char*)mem_alloc(from_len);
					base64_decode_i_bs((char*)from, from_len, (unsigned char*)tmp);
					base64_encode(tmp, (from_len*3)/4+1, (char*)to);
					((char*)to)[from_len] =0;
					MEM_FREE(tmp);
					return from_len;
				}
				case e_b64_crypt:	/* crypt encoding */
				{
					unsigned char *tmp = (unsigned char*)mem_alloc(from_len);
					base64_decode_i_bs((char*)from, from_len, (unsigned char*)tmp);
					base64_encode_i(tmp, (from_len*3)/4+1, (char*)to);
					((char*)to)[from_len] =0;
					MEM_FREE(tmp);
					return from_len;
				}
				case e_b64_cryptBS:	/* crypt encoding, network order (used by WPA, cisco9, etc) */
				{
					memcpy(to, from, from_len);
					((char*)to)[from_len]=0;
					return from_len;
				}
				default:
					return ERR_base64_unk_to_type;
			}
		}
		default:
			return ERR_base64_unk_from_type;
	}
	return 0;
}
void base64_convert_error_exit(int err) {
	// TODO: add error codes when created.
	switch (err) {
		case ERR_base64_unk_from_type:	fprintf (stderr, "base64_convert error, Unknown From Type\n", err); break;
		case ERR_base64_unk_to_type:	fprintf (stderr, "base64_convert error, Unknown To Type\n", err); break;
		case ERR_base64_to_buffer_sz:	fprintf (stderr, "base64_convert error, *to buffer too small\n", err); break;
		case ERR_base64_unhandled:		fprintf (stderr, "base64_convert error, currently unhandled conversion\n", err); break;
		default:						fprintf (stderr, "base64_convert_error_exit(%d)\n", err);
	}
	exit(1);
}
char *base64_convert_error(int err) {
	char *p = (char*)mem_alloc(256);
	switch (err) {
		case ERR_base64_unk_from_type:	sprintf(p, "base64_convert error, Unknown From Type\n", err); break;
		case ERR_base64_unk_to_type:	sprintf(p, "base64_convert error, Unknown To Type\n", err); break;
		case ERR_base64_to_buffer_sz:	sprintf(p, "base64_convert error, *to buffer too small\n", err); break;
		case ERR_base64_unhandled:		sprintf(p, "base64_convert error, currently unhandled conversion\n", err); break;
		default:						sprintf(p, "base64_convert_error_exit(%d)\n", err);
	}
	return p;
}

static int usage(char *name)
{
	fprintf(stderr, "Usage: %s [-i input_type] [-o output_type] [-q] data [data ...]\n"
	        "\tdata must match input_type (if hex, then data should be in hex)\n"
			"\t-q will only output resultant string. No extra junk text\n"
			"\tinput/output types:\n"
			"\t\traw\traw data byte\n"
			"\t\thex\thexidecimal string (for input, case does not matter)\n"
			"\t\thexU\thexidecimal string uppercase (if used for output type)\n"
			"\t\tmime\tbase64 mime encoding\n"
			"\t\tcrypt\tbase64 crypt character set encoding\n"
			"\t\tcryptBS\tbase64 crypt encoding, byte swapped\n"
			"",
	        name);
	return EXIT_FAILURE;
}

static b64_convert_type str2convtype(const char *in) {
	if (!strcmp(in, "raw")) return e_b64_raw;
	if (!strcmp(in, "hex")) return e_b64_hex;
	if (!strcmp(in, "hexU")) return e_b64_hexU;
	if (!strcmp(in, "mime")) return e_b64_mime;
	if (!strcmp(in, "crypt")) return e_b64_crypt;
	if (!strcmp(in, "cryptBS")) return e_b64_cryptBS;
	return e_b64_unk;
}

/* simple conerter of strings or raw memory */
int base64conv(int argc, char **argv) {
	int c;
	b64_convert_type in_t=e_b64_unk, out_t=e_b64_unk;
	int quiet=0;

	/* Parse command line */
	while ((c = getopt(argc, argv, "i:o:q!")) != -1) {
		switch (c) {
		case 'i':
			in_t = str2convtype(optarg);
			if (in_t == e_b64_unk) {
				fprintf(stderr, "%s error: invalid input type %s\n", argv[0], optarg);
				return usage(argv[0]);
			}
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
		case '?':
		default:
			return usage(argv[0]);
		}
	}
	argc -= optind;
	if(argc == 0)
		return usage(argv[0]);
	argv += optind;

	while(argc--) {
		char *po = (char*)mem_calloc(strlen(*argv)*3);
		if (!quiet)
			printf("%s  -->  ", *argv);
		printf("%s\n", base64_convert_cp(*argv, in_t, strlen(*argv), po, out_t, strlen(*argv)*3));
		MEM_FREE(po);
		++argv;
	}
	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	return 0;
}
