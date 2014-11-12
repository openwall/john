/*
 * These are conversion functions for MIME Base64 (as opposed to MIME in base6.[ch] and
 * crypt(3) encoding found in common.[ch]).  This code will convert between many base64
 * types, raw memory, hex, etc.
 * functions added to convert between the 2 types (JimF)
 *
 * Coded Fall 2014 by Jim Fougeron.  Code placed in public domain.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted, as long an unmodified copy of this
 * license/disclaimer accompanies the source.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _BASE64_CONVERT_H
#define _BASE64_CONVERT_H

typedef enum {
		e_b64_unk=-1,	/* invalid type seen from command line usage */
		e_b64_raw,		/* raw memory */
		e_b64_hex,		/* hex */
		e_b64_mime,		/* mime */
		e_b64_crypt,	/* crypt encoding */
		e_b64_cryptBS,	/* crypt encoding, network order (used by WPA, cisco9, etc) */
} b64_convert_type;

/*
 * Base-64 modification flags
 */
#define flg_Base64_HEX_UPCASE			1
#define flg_Base64_MIME_TRAIL_EQ		2
#define flg_Base64_CRYPT_TRAIL_DOTS		4
#define flg_Base64_MIME_PLUS_TO_DOT		8

/*
 * return will be number of bytes converted and placed into *to (can be less than to_len).  A negative return is
 * an error, which can be passed to one of the error processing functions
 */
int base64_convert(const void *from, b64_convert_type from_t, int from_len, void *to, b64_convert_type to_t, int to_len, unsigned flags);
char *base64_convert_cp(const void *from, b64_convert_type from_t, int from_len, void *to, b64_convert_type to_t, int to_len, unsigned flags);
void base64_convert_error_exit(int err);
char *base64_convert_error(int err);  /* allocates buffer, which caller must free */

//char *mime64_to_crypt64(const char *in, char *out, int len); /* out buffer at least len+1 */
//char *crypt64_to_mime64(const char *in, char *out, int len);

#endif  // _BASE64_CONVERT_H
