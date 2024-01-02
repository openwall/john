/*
 * These are conversion functions for MIME Base64 (as opposed to MIME in
 * base6.[ch] and crypt(3) encoding found in common.[ch]).  This code will
 * convert between many base64 types, raw memory, hex, etc.
 * functions added to convert between the 3 types (JimF)
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

/*********************************************************************
 * Length macros which convert from one system to the other.
 * RAW_TO_B64_LEN(x) returns 'exact' base64 string length needed. NOTE, some
 *     base64 will padd to an even 4 characters.  The length from this macro
 *     DOES NOT include padding values.
 * B64_TO_RAW_LEN(x) returns raw string length needed for the base-64 string
 *     that is NOT padded in any way (i.e.  needs to be same value as returned
 *     from RAW_TO_B64_LEN(x)  )
 *********************************************************************/
#define RAW_TO_B64_LEN(a) (((a)*4+2)/3)
#define B64_TO_RAW_LEN(a) (((a)*3+1)/4)

typedef enum {
		e_b64_unk=-1,	/* invalid type seen from command line usage */
		e_b64_raw,		/* raw memory */
		e_b64_hex,		/* hex */
		e_b64_mime,		/* mime */
		e_b64_crypt,	/* crypt encoding */
		e_b64_cryptBS,	/* crypt encoding, network order (WPA, cisco9, etc) */
} b64_convert_type;

/*
 * Base-64 modification flags
 */
#define flg_Base64_NO_FLAGS             0x00
#define flg_Base64_HEX_UPCASE           0x01
#define flg_Base64_HEX_LOCASE           0x02
#define flg_Base64_MIME_TRAIL_EQ        0x04
#define flg_Base64_CRYPT_TRAIL_DOTS     0x08
#define flg_Base64_MIME_PLUS_TO_DOT     0x10
// mime alphabet, BUT last 2 chars are -_ (instead of +/ )
#define flg_Base64_MIME_DASH_UNDER      0x20
#define flg_Base64_MIME_TRAIL_EQ_CNT    0x40
// #define flg_Base64_RET_NEG_IF_NOT_PURE  0x80   // Depricated, invalid flag!
#define flg_Base64_DONOT_NULL_TERMINATE 0x100

/*
 * return will be number of bytes converted and placed into *to (can be less
 * than to_len).
 *
 * the length of the to, MUST be at least max len + 1 (for the null byte), for
 * types, e_b64_hex, e_b64_mime, e_b64_crypt and e_b64_cryptBS. Each of those
 * 'to' types will get a null byte added.  The exception is if flag
 * flg_Base64_DONOT_NULL_TERMINATE is used.  In that case, the code will NOT
 * add a null terminator. The output type e_b64_raw NEVER null terminates.
 *
 * NOTE, the buffer should be max len + 4 for any base-64 conversion.
 */
size_t base64_convert(const void *from,       // input data.
                   b64_convert_type from_t,   // b64_convert_type of input data
                   size_t from_len,           // length of input to use
                   void *to,                  // output buf (large enough + x)
                   b64_convert_type to_t,     // b64_convert_type to convert to
                   size_t to_len,
                   unsigned flags,
		   int *err);                 // optional pointer to int, set on error. NULL is fine, but no error return given.
/* same function as base64_convert(), but returns the *to as a char* and has
 * its own error handling (prints an error and terminates the process) if err
 * is not NULL */
char *base64_convert_cp(const void *from,
                        b64_convert_type from_t,
                        size_t from_len,
                        void *to,
                        b64_convert_type to_t,
                        size_t to_len,
                        unsigned flags,
			int *err);
size_t base64_valid_length(const char *from, b64_convert_type from_t, unsigned flags, int *err);
void base64_convert_error_exit(int err);
char *base64_convert_error(int err);  /* allocates buffer, caller must free */

#endif  // _BASE64_CONVERT_H
