/*
 * This is MIME Base64 (as opposed to crypt(3) encoding found in common.[ch])
 * functions added to convert between the 2 types (JimF)
 */

#ifndef _BASE64_H
#define _BASE64_H

int base64_decode(char *in, int inlen, char *out);
char *mime64_to_crypt64(const char *in, char *out, int len); /* out buffer at least len+1 */
char *crypt64_to_mime64(const char *in, char *out, int len);

#endif
