/*
 * This is MIME Base64 (as opposed to crypt(3) encoding found in common.[ch])
 */

#ifndef _BASE64_H
#define _BASE64_H

int base64_decode(char *in, int inlen, char *out);

#endif
