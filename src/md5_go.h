/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, placed in
 * the public domain, and hacked by others.
 *
 * If you reuse the code for another purpose, please download the original from:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 */

#if !defined(_MD5_GO_H)
#define _MD5_GO_H

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD5_u32plus;
extern void MD5_Go(unsigned char *data, unsigned int len);
extern void MD5_Go2(unsigned char *data, unsigned int len, unsigned char *result);

#endif
