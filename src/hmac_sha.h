/*
 * free 'simple' hmac_sha*. Public domain, 2015, JimF.
 * Built for John source to replace other code.
 *
 * This software was written by JimF jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#ifndef _JTR_HMAC_SHA_H

extern void JTR_hmac_sha1(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len);
#define hmac_sha1(key,keylen,data,datalen,dgst,dgstlen) JTR_hmac_sha1(key,keylen,data,datalen,dgst,dgstlen)

extern void JTR_hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len);
#define hmac_sha256(key,keylen,data,datalen,dgst,dgstlen) JTR_hmac_sha256(key,keylen,data,datalen,dgst,dgstlen)

extern void JTR_hmac_sha512(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len);
#define hmac_sha512(key,keylen,data,datalen,dgst,dgstlen) JTR_hmac_sha512(key,keylen,data,datalen,dgst,dgstlen)

extern void JTR_hmac_sha224(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len);
#define hmac_sha224(key,keylen,data,datalen,dgst,dgstlen) JTR_hmac_sha224(key,keylen,data,datalen,dgst,dgstlen)

extern void JTR_hmac_sha384(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *digest, int digest_len);
#define hmac_sha384(key,keylen,data,datalen,dgst,dgstlen) JTR_hmac_sha384(key,keylen,data,datalen,dgst,dgstlen)

#endif /* _JTR_HMAC_SHA_H */
