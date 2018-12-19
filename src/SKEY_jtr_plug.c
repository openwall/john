/*
  SKEY_jtr_plug.c

  S/Key native algorithm for JtR.

  This is the actual SKEY algorithm, internalized into JtR code. The
  -lskey is only on a few systems, and very hard to find. This code
  may not be highly optimized, BUT it provides a basis for all systems
  to perform SKEY checks.

  Code added May 2014, JimF.  Released into public domain, and is usable
  in source or binary form, with or without modifications with no
  restrictions.

*/

#include "arch.h"
#include <stdio.h>
#include "SKEY_jtr.h"
#include "misc.h"
#include "md4.h"
#include "md5.h"
#include "sha.h"
#include "sph_ripemd.h"

#ifndef HAVE_SKEY
// If HAVE_SKEY is defined, THEN we will use the native
// library and not this code.

static int which;  // 0==md4, 1=md5, 2=sha1, 3=rmd160
static unsigned int tmp_buf[5];// large enough for sha1/ripemd160

char *jtr_skey_set_algorithm(char *buf) {
	if (!strcmp(buf, "md4"))    { which = 0; return "md4"; }
	if (!strcmp(buf, "md5"))    { which = 1; return "md5"; }
	if (!strcmp(buf, "sha1"))   { which = 2; return "sha1"; }
	if (!strcmp(buf, "rmd160")) { which = 3; return "rmd160"; }
	return NULL;
}
static void md4_f(unsigned int *crypt, unsigned char *in, int len) {
	MD4_CTX ctx;
	MD4_Init(&ctx);
	MD4_Update(&ctx, in, len);
	MD4_Final((unsigned char*)tmp_buf, &ctx);
	crypt[0] = tmp_buf[0]^tmp_buf[2];
	crypt[1] = tmp_buf[1]^tmp_buf[3];
}
static void md5_f(unsigned int *crypt, unsigned char *in, int len) {
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, in, len);
	MD5_Final((unsigned char*)tmp_buf, &ctx);
	crypt[0] = tmp_buf[0]^tmp_buf[2];
	crypt[1] = tmp_buf[1]^tmp_buf[3];
}
static void sha1_f(unsigned int *crypt, unsigned char *in, int len) {
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, in, len);
	SHA1_Final((unsigned char*)tmp_buf, &ctx);
	crypt[0] = tmp_buf[0]^tmp_buf[2]^tmp_buf[4];
	crypt[1] = tmp_buf[1]^tmp_buf[3];
}
static void rmd160_f(unsigned int *crypt, unsigned char *in, int len) {
	sph_ripemd160_context ctx;
	sph_ripemd160_init(&ctx);
	sph_ripemd160(&ctx, in, len);
	sph_ripemd160_close(&ctx, (unsigned char*)tmp_buf);
	crypt[0] = tmp_buf[0]^tmp_buf[2]^tmp_buf[4];
	crypt[1] = tmp_buf[1]^tmp_buf[3];
}
void jtr_skey_keycrunch(unsigned char *saved_key, char *saved_salt_seed, char *saved_pass) {
	unsigned char tmp[256];
	int slen, plen;
	slen = strlen(saved_salt_seed);
	plen = strlen(saved_pass);
	strcpy((char*)tmp, saved_salt_seed);
	strlwr((char*)tmp);
	strcpy((char*)(&tmp[slen]), saved_pass);
	plen += slen;
	switch (which) {
		case 0: md4_f((unsigned int *)saved_key,    tmp, plen); return;
		case 1: md5_f((unsigned int *)saved_key,    tmp, plen); return;
		case 2: sha1_f((unsigned int *)saved_key,   tmp, plen); return;
		case 3: rmd160_f((unsigned int *)saved_key, tmp, plen); return;
	}
}
void jtr_skey_f(unsigned char *saved_key) {
	switch (which) {
		case 0: md4_f((unsigned int *)saved_key, saved_key, 8); return;
		case 1: md5_f((unsigned int *)saved_key, saved_key, 8); return;
		case 2: sha1_f((unsigned int *)saved_key, saved_key, 8); return;
		case 3: rmd160_f((unsigned int *)saved_key, saved_key, 8); return;
	}
}

#endif
