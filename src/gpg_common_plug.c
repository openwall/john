/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2016 JimF
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 *  Functions and data which is common among the GPG crackers
 *  (CPU, OpenCL)
 */

#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <assert.h>
#include <openssl/blowfish.h>
#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include "idea-JtR.h"
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/des.h>
#include "sha2.h"
#include "md5.h"

#include "formats.h"
#include "memory.h"
#include "common.h"
#include "gpg_common.h"
#include "memdbg.h"

struct gpg_common_custom_salt *gpg_common_cur_salt;

// Returns the block size (in bytes) of a given cipher
uint32_t gpg_common_blockSize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_BLOCK;
		case CIPHER_BLOWFISH:
			return BF_BLOCK;
		case CIPHER_IDEA:
			return 8;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256:
			return AES_BLOCK_SIZE;
		case CIPHER_3DES:
			return 8;
		default:
			break;
	}
	return 0;
}

// Returns the key size (in bytes) of a given cipher
uint32_t gpg_common_keySize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_KEY_LENGTH; // 16
		case CIPHER_BLOWFISH:
			return 16;
		case CIPHER_AES128:
			return 16;
		case CIPHER_AES192:
			return 24;
		case CIPHER_AES256:
			return 32;
		case CIPHER_IDEA:
			return 16;
		case CIPHER_3DES:
			return 24;
		default: break;
	}
	assert(0);
	return 0;
}

static int gpg_common_valid_cipher_algorithm(int cipher_algorithm)
{
	switch(cipher_algorithm) {
		case CIPHER_CAST5: return 1;
		case CIPHER_BLOWFISH: return 1;
		case CIPHER_AES128: return 1;
		case CIPHER_AES192: return 1;
		case CIPHER_AES256: return 1;
		case CIPHER_IDEA: return 1;
		case CIPHER_3DES: return 1;
	}

	return 0;
}

static int gpg_common_valid_hash_algorithm(int hash_algorithm, int spec, int isCPU)
{
	static int warn_once = 1;

	if(spec == SPEC_SIMPLE || spec == SPEC_SALTED) {
		if (!isCPU)
			goto print_warn_once;
		switch(hash_algorithm) {
			case HASH_SHA1: return 1;
			case HASH_MD5: return 1;
			case 0: return 1; // http://www.ietf.org/rfc/rfc1991.txt
		}
	}
	if(spec == SPEC_ITERATED_SALTED) {
		if (!isCPU) {
			if (hash_algorithm==HASH_SHA1) return 1;
			goto print_warn_once;
		}
		switch(hash_algorithm)
		{
			case HASH_SHA1: return 1;
			case HASH_MD5: return 1;
			case HASH_SHA256: return 1;
			case HASH_RIPEMD160: return 1;
			case HASH_SHA512: return 1;
		}
	}
	return 0;
print_warn_once:
	if(warn_once) {
		fprintf(stderr,
		        "[-] gpg-opencl currently only supports keys using iterated salted SHA1\n");
		warn_once = 0;
	}
	return 0;
}

int gpg_common_valid(char *ciphertext, struct fmt_main *self, int is_CPU_format)
{
	char *ctcopy, *keeptr, *p;
	int res,j,spec,usage,algorithm,ex_flds=0;
	int symmetric_mode = 0;

	if (strncmp(ciphertext, "$gpg$*", 6) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 6;	/* skip over "$gpg$" marker and '*' */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* algorithm */
		goto err;
	if (!isdec(p))
		goto err;
	algorithm = atoi(p); // FIXME: which values are valid?
	if (algorithm == 0) { // files using GPG symmetric encryption?
		symmetric_mode = 1;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* datalen */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > BIG_ENOUGH * 2)
		goto err;
	if (!symmetric_mode) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* bits */
			goto err;
		if (!isdec(p)) // FIXME: bits == 0 allowed?
			goto err;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* data */
		goto err;
	if (hexlenl(p) != res*2)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* spec */
		goto err;
	if (!isdec(p))
		goto err;
	spec = atoi(p);
	if ((p = strtokm(NULL, "*")) == NULL)	/* usage */
		goto err;
	if (!isdec(p))
		goto err;
	usage = atoi(p);
	if (!symmetric_mode) {
		if(usage != 0 && usage != 254 && usage != 255 && usage != 1)
			goto err;
	} else {
		if(usage != 9 && usage != 18) // https://tools.ietf.org/html/rfc4880
			goto err;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* hash_algorithm */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if(!gpg_common_valid_hash_algorithm(res, spec, is_CPU_format))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* cipher_algorithm */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if(!gpg_common_valid_cipher_algorithm(res))
		goto err;
	if (!symmetric_mode) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* ivlen */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res != 8 && res != 16)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
			goto err;
		if (hexlenl(p) != res*2)
			goto err;
	}
	/* handle "SPEC_SIMPLE" correctly */
	if ((spec != 0 || usage == 255))
		;
	else if (spec == 0) {
		MEM_FREE(keeptr);
		return 1;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* count */
		goto err;
	if (!isdec(p)) // FIXME: count == 0 allowed?
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p) != SALT_LENGTH*2)
		goto err;
	/*
	 * For some test vectors, there are no more fields,
	 * for others, there are (and need to be checked)
	 * this logic taken from what happens in salt()
	 */
	if (usage == 255 && spec == 1 && algorithm == 17) {
		/* old hashes will crash!, "gpg --s2k-mode 1 --gen-key" */
		ex_flds = 4; /* handle p, q, g, y */
	} else if (usage == 255 && spec == 1 && algorithm == 16) {
		/* ElGamal */
		ex_flds = 3; /* handle p, g, y */
	} else if (usage == 255 && spec == 1) {
		/* RSA */
		ex_flds = 1; /* handle p */
	} else if (usage == 255 && spec == 3 && algorithm == 1) {
		/* gpg --homedir . --s2k-cipher-algo 3des --simple-sk-checksum --gen-key */
		ex_flds = 1; /* handle p */
	} else {
		/* NOT sure what to do here, probably nothing */
	}

	p = strtokm(NULL, "*"); /* NOTE, do not goto err if null, we WANT p nul if there are no fields */

	if (symmetric_mode) {
		goto good;
	}

	for (j = 0; j < ex_flds; ++j) {  /* handle extra p, q, g, y fields */
		if (!p) /* check for null p */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > BIG_ENOUGH * 2)
			goto err; // FIXME: warn if BIG_ENOUGH isn't big enough?
		if ((p = strtokm(NULL, "*")) == NULL)
			goto err;
		if (hexlenl(p) != res*2)
			goto err;
		p = strtokm(NULL, "*");  /* NOTE, do not goto err if null, we WANT p nul if there are no fields */
	}

	if (p)	/* at this point, there should be NO trailing stuff left from the hash. */
		goto err;

good:
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *gpg_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct gpg_common_custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += 6;	/* skip over "$gpg$" marker and first '*' */
	p = strtokm(ctcopy, "*");
	cs.pk_algorithm = atoi(p);
	if (cs.pk_algorithm == 0) {
		cs.symmetric_mode = 1;
	}
	p = strtokm(NULL, "*");
	cs.datalen = atoi(p);
	if (!cs.symmetric_mode) {
		p = strtokm(NULL, "*");
		cs.bits = atoi(p);
	}
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.datalen; i++)
		cs.data[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.spec = atoi(p);
	p = strtokm(NULL, "*");
	cs.usage = atoi(p);
	p = strtokm(NULL, "*");
	cs.hash_algorithm = atoi(p);
	p = strtokm(NULL, "*");
	cs.cipher_algorithm = atoi(p);
	if (!cs.symmetric_mode) {
		p = strtokm(NULL, "*");
		cs.ivlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.ivlen; i++)
			cs.iv[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	p = strtokm(NULL, "*");
	/* handle "SPEC_SIMPLE" correctly */
	if (cs.spec != 0 || cs.usage == 255) {
		cs.count = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < SALT_LENGTH; i++)
			cs.salt[i] =
			atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (cs.usage == 255 && cs.spec == 1 && cs.pk_algorithm == 17) {
		/* old hashes will crash!, "gpg --s2k-mode 1 --gen-key" */
		p = strtokm(NULL, "*");
		cs.pl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.p[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.ql = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.q[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.gl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.g[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.yl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.y[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (cs.usage == 255 && cs.spec == 1 && cs.pk_algorithm == 16) {
		/* ElGamal */
		p = strtokm(NULL, "*");
		cs.pl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.p[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.gl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.g[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.yl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.y[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (cs.usage == 255 && cs.pk_algorithm == 1) {
		/* RSA */
		p = strtokm(NULL, "*");
		cs.nl = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < strlen(p) / 2; i++)
			cs.n[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
			atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);
	return (void *)&cs;
}
static int give_multi_precision_integer(unsigned char *buf, int len, int *key_bytes, unsigned char *out)
{
	int bytes;
	int i;
	int bits = buf[len] * 256;
	len++;
	bits += buf[len];
	len++;
	bytes = (bits + 7) / 8;
	*key_bytes = bytes;

	for (i = 0; i < bytes; i++)
		out[i] = buf[len++];

	return bytes + 2;
}

// borrowed from "passe-partout" project
static int check_dsa_secret_key(DSA *dsa)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_dsa_secret_key()\n");
		error();
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in check_dsa_secret_key()\n");
		error();
	}

	error = BN_mod_exp(res, dsa->g, dsa->priv_key, dsa->p, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, dsa->pub_key);

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(dsa->g);
	BN_free(dsa->q);
	BN_free(dsa->p);
	BN_free(dsa->pub_key);
	BN_free(dsa->priv_key);

	return rc;
}

typedef struct {
	BIGNUM *p;          /* prime */
	BIGNUM *g;          /* group generator */
	BIGNUM *y;          /* g^x mod p */
	BIGNUM *x;          /* secret exponent */
} ElGamal_secret_key;

// borrowed from GnuPG
static int check_elg_secret_key(ElGamal_secret_key *elg)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_elg_secret_key()\n");
		error();
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in chec_elg_secret_key()\n");
		error();
	}

	error = BN_mod_exp(res, elg->g, elg->x, elg->p, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, elg->y);

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(elg->g);
	BN_free(elg->p);
	BN_free(elg->y);
	BN_free(elg->x);

	return rc;
}

typedef struct {
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *n;
} RSA_secret_key;

// borrowed from GnuPG
static int check_rsa_secret_key(RSA_secret_key *rsa)
{
	int error;
	int rc = -1;
	BIGNUM *res = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!res) {
		fprintf(stderr, "failed to allocate result BN in check_rsa_secret_key()\n");
		error();
	}
	if (!ctx) {
		fprintf(stderr, "failed to allocate BN_CTX ctx in chec_rsa_secret_key()\n");
		error();
	}

	error = BN_mul(res, rsa->p, rsa->q, ctx);
	if ( error == 0 ) {
		goto freestuff;
	}

	rc = BN_cmp(res, rsa->n);  // p * q == n

freestuff:

	BN_CTX_free(ctx);
	BN_free(res);
	BN_free(rsa->p);
	BN_free(rsa->q);
	BN_free(rsa->n);

	return rc;
}

int gpg_common_check(unsigned char *keydata, int ks)
{
	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
	unsigned char ivec[32];
	unsigned char out[BIG_ENOUGH * 2] = { 0 };
	int tmp = 0;
	uint32_t num_bits = 0;
	int checksumOk;
	int i;
	uint8_t checksum[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;

	// Quick Hack
	if (!gpg_common_cur_salt->symmetric_mode)
		memcpy(ivec, gpg_common_cur_salt->iv, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));
	else
		memset(ivec, 0, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));

	switch (gpg_common_cur_salt->cipher_algorithm) {
		case CIPHER_IDEA: {
					   IDEA_KEY_SCHEDULE iks;
					   JtR_idea_set_encrypt_key(keydata, &iks);
					   JtR_idea_cfb64_encrypt(gpg_common_cur_salt->data, out, SALT_LENGTH, &iks, ivec, &tmp, IDEA_DECRYPT);
				   }
				   break;
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(gpg_common_cur_salt->data, out, CAST_BLOCK, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(gpg_common_cur_salt->data, out, BF_BLOCK, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(gpg_common_cur_salt->data, out, AES_BLOCK_SIZE, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		case CIPHER_3DES: {
					  DES_cblock key1, key2, key3;
					  DES_cblock divec;
					  DES_key_schedule ks1, ks2, ks3;
					  int num = 0;
					  memcpy(key1, keydata + 0, 8);
					  memcpy(key2, keydata + 8, 8);
					  memcpy(key3, keydata + 16, 8);
					  memcpy(divec, ivec, 8);
					  DES_set_key((DES_cblock *)key1, &ks1);
					  DES_set_key((DES_cblock *)key2, &ks2);
					  DES_set_key((DES_cblock *)key3, &ks3);
					  DES_ede3_cfb64_encrypt(gpg_common_cur_salt->data, out, SALT_LENGTH, &ks1, &ks2, &ks3, &divec, &num, DES_DECRYPT);
				    }
				    break;

		default:
				    printf("(check) Unknown Cipher Algorithm %d ;(\n", gpg_common_cur_salt->cipher_algorithm);
				    break;
	}

	if (!gpg_common_cur_salt->symmetric_mode) {
		num_bits = ((out[0] << 8) | out[1]);
		if (num_bits < MIN_BN_BITS || num_bits > gpg_common_cur_salt->bits) {
			return 0;
		}
	}
	// Decrypt all data
	if (!gpg_common_cur_salt->symmetric_mode)
		memcpy(ivec, gpg_common_cur_salt->iv, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));
	else
		memset(ivec, 0, gpg_common_blockSize(gpg_common_cur_salt->cipher_algorithm));
	tmp = 0;
	switch (gpg_common_cur_salt->cipher_algorithm) {
		case CIPHER_IDEA: {
					   IDEA_KEY_SCHEDULE iks;
					   JtR_idea_set_encrypt_key(keydata, &iks);
					   JtR_idea_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &iks, ivec, &tmp, IDEA_DECRYPT);
				   }
				   break;
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		case CIPHER_3DES: {
					  DES_cblock key1, key2, key3;
					  DES_cblock divec;
					  DES_key_schedule ks1, ks2, ks3;
					  int num = 0;
					  memcpy(key1, keydata + 0, 8);
					  memcpy(key2, keydata + 8, 8);
					  memcpy(key3, keydata + 16, 8);
					  memcpy(divec, ivec, 8);
					  DES_set_key((DES_cblock *) key1, &ks1);
					  DES_set_key((DES_cblock *) key2, &ks2);
					  DES_set_key((DES_cblock *) key3, &ks3);
					  DES_ede3_cfb64_encrypt(gpg_common_cur_salt->data, out, gpg_common_cur_salt->datalen, &ks1, &ks2, &ks3, &divec, &num, DES_DECRYPT);
				    }
				    break;
		default:
				    break;
	}

	if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 18) { // uses zero IV (see g10/encrypt.c)!
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, out, gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH);
		SHA1_Final(checksum, &ctx);
		if (memcmp(checksum, out + gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0)
			return 1;  /* we have a 20 byte verifier ;) */
		else
			return 0;
	} else if (gpg_common_cur_salt->symmetric_mode && gpg_common_cur_salt->usage == 9) {
		// https://www.ietf.org/rfc/rfc2440.txt
		if ((out[9] == out[7]) && (out[8] == out[6])) // XXX this verifier is not good at all!
			return 1;
		else
			return 0;
	}

	// Verify
	checksumOk = 0;
	switch (gpg_common_cur_salt->usage) {
		case 254: {
				  SHA1_Init(&ctx);
				  SHA1_Update(&ctx, out, gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH);
				  SHA1_Final(checksum, &ctx);
				  if (memcmp(checksum, out + gpg_common_cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0)
					  return 1;  /* we have a 20 byte verifier ;) */
				  else
					  return 0;
			  } break;
		case 0:
		case 255: {
				  // https://tools.ietf.org/html/rfc4880#section-3.7.2
				  uint16_t sum = 0;
				  for (i = 0; i < gpg_common_cur_salt->datalen - 2; i++) {
					  sum += out[i];
				  }
				  if (sum == ((out[gpg_common_cur_salt->datalen - 2] << 8) | out[gpg_common_cur_salt->datalen - 1])) {
					  checksumOk = 1;
				  }
			  } break;
		default:
			  break;
	}
	// If the checksum is ok, try to parse the first MPI of the private key
	// Stop relying on checksum altogether, GnuPG ignores it (after
	// documenting why though!)
	if (checksumOk) {
		BIGNUM *b = NULL;
		uint32_t blen = (num_bits + 7) / 8;
		int ret;
		if (gpg_common_cur_salt->datalen == 24 && blen != 20)  /* verifier 1 */
			return 0;
		if (blen < gpg_common_cur_salt->datalen && ((b = BN_bin2bn(out + 2, blen, NULL)) != NULL)) {
			char *str = BN_bn2hex(b);
			DSA dsa;
			ElGamal_secret_key elg;
			RSA_secret_key rsa;
			if (strlen(str) != blen * 2) { /* verifier 2 */
				OPENSSL_free(str);
				BN_free(b);
				return 0;
			}
			OPENSSL_free(str);

			if (gpg_common_cur_salt->pk_algorithm == 17) { /* DSA check */
				dsa.p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				// puts(BN_bn2hex(dsa.p));
				dsa.q = BN_bin2bn(gpg_common_cur_salt->q, gpg_common_cur_salt->ql, NULL);
				// puts(BN_bn2hex(dsa.q));
				dsa.g = BN_bin2bn(gpg_common_cur_salt->g, gpg_common_cur_salt->gl, NULL);
				// puts(BN_bn2hex(dsa.g));
				dsa.priv_key = b;
				dsa.pub_key = BN_bin2bn(gpg_common_cur_salt->y, gpg_common_cur_salt->yl, NULL);
				// puts(BN_bn2hex(dsa.pub_key));
				ret = check_dsa_secret_key(&dsa); /* verifier 3 */
				if (ret != 0)
					return 0;
			}
			if (gpg_common_cur_salt->pk_algorithm == 16 || gpg_common_cur_salt->pk_algorithm == 20) { /* ElGamal check */
				elg.p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				// puts(BN_bn2hex(elg.p));
				elg.g = BN_bin2bn(gpg_common_cur_salt->g, gpg_common_cur_salt->gl, NULL);
				// puts(BN_bn2hex(elg.g));
				elg.x = b;
				// puts(BN_bn2hex(elg.x));
				elg.y = BN_bin2bn(gpg_common_cur_salt->y, gpg_common_cur_salt->yl, NULL);
				// puts(BN_bn2hex(elg.y));
				ret = check_elg_secret_key(&elg); /* verifier 3 */
				if (ret != 0)
					return 0;
			}
			if (gpg_common_cur_salt->pk_algorithm == 1) { /* RSA check */
				// http://www.ietf.org/rfc/rfc4880.txt
				int length = 0;
				length += give_multi_precision_integer(out, length, &gpg_common_cur_salt->dl, gpg_common_cur_salt->d);
				length += give_multi_precision_integer(out, length, &gpg_common_cur_salt->pl, gpg_common_cur_salt->p);
				length += give_multi_precision_integer(out, length, &gpg_common_cur_salt->ql, gpg_common_cur_salt->q);

				rsa.n = BN_bin2bn(gpg_common_cur_salt->n, gpg_common_cur_salt->nl, NULL);
				rsa.p = BN_bin2bn(gpg_common_cur_salt->p, gpg_common_cur_salt->pl, NULL);
				rsa.q = BN_bin2bn(gpg_common_cur_salt->q, gpg_common_cur_salt->ql, NULL);

				// b is not used.  So we must free it, or we have a leak.
				BN_free(b);
				ret = check_rsa_secret_key(&rsa);
				if (ret != 0)
					return 0;
			}
			return 1;
		}
	}
	return 0;
}

/*
 * Report gpg --s2k-count n as 1st tunable cost,
 * hash algorithm as 2nd tunable cost,
 * cipher algorithm as 3rd tunable cost.
 */

unsigned int gpg_common_gpg_s2k_count(void *salt)
{
	struct gpg_common_custom_salt *my_salt;

	my_salt = salt;
	if (my_salt->spec == 3)
		/*
		 * gpg --s2k-count is only meaningful
		 * if --s2k-mode is 3, see man gpg
		 */
		return (unsigned int) my_salt->count;
	else if (my_salt->spec == 1)
		return 1; /* --s2k-mode 1 */
	else
		return 0; /* --s2k-mode 0 */
}

unsigned int gpg_common_gpg_hash_algorithm(void *salt)
{
	struct gpg_common_custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->hash_algorithm;
}
unsigned int gpg_common_gpg_cipher_algorithm(void *salt)
{
	struct gpg_common_custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->cipher_algorithm;
}
