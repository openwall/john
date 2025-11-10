/*
 * PDF cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2013, Shane Quigley
 * Copyright (c) 2024, magnum
 *
 * Uses code from pdfcrack, Sumatra PDF and MuPDF which are under GPL.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pdf;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pdf);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "pdf_common.h"
#include "md5.h"
#include "aes.h"
#include "sha2.h"
#include "rc4.h"
#include "pdfcrack_md5.h"

#define FORMAT_LABEL        "PDF"
#define ALGORITHM_NAME      ALGORITHM_BASE " 32/" ARCH_BITS_STR
#define MAX_KEYS_PER_CRYPT  4

#ifndef OMP_SCALE
#define OMP_SCALE           8 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	any_pdf_cracked = 0;
	pdf_cracked_size = sizeof(*pdf_cracked) * self->params.max_keys_per_crypt;
	pdf_cracked = mem_calloc(sizeof(*pdf_cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(pdf_cracked);
	MEM_FREE(saved_key);
}

/* Compute an encryption key (PDF 1.7 algorithm 3.2) */
static void
pdf_compute_encryption_key(unsigned char *password, int pwlen, unsigned char *key)
{
        unsigned char buf[32];
        unsigned int p;
        int n;
        MD5_CTX md5;

        n = pdf_salt->key_length / 8;

        /* Step 1-2 - init md5 and hash padded password  */
        if (pwlen > 32)
                pwlen = 32;
        MD5_Init(&md5);
        MD5_Update(&md5, password, pwlen);
        MD5_Update(&md5, pdf_padding, 32 - pwlen);

        /* Step 3 - pass O value */
        MD5_Update(&md5, pdf_salt->o, 32);

        /* Step 4 - pass P value as unsigned int, low-order byte first */
        p = (unsigned int) pdf_salt->P;
        buf[0] = (p) & 0xFF;
        buf[1] = (p >> 8) & 0xFF;
        buf[2] = (p >> 16) & 0xFF;
        buf[3] = (p >> 24) & 0xFF;
        MD5_Update(&md5, buf, 4);

        /* Step 5 - pass first element of ID array */
        MD5_Update(&md5, pdf_salt->id, pdf_salt->id_len);

        /* Step 6 (revision 4 or greater) - if metadata is not encrypted pass 0xFFFFFFFF */
        if (pdf_salt->R >= 4)
        {
                if (!pdf_salt->encrypt_metadata)
                {
                        buf[0] = 0xFF;
                        buf[1] = 0xFF;
                        buf[2] = 0xFF;
                        buf[3] = 0xFF;
                        MD5_Update(&md5, buf, 4);
                }
        }

        /* Step 7 - finish the hash */
        MD5_Final(buf, &md5);

        /* Step 8 (revision 3 or greater) - do some voodoo 50 times */
        if (pdf_salt->R >= 3)
        {
	        int i;

	        switch(pdf_salt->key_length) {
	        case 128:
		        md5x50_128(buf);
		        break;
	        case 40:
		        md5x50_40(buf);
		        break;
	        default:
		        for (i = 0; i < 50; i++) {
			        MD5_Init(&md5);
			        MD5_Update(&md5, buf, n);
			        MD5_Final(buf, &md5);
		        }
	        }
        }
        /* Step 9 - the key is the first 'n' bytes of the result */
        memcpy(key, buf, n);
}

/* Compute an encryption key (PDF 1.7 ExtensionLevel 3 algorithm 3.2a) */
static void
pdf_compute_encryption_key_r5(unsigned char *password, int pwlen, int ownerkey, unsigned char *validationkey)
{
        unsigned char buffer[128 + 8 + 48];
        SHA256_CTX sha256;

        /* Step 2 - truncate UTF-8 password to 127 characters */

        if (pwlen > 127)
                pwlen = 127;

        /* Step 3/4 - test password against owner/user key and compute encryption key */

        memcpy(buffer, password, pwlen);
        if (ownerkey)
        {
                memcpy(buffer + pwlen, pdf_salt->o + 32, 8);
                memcpy(buffer + pwlen + 8, pdf_salt->u, 48);
        }
        else
                memcpy(buffer + pwlen, pdf_salt->u + 32, 8);

        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buffer, pwlen + 8 + (ownerkey ? 48 : 0));
        SHA256_Final(validationkey, &sha256);
}

/* SumatraPDF: support crypt version 5 revision 6 */
/*
 * Compute an encryption key (PDF 1.7 ExtensionLevel 8 algorithm 3.2b)
 * https://web.archive.org/web/20130211160511/http://esec-lab.sogeti.com/post/The-undocumented-password-validation-algorithm-of-Adobe-Reader-X
 */
static void
pdf_compute_hardened_hash_r6(unsigned char *password, int pwlen, unsigned char salt[8],
        unsigned char *ownerkey, unsigned char hash[32])
{
        unsigned char data[(PLAINTEXT_LENGTH + 64) * 64];
        unsigned char block[64];
        int block_size = 32;
        int data_len = 0;
        int i, j, sum;

        SHA256_CTX sha256;
        SHA512_CTX sha384;
        SHA512_CTX sha512;
        AES_KEY aes;

        /* Step 1: calculate initial data block */
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password, pwlen);
        SHA256_Update(&sha256, salt, 8);
        if (ownerkey)
                SHA256_Update(&sha256, ownerkey, 48);
        SHA256_Final(block, &sha256);

        for (i = 0; i < 64 || i < data[data_len * 64 - 1] + 32; i++)
        {
                /* Step 2: repeat password and data block 64 times */
                memcpy(data, password, pwlen);
                memcpy(data + pwlen, block, block_size);
                // ownerkey is always NULL
                // memcpy(data + pwlen + block_size, ownerkey, ownerkey ? 48 : 0);
                data_len = pwlen + block_size /* + (ownerkey ? 48 : 0) */;
                for (j = 1; j < 64; j++)
                        memcpy(data + j * data_len, data, data_len);

                /* Step 3: encrypt data using data block as key and iv */
                AES_set_encrypt_key(block, 128, &aes);
                // aes_crypt_cbc(&aes, AES_ENCRYPT, data_len * 64, block + 16, data, data);
                AES_cbc_encrypt(data, data, data_len * 64, &aes, block + 16, AES_ENCRYPT);

                /* Step 4: determine SHA-2 hash size for this round */
                for (j = 0, sum = 0; j < 16; j++)
                        sum += data[j];

                /* Step 5: calculate data block for next round */
                block_size = 32 + (sum % 3) * 16;
                switch (block_size)
                {
                case 32:
                        SHA256_Init(&sha256);
                        SHA256_Update(&sha256, data, data_len * 64);
                        SHA256_Final(block, &sha256);
                        break;
                case 48:
                        SHA384_Init(&sha384);
                        SHA384_Update(&sha384, data, data_len * 64);
                        SHA384_Final(block, &sha384);
                        break;
                case 64:
                        SHA512_Init(&sha512);
                        SHA512_Update(&sha512, data, data_len * 64);
                        SHA512_Final(block, &sha512);
                        break;
                }
        }

        //memset(data, 0, sizeof(data));
        memcpy(hash, block, 32);
}

/* Computing the user password (PDF 1.7 algorithm 3.4 and 3.5) */
static void pdf_compute_user_password(unsigned char *password,  unsigned char *output)
{
	int pwlen = strlen((char*)password);
	unsigned char key[MAX_KEY_SIZE / 8];
	int n = pdf_salt->key_length / 8;

	if (pdf_salt->R == 2) {
		RC4_KEY arc4;

		pdf_compute_encryption_key(password, pwlen, key);
		RC4_set_key(&arc4, n, key);
		RC4(&arc4, 32, pdf_padding, output);
	}
	else if (pdf_salt->R == 3 || pdf_salt->R == 4) {
		unsigned char xor[32];
		unsigned char digest[16];
		MD5_CTX md5;
		RC4_KEY arc4;
		int i, x;

		pdf_compute_encryption_key(password, pwlen, key);
		MD5_Init(&md5);
		MD5_Update(&md5, (char*)pdf_padding, 32);
		MD5_Update(&md5, pdf_salt->id, pdf_salt->id_len);
		MD5_Final(digest, &md5);
		RC4_set_key(&arc4, n, key);
		RC4(&arc4, 16, digest, output);
		for (x = 1; x <= 19; x++) {
			for (i = 0; i < n; i++)
				xor[i] = key[i] ^ x;
			RC4_set_key(&arc4, n, xor);
			RC4(&arc4, 16, output, output);
		}
		//memcpy(output + 16, padding, 16);  /* pointless - we only test 16 bytes of it */
	}
	if (pdf_salt->R == 5) {
		pdf_compute_encryption_key_r5(password, pwlen, 0, output);
	}

	/* SumatraPDF: support crypt version 5 revision 6 */
	if (pdf_salt->R == 6)
		pdf_compute_hardened_hash_r6(password, pwlen, pdf_salt->u + 32,  NULL, output);

	/* RC4-40 has password collisions - might be good to know the key */
	if (!bench_or_test_running && pdf_salt->key_length == 40 && !memcmp(output, pdf_salt->u, 16)) {
		char h_key[2 * 5 + 1], *p;
		int i;

		p = &h_key[0];
		for (i = 0; i < 2 * n; i++)
			*p++ = itoa16[key[i >> 1] >> (4 * ((i & 0x1) ^ 1)) & 0xf];
		*p = 0;

		log_event("+ RC4 key: %s", h_key);
		if (options.verbosity > VERB_DEFAULT)
			fprintf(stderr, "+ RC4 key: %s\n", h_key);
	}
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void set_salt(void *salt)
{
	pdf_salt = (pdf_salt_type*)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_pdf_cracked) {
		memset(pdf_cracked, 0, pdf_cracked_size);
		any_pdf_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char output[32];
		pdf_compute_user_password((unsigned char*)saved_key[index], output);
		if (pdf_salt->R == 2 || pdf_salt->R == 5 || pdf_salt->R == 6)
			if (memcmp(output, pdf_salt->u, 32) == 0) {
				pdf_cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_pdf_cracked |= 1;
			}
		if (pdf_salt->R == 3 || pdf_salt->R == 4)
			if (memcmp(output, pdf_salt->u, 16) == 0) {
				pdf_cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_pdf_cracked |= 1;
			}
	}

	return count;
}

struct fmt_main fmt_pdf = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"revision",
			"key length"
		},
		{ FORMAT_TAG, FORMAT_TAG_OLD },
		pdf_tests
	},
	{
		init,
		done,
		fmt_default_reset,
		pdf_prepare,
		pdf_valid,
		fmt_default_split,
		fmt_default_binary,
		pdf_get_salt,
		{
			pdf_revision,
			pdf_keylen
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		pdf_cmp_all,
		pdf_cmp_one,
		pdf_cmp_exact
	}
};

#endif /* plugin stanza */
