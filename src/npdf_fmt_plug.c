/* PDF cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Uses code from Sumatra PDF and MuPDF which are under GPL */

#include <string.h>
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "md5.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include <openssl/aes.h>
#include "sha2.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL        "npdf"
#define FORMAT_NAME         "PDF MD5 SHA-2 RC4 / AES"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1000
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#if defined (_OPENMP)
static int omp_t = 1;
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static struct custom_salt {
	int V;
	int R;
	int P;
	char encrypt_metadata;
	unsigned char u[127];
	unsigned char o[127];
	unsigned char ue[32];
	unsigned char oe[32];
	unsigned char id[32];
	int length;
	int length_id;
	int length_u;
	int length_o;
	int length_ue;
	int length_oe;
} *crypt;

static struct fmt_tests npdf_tests[] = {
	{"$npdf$4*4*128*-1028*1*16*e03460febe17a048b0adc7f7631bcc56*32*3456205208ad52066d5604018d498a6400000000000000000000000000000000*32*6d598152b22f8fa8085b19a866dce1317f645788a065a74831588a739a579ac4", "openwall"},
	{"$npdf$2*3*128*-4*1*16*34b1b6e593787af681a9b63fa8bf563b*32*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*32*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f", "test"},
	{"$npdf$4*4*128*-1028*1*16*c015cff8dbf99345ac91c84a45667784*32*0231a4c9cae29b53892874e168cfae9600000000000000000000000000000000*32*137ad7063db5114a66ce1900d47e5cab9c5d7053487d92ac978f54db86eca393", "testpassword"},
	{"$npdf$5*6*256*-1028*1*16*05e5abeb21ad2e47adac1c2b2c7b7a31*127*51d3a6a09a675503383e5bc0b53da77ec5d5ea1d1998fb94e00a02a1c2e49313c177905272a4e8e68b382254ec8ed74800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*dc38f01ef129aae2fca847396465ed518f9c7cf4f2c8cb4399a849d0fe9110227739ab88ddc9a6cf388ae11941270af500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*b8e137baf316e0789ffa73f888d26495c14d31f2cfff3799e339e2fa078649f5*32*835a9e07461992791914c3d62d37493e07d140937529ab43e26ac2a657152c3c", "testpassword"},
	{"$npdf$5*5*256*-1028*1*16*762896ef582ca042a15f380c63ab9f2c*127*8713e2afdb65df1d3801f77a4c4da4905c49495e7103afc2deb06d9fba7949a565143288823871270d9d882075a75da600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*15d0b992974ff80529e4b616b8c4c79d787705b6c8a9e0f85446498ae2432e0027d8406b57f78b60b11341a0757d7c4a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*a7a0f3891b469ba7261ce04752dad9c6de0db9c4155c4180e721938a7d9666c7*32*2fa9a0c52badebae2c19dfa7b0005a9cfc909b92babbe7db66a794e96a9f91e3", "openwall"},
	{NULL}
};

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$npdf$", 6);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 6;	/* skip over "$npdf$" marker */
	p = strtok(ctcopy, "*");
	cs.V = atoi(p);
	p = strtok(NULL, "*");
	cs.R = atoi(p);
	p = strtok(NULL, "*");
	cs.length = atoi(p);
	p = strtok(NULL, "*");
	cs.P = atoi(p);
	p = strtok(NULL, "*");
	cs.encrypt_metadata = atoi(p);
	p = strtok(NULL, "*");
	cs.length_id = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.length_id; i++)
		cs.id[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.length_u = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.length_u; i++)
		cs.u[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.length_o = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.length_o; i++)
		cs.o[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	crypt = (struct custom_salt *)salt;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

static void npdf_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}


static const unsigned char padding[32] =
{
        0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
        0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
        0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
        0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
};


/* Compute an encryption key (PDF 1.7 algorithm 3.2) */
static void
pdf_compute_encryption_key(unsigned char *password, int pwlen, unsigned char *key)
{
        unsigned char buf[32];
        unsigned int p;
        int n;
        MD5_CTX md5;

        n = crypt->length / 8;

        /* Step 1 - copy and pad password string */
        if (pwlen > 32)
                pwlen = 32;
        memcpy(buf, password, pwlen);
        memcpy(buf + pwlen, padding, 32 - pwlen);

        /* Step 2 - init md5 and pass value of step 1 */
        MD5_Init(&md5);
        MD5_Update(&md5, buf, 32);

        /* Step 3 - pass O value */
        MD5_Update(&md5, crypt->o, 32);


	/* Step 4 - pass P value as unsigned int, low-order byte first */
        p = (unsigned int) crypt->P;
        buf[0] = (p) & 0xFF;
        buf[1] = (p >> 8) & 0xFF;
        buf[2] = (p >> 16) & 0xFF;
        buf[3] = (p >> 24) & 0xFF;
        MD5_Update(&md5, buf, 4);

        /* Step 5 - pass first element of ID array */
        MD5_Update(&md5, crypt->id, crypt->length_id);

        /* Step 6 (revision 4 or greater) - if metadata is not encrypted pass 0xFFFFFFFF */
        if (crypt->R >= 4)
        {
                if (!crypt->encrypt_metadata)
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
        if (crypt->R >= 3)
        {
                /* for (i = 0; i < 50; i++)
                {
                        MD5_Init(&md5);
                        MD5_Update(&md5, buf, n);
                        MD5_Final(buf, &md5);
		} */

		md5_50(buf);
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
                memcpy(buffer + pwlen, crypt->o + 32, 8);
                memcpy(buffer + pwlen + 8, crypt->u, 48);
        }
        else
                memcpy(buffer + pwlen, crypt->u + 32, 8);

        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buffer, pwlen + 8 + (ownerkey ? 48 : 0));
        SHA256_Final(validationkey, &sha256);
}

/* SumatraPDF: support crypt version 5 revision 6 */
/*
 * Compute an encryption key (PDF 1.7 ExtensionLevel 8 algorithm 3.2b)
 * http://esec-lab.sogeti.com/post/The-undocumented-password-validation-algorithm-of-Adobe-Reader-X
 */

static void
pdf_compute_hardened_hash_r6(unsigned char *password, int pwlen, unsigned char salt[8],
        unsigned char *ownerkey, unsigned char hash[32])
{
        unsigned char data[(128 + 64 + 48) * 64];
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
                memcpy(data + pwlen + block_size, ownerkey, ownerkey ? 48 : 0);
                data_len = pwlen + block_size + (ownerkey ? 48 : 0);
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

        memset(data, 0, sizeof(data));
        memcpy(hash, block, 32);
}




/* Computing the user password (PDF 1.7 algorithm 3.4 and 3.5) */

static void pdf_compute_user_password(unsigned char *password,  unsigned char *output)
{

	int pwlen = strlen((char*)password);
	unsigned char key[128];

	if (crypt->R == 2) {
		RC4_KEY arc4;
		int n;
                n = crypt->length / 8;
                pdf_compute_encryption_key(password, pwlen, key);
		RC4_set_key(&arc4, n, key);
		RC4(&arc4, 32, padding, output);
	}

	if (crypt->R == 3 || crypt->R == 4)
        {
                unsigned char xor[32];
                unsigned char digest[16];
                MD5_CTX md5;
		RC4_KEY arc4;
                int i, x, n;
                n = crypt->length / 8;
                pdf_compute_encryption_key(password, pwlen, key);
                MD5_Init(&md5);
                MD5_Update(&md5, (char*)padding, 32);
        	MD5_Update(&md5, crypt->id, crypt->length_id);
                MD5_Final(digest, &md5);
		RC4_set_key(&arc4, n, key);
		RC4(&arc4, 16, digest, output);
                for (x = 1; x <= 19; x++)
                {
                        for (i = 0; i < n; i++)
                                xor[i] = key[i] ^ x;
			RC4_set_key(&arc4, n, xor);
			RC4(&arc4, 16, output, output);
                }
                memcpy(output + 16, padding, 16);
        }
	if (crypt->R == 5) {
		pdf_compute_encryption_key_r5(password, pwlen, 0, output);
	}

	/* SumatraPDF: support crypt version 5 revision 6 */
        if (crypt->R == 6)
		pdf_compute_hardened_hash_r6(password, pwlen, crypt->u + 32,  NULL, output);
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char output[32];
		pdf_compute_user_password((unsigned char*)saved_key[index], output);
		if (crypt->R == 2 || crypt->R == 5 || crypt->R == 6)
			if(memcmp(output, crypt->u, 32) == 0)
				any_cracked = cracked[index] = 1;
		if (crypt->R == 3 || crypt->R == 4)
			if(memcmp(output, crypt->u, 16) == 0)
				any_cracked = cracked[index] = 1;
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

struct fmt_main fmt_npdf = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		npdf_tests
	},
	{
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		npdf_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
