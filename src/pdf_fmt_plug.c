/* PDF cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Uses code from Sumatra PDF and MuPDF which are under GPL.
 *
 * Edited by Shane Quigley in 2013.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pdf;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pdf);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "md5.h"
#include "aes.h"
#include "sha2.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include "loader.h"

#define FORMAT_LABEL        "PDF"
#define FORMAT_NAME         ""
#define FORMAT_TAG          "$pdf$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG_OLD      "$pdf$Standard*"
#define FORMAT_TAG_OLD_LEN  (sizeof(FORMAT_TAG_OLD)-1)
#define ALGORITHM_NAME      "MD5 SHA2 RC4/AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x507
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN        1
#define SALT_ALIGN          sizeof(int)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  4

#ifndef OMP_SCALE
#define OMP_SCALE           8 // Tuned w/ MKPC for core i7
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
	unsigned char id[128];
	int length;
	int length_id;
	int length_u;
	int length_o;
	int length_ue;
	int length_oe;
} *crypt_out;

static struct fmt_tests pdf_tests[] = {
	{"$pdf$4*4*128*-1028*1*16*e03460febe17a048b0adc7f7631bcc56*32*3456205208ad52066d5604018d498a6400000000000000000000000000000000*32*6d598152b22f8fa8085b19a866dce1317f645788a065a74831588a739a579ac4", "openwall"},
	{"$pdf$2*3*128*-4*1*16*34b1b6e593787af681a9b63fa8bf563b*32*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*32*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f", "test"},
	{"$pdf$4*4*128*-1028*1*16*c015cff8dbf99345ac91c84a45667784*32*0231a4c9cae29b53892874e168cfae9600000000000000000000000000000000*32*137ad7063db5114a66ce1900d47e5cab9c5d7053487d92ac978f54db86eca393", "testpassword"},
	{"$pdf$5*6*256*-1028*1*16*05e5abeb21ad2e47adac1c2b2c7b7a31*127*51d3a6a09a675503383e5bc0b53da77ec5d5ea1d1998fb94e00a02a1c2e49313c177905272a4e8e68b382254ec8ed74800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*dc38f01ef129aae2fca847396465ed518f9c7cf4f2c8cb4399a849d0fe9110227739ab88ddc9a6cf388ae11941270af500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*b8e137baf316e0789ffa73f888d26495c14d31f2cfff3799e339e2fa078649f5*32*835a9e07461992791914c3d62d37493e07d140937529ab43e26ac2a657152c3c", "testpassword"},
	{"$pdf$5*5*256*-1028*1*16*762896ef582ca042a15f380c63ab9f2c*127*8713e2afdb65df1d3801f77a4c4da4905c49495e7103afc2deb06d9fba7949a565143288823871270d9d882075a75da600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*15d0b992974ff80529e4b616b8c4c79d787705b6c8a9e0f85446498ae2432e0027d8406b57f78b60b11341a0757d7c4a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*a7a0f3891b469ba7261ce04752dad9c6de0db9c4155c4180e721938a7d9666c7*32*2fa9a0c52badebae2c19dfa7b0005a9cfc909b92babbe7db66a794e96a9f91e3", "openwall"},
	/* following are old-style hashes */
	{"$pdf$Standard*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*16*34b1b6e593787af681a9b63fa8bf563b*1*1*0*1*4*128*-4*3*2", "test"},
	{"$pdf$Standard*9a1156c38ab8177598d1608df7d7e340ae639679bd66bc4cda9bc9a4eedeb170*1f300cd939dd5cf0920c787f12d16be22205e55a5bec5c9c6d563ab4fd0770d7*16*c015cff8dbf99345ac91c84a45667784*1*1*0*1*6*40*-4*2*1", "testpassword"},
	{"$pdf$Standard*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499*bf38d7a59daaf38365a338e1fc07976102f1dfd6bdb52072032f57920109b43a*16*c56bbc4145d25b468a873618cd71c2d3*1*1*0*1*6*40*-4*2*1", "test"},
	{"$pdf$Standard*137ad7063db5114a66ce1900d47e5cab9c5d7053487d92ac978f54db86eca393*0231a4c9cae29b53892874e168cfae9600000000000000000000000000000000*16*c015cff8dbf99345ac91c84a45667784*1*1*0*1*6*128*-1028*3*2", "testpassword"},
	{"$pdf$Standard*d83a8ab680f144dfb2ff2334c206a6060779e007701ab881767f961aecda7984*a5ed4de7e078cb75dfdcd63e8da7a25800000000000000000000000000000000*16*06a7f710cf8dfafbd394540d40984ae2*1*1*0*1*4*128*-1028*3*2", "July2099"},
	{"$pdf$Standard*6a80a547b8b8b7636fcc5b322f1c63ce4b670c9b01f2aace09e48d85e1f19f83*e64eb62fc46be66e33571d50a29b464100000000000000000000000000000000*16*14a8c53ffa4a79b3ed9421ef15618420*1*1*0*1*4*128*-1028*3*2", "38r285a9"},
	{"$pdf$Standard*2446dd5ed2e18b3ce1ac9b56733226018e3f5c2639051eb1c9b2b215b30bc820*fa3af175d761963c8449ee7015b7770800000000000000000000000000000000*16*12a4da1abe6b7a1ceb84610bad87236d*1*1*0*1*4*128*-1028*3*2", "WHATwhatWHERE?"},
	{"$pdf$Standard*e600ecc20288ad8b0d64a929c6a83ee2517679aa0218beceea8b7986726a8cdb*38aca54678d67c003a8193381b0fa1cc101112131415161718191a1b1c1d1e1f*16*1521fbe61419fcad51878cc5d478d5ff*1*1*0*1*4*128*-3904*3*2", ""},
	/* CMIYC 2013 "pro" hashes */
	{"$pdf$4*4*128*-4*1*16*f7bc2744e1652cf61ca83cac8fccb535*32*f55cc5032f04b985c5aeacde5ec4270f0122456a91bae5134273a6db134c87c4*32*785d891cdcb5efa59893c78f37e7b75acef8924951039b4fa13f62d92bb3b660", "L4sV3g4z"},
	{"$pdf$4*4*128*-4*1*16*ec8ea2af2977db1faa4a955904dc956f*32*fc413edb049720b1f8eac87a358faa740122456a91bae5134273a6db134c87c4*32*1ba7aed2f19c77ac6b5061230b62e80b48fc42918f92aef689ceb07d26204991", "ZZt0pr0x"},
	{"$pdf$4*4*128*-4*1*16*56761d6da774d8d47387dccf1a84428c*32*640782cab5b7c8f6cf5eab82c38016540122456a91bae5134273a6db134c87c4*32*b5720d5f3d9675a280c6bb8050cbb169e039b578b2de4a42a40dc14765e064cf", "24Le`m0ns"},
	/* This hash exposed a problem with our length_id check */
	{"$pdf$1*2*40*-4*1*36*65623237393831382d636439372d343130332d613835372d343164303037316639386134*32*c7230519f7db63ab1676fa30686428f0f997932bf831f1c1dcfa48cfb3b7fe99*32*161cd2f7c95283ca9db930b36aad3571ee6f5fb5632f30dc790e19c5069c86b8", "vision"},
	/* This hash has unsigned permission value, and an id length of 0 */
	{"$pdf$1*2*40*4294967239*1*0**32*585e4cc4113bbd8ff4012dce92dd7df1e1216fb630b29cf5aeea10a820066c26*32*b1db56a883cab5a22dd5fc390618a0f8e16cab8af14e67ccba5f90837aac898b", "123456"},
	{NULL}
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	char *p;
	int res;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* V */
		goto err;
	if (!isdec(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* R */
		goto err;
	if (!isdec(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* P */
		goto err;
	/* Somehow this can be signed or unsigned int; -2147483648 .. 4294967295 */
	if (!isdec_negok(p) && !isdecu(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* encrypt_metadata */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length_id */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 128)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* id */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	/* id length can be 0 */
	if (*p && !ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length_u */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 127)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* u */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* length_o */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 127)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* o */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static int old_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG_OLD, FORMAT_TAG_OLD_LEN))
		return 0;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_OLD_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* o_string */
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* u_string */
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* fileIDLen */
		goto error;
	if (strncmp(ptr, "16", 2))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* fileID */
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* encryptMetaData */
		goto error;
	res = atoi(ptr);
	if (res != 0 && res != 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* work_with_user */
		goto error;
	res = atoi(ptr);
	if (res != 0 && res != 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* have_userpassword */
		goto error;
	res = atoi(ptr);
	if (res != 0 && res != 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* version_major */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* version_minor */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* length */
		goto error;
	res = atoi(ptr);
	if (res < 0 || res > 256)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* permissions */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* revision */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* version */
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

char * convert_old_to_new(char ciphertext[])
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *out = mem_alloc_tiny(strlen(ctcopy), MEM_ALIGN_NONE);
	const char *fields[14];
	char *p;
	int c = 0;
	p = strtokm(ctcopy, "*");
	for (c = 0; c < 14; c++) {
		fields[c] = p;
		p = strtokm(NULL, "*");
	}
	strcpy(out,FORMAT_TAG);
	strcat(out,fields[13]);
	strcat(out,"*");
	strcat(out,fields[12]);
	strcat(out,"*");
	strcat(out,fields[10]);
	strcat(out,"*");
	strcat(out,fields[11]);
	strcat(out,"*");
	strcat(out,fields[5]);
	strcat(out,"*");
	strcat(out,fields[3]);
	strcat(out,"*");
	strcat(out,fields[4]);
	strcat(out,"*32*");
	strcat(out,fields[2]);
	strcat(out,"*32*");
	strcat(out,fields[1]);
	MEM_FREE(keeptr);
	return out;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	// Convert old format to new one
	if (!strncmp(split_fields[1], FORMAT_TAG_OLD, FORMAT_TAG_OLD_LEN) &&
	    old_valid(split_fields[1], self))
		return convert_old_to_new(split_fields[1]);

	return split_fields[1];
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$pdf$" marker */
	p = strtokm(ctcopy, "*");
	cs.V = atoi(p);
	p = strtokm(NULL, "*");
	cs.R = atoi(p);
	p = strtokm(NULL, "*");
	cs.length = atoi(p);
	p = strtokm(NULL, "*");
	cs.P = atoi(p);
	p = strtokm(NULL, "*");
	cs.encrypt_metadata = atoi(p);
	p = strtokm(NULL, "*");
	cs.length_id = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length_id; i++)
		cs.id[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.length_u = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length_u; i++)
		cs.u[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.length_o = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.length_o; i++)
		cs.o[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	crypt_out = (struct custom_salt *)salt;
}

static void pdf_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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

        n = crypt_out->length / 8;

        /* Step 1 - copy and pad password string */
        if (pwlen > 32)
                pwlen = 32;
        memcpy(buf, password, pwlen);
        memcpy(buf + pwlen, padding, 32 - pwlen);

        /* Step 2 - init md5 and pass value of step 1 */
        MD5_Init(&md5);
        MD5_Update(&md5, buf, 32);

        /* Step 3 - pass O value */
        MD5_Update(&md5, crypt_out->o, 32);

        /* Step 4 - pass P value as unsigned int, low-order byte first */
        p = (unsigned int) crypt_out->P;
        buf[0] = (p) & 0xFF;
        buf[1] = (p >> 8) & 0xFF;
        buf[2] = (p >> 16) & 0xFF;
        buf[3] = (p >> 24) & 0xFF;
        MD5_Update(&md5, buf, 4);

        /* Step 5 - pass first element of ID array */
        MD5_Update(&md5, crypt_out->id, crypt_out->length_id);

        /* Step 6 (revision 4 or greater) - if metadata is not encrypted pass 0xFFFFFFFF */
        if (crypt_out->R >= 4)
        {
                if (!crypt_out->encrypt_metadata)
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
        if (crypt_out->R >= 3)
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
                memcpy(buffer + pwlen, crypt_out->o + 32, 8);
                memcpy(buffer + pwlen + 8, crypt_out->u, 48);
        }
        else
                memcpy(buffer + pwlen, crypt_out->u + 32, 8);

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
                // ownerkey is always NULL
                // memcpy(data + pwlen + block_size, ownerkey, ownerkey ? 48 : 0);
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

	if (crypt_out->R == 2) {
		RC4_KEY arc4;
		int n;
		n = crypt_out->length / 8;
		pdf_compute_encryption_key(password, pwlen, key);
		RC4_set_key(&arc4, n, key);
		RC4(&arc4, 32, padding, output);
	}

	if (crypt_out->R == 3 || crypt_out->R == 4) {
		unsigned char xor[32];
		unsigned char digest[16];
		MD5_CTX md5;
		RC4_KEY arc4;
		int i, x, n;
		n = crypt_out->length / 8;
		pdf_compute_encryption_key(password, pwlen, key);
		MD5_Init(&md5);
		MD5_Update(&md5, (char*)padding, 32);
		MD5_Update(&md5, crypt_out->id, crypt_out->length_id);
		MD5_Final(digest, &md5);
		RC4_set_key(&arc4, n, key);
		RC4(&arc4, 16, digest, output);
		for (x = 1; x <= 19; x++) {
			for (i = 0; i < n; i++)
				xor[i] = key[i] ^ x;
			RC4_set_key(&arc4, n, xor);
			RC4(&arc4, 16, output, output);
		}
		memcpy(output + 16, padding, 16);
	}
	if (crypt_out->R == 5) {
		pdf_compute_encryption_key_r5(password, pwlen, 0, output);
	}

	/* SumatraPDF: support crypt version 5 revision 6 */
	if (crypt_out->R == 6)
		pdf_compute_hardened_hash_r6(password, pwlen, crypt_out->u + 32,  NULL, output);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char output[32];
		pdf_compute_user_password((unsigned char*)saved_key[index], output);
		if (crypt_out->R == 2 || crypt_out->R == 5 || crypt_out->R == 6)
			if (memcmp(output, crypt_out->u, 32) == 0) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		if (crypt_out->R == 3 || crypt_out->R == 4)
			if (memcmp(output, crypt_out->u, 16) == 0) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
	}

	return count;
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

/*
 * Report revision as tunable cost, since between revisions 2 and 6,
 * only revisions 3 and 4 seem to have a similar c/s rate.
 */
static unsigned int pdf_revision(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->R;
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
		},
		{ FORMAT_TAG, FORMAT_TAG_OLD },
		pdf_tests
	},
	{
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			pdf_revision,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		pdf_set_key,
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

#endif /* plugin stanza */
