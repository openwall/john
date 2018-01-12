/*
 * Common code for the LibreOffice format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "libreoffice_common.h"
#include "johnswap.h"
#include <openssl/blowfish.h>
#include "sha.h"
#include "aes.h"
#define OPENCL_FORMAT
#include "pbkdf2_hmac_sha1.h"
#include "memdbg.h"

int libreoffice_valid(char *ciphertext, struct fmt_main *self, int is_cpu, int types)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* cipher type */
		goto err;
	if (strlen(p) != 1)
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ( !(types & 1) && res == 0)  /* sha1 type, but sha1 not wanted */
		goto err;
	if ( !(types & 2) && res == 1)  /* sha256 type, but sha1 not wanted */
		goto err;

	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum type */
		goto err;
	if (strlen(p) != 1)
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* key size */
		goto err;
	res = atoi(p);
	if (res != 16 && res != 32)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum field (skipped) */
		goto err;
	res = hexlenl(p, &extra);
	if (extra)
		goto err;
	if (res != 40 && res != 64) // 2 hash types (SHA-1 and SHA-256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv length */
		goto err;
	res = atoi(p);
	if (res > 16 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	res = atoi(p);
	if (res > 32 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* something (used for original_length from star office hashes) */
		goto err;
	res = atoi(p);
	if (res > 1024 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* content */
		goto err;
	res = strlen(p);
	if (res > 2048 || res & 1)
		goto err;
	if (!ishexlc(p))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *libreoffice_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$odf$*" */
	p = strtokm(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.key_size = atoi(p);
	strtokm(NULL, "*");
	/* skip checksum field */
	p = strtokm(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.original_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; p[i * 2] && i < 1024; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.content_length = i;
	if (cs.original_length == 0)
		cs.original_length = cs.content_length;
	MEM_FREE(keeptr);

	return (void *)&cs;
}

void *libreoffice_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[32+1];  // max(SHA-1, SHA-256)
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, type, len;
	char *ctcopy = strdup(ciphertext + FORMAT_TAG_LEN);

	memset(&buf, 0, sizeof(buf));
	p = strtokm(ctcopy, "*");
	type = atoi(p);
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	p = strtokm(NULL, "*");

	len = 20; // sha1
	if (type == 1)
		len = 32;
	for (i = 0; i < len; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(ctcopy);

	return out;
}

char *libreoffice_prepare(char *fields[10], struct fmt_main *self) {
	if (!strncmp(fields[1], "$sxc$*", 6)) {
		static char *buf = NULL;
		char *cp1, *cp2, *cp3;
		int i;
		if (!buf)
			buf = mem_alloc_tiny(3*1024, 4);
		cp1 = buf;
		cp2 = fields[1];
		cp2 += 6;
		strcpy(cp1, FORMAT_TAG);
		cp1 += strlen(FORMAT_TAG);
		cp3 = cp2;
		for (i = 0; i < 10; ++i) {
			cp3 = strchr(cp3, '*');
			++cp3;
		}
		strncpy(cp1, cp2, cp3-cp2);
		cp1 += cp3-cp2;
		cp3 = strchr(cp3, '*');
		cp3++;
		strcpy(cp1, cp3);
		return buf;
	}
	return fields[1];
}

int libre_common_cmp_exact(char *source, char *pass, struct custom_salt *cur_salt) {
	unsigned char key[32];
	unsigned char hash[32];
	unsigned char *binary;
	BF_KEY bf_key;
	int bf_ivec_pos;
	unsigned char ivec[16];
	unsigned char output[1024];
	unsigned int crypt[8];
	SHA_CTX ctx;

	binary = libreoffice_get_binary(source);

	if (cur_salt->checksum_type == 0 && cur_salt->cipher_type == 0) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char *)pass, strlen(pass));
		SHA1_Final(hash, &ctx);
		pbkdf2_sha1(hash, 20, cur_salt->salt,
				   cur_salt->salt_length,
				   cur_salt->iterations, key,
				   cur_salt->key_size, 0);
		bf_ivec_pos = 0;
		memcpy(ivec, cur_salt->iv, 8);
		BF_set_key(&bf_key, cur_salt->key_size, key);
		BF_cfb64_encrypt(cur_salt->content, output, cur_salt->content_length, &bf_key, ivec, &bf_ivec_pos, 0);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, output, cur_salt->original_length);
		SHA1_Final((unsigned char*)crypt, &ctx);
		if (!memcmp(crypt, binary, 20))
			return 1;
		// try the buggy version.
		if (cur_salt->original_length % 64 >= 52 && cur_salt->original_length % 64 <= 55) {
			SHA1_Libre_Buggy(output, cur_salt->original_length, crypt);
			if (!memcmp(crypt, binary, 20))
				return 1;
		}
	} else {
		SHA256_CTX ctx;
		AES_KEY akey;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (unsigned char *)pass, strlen(pass));
		SHA256_Final((unsigned char *)hash, &ctx);
		pbkdf2_sha1(hash, 32, cur_salt->salt, cur_salt->salt_length,
			    cur_salt->iterations, key, cur_salt->key_size, 0);
		memcpy(ivec, cur_salt->iv, 16);
		memset(&akey, 0, sizeof(AES_KEY));
		if (AES_set_decrypt_key(key, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed!\n");
		}
		AES_cbc_encrypt(cur_salt->content, output, cur_salt->content_length, &akey, ivec, AES_DECRYPT);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, output, cur_salt->content_length);
		SHA256_Final((unsigned char*)crypt, &ctx);
		if (!memcmp(crypt, binary, 32))
			return 1;
	}
	return 0;
}

/*
 * The format tests all have iteration count 1024.
 * Just in case the iteration count is tunable, let's report it.
 */
unsigned int libreoffice_iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->iterations;
}



typedef struct
{
    uint32_t st[5];
    uint32_t cnt;
    unsigned char buf[64];
} SHA1_CTX_buggy;

#define rol(n, bits) (((n) << (bits)) | ((n) >> (32 - (bits))))
#define W2(i) (W[i&15] = rol(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15],1))
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+W[i]+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+W2(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+W2(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+W2(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+W2(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

static void SHA1Hash_buggy(uint32_t st[5], const unsigned char buf[64]) {
	uint32_t a, b, c, d, e, W[16];

#if ARCH_LITTLE_ENDIAN
	uint32_t *p32 = (uint32_t*)buf;
	for (a = 0; a < 16; ++a)
		W[a] = JOHNSWAP(p32[a]);
#else
	memcpy((char*)W, buf, 64);
#endif

	a = st[0];
	b = st[1];
	c = st[2];
	d = st[3];
	e = st[4];
	R0(a, b, c, d, e, 0);
	R0(e, a, b, c, d, 1);
	R0(d, e, a, b, c, 2);
	R0(c, d, e, a, b, 3);
	R0(b, c, d, e, a, 4);
	R0(a, b, c, d, e, 5);
	R0(e, a, b, c, d, 6);
	R0(d, e, a, b, c, 7);
	R0(c, d, e, a, b, 8);
	R0(b, c, d, e, a, 9);
	R0(a, b, c, d, e, 10);
	R0(e, a, b, c, d, 11);
	R0(d, e, a, b, c, 12);
	R0(c, d, e, a, b, 13);
	R0(b, c, d, e, a, 14);
	R0(a, b, c, d, e, 15);
	R1(e, a, b, c, d, 16);
	R1(d, e, a, b, c, 17);
	R1(c, d, e, a, b, 18);
	R1(b, c, d, e, a, 19);
	R2(a, b, c, d, e, 20);
	R2(e, a, b, c, d, 21);
	R2(d, e, a, b, c, 22);
	R2(c, d, e, a, b, 23);
	R2(b, c, d, e, a, 24);
	R2(a, b, c, d, e, 25);
	R2(e, a, b, c, d, 26);
	R2(d, e, a, b, c, 27);
	R2(c, d, e, a, b, 28);
	R2(b, c, d, e, a, 29);
	R2(a, b, c, d, e, 30);
	R2(e, a, b, c, d, 31);
	R2(d, e, a, b, c, 32);
	R2(c, d, e, a, b, 33);
	R2(b, c, d, e, a, 34);
	R2(a, b, c, d, e, 35);
	R2(e, a, b, c, d, 36);
	R2(d, e, a, b, c, 37);
	R2(c, d, e, a, b, 38);
	R2(b, c, d, e, a, 39);
	R3(a, b, c, d, e, 40);
	R3(e, a, b, c, d, 41);
	R3(d, e, a, b, c, 42);
	R3(c, d, e, a, b, 43);
	R3(b, c, d, e, a, 44);
	R3(a, b, c, d, e, 45);
	R3(e, a, b, c, d, 46);
	R3(d, e, a, b, c, 47);
	R3(c, d, e, a, b, 48);
	R3(b, c, d, e, a, 49);
	R3(a, b, c, d, e, 50);
	R3(e, a, b, c, d, 51);
	R3(d, e, a, b, c, 52);
	R3(c, d, e, a, b, 53);
	R3(b, c, d, e, a, 54);
	R3(a, b, c, d, e, 55);
	R3(e, a, b, c, d, 56);
	R3(d, e, a, b, c, 57);
	R3(c, d, e, a, b, 58);
	R3(b, c, d, e, a, 59);
	R4(a, b, c, d, e, 60);
	R4(e, a, b, c, d, 61);
	R4(d, e, a, b, c, 62);
	R4(c, d, e, a, b, 63);
	R4(b, c, d, e, a, 64);
	R4(a, b, c, d, e, 65);
	R4(e, a, b, c, d, 66);
	R4(d, e, a, b, c, 67);
	R4(c, d, e, a, b, 68);
	R4(b, c, d, e, a, 69);
	R4(a, b, c, d, e, 70);
	R4(e, a, b, c, d, 71);
	R4(d, e, a, b, c, 72);
	R4(c, d, e, a, b, 73);
	R4(b, c, d, e, a, 74);
	R4(a, b, c, d, e, 75);
	R4(e, a, b, c, d, 76);
	R4(d, e, a, b, c, 77);
	R4(c, d, e, a, b, 78);
	R4(b, c, d, e, a, 79);
	st[0] += a;
	st[1] += b;
	st[2] += c;
	st[3] += d;
	st[4] += e;
}

static void SHA1Init_buggy(SHA1_CTX_buggy *ctx) {
	ctx->st[0] = 0x67452301;
	ctx->st[1] = 0xEFCDAB89;
	ctx->st[2] = 0x98BADCFE;
	ctx->st[3] = 0x10325476;
	ctx->st[4] = 0xC3D2E1F0;
	ctx->cnt = 0;
}

static void SHA1Update_buggy(SHA1_CTX_buggy *ctx, const unsigned char *data, uint32_t len) {
	uint32_t i;
	uint32_t j;

	j = (ctx->cnt&63);
	ctx->cnt += len;
	if ((j + len) > 63) {
		memcpy(&ctx->buf[j], data, (i = 64 - j));
		SHA1Hash_buggy(ctx->st, ctx->buf);
		for (; i + 63 < len; i += 64)
			SHA1Hash_buggy(ctx->st, &data[i]);
		j = 0;
	}
	else
		i = 0;
	memcpy(&ctx->buf[j], &data[i], len - i);
}

static void SHA1Final_buggy(unsigned char digest[20], SHA1_CTX_buggy *ctx) {
	unsigned i;
	int LibreOffice_bug = 0;
	const unsigned char *pad = (unsigned char*)"\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	uint32_t bits = ctx->cnt<<3;

	if ((ctx->cnt & 63) >= 52 && (ctx->cnt & 63) <= 55) {
		LibreOffice_bug = 1;
	}

	i = ctx->cnt&63;
	if (i < 56) {
		SHA1Update_buggy(ctx, pad, 60-i);
	} else {
		SHA1Update_buggy(ctx, pad, 64-i);
		SHA1Update_buggy(ctx, &pad[4], 60);
	}
	if (LibreOffice_bug)
		SHA1Update_buggy(ctx, &pad[4], 64);

#if ARCH_LITTLE_ENDIAN
	bits = JOHNSWAP(bits);
#endif
	SHA1Update_buggy(ctx, (unsigned char*)&bits, 4);
	for (i = 0; i < 20; i++)
	{
		digest[i] = (unsigned char)
			((ctx->st[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
}

// mimic bug in Star/Libre office SHA1. Needed for any string of length 52 to 55 mod(64)
void SHA1_Libre_Buggy(unsigned char *data, int len, uint32_t results[5]) {
	SHA1_CTX_buggy ctx;
	SHA1Init_buggy(&ctx);
	SHA1Update_buggy(&ctx, data, len);
	SHA1Final_buggy((unsigned char*)results, &ctx);
}
