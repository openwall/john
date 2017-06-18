#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_ctx.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

// input
typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pfx_password;

// output
typedef struct {
	uint8_t v[20];
} pfx_hash;

// input
typedef struct {
	uint32_t iterations;
	uint32_t keylen;
	uint32_t saltlen;
	uint8_t salt[20];
} pfx_salt;

#define PKCS12_MAX_PWDLEN 128

void pkcs12_fill_buffer(unsigned char *data, size_t data_len, const unsigned char *filler, size_t fill_len)
{
	unsigned char *p = data;
	size_t use_len;
	int i;

	while (data_len > 0) {
		use_len = (data_len > fill_len) ? fill_len : data_len;
		// memcpy(p, filler, use_len);
		for (i = 0; i < use_len; i++)
			p[i] = filler[i];
		p += use_len;
		data_len -= use_len;
	}
}

int pkcs12_pbe_derive_key(int iterations, int id, const unsigned
		char *pwd, size_t pwdlen, const unsigned char *salt,
		size_t saltlen, unsigned char *key, size_t keylen)
{
	size_t i;
	unsigned char unipwd[PKCS12_MAX_PWDLEN * 2 + 2], *cp = unipwd;

	for (i = 0; i < pwdlen; i++) {
		*cp++ = 0;
		*cp++ = pwd[i];
	}
	*cp++ = 0;
	*cp = 0;

	// mbedtls_pkcs12_derivation(key, keylen, unipwd, pwdlen * 2 + 2, salt, saltlen, md_type, id, iterations);
	// static int mbedtls_pkcs12_derivation( unsigned char *data, size_t datalen, const unsigned char *pwd, size_t pwdlen, const unsigned char *salt, size_t saltlen, int md_type, int id, int iterations)
	pwdlen =  pwdlen * 2 + 2;
	pwd = unipwd;

	unsigned int j, k;
	unsigned char diversifier[128];
	unsigned char salt_block[128], pwd_block[128], hash_block[128];
	unsigned char hash_output[1024];
	unsigned char *p;
	unsigned char c;
	size_t hlen, use_len, v, v2, datalen;
	SHA_CTX md_ctx;

	hlen = 20;	// for SHA1
	v = 64;
	v2 = ((pwdlen+64)/64)*64;

	// memset(diversifier, (unsigned char)id, v);
	for (k = 0; k < v; k++)
		diversifier[k] = (unsigned char)id;

	pkcs12_fill_buffer(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer(pwd_block,  v2, pwd,  pwdlen);

	p = key; // data
	datalen = keylen;
	while (datalen > 0) {
		// Calculate hash(diversifier || salt_block || pwd_block)
		SHA1_Init(&md_ctx);
		SHA1_Update(&md_ctx, diversifier, v);
		SHA1_Update(&md_ctx, salt_block, v);
		SHA1_Update(&md_ctx, pwd_block, v2);
		SHA1_Final(hash_output, &md_ctx);
		// Perform remaining (iterations - 1) recursive hash calculations
		for (i = 1; i < (size_t) iterations; i++) {
			SHA1_Init(&md_ctx);
			SHA1_Update(&md_ctx, hash_output, hlen);
			SHA1_Final(hash_output, &md_ctx);
		}

		use_len = (datalen > hlen) ? hlen : datalen;
		// memcpy(p, hash_output, use_len);
		for (k = 0; k < use_len; k++)
			p[k] = hash_output[k];

		datalen -= use_len;
		p += use_len;

		if (datalen == 0)
			break;

		// Concatenating copies of hash_output into hash_block (B)
		pkcs12_fill_buffer(hash_block, v, hash_output, hlen);

		// B += 1
		for (i = v; i > 0; i--)
			if (++hash_block[i - 1] != 0)
				break;

		// salt_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = salt_block[i - 1] + hash_block[i - 1] + c;
			c = (unsigned char)(j >> 8);
			salt_block[i - 1] = j & 0xFF;
		}

		// pwd_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = pwd_block[i - 1] + hash_block[i - 1] + c;
			c = (unsigned char)(j >> 8);
			pwd_block[i - 1] = j & 0xFF;
		}
	}

	return 0;
}

void pfx_crypt(__global const uchar *password, uint32_t password_length,
		__constant const uchar *salt, uint32_t saltlen,
		uint iterations, __global uchar *key, uint keylen)
{
	int i;
	uint8_t csalt[20];
	uint8_t cpassword[PLAINTEXT_LENGTH];
	uint8_t ckey[32];

	for (i = 0; i < password_length; i++)
		cpassword[i] = password[i];

	for (i = 0; i < saltlen; i++)
		csalt[i] = salt[i];

	pkcs12_pbe_derive_key(iterations, 3, cpassword, password_length, csalt, saltlen, ckey, keylen);

	for (i = 0; i < keylen; i++)
		key[i] = ckey[i];
}

__kernel void pfx(__global const pfx_password *inbuffer,
		__global pfx_hash *outbuffer,
		__constant pfx_salt *salt)
{
	uint idx = get_global_id(0);

	pfx_crypt(inbuffer[idx].v, inbuffer[idx].length, salt->salt, salt->saltlen, salt->iterations, outbuffer[idx].v, salt->keylen);
}
