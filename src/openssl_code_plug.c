#include "md5.h"
#include "sha.h"
#include "sha2.h"
#include "openssl_code.h"

void BytesToKey(int key_sz, hash_type h, const unsigned char *salt,
                       const unsigned char *data, int data_len, int count,
                       unsigned char *key, unsigned char *iv)
{
	const int key_len = key_sz / 8;
	const int iv_len = IV_LEN;
	const int tot_len = key_len + iv_len;
	int i;
	int size_made = 0;
	unsigned char out[128];
	unsigned char *last_out = out;

	if (h == md5) {
		const int hash_len = 16;
		MD5_CTX ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, data, data_len);
		MD5_Update(&ctx, salt, 8);
		MD5_Final(out, &ctx);
		for (i = 1; i < count; i++) {
			MD5_Init(&ctx);
			MD5_Update(&ctx, out, hash_len);
			MD5_Final(out, &ctx);
		}
		size_made += hash_len;
		while (size_made < tot_len) {
			MD5_Init(&ctx);
			MD5_Update(&ctx, last_out, hash_len);
			MD5_Update(&ctx, data, data_len);
			MD5_Update(&ctx, salt, 8);
			MD5_Final(&out[size_made], &ctx);
			for (i = 1; i < count; i++) {
				MD5_Init(&ctx);
				MD5_Update(&ctx, last_out, hash_len);
				MD5_Final(&out[size_made], &ctx);
			}
			last_out = &out[size_made];
			size_made += hash_len;
		}
	}
	else if (h == sha1) {
		const int hash_len = 20;
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, data, data_len);
		SHA1_Update(&ctx, salt, 8);
		SHA1_Final(out, &ctx);
		for (i = 1; i < count; i++) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, out, hash_len);
			SHA1_Final(out, &ctx);
		}
		size_made += hash_len;
		while (size_made < tot_len) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, last_out, hash_len);
			SHA1_Update(&ctx, data, data_len);
			SHA1_Update(&ctx, salt, 8);
			SHA1_Final(&out[size_made], &ctx);
			for (i = 1; i < count; i++) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, last_out, hash_len);
				SHA1_Final(&out[size_made], &ctx);
			}
			last_out = &out[size_made];
			size_made += hash_len;
		}
	}
	else if (h == sha256) {
		const int hash_len = 32;
		SHA256_CTX ctx;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, data, data_len);
		SHA256_Update(&ctx, salt, 8);
		SHA256_Final(out, &ctx);
		for (i = 1; i < count; i++) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, out, hash_len);
			SHA256_Final(out, &ctx);
		}
		size_made += hash_len;
		while (size_made < tot_len) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, last_out, hash_len);
			SHA256_Update(&ctx, data, data_len);
			SHA256_Update(&ctx, salt, 8);
			SHA256_Final(&out[size_made], &ctx);
			for (i = 1; i < count; i++) {
				SHA256_Init(&ctx);
				SHA256_Update(&ctx, last_out, hash_len);
				SHA256_Final(&out[size_made], &ctx);
			}
			last_out = &out[size_made];
			size_made += hash_len;
		}
	}

	memcpy(key, out, key_len);
	memcpy(iv, &out[key_len], IV_LEN);
}
