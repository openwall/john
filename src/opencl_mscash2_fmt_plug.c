/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * with added proper Unicode support and other fixes (c) 2013 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_mscash2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_mscash2);
#else

#include "formats.h"
#include "common.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include "md4.h"
#include "sha.h"
#include "unicode.h"
#include "opencl_mscash2_helper_plug.h"
#include "loader.h"
#include "config.h"
#include "mscash_common.h"


#define SQRT_2                      0x5a827999
#define SQRT_3                      0x6ed9eba1

#define FORMAT_NAME		   "MS Cache Hash 2 (DCC2)"
#define KERNEL_NAME		   "PBKDF2"
#define ALGORITHM_NAME		   "PBKDF2-SHA1 OpenCL"
#define MAX_PLAINTEXT_LENGTH      125

#define MAX_KEYS_PER_CRYPT        1
#define MIN_KEYS_PER_CRYPT        1

#define GPU_BINARY_SIZE           4
#define SALT_SIZE                 sizeof(ms_cash2_salt)

 #define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

typedef struct {
	unsigned int 	length ;
	unsigned int 	iter_cnt;
	unsigned char 	username[MAX_SALT_LENGTH * 3 + 1] ;
} ms_cash2_salt ;

static cl_uint 		*dcc_hash_host ;
static cl_uint 		*dcc2_hash_host ;
static unsigned int    initialized;
static unsigned char 	(*key_host)[MAX_PLAINTEXT_LENGTH + 1] ;
static ms_cash2_salt 	currentsalt ;
static cl_uint          *hmac_sha1_out ;
static struct fmt_main  *self = NULL;

static void set_key(char*, int) ;

static void init(struct fmt_main *__self)
{
	//Prepare OpenCL environment.
	opencl_load_environment();

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(FORMAT_LABEL);

	initNumDevices();

	mscash2_adjust_tests(options.target_enc, __self->params.plaintext_length, MAX_SALT_LENGTH);
	if (options.target_enc == UTF_8) {
		__self->params.plaintext_length *= 3;
		if (__self->params.plaintext_length > 125)
			__self->params.plaintext_length = 125;
	}

	self = __self;
}

static void reset(struct db_main *db)
{
	if (!initialized) {
		unsigned int i;
		self->params.max_keys_per_crypt = 0;

		for ( i=0; i < get_number_of_devices_in_use(); i++)
			self->params.max_keys_per_crypt += selectDevice(engaged_devices[i], self);

		///Allocate memory
		key_host = mem_calloc(self->params.max_keys_per_crypt, sizeof(*key_host));
		dcc_hash_host = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * self->params.max_keys_per_crypt);
		dcc2_hash_host = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * self->params.max_keys_per_crypt);
		hmac_sha1_out  = (cl_uint*)mem_alloc(5 * sizeof(cl_uint) * self->params.max_keys_per_crypt);

		memset(dcc_hash_host, 0, 4 * sizeof(cl_uint) * self->params.max_keys_per_crypt);
		memset(dcc2_hash_host, 0, 4 * sizeof(cl_uint) * self->params.max_keys_per_crypt);

		initialized++;
	}
}

static void DCC(unsigned char *salt, unsigned int username_len,
                unsigned int *dcc_hash, unsigned int count)
{
	unsigned int id ;
	unsigned int buffer[64] ;
	unsigned int nt_hash[69] ; // large enough to handle 128 byte user name (when we expand to that size).
	int password_len;
	MD4_CTX ctx;

	for (id = 0; id < count; id++) {
		/* Proper Unicode conversion from UTF-8 or codepage */
		password_len = enc_to_utf16((UTF16*)buffer,
		                            MAX_PLAINTEXT_LENGTH,
		                            (UTF8*)key_host[id],
		                            strlen((const char*)key_host[id]));
		/* Handle truncation */
		if (password_len < 0)
			password_len = strlen16((UTF16*)buffer);

		// generate MD4 hash of the password (NT hash)
		MD4_Init(&ctx);
		MD4_Update(&ctx, buffer, password_len<<1);
		MD4_Final((unsigned char*)nt_hash, &ctx);

		// concatenate NT hash and the username (salt)
		memcpy((unsigned char *)nt_hash + 16, salt, username_len << 1) ;

		MD4_Init(&ctx);
		MD4_Update(&ctx, nt_hash, (username_len<<1)+16);
		MD4_Final((unsigned char*)(dcc_hash+4*id), &ctx);
	}
}

static void done(void) {
	MEM_FREE(dcc2_hash_host) ;
	MEM_FREE(dcc_hash_host) ;
	MEM_FREE(key_host) ;
	MEM_FREE(hmac_sha1_out);
	releaseAll();
	initialized = 0;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return mscash2_common_valid(ciphertext, MAX_SALT_LENGTH, self);
}

static void *get_salt(char *ciphertext)
{
	static ms_cash2_salt salt;
	char *pos = strchr(ciphertext, '#') + 1;
	char *end = strrchr(ciphertext, '#');
	int length = 0;

	memset(&salt, 0, sizeof(salt));

	while (pos < end)
		salt.username[length++] = *pos++;
	salt.username[length] = 0;
	salt.length = length;

	end = strchr(ciphertext, '#');
	salt.iter_cnt = strtol(ciphertext + FORMAT_TAG2_LEN, &end, 10);

	return &salt;
}

static void set_salt(void *salt) {
	memcpy(&currentsalt, salt, sizeof(ms_cash2_salt)) ;
}

static void set_key(char *key, int index) {
	int 	strlength, i ;

	strlength = strlen(key) ;

	for (i = 0; i <= strlength; ++i)
		key_host[index][i] = key[i] ;
}

static  char *get_key(int index) {
	/* Ensure truncation due to over-length or invalid UTF-8 is made like in GPU code. */
	if (options.target_enc == UTF_8)
		truncate_utf8((UTF8*)key_host[index], MAX_PLAINTEXT_LENGTH);

	return (char *)key_host[index] ;
}

static void pbkdf2_iter0(unsigned int *input_dcc_hash,unsigned char *salt_buffer, unsigned int salt_len, int count){
	SHA_CTX ctx1, ctx2;
	unsigned int ipad[SHA_LBLOCK], opad[SHA_LBLOCK];
	unsigned int tmp_hash[SHA_DIGEST_LENGTH/4], i, k;

	memset(&ipad[4], 0x36, SHA_CBLOCK-16);
	memset(&opad[4], 0x5C, SHA_CBLOCK-16);

	for (k = 0; k < count; k++) {
		i = k * 4;
		ipad[0] = dcc_hash_host[i]^0x36363636;
		opad[0] = dcc_hash_host[i++]^0x5C5C5C5C;
		ipad[1] = dcc_hash_host[i]^0x36363636;
		opad[1] = dcc_hash_host[i++]^0x5C5C5C5C;
		ipad[2] = dcc_hash_host[i]^0x36363636;
		opad[2] = dcc_hash_host[i++]^0x5C5C5C5C;
		ipad[3] = dcc_hash_host[i]^0x36363636;
		opad[3] = dcc_hash_host[i++]^0x5C5C5C5C;

		SHA1_Init(&ctx1);
		SHA1_Init(&ctx2);

		SHA1_Update(&ctx1, ipad, SHA_CBLOCK);
		SHA1_Update(&ctx2, opad, SHA_CBLOCK);

		SHA1_Update(&ctx1, salt_buffer, salt_len);
		SHA1_Update(&ctx1, "\x0\x0\x0\x1", 4);
		SHA1_Final((unsigned char*)tmp_hash,&ctx1);

		SHA1_Update(&ctx2, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)(hmac_sha1_out + 5 * k), &ctx2);
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount ;
	int salt_len;
#ifdef _DEBUG
	struct timeval startc, endc, startg, endg ;
	gettimeofday(&startc, NULL) ;
#endif
	UTF16 salt_host[SALT_BUFFER_SIZE >> 1];

	memset(salt_host, 0, sizeof(salt_host));

	/* Proper Unicode conversion from UTF-8 or codepage */
	salt_len = enc_to_utf16(salt_host,
	                        MAX_SALT_LENGTH,
	                        (UTF8*)currentsalt.username,
	                        currentsalt.length);
	/* Handle truncation */
	if (salt_len < 0)
		salt_len = strlen16(salt_host);

	DCC((unsigned char*)salt_host, salt_len, dcc_hash_host, count) ;

	if (salt_len > 22)
		pbkdf2_iter0(dcc_hash_host,(unsigned char*)salt_host, (salt_len << 1) , count);

#ifdef _DEBUG
	gettimeofday(&startg, NULL) ;
#endif
	///defined in opencl_mscash2_helper_plug.c. Details provided in opencl_mscash2_helper_plug.h
	dcc2Execute(dcc_hash_host, hmac_sha1_out, (cl_uint*)salt_host, salt_len, currentsalt.iter_cnt, dcc2_hash_host, count) ;

#ifdef _DEBUG
	gettimeofday(&endg, NULL);
	gettimeofday(&endc, NULL);
	fprintf(stderr, "\nGPU:%f  ",(endg.tv_sec - startg.tv_sec) + (double)(endg.tv_usec - startg.tv_usec) / 1000000.000) ;
	fprintf(stderr, "CPU:%f  ",(endc.tv_sec - startc.tv_sec) + (double)(endc.tv_usec - startc.tv_usec) / 1000000.000 - ((endg.tv_sec - startg.tv_sec) + (double)(endg.tv_usec - startg.tv_usec) / 1000000.000)) ;
#endif
	return count ;
}

static int binary_hash_0(void *binary) {
#ifdef _DEBUG
	puts("binary") ;
	unsigned int i, *b = binary ;
	for (i = 0; i < 4; i++)
		fprintf(stderr, "%08x ", b[i]);
	puts("") ;
#endif
	return (((unsigned int *) binary)[0] & PH_MASK_0) ;
}

static int get_hash_0(int index) {
#ifdef _DEBUG
	int i;
	puts("get_hash");
	for (i = 0; i < 4; i++)
		fprintf(stderr, "%08x ", dcc2_hash_host[index]) ;
	puts("") ;
#endif
	return dcc2_hash_host[4 * index] & PH_MASK_0 ;
}

static int get_hash_1(int index) {
	return dcc2_hash_host[4 * index] & PH_MASK_1 ;
}

static int get_hash_2(int index) {
	return dcc2_hash_host[4 * index] & PH_MASK_2 ;
}

static int get_hash_3(int index) {
	return dcc2_hash_host[4 * index] & PH_MASK_3 ;
}

static int get_hash_4(int index) {
	return dcc2_hash_host[4 * index] & PH_MASK_4 ;
}

static int get_hash_5(int index) {
	return dcc2_hash_host[4 * index] & PH_MASK_5 ;
}

static int get_hash_6(int index) {
	return dcc2_hash_host[4 * index] & PH_MASK_6 ;
}

static int cmp_all(void *binary, int count) {
	unsigned int 	i, b = ((unsigned int *) binary)[0] ;

	for (i = 0; i < count; i++)
		if (b == dcc2_hash_host[4 * i])
			return 1 ;

	return 0 ;
}

static int cmp_one(void *binary, int index)
{
	return 1 ;
}

static int cmp_exact(char *source, int index)
{
      unsigned int 	*bin, i ;

      bin = (unsigned int*)mscash_common_binary(source) ;
      i = 4 * index + 1 ;

      if (bin[1] != dcc2_hash_host[i++])
		return 0 ;

      if (bin[2] != dcc2_hash_host[i++])
		return 0 ;

      if (bin[3] != dcc2_hash_host[i])
		return 0 ;

      return 1 ;
}

static int salt_hash(void *salt) {
	ms_cash2_salt 	*_s = (ms_cash2_salt *)salt ;
	unsigned char   *s = _s->username ;
	unsigned int 	hash = 5381 ;

	while (*s != '\0')
		hash = ((hash << 5) + hash) ^ *s++ ;

	return hash & (SALT_HASH_SIZE - 1) ;
}

struct fmt_main fmt_opencl_mscash2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH | 0x100,
		0,
		MAX_PLAINTEXT_LENGTH,
		GPU_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MAX_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG2 },
		mscash2_common_tests
	},{
		init,
		done,
		reset,
		mscash2_common_prepare,
		valid,
		mscash2_common_split,
		mscash_common_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6

		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
