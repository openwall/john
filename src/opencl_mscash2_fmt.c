/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms :
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
* This format supports salts upto 19 characters.
* Minor bugs in original S3nf implementation limits salts upto 8 characters.
*
* Note: When cracking in single mode keep set MAX_KEYS_PER_CRYPT equal to 65536 or less or use the cpu version instead.
*/

#include "formats.h"
#include "common.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include "md4.h"
#include "sha.h"
#include "unicode.h"
#include "common_opencl_pbkdf2.h"
#include "loader.h"
#include "config.h"


#define INIT_MD4_A                  0x67452301
#define INIT_MD4_B                  0xefcdab89
#define INIT_MD4_C                  0x98badcfe
#define INIT_MD4_D                  0x10325476
#define SQRT_2                      0x5a827999
#define SQRT_3                      0x6ed9eba1


#define FORMAT_LABEL	           "mscash2-opencl"
#define FORMAT_NAME		   "M$ Cache Hash 2 (DCC2)"
#define KERNEL_NAME		   "PBKDF2"
#define ALGORITHM_NAME		   "PBKDF2-SHA1 OpenCL"
#define BENCHMARK_COMMENT	   ""
#define BENCHMARK_LENGTH	  -1
#define MSCASH2_PREFIX            "$DCC2$"
#define MAX_PLAINTEXT_LENGTH      125
#define MAX_CIPHERTEXT_LENGTH     7 +7 + MAX_SALT_LENGTH + 32

#define BINARY_SIZE               4
#define BINARY_ALIGN              4
#define SALT_SIZE                 sizeof(ms_cash2_salt)
#define SALT_ALIGN                4

# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

typedef struct {
	unsigned int 	length ;
	unsigned char 	username[MAX_SALT_LENGTH + 1] ;
} ms_cash2_salt ;

static struct fmt_tests tests[] = {
	{"$DCC2$test#a86012faf7d88d1fc037a69764a92cac", "password"},
	{"$DCC2$test3#360e51304a2d383ea33467ab0b639cc4", "test3" },
	{"$DCC2$10240#test4#6f79ee93518306f071c47185998566ae", "test4" },
	{"$DCC2$january#26b5495b21f9ad58255d99b5e117abe2", "verylongpassword" },
	{"$DCC2$february#469375e08b5770b989aa2f0d371195ff", "(##)(&#*%%" },
	{"$DCC2$nineteen_characters#c4201b8267d74a2db1d5d19f5c9f7b57", "verylongpassword" },
	{"$DCC2$nineteen_characters#87136ae0a18b2dafe4a41d555425b2ed", "w00t"},
	{"$DCC2$administrator#56f8c24c5a914299db41f70e9b43f36d", "w00t" },
	{"$DCC2$AdMiNiStRaToR#56f8C24c5A914299Db41F70e9b43f36d", "w00t" },                   //Salt and hash are lowercased
	{"$DCC2$10240#TEST2#c6758e5be7fc943d00b97972a8a97620", "test2" },                    // salt is lowercased before hashing
	{"$DCC2$10240#eighteencharacters#fc5df74eca97afd7cd5abb0032496223", "w00t" },
	{"$DCC2$john-the-ripper#495c800a038d11e55fafc001eb689d1d", "batman#$@#1991" },
	{"$DCC2$#59137848828d14b1fca295a5032b52a1", "a" },                                   //Empty Salt
	{"$DCC2$10240#nineteen_characters#cda4cef92db4398ce648a8fed8dc6853", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	//MAX length salt with MAX length password
	{"$DCC2$10240#12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678#5ba26de44bd3a369f43a1c72fba76d45", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{NULL}
} ;

static cl_uint 		*dcc_hash_host ;
static cl_uint 		*dcc2_hash_host ;
static unsigned char 	(*key_host)[MAX_PLAINTEXT_LENGTH + 1] ;
static ms_cash2_salt 	currentsalt ;
static cl_uint          *hmac_sha1_out ;

extern int mscash2_valid(char *, int,  const char *, struct fmt_main *);
extern char * mscash2_prepare(char **, struct fmt_main *);
extern char * mscash2_split(char *, int, struct fmt_main *);

static void set_key(char*, int) ;
static int crypt_all(int *pcount, struct db_salt *salt) ;

static void init(struct fmt_main *self) {
	int 	i ;

	//Prepare OpenCL environment.
	opencl_preinit();

	///Allocate memory
	key_host = mem_calloc(self -> params.max_keys_per_crypt * sizeof(*key_host)) ;
	dcc_hash_host = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * MAX_KEYS_PER_CRYPT) ;
	dcc2_hash_host = (cl_uint*)mem_alloc(4 * sizeof(cl_uint) * MAX_KEYS_PER_CRYPT) ;
	hmac_sha1_out  = (cl_uint*)mem_alloc(5 * sizeof(cl_uint) * MAX_KEYS_PER_CRYPT) ;

	memset(dcc_hash_host, 0, 4 * sizeof(cl_uint) * MAX_KEYS_PER_CRYPT) ;
	memset(dcc2_hash_host, 0, 4 * sizeof(cl_uint) * MAX_KEYS_PER_CRYPT) ;

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(OCL_CONFIG);

	for( i=0; i < opencl_get_devices(); i++)
		select_device(ocl_device_list[i], self) ;

	warning() ;
}

static void DCC(unsigned char *salt, unsigned int username_len, unsigned int *dcc_hash, unsigned int count) {
	unsigned int 	i, id ;
	unsigned int 	buffer[64] ;
	unsigned int 	nt_hash[69] ; // large enough to handle 128 byte user name (when we expand to that size).
	unsigned int 	password_len;
	MD4_CTX ctx;

	for (id = 0; id < count; id++) {

		password_len = strlen((const char*)key_host[id]) ;

		// convert ASCII password to Unicode
		for (i = 0; i <= password_len  >> 1; i++)
			buffer[i] = key_host[id][2 * i] | (key_host[id][2 * i + 1] << 16) ;

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

static void done() {
	MEM_FREE(dcc2_hash_host) ;
	MEM_FREE(dcc_hash_host) ;
	MEM_FREE(key_host) ;
	MEM_FREE(hmac_sha1_out);
	clean_all_buffer() ;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return mscash2_valid(ciphertext, MAX_SALT_LENGTH, FORMAT_LABEL, self);
}

static void *binary(char *ciphertext)
{
	static unsigned int 	binary[4] ;
	int 			i ;
	char 			*hash ;

	hash = strrchr(ciphertext, '#') + 1 ;

	if (hash == NULL)
		return binary ;

	for (i = 0; i < 4; i++) {
		sscanf(hash + (8 * i), "%08x", &binary[i]) ;
		binary[i] = SWAP(binary[i]) ;
	}

	return binary ;
}

static void *salt(char *ciphertext) {
	static ms_cash2_salt 	salt ;
	unsigned int 		length ;
	char 			*pos ;

	memset(&salt, 0, sizeof(salt)) ;
	length = 0 ;
	pos = strchr(ciphertext, '#') + 1 ;

	while (*pos != '#') {
		if (length == MAX_SALT_LENGTH)
			return NULL ;

		salt.username[length++] = *pos++ ;
	      }

	salt.username[length] = 0 ;
	salt.length = length ;

	return &salt ;
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
	return (char *)key_host[index] ;
}

static void pbkdf2_iter0(unsigned int *input_dcc_hash,unsigned char *salt_buffer, unsigned int salt_len, int count){
	SHA_CTX ctx1, ctx2;
	unsigned int ipad[SHA_LBLOCK], opad[SHA_LBLOCK];
	unsigned int tmp_hash[SHA_DIGEST_LENGTH/4], i, k;

	memset(&ipad[4], 0x36, SHA_CBLOCK-16);
	memset(&opad[4], 0x5C, SHA_CBLOCK-16);

	for(k = 0; k < count; k++) {
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

static int crypt_all(int *pcount, struct db_salt *salt) {
	int 		count = *pcount ;
	unsigned int 	i ;
#ifdef _DEBUG
	struct timeval startc, endc, startg, endg ;
	gettimeofday(&startc, NULL) ;
#endif
	unsigned char 	salt_unicode[(MAX_SALT_LENGTH << 1) + 1] ;
	cl_uint 	salt_host[(MAX_SALT_LENGTH >> 1) + 1] ;

	memset(salt_unicode, 0, (MAX_SALT_LENGTH << 1) + 1) ;
	memset(salt_host, 0, ((MAX_SALT_LENGTH >> 1) + 1) * sizeof(cl_uint)) ;

	if (currentsalt.length & 1 )
		for (i = 0; i < (currentsalt.length >> 1) + 1; i++)
			((unsigned int *)salt_unicode)[i] = currentsalt.username[2 * i] | (currentsalt.username[2 * i + 1] << 16) ;
	else
		for (i = 0; i < (currentsalt.length >> 1) ; i++)
			((unsigned int *)salt_unicode)[i] = currentsalt.username[2 * i] | (currentsalt.username[2 * i + 1] << 16) ;

	memcpy(salt_host, salt_unicode, (MAX_SALT_LENGTH << 1) + 1) ;

	DCC(salt_unicode, currentsalt.length, dcc_hash_host, count) ;

	if(currentsalt.length > 22)
		pbkdf2_iter0(dcc_hash_host,(unsigned char*)salt_host, (currentsalt.length << 1) , count);

#ifdef _DEBUG
	gettimeofday(&startg, NULL) ;
#endif
	///defined in common_opencl_pbkdf2.c. Details provided in common_opencl_pbkdf2.h
	pbkdf2_divide_work(dcc_hash_host, salt_host, currentsalt.length, dcc2_hash_host, hmac_sha1_out, count) ;

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
	return (((unsigned int *) binary)[0] & 0xf) ;
}

static int get_hash_0(int index) {
#ifdef _DEBUG
	int i;
	puts("get_hash");
	for (i = 0; i < 4; i++)
		fprintf(stderr, "%08x ", dcc2_hash_host[index]) ;
	puts("") ;
#endif
	return dcc2_hash_host[4 * index] & 0xf ;
}

static int get_hash_1(int index) {
	return dcc2_hash_host[4 * index] & 0xff ;
}

static int get_hash_2(int index) {
	return dcc2_hash_host[4 * index] & 0xfff ;
}

static int get_hash_3(int index) {
	return dcc2_hash_host[4 * index] & 0xffff ;
}

static int get_hash_4(int index) {
	return dcc2_hash_host[4 * index] & 0xfffff ;
}

static int get_hash_5(int index) {
	return dcc2_hash_host[4 * index] & 0xffffff ;
}

static int get_hash_6(int index) {
	return dcc2_hash_host[4 * index] & 0x7ffffff ;
}

static int cmp_all(void *binary, int count) {
	unsigned int 	i, b = ((unsigned int *) binary)[0] ;

	for (i = 0; i < count; i++)
		if (b == dcc2_hash_host[4 * i])
			return 1 ;

	return 0 ;
}

static int cmp_one(void *binary, int index) {
	return 1 ;
}

static int cmp_exact(char *source, int count) {
      unsigned int 	*bin, i ;

      bin = (unsigned int*)binary(source) ;
      i = 4 * count + 1 ;

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
		BENCHMARK_LENGTH,
		MAX_PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MAX_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		0,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE,
		tests
	},{
		init,
		done,
		fmt_default_reset,
		mscash2_prepare,
		valid,
		mscash2_split,
		binary,
		salt,
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
