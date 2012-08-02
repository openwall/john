/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_cryptsha256.h"
#include "cuda_common.h"
#include <unistd.h>

#define FORMAT_LABEL		"sha256crypt-cuda"
#define FORMAT_NAME		"sha256crypt"

#define ALGORITHM_NAME		"CUDA"

#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define BINARY_SIZE		32
#define MD5_DIGEST_LENGTH 	16

#define SALT_SIZE		(3+7+9+16)

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

extern void sha256_crypt_gpu(crypt_sha256_password * inbuffer,
    uint32_t * outbuffer, crypt_sha256_salt * host_salt);

static crypt_sha256_password *inbuffer;//[MAX_KEYS_PER_CRYPT];			/** plaintext ciphertexts **/
static uint32_t *outbuffer;//[MAX_KEYS_PER_CRYPT * 8];				/** calculated hashes **/

static char currentsalt[64];
static crypt_sha256_salt host_salt;

void sha256_crypt_cpu(crypt_sha256_password * passwords,
    crypt_sha256_hash * output, crypt_sha256_salt * salt);


static struct fmt_tests tests[] = {
	{"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
	    "Hello world!"},
	/*{"$5$UOUBPEMKQRHHRFML$zicoLpMLhBsNGtEplY/ehM0NtiAqxijiBCrolt7WBW0","jjti"},

	   {"$5$XSLWLBSQUCNOWXOB$i7Ho5wUAIjsH2e2zA.WarqYLWir5nmZbUEcjK//Or7.","hgnirgayjnhvi"},
	   {"$5$VDCTRFOIDQXRQVHR$uolqT0wEwU.pvI9jq5xU457JQpiwTTKX3PB/9RS4/h4","o"},
	   {"$5$WTYWNCYHNPMXPG$UwZyrq0irhWs4OcLKcqSbFdktZaNAD2by1CiNNw7oID","tcepf"},
	   {"$5$DQUHKJNMVOEBGBG$91u2d/jMN5QuW3/kBEPG0xC2G8y1TuDU7SGAUYTX.y0","wbfhoc"},


	   {"$5$saltstring$0Az3qME7zTXm78kfHrR2OtT8WOu2gd8bcVn/9Y.3l/7", "john"},

	   {"$5$saltstring$7cz4bTeQ7MnNssphNhFVrITtuJYY/1tdvLL2uzLvOk8","a"},
	   {"$5$saltstring$4Wjlxdm/Hbpo8ZQzKFazuvfUZPVVUQn6v1oPTX3nwX/","ab"},
	   {"$5$saltstring$tDHA0KPsYQ8V.LDB1/fgW7cvROod5ZajSrx1tZU2JG9","abc"},
	   {"$5$saltstring$LfhGTHVGfbAkxy/xKLgvSfXyeE7hZheoMRKhjfvNF6.","abcd"},
	   {"$5$saltstring$Qg0Xm9f2VY.ePLAwNXnOPU/s8btLptK/tEU/gFnn8BD","abcde"},
	   {"$5$saltstring$2Snf.yaHnLnLI3Qhsk2S119X4vKbwQyiTMOHp3Oy7F5","abcdef"},
	   {"$5$saltstring$4Y5UR.6zwplRx6y93NJVyNkxqdlyT64EV68F2mCrZ16","abcdefg"},
	   {"$5$saltstring$bEM3iuUR.CTgy8Wygh4zu.CAgmlwx3uxm3dGA34.Ij4","abcdefgh"},
	   {"$5$saltstring$1/OrKXZSFlaEE2DKMhKKE8qCld5X0Ez0vtz5TvO3U3D","abcdefghi"},
	   {"$5$saltstring$1IbZU70/Wo9m1b40ha6Ao8d.v6Ja0.bAFg5/QFVzoX/","abcdefghij"},

	   {"$5$saltstring$S4gCgloAzqAXE5sRz9DShPvaXrwt4vjDJ4fYgIMbLo1","abcdefghijk"},
	   {"$5$saltstring$AFNSzsWaoMDvt7lk2bx0rPapzCz2zGahXDdFeoXrNE9","abcdefghijkl"},
	   {"$5$saltstring$QfHc8JBd2DfyloVL0YLDa23Dc67N9mbdYqyRJQlFqZ5","abcdefghijklm"},
	   {"$5$saltstring$XKHiS.SSJ545PvJJr2t.HyUpmPZDAIT8fVvzr/HGhd0","abcdefghijklmn"},
	   {"$5$saltstring$VxW44bFDcvixlQoTE4E.k5c8v1w0fGMyZ4tn8nGcWn0","abcdefghijklmno"},

	   {"$5$QSTVVEKDIDYRNK$4j8TST.29P07GHASD.BUHd0UTaFz7h.Mz//zcHokoZ5","cgyihfkqk"},

	 */

	//{"$5$rounds=5000$abcdefghijklmnop$BAYQep7SsuSczAeXlks3F54SpxMUUludHi1C4JVOqpD","abcdefghijklmno"},
	{NULL}
};

static void cleanup()
{
 free(inbuffer);
 free(outbuffer);
}

static void init(struct fmt_main *self)
{
  //Alocate memory for hashes and passwords
  inbuffer=(crypt_sha256_password*)calloc(MAX_KEYS_PER_CRYPT,sizeof(crypt_sha256_password));
  outbuffer=(uint32_t*)malloc(sizeof(uint32_t)*MAX_KEYS_PER_CRYPT*8);
  check_mem_allocation(inbuffer,outbuffer);
  atexit(cleanup);
  //Initialize CUDA
  cuda_init(gpu_id);
}

static int valid(char *ciphertext,struct fmt_main *self)
{
	uint32_t i, j;
	int len = strlen(ciphertext);
	char *p;
	if (strncmp(ciphertext, "$5$", 3) != 0)
		return 0;
	p = strrchr(ciphertext, '$');
	if (p == NULL)
		return 0;
	for (i = p - ciphertext + 1; i < len; i++) {
		int found = 0;
		for (j = 0; j < 64; j++)
			if (itoa64[j] == ARCH_INDEX(ciphertext[i])) {
				found = 1;
				break;
			}
		if (found == 0)
			return 0;
	}
	if (len - (p - ciphertext + 1) != 43)
		return 0;
	return 1;
};

static int findb64(char c)
{
	int ret = ARCH_INDEX(atoi64[(uint8_t) c]);
	return ret != 0x7f ? ret : 0;
}

static void magic(char *crypt, char *alt)
{

#define _24bit_from_b64(I,B2,B1,B0) \
  {\
      uint8_t c1,c2,c3,c4,b0,b1,b2;\
      uint32_t w;\
      c1=findb64(crypt[I+0]);\
      c2=findb64(crypt[I+1]);\
      c3=findb64(crypt[I+2]);\
      c4=findb64(crypt[I+3]);\
      w=c4<<18|c3<<12|c2<<6|c1;\
      b2=w&0xff;w>>=8;\
      b1=w&0xff;w>>=8;\
      b0=w&0xff;w>>=8;\
      alt[B2]=b0;\
      alt[B1]=b1;\
      alt[B0]=b2;\
  }
	uint32_t w;
	_24bit_from_b64(0, 0, 10, 20);
	_24bit_from_b64(4, 21, 1, 11);
	_24bit_from_b64(8, 12, 22, 2);
	_24bit_from_b64(12, 3, 13, 23);
	_24bit_from_b64(16, 24, 4, 14);
	_24bit_from_b64(20, 15, 25, 5);
	_24bit_from_b64(24, 6, 16, 26);
	_24bit_from_b64(28, 27, 7, 17);
	_24bit_from_b64(32, 18, 28, 8);
	_24bit_from_b64(36, 9, 19, 29);
	w =
	    findb64(crypt[42]) << 12 | findb64(crypt[41]) << 6 |
	    findb64(crypt[40]);
	alt[30] = w & 0xff;
	w >>= 8;
	alt[31] = w & 0xff;
	w >>= 8;
}

static void *binary(char *ciphertext)
{
	static char b[BINARY_SIZE];
	char *p;
	memset(b, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '$');
	if(p!=NULL)
	magic(p+1, b);
	return (void *) b;
}

static void *salt(char *ciphertext)
{
	int end = 0, i, len = strlen(ciphertext);
	static unsigned char ret[64];
	for (i = len - 1; i >= 0; i--)
		if (ciphertext[i] == '$') {
			end = i;
			break;

		}
	for (i = 0; i < end; i++)
		ret[i] = ciphertext[i];
	ret[end] = 0;
	return (void *) ret;
}

static int binary_hash_0(void *binary)
{
	return (((ARCH_WORD_32 *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0x7ffffff;
}

static void set_salt(void *salt)
{
	unsigned char *s = salt;
	int len = strlen(salt);
	unsigned char offset = 0;
	memcpy(currentsalt,s,len+1);
	host_salt.rounds = ROUNDS_DEFAULT;

	if (strncmp((char *) "$5$", (char *) currentsalt, 3) == 0)
		offset += 3;

	if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0) {
		const char *num = currentsalt + offset + 7;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			endp += 1;
			host_salt.rounds =
			    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
		}
		offset = endp - currentsalt;
	}
	memcpy(host_salt.salt, currentsalt + offset, 16);
	host_salt.saltlen = strlen(host_salt.salt);
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
	inbuffer[index].length = len;
	memcpy(inbuffer[index].v, key, len);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}

static void crypt_all(int count)
{
	sha256_crypt_gpu(inbuffer, outbuffer, &host_salt);
}

static int get_hash_0(int index)
{

	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xf;
}

static int get_hash_1(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xff;
}

static int get_hash_2(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xfff;
}

static int get_hash_3(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xffff;
}

static int get_hash_4(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xfffff;
}

static int get_hash_5(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xffffff;
}

static int get_hash_6(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t *out = outbuffer;
	for (i = 0; i < count; i++)
		if (b == out[hash_addr(0, i)])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	uint32_t *out = outbuffer;

	for (i = 0; i < 8; i++)
		if (t[i] != out[hash_addr(i, index)])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_cuda_cryptsha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
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
