/* Modified in August, 2012 by Dhiru Kholia (dhiru at openwall.com) for MS SQL 2012
 *
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Modified by Mathieu Perrin (mathieu at tpfh.org) 09/06
 * Microsoft MS-SQL05 password cracker
 *
 * UTF-8 support by magnum 2011, same terms as above
 *
 * Creating MS SQL 2012 hashes:
 *
 * sqlcmd -L
 * sqlcmd -S <server> -U sa -P <password>
 * 1> select pwdencrypt("openwall")
 * 2> go
 *
 * Dumping hashes from MS SQL server 2012:
 *
 * sqlcmd -S <server> -U sa -P <password>
 * 1> select * from sys.sql_logins
 * 2> go */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "sha.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL			"mssql12"
#define FORMAT_NAME			"MS SQL 2012 SHA512"
#define ALGORITHM_NAME			"ms-sql12"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		25
#define CIPHERTEXT_LENGTH		54 + 44 * 2

#define BINARY_SIZE			64
#define SALT_SIZE			4

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"0x0200F733058A07892C5CACE899768F89965F6BD1DED7955FE89E1C9A10E27849B0B213B5CE92CC9347ECCB34C3EFADAF2FD99BFFECD8D9150DD6AACB5D409A9D2652A4E0AF16", "Password1!"},
	{"0x0200AB3E1F9028A739EEF62ABF672427276A32D5EDD349E638E7F2CD81DAA247CFE20EE4E3B0A30B2D0AE3C3FA010E61752F1BF45E045041F1B988C083C7F118527E3E5F0562", "openwall"},
	/* hashes from https://hashcat.net/forum */
	{"0x02006BF4AB05873FF0C8A4AFD1DC5912CBFDEF62E0520A3353B04E1184F05C873C9C76BBADDEAAC1E9948C7B6ABFFD62BFEFD7139F17F6AFE10BE0FEE7A178644623067C2423", "carlos"},
	{"0x0200935819BA20F1C7289CFF2F8FF9F0E40DA5E6D04986F988CFE6603DA0D2BC0160776614763198967D603FBD8C103151A15E70D18E7B494C7F13F16804A7A4EB206084E632", "test"},
	{"0x0200570AC969EF7C6CCB3312E8BEDE1D635EB852C06496957F0FA845B20FCD1C7C457474A5B948B68C47C2CB704D08978871F532C9EB11199BB5F56A06AC915C3799DB8A64C1", "test1"},
	{"0x0200A56045DBCD848E297FA8D06E7579D62B7129928CA0BC5D232A7320972EF5A5455C01411B8D3A7FF3D18A55058A12FAEE5DA410AFE6CE61FF5C39E5FF57CD3EDD57DB1C3B", "test2"},
	{"0x020059799F1B6D897BE2C5A76D3FFDC52B308190E82FA01F2FA51129B4863A7EE21B3FF6FE9F7850976045237805F338DD36DC9345B429F47A402614C6F2F2B02C56DF14C4F4", "Paul"},
	{"0x0200881E2999DD8E3583695F405696257B99559953705A34D774C15AC1D42699BB77BC56DB5F657751335C1B350890E643790553B60329CAE7A2E7D3C04CF8856C4DB0058723", "DBAmaster"},
	{"0x0200D648446E70180A6DFB6DF14DB38623EBFE490FE445751900FD5DC45A2B5D20D7AFFE8C6FFC2890BAE1AF34430A21F2F1E4DE50E25757FDB4789716D8D85C6985A00BC454", "database"},
	{"0x02008AC3B9DC7B67EF9D3C1D25D8007A4B957D5BD61D71E5E9DA08D9F8F012EDDAD168E1CADD93D4627433FBFEE8BCF6CBB42D5B9A31886FC5FF7F970B164F4B5815E03D6DE7", "jhl9mqe5"},
	{"0x020094C4D05A082DB1362B1A972C5D5F1C04C527090A7427E93C13AFEC705A011D8980E994FA647C7D44E25A427246218E25674571DB1710E49C713FB17129549C29E303086A", "coldfusion"},
	{"0x0200B9BD5C85918D9BEE84417957618FBA1CB80B71E81550FAE09AD027B4089017CD6461D8EC9509873C2D5096CDBE8F16E4EFA9035C35F9F4917CE58DB99DC6836CEA7483A7", "sql2005"},
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];
static char (*saved_key)[PLAINTEXT_LENGTH*2 + 1 + SALT_SIZE];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / 4];
static int *key_length;

static int valid(char *ciphertext, struct fmt_main *self)
{
	if(memcmp(ciphertext, "0x0200", 6))
		return 0;
	return 1;
}

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void * get_salt(char * ciphertext)
{
	static unsigned char *out2;
	int l;

	if (!out2) out2 = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	for(l=0;l<SALT_SIZE;l++)
	{
		out2[l] = atoi16[ARCH_INDEX(ciphertext[l*2+6])]*16
			+ atoi16[ARCH_INDEX(ciphertext[l*2+7])];
	}

	return out2;
}

static void set_key_enc(char *_key, int index);

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
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	key_length = mem_calloc_tiny(sizeof(*key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	if (options.utf8) {
		self->methods.set_key = set_key_enc;
		self->params.plaintext_length = PLAINTEXT_LENGTH * 3;
	}
	else if (options.iso8859_1 || options.ascii) {
		; // do nothing
	}
	else {
		self->methods.set_key = set_key_enc;
	}
}

static void set_key(char *_key, int index)
{
	/* ASCII or ISO-8859-1 to UCS-2 */
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = (UTF16*)saved_key[index];
	for (key_length[index] = 0; s[key_length[index]]; key_length[index]++)
		d[key_length[index]] = s[key_length[index]];
	d[key_length[index]] = 0;
	key_length[index] <<= 1;

}

static void set_key_enc(char *_key, int index)
{
	/* UTF-8 or legacy codepage to UCS-2 */
	key_length[index] = enc_to_utf16((UTF16*)saved_key[index], PLAINTEXT_LENGTH,
	                          (unsigned char*)_key, strlen(_key));
	if (key_length[index] < 0)
		key_length[index] = strlen16((UTF16*)saved_key[index]);
	key_length[index] <<= 1;
}

static char *get_key(int index) {
	((UTF16*)saved_key[index])[key_length[index]>>1] = 0;
	return (char*)utf16_to_enc((UTF16*)saved_key[index]);
}

static int cmp_all(void *binary, int count) {
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_exact(char *source, int count) {
	return (1);
}

static int cmp_one(void * binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void crypt_all(int count) {
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		SHA512_CTX ctx;
		memcpy(saved_key[index]+key_length[index], cursalt, SALT_SIZE);
		SHA512_Init(&ctx );
		SHA512_Update(&ctx, saved_key[index], key_length[index]+SALT_SIZE );
		SHA512_Final((unsigned char *)crypt_out[index], &ctx);
	}
}

static void * binary(char *ciphertext)
{
	static char *realcipher;
	int i;

	if(!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+14])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+15])];
	}
	return (void *)realcipher;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int salt_hash(void *salt)
{
	// The >> 8 gave much better distribution on a huge set I analysed
	// although that was mssql05
	return (*((ARCH_WORD_32 *)salt) >> 8) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_mssql12 = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
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
