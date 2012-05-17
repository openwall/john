/* Mozilla cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * Uses code from FireMasterLinux project.
 * (http://code.google.com/p/rainbowsandpwnies/wiki/FiremasterLinux) */

#ifdef HAVE_NSS
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include <openssl/sha.h>
#include "lowpbe.h"
#include "KeyDBCracker.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               32
#endif

#define FORMAT_LABEL		"mozilla"
#define FORMAT_NAME		"Mozilla"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	16
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(*salt_struct)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

struct custom_salt {
	SHA_CTX pctx;
	SECItem saltItem;
	unsigned char encString[128];
	struct NSSPKCS5PBEParameter *paramPKCS5;;
	struct KeyCrackData keyCrackData;
	struct NSSPKCS5PBEParameter gpbe_param;
	unsigned char salt_data[4096];
} *salt_struct;

#ifdef DEBUF
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int CheckMasterPassword(char *password, SECItem *pkcs5_pfxpbe, SECItem *secPreHash)
{
	unsigned char passwordHash[SHA1_LENGTH+1];
	SHA_CTX ctx;
	// Copy already calculated partial hash data..
	memcpy(&ctx, &salt_struct->pctx, sizeof(SHA_CTX) );
	SHA1_Update(&ctx, (unsigned char *)password, strlen(password));
	SHA1_Final(passwordHash, &ctx);
	return nsspkcs5_CipherData(salt_struct->paramPKCS5, passwordHash, salt_struct->encString, pkcs5_pfxpbe, secPreHash);
}


static struct fmt_tests mozilla_tests[] = {
	{"$mozilla$*3*20*1*5199adfab24e85e3f308bacf692115f23dcd4f8f*11*2a864886f70d010c050103*16*9debdebd4596b278de029b2b2285ce2e*20*2c4d938ccb3f7f1551262185ccee947deae3b8ae", "12345678"},
	{"$mozilla$*3*20*1*4f184f0d3c91cf52ee9190e65389b4d4c8fc66f2*11*2a864886f70d010c050103*16*590d1771368107d6be64844780707787*20*b8458c712ffcc2ff938409804cf3805e4bb7d722", "openwall"},
	{"$mozilla$*3*20*1*897f35ff10348f0d3a7739dbf0abddc62e2e64c3*11*2a864886f70d010c050103*16*1851b917997b3119f82b8841a764db62*20*197958dd5e114281f59f9026ad8b7cfe3de7196a", "password"},
	{NULL}
};


static void init(struct fmt_main *pFmt)
{
#if defined (_OPENMP)
	int omp_t;

	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$mozilla$", 9);
}

static void *get_salt(char *ciphertext)
{
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	ctcopy += 9;	/* skip over "$vnc$*" */
	salt_struct = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	char *p = strtok(ctcopy, "*");
	salt_struct->keyCrackData.version = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->keyCrackData.saltLen = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->keyCrackData.nnLen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < salt_struct->keyCrackData.saltLen; i++)
		salt_struct->keyCrackData.salt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	salt_struct->keyCrackData.salt[salt_struct->keyCrackData.saltLen] = 0;
	p = strtok(NULL, "*");
	salt_struct->keyCrackData.oidLen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < salt_struct->keyCrackData.oidLen; i++)
		salt_struct->keyCrackData.oidData[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	salt_struct->keyCrackData.oidData[salt_struct->keyCrackData.oidLen] =0;
	p = strtok(NULL, "*");
	salt_struct->keyCrackData.encDataLen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < salt_struct->keyCrackData.oidLen; i++)
		salt_struct->keyCrackData.encData[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	salt_struct->keyCrackData.globalSaltLen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < salt_struct->keyCrackData.globalSaltLen; i++)
		salt_struct->keyCrackData.globalSalt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	// initialize the pkcs5 structure
	salt_struct->saltItem.type = (SECItemType) 0;
	salt_struct->saltItem.len  = salt_struct->keyCrackData.saltLen;
	salt_struct->saltItem.data = salt_struct->keyCrackData.salt;
	salt_struct->paramPKCS5 = nsspkcs5_NewParam(0, &salt_struct->saltItem, 1, &salt_struct->gpbe_param, salt_struct->salt_data);
	if(salt_struct->paramPKCS5 == NULL) {
		fprintf(stderr, "\nFailed to initialize NSSPKCS5 structure");
		exit(0);
	}
	// Current algorithm is
	// SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC
	// Setup the encrypted password-check string
	memcpy(salt_struct->encString, salt_struct->keyCrackData.encData, salt_struct->keyCrackData.encDataLen );
	// Calculate partial sha1 data for password hashing
	SHA1_Init(&salt_struct->pctx);
	SHA1_Update(&salt_struct->pctx, salt_struct->keyCrackData.globalSalt, salt_struct->keyCrackData.globalSaltLen);

	free(keeptr);
	return (void *)salt_struct;
}


static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char data1[256];
		unsigned char data2[512];
		SECItem secPreHash;
		secPreHash.data = data1;
		memcpy(secPreHash.data + SHA1_LENGTH, salt_struct->saltItem.data, salt_struct->saltItem.len);
		secPreHash.len = salt_struct->saltItem.len + SHA1_LENGTH;
		SECItem pkcs5_pfxpbe;
		pkcs5_pfxpbe.data = data2;
		cracked[index] = CheckMasterPassword(saved_key[index],
		                                     &pkcs5_pfxpbe,
		                                     &secPreHash);
	}
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

static void mozilla_set_key(char *key, int index)
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

struct fmt_main mozilla_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		mozilla_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		mozilla_set_key,
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
#else
#ifdef __GNUC__
#warning Note: Mozilla format disabled, un-comment HAVE_NSS in Makefile if you have NSS installed.
#endif
#endif
