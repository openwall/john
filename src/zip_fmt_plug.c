/*
 * ZIP cracker patch for JtR. Hacked together during June of 2011
 * by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * http://www.winzip.com/aes_info.htm (There is a 1 in 65,536 chance that an
 * incorrect password will yield a matching verification value; therefore, a
 * matching verification value cannot be absolutely relied on to indicate a
 * correct password.). The alternative is to implement/use a full unzip engine.
 *
 * This format significantly improved, Summer of 2014, JimF.  Changed the signature
 * to the $zip2$, and added logic to properly make this format work. Now there is no
 * false positives any more.  Now it properly cracks the passwords. There is
 * an hmac-sha1 'key' that is also processed (and the decryption key), in the pbkdf2
 * call.  Now we use this hmac-sha1 key, process the compressed and encrypted buffer,
 * compare to a 10 byte checksum (which is now the binary blob), and we KNOW that we
 * have cracked or not cracked the key.  The $zip$ was broken before, so that signature
 * has simply been retired as DOA.  This format is now much like the pkzip format.
 * it may have all data contained within the hash string, OR it may have some, and
 * have a file pointer on where to get the rest of the data.
 *
 * optimizations still that can be done.
 *  1. decrypt and inflate some data for really large buffers, BEFORE doing the
 *     hmac-sha1 call.  The inflate algorithm is pretty self checking for 'valid'
 *     data, so a few hundred bytes of checking and we are 99.999% sure we have the
 *     right password, before starting an expensive hmac (for instance if the zip blob
 *     was 50mb).
 *  2. Put in the 'file magic' logic we have for pkzip. There is a place holder for it,
 *     but the logic has not been added.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_zip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_zip);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "memory.h"
#include "pkzip.h"
#include "pbkdf2_hmac_sha1.h"
#include "dyna_salt.h"
#include "hmac_sha.h"
#include "memdbg.h"

#define KEY_LENGTH(mode)        (8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)       (4 * ((mode) & 3) + 4)

typedef struct my_salt_t {
	dyna_salt dsalt;
	uint64_t comp_len;
	struct {
		uint16_t type : 4;
		uint16_t mode : 4;
	} v;
	unsigned char passverify[2];
	unsigned char salt[SALT_LENGTH(3)];
	//uint64_t data_key; // MSB of md5(data blob).  We lookup using this.
	unsigned char datablob[1];
} my_salt;

#define FORMAT_LABEL        "ZIP"
#define FORMAT_NAME         "WinZip"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define PLAINTEXT_LENGTH    125
#define BINARY_ALIGN        sizeof(uint32_t)
#define SALT_SIZE           sizeof(my_salt*)
#define SALT_ALIGN          sizeof(my_salt*)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  (SSE_GROUP_SZ_SHA1 * 8)
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  8
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           32	// Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*crypt_key)[((WINZIP_BINARY_SIZE+3)/4)*4];
static my_salt *saved_salt;


//    filename:$zip2$*Ty*Mo*Ma*Sa*Va*Le*DF*Au*$/zip2$
//    Ty = type (0) and ignored.
//    Mo = mode (1 2 3 for 128/192/256 bit
//    Ma = magic (file magic).  This is reserved for now.  See pkzip_fmt_plug.c or zip2john.c for information.
//         For now, this must be a '0'
//    Sa = salt(hex).   8, 12 or 16 bytes of salt (depends on mode)
//    Va = Verification bytes(hex) (2 byte quick checker)
//    Le = real compr len (hex) length of compressed/encrypted data (field DF)
//    DF = compressed data DF can be L*2 hex bytes, and if so, then it is the ENTIRE file blob written 'inline'.
//         However, if the data blob is too long, then a .zip ZIPDATA_FILE_PTR_RECORD structure will be the 'contents' of DF
//    Au = Authentication code (hex) a 10 byte hex value that is the hmac-sha1 of data over D. This is the binary() value

//  ZIPDATA_FILE_PTR_RECORD  (this can be the 'DF' of this above hash line.
//      *ZFILE*Fn*Oh*Ob*  (Note, the leading and trailing * are the * that 'wrap' the DF object.
//  ZFILE This is the literal string ZFILE
//  Fn    This is the name of the .zip file.  NOTE the user will need to keep the .zip file in proper locations (same as
//        was seen when running zip2john. If the file is removed, this hash line will no longer be valid.
//  Oh    Offset to the zip central header record for this blob.
//  Ob    Offset to the start of the blob data

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}


static void *get_salt(char *ciphertext)
{
	uint64_t i;
	my_salt salt, *psalt;
	static unsigned char *ptr;
	/* extract data from "ciphertext" */
	c8 *copy_mem = strdup(ciphertext);
	c8 *cp, *p;

	if (!ptr) ptr = mem_alloc_tiny(sizeof(my_salt*),sizeof(my_salt*));
	p = copy_mem + WINZIP_TAG_LENGTH+1; /* skip over "$zip2$*" */
	memset(&salt, 0, sizeof(salt));
	cp = strtokm(p, "*"); // type
	salt.v.type = atoi((const char*)cp);
	cp = strtokm(NULL, "*"); // mode
	salt.v.mode = atoi((const char*)cp);
	cp = strtokm(NULL, "*"); // file_magic enum (ignored)
	cp = strtokm(NULL, "*"); // salt
	for (i = 0; i < SALT_LENGTH(salt.v.mode); i++)
		salt.salt[i] = (atoi16[ARCH_INDEX(cp[i<<1])]<<4) | atoi16[ARCH_INDEX(cp[(i<<1)+1])];
	cp = strtokm(NULL, "*");	// validator
	salt.passverify[0] = (atoi16[ARCH_INDEX(cp[0])]<<4) | atoi16[ARCH_INDEX(cp[1])];
	salt.passverify[1] = (atoi16[ARCH_INDEX(cp[2])]<<4) | atoi16[ARCH_INDEX(cp[3])];
	cp = strtokm(NULL, "*");	// data len
	sscanf((const char *)cp, "%"PRIx64, &salt.comp_len);

	// later we will store the data blob in our own static data structure, and place the 64 bit LSB of the
	// MD5 of the data blob into a field in the salt. For the first POC I store the entire blob and just
	// make sure all my test data is small enough to fit.

	cp = strtokm(NULL, "*");	// data blob

	// Ok, now create the allocated salt record we are going to return back to John, using the dynamic
	// sized data buffer.
	psalt = (my_salt*)mem_calloc(1, sizeof(my_salt) + salt.comp_len);
	psalt->v.type = salt.v.type;
	psalt->v.mode = salt.v.mode;
	psalt->comp_len = salt.comp_len;
	psalt->dsalt.salt_alloc_needs_free = 1;  // we used mem_calloc, so JtR CAN free our pointer when done with them.
	memcpy(psalt->salt, salt.salt, sizeof(salt.salt));
	psalt->passverify[0] = salt.passverify[0];
	psalt->passverify[1] = salt.passverify[1];

	// set the JtR core linkage stuff for this dyna_salt
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(my_salt, comp_len);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(my_salt, comp_len, datablob, psalt->comp_len);


	if (strcmp((const char*)cp, "ZFILE")) {
	for (i = 0; i < psalt->comp_len; i++)
		psalt->datablob[i] = (atoi16[ARCH_INDEX(cp[i<<1])]<<4) | atoi16[ARCH_INDEX(cp[(i<<1)+1])];
	} else {
		c8 *Fn, *Oh, *Ob;
		long len;
		uint32_t id;
		FILE *fp;

		Fn = strtokm(NULL, "*");
		Oh = strtokm(NULL, "*");
		Ob = strtokm(NULL, "*");

		fp = fopen((const char*)Fn, "rb");
		if (!fp) {
			psalt->v.type = 1; // this will tell the format to 'skip' this salt, it is garbage
			goto Bail;
		}
		sscanf((const char*)Oh, "%lx", &len);
		if (fseek(fp, len, SEEK_SET)) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		id = fget32LE(fp);
		if (id != 0x04034b50U) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		sscanf((const char*)Ob, "%lx", &len);
		if (fseek(fp, len, SEEK_SET)) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		if (fread(psalt->datablob, 1, psalt->comp_len, fp) != psalt->comp_len) {
			fclose(fp);
			psalt->v.type = 1;
			goto Bail;
		}
		fclose(fp);
	}
Bail:;
	MEM_FREE(copy_mem);

	memcpy(ptr, &psalt, sizeof(my_salt*));
	return (void*)ptr;
}

static void set_salt(void *salt)
{
	saved_salt = *((my_salt**)salt);
}

static void set_key(char *key, int index)
{
	strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

	if (saved_salt->v.type) {
		// This salt passed valid() but failed get_salt().
		// Should never happen.
		memset(crypt_key, 0, count * WINZIP_BINARY_SIZE);
		return count;
	}

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, saved_key, saved_salt, crypt_key)
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned char pwd_ver[64*MIN_KEYS_PER_CRYPT];
		int lens[MIN_KEYS_PER_CRYPT], i;
		int something_hit = 0, hits[MIN_KEYS_PER_CRYPT] = {0};
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = &pwd_ver[i*(2+2*KEY_LENGTH(saved_salt->v.mode))];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, saved_salt->salt,
		                SALT_LENGTH(saved_salt->v.mode), KEYING_ITERATIONS,
		                pout, 2, 2*KEY_LENGTH(saved_salt->v.mode));
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			if (!memcmp(pout[i], saved_salt->passverify, 2))
				something_hit = hits[i] = 1;
		if (something_hit) {
			pbkdf2_sha1_sse((const unsigned char **)pin, lens,
				                saved_salt->salt,
				                SALT_LENGTH(saved_salt->v.mode),
				                KEYING_ITERATIONS, pout,
				                KEY_LENGTH(saved_salt->v.mode),
				                KEY_LENGTH(saved_salt->v.mode));
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				if (hits[i]) {
					hmac_sha1(pout[i], KEY_LENGTH(saved_salt->v.mode),
				                  (const unsigned char*)saved_salt->datablob,
				                  saved_salt->comp_len, crypt_key[index+i],
				                  WINZIP_BINARY_SIZE);
				}
				else
					memset(crypt_key[index+i], 0, WINZIP_BINARY_SIZE);
			}
		} else {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
				memset(crypt_key[index+i], 0, WINZIP_BINARY_SIZE);
		}
#else
		union {
			unsigned char pwd_ver[64];
			uint32_t w;
		} x;
		unsigned char *pwd_ver = x.pwd_ver;

		pbkdf2_sha1((unsigned char *)saved_key[index], strlen(saved_key[index]),
		            saved_salt->salt, SALT_LENGTH(saved_salt->v.mode),
		            KEYING_ITERATIONS, pwd_ver, 2,
		            2*KEY_LENGTH(saved_salt->v.mode));
		if (!memcmp(pwd_ver, saved_salt->passverify, 2)) {
			pbkdf2_sha1((unsigned char *)saved_key[index],
			            strlen(saved_key[index]), saved_salt->salt,
			            SALT_LENGTH(saved_salt->v.mode), KEYING_ITERATIONS,
			            pwd_ver, KEY_LENGTH(saved_salt->v.mode),
			            KEY_LENGTH(saved_salt->v.mode));
			hmac_sha1(pwd_ver, KEY_LENGTH(saved_salt->v.mode),
			          (const unsigned char*)saved_salt->datablob,
			          saved_salt->comp_len, crypt_key[index],
			          WINZIP_BINARY_SIZE);
		}
		else
			memset(crypt_key[index], 0, WINZIP_BINARY_SIZE);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (((uint32_t*)&(crypt_key[i]))[0] == ((uint32_t*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((uint32_t*)&(crypt_key[index]))[0] == ((uint32_t*)binary)[0]);
}

static int cmp_exact(char *source, int index)
{
	void *b = winzip_common_binary(source);
	return !memcmp(b, crypt_key[index], sizeof(crypt_key[index]));
}

struct fmt_main fmt_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		WINZIP_BENCHMARK_COMMENT,
		WINZIP_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		4, // WINZIP_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{ NULL },
		{ WINZIP_FORMAT_TAG },
		winzip_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		winzip_common_valid,
		winzip_common_split,
		winzip_common_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		set_key,
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
