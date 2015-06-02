/*
 * ZIP cracker patch for JtR. Hacked together during June of 2011
 * by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Files borrowed from http://www.gladman.me.uk/cryptography_technology/fileencrypt/
 * have "gladman_" prepended to them.
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
#include <assert.h>
#include <errno.h>
#include <ctype.h>

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
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1	// Tuned on core i7
#endif
static int omp_t = 1;
#endif
#include "gladman_hmac.h"
#include "memdbg.h"

#define KEY_LENGTH(mode)        (8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)       (4 * ((mode) & 3) + 4)

typedef struct my_salt_t {
	dyna_salt dsalt;
	uint32_t comp_len;
	struct {
		uint16_t type     : 4;
		uint16_t mode : 4;
	} v;
	unsigned char passverify[2];
	unsigned char salt[SALT_LENGTH(3)];
	//uint64_t data_key; // MSB of md5(data blob).  We lookup using this.
	unsigned char datablob[1];
} my_salt;


/* From gladman_fileenc.h */
#define PWD_VER_LENGTH         2
#define KEYING_ITERATIONS   1000
#define FORMAT_LABEL        "ZIP"
#define FORMAT_NAME         "WinZip"
#define FORMAT_TAG			"$zip2$"
#define FORMAT_CLOSE_TAG	"$/zip2$"
#define TAG_LENGTH			6
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1001
#define BINARY_SIZE         10
#define PLAINTEXT_LENGTH	125
#define BINARY_ALIGN        sizeof(ARCH_WORD_32)
#define SALT_SIZE           sizeof(my_salt*)
#define SALT_ALIGN          sizeof(my_salt*)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*crypt_key)[((BINARY_SIZE+3)/4)*4];

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

static struct fmt_tests zip_tests[] = {
	{"$zip2$*0*1*0*9ffba76344938a7d*cc41*210*fb28d3fd983302058c5296c07442502ae05bb59adb9eb2378cb0841efa227cd58f7076ec00bb5faaee24c3433763d715461d4e714cdd9d933f621d2cf6ae73d824414ca2126cfc608d8fc7641d2869afa90f28be7113c71c6b6a3ad6d6633173cde9d7c1bb449cc0a1f8cbab8639255684cd25cb363234f865d9224f4065c0c62e5e60c2500bc78fa903630ccbb5816be2ef5230d411051d7bc54ecdf9dcbe500e742da2a699de0ec1f20b256dbcd506f926e91a1066a74b690f9dd50bd186d799deca428e6230957e2c6fcdcec73927d77bb49699a80e9c1540a13899ecb0b635fb728e1ade737895d3ff9babd4927bbbc296ec92bab87fd7930db6d55e74d610aef2b6ad19b7db519c0e7a257f9f78538bb0e9081c8700f7e8cd887f15a212ecb3d5a221cb8fe82a22a3258703f3c7af77ef5ecf25b4e6fb4118b00547c271d9b778b825247a4cd151bff81436997818f9d3c95155910ff152ad28b0857dcfc943e32729379c634d29a50655dc05fb63fa5f20c9c8cbdc630833a97f4f02792fcd6b1b73bfb4d333485bb0eb257b9db0481d11abfa06c2e0b82817d432341f9bdf2385ede8ca5d94917fa0bab9c2ed9d26ce58f83a93d418aa27a88697a177187e63f89904c0b9053151e30a7855252dab709aee47a2a8c098447160c8f96c56102067d9c8ffc4a74cd9011a2522998da342448b78452c6670eb7eb80ae37a96ca15f13018e16c93d515d75e792f49*bd2e946811c4c5b09694*$/zip2$", "hello1"},
	{"$zip2$*0*3*0*855f69693734c7be8c1093ea5bae6114*f035*210*c02aa1d42cc7623c0746979c6c2ce78e8492e9ab1d0954b76d328c52c4d555fbdc2af52822c7b6f4548fc5cca615cd0510f699d4b6007551c38b4183cafba7b073a5ba86745f0c3842896b87425d5247d3b09e0f9f701b50866e1636ef62ee20343ea6982222434fdaf2e52fe1c90f0c30cf2b4528b79abd2824e14869846c26614d9cbc156964d63041bfab66260821bedc151663adcb2c9ac8399d921ddac06c9a4cd8b442472409356cfe0655c9dbbec36b142611ad5604b68108be3321b2324d5783938e52e5c15ec4d8beb2b5010fad66d8cf6a490370ec86878ad2b393c5aa4523b95ae21f8dd5f0ae9f24581e94793a01246a4cc5a0f772e041b3a604ae334e43fe41d32058f857c227cee567254e9c760d472af416abedf8a87e67b309d30bc94d77ef6617b0867976a4b3824c0c1c4aa2b2668f9eb70c493d20d7fab69436c59e47db40f343d98a3b7503e07969d26afa92552d15009542bf2af9b47f2cfa0c2283883e99d0966e5165850663a2deed557fb8554a16f3a9cb04b9010c4b70576b18695dfea973aa4bc607069a1d90e890973825415b717c7bdf183937fa8a3aa985be1eadc8303f756ebd07f864082b775d7788ee8901bb212e69f01836d45db320ff1ea741fa8a3c13fa49ebc34418442e6bd8b1845c56d5c798767c92a503228148a6db44a08fc4a1c1d55eea73dbb2bd4f2ab09f00b043ee0df740681f5c5579ecbb1dbb7f7f3f67ffe2*c6b781ef18c5ccd83869*$/zip2$", "hello1"},
#if 0
//   This signature is specific to JimF.  I have left it commented here.  We can
//   add one, to the unused, if we choose to, BUT the problem is that it requires
//   a path that can be found.  I have tested this (at least it 'worked' for this
//   one.  Hopefully it is working fully.  If not, I will fix whatever problems it has.
#ifdef _MSC_VER
	{"$zip2$*0*1*0*9bdb664673e9a944*e25a*c5*ZFILE*/phpbb/johnripper/bleeding/winz128.zip*1004*1050*925583ab1f1cdb901097*$/zip2$", "hello1"},
#else
	{"$zip2$*0*1*0*9bdb664673e9a944*e25a*c5*ZFILE*/c/phpbb/johnripper/bleeding/winz128.zip*1004*1050*925583ab1f1cdb901097*$/zip2$", "hello1"},
#endif
#endif
	{NULL}
};

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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

static const char *ValidateZipFileData(u8 *Fn, u8 *Oh, u8 *Ob, unsigned len, u8 *Auth) {
	u32 id, i;
	long off;
	unsigned char bAuth[10], b;
	static char tmp[8192+256]; // 8192 size came from zip2john.  That is max path it can put into a filename
	FILE *fp;

	fp = fopen((c8*)Fn, "rb"); /* have to open in bin mode for OS's where this matters, DOS/Win32 */
	if (!fp) {
		/* this error is listed, even if not in pkzip debugging mode. */
		snprintf(tmp, sizeof(tmp), "Error loading a zip-aes hash line. The ZIP file '%s' could NOT be found\n", Fn);
		return tmp;
	}

	sscanf((char*)Oh, "%lx", &off);
	if (fseek(fp, off, SEEK_SET) != 0) {
		fclose(fp);
		snprintf(tmp, sizeof(tmp), "Not able to seek to specified offset in the .zip file %s, to read the zip blob data.", Fn);
		return tmp;
	}

	id = fget32LE(fp);
	if (id != 0x04034b50U) {
		fclose(fp);
		snprintf(tmp, sizeof(tmp), "Compressed zip file offset does not point to start of zip blob in file %s", Fn);
		return tmp;
	}

	sscanf((char*)Ob, "%lx", &off);
	off += len;
	if (fseek(fp, off, SEEK_SET) != 0) {
		fclose(fp);
		snprintf(tmp, sizeof(tmp), "Not enough data in .zip file %s, to read the zip blob data.", Fn);
		return tmp;
	}
	if (fread(bAuth, 1, 10, fp) != 10) {
		fclose(fp);
		snprintf(tmp, sizeof(tmp), "Not enough data in .zip file %s, to read the zip authentication data.", Fn);
		return tmp;
	}
	fclose(fp);
	for (i = 0; i < 10; ++i) {
		b = (atoi16[ARCH_INDEX(Auth[i*2])]<<4) + atoi16[ARCH_INDEX(Auth[i*2+1])];
		if (b != bAuth[i]) {
			snprintf(tmp, sizeof(tmp), "Authentication record in .zip file %s, did not match.", Fn);
			return tmp;
		}
	}
	return "";
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	u8 *ctcopy, *keeptr, *p, *cp, *Fn=0, *Oh=0, *Ob=0;
	const char *sFailStr="Truncated hash, pkz_GetFld() returned NULL";
	unsigned val;
	int ret = 0;
	int zip_file_validate=0;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) || ciphertext[TAG_LENGTH] != '*')
		return 0;
	if (!(ctcopy = (u8*)strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;

	p = &ctcopy[TAG_LENGTH+1];
	if ((p = pkz_GetFld(p, &cp)) == NULL)		// type
		goto Bail;
	if (!cp || *cp != '0') { sFailStr = "Out of data, reading count of hashes field"; goto Bail; }

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// mode
		goto Bail;
	if (cp[1] || *cp < '1' || *cp > '3') {
		sFailStr = "Invalid aes mode (only valid for 1 to 3)"; goto Bail; }
	val = *cp - '0';

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// file_magic enum (ignored for now, just a place holder)
		goto Bail;

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// salt
		goto Bail;
	if (!pkz_is_hex_str(cp) || strlen((char*)cp) != SALT_LENGTH(val)<<1)  {
		sFailStr = "Salt invalid or wrong length"; goto Bail; }

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// validator
		goto Bail;
	if (!pkz_is_hex_str(cp) || strlen((char*)cp) != 4)  {
		sFailStr = "Validator invalid or wrong length (4 bytes hex)"; goto Bail; }

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// Data len.
		goto Bail;
	if (!pkz_is_hex_str(cp))  {
		sFailStr = "Data length invalid (not hex number)"; goto Bail; }
	sscanf((const char*)cp, "%x", &val);

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// data blob, OR file structure
		goto Bail;
	if (!strcmp((char*)cp, "ZFILE")) {
		if ((p = pkz_GetFld(p, &Fn)) == NULL)
			goto Bail;
		if ((p = pkz_GetFld(p, &Oh)) == NULL)
			goto Bail;
		if ((p = pkz_GetFld(p, &Ob)) == NULL)
			goto Bail;
		zip_file_validate = 1;
	} else {
		if (!pkz_is_hex_str(cp) || strlen((char*)cp) != val<<1)  {
			sFailStr = "Inline data blob invalid (not hex number), or wrong length"; goto Bail; }
	}

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// authentication_code
		goto Bail;
	if (!pkz_is_hex_str(cp) || strlen((char*)cp) != BINARY_SIZE<<1)  {
		sFailStr = "Authentication data invalid (not hex number), or not 20 hex characters"; goto Bail; }

	// Ok, now if we have to pull from .zip file, lets do so, and we can validate with the authentication bytes
	if (zip_file_validate) {
		sFailStr = ValidateZipFileData(Fn, Oh, Ob, val, cp);
		if (*sFailStr) {
			/* this error is listed, even if not in pkzip debugging mode. */
			fprintf(stderr, "zip-aes file validation failed [%s] Hash is %s\n", sFailStr, ciphertext);
			return 0;
		}
	}

	if ((p = pkz_GetFld(p, &cp)) == NULL)		// Trailing signature
		goto Bail;
	if (strcmp((char*)cp, FORMAT_CLOSE_TAG)) {
		sFailStr = "Invalid trailing zip2 signature"; goto Bail; }
	ret = 1;

Bail:;
#ifdef ZIP_DEBUG
	fprintf (stderr, "pkzip validation failed [%s]  Hash is %s\n", sFailStr, ciphertext);
#endif
	MEM_FREE(keeptr);
	return ret;
}

static void *binary(char *ciphertext) {
	static union {
		unsigned char buf[10];
		unsigned x;
	} x;
	unsigned char *bin = x.buf;
	char *c = strrchr(ciphertext, '*')-2*BINARY_SIZE;
	int i;

	for (i = 0; i < BINARY_SIZE; ++i) {
		bin[i] = atoi16[ARCH_INDEX(c[i<<1])] << 4 | atoi16[ARCH_INDEX(c[(i<<1)+1])];
	}
	return bin;
}

static void *get_salt(char *ciphertext)
{
	int i;
	my_salt salt, *psalt;
	static unsigned char *ptr;
	/* extract data from "ciphertext" */
	u8 *copy_mem = (u8*)strdup(ciphertext);
	u8 *cp, *p;

	if (!ptr) ptr = mem_alloc_tiny(sizeof(my_salt*),sizeof(my_salt*));
	p = copy_mem + TAG_LENGTH+1; /* skip over "$zip2$*" */
	memset(&salt, 0, sizeof(salt));
	p = pkz_GetFld(p, &cp); // type
	salt.v.type = atoi((const char*)cp);
	p = pkz_GetFld(p, &cp); // mode
	salt.v.mode = atoi((const char*)cp);
	p = pkz_GetFld(p, &cp); // file_magic enum (ignored)
	p = pkz_GetFld(p, &cp); // salt
	for (i = 0; i < SALT_LENGTH(salt.v.mode); i++)
		salt.salt[i] = (atoi16[ARCH_INDEX(cp[i<<1])]<<4) | atoi16[ARCH_INDEX(cp[(i<<1)+1])];
	p = pkz_GetFld(p, &cp);	// validator
	salt.passverify[0] = (atoi16[ARCH_INDEX(cp[0])]<<4) | atoi16[ARCH_INDEX(cp[1])];
	salt.passverify[1] = (atoi16[ARCH_INDEX(cp[2])]<<4) | atoi16[ARCH_INDEX(cp[3])];
	p = pkz_GetFld(p, &cp);	// data len
	sscanf((const char *)cp, "%x", &salt.comp_len);

	// later we will store the data blob in our own static data structure, and place the 64 bit LSB of the
	// MD5 of the data blob into a field in the salt. For the first POC I store the entire blob and just
	// make sure all my test data is small enough to fit.

	p = pkz_GetFld(p, &cp);	// data blob

	// Ok, now create the allocated salt record we are going to return back to John, using the dynamic
	// sized data buffer.
	psalt = (my_salt*)mem_calloc(1, sizeof(my_salt)+salt.comp_len);
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
		u8 *Fn, *Oh, *Ob;
		long len;
		uint32_t id;
		FILE *fp;

		p = pkz_GetFld(p, &Fn);
		p = pkz_GetFld(p, &Oh);
		p = pkz_GetFld(p, &Ob);

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
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int get_hash_0(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & 0x7ffffff; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

	if (saved_salt->v.type) {
		// This salt passed valid() but failed get_salt().
		// Should never happen.
		memset(crypt_key, 0, count * BINARY_SIZE);
		return count;
	}

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, saved_key, saved_salt, crypt_key)
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned char pwd_ver[(2+64)*MAX_KEYS_PER_CRYPT];
		int lens[MAX_KEYS_PER_CRYPT], i;
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = &pwd_ver[i*(2+2*KEY_LENGTH(saved_salt->v.mode))];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, saved_salt->salt, SALT_LENGTH(saved_salt->v.mode), KEYING_ITERATIONS, pout, 2+2*KEY_LENGTH(saved_salt->v.mode), 0);
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			if (!memcmp(&(pout[i][KEY_LENGTH(saved_salt->v.mode)<<1]), saved_salt->passverify, 2))
			{
				// yes, I know gladman's code but for now that is what I am using.  Later we will improve.
				hmac_sha1(&(pout[i][KEY_LENGTH(saved_salt->v.mode)]), KEY_LENGTH(saved_salt->v.mode),
						   (const unsigned char*)saved_salt->datablob, saved_salt->comp_len,
						   crypt_key[index+i], BINARY_SIZE);
			}
			else
				memset(crypt_key[index+i], 0, BINARY_SIZE);
		}
#else
		int LEN = 2+2*KEY_LENGTH(saved_salt->v.mode);
		union {
			// MUST be aligned on 4 byte boundary for alter endianity on BE
			// we also need 2 extra bytes for endianity flipping.
			unsigned char pwd_ver[4+64];
			ARCH_WORD_32 w;
		} x;
		unsigned char *pwd_ver = x.pwd_ver;
#if !ARCH_LITTLE_ENDIAN
		LEN += 2;
#endif
		pbkdf2_sha1((unsigned char *)saved_key[index],
		       strlen(saved_key[index]), saved_salt->salt, SALT_LENGTH(saved_salt->v.mode),
		       KEYING_ITERATIONS, pwd_ver, LEN, 0);
#if !ARCH_LITTLE_ENDIAN
		alter_endianity(pwd_ver, LEN);
#endif
		if (!memcmp(&(pwd_ver[KEY_LENGTH(saved_salt->v.mode)<<1]), saved_salt->passverify, 2))
		{
			// yes, I know gladman's code but for now that is what I am using.  Later we will improve.
			hmac_sha1(&(pwd_ver[KEY_LENGTH(saved_salt->v.mode)]), KEY_LENGTH(saved_salt->v.mode),
                       (const unsigned char*)saved_salt->datablob, saved_salt->comp_len,
                       crypt_key[index], BINARY_SIZE);
		}
		else
			memset(crypt_key[index], 0, BINARY_SIZE);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (((ARCH_WORD_32*)&(crypt_key[i]))[0] == ((ARCH_WORD_32*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((ARCH_WORD_32*)&(crypt_key[index]))[0] == ((ARCH_WORD_32*)binary)[0]);
}

static int cmp_exact(char *source, int index)
{
	void *b = binary(source);
	return !memcmp(b, crypt_key[index], sizeof(crypt_key[index]));
}

struct fmt_main fmt_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		4, // BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		zip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,  // to add
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_dyna_salt_hash,
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
