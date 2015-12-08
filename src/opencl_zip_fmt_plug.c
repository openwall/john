/*
 *
 * This software is Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>
 * with some code (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and improvements (c) 2014 by magnum and JimF.
 *
 * This is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_zip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_zip);
#else

#include <string.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "common-opencl.h"
#include "pkzip.h"
#include "dyna_salt.h"
#include "hmac_sha.h"
#include "options.h"
#include "stdint.h"

#define FORMAT_LABEL		"zip-opencl"
#define FORMAT_NAME		"ZIP"
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL AES"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1001
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define BINARY_SIZE		10
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(my_salt*)
#define SALT_ALIGN		4

#define FORMAT_TAG		"$zip2$"
#define FORMAT_CLOSE_TAG	"$/zip2$"
#define TAG_LENGTH		6

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} zip_password;

typedef struct {
	uint32_t v[(2 * KEY_LENGTH(3) + PWD_VER_LENGTH + 3) / 4];
} zip_hash;

typedef struct {
	int     iterations;
	int     outlen;
	uint8_t length;
	uint8_t salt[64];
} zip_salt;

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

static my_salt *saved_salt;

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

static unsigned char (*crypt_key)[BINARY_SIZE];

static cl_int cl_error;
static zip_password *inbuffer;
static zip_hash *outbuffer;
static zip_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

static size_t insize, outsize, settingsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(zip_password) * gws;
	outsize = sizeof(zip_hash) * gws;
	settingsize = sizeof(zip_salt);

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	crypt_key = mem_calloc(gws, sizeof(*crypt_key));

	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (crypt_key) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(crypt_key);
		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
		         PLAINTEXT_LENGTH,
		         (int)sizeof(currentsalt.salt),
		         (int)sizeof(outbuffer->v));
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "derive_key", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
		                       self, create_clobj, release_clobj,
		                       sizeof(zip_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static const char *ValidateZipFileData(c8 *Fn, c8 *Oh, c8 *Ob, unsigned len, c8 *Auth) {
	u32 id, i;
	long off;
	unsigned char bAuth[10], b;
	static char tmp[8192+256]; // 8192 size came from zip2john.  That is max path it can put into a filename
	FILE *fp;

	fp = fopen(Fn, "rb"); /* have to open in bin mode for OS's where this matters, DOS/Win32 */
	if (!fp) {
		/* this error is listed, even if not in pkzip debugging mode. */
		snprintf(tmp, sizeof(tmp), "Error loading a zip-aes hash line. The ZIP file '%s' could NOT be found\n", Fn);
		return tmp;
	}

	sscanf(Oh, "%lx", &off);
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

	sscanf(Ob, "%lx", &off);
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
	c8 *ctcopy, *keeptr, *p, *cp, *Fn=0, *Oh=0, *Ob=0;
	const char *sFailStr="Truncated hash, strtokm() returned NULL";
	unsigned val;
	int ret = 0;
	int zip_file_validate=0;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) || ciphertext[TAG_LENGTH] != '*')
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;

	p = &ctcopy[TAG_LENGTH+1];

	// type
	if ((cp = strtokm(p, "*")) == NULL || !cp || *cp != '0') {
		sFailStr = "Out of data, reading count of hashes field"; goto Bail; }

	// mode
	if ((cp = strtokm(NULL, "*")) == NULL || cp[1] || *cp < '1' || *cp > '3') {
		sFailStr = "Invalid aes mode (only valid for 1 to 3)"; goto Bail; }
	val = *cp - '0';

	if ((cp = strtokm(NULL, "*")) == NULL)		// file_magic enum (ignored for now, just a place holder)
		goto Bail;

	// salt
	if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen((char*)cp) != SALT_LENGTH(val)<<1)  {
		sFailStr = "Salt invalid or wrong length"; goto Bail; }

	// validator
	if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen((char*)cp) != 4)  {
		sFailStr = "Validator invalid or wrong length (4 bytes hex)"; goto Bail; }

	// Data len.
	if ((cp = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp))  {
		sFailStr = "Data length invalid (not hex number)"; goto Bail; }
	sscanf((const char*)cp, "%x", &val);

	if ((cp = strtokm(NULL, "*")) == NULL)		// data blob, OR file structure
		goto Bail;
	if (!strcmp((char*)cp, "ZFILE")) {
		if ((Fn = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp))
			goto Bail;
		if ((Oh = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp))
			goto Bail;
		if ((Ob = strtokm(NULL, "*")) == NULL || !cp[0] || !ishexlc_oddOK(cp))
			goto Bail;
		zip_file_validate = 1;
	} else {
		if (!ishexlc(cp) || strlen((char*)cp) != val<<1)  {
			sFailStr = "Inline data blob invalid (not hex number), or wrong length"; goto Bail; }
	}

	// authentication_code
	if ((cp = strtokm(NULL, "*")) == NULL || !ishexlc(cp) || strlen((char*)cp) != BINARY_SIZE<<1)  {
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

	// Trailing signature
	if ((cp = strtokm(NULL, "*")) == NULL || strcmp((char*)cp, FORMAT_CLOSE_TAG)) {
		sFailStr = "Invalid trailing zip2 signature"; goto Bail; }
	if ((strtokm(NULL, "*")) != NULL) {
		sFailStr = "Trailing crap after pkzip hash, ignored"; goto Bail; }

	ret = 1;

Bail:;
#ifdef ZIP_DEBUG
	fprintf (stderr, "pkzip validation failed [%s]  Hash is %s\n", sFailStr, ciphertext);
#endif
	MEM_FREE(keeptr);
	return ret;
}

static void *get_binary(char *ciphertext) {
	static unsigned buf[(BINARY_SIZE+sizeof(unsigned)-1)/sizeof(unsigned)];
	unsigned char *bin = (unsigned char*)buf;
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
	c8 *copy_mem = strdup(ciphertext);
	c8 *cp, *p;

	if (!ptr) ptr = mem_alloc_tiny(sizeof(my_salt*),sizeof(my_salt*));
	p = copy_mem + TAG_LENGTH+1; /* skip over "$zip2$*" */
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
	sscanf((const char *)cp, "%x", &salt.comp_len);

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

	memcpy((char*)currentsalt.salt, saved_salt->salt, SALT_LENGTH(saved_salt->v.mode));
	currentsalt.length = SALT_LENGTH(saved_salt->v.mode);
	currentsalt.iterations = KEYING_ITERATIONS;
	currentsalt.outlen = 2 * KEY_LENGTH(saved_salt->v.mode) + PWD_VER_LENGTH;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
	               CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	               "Copy setting to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (saved_salt->v.type) {
		// This salt passed valid() but failed get_salt().
		// Should never happen.
		memset(crypt_key, 0, count * BINARY_SIZE);
		return count;
	}

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (!memcmp(&((unsigned char*)outbuffer[index].v)[2 * KEY_LENGTH(saved_salt->v.mode)], saved_salt->passverify, 2))
			hmac_sha1(&((unsigned char*)outbuffer[index].v)[KEY_LENGTH(saved_salt->v.mode)],
			          KEY_LENGTH(saved_salt->v.mode),
			          (const unsigned char*)saved_salt->datablob,
			          saved_salt->comp_len,
			          crypt_key[index], BINARY_SIZE);
		else
			memset(crypt_key[index], 0, BINARY_SIZE);
	}

	return count;
}

static int get_hash_0(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)&(crypt_key[index]))[0] & PH_MASK_6; }

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
	void *b = get_binary(source);
	return !memcmp(b, crypt_key[index], sizeof(crypt_key[index]));
}

struct fmt_main fmt_opencl_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT,
		{ NULL },
		zip_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
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

#endif /* HAVE_OPENCL */
