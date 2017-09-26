/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for GPG format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Converted to use 'common' code, Feb29-Mar1 2016, JimF.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_gpg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_gpg);
#else

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <openssl/blowfish.h>
#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "aes.h"
#include "idea-JtR.h"
#include "md5.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include "sha.h"
#include "common-opencl.h"
#include "options.h"
#include "sha2.h"
#include "gpg_common.h"

#define FORMAT_LABEL		"gpg-opencl"
#define FORMAT_NAME		"OpenPGP / GnuPG Secret Key"
#define ALGORITHM_NAME		"SHA1 OpenCL"
#define SALT_SIZE		sizeof(struct gpg_common_custom_salt*)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} gpg_password;

typedef struct {
	uint8_t v[32];
} gpg_hash;

typedef struct {
	uint32_t length;
	uint32_t count;
	uint32_t key_len;
	uint8_t salt[SALT_LENGTH];
} gpg_salt;

struct fmt_tests gpg_tests[] = {  // from GPU
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*667*2048*387de4c9e2c1018aed84af75922ecaa92d1bc68d48042144c77dfe168de1fd654e4db77bfbc60ec68f283483382413cbfddddcfad714922b2d558f8729f705fbf973ab1839e756c26207a4bc8796eeb567bf9817f73a2a81728d3e4bc0894f62ad96e04e60752d84ebc01316703b0fd0f618f6120289373347027924606712610c583b25be57c8a130bc4dd796964f3f03188baa057d6b8b1fd36675af94d45847eeefe7fff63b755a32e8abe26b7f3f58bb091e5c7b9250afe2180b3d0abdd2c1db3d4fffe25e17d5b7d5b79367d98c523a6c280aafef5c1975a42fd97242ba86ced73c5e1a9bcab82adadd11ef2b64c3aad23bc930e62fc8def6b1d362e954795d87fa789e5bc2807bfdc69bba7e66065e3e3c2df0c25eab0fde39fbe54f32b26f07d88f8b05202e55874a1fa37d540a5af541e28370f27fe094ca8758cd7ff7b28df1cbc475713d7604b1af22fd758ebb3a83876ed83f003285bc8fdc7a5470f7c5a9e8a93929941692a9ff9f1bc146dcc02aab47e2679297d894f28b62da16c8baa95cd393d838fa63efc9d3f88de93dc970c67022d5dc88dce25decec8848f8e6f263d7c2c0238d36aa0013d7edefd43dac1299a54eb460d9b82cb53cf86fcb7c8d5dba95795a1adeb729a705b47b8317594ac3906424b2c0e425343eca019e53d927e6bc32688bd9e87ee808fb1d8eeee8ab938855131b839776c7da79a33a6d66e57eadb430ef04809009794e32a03a7e030b8792be5d53ceaf480ffd98633d1993c43f536a90bdbec8b9a827d0e0a49155450389beb53af5c214c4ec09712d83b175671358d8e9d54da7a8187f72aaaca5203372841af9b89a07b8aadecafc0f2901b8aec13a5382c6f94712d629333b301afdf52bdfa62534de2b10078cd4d0e781c88efdfe4e5252e39a236af449d4d62081cee630ab*3*254*2*3*8*b1fdf3772bb57e1f*65536*2127ccd55e721ba0", "polished"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*e5f3ef815854f90dfdc3ad61c9c92e512a53d7203b8a5665a8b00ac5ed92340a6ed74855b976fc451588cc5d51776b71657830f2c311859022a25412ee6746622febff8184824454c15a50d64c18b097af28d3939f5c5aa9589060f25923b8f7247e5a2130fb8241b8cc07a33f70391de7f54d84703d2537b4d1c307bdf824c6be24c6e36501e1754cc552551174ed51a2f958d17c6a5bd3b4f75d7979537ee1d5dcd974876afb93f2bcda7468a589d8dba9b36afbe019c9086d257f3f047e3ff896e52783f13219989307bf277e04a5d949113fc4efcc747334f307a448b949ee61b1db326892a9198789f9253994a0412dd704d9e083000b63fa07096d9d547e3235f7577ecd49199c9c3edfa3e43f65d6c506363d23c21561707f790e17ea25b7a7fce863b3c952218a3ac649002143c9b02df5c47ed033b9a1462d515580b10ac79ebdca61babb020400115f1e9fad26318a32294034ea4cbaf681c7b1de12c4ddb99dd4e39e6c8f13a322826dda4bb0ad22981b17f9e0c4d50d7203e205fb2ee6ded117a87e47b58f58f442635837f2debc6fcfbaebba09cff8b2e855d48d9b96c9a9fb020f66c97dffe53bba316ef756c797557f2334331eecaedf1ab331747dc0af6e9e1e4c8e2ef9ed2889a5facf72f1c43a24a6591b2ef5128ee872d299d32f8c0f1edf2bcc35f453ce27c534862ba2c9f60b65b641e5487f5be53783d79e8c1e5f62fe336d8854a8121946ea14c49e26ff2b2db36cef81390da7b7a8d31f7e131dccc32e6828a32b13f7a56a28d0a28afa8705adbf60cb195b602dd8161d8b6d8feff12b16eb1ac463eaa6ae0fd9c2d906d43d36543ef33659a04cf4e69e99b8455d666139e8860879d7e933e6c5d995dd13e6aaa492b21325f23cbadb1bc0884093ac43651829a6fe5fe4c138aff867eac253569d0dc6*3*254*2*3*8*e318a03635a19291*65536*06af8a67764f5674", "blingbling"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*8487ca407790457c30467936e109d968bdff7fa4f4d87b0af92e2384627ca546f2898e5f77c00300db87a3388476e2de74f058b8743c2d59ada316bc81c79fdd31e403e46390e3e614f81187fb0ae4ca26ed53a0822ace48026aa8a8f0abdf17d17d72dfa1eba7a763bbd72f1a1a8c020d02d7189bd95b12368155697f5e4e013f7c81f671ca320e72b61def43d3e2cb3d23d105b19fe161f2789a3c81363639b4258c855c5acd1dd6596c46593b2bfec23d319b58d4514196b2e41980fbb05f376a098049f3258f9cdf1628c6ff780963e2c8dc26728d33c6733fbac6e415bd16d924a087269e8351dd1c6129d1ac7925f19d7c9a9ed3b08a53e207ffbfba1d43891da68e39749775b38cbe9e6831def4b4297ce7446d09944583367f58205a4f986d5a84c8cf3871a7e2b6c4e2c94ff1df51cd94aecf7a76cd6991a785c66c78f686e6c47add9e27a6b00a2e709f1383f131e3b83b05c812b2ec76e732d713b780c381b0785f136cd00de7afa0276c95c5f0bb3a4b6ad484d56e390c11f9d975729ae1665189190fd131f49109f899735fd2c2efbafd8b971b196d18aeff70decc9768381f0b2243a05db99bd5911d5b94770ee315e1fe3ab0e090aa460d2c8d06a06fef254fd5fa8967386f1f5d37ea6f667215965eefe3fc6bc131f2883c02925a2a4f05dabc48f05867e68bb68741b6fb3193b7c51b7d053f6fd45108e496b9f8f2810fa75ffe454209e2249f06cc1bfc838a97436ebd64001b9619513bcb519132ce39435ed0d7c84ec0c6013e786eef5f9e23738debc70a68a389040e8caad6bd5bb486e43395e570f8780d3f1d837d2dc2657bbded89f76b06c28c5a58ecaa25a225d3d4513ee8dc8655907905590737b971035f690ac145b2d4322ecc86831f36b39d1490064b2aa27b23084a3a0b029e49a52b6a608219*3*254*2*3*8*0409f810febe5e05*65536*ce0e64511258eecc", "njokuani."},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*348*1024*e5fbff62d94b41de7fc9f3dd93685aa6e03a2c0fcd75282b25892c74922ec66c7327933087304d34d1f5c0acca5659b704b34a67b0d8dedcb53a10aee14c2615527696705d3ab826d53af457b346206c96ef4980847d02129677c5e21045abe1a57be8c0bf7495b2040d7db0169c70f59994bba4c9a13451d38b14bd13d8fe190cdc693ee207d8adfd8f51023b7502c7c8df5a3c46275acad6314d4d528df37896f7b9e53adf641fe444e18674d59cf46d5a6dffdc2f05e077346bf42fe35937e95f644a58a2370012d993c5008e6d6ff0c66c6d0d0b2f1c22961b6d12563a117897675f6b317bc71e4f2dbf6b9fff23186da2724a584d70401136e8c500784df462ea6548db4eecc782e79afe52fd8c1106c7841c085b8d44465d7a1910161d6c707a377a72f85c39fcb4ee58e6b2f617b6c4b173a52f171854f0e1927fa9fcd9d5799e16d840f06234698cfc333f0ad42129e618c2b9c5b29b17b7*3*254*2*3*8*7353cf09958435f9*9961472*efadea6cd5f3e5a7", "openwall"},
	/* SHA1-CAST5 salt-iter */
	{"$gpg$*1*668*2048*97b296b60904f6d505344b5b0aa277b0f40de05788a39cd9c39b14a56b607bd5db65e8da6111149a1725d06a4b52bdddf0e467e26fe13f72aa5570a0ea591eec2e24d3e9dd7534f26ec9198c8056ea1c03a88161fec88afd43474d31bf89756860c2bc6a6bc9e2a4a2fc6fef30f8cd2f74da6c301ccd5863f3240d1a2db7cbaa2df3a8efe0950f6200cbc10556393583a6ebb2e041095fc62ae3a9e4a0c5c830d73faa72aa8167b7b714ab85d927382d77bbfffb3f7c8184711e81cf9ec2ca03906e151750181500238f7814d2242721b2307baa9ea66e39b10a4fdad30ee6bff50d79ceac604618e74469ae3c80e7711c16fc85233a9eac39941a564b38513c1591502cde7cbd47a4d02a5d7d5ceceb7ff920ee40c29383bd7779be1e00b60354dd86ca514aa30e8f1523efcffdac1292198fe96983cb989a259a4aa475ed9b4ce34ae2282b3ba0169b2e82f9dee476eff215db33632cdcc72a65ba2e68d8e3f1fed90aaa68c4c886927b733144fb7225f1208cd6a108e675cc0cb11393db7451d883abb6adc58699393b8b7b7e19c8584b6fc95720ced39eabaa1124f423cc70f38385c4e9c4b4eeb39e73e891da01299c0e6ce1e97e1750a5c615e28f486c6a0e4da52c15285e7cf26ac859f5f4190e2804ad81ba4f8403e6358fbf1d48c7d593c3bac20a403010926877db3b9d7d0aaacd713a2b9833aff88d1e6b4d228532a66fe68449ad0d706ca7563fe8c2ec77062cc33244a515f2023701c052f0dd172b7914d497fdaefabd91a199d6cb2b62c71472f52c65d6a67d97d7713d39e91f347d2bc73b421fb5c6c6ba028555e5a92a535aabf7a4234d6ea8a315d8e6dcc82087cc76ec8a7b2366cecf176647538968e804541b79a1b602156970d1b943eb2641f2b123e45d7cace9f2dc84b704938fa8c7579a859ef87eca46*3*254*2*3*8*d911a3f73b050340*2097152*347e15bee29eb77d", "password"},
	/* SHA1-CAST5 salt-iter, DSA key */
	{"$gpg$*17*42*1024*d974ae70cfbf8ab058b2e1d898add67ab1272535e8c4b9c5bd671adce22d08d5db941a60e0715b4f0c9d*3*254*2*3*8*a9e85673bb9199d8*11534336*71e35b85cddfe2af", "crackme"},
	{NULL}
};

static int *cracked;
static int any_cracked;

static cl_int cl_error;
static gpg_password *inbuffer;
static gpg_hash *outbuffer;
static gpg_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

size_t insize, outsize, settingsize, cracked_size;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(gpg_password) * gws;
	outsize = sizeof(gpg_hash) * gws;
	settingsize = sizeof(gpg_salt);
	cracked_size = sizeof(*cracked) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	cracked = mem_calloc(1, cracked_size);

	// Allocate memory
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
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
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
		         "-DPLAINTEXT_LENGTH=%d -DSALT_LENGTH=%d",
		         PLAINTEXT_LENGTH, SALT_LENGTH);
		opencl_init("$JOHN/kernels/gpg_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "gpg", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(gpg_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 300);
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	return gpg_common_valid(ciphertext, self, 0);
}

static void set_salt(void *salt)
{
	gpg_common_cur_salt = *(struct gpg_common_custom_salt **)salt;
	currentsalt.length = SALT_LENGTH;
	memcpy((char*)currentsalt.salt, gpg_common_cur_salt->salt, currentsalt.length);
	currentsalt.count = gpg_common_cur_salt->count;
	currentsalt.key_len = gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint32_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	if (gpg_common_check(outbuffer[index].v, gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm)))
	{
		cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
		any_cracked |= 1;
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

/*
 * Report gpg --s2k-count n as 1st tunable cost,
 * hash algorithm as 2nd tunable cost,
 * cipher algorithm as 3rd tunable cost.
 */

struct fmt_main fmt_opencl_gpg = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"s2k-count", /* only for gpg --s2k-mode 3, see man gpg, option --s2k-count n */
			"hash algorithm [2:SHA1]",
			"cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]",
		},
		{ FORMAT_TAG },
		gpg_tests
	},
	{
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		gpg_common_get_salt,
		{
			gpg_common_gpg_s2k_count,
			gpg_common_gpg_hash_algorithm,
			gpg_common_gpg_cipher_algorithm,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

#endif /* HAVE_OPENCL */
