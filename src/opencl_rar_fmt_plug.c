/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav
 * and OMP, AES-NI and OpenCL support.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum and it is hereby released to the general public
 * under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 * Huge thanks to Marc Bevand <m.bevand (at) gmail.com> for releasing unrarhp
 * (http://www.zorinaq.com/unrarhp/) and documenting the RAR encryption scheme.
 * This patch is made possible by unrarhp's documentation.
 *
 * http://anrieff.net/ucbench/technical_qna.html is another useful reference
 * for RAR encryption scheme.
 *
 * Thanks also to Pavel Semjanov for crucial help with Huffman table checks.
 *
 * For type = 0 for files encrypted with "rar -hp ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(partial-file-contents):type::::archive_name
 *
 * For type = 1 for files encrypted with "rar -p ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*archive_name*offset-for-ciphertext*method:type::file_name
 *
 * or (inlined binary)
 *
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*1*hex(full encrypted file)*method:type::file_name
 *
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_rar;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_rar);
#else

#define STEP			0
#define SEED			256
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "arch.h"
#include "sha.h"

#if AC_BUILT
#include "autoconfig.h"
#endif
#if _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
#include "win32_memmap.h"
#ifndef __CYGWIN__
#include "mmap-windows.c"
#elif defined HAVE_MMAP
#include <sys/mman.h>
#endif
#elif defined(HAVE_MMAP)
#include <sys/mman.h>
#endif

#ifdef _OPENMP
#include <omp.h>
#include <pthread.h>
#ifndef OMP_SCALE
#define OMP_SCALE		32
#endif
static pthread_mutex_t *lockarray;
#endif

#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "dyna_salt.h"
#include "memory.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"
#include "unrar.h"
#include "common-opencl.h"
#include "config.h"
#include "jumbo.h"

#define FORMAT_LABEL		"rar-opencl"
#define FORMAT_NAME		"RAR3"
#define ALGORITHM_NAME		"SHA1 OpenCL AES"
#ifdef DEBUG
#define BENCHMARK_COMMENT	" (length 1-16)"
#else
#define BENCHMARK_COMMENT	" (length 4)"
#endif
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	22 /* Max. currently supported is 22 */
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		sizeof(rarfile*)
#define SALT_ALIGN		sizeof(rarfile*)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static const char * warn[] = {
	"key xfer: "  ,  ", len xfer: "   , ", init: " , ", loop: " ,
	", final: ", ", key xfer: ", ", iv xfer: "
};

static int split_events[] = { 3, -1, -1 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

#define ITERATIONS		0x40000
#define HASH_LOOPS		0x04000 // Fixed, do not change

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

static int omp_t = 1;
static unsigned char *saved_salt;
static unsigned char *saved_key;
static int new_keys;
static int (*cracked);
static unpack_data_t (*unpack_data);
static struct fmt_main *self;

static unsigned int *saved_len;
static unsigned char *aes_key;
static unsigned char *aes_iv;

typedef struct {
	dyna_salt dsalt; /* must be first. allows dyna_salt to work */
	/* place all items we are NOT going to use for salt comparison, first */
	unsigned char *blob;
	/* data from this point on, is part of the salt for compare reasons */
	unsigned char salt[8];
	int type;	/* 0 = -hp, 1 = -p */
	/* for rar -p mode only: */
	union {
		unsigned int w;
		unsigned char c[4];
	} crc;
	unsigned long long pack_size;
	unsigned long long unp_size;
	int method;
	unsigned char blob_hash[20]; // holds an sha1, but could be 'any' hash.
	// raw_data should be word aligned, and 'ok'
	unsigned char raw_data[1];
} rarfile;

static rarfile *cur_file;

/* Determines when to use CPU instead (eg. Single mode, few keys in a call) */
#define CPU_GPU_RATIO		32
static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_OutputBuf, cl_round, cl_aes_key, cl_aes_iv;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_salt, pinned_aes_key, pinned_aes_iv;
static cl_kernel RarInit, RarFinal;

/* cRARk use 4-char passwords for CPU benchmark */
static struct fmt_tests cpu_tests[] = {
	{"$RAR3$*0*b109105f5fe0b899*d4f96690b1a8fe1f120b0290a85a2121", "test"},
	{"$RAR3$*0*42ff7e92f24fb2f8*9d8516c8c847f1b941a0feef064aaf0d", "1234"},
	{"$RAR3$*0*56ce6de6ddee17fb*4c957e533e00b0e18dfad6accc490ad9", "john"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*1*c47c5bef0bbd1e98*965f1453*48*47*1*c5e987f81d316d9dcfdb6a1b27105ce63fca2c594da5aa2f6fdf2f65f50f0d66314f8a09da875ae19d6c15636b65c815*30", "test"},
	{"$RAR3$*1*b4eee1a48dc95d12*965f1453*64*47*1*0fe529478798c0960dd88a38a05451f9559e15f0cf20b4cac58260b0e5b56699d5871bdcc35bee099cc131eb35b9a116adaedf5ecc26b1c09cadf5185b3092e6*33", "test"},
#ifdef DEBUG
	/* Various lengths, these should be in self-test but not benchmark */
	/* from CMIYC 2012 */
	{"$RAR3$*1*0f263dd52eead558*834015cd*384*693*1*e28e9648f51b59e32f573b302f0e94aadf1050678b90c38dd4e750c7dd281d439ab4cccec5f1bd1ac40b6a1ead60c75625666307171e0fe2639d2397d5f68b97a2a1f733289eac0038b52ec6c3593ff07298fce09118c255b2747a02c2fa3175ab81166ebff2f1f104b9f6284a66f598764bd01f093562b5eeb9471d977bf3d33901acfd9643afe460e1d10b90e0e9bc8b77dc9ac40d40c2d211df9b0ecbcaea72c9d8f15859d59b3c85149b5bb5f56f0218cbbd9f28790777c39e3e499bc207289727afb2b2e02541b726e9ac028f4f05a4d7930efbff97d1ffd786c4a195bbed74997469802159f3b0ae05b703238da264087b6c2729d9023f67c42c5cbe40b6c67eebbfc4658dfb99bfcb523f62133113735e862c1430adf59c837305446e8e34fac00620b99f574fabeb2cd34dc72752014cbf4bd64d35f17cef6d40747c81b12d8c0cd4472089889a53f4d810b212fb314bf58c3dd36796de0feeefaf26be20c6a2fd00517152c58d0b1a95775ef6a1374c608f55f416b78b8c81761f1d*33:1::to-submit-challenges.txt", "wachtwoord"},
	{"$RAR3$*1*9759543e04fe3a22*834015cd*384*693*1*cdd2e2478e5153a581c47a201490f5d9b69e01584ae488a2a40203da9ba8c5271ed8edc8f91a7bd262bb5e5de07ecbe9e2003d054a314d16caf2ea1de9f54303abdee1ed044396f7e29c40c38e638f626442efd9f511b4743758cd4a6025c5af81d1252475964937d80bfd50d10c171e7e4041a66c02a74b2b451ae83b6807990fb0652a8cdab530c5a0c497575a6e6cbe2db2035217fe849d2e0b8693b70f3f97b757229b4e89c8273197602c23cc04ff5f24abf3d3c7eb686fc3eddce1bfe710cc0b6e8bd012928127da38c38dd8f056095982afacb4578f6280d51c6739739e033674a9413ca88053f8264c5137d4ac018125c041a3489daaf175ef75e9282d245b92948c1bbcf1c5f25b7028f6d207d87fe9598c2c7ccd1553e842a91ab8ca9261a51b14601a756070388d08039466dfa36f0b4c7ea7dd9ff25c9d98687203c58f9ec8757cafe4d2ed785d5a9e6d5ea838e4cc246a9e6d3c30979dcce56b380b05f9103e6443b35357550b50229c47f845a93a48602790096828d9d6bef0*33:1::to-submit-challenges.txt", "Sleepingbaby210"},
	{"$RAR3$*1*79e17c26407a7d52*834015cd*384*693*1*6844a189e732e9390b5a958b623589d5423fa432d756fd00940ac31e245214983507a035d4e0ee09469491551759a66c12150fe6c5d05f334fb0d8302a96d48ef4da04954222e0705507aaa84f8b137f284dbec344eee9cea6b2c4f63540c64df3ee8be3013466d238c5999e9a98eb6375ec5462869bba43401ec95077d0c593352339902c24a3324178e08fe694d11bfec646c652ffeafbdda929052c370ffd89168c83194fedf7c50fc7d9a1fbe64332063d267a181eb07b5d70a5854067db9b66c12703fde62728d3680cf3fdb9933a0f02bfc94f3a682ad5e7c428d7ed44d5ff554a8a445dea28b81e3a2631870e17f3f3c0c0204136802c0701590cc3e4c0ccd9f15e8be245ce9caa6969fab9e8443ac9ad9e73e7446811aee971808350c38c16c0d3372c7f44174666d770e3dd321e8b08fb2dc5e8a6a5b2a1720bad66e54abc194faabc5f24225dd8fee137ba5d4c2ed48c6462618e6333300a5b8dfc75c65608925e786eb0988f7b3a5ab106a55168d1001adc47ce95bba77b38c35b*33:1::to-submit-challenges.txt", "P-i-r-A-T-E"},
	{"$RAR3$*1*e1df79fd9ee1dadf*771a163b*64*39*1*edc483d67b94ab22a0a9b8375a461e06fa1108fa72970e16d962092c311970d26eb92a033a42f53027bdc0bb47231a12ed968c8d530a9486a90cbbc00040569b*33", "333"},
	{"$RAR3$*1*c83c00534d4af2db*771a163b*64*39*1*05244526d6b32cb9c524a15c79d19bba685f7fc3007a9171c65fc826481f2dce70be6148f2c3497f0d549aa4e864f73d4e4f697fdb66ff528ed1503d9712a414*33", "11eleven111"},
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif
	{NULL}
};

/* cRARk use 5-char passwords for GPU benchmark */
static struct fmt_tests gpu_tests[] = {
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*1*c47c5bef0bbd1e98*965f1453*48*47*1*c5e987f81d316d9dcfdb6a1b27105ce63fca2c594da5aa2f6fdf2f65f50f0d66314f8a09da875ae19d6c15636b65c815*30", "test"},
	{"$RAR3$*1*b4eee1a48dc95d12*965f1453*64*47*1*0fe529478798c0960dd88a38a05451f9559e15f0cf20b4cac58260b0e5b56699d5871bdcc35bee099cc131eb35b9a116adaedf5ecc26b1c09cadf5185b3092e6*33", "test"},
#ifdef DEBUG
	{"$RAR3$*0*af24c0c95e9cafc7*e7f207f30dec96a5ad6f917a69d0209e", "magnum"},
	{"$RAR3$*0*2653b9204daa2a8e*39b11a475f486206e2ec6070698d9bbc", "123456"},
	{"$RAR3$*0*63f1649f16c2b687*8a89f6453297bcdb66bd756fa10ddd98", "abc123"},
	/* -p mode tests, -m0 and -m3 (in that order) */
	{"$RAR3$*1*575b083d78672e85*965f1453*48*47*1*cd3d8756438f43ab70e668792e28053f0ad7449af1c66863e3e55332bfa304b2c082b9f23b36cd4a8ebc0b743618c5b2*30", "magnum"},
	{"$RAR3$*1*6f5954680c87535a*965f1453*64*47*1*c9bb398b9a5d54f035fd22be54bc6dc75822f55833f30eb4fb8cc0b8218e41e6d01824e3467475b90b994a5ddb7fe19366d293c9ee305316c2a60c3a7eb3ce5a*33", "magnum"},
	/* Various lengths, these should be in self-test but not benchmark */
	/* from CMIYC 2012 */
	{"$RAR3$*1*0f263dd52eead558*834015cd*384*693*1*e28e9648f51b59e32f573b302f0e94aadf1050678b90c38dd4e750c7dd281d439ab4cccec5f1bd1ac40b6a1ead60c75625666307171e0fe2639d2397d5f68b97a2a1f733289eac0038b52ec6c3593ff07298fce09118c255b2747a02c2fa3175ab81166ebff2f1f104b9f6284a66f598764bd01f093562b5eeb9471d977bf3d33901acfd9643afe460e1d10b90e0e9bc8b77dc9ac40d40c2d211df9b0ecbcaea72c9d8f15859d59b3c85149b5bb5f56f0218cbbd9f28790777c39e3e499bc207289727afb2b2e02541b726e9ac028f4f05a4d7930efbff97d1ffd786c4a195bbed74997469802159f3b0ae05b703238da264087b6c2729d9023f67c42c5cbe40b6c67eebbfc4658dfb99bfcb523f62133113735e862c1430adf59c837305446e8e34fac00620b99f574fabeb2cd34dc72752014cbf4bd64d35f17cef6d40747c81b12d8c0cd4472089889a53f4d810b212fb314bf58c3dd36796de0feeefaf26be20c6a2fd00517152c58d0b1a95775ef6a1374c608f55f416b78b8c81761f1d*33:1::to-submit-challenges.txt", "wachtwoord"},
	{"$RAR3$*1*9759543e04fe3a22*834015cd*384*693*1*cdd2e2478e5153a581c47a201490f5d9b69e01584ae488a2a40203da9ba8c5271ed8edc8f91a7bd262bb5e5de07ecbe9e2003d054a314d16caf2ea1de9f54303abdee1ed044396f7e29c40c38e638f626442efd9f511b4743758cd4a6025c5af81d1252475964937d80bfd50d10c171e7e4041a66c02a74b2b451ae83b6807990fb0652a8cdab530c5a0c497575a6e6cbe2db2035217fe849d2e0b8693b70f3f97b757229b4e89c8273197602c23cc04ff5f24abf3d3c7eb686fc3eddce1bfe710cc0b6e8bd012928127da38c38dd8f056095982afacb4578f6280d51c6739739e033674a9413ca88053f8264c5137d4ac018125c041a3489daaf175ef75e9282d245b92948c1bbcf1c5f25b7028f6d207d87fe9598c2c7ccd1553e842a91ab8ca9261a51b14601a756070388d08039466dfa36f0b4c7ea7dd9ff25c9d98687203c58f9ec8757cafe4d2ed785d5a9e6d5ea838e4cc246a9e6d3c30979dcce56b380b05f9103e6443b35357550b50229c47f845a93a48602790096828d9d6bef0*33:1::to-submit-challenges.txt", "Sleepingbaby210"},
	{"$RAR3$*1*79e17c26407a7d52*834015cd*384*693*1*6844a189e732e9390b5a958b623589d5423fa432d756fd00940ac31e245214983507a035d4e0ee09469491551759a66c12150fe6c5d05f334fb0d8302a96d48ef4da04954222e0705507aaa84f8b137f284dbec344eee9cea6b2c4f63540c64df3ee8be3013466d238c5999e9a98eb6375ec5462869bba43401ec95077d0c593352339902c24a3324178e08fe694d11bfec646c652ffeafbdda929052c370ffd89168c83194fedf7c50fc7d9a1fbe64332063d267a181eb07b5d70a5854067db9b66c12703fde62728d3680cf3fdb9933a0f02bfc94f3a682ad5e7c428d7ed44d5ff554a8a445dea28b81e3a2631870e17f3f3c0c0204136802c0701590cc3e4c0ccd9f15e8be245ce9caa6969fab9e8443ac9ad9e73e7446811aee971808350c38c16c0d3372c7f44174666d770e3dd321e8b08fb2dc5e8a6a5b2a1720bad66e54abc194faabc5f24225dd8fee137ba5d4c2ed48c6462618e6333300a5b8dfc75c65608925e786eb0988f7b3a5ab106a55168d1001adc47ce95bba77b38c35b*33:1::to-submit-challenges.txt", "P-i-r-A-T-E"},
	{"$RAR3$*1*e1df79fd9ee1dadf*771a163b*64*39*1*edc483d67b94ab22a0a9b8375a461e06fa1108fa72970e16d962092c311970d26eb92a033a42f53027bdc0bb47231a12ed968c8d530a9486a90cbbc00040569b*33", "333"},
	{"$RAR3$*1*c83c00534d4af2db*771a163b*64*39*1*05244526d6b32cb9c524a15c79d19bba685f7fc3007a9171c65fc826481f2dce70be6148f2c3497f0d549aa4e864f73d4e4f697fdb66ff528ed1503d9712a414*33", "11eleven111"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif
	{NULL}
};

#if defined (_OPENMP)
static void lock_callback(int mode, int type, const char *file, int line)
{
	(void)file;
	(void)line;
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&(lockarray[type]));
	else
		pthread_mutex_unlock(&(lockarray[type]));
}

static unsigned long thread_id(void)
{
	return omp_get_thread_num();
}

static void init_locks(void)
{
	int i;
	lockarray = (pthread_mutex_t*) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&(lockarray[i]), NULL);
	CRYPTO_set_id_callback(thread_id);
	CRYPTO_set_locking_callback(lock_callback);
}
#endif	/* _OPENMP */

/* Use AES-NI if available. This is not supported with low-level calls,
   we have to use EVP) */
static void init_aesni(void)
{
	ENGINE *e;
	const char *engine_id = "aesni";

	ENGINE_load_builtin_engines();
	e = ENGINE_by_id(engine_id);
	if (!e) {
		//fprintf(stderr, "AES-NI engine not available\n");
		return;
	}
	if (!ENGINE_init(e)) {
		fprintf(stderr, "AES-NI engine could not init\n");
		ENGINE_free(e);
		return;
	}
	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL & ~ENGINE_METHOD_RAND)) {
		/* This should only happen when 'e' can't initialise, but the
		 * previous statement suggests it did. */
		fprintf(stderr, "AES-NI engine initialized but then failed\n");
		abort();
	}
	ENGINE_finish(e);
	ENGINE_free(e);
}

#ifndef __APPLE__ /* Apple segfaults on this :) */
static void openssl_cleanup(void)
{
	ENGINE_cleanup();
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}
#endif

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;
	int bench_len = strlen(self->params.tests[0].plaintext) * 2;

	pinned_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, UNICODE_LENGTH * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, UNICODE_LENGTH * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_key = (unsigned char*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, UNICODE_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, UNICODE_LENGTH * gws);

	pinned_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_len = (unsigned int*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_len, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_len");
	for (i = 0; i < gws; i++)
		saved_len[i] = bench_len;

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_salt = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 8, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	memset(saved_salt, 0, 8);

	cl_OutputBuf = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_int) * 5 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	cl_round = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	// aes_key is uchar[16] but kernel treats it as uint[4]
	pinned_aes_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_aes_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_uint) * 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	aes_key = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_aes_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * 4 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory aes_key");
	memset(aes_key, 0, 16 * gws);

	pinned_aes_iv = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_aes_iv = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	aes_iv = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_aes_iv, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory aes_iv");
	memset(aes_iv, 0, 16 * gws);

	HANDLE_CLERROR(clSetKernelArg(RarInit, 0, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(RarInit, 1, sizeof(cl_mem), (void*)&cl_round), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_round), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem), (void*)&cl_aes_iv), "Error setting argument 5");

	HANDLE_CLERROR(clSetKernelArg(RarFinal, 0, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(RarFinal, 1, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(RarFinal, 2, sizeof(cl_mem), (void*)&cl_aes_key), "Error setting argument 2");

	cracked = mem_alloc(sizeof(*cracked) * gws);
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return MIN(
		MIN(autotune_get_task_max_work_group_size(FALSE, 0, RarInit),
		    autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel)),
		autotune_get_task_max_work_group_size(FALSE, 0, RarFinal));
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return 1;
	else
		return 64;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_aes_key, aes_key, 0, NULL, NULL), "Error Unmapping aes_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_aes_iv, aes_iv, 0, NULL, NULL), "Error Unmapping aes_iv");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(cl_aes_key), "Release aes_key");
	HANDLE_CLERROR(clReleaseMemObject(cl_aes_iv), "Release aes_iv");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release saved_key");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_len), "Release saved_len");
	HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release salt");
	HANDLE_CLERROR(clReleaseMemObject(pinned_aes_key), "Release aes_key");
	HANDLE_CLERROR(clReleaseMemObject(pinned_aes_iv), "Release aes_iv");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_key), "Release saved_key");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_len), "Release saved_len");
	HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release salt");
	HANDLE_CLERROR(clReleaseMemObject(cl_OutputBuf), "Release OutputBuf");

	MEM_FREE(cracked);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(RarInit), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(RarFinal), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

	MEM_FREE(unpack_data);
}

static void clear_keys(void)
{
	memset(saved_len, 0, sizeof(int) * global_work_size);
}

#undef set_key
static void set_key(char *key, int index)
{
	int plen;
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	/* UTF-16LE encode the password, encoding aware */
	plen = enc_to_utf16(buf, PLAINTEXT_LENGTH, (UTF8*) key, strlen(key));

	if (plen < 0)
		plen = strlen16(buf);

	memcpy(&saved_key[UNICODE_LENGTH * index], buf, UNICODE_LENGTH);

	saved_len[index] = plen << 1;

	new_keys = 1;
}

static void *get_salt(char *ciphertext)
{
	unsigned int i, type, ex_len;
	static unsigned char *ptr;
	/* extract data from "salt" */
	char *encoded_salt;
	char *saltcopy = strdup(ciphertext);
	char *keep_ptr = saltcopy;
	rarfile *psalt;
	unsigned char tmp_salt[8];
	int inlined = 1;
	SHA_CTX ctx;

	if (!ptr) ptr = mem_alloc_tiny(sizeof(rarfile*),sizeof(rarfile*));
	saltcopy += 7;		/* skip over "$RAR3$*" */
	type = atoi(strtokm(saltcopy, "*"));
	encoded_salt = strtokm(NULL, "*");
	for (i = 0; i < 8; i++)
		tmp_salt[i] = atoi16[ARCH_INDEX(encoded_salt[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_salt[i * 2 + 1])];
	if (type == 0) {	/* rar-hp mode */
		char *encoded_ct = strtokm(NULL, "*");
		psalt = mem_calloc(1, sizeof(*psalt)+16);
		psalt->type = type;
		ex_len = 16;
		memcpy(psalt->salt, tmp_salt, 8);
		for (i = 0; i < 16; i++)
			psalt->raw_data[i] = atoi16[ARCH_INDEX(encoded_ct[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_ct[i * 2 + 1])];
		psalt->blob = psalt->raw_data;
		psalt->pack_size = 16;
	} else {
		char *p = strtokm(NULL, "*");
		char crc_c[4];
		unsigned long long pack_size;
		unsigned long long unp_size;

		for (i = 0; i < 4; i++)
			crc_c[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
		pack_size = atoll(strtokm(NULL, "*"));
		unp_size = atoll(strtokm(NULL, "*"));
		inlined = atoi(strtokm(NULL, "*"));
		ex_len = pack_size;

		/* load ciphertext. We allocate and load all files
		   here, and they are freed when password found. */
#if HAVE_MMAP
		psalt = mem_calloc(1, sizeof(*psalt) + (inlined ? ex_len : 0));
#else
		psalt = mem_calloc(1, sizeof(*psalt) + ex_len);
#endif
		psalt->type = type;
		memcpy(psalt->salt, tmp_salt, 8);
		psalt->pack_size = pack_size;
		psalt->unp_size = unp_size;
		memcpy(psalt->crc.c, crc_c, 4);

		if (inlined) {
			unsigned char *d = psalt->raw_data;
			p = strtokm(NULL, "*");
			for (i = 0; i < psalt->pack_size; i++)
				*d++ = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
			psalt->blob = psalt->raw_data;
		} else {
			FILE *fp;
			char *archive_name = strtokm(NULL, "*");
			long long pos = atoll(strtokm(NULL, "*"));
#if HAVE_MMAP
			if (!(fp = fopen(archive_name, "rb"))) {
				fprintf(stderr, "! %s: %s\n", archive_name,
				        strerror(errno));
				error();
			}
#ifdef RAR_DEBUG
			fprintf(stderr, "RAR mmap() len %llu offset 0\n",
			        pos + psalt->pack_size);
#endif
			psalt->blob = mmap(NULL, pos + psalt->pack_size,
			                   PROT_READ, MAP_SHARED,
			                   fileno(fp), 0);
			if (psalt->blob == MAP_FAILED) {
				fprintf(stderr, "Error loading file from "
				        "archive '%s'. Archive possibly "
				        "damaged.\n", archive_name);
				error();
			}
			psalt->blob += pos;
#else
			size_t count;

			if (!(fp = fopen(archive_name, "rb"))) {
				fprintf(stderr, "! %s: %s\n", archive_name, strerror(errno));
				error();
			}
			jtr_fseek64(fp, pos, SEEK_SET);
			count = fread(psalt->raw_data, 1, psalt->pack_size, fp);
			if (count != psalt->pack_size) {
				fprintf(stderr, "Error loading file from archive '%s', expected %llu bytes, got %zu. Archive possibly damaged.\n", archive_name, psalt->pack_size, count);
				error();
			}
			psalt->blob = psalt->raw_data;
#endif
			fclose(fp);
		}
		p = strtokm(NULL, "*");
		psalt->method = atoi16[ARCH_INDEX(p[0])] * 16 + atoi16[ARCH_INDEX(p[1])];
		if (psalt->method != 0x30)
#if ARCH_LITTLE_ENDIAN
			psalt->crc.w = ~psalt->crc.w;
#else
			psalt->crc.w = JOHNSWAP(~psalt->crc.w);
#endif
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, psalt->blob, psalt->pack_size);
	SHA1_Final(psalt->blob_hash, &ctx);
	MEM_FREE(keep_ptr);
#if HAVE_MMAP
	psalt->dsalt.salt_alloc_needs_free = inlined;
#else
	psalt->dsalt.salt_alloc_needs_free = 1;
#endif
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(rarfile, salt);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(rarfile, salt, raw_data, 0);
	memcpy(ptr, &psalt, sizeof(rarfile*));
	return (void*)ptr;
}

static void set_salt(void *salt)
{
	cur_file = *((rarfile**)salt);
	memcpy(saved_salt, cur_file->salt, 8);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, 8, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
}

static void init(struct fmt_main *_self)
{
	char build_opts[64];

	self = _self;

	snprintf(build_opts, sizeof(build_opts), "-DPLAINTEXT_LENGTH=%u", PLAINTEXT_LENGTH);
	opencl_init("$JOHN/kernels/rar_kernel.cl", gpu_id, build_opts);

	// create kernels to execute
	RarInit = clCreateKernel(program[gpu_id], "RarInit", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[gpu_id], "RarHashLoop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	RarFinal = clCreateKernel(program[gpu_id], "RarFinal", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

#ifdef DEBUG
	self->params.benchmark_comment = " (1-16 characters)";
#endif
	/* We mimic the lengths of cRARk for comparisons */
	if (!cpu(device_info[gpu_id])) {
#ifndef DEBUG
		self->params.benchmark_comment = " (length 5)";
#endif
		self->params.tests = gpu_tests;
	}

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	init_locks();
#endif /* _OPENMP */

	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);

	unpack_data = mem_calloc(omp_t, sizeof(unpack_data_t));

	/* OpenSSL init */
	init_aesni();
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#ifndef __APPLE__
	atexit(openssl_cleanup);
#endif
	/* CRC-32 table init, do it before we start multithreading */
	{
		CRC32_t crc;
		CRC32_Init(&crc);
	}
}

static void reset(struct db_main *db)
{
	if (!db) {
		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
		                       warn, 3, self,
		                       create_clobj, release_clobj,
		                       UNICODE_LENGTH + sizeof(cl_int) * 14, 0);

		//Auto tune execution from shared/included code.
		self->methods.crypt_all = crypt_all_benchmark;
		autotune_run(self, ITERATIONS, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
		self->methods.crypt_all = crypt_all;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int mode;

	if (strncmp(ciphertext, "$RAR3$*", 7))
		return 0;
	if (!(ctcopy = strdup(ciphertext))) {
		fprintf(stderr, "Memory allocation failed in %s, unable to check if hash is valid!", FORMAT_LABEL);
		return 0;
	}
	keeptr = ctcopy;
	ctcopy += 7;
	if (!(ptr = strtokm(ctcopy, "*"))) /* -p or -h mode */
		goto error;
	if (hexlen(ptr) != 1)
		goto error;
	mode = atoi(ptr);
	if (mode < 0 || mode > 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (hexlen(ptr) != 16) /* 8 bytes of salt */
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (mode == 0) {
		if (hexlen(ptr) != 32) /* 16 bytes of encrypted known plain */
			goto error;
		MEM_FREE(keeptr);
		return 1;
	} else {
		int inlined;
		long long plen, ulen;

		if (hexlen(ptr) != 8) /* 4 bytes of CRC */
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* pack_size */
			goto error;
		if (strlen(ptr) > 12) { // pack_size > 1 TB? Really?
			fprintf(stderr, "pack_size > 1TB not supported (%s)\n", FORMAT_NAME);
			goto error;
		}
		if ((plen = atoll(ptr)) < 16)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* unp_size */
			goto error;
		if (strlen(ptr) > 12) {
			fprintf(stderr, "unp_size > 1TB not supported (%s)\n", FORMAT_NAME);
			goto error;
		}
		if ((ulen = atoll(ptr)) < 1)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* inlined */
			goto error;
		if (hexlen(ptr) != 1)
			goto error;
		inlined = atoi(ptr);
		if (inlined < 0 || inlined > 1)
			goto error;
		if (!(ptr = strtokm(NULL, "*"))) /* pack_size / archive_name */
			goto error;
		if (inlined) {
			if (hexlen(ptr) != plen * 2)
				goto error;
		} else {
			FILE *fp;
			char *archive_name;
			archive_name = ptr;
			if (!(fp = fopen(archive_name, "rb"))) {
				fprintf(stderr, "! %s: %s, skipping.\n", archive_name, strerror(errno));
				goto error;
			}
			if (!(ptr = strtokm(NULL, "*"))) /* pos */
				goto error;
			/* We could go on and actually try seeking to pos
			   but this is enough for now */
			fclose(fp);
		}
		if (!(ptr = strtokm(NULL, "*"))) /* method */
			goto error;
	}
	MEM_FREE(keeptr);
	return 1;

error:
#ifdef RAR_DEBUG
	{
		char buf[68];
		strnzcpy(buf, ciphertext, sizeof(buf));
		fprintf(stderr, "rejecting %s\n", buf);
	}
#endif
	MEM_FREE(keeptr);
	return 0;
}

static char *get_key(int index)
{
	UTF16 tmpbuf[PLAINTEXT_LENGTH + 1];

	memcpy(tmpbuf, &((UTF16*) saved_key)[index * PLAINTEXT_LENGTH], saved_len[index]);
	memset(&tmpbuf[saved_len[index] >> 1], 0, 2);
	return (char*) utf16_to_enc(tmpbuf);
}

#define ADD_BITS(n)	\
	{ \
		if (bits < 9) { \
			hold |= ((unsigned int)*next++ << (24 - bits)); \
			bits += 8; \
		} \
		hold <<= n; \
		bits -= n; \
	}

/*
 * This function is loosely based on JimF's check_inflate_CODE2() from
 * pkzip_fmt. Together with the other bit-checks, we are rejecting over 96%
 * of the candidates without resorting to a slow full check (which in turn
 * may reject semi-early, especially if it's a PPM block)
 *
 * Input is first 16 bytes of RAR buffer decrypted, as-is. It also contain the
 * first 2 bits, which have already been decoded, and have told us we had an
 * LZ block (RAR always use dynamic Huffman table) and keepOldTable was not set.
 *
 * RAR use 20 x (4 bits length, optionally 4 bits zerocount), and reversed
 * byte order.
 */
static MAYBE_INLINE int check_huffman(unsigned char *next) {
	unsigned int bits, hold, i;
	int left;
	unsigned int ncount[4];
	unsigned char *count = (unsigned char*)ncount;
	unsigned char bit_length[20];
#ifdef DEBUG
	unsigned char *was = next;
#endif

#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
	hold = JOHNSWAP(*(unsigned int*)next);
#else
	hold = next[3] + (((unsigned int)next[2]) << 8) +
		(((unsigned int)next[1]) << 16) +
		(((unsigned int)next[0]) << 24);
#endif
	next += 4;	// we already have the first 32 bits
	hold <<= 2;	// we already processed 2 bits, PPM and keepOldTable
	bits = 32 - 2;

	/* First, read 20 pairs of (bitlength[, zerocount]) */
	for (i = 0 ; i < 20 ; i++) {
		int length, zero_count;

		length = hold >> 28;
		ADD_BITS(4);
		if (length == 15) {
			zero_count = hold >> 28;
			ADD_BITS(4);
			if (zero_count == 0) {
				bit_length[i] = 15;
			} else {
				zero_count += 2;
				while (zero_count-- > 0 &&
				       i < sizeof(bit_length) /
				       sizeof(bit_length[0]))
					bit_length[i++] = 0;
				i--;
			}
		} else {
			bit_length[i] = length;
		}
	}

#ifdef DEBUG
	if (next - was > 16) {
		fprintf(stderr, "*** (possible) BUG: check_huffman() needed %u bytes, we only have 16 (bits=%d, hold=0x%08x)\n", (int)(next - was), bits, hold);
		dump_stuff_msg("complete buffer", was, 16);
		error();
	}
#endif

	/* Count the number of codes for each code length */
	memset(count, 0, 16);
	for (i = 0; i < 20; i++) {
		++count[bit_length[i]];
	}

	count[0] = 0;
	if (!ncount[0] && !ncount[1] && !ncount[2] && !ncount[3])
		return 0; /* No codes at all */

	left = 1;
	for (i = 1; i < 16; ++i) {
		left <<= 1;
		left -= count[i];
		if (left < 0) {
			return 0; /* over-subscribed */
		}
	}
	if (left) {
		return 0; /* incomplete set */
	}
	return 1; /* Passed this check! */
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * gws, saved_key, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_key");
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * gws, saved_len, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer saved_len");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarInit, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarFinal, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");
	// read back aes key & iv
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_key, CL_FALSE, 0, 16 * gws, aes_key, 0, NULL, multi_profilingEvent[5]), "failed in reading key back");
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_iv, CL_TRUE, 0, 16 * gws, aes_iv, 0, NULL, multi_profilingEvent[6]), "failed in reading iv back");

	return count;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	int k;
	size_t gws = ((count + (local_work_size - 1)) / local_work_size) * local_work_size;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * gws, saved_key, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_key");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * gws, saved_len, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_len");
		new_keys = 0;
	}
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarInit, 1, NULL, &gws, &local_work_size, 0, NULL, firstEvent), "failed in clEnqueueNDRangeKernel");
	for (k = 0; k < 16; k++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarFinal, 1, NULL, &gws, &local_work_size, 0, NULL, lastEvent), "failed in clEnqueueNDRangeKernel");
	// read back aes key & iv
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_key, CL_FALSE, 0, 16 * gws, aes_key, 0, NULL, NULL), "failed in reading key back");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_iv, CL_TRUE, 0, 16 * gws, aes_iv, 0, NULL, NULL), "failed in reading iv back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		int i16 = index*16;
		unsigned int inlen = 16;
		int outlen;
		EVP_CIPHER_CTX aes_ctx;

		EVP_CIPHER_CTX_init(&aes_ctx);
		EVP_DecryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, &aes_key[i16], &aes_iv[i16]);
		EVP_CIPHER_CTX_set_padding(&aes_ctx, 0);

		/* AES decrypt, uses aes_iv, aes_key and blob */
		if (cur_file->type == 0) {	/* rar-hp mode */
			unsigned char plain[16];

			outlen = 0;

			EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cur_file->blob, inlen);
			EVP_DecryptFinal_ex(&aes_ctx, &plain[outlen], &outlen);

			cracked[index] = !memcmp(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7);

		} else {

			if (cur_file->method == 0x30) {	/* stored, not deflated */
				CRC32_t crc;
				unsigned char crc_out[4];
				unsigned char plain[0x8010];
				unsigned long long size = cur_file->unp_size;
				unsigned char *cipher = cur_file->blob;

				/* Use full decryption with CRC check.
				   Compute CRC of the decompressed plaintext */
				CRC32_Init(&crc);
				outlen = 0;

				while (size > 0x8000) {
					inlen = 0x8000;

					EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cipher, inlen);
					CRC32_Update(&crc, plain, outlen > size ? size : outlen);
					size -= outlen;
					cipher += inlen;
				}
				EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cipher, (size + 15) & ~0xf);
				EVP_DecryptFinal_ex(&aes_ctx, &plain[outlen], &outlen);
				size += outlen;
				CRC32_Update(&crc, plain, size);
				CRC32_Final(crc_out, crc);

				/* Compare computed CRC with stored CRC */
				cracked[index] = !memcmp(crc_out, &cur_file->crc.c, 4);
			} else {
				const int solid = 0;
				unpack_data_t *unpack_t;
				unsigned char plain[20];

				cracked[index] = 0;

				/* Decrypt just one block for early rejection */
				outlen = 0;
				EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cur_file->blob, 16);
				EVP_DecryptFinal_ex(&aes_ctx, &plain[outlen], &outlen);

#if 1
				/* Early rejection */
				if (plain[0] & 0x80) {
					// PPM checks here.
					if (!(plain[0] & 0x20) ||  // Reset bit must be set
					    (plain[1] & 0x80))     // MaxMB must be < 128
						goto bailOut;
				} else {
					// LZ checks here.
					if ((plain[0] & 0x40) ||   // KeepOldTable can't be set
					    !check_huffman(plain)) // Huffman table check
						goto bailOut;
				}
#endif
				/* Reset stuff for full check */
				EVP_DecryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, &aes_key[i16], &aes_iv[i16]);
				EVP_CIPHER_CTX_set_padding(&aes_ctx, 0);
#ifdef _OPENMP
				unpack_t = &unpack_data[omp_get_thread_num()];
#else
				unpack_t = unpack_data;
#endif
				unpack_t->max_size = cur_file->unp_size;
				unpack_t->dest_unp_size = cur_file->unp_size;
				unpack_t->pack_size = cur_file->pack_size;
				unpack_t->iv = &aes_iv[i16];
				unpack_t->ctx = &aes_ctx;
				unpack_t->key = &aes_key[i16];

				if (rar_unpack29(cur_file->blob, solid, unpack_t))
					cracked[index] = !memcmp(&unpack_t->unp_crc, &cur_file->crc.c, 4);
bailOut:;
			}
		}
		EVP_CIPHER_CTX_cleanup(&aes_ctx);
	}
	return count;
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

struct fmt_main fmt_ocl_rar = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP | FMT_DYNA_SALT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		cpu_tests // Changed in init if GPU
	},{
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		clear_keys,
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
