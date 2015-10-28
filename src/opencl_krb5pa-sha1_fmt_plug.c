/*
 * Kerberos 5 "PA ENC TIMESTAMP" by magnum & Dhiru
 *
 * Pcap file -> input file:
 * 1. tshark -r capture.pcapng -T pdml  > ~/capture.pdml
 * 2. krbng2john.py ~/capture.pdml > krb5.in
 * 3. Run john on krb5.in
 *
 * http://www.ietf.org/rfc/rfc4757.txt
 * http://www.securiteam.com/windowsntfocus/5BP0H0A6KM.html
 *
 * Input format is 'user:$krb5pa$etype$user$realm$salt$timestamp+checksum'
 *
 * NOTE: Checksum implies last 12 bytes of PA_ENC_TIMESTAMP value in AS-REQ
 * packet.
 *
 * Default Salt: realm + user
 *
 * AES-256 encryption & decryption of AS-REQ timestamp in Kerberos v5
 * See the following RFC for more details about the crypto & algorithms used:
 *
 * RFC3961 - Encryption and Checksum Specifications for Kerberos 5
 * RFC3962 - Advanced Encryption Standard (AES) Encryption for Kerberos 5
 *
 * march 09 / kevin devine <wyse101 0x40 gmail.com>
 *
 * This software is Copyright (c) 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * This software is Copyright (c) 2012 Dhiru Kholia (dhiru at openwall.com) and
 * released under same terms as above
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_krb5pa_sha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_krb5pa_sha1);
#else

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "common.h"
#include "unicode.h"
#include "config.h"
#include "aes.h"
#include "common-opencl.h"
#define OUTLEN 32
#include "opencl_pbkdf2_hmac_sha1.h"
#include "hmac_sha.h"
#include "loader.h"

#define FORMAT_LABEL		"krb5pa-sha1-opencl"
#define FORMAT_NAME		"Kerberos 5 AS-REQ Pre-Auth etype 17/18" /* aes-cts-hmac-sha1-96 */
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1001
#define BINARY_SIZE		12
#define BINARY_ALIGN		4
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		1
#define MAX_SALTLEN             52
#define MAX_REALMLEN            MAX_SALTLEN
#define MAX_USERLEN             MAX_SALTLEN
#define TIMESTAMP_SIZE          44
#define CHECKSUM_SIZE           BINARY_SIZE
#define TOTAL_LENGTH            (14 + 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) + MAX_REALMLEN + MAX_USERLEN + MAX_SALTLEN)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

/* This handles all sizes */
#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)
/* This is faster but can't handle size 3 */
//#define GETPOS(i, index)	(((index) & (ocl_v_width - 1)) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static struct fmt_tests tests[] = {
	{"$krb5pa$18$user1$EXAMPLE.COM$$2a0e68168d1eac344da458599c3a2b33ff326a061449fcbc242b212504e484d45903c6a16e2d593912f56c93883bf697b325193d62a8be9c", "openwall"},
	{"$krb5pa$18$user1$EXAMPLE.COM$$a3918bd0381107feedec8db0022bdf3ac56e534ed54d13c62a7013a47713cfc31ef4e7e572f912fa4164f76b335e588bf29c2d17b11c5caa", "openwall"},
	{"$krb5pa$18$l33t$EXAMPLE.COM$$98f732b309a1d7ef2355a974842a32894d911e97150f5d57f248e1c2632fbd3735c5f156532ccae0341e6a2d779ca83a06021fe57dafa464", "openwall"},
	{"$krb5pa$18$aduser$AD.EXAMPLE.COM$$64dfeee04be2b2e0423814e0df4d0f960885aca4efffe6cb5694c4d34690406071c4968abd2c153ee42d258c5e09a41269bbcd7799f478d3", "password@123"},
	{"$krb5pa$18$aduser$AD.EXAMPLE.COM$$f94f755a8b4493d925094a4eb1cec630ac40411a14c9733a853516fe426637d9daefdedc0567e2bb5a83d4f89a0ad1a4b178662b6106c0ff", "password@12345678"},
	{"$krb5pa$18$aduser$AD.EXAMPLE.COM$AD.EXAMPLE.COMaduser$f94f755a8b4493d925094a4eb1cec630ac40411a14c9733a853516fe426637d9daefdedc0567e2bb5a83d4f89a0ad1a4b178662b6106c0ff", "password@12345678"},
	/* etype 17 hash obtained using MiTM etype downgrade attack */
	{"$krb5pa$17$user1$EXAMPLE.COM$$c5461873dc13665771b98ba80be53939e906d90ae1ba79cf2e21f0395e50ee56379fbef4d0298cfccfd6cf8f907329120048fd05e8ae5df4", "openwall"},
	{NULL},
};

static cl_mem mem_in, mem_out, mem_salt, mem_state, pinned_in, pinned_out;
static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final;
static struct fmt_main *self;

static struct custom_salt {
	int type;
	int etype;
	unsigned char realm[64];
	unsigned char user[64];
	unsigned char salt[64]; /* realm + user */
	unsigned char ct[TIMESTAMP_SIZE];
} *cur_salt;

static unsigned char constant[16];
static unsigned char ke_input[16];
static unsigned char ki_input[16];

static size_t key_buf_size;
static unsigned int *inbuffer;
static pbkdf2_salt currentsalt;
static pbkdf2_out *output;
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static int new_keys;

#define ITERATIONS		(4096 - 1)
#define HASH_LOOPS		105 // Must be made from factors 3, 3, 5, 7, 13
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"P xfer: ",  ", init: ",  ", loop: ",  ", inter: ",  ", final: ",  ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_final));
	return s;
}

#if 0
struct fmt_main *me;
#endif

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= ocl_v_width;

	key_buf_size = 64 * gws;

	/// Allocate memory
	pinned_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned in");
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	inbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, key_buf_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(pbkdf2_salt), &currentsalt, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");

	pinned_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned out");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_out, CL_TRUE, CL_MAP_READ, 0, sizeof(pbkdf2_out) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	crypt_out = mem_alloc(sizeof(*crypt_out) * gws);
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_in, inbuffer, 0, NULL, NULL), "Error Unmapping mem in");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_out, output, 0, NULL, NULL), "Error Unmapping mem in");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_in), "Release pinned_in");
		HANDLE_CLERROR(clReleaseMemObject(pinned_out), "Release pinned_out");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release pinned_in");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");

		MEM_FREE(crypt_out);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release Kernel");

		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

/* n-fold(k-bits):
 * l = lcm(n,k)
 * r = l/k
 * s = k-bits | k-bits rot 13 | k-bits rot 13*2 | ... | k-bits rot 13*(r-1)
 * compute the 1's complement sum:
 * n-fold = s[0..n-1]+s[n..2n-1]+s[2n..3n-1]+..+s[(k-1)*n..k*n-1] */

/* representation: msb first, assume n and k are multiples of 8, and
 * that k>=16.  this is the case of all the cryptosystems which are
 * likely to be used.  this function can be replaced if that
 * assumption ever fails.  */

/* input length is in bits */
static void nfold(unsigned int inbits, const unsigned char *in,
    unsigned int outbits,unsigned char *out)
{
	int a,b,c,lcm;
	int byte, i, msbit;

	/* the code below is more readable if I make these bytes
	 * instead of bits */

	inbits >>= 3;
	outbits >>= 3;

	/* first compute lcm(n,k) */

	a = outbits;
	b = inbits;

	while (b != 0) {
		c = b;
		b = a % b;
		a = c;
	}

	lcm = outbits*inbits/a;

	/* now do the real work */
	memset(out, 0, outbits);
	byte = 0;

	/* this will end up cycling through k lcm(k,n)/k times, which
	 * is correct */
	for (i = lcm - 1; i >= 0; i--) {
		/* compute the msbit in k which gets added into this byte */
		msbit = (/* first, start with the msbit in the first, unrotated byte */
				((inbits << 3) - 1)

				/* then, for each byte, shift to the right for each
				 * repetition */
				+(((inbits << 3) + 13) * (i / inbits))
				/* last, pick out the correct byte within that
				 * shifted repetition */
				+((inbits - (i % inbits)) << 3)
				) % (inbits << 3);

		/* pull out the byte value itself */
		byte += (((in[((inbits  - 1) - (msbit >> 3)) % inbits] << 8)|
					(in[((inbits) - (msbit>>3)) % inbits]))
				>>((msbit & 7) + 1)) & 0xff;

		/* do the addition */
		byte += out[i % outbits];
		out[i % outbits] = byte & 0xff;

		/* keep around the carry bit, if any */
		byte >>= 8;
	}
	/* if there's a carry bit left over, add it back in */
	if (byte) {
		for (i = outbits - 1; i >= 0; i--) {
			/* do the addition */
			byte += out[i];
			out[i] = byte & 0xff;

			/* keep around the carry bit, if any */
			byte >>= 8;\
		}
	}
}

static void init(struct fmt_main *_self)
{
	unsigned char usage[5];
	static char valgo[sizeof(ALGORITHM_NAME) + 8] = "";

	self = _self;

	opencl_prepare_dev(gpu_id);
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		ocl_v_width = 2;
	else
		ocl_v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (ocl_v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}

	// generate 128 bits from 40 bits of "kerberos" string
	nfold(8 * 8, (unsigned char*)"kerberos", 128, constant);

	memset(usage,0,sizeof(usage));
	usage[3] = 0x01;        // key number in big-endian format
	usage[4] = 0xAA;        // used to derive Ke
	nfold(sizeof(usage)*8,usage,sizeof(ke_input)*8,ke_input);

	memset(usage,0,sizeof(usage));
	usage[3] = 0x01;        // key number in big-endian format
	usage[4] = 0x55;        // used to derive Ki
	nfold(sizeof(usage)*8,usage,sizeof(ki_input)*8,ki_input);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DITERATIONS=%u -DOUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
		         HASH_LOOPS, ITERATIONS, OUTLEN,
		         PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_kernel.cl", gpu_id,
		            build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 2 * HASH_LOOPS, split_events,
		                       warn, 2, self, create_clobj,
		                       release_clobj,
		                       ocl_v_width * sizeof(pbkdf2_state), 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, 4 * ITERATIONS + 4, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 5000000000ULL));
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *data = ciphertext;
	int type, saltlen = 0;

	// tag is mandatory
	if (strncmp(ciphertext, "$krb5pa$", 8) != 0)
		return 0;
	data += 8;

	// etype field, 17 or 18
	p = strchr(data, '$');
	if (!p || p - data != 2)
		return 0;
	type = atoi(data);
	if (type < 17 || type > 18)
		return 0;
	data = p + 1;

	// user field
	p = strchr(data, '$');
	if (!p || p - data > MAX_USERLEN)
		return 0;
	saltlen += p - data;
	data = p + 1;

	// realm field
	p = strchr(data, '$');
	if (!p || p - data > MAX_REALMLEN)
		return 0;
	saltlen += p - data;
	data = p + 1;

	// salt field
	p = strchr(data, '$');
	if (!p)
		return 0;
	// if salt is empty, realm.user is used instead
	if (p - data)
		saltlen = p - data;
	data = p + 1;

	// We support a max. total salt length of 52.
	// We could opt to emit a warning if rejected here.
	if(saltlen > MAX_SALTLEN) {
		static int warned = 0;

		if (!ldr_in_pot)
		if (!warned++)
			fprintf(stderr, "%s: One or more hashes rejected due to salt length limitation\n", FORMAT_LABEL);

		return 0;
	}


	// 56 bytes (112 hex chars) encrypted timestamp + checksum
	if (strlen(data) != 2 * (TIMESTAMP_SIZE + CHECKSUM_SIZE) ||
	    strspn(data, HEXCHARS_all) != strlen(data))
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += 8;
	p = strtokm(ctcopy, "$");
	cs.etype = atoi(p);
	p = strtokm(NULL, "$");
	if (p[-1] == '$')
		cs.user[0] = 0;
	else {
		strcpy((char*)cs.user, p);
		p = strtokm(NULL, "$");
	}
	if (p[-1] == '$')
		cs.realm[0] = 0;
	else {
		strcpy((char*)cs.realm, p);
		p = strtokm(NULL, "$");
	}
	if (p[-1] == '$') {
		strcpy((char*)cs.salt, (char*)cs.realm);
		strcat((char*)cs.salt, (char*)cs.user);
	} else {
		strcpy((char*)cs.salt, p);
		p = strtokm(NULL, "$");
	}
	for (i = 0; i < TIMESTAMP_SIZE; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
}

static void set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while (i < PLAINTEXT_LENGTH &&
	       (ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;
	ret[i] = 0;

	return ret;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[TOTAL_LENGTH + 1];
	char in[TOTAL_LENGTH + 1];
	char salt[MAX_SALTLEN + 1];
	char *data;
	char *e, *u, *r, *s, *tc;

	strnzcpy(in, ciphertext, sizeof(in));

	tc = strrchr(in, '$'); *tc++ = 0;
	s = strrchr(in, '$'); *s++ = 0;
	r = strrchr(in, '$'); *r++ = 0;
	u = strrchr(in, '$'); *u++ = 0;
	e = in + 8;

	/* Default salt is user.realm */
	if (!*s) {
		snprintf(salt, sizeof(salt), "%s%s", r, u);
		s = salt;
	}
	snprintf(out, sizeof(out), "$krb5pa$%s$%s$%s$%s$%s", e, u, r, s, tc);

	data = out + strlen(out) - 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) - 1;
	strlwr(data);

	return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1 + TIMESTAMP_SIZE * 2; /* skip to checksum field */
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	currentsalt.length = strlen((char*)cur_salt->salt);
	currentsalt.iterations = ITERATIONS;
	memcpy(currentsalt.salt, cur_salt->salt, currentsalt.length);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(pbkdf2_salt), &currentsalt, 0, NULL, NULL), "Copy setting to gpu");
}

static void AES_cts_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const AES_KEY *key,
                            unsigned char *ivec, const int encryptp)
{
	unsigned char tmp[AES_BLOCK_SIZE];
	unsigned int i;

	if (encryptp) {
		while(len > AES_BLOCK_SIZE) {
			for (i = 0; i < AES_BLOCK_SIZE; i++)
				tmp[i] = in[i] ^ ivec[i];
			AES_encrypt(tmp, out, key);
			memcpy(ivec, out, AES_BLOCK_SIZE);
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}
		for (i = 0; i < len; i++)
			tmp[i] = in[i] ^ ivec[i];

		for (; i < AES_BLOCK_SIZE; i++)
			tmp[i] = 0 ^ ivec[i];

		AES_encrypt(tmp, out - AES_BLOCK_SIZE, key);
		memcpy(out, ivec, len);
		memcpy(ivec, out - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	} else {
		unsigned char tmp2[AES_BLOCK_SIZE];
		unsigned char tmp3[AES_BLOCK_SIZE];
		while(len > AES_BLOCK_SIZE * 2) {
			memcpy(tmp, in, AES_BLOCK_SIZE);
			AES_decrypt(in, out, key);
			for (i = 0; i < AES_BLOCK_SIZE; i++)
				out[i] ^= ivec[i];
			memcpy(ivec, tmp, AES_BLOCK_SIZE);
			len -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}

		len -= AES_BLOCK_SIZE;
		memcpy(tmp, in, AES_BLOCK_SIZE); /* save last iv */
		AES_decrypt(in, tmp2, key);
		memcpy(tmp3, in + AES_BLOCK_SIZE, len);
		memcpy(tmp3 + len, tmp2 + len, AES_BLOCK_SIZE - len); /* xor 0 */

		for (i = 0; i < len; i++)
			out[i + AES_BLOCK_SIZE] = tmp2[i] ^ tmp3[i];

		AES_decrypt(tmp3, out, key);
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			out[i] ^= ivec[i];
		memcpy(ivec, tmp, AES_BLOCK_SIZE);
	}
}

// keysize = 32 for 256 bits, 16 for 128 bits
static void dk(unsigned char key_out[], unsigned char key_in[],
    size_t key_size, unsigned char ptext[], size_t ptext_size)
{
	unsigned char iv[32];
	unsigned char plaintext[32];
	AES_KEY ekey;

	memset(iv,0,sizeof(iv));
	memset(plaintext,0,sizeof(plaintext));
	memcpy(plaintext,ptext,16);

	AES_set_encrypt_key(key_in,key_size*8,&ekey);
	AES_cbc_encrypt(plaintext,key_out,key_size,&ekey,iv,AES_ENCRYPT);
}

static void krb_decrypt(const unsigned char ciphertext[], size_t ctext_size,
    unsigned char plaintext[], const unsigned char key[], size_t key_size)
{
	unsigned char iv[32];
	AES_KEY ekey;

	memset(iv,0,sizeof(iv));
	AES_set_decrypt_key(key,key_size*8,&ekey);
	AES_cts_encrypt(ciphertext,plaintext,ctext_size,&ekey,iv,AES_DECRYPT);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	int key_size;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	if (cur_salt->etype == 17)
		key_size = 16;
	else
		key_size = 32;

	/// Copy data to gpu
	if (ocl_autotune_running || new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : ITERATIONS / HASH_LOOPS); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : ITERATIONS / HASH_LOOPS); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run loop kernel (2nd pass)");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[4]), "Run final kernel (SHA1)");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Failed running final kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[5]), "Copy result back");

	if (!ocl_autotune_running) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++) {
			unsigned char base_key[32];
			unsigned char Ke[32];
			unsigned char plaintext[TIMESTAMP_SIZE];

			//pbkdf2((const unsigned char*)saved_key[i], len, (unsigned char *)cur_salt->salt,strlen((char*)cur_salt->salt), 4096, (unsigned int*)tkey);

			// generate 128 bits from 40 bits of "kerberos" string
			// This is precomputed in init()
			//nfold(8 * 8, (unsigned char*)"kerberos", 128, constant);
			dk(base_key, (unsigned char*)output[i].dk, key_size, constant, 32);

			/* The "well-known constant" used for the DK function is the key usage number,
			 * expressed as four octets in big-endian order, followed by one octet indicated below.
			 * Kc = DK(base-key, usage | 0x99);
			 * Ke = DK(base-key, usage | 0xAA);
			 * Ki = DK(base-key, usage | 0x55); */

			// derive Ke for decryption/encryption
			// This is precomputed in init()
			//memset(usage,0,sizeof(usage));
			//usage[3] = 0x01;        // key number in big-endian format
			//usage[4] = 0xAA;        // used to derive Ke

			//nfold(sizeof(usage)*8,usage,sizeof(ke_input)*8,ke_input);
			dk(Ke, base_key, key_size, ke_input, 32);

			// decrypt the AS-REQ timestamp encrypted with 256-bit AES
			// here is enough to check the string, further computation below is required
			// to fully verify the checksum
			krb_decrypt(cur_salt->ct, TIMESTAMP_SIZE, plaintext, Ke, key_size);

			// Check a couple bytes from known plain (YYYYMMDDHHMMSSZ) and
			// bail out if we are out of luck.
			if (plaintext[22] == '2' && plaintext[23] == '0' && plaintext[36] == 'Z') {
				unsigned char Ki[32];
				unsigned char checksum[20];

				// derive Ki used in HMAC-SHA-1 checksum
				// This is precomputed in init()
				//memset(usage,0,sizeof(usage));
				//usage[3] = 0x01;        // key number in big-endian format
				//usage[4] = 0x55;        // used to derive Ki
				//nfold(sizeof(usage)*8,usage,sizeof(ki_input)*8,ki_input);
				dk(Ki, base_key, key_size, ki_input, 32);

				// derive checksum of plaintext (only 96 bits used out of 160)
				hmac_sha1(Ki, key_size, plaintext, TIMESTAMP_SIZE, checksum, 20);
				memcpy(crypt_out[i], checksum, BINARY_SIZE);
			} else {
				memset(crypt_out[i], 0, BINARY_SIZE);
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_krb5pa_sha1 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
		{ NULL },
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		split,
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		clear_keys,
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
