/*
 * Java KeyStore cracker. Written by Dhiru Kholia <dhiru at openwall.com> and
 * Narendra Kangralkar <narendrakangralkar at gmail.com>.
 *
 * Input Format: $keystore$target$data_length$data$hash$nkeys$keylength$keydata$keylength$keydata...
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Narendra Kangralkar <narendrakangralkar at gmail.com> and it is hereby
 * released to the general public under the following terms: *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Major re-write - JimF, Feb, 2016.
 *  + Added SIMD and prebuild all salt data for SIMD.
 *  + made a common code module (for sharing code with GPU)
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keystore;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keystore);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "simd-intrinsics.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "dyna_salt.h"
#include "johnswap.h"
#include "keystore_common.h"

#ifdef SIMD_COEF_32
#define NBKEYS                  (SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif

#define FORMAT_LABEL            "keystore"
#define FORMAT_NAME             "Java KeyStore"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "SHA1 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct keystore_salt *)
#define SALT_ALIGN              sizeof(struct keystore_salt *)

#ifndef OMP_SCALE
#define OMP_SCALE               128 // MKPC and i7 tuned for i7
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      NBKEYS
#define MAX_KEYS_PER_CRYPT      (64 * NBKEYS)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static SHA_CTX (*saved_ctx);
static int dirty;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static int *MixOrder, MixOrderLen;

#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ((index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32)
#else
#define GETPOS(i, index)        ((index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32)
#endif
static unsigned salt_mem_total;

typedef struct preload_t {
	// Only handle password lengths of 4 to 24 (21 elements) in this code.
	// passwords of other lengths are handled by oSSL CTX method.
	uint32_t (*first_blk)[21][SHA_BUF_SIZ*NBKEYS];
	uint32_t *ex_data[21];
	int n_ex[21]; // number of sha blocks in ex_data.
	unsigned char data_hash[20];	// to find if this one loaded before.
	struct preload_t *next;
} preload;

static preload *salt_preload;	// this is our linked list.
static preload *cursimd;	// set_salt points this to the current salt.

#endif

typedef struct keystore_salt_t {
	dyna_salt dsalt;
	int target;
	int data_length;
	int count;
	int keysize;
	unsigned char data_hash[20]; // this is the SHA of the data block.
	unsigned char *data;
	unsigned char *keydata;
	void *ptr;	// points to a pre-built salt record (only SIMD)
} keystore_salt;

static keystore_salt *keystore_cur_salt;

/* To guard against tampering with the keystore, we append a keyed
 * hash with a bit of whitener. */
inline static void getPreKeyedHash(int idx)
{
	int i, j;
        unsigned char passwdBytes[PLAINTEXT_LENGTH * 2];
	const char *magic = "Mighty Aphrodite";
	char *password = saved_key[idx];
	SHA_CTX *ctxp = &saved_ctx[idx];

        for (i=0, j=0; i < strlen(password); i++) {
            // should this be proper LE UTF16 encoded???  NOPE. We now have
            // a utf-8 encoded test hash, and the below method works.
            // actually tried utf8_to_utf16_be, and the ascii passwords
            // work fine, but the utf8 hash FAILS.

            //passwdBytes[j++] = (password[i] >> 8);
            passwdBytes[j++] = 0;
            passwdBytes[j++] = password[i];
        }
	SHA1_Init(ctxp);
	SHA1_Update(ctxp, passwdBytes, saved_len[idx] * 2);
	SHA1_Update(ctxp, magic, 16);
}

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	// We need 1 more saved_key than is 'used'. This extra key is used
	// in SIMD code, for all part full grouped blocks.
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt + 1);
	saved_len = mem_calloc(sizeof(*saved_len), self->params.max_keys_per_crypt + 1);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
	saved_ctx = mem_calloc(sizeof(*saved_ctx), self->params.max_keys_per_crypt);
	MixOrderLen = self->params.max_keys_per_crypt*MIN_KEYS_PER_CRYPT+MIN_KEYS_PER_CRYPT;
	MixOrder = mem_calloc(MixOrderLen, sizeof(int));
}

static void done(void)
{
	MEM_FREE(MixOrder);
	MEM_FREE(saved_ctx);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

#ifdef SIMD_COEF_32
static
void link_salt(keystore_salt *ps) {
	const unsigned char *magic = (const unsigned char*)"Mighty Aphrodite";
	const unsigned char *cpm;
	unsigned char *cpo;
	int threads=1;
	int j,k,t,idx;
	preload *p = salt_preload;

#ifdef _OPENMP
	threads = omp_get_max_threads();
#endif
	while (p) {
		if (!memcmp(p->data_hash, ps->data_hash, 20)) {
			ps->ptr = p;
			return;
		}
		p = p->next;
	}
	p = (preload *)mem_alloc_tiny(sizeof(preload), 16);
	memset(p, 0, sizeof(preload));
	memcpy(p->data_hash, ps->data_hash, 20);
	// make sure this salt was not already loaded. IF it is loaded, then
	// adjust the pointer in the salt-db record.
	p->first_blk = mem_calloc_tiny(threads * sizeof(*p->first_blk), MEM_ALIGN_SIMD);
	salt_mem_total += threads*sizeof(*p->first_blk);
	for (t = 0; t < threads; ++t) {	// t is threads
	for (j = 0; j < 21; ++j) {	// j is length-4 of candidate password
		// actual length of this full string to SHA1.
		unsigned bits, len = (j+4)*2+16+ps->data_length;

		cpo = (unsigned char*)p->first_blk[t][j];
		for (idx = 0; idx < NBKEYS; ++idx) {
			cpm = magic;
			for (k = (j+4)*2; *cpm; ++k) {
				cpo[GETPOS(k, idx)] = *cpm++;
			}
			cpm = ps->data;
			while (k < 64) {
				cpo[GETPOS(k, idx)] = *cpm++;
				++k;
			}
		}
		if (t==0) {
			// we only add 1 instance of the ex_data. for each
			// password length, since this data is read only.
			// All threads can share it.
			p->ex_data[j] = mem_calloc_tiny(((len+8)/64+1) *
				64*NBKEYS, MEM_ALIGN_SIMD);
			salt_mem_total += ((len+8)/64+1)*64*NBKEYS;
			for (idx = 0; idx < NBKEYS; ++idx) {
				int x, z=64-((j+4)*2+16), x_full=0;
				cpm = ps->data;
				cpm += z;
				cpo =  (unsigned char*)p->ex_data[j];
				for (x=0; x+z < ps->data_length; ++x) {
					cpo[GETPOS(x, idx)] = *cpm++;
					if (x == 63) {
						x -= 64;
						cpo += 64*NBKEYS;
						z += 64;
						x_full += 64;
					}
				}
				cpo[GETPOS(x, idx)]  = 0x80;
				x += x_full;
				p->n_ex[j] = x/64+1;
				if (x%64 > 55) {
					++p->n_ex[j];
					cpo += 64*NBKEYS;
				}
				// now put bit length;
				bits = len<<3;
				x = 63;
				while (bits) {
					cpo[GETPOS(x, idx)] = bits&0xFF;
					bits >>= 8;
					--x;
				}
			}
		}
	}
	}
	// link this preload record into our list.
	p->next = salt_preload;
	salt_preload = p;

	// Adjust salt record.
	ps->ptr = p;
}
#endif

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	SHA_CTX ctx;
	static void *ptr;
	keystore_salt cs;

	memset(&cs, 0, sizeof(keystore_salt));
	ctcopy += FORMAT_TAG_LEN; /* skip over "$keystore$" */
	p = strtokm(ctcopy, "$");
	cs.target = atoi(p);
	p = strtokm(NULL, "$");
	cs.data_length = atoi(p);
	p = strtokm(NULL, "$");
	cs.data = mem_alloc_tiny(cs.data_length, 1);
	for (i = 0; i < cs.data_length; i++) {
		cs.data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	// used as a way to later compare salts.  It is ALSO the
	// hash for a 0 byte password for this salt.
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, "Mighty Aphrodite", 16);
	SHA1_Update(&ctx, cs.data, cs.data_length);
	SHA1_Final(cs.data_hash, &ctx);

#ifdef SIMD_COEF_32
	link_salt(&cs);
#endif

	p = strtokm(NULL, "$"); /* skip hash */
	p = strtokm(NULL, "$");
	cs.count = atoi(p);
	p = strtokm(NULL, "$");
	cs.keysize = atoi(p);
	cs.keydata = mem_alloc_tiny(cs.keysize, 1);
	for (i = 0; i < cs.keysize; i++)
		cs.keydata[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);

	// setup the dyna_salt stuff.
	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(keystore_salt, data_length);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(keystore_salt, data_length, data, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(keystore_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(keystore_salt));

	return (void *) &ptr;
}

static void set_salt(void *salt)
{
	keystore_cur_salt = *(keystore_salt **) salt;
#ifdef SIMD_COEF_32
	cursimd = (preload*)keystore_cur_salt->ptr;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index, tot_todo;

#ifdef SIMD_COEF_32
	// in SIMD code, we need to sort by password length. NOTE, 0-3 and +24
	// byte passwords 'all' group into the final group. Those are run 1 at
	// a time through CTX based code.
	int j, tot=0;

	tot_todo = 0;
	saved_len[count] = 0; // point all 'tail' MMX buffer elements to this location.
	for (j = 0; j < 21 && tot<count; ++j) {
		for (index = 0; index < count; ++index) {
			if (saved_len[index] == j+4) {
				MixOrder[tot_todo++] = index;
				++tot;
			}
		}
		while (tot_todo % MIN_KEYS_PER_CRYPT)
			MixOrder[tot_todo++] = count;
	}
	if (tot < count) {
		// these do not get SIMD usage.
		for (index = 0; index < count; ++index) {
			if (saved_len[index] < 4 || saved_len[index] > 24) {
				MixOrder[tot_todo] = index;
				++tot;
				// we only want to do ONE password CTX mode
				// per loop through the thread.
				tot_todo += MIN_KEYS_PER_CRYPT;
			}
		}
	}
#else
	// no need to mix. just run them one after the next, in any order.
	for (index = 0; index < count; ++index)
		MixOrder[index] = index;
	tot_todo = count;
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < tot_todo; index += MIN_KEYS_PER_CRYPT) {
		SHA_CTX ctx;
#ifdef SIMD_COEF_32
		int x, tid=0, len, idx;
		char tmp_sse_out[20*MIN_KEYS_PER_CRYPT+MEM_ALIGN_SIMD];
		uint32_t *sse_out;
		sse_out = (uint32_t *)mem_align(tmp_sse_out, MEM_ALIGN_SIMD);
#ifdef _OPENMP
		tid = omp_get_thread_num();
#endif
		len = saved_len[MixOrder[index]];
		if (len >= 4 && len <= 24) {
			unsigned char *po;
			po = (unsigned char*)cursimd->first_blk[tid][len-4];
			for (x = 0; x < MIN_KEYS_PER_CRYPT; ++x) {
				int j;
				unsigned char *p;
				idx = MixOrder[index+x];
				p = (unsigned char*)saved_key[idx];
				for (j = 0; j < len; ++j)
					po[GETPOS(j*2+1,x)] = p[j];
			}
			SIMDSHA1body(po, sse_out, NULL, SSEi_MIXED_IN);
			po = (unsigned char*)cursimd->ex_data[len-4];
			for (x = 0; x < cursimd->n_ex[len-4]; ++x) {
				SIMDSHA1body(po, sse_out, sse_out, SSEi_MIXED_IN|SSEi_RELOAD);
				po += 64*MIN_KEYS_PER_CRYPT;
			}
#ifdef SIMD_COEF_32
			// we have to 'marshal' the data back into the SIMD output buf.
			// but we only marshal the first 4 bytes.
			for (x = 0; x <  MIN_KEYS_PER_CRYPT; ++x) {
				idx = MixOrder[index+x];
				if (idx < count)
#if ARCH_LITTLE_ENDIAN==1
					crypt_out[idx][0] = JOHNSWAP(sse_out[5*SIMD_COEF_32*(x/SIMD_COEF_32)+x%SIMD_COEF_32]);
#else
					crypt_out[idx][0] = sse_out[5*SIMD_COEF_32*(x/SIMD_COEF_32)+x%SIMD_COEF_32];
#endif
			}
#endif

			// we do NOT want to fall through.  We handled this
			// SIMD block of data already.
			continue;
		}

#endif
		if (dirty)
			getPreKeyedHash(MixOrder[index]);
		if (saved_len[MixOrder[index]] == 0)
			memcpy(crypt_out[MixOrder[index]], keystore_cur_salt->data_hash, 20);
		else {
			memcpy(&ctx, &saved_ctx[MixOrder[index]], sizeof(ctx));
			SHA1_Update(&ctx, keystore_cur_salt->data, keystore_cur_salt->data_length);
			SHA1_Final((unsigned char*)crypt_out[MixOrder[index]], &ctx);
		}
	}
	dirty = 0;
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (((uint32_t*)binary)[0] == crypt_out[index][0])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	unsigned char *binary = (unsigned char *)keystore_common_get_binary(source);
#ifdef SIMD_COEF_32
	// in SIMD, we only have the first 4 bytes copied into the binary buffer.
	// to for a cmp_one, so we do a full CTX type check
	SHA_CTX ctx;
	getPreKeyedHash(index);
	memcpy(&ctx, &saved_ctx[index], sizeof(ctx));
	SHA1_Update(&ctx, keystore_cur_salt->data, keystore_cur_salt->data_length);
	SHA1_Final((unsigned char*)crypt_out[index], &ctx);
#endif
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static void keystore_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
	dirty = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_keystore = {
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
		/* FIXME: report keystore_cur_salt->data_length as tunable cost? */
		{ NULL },
		{ FORMAT_TAG },
		keystore_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		keystore_common_valid_cpu,
		fmt_default_split,
		keystore_common_get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		keystore_set_key,
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
