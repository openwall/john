/* VNC cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * On Windows, Use Ettercap to get VNC challenge-response pairs in
 * JtR format. E.g. ettercap -Tq -r /home/user/sample.pcap
 *
 * On other platforms, vncpcap2john.cpp should be able to parse
 * .pcap files and output VNC challenge-response pairs in JtR format
 *
 * bit_flip table and encryption algorithm are taken fron VNCcrack.
 *
 * (C) 2003, 2004, 2006, 2008 Jack Lloyd <lloyd@randombit.net>
 * Licensed under the GNU GPL v2
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA. */

#include <openssl/des.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"vnc"
#define FORMAT_NAME		"VNC DES"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	8
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

/* DES_set_odd_parity() already applied */
static const unsigned char bit_flip[256] = {
	0x01, 0x80, 0x40, 0xC1, 0x20, 0xA1, 0x61, 0xE0, 0x10, 0x91, 0x51, 0xD0, 0x31,
	0xB0, 0x70, 0xF1, 0x08, 0x89, 0x49, 0xC8, 0x29, 0xA8, 0x68, 0xE9, 0x19, 0x98,
	0x58, 0xD9, 0x38, 0xB9, 0x79, 0xF8, 0x04, 0x85, 0x45, 0xC4, 0x25, 0xA4, 0x64,
	0xE5, 0x15, 0x94, 0x54, 0xD5, 0x34, 0xB5, 0x75, 0xF4, 0x0D, 0x8C, 0x4C, 0xCD,
	0x2C, 0xAD, 0x6D, 0xEC, 0x1C, 0x9D, 0x5D, 0xDC, 0x3D, 0xBC, 0x7C, 0xFD, 0x02,
	0x83, 0x43, 0xC2, 0x23, 0xA2, 0x62, 0xE3, 0x13, 0x92, 0x52, 0xD3, 0x32, 0xB3,
	0x73, 0xF2, 0x0B, 0x8A, 0x4A, 0xCB, 0x2A, 0xAB, 0x6B, 0xEA, 0x1A, 0x9B, 0x5B,
	0xDA, 0x3B, 0xBA, 0x7A, 0xFB, 0x07, 0x86, 0x46, 0xC7, 0x26, 0xA7, 0x67, 0xE6,
	0x16, 0x97, 0x57, 0xD6, 0x37, 0xB6, 0x76, 0xF7, 0x0E, 0x8F, 0x4F, 0xCE, 0x2F,
	0xAE, 0x6E, 0xEF, 0x1F, 0x9E, 0x5E, 0xDF, 0x3E, 0xBF, 0x7F, 0xFE, 0x01, 0x80,
	0x40, 0xC1, 0x20, 0xA1, 0x61, 0xE0, 0x10, 0x91, 0x51, 0xD0, 0x31, 0xB0, 0x70,
	0xF1, 0x08, 0x89, 0x49, 0xC8, 0x29, 0xA8, 0x68, 0xE9, 0x19, 0x98, 0x58, 0xD9,
	0x38, 0xB9, 0x79, 0xF8, 0x04, 0x85, 0x45, 0xC4, 0x25, 0xA4, 0x64, 0xE5, 0x15,
	0x94, 0x54, 0xD5, 0x34, 0xB5, 0x75, 0xF4, 0x0D, 0x8C, 0x4C, 0xCD, 0x2C, 0xAD,
	0x6D, 0xEC, 0x1C, 0x9D, 0x5D, 0xDC, 0x3D, 0xBC, 0x7C, 0xFD, 0x02, 0x83, 0x43,
	0xC2, 0x23, 0xA2, 0x62, 0xE3, 0x13, 0x92, 0x52, 0xD3, 0x32, 0xB3, 0x73, 0xF2,
	0x0B, 0x8A, 0x4A, 0xCB, 0x2A, 0xAB, 0x6B, 0xEA, 0x1A, 0x9B, 0x5B, 0xDA, 0x3B,
	0xBA, 0x7A, 0xFB, 0x07, 0x86, 0x46, 0xC7, 0x26, 0xA7, 0x67, 0xE6, 0x16, 0x97,
	0x57, 0xD6, 0x37, 0xB6, 0x76, 0xF7, 0x0E, 0x8F, 0x4F, 0xCE, 0x2F, 0xAE, 0x6E,
	0xEF, 0x1F, 0x9E, 0x5E, 0xDF, 0x3E, 0xBF, 0x7F, 0xFE
};

#ifdef VNC_DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static struct fmt_tests vnc_tests[] = {
	{"$vnc$*84076F040550EEA9341967633B5F3855*DD96D21781A70DA49443279975404DD0", "pass1234"},
	{"$vnc$*6EFF78767762AD104E52A2E15FDA3A1A*C448C3C4BA7218EBAC29FD6623E85BAC", "pass1234"},
	{"$vnc$*0805B790B58E967F2A350A0C99DE3881*AECB26FAEAAA62D79636A5934BAC1078", "Password"},
	{"$vnc$*ADDC021F444F999B8E27144C0DCE7389*AFAF1BB57588784333962A124668A2C6", "openwall"},
	{"$vnc$*1D03C57F2DFFCC72A5AE3AD559C9C3DB*547B7A6F36A154DB03A2575C6F2A4EC5", "openwall"},
	{NULL}
};

static struct custom_salt {
	char unsigned challenge[16];
	char unsigned response[16];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
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
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$vnc$", 5);
}

static void *get_salt(char *ciphertext)
{
	int i;
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *p, *keeptr = ctcopy;
	ctcopy += 6;	/* skip over "$vnc$*" */
	p = strtok(ctcopy, "*");
	for (i = 0; i < 16; i++)
		cs.challenge[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.response[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
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
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		int i;
		DES_cblock des_key;
		DES_key_schedule schedule;
		DES_cblock ivec;
		unsigned char encrypted_challenge[16] = { 0 };
		/* process key */
		for(i = 0; i < strlen((const char*)saved_key[index]); i++)
			des_key[i] = bit_flip[ARCH_INDEX(saved_key[index][i])];
		memset(ivec, 0, 8);
		DES_set_key_unchecked(&des_key, &schedule);
		/* do encryption */
		DES_cbc_encrypt(cur_salt->challenge, &encrypted_challenge[0], 8, &schedule, &ivec, DES_ENCRYPT);
		if(memcmp(encrypted_challenge, cur_salt->response, 8) == 0) {
			DES_cbc_encrypt(&cur_salt->challenge[8], &encrypted_challenge[8], 8, &schedule, &ivec, DES_ENCRYPT);
			if(memcmp(encrypted_challenge, cur_salt->response, 16) == 0)
				memcpy((unsigned char*)crypt_out[index], encrypted_challenge, 16);
		}
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

static void vnc_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > 8)
		saved_key_length = 8;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main vnc_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		vnc_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
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
		fmt_default_salt_hash,
		set_salt,
		vnc_set_key,
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
