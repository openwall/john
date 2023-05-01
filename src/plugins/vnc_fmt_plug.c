/*
 * VNC cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * On Windows, Use Ettercap to get VNC challenge-response pairs in
 * JtR format. E.g. ettercap -Tq -r /home/user/sample.pcap
 *
 * On other platforms, vncpcap2john.cpp should be able to parse
 * .pcap files and output VNC challenge-response pairs in JtR format.
 *
 * bit_flip table and encryption algorithm are taken fron VNCcrack.
 *
 * (C) 2003, 2004, 2006, 2008 Jack Lloyd <lloyd@randombit.net>
 * Licensed under the GNU GPL v2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_vnc;
#elif FMT_REGISTERS_H
john_register_one(&fmt_vnc);
#else

#include <openssl/des.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "VNC"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$vnc$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        8
#define BINARY_SIZE             16
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128

#ifndef OMP_SCALE
#define OMP_SCALE               64 // Tuned w/ MKPC for core i7
#endif

/* DES_set_odd_parity() already applied */
static const unsigned char bit_flip[256] = {
	0x01, 0x80, 0x40, 0xC1, 0x20, 0xA1, 0x61, 0xE0,
	0x10, 0x91, 0x51, 0xD0, 0x31, 0xB0, 0x70, 0xF1,
	0x08, 0x89, 0x49, 0xC8, 0x29, 0xA8, 0x68, 0xE9,
	0x19, 0x98, 0x58, 0xD9, 0x38, 0xB9, 0x79, 0xF8,
	0x04, 0x85, 0x45, 0xC4, 0x25, 0xA4, 0x64, 0xE5,
	0x15, 0x94, 0x54, 0xD5, 0x34, 0xB5, 0x75, 0xF4,
	0x0D, 0x8C, 0x4C, 0xCD, 0x2C, 0xAD, 0x6D, 0xEC,
	0x1C, 0x9D, 0x5D, 0xDC, 0x3D, 0xBC, 0x7C, 0xFD,
	0x02, 0x83, 0x43, 0xC2, 0x23, 0xA2, 0x62, 0xE3,
	0x13, 0x92, 0x52, 0xD3, 0x32, 0xB3, 0x73, 0xF2,
	0x0B, 0x8A, 0x4A, 0xCB, 0x2A, 0xAB, 0x6B, 0xEA,
	0x1A, 0x9B, 0x5B, 0xDA, 0x3B, 0xBA, 0x7A, 0xFB,
	0x07, 0x86, 0x46, 0xC7, 0x26, 0xA7, 0x67, 0xE6,
	0x16, 0x97, 0x57, 0xD6, 0x37, 0xB6, 0x76, 0xF7,
	0x0E, 0x8F, 0x4F, 0xCE, 0x2F, 0xAE, 0x6E, 0xEF,
	0x1F, 0x9E, 0x5E, 0xDF, 0x3E, 0xBF, 0x7F, 0xFE,
	0x01, 0x80, 0x40, 0xC1, 0x20, 0xA1, 0x61, 0xE0,
	0x10, 0x91, 0x51, 0xD0, 0x31, 0xB0, 0x70, 0xF1,
	0x08, 0x89, 0x49, 0xC8, 0x29, 0xA8, 0x68, 0xE9,
	0x19, 0x98, 0x58, 0xD9, 0x38, 0xB9, 0x79, 0xF8,
	0x04, 0x85, 0x45, 0xC4, 0x25, 0xA4, 0x64, 0xE5,
	0x15, 0x94, 0x54, 0xD5, 0x34, 0xB5, 0x75, 0xF4,
	0x0D, 0x8C, 0x4C, 0xCD, 0x2C, 0xAD, 0x6D, 0xEC,
	0x1C, 0x9D, 0x5D, 0xDC, 0x3D, 0xBC, 0x7C, 0xFD,
	0x02, 0x83, 0x43, 0xC2, 0x23, 0xA2, 0x62, 0xE3,
	0x13, 0x92, 0x52, 0xD3, 0x32, 0xB3, 0x73, 0xF2,
	0x0B, 0x8A, 0x4A, 0xCB, 0x2A, 0xAB, 0x6B, 0xEA,
	0x1A, 0x9B, 0x5B, 0xDA, 0x3B, 0xBA, 0x7A, 0xFB,
	0x07, 0x86, 0x46, 0xC7, 0x26, 0xA7, 0x67, 0xE6,
	0x16, 0x97, 0x57, 0xD6, 0x37, 0xB6, 0x76, 0xF7,
	0x0E, 0x8F, 0x4F, 0xCE, 0x2F, 0xAE, 0x6E, 0xEF,
	0x1F, 0x9E, 0x5E, 0xDF, 0x3E, 0xBF, 0x7F, 0xFE
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
	{"$vnc$*2F7532B3EFD17EEA5DD3A0949FFDF1D8*0EB42D4D9AC1EF1B6EF6647B9594A621", "12345678"}, // truncated password, typed password was "1234567890"
	{"$vnc$*7963F9BB7BA6A42A085763808156F570*475B10D05648E4110D77F03916106F98", "123"}, // short password
	{"$vnc$*84076F040550EEA9341967633B5F3855*DD96D21781A70DA49443279975404DD0", "pass1234"},
	{"$vnc$*6EFF78767762AD104E52A2E15FDA3A1A*C448C3C4BA7218EBAC29FD6623E85BAC", "pass1234"},
	{"$vnc$*0805B790B58E967F2A350A0C99DE3881*AECB26FAEAAA62D79636A5934BAC1078", "Password"},
	{"$vnc$*ADDC021F444F999B8E27144C0DCE7389*AFAF1BB57588784333962A124668A2C6", "openwall"},
	{"$vnc$*1D03C57F2DFFCC72A5AE3AD559C9C3DB*547B7A6F36A154DB03A2575C6F2A4EC5", "openwall"},
	{"$vnc$*84076F040550EEA9341967633B5F3855*807575689582379F7D807F736DE9E434", "pass\xc2\xA3"}, // high bit set is 'fun' for DES. c2a3 is £ in utf8 bytes.
	{NULL}
};

static struct custom_salt {
	unsigned char challenge[16];
	unsigned char response[16];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*des_key)[PLAINTEXT_LENGTH];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	des_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*des_key));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(des_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip leading $vnc$* */

	if (!(ptr = strtokm(ctcopy, "*")))
		goto error;
	if (hexlenu(ptr, &extra) != 32 || extra)
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (hexlenu(ptr, &extra) != 32 || extra)
		goto error;
	MEM_FREE(keeptr);
	return 1;

error:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	int i;
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *p, *keeptr = ctcopy;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$vnc$*" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < 16; i++)
		cs.challenge[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
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

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		DES_key_schedule schedule;
		unsigned char encrypted_challenge[16];
		/* process key (note, moved to get_key) */
		DES_set_key_unchecked(&des_key[index], &schedule);
		/* do encryption (switched to ECB crypting) */
		DES_ecb_encrypt((const_DES_cblock *)cur_salt->challenge, (DES_cblock*)&encrypted_challenge[0], &schedule, DES_ENCRYPT);
		if (memcmp(encrypted_challenge, cur_salt->response, 8) == 0) {
			DES_ecb_encrypt((const_DES_cblock *)&cur_salt->challenge[8], (DES_cblock*)&encrypted_challenge[8], &schedule, DES_ENCRYPT);
			memcpy((unsigned char*)crypt_out[index], encrypted_challenge, 16);
		} else {
			crypt_out[index][0] = crypt_out[index][1] = 0;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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

static void vnc_set_key(char *key, int index)
{
	int i, saved_len = strlen(key);
	if (saved_len > 8)
		saved_len = 8;
	memset(saved_key[index], 0, 9);
	memcpy(saved_key[index], key, saved_len);
	memset(&des_key[index], 0, 8);
	for (i = 0; i < 8; ++i)
		des_key[index][i] = bit_flip[ARCH_INDEX(saved_key[index][i])];
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_vnc = {
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
		FMT_CASE | FMT_TRUNC | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ FORMAT_TAG },
		vnc_tests
	}, {
		init,
		done,
		fmt_default_reset,
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		vnc_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */
