/*
 * DOMINOSEC_fmt.c (version 3)
 *
 * Notes/Domino More Secure Internet Password module for Solar Designer's JtR
 * by regenrecht at o2.pl, Dec 2005.
 * Algorithm discovery by regenrecht at o2.pl, bartavelle at bandecon.com.
 *
 * Short description.
 * 1. Make 128bit digest of key. (128/8=16 bytes)
 * 2. Do bin2hex() of key digest and put braces around it. (16*2+2=34 bytes)
 * 3. Concat output of previous step to 5 bytes of salt. (5+34=39 bytes)
 * 4. Make 128bit digest of first 34 bytes (out of 39 bytes). (128/8=16 bytes)
 * 5. Compare first 10 bytes (out of 16) to check if the key was correct.
 *
 * Password file should have form of:
 * TomaszJegerman:(GKjXibCW2Ml6juyQHUoP)
 * RubasznyJan:(GrixoFHOckC/2CnHrHtM)
 *
 * Further optimizations (including some code rewrites) by Solar Designer
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_DOMINOSEC;
#elif FMT_REGISTERS_H
john_register_one(&fmt_DOMINOSEC);
#else

#include <ctype.h>
#include <string.h>
#ifdef DOMINOSEC_32BIT
#include <stdint.h>
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "../misc.h"
#include "../formats.h"
#include "../common.h"

#ifndef OMP_SCALE
#define OMP_SCALE           4	// MKPC and OMP_SCALE tuned for core i7
#endif

#define FORMAT_LABEL		"dominosec"
#define FORMAT_NAME		"Lotus Notes/Domino 6 More Secure Internet Password"
#define ALGORITHM_NAME		"8/" ARCH_BITS_STR

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	7

#define PLAINTEXT_LENGTH	64
#define CIPHERTEXT_LENGTH	22
#define BINARY_SIZE		9 /* oh, well :P */
#define BINARY_ALIGN		sizeof(uint32_t)
#define SALT_SIZE		5
#define SALT_ALIGN		sizeof(uint32_t)

#define DIGEST_SIZE		16
#define BINARY_BUFFER_SIZE	(DIGEST_SIZE-SALT_SIZE)
#define ASCII_DIGEST_LENGTH	(DIGEST_SIZE*2)
#define MIN_KEYS_PER_CRYPT	3
#define MAX_KEYS_PER_CRYPT	24

static unsigned char (*digest34)[34];
static char (*saved_key)[PLAINTEXT_LENGTH+1];
static uint32_t (*crypt_out)[(DIGEST_SIZE + 3) / sizeof(uint32_t)];
static unsigned char saved_salt[SALT_SIZE];
static int keys_changed, salt_changed;

static const char hex_table[][2] = {
	"00", "01", "02", "03", "04", "05", "06", "07",
	"08", "09", "0A", "0B",	"0C", "0D", "0E", "0F",
	"10", "11", "12", "13", "14", "15", "16", "17",
	"18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
	"20", "21", "22", "23",	"24", "25", "26", "27",
	"28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
	"30", "31", "32", "33", "34", "35", "36", "37",
	"38", "39", "3A", "3B",	"3C", "3D", "3E", "3F",
	"40", "41", "42", "43", "44", "45", "46", "47",
	"48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
	"50", "51", "52", "53",	"54", "55", "56", "57",
	"58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
	"60", "61", "62", "63", "64", "65", "66", "67",
	"68", "69", "6A", "6B",	"6C", "6D", "6E", "6F",
	"70", "71", "72", "73", "74", "75", "76", "77",
	"78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
	"80", "81", "82", "83",	"84", "85", "86", "87",
	"88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
	"90", "91", "92", "93", "94", "95", "96", "97",
	"98", "99", "9A", "9B",	"9C", "9D", "9E", "9F",
	"A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
	"A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
	"B0", "B1", "B2", "B3",	"B4", "B5", "B6", "B7",
	"B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
	"C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7",
	"C8", "C9", "CA", "CB",	"CC", "CD", "CE", "CF",
	"D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
	"D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
	"E0", "E1", "E2", "E3",	"E4", "E5", "E6", "E7",
	"E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
	"F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
	"F8", "F9", "FA", "FB",	"FC", "FD", "FE", "FF"
};

static const unsigned char lotus_magic_table[] = {
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
	0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
	0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
	0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
	0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
	0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
	0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
	0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
	0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
	0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
	0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
	0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
	0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
	0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
	0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
	0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
	0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
	0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
	0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
	0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
	0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
	0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
	0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
	0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
	0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
	0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
	0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
	0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
	0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
	0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
	0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
	/* double power! */
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
	0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
	0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
	0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
	0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36
};

static struct fmt_tests tests[] = {
	{"(GVMroLzc50YK/Yd+L8KH)", ""},
	{"(GqnUDNNGNUz5HRoelmLU)", "x"},
	{"(GNBpcGJRYpBe9orUOpmZ)", "dupaaa123"},
	{"(G0xjUQzdKxvHpUYqo5hU)", "koziolekmatolek"},
	{"(G+dfECo845XxUw+nFVYD)", "szesnascieznakow"},
	{"(GowT5I2hVHZpRWpvGmux)", "terazjakiesdwadziesciacos"},
	{"(Gq2bAtpguiTSSycy6dhu)", "trzydziescidwamozesieudaojnieuda"},
	{"(G82TtgNcqcHGkpEo7wQp)", "looongrandominputdataforfunbutnotonlyoi!"},
	{NULL}
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
	digest34  = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*digest34));
	keys_changed = salt_changed = 0;
}

static void done(void)
{
	MEM_FREE(digest34);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static struct {
	unsigned char salt[SALT_SIZE];
	unsigned char hash[BINARY_BUFFER_SIZE];
} cipher_binary_struct;

static void mdtransform_norecalc_1(unsigned char state[16], unsigned char block[16])
{
	union {
		unsigned char c[48];
#ifdef DOMINOSEC_32BIT
		uint32_t u32[12];
#endif
	} x;
	unsigned char *p;
	unsigned int i, j, t;

	t = 0; p = x.c;
	for (j = 48; j > 32; j--) {
		t = state[p - x.c] ^ lotus_magic_table[j + t];
		*p++ = t;
	}
	for (; j > 16; j--) {
		t = block[p - x.c - 16] ^ lotus_magic_table[j + t];
		*p++ = t;
	}
	for (; j > 0; j--) {
		t = state[p - x.c - 32] ^ block[p - x.c - 32] ^ lotus_magic_table[j + t];
		*p++ = t;
	}

#ifndef DOMINOSEC_32BIT
	for (i = 0; i < 16; i++) {
		p = x.c;
		for (j = 48; j > 0; j--) {
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j-- + t];
			t = *p++ ^= lotus_magic_table[j + t];
		}
	}
#else
	for (i = 0; i < 16; i++) {
		uint32_t *q = x.u32;
		p = x.c;
		for (j = 48; j > 0; j--) {
			uint32_t u = *q++;
			t = *p++ = u ^ lotus_magic_table[j-- + t];
			t = *p++ = (u >> 8) ^ lotus_magic_table[j-- + t];
			u >>= 16;
			t = *p++ = u ^ lotus_magic_table[j-- + t];
			t = *p++ = (u >> 8) ^ lotus_magic_table[j + t];
		}
	}
#endif

	p = x.c;
	for (j = 48; j > 32; j--) {
		state[p - x.c] = t = *p ^ lotus_magic_table[j + t];
		p++;
	}
}

static void mdtransform_1(unsigned char state[16],
    unsigned char checksum[16], unsigned char block[16])
{
	unsigned char c;
	unsigned int i, t;

	mdtransform_norecalc_1(state, block);

	t = checksum[15];
	for (i = 0; i < 16; i++) {
		c = lotus_magic_table[block[i] ^ t];
		t = checksum[i] ^= c;
	}
}

static void mdtransform_norecalc_3(unsigned char state[3][16],
    unsigned char block0[16],
    unsigned char block1[16],
    unsigned char block2[16])
{
	union {
		unsigned char c[48];
#ifdef DOMINOSEC_32BIT
		uint32_t u32[12];
#endif
	} x[3];
	unsigned char *p0, *p1, *p2;
	unsigned int i, j, t0, t1, t2;

	t0 = t1 = t2 = 0;
	p0 = x[0].c;
	p1 = x[1].c;
	p2 = x[2].c;
	for (j = 48; j > 32; j--) {
		t0 = state[0][p0 - x[0].c] ^ lotus_magic_table[j + t0];
		t1 = state[1][p1 - x[1].c] ^ lotus_magic_table[j + t1];
		t2 = state[2][p2 - x[2].c] ^ lotus_magic_table[j + t2];
		*p0++ = t0;
		*p1++ = t1;
		*p2++ = t2;
	}
	for (; j > 16; j--) {
		t0 = block0[p0 - x[0].c - 16] ^ lotus_magic_table[j + t0];
		t1 = block1[p1 - x[1].c - 16] ^ lotus_magic_table[j + t1];
		t2 = block2[p2 - x[2].c - 16] ^ lotus_magic_table[j + t2];
		*p0++ = t0;
		*p1++ = t1;
		*p2++ = t2;
	}
	for (; j > 0; j--) {
		t0 = state[0][p0 - x[0].c - 32] ^ block0[p0 - x[0].c - 32] ^ lotus_magic_table[j + t0];
		t1 = state[1][p1 - x[1].c - 32] ^ block1[p1 - x[1].c - 32] ^ lotus_magic_table[j + t1];
		t2 = state[2][p2 - x[2].c - 32] ^ block2[p2 - x[2].c - 32] ^ lotus_magic_table[j + t2];
		*p0++ = t0;
		*p1++ = t1;
		*p2++ = t2;
	}

#ifndef DOMINOSEC_32BIT
	for (i = 0; i < 16; i++) {
		p0 = x[0].c;
		p1 = x[1].c;
		p2 = x[2].c;
		for (j = 48; j > 0; j--) {
			t0 = *p0++ ^= lotus_magic_table[j + t0];
			t1 = *p1++ ^= lotus_magic_table[j + t1];
			t2 = *p2++ ^= lotus_magic_table[j-- + t2];
			t0 = *p0++ ^= lotus_magic_table[j + t0];
			t1 = *p1++ ^= lotus_magic_table[j + t1];
			t2 = *p2++ ^= lotus_magic_table[j-- + t2];
			t0 = *p0++ ^= lotus_magic_table[j + t0];
			t1 = *p1++ ^= lotus_magic_table[j + t1];
			t2 = *p2++ ^= lotus_magic_table[j-- + t2];
			t0 = *p0++ ^= lotus_magic_table[j + t0];
			t1 = *p1++ ^= lotus_magic_table[j + t1];
			t2 = *p2++ ^= lotus_magic_table[j + t2];
		}
	}
#else
	for (i = 0; i < 16; i++) {
		uint32_t *q0 = x[0].u32;
		uint32_t *q1 = x[1].u32;
		uint32_t *q2 = x[2].u32;
		p0 = x[0].c;
		p1 = x[1].c;
		p2 = x[2].c;
		for (j = 48; j > 0; j--) {
			uint32_t u0 = *q0++;
			uint32_t u1 = *q1++;
			uint32_t u2 = *q2++;
			t0 = *p0++ = u0 ^ lotus_magic_table[j + t0];
			t1 = *p1++ = u1 ^ lotus_magic_table[j + t1];
			t2 = *p2++ = u2 ^ lotus_magic_table[j-- + t2];
			t0 = *p0++ = (u0 >> 8) ^ lotus_magic_table[j + t0];
			t1 = *p1++ = (u1 >> 8) ^ lotus_magic_table[j + t1];
			t2 = *p2++ = (u2 >> 8) ^ lotus_magic_table[j-- + t2];
			u0 >>= 16;
			u1 >>= 16;
			u2 >>= 16;
			t0 = *p0++ = u0 ^ lotus_magic_table[j + t0];
			t1 = *p1++ = u1 ^ lotus_magic_table[j + t1];
			t2 = *p2++ = u2 ^ lotus_magic_table[j-- + t2];
			t0 = *p0++ = (u0 >> 8) ^ lotus_magic_table[j + t0];
			t1 = *p1++ = (u1 >> 8) ^ lotus_magic_table[j + t1];
			t2 = *p2++ = (u2 >> 8) ^ lotus_magic_table[j + t2];
		}
	}
#endif

	p0 = x[0].c;
	p1 = x[1].c;
	p2 = x[2].c;
	for (j = 48; j > 32; j--) {
		state[0][p0 - x[0].c] = t0 = *p0 ^ lotus_magic_table[j + t0];
		state[1][p1 - x[1].c] = t1 = *p1 ^ lotus_magic_table[j + t1];
		state[2][p2 - x[2].c] = t2 = *p2 ^ lotus_magic_table[j + t2];
		p0++;
		p1++;
		p2++;
	}
}

static void mdtransform_3(unsigned char state[3][16],
    unsigned char checksum[3][16],
    unsigned char block0[16],
    unsigned char block1[16],
    unsigned char block2[16])
{
	unsigned int i, t0, t1, t2;

	mdtransform_norecalc_3(state, block0, block1, block2);

	t0 = checksum[0][15];
	t1 = checksum[1][15];
	t2 = checksum[2][15];
	for (i = 0; i < 16; i++) {
		t0 = checksum[0][i] ^= lotus_magic_table[block0[i] ^ t0];
		t1 = checksum[1][i] ^= lotus_magic_table[block1[i] ^ t1];
		t2 = checksum[2][i] ^= lotus_magic_table[block2[i] ^ t2];
	}
}

#if 0
static void domino_big_md_1(unsigned char *in, unsigned int size, unsigned char *out)
{
	unsigned char state[16] = {0};
	unsigned char checksum[16] = {0};
	unsigned char block[16];
	unsigned int curpos = 0;

	while (curpos + 15 < size) {
		mdtransform_1(state, checksum, in + curpos);
		curpos += 16;
	}

	{
		unsigned int pad = size - curpos;
		memcpy(block, in + curpos, pad);
		memset(block + pad, 16 - pad, 16 - pad);
		mdtransform_1(state, checksum, block);
	}

	mdtransform_norecalc_1(state, checksum);

	memcpy(out, state, 16);
}
#endif

static void domino_big_md_3(unsigned char *in0, unsigned int size0,
    unsigned char *in1, unsigned int size1,
    unsigned char *in2, unsigned int size2,
    unsigned char *out0, unsigned char *out1, unsigned char *out2)
{
	unsigned char state[3][16] = {{0}, {0}, {0}};
	unsigned char checksum[3][16] = {{0}, {0}, {0}};
	unsigned char block[3][16];
	unsigned int min, curpos = 0, curpos0, curpos1, curpos2;

	min = (size0 < size1) ? size0 : size1;
	if (size2 < min)
		min = size2;

	while (curpos + 15 < min) {
		mdtransform_3(state, checksum,
		    in0 + curpos, in1 + curpos, in2 + curpos);
		curpos += 16;
	}

	curpos0 = curpos;
	while (curpos0 + 15 < size0) {
		mdtransform_1(state[0], checksum[0], in0 + curpos0);
		curpos0 += 16;
	}

	curpos1 = curpos;
	while (curpos1 + 15 < size1) {
		mdtransform_1(state[1], checksum[1], in1 + curpos1);
		curpos1 += 16;
	}

	curpos2 = curpos;
	while (curpos2 + 15 < size2) {
		mdtransform_1(state[2], checksum[2], in2 + curpos2);
		curpos2 += 16;
	}

	{
		unsigned int pad0 = size0 - curpos0;
		unsigned int pad1 = size1 - curpos1;
		unsigned int pad2 = size2 - curpos2;
		memcpy(block[0], in0 + curpos0, pad0);
		memcpy(block[1], in1 + curpos1, pad1);
		memcpy(block[2], in2 + curpos2, pad2);
		memset(block[0] + pad0, 16 - pad0, 16 - pad0);
		memset(block[1] + pad1, 16 - pad1, 16 - pad1);
		memset(block[2] + pad2, 16 - pad2, 16 - pad2);
		mdtransform_3(state, checksum, block[0], block[1], block[2]);
	}

	mdtransform_norecalc_3(state, checksum[0], checksum[1], checksum[2]);

	memcpy(out0, state[0], 16);
	memcpy(out1, state[1], 16);
	memcpy(out2, state[2], 16);
}

static void domino_big_md_3_34(unsigned char *in0,
    unsigned char *in1,
    unsigned char *in2,
    unsigned char *out0,
    unsigned char *out1,
    unsigned char *out2)
{
	unsigned char state[3][16] = {{0}, {0}, {0}};
	unsigned char checksum[3][16] = {{0}, {0}, {0}};
	unsigned char block[3][16];

	mdtransform_3(state, checksum, in0, in1, in2);
	mdtransform_3(state, checksum, in0 + 16, in1 + 16, in2 + 16);

	memcpy(block[0], in0 + 32, 2);
	memcpy(block[1], in1 + 32, 2);
	memcpy(block[2], in2 + 32, 2);
	memset(block[0] + 2, 14, 14);
	memset(block[1] + 2, 14, 14);
	memset(block[2] + 2, 14, 14);
	mdtransform_3(state, checksum, block[0], block[1], block[2]);

	mdtransform_norecalc_3(state, checksum[0], checksum[1], checksum[2]);

	memcpy(out0, state[0], 16);
	memcpy(out1, state[1], 16);
	memcpy(out2, state[2], 16);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	unsigned int i;
	unsigned char ch;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;

	if (ciphertext[0] != '(' ||
		ciphertext[1] != 'G' ||
		ciphertext[CIPHERTEXT_LENGTH-1] != ')')
		return 0;

	for (i = 1; i < CIPHERTEXT_LENGTH-1; ++i) {
		ch = ciphertext[i];
		if (!isalnum(ch) && ch != '+' && ch != '/')
			return 0;
	}

	return 1;
}

/*
static unsigned int proper_mul(int delta_apsik)
{
	__asm__("movl $0xAAAAAAAB, %eax	\n"
		"movl 0x8(%ebp), %edx	\n"
		"mul %edx		\n"
		"shr $0x2,%edx		\n"
		"movl %edx, %eax	\n");
}
*/

static void decode(unsigned char *ascii_cipher, unsigned char *binary)
{
	unsigned int out = 0, apsik = 0, loop;
	unsigned int i;
	unsigned char ch;

	ascii_cipher += 2;
	i = 0;
	do {
		if (apsik < 8) {
			/* should be using proper_mul, but what the heck...
			it's nearly the same :] */
			loop = 2; /* ~ loop = proper_mul(13 - apsik); */
			apsik += loop*6;

			do {
				out <<= 6;
				ch = *ascii_cipher;

				if (ch < '0' || ch > '9')
					if (ch < 'A' || ch > 'Z')
						if (ch < 'a' || ch > 'z')
							if (ch != '+')
								if (ch == '/')
									out += '?';
								else
								{ ; } /* shit happens */
							else
								out += '>';
						else
							out += ch-'=';
					else
						out += ch-'7';
				else
					out += ch-'0';
				++ascii_cipher;
			} while (--loop);
		}

		loop = apsik-8;
		ch = out >> loop;
		*(binary+i) = ch;
		ch <<= loop;
		apsik = loop;
		out -= ch;
	} while (++i < 15);

	binary[3] += -4;
}

static void *get_binary(char *ciphertext)
{
	static uint32_t out[BINARY_SIZE / sizeof(uint32_t) + 1];

	decode((unsigned char*)ciphertext, (unsigned char*)&cipher_binary_struct);
	memcpy(out, cipher_binary_struct.hash, BINARY_SIZE);
	return (void*)out;
}

static void *get_salt(char *ciphertext)
{
	static uint32_t out[SALT_SIZE / sizeof(uint32_t) + 1];

	decode((unsigned char*)ciphertext, (unsigned char*)&cipher_binary_struct);
	memcpy(out, cipher_binary_struct.salt, SALT_SIZE);
	return (void*)out;
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, SALT_SIZE);
	salt_changed = 1;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
	keys_changed = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += 3) {
		int i, j;

		if (keys_changed) {
			char *k0 = saved_key[index];
			char *k1 = saved_key[index + 1];
			char *k2 = saved_key[index + 2];
			unsigned char digest16[3][16];
			domino_big_md_3((unsigned char *)k0, strlen(k0),
			    (unsigned char *)k1, strlen(k1),
			    (unsigned char *)k2, strlen(k2),
			    digest16[0], digest16[1], digest16[2]);

			/* Not (++i < 16) !
			 * Domino will do hash of first 34 bytes ignoring The Fact that now
			 * there is a salt at a beginning of buffer. This means that last 5
			 * bytes "EEFF)" of password digest are meaningless.
			 */

			for (i = 0, j = 6; i < 14; i++, j += 2) {
				const char *hex2 = hex_table[ARCH_INDEX(digest16[0][i])];
				digest34[index][j] = hex2[0];
				digest34[index][j + 1] = hex2[1];
				hex2 = hex_table[ARCH_INDEX(digest16[1][i])];
				digest34[index + 1][j] = hex2[0];
				digest34[index + 1][j + 1] = hex2[1];
				hex2 = hex_table[ARCH_INDEX(digest16[2][i])];
				digest34[index + 2][j] = hex2[0];
				digest34[index + 2][j + 1] = hex2[1];
			}
		}

		if (salt_changed) {
			digest34[index + 2][0] = digest34[index + 1][0] =
			    digest34[index][0] = saved_salt[0];
			digest34[index + 2][1] = digest34[index + 1][1] =
			    digest34[index][1] = saved_salt[1];
			digest34[index + 2][2] = digest34[index + 1][2] =
			    digest34[index][2] = saved_salt[2];
			digest34[index + 2][3] = digest34[index + 1][3] =
			    digest34[index][3] = saved_salt[3];
			digest34[index + 2][4] = digest34[index + 1][4] =
			    digest34[index][4] = saved_salt[4];
			digest34[index + 2][5] = digest34[index + 1][5] =
			    digest34[index][5] = '(';
		}

		domino_big_md_3_34(digest34[index], digest34[index + 1],
		    digest34[index + 2],
		    (unsigned char *)crypt_out[index],
		    (unsigned char *)crypt_out[index + 1],
		    (unsigned char *)crypt_out[index + 2]);
	}

	keys_changed = salt_changed = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	/*
	 * Only 10 bytes of digest are to be checked.
	 * 48 bits are left alone.
	 * Funny that.
	 */
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

#define COMMON_GET_HASH_VAR crypt_out
#include "../common-get-hash.h"

static int salt_hash(void *salt)
{
	//printf("salt %08x hash %03x\n", *(uint32_t*)salt, *(uint32_t*)salt & (SALT_HASH_SIZE - 1));
	return *(uint32_t*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_DOMINOSEC = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ NULL },
		tests
	},
	{
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "../common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
