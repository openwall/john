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
 */

#include <ctype.h>
#include <string.h>

#include "misc.h"
#include "formats.h"
#include "common.h"

#define FORMAT_LABEL		"dominosec"
#define FORMAT_NAME		"More Secure Internet Password"
#define ALGORITHM_NAME		"RSA MD defined by BSAFE 1.x - Lotus v6"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define PLAINTEXT_LENGTH	64
#define CIPHERTEXT_LENGTH	22
#define BINARY_SIZE		9 /* oh, well :P */
#define SALT_SIZE		5

#define DIGEST_SIZE		16
#define BINARY_BUFFER_SIZE	(DIGEST_SIZE-SALT_SIZE)
#define ASCII_DIGEST_LENGTH	(DIGEST_SIZE*2)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static unsigned char key_digest[DIGEST_SIZE];
static char saved_key[PLAINTEXT_LENGTH+1];
static unsigned char crypted_key[DIGEST_SIZE];
static unsigned char salt_and_digest[SALT_SIZE+1+ASCII_DIGEST_LENGTH+1+1] =
	"saalt(................................)";
static unsigned int saved_key_len;

static const char *hex_table[] = {
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
};

static struct fmt_tests dominosec_tests[] = {
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

struct cipher_binary_struct {
	unsigned char salt[SALT_SIZE];
	unsigned char hash[BINARY_BUFFER_SIZE];
} cipher_binary;

static void mdtransform(unsigned char state[16], unsigned char checksum[16], unsigned char block[16])
{
	unsigned char x[48];
	unsigned int t = 0;
	unsigned int i,j;
	unsigned char * pt;
	unsigned char c;

	memcpy(x, state, 16);
	memcpy(x+16, block, 16);

	for(i=0;i<16;i++)
		x[i+32] = state[i] ^ block[i];

	for (i = 0; i < 18; ++i)
	{
		pt = (unsigned char*)&x;
		for (j = 48; j > 0; j--)
		{
			*pt ^= lotus_magic_table[j+t];
			t = *pt;
			pt++;
		}
	}

	memcpy(state, x, 16);

	t = checksum[15];
	for (i = 0; i < 16; i++)
	{
		c = lotus_magic_table[block[i]^t];
		checksum[i] ^= c;
		t = checksum[i];
	}
}

static void mdtransform_norecalc(unsigned char state[16], unsigned char block[16])
{
	unsigned char x[48], *pt;
	unsigned int t = 0;
	unsigned int i,j;

	memcpy(x, state, 16);
	memcpy(x+16, block, 16);

	for(i=0;i<16;i++)
		x[i+32] = state[i] ^ block[i];

	for(i = 0; i < 18; ++i)
	{
		pt = (unsigned char*)&x;
		for (j = 48; j > 0; j--)
		{
			*pt ^= lotus_magic_table[j+t];
			t = *pt;
			pt++;
		}
  	}

	memcpy(state, x, 16);
}

static void domino_big_md(unsigned char * saved_key, int size, unsigned char * crypt_key)
{
	unsigned char state[16] = {0};
	unsigned char checksum[16] = {0};
	unsigned char block[16];
	unsigned int x;
	unsigned int curpos = 0;

	while(curpos + 15 < size)
	{
		memcpy(block, saved_key + curpos, 16);
		mdtransform(state, checksum, block);
		curpos += 16;
	}

	if(curpos != size)
	{
		x = size - curpos;
		memcpy(block, saved_key + curpos, x);
		memset(block + x, 16 - x, 16 - x);
		mdtransform(state, checksum, block);
	}
	else
	{
		memset(block, 16, 16);
		mdtransform(state, checksum, block);
	}

	mdtransform_norecalc(state, checksum);

	memcpy(crypt_key, state, 16);
}

static int dominosec_valid(char *ciphertext, struct fmt_main *pFmt)
{
	unsigned int i;
	unsigned char ch;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
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
static unsigned int dominosec_proper_mul(int delta_apsik)
{
	__asm__("movl $0xAAAAAAAB, %eax	\n"
		"movl 0x8(%ebp), %edx	\n"
		"mul %edx		\n"
		"shr $0x2,%edx		\n"
		"movl %edx, %eax	\n");
}
*/

static void dominosec_decode(unsigned char *ascii_cipher, unsigned char *binary)
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
									; /* shit happens */
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

static void *dominosec_binary(char *ciphertext)
{
	dominosec_decode((unsigned char*)ciphertext, (unsigned char*)&cipher_binary);
	return (void*)cipher_binary.hash;
}

static void *dominosec_salt(char *ciphertext)
{
	return cipher_binary.salt;
}

static void dominosec_set_salt(void *salt)
{
	memcpy(salt_and_digest, salt, SALT_SIZE);
}

static void dominosec_set_key(char *key, int index)
{
	unsigned char *offset = salt_and_digest+6;
	unsigned int i;

	saved_key_len = strlen(key);
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH);

	domino_big_md((unsigned char*)key, saved_key_len, key_digest);

	i = 0;
	do {
		memcpy(offset, *(hex_table+*(key_digest+i)), 2);
		offset += 2;
	} while (++i < 14);

	/*
	 * Not (++i < 16) !
	 * Domino will do hash of first 34 bytes ignoring The Fact that now
	 * there is a salt at a beginning of buffer. This means that last 5
	 * bytes "EEFF)" of password digest are meaningless.
	 */
}

static char *dominosec_get_key(int index)
{
	return saved_key;
}

static void dominosec_crypt_all(int count)
{
	domino_big_md(salt_and_digest, 34, crypted_key);
}

static int dominosec_cmp_all(void *binary, int count)
{
	/*
	 * Only 10 bytes of digest are to be checked.
	 * 48 bits are left alone.
	 * Funny that.
	 */
	return !memcmp(crypted_key, binary, BINARY_SIZE);
}

static int dominosec_cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_DOMINOSEC = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		dominosec_tests
	},
	{
		fmt_default_init,
		fmt_default_prepare,
		dominosec_valid,
		fmt_default_split,
		dominosec_binary,
		dominosec_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		dominosec_set_salt,
		dominosec_set_key,
		dominosec_get_key,
		fmt_default_clear_keys,
		dominosec_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		dominosec_cmp_all,
		dominosec_cmp_all,
		dominosec_cmp_exact
	}
};
