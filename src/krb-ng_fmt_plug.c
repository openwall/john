/* MS Kerberos 5 "PA ENC TIMESTAMP" by magnum (modified by Dhiru)
 *
 * This attacks a known-plaintext vulnerability in AS_REQ pre-auth packets. The
 * known plaintext is a UTC timestamp in the format 20081120171510Z. Only if
 * this indicate a match we decrypt the whole timestamp and calculate our own
 * checksum to be really sure.
 *
 * The plaintext attack combined with re-using key setup was said to result in
 * more than 60% speedup. This was confirmed using John the Ripper and variants
 * of this code.
 *
 * http://www.ietf.org/rfc/rfc4757.txt
 * http://www.securiteam.com/windowsntfocus/5BP0H0A6KM.html
 *
 * Input format is 'user:$krb5ng$0$user$realm$timestamp$checksum' OR
 * user:$krb5ng$1$salt$timestamp$checksum' OR
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
 * This software is Copyright (c) 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * This software is Copyright (c) 2012 Dhiru Kholia (dhiru at openwall.com) and
 * released under same terms as above */

#include <openssl/aes.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif
#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "common.h"
#include "unicode.h"
#ifndef FAST_PBKDF2
#include "gladman_fileenc.h"
#else
#include "keychain.h"
#endif

#define FORMAT_LABEL       "krb5ng"
#define FORMAT_NAME        "MS Kerberos 5 AS-REQ Pre-Auth aes256-cts-hmac-sha1-96"
#define ALGORITHM_NAME     "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT  ""
#define BENCHMARK_LENGTH   0
#define PLAINTEXT_LENGTH   125
#define BINARY_SIZE		12
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests tests[] = {
	{"$krb5ng$0$user1$EXAMPLE.COM$2a0e68168d1eac344da458599c3a2b33ff326a061449fcbc242b212504e484d45903c6a16e2d593912f56c93$883bf697b325193d62a8be9c", "openwall"},
	{"$krb5ng$0$user1$EXAMPLE.COM$a3918bd0381107feedec8db0022bdf3ac56e534ed54d13c62a7013a47713cfc31ef4e7e572f912fa4164f76b$335e588bf29c2d17b11c5caa", "openwall"},
	{"$krb5ng$0$l33t$EXAMPLE.COM$98f732b309a1d7ef2355a974842a32894d911e97150f5d57f248e1c2632fbd3735c5f156532ccae0341e6a2d$779ca83a06021fe57dafa464", "openwall"},
        {"$krb5ng$0$aduser$AD.EXAMPLE.COM$64dfeee04be2b2e0423814e0df4d0f960885aca4efffe6cb5694c4d34690406071c4968abd2c153ee42d258c$5e09a41269bbcd7799f478d3", "password@123"},
        {"$krb5ng$0$aduser$AD.EXAMPLE.COM$f94f755a8b4493d925094a4eb1cec630ac40411a14c9733a853516fe426637d9daefdedc0567e2bb5a83d4f8$9a0ad1a4b178662b6106c0ff", "password@12345678"},
	{"$krb5ng$1$AD.EXAMPLE.COMaduser$f94f755a8b4493d925094a4eb1cec630ac40411a14c9733a853516fe426637d9daefdedc0567e2bb5a83d4f8$9a0ad1a4b178662b6106c0ff", "password@12345678"},
	{NULL},
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int type;
	unsigned char realm[64];
	unsigned char user[64];
	unsigned char ct[44];
	unsigned char salt[128]; /* realm + user */
} *cur_salt;

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

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}


#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, "$krb5ng$", 8) != 0)
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
	ctcopy += 8;
	p = strtok(ctcopy, "$");
	cs.type = atoi(p);
	p = strtok(NULL, "$");

	if (cs.type == 0) {
		strcpy((char*)cs.user, p);
		p = strtok(NULL, "$");
		strcpy((char*)cs.realm, p);
		strcpy((char*)cs.salt, (char*)cs.realm);
		strcat((char*)cs.salt, (char*)cs.user);
	}
	else
		strcpy((char*)cs.salt, p);
	p = strtok(NULL, "$");
	for (i = 0; i < 44; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
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
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static char *get_key(int index)
{
	return saved_key[index];
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

static void
AES_cts_encrypt(const unsigned char *in, unsigned char *out,
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
void dk(unsigned char key_out[], unsigned char key_in[],
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

void krb_decrypt(const unsigned char ciphertext[], size_t ctext_size,
    unsigned char plaintext[], const unsigned char key[], size_t key_size)
{
	unsigned char iv[32];
	AES_KEY ekey;

	memset(iv,0,sizeof(iv));
	AES_set_decrypt_key(key,key_size*8,&ekey);
	AES_cts_encrypt(ciphertext,plaintext,ctext_size,&ekey,iv,AES_DECRYPT);
}

void krb_encrypt(const unsigned char ciphertext[], size_t ctext_size,
    unsigned char plaintext[], const unsigned char key[], size_t key_size)
{
	unsigned char iv[32];
	AES_KEY ekey;

	memset(iv,0,sizeof(iv));
	AES_set_encrypt_key(key,key_size*8,&ekey);
	AES_cts_encrypt(ciphertext,plaintext,ctext_size,&ekey,iv,AES_ENCRYPT);
}


static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char tkey[32];
		unsigned char base_key[32];
		unsigned char constant[16];
		unsigned char usage[5];
		unsigned char ke_input[16];
		unsigned char Ke[32];
		unsigned char plaintext[44];
		unsigned char ki_input[16];
		unsigned char Ki[32];
		unsigned char checksum[20];

#ifdef FAST_PBKDF2
		pbkdf2((const unsigned char*)saved_key[index], strlen(saved_key[index]), (unsigned char *)cur_salt->salt,strlen((char*)cur_salt->salt), 4096, (unsigned int*)tkey);
#else
		derive_key((unsigned char*)saved_key[index], strlen(saved_key[index]), cur_salt->salt, strlen((char*)cur_salt->salt), 4096, tkey, 32);
#endif
		// generate 128 bits from 40 bits of "kerberos" string
		nfold(8 * 8, (unsigned char*)"kerberos", 128, constant);   // can be precomputed
		dk(base_key,tkey,32,constant,32);

		/* The "well-known constant" used for the DK function is the key usage number,
		 * expressed as four octets in big-endian order, followed by one octet indicated below.
		 * Kc = DK(base-key, usage | 0x99);
		 * Ke = DK(base-key, usage | 0xAA);
		 * Ki = DK(base-key, usage | 0x55); */

		// derive Ke for decryption/encryption
		memset(usage,0,sizeof(usage));
		usage[3] = 0x01;        // key number in big-endian format
		usage[4] = 0xAA;        // used to derive Ke

		nfold(sizeof(usage)*8,usage,sizeof(ke_input)*8,ke_input);   // precompute
		dk(Ke,base_key,32,ke_input,32);

		// decrypt the AS-REQ timestamp encrypted with 256-bit AES
		// here is enough to check the string, further computation below is required
		// to fully verify the checksum
		krb_decrypt(cur_salt->ct,44,plaintext,Ke,sizeof(Ke));

		// derive Ki used in HMAC-SHA-1 checksum
		memset(usage,0,sizeof(usage));
		usage[3] = 0x01;        // key number in big-endian format
		usage[4] = 0x55;        // used to derive Ki
		nfold(sizeof(usage)*8,usage,sizeof(ki_input)*8,ki_input);    // precompute
		dk(Ki,base_key,32,ki_input,32);

		// derive checksum of plaintext
		hmac_sha1(Ki, 32, plaintext,44,checksum, 20);
		memcpy(crypt_out[index], checksum, 12);
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

struct fmt_main fmt_krb5ng = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
