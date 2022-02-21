#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#include <openssl/des.h>

#include "krb5_common.h"
#include "memory.h"

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
void nfold(unsigned int inbits, const unsigned char *in,
		unsigned int outbits, unsigned char *out)
{
	int a, b, c, lcm;
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

	lcm = outbits * inbits / a;

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
		byte += (((in[((inbits - 1) - (msbit >> 3)) % inbits] << 8)|
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

void AES_cts_encrypt(const unsigned char *in, unsigned char *out, size_t len,
		const AES_KEY *key, unsigned char *ivec, const int encryptp)
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
void dk(unsigned char key_out[], unsigned char key_in[], size_t key_size,
		unsigned char ptext[], size_t ptext_size)
{
	unsigned char iv[16];
	unsigned char plaintext[32];
	AES_KEY ekey;

	memset(iv, 0, sizeof(iv));
	memset(plaintext, 0, sizeof(plaintext));
	memcpy(plaintext, ptext, 16);

	AES_set_encrypt_key(key_in, key_size * 8, &ekey);
	AES_cbc_encrypt(plaintext, key_out, key_size, &ekey, iv, AES_ENCRYPT);
}

void krb_decrypt(const unsigned char ciphertext[], size_t ctext_size,
		unsigned char plaintext[], const unsigned char key[], size_t key_size)
{
	unsigned char iv[32];
	AES_KEY ekey;

	memset(iv, 0, sizeof(iv));
	AES_set_decrypt_key(key, key_size * 8, &ekey);
	AES_cts_encrypt(ciphertext, plaintext, ctext_size, &ekey, iv, AES_DECRYPT);
}

#if 0 /* This is not used */
static void krb_encrypt(const unsigned char ciphertext[], size_t ctext_size,
		unsigned char plaintext[], const unsigned char key[], size_t key_size)
{
	unsigned char iv[32];
	AES_KEY ekey;

	memset(iv, 0, sizeof(iv));
	AES_set_encrypt_key(key, key_size * 8, &ekey);
	AES_cts_encrypt(ciphertext, plaintext, ctext_size, &ekey, iv, AES_ENCRYPT);
}
#endif

// The following functions are borrowed from Shishi project. See
// lib/crypto-des.c and lib/low-crypto.c files in Shishi. Copyrighted by Simon
// Josefsson and licensed under GPLv3.

void des_set_odd_key_parity_shishi(char key[8])
{
	int i, j;

	for (i = 0; i < 8; i++) {
		int n_set_bits = 0;

		for (j = 1; j < 8; j++)
			if (key[i] & (1 << j))
				n_set_bits++;

		key[i] &= ~1;
		if ((n_set_bits % 2) == 0)
			key[i] |= 1;
	}
}

static char weak_des_keys[16][8] = {
	/* Weak keys */
	"\x01\x01\x01\x01\x01\x01\x01\x01",
	"\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
	"\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
	"\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
	/* Semiweak keys */
	"\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
	"\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
	"\x01\xE0\x01\xE0\x01\xF1\x01\xF1",
	"\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE",
	"\x01\x1F\x01\x1F\x01\x0E\x01\x0E",
	"\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE",
	"\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
	"\xE0\x1F\xE1\x0F\xF1\x0E\xF1\x0E",
	"\xE0\x01\xE0\x01\xF1\x01\xF1\x01",
	"\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E",
	"\x1F\x01\x1F\x01\x0E\x01\x0E\x01",
	"\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"
};

void des_key_correction_shishi(char key[8])
{
	size_t i;

	/* fixparity(key); */
	des_set_odd_key_parity_shishi(key);

	/* This loop could be replaced by optimized code (compare nettle),
	   but let's not do that. */
	for (i = 0; i < 16; i++) {
		if (memcmp (key, weak_des_keys[i], 8) == 0) {
			key[7] ^= 0xF0;
			break;
		}
	}
}

void des_cbc_mac_shishi(char key[8], char iv[8], unsigned char *in, size_t inlen, char *out)
{
	DES_cblock dkey;
	DES_cblock ivec;
	DES_key_schedule dks;
#ifdef _MSC_VER
	unsigned char *ct;
	ct = mem_alloc(inlen);
#else
	unsigned char ct[inlen]; // XXX
#endif

	memcpy(dkey, key, 8);
	DES_set_key_unchecked((DES_cblock *)dkey, &dks);
	memcpy(ivec, iv, 8);
	DES_cbc_encrypt(in, ct, inlen, &dks, &ivec, DES_ENCRYPT);
	memcpy(out, ct + inlen - 8, 8);
#ifdef _MSC_VER
	MEM_FREE(ct);
#endif
}

// Borrowed from the Shishi project, https://tools.ietf.org/html/rfc1510 (string_to_key)
int des_string_to_key_shishi(char *string, size_t stringlen,
		char *salt, size_t saltlen, unsigned char *outkey)
{
	unsigned char s[125 + 256], s_copy[125 + 256];  // Sync. this with PLAINTEXT_LENGTH and MAX_SALT_SIZE in krb5_db_fmt_plug.c. More is OK, less is not.
	int n_s;
	int odd;
	char tempkey[8];
	char p[8];
	int i, j;
	char temp, temp2;

	odd = 1;
	n_s = stringlen + saltlen;
	if ((n_s % 8) != 0)
		n_s += 8 - n_s % 8;
	memset(s, 0, n_s);
	memcpy(s, string, stringlen);
	if (saltlen > 0)
		memcpy(s + stringlen, salt, saltlen);
	memset(tempkey, 0, sizeof(tempkey));
	memcpy(s_copy, s, n_s);  // This is required as the following loop changes "s". Upstream is unaware of this bug in their code.
	for (i = 0; i < n_s / 8; i++) {
		for (j = 0; j < 8; j++)
			s[i * 8 + j] = s[i * 8 + j] & ~0x80;

		if (odd == 0) {
			for (j = 0; j < 4; j++) {
				temp = s[i * 8 + j];
				temp =
					((temp >> 6) & 0x01) |
					((temp >> 4) & 0x02) |
					((temp >> 2) & 0x04) |
					((temp) & 0x08) |
					((temp << 2) & 0x10) |
					((temp << 4) & 0x20) | ((temp << 6) & 0x40);
				temp2 = s[i * 8 + 7 - j];
				temp2 =
					((temp2 >> 6) & 0x01) |
					((temp2 >> 4) & 0x02) |
					((temp2 >> 2) & 0x04) |
					((temp2) & 0x08) |
					((temp2 << 2) & 0x10) |
					((temp2 << 4) & 0x20) | ((temp2 << 6) & 0x40);
				s[i * 8 + j] = temp2;
				s[i * 8 + 7 - j] = temp;
			}
		}

		odd = !odd;
		/* tempkey = tempkey XOR 8byteblock; */
		for (j = 0; j < 8; j++)
			tempkey[j] ^= s[i * 8 + j];
	}

	for (j = 0; j < 8; j++)
		tempkey[j] = tempkey[j] << 1;

	des_key_correction_shishi(tempkey);
	memcpy(s, string, stringlen);
	if (saltlen > 0)
		memcpy(s + stringlen, salt, saltlen);
	des_cbc_mac_shishi(tempkey, tempkey, s_copy, n_s, p);
	memcpy(tempkey, p, 8);
	des_key_correction_shishi(tempkey);
	memcpy(outkey, tempkey, 8);

	return 0;
}

#endif /* HAVE_LIBCRYPTO */
