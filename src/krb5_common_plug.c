#include "krb5_common.h"

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
		unsigned int outbits,unsigned char *out)
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
	unsigned char iv[32];
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
