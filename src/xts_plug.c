#include "arch.h"
#include "xts.h"

#define SERPENT_KS (140 * 4)

/*****************************************************************************
 * We know first sector has tweak value of 0. For this, we just AES a null 16
 * bytes, then do the XeX using the results for our xor, then modular mult
 * GF(2) that value for the next round. NOTE, len MUST be an even multiple of
 * 16 bytes. We do NOT handle CT stealing. But the way we use it in the TC
 * format we only decrypt 16 bytes, and later (if it looks 'good'), we decrypt
 * the whole first sector (512-64 bytes) both which are even 16 byte data.
 * This code has NOT been optimized. It was based on simple reference code that
 * I could get my hands on. However, 'mostly' we do a single limb AES-XTS which
 * is just 2 AES, and the buffers xored (before and after). There is no mulmod
 * GF(2) logic done in that case. NOTE, there was NO noticeable change in
 * speed, from using original oSSL AES_256_XTS vs this code, so this code
 * is deemed 'good enough' for usage in this location.
 *
 * This was also used in vdi_fmt, so the code was pulled out of those files,
 * and a 'common' file was made.
 *
 * Note, modified to handle multiple width AES (currently 256 and 128 bits)
 *****************************************************************************/
void AES_XTS_decrypt(const unsigned char *double_key, unsigned char *out,
		const unsigned char *data, unsigned len, int bits)
{
	unsigned char tweak[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned char buf[16];
	int i, j, cnt;
	AES_KEY key1, key2;

	AES_set_decrypt_key(double_key, bits, &key1);
	AES_set_encrypt_key(&double_key[bits / 8], bits, &key2);

	// first aes tweak, we do it right over tweak
	AES_encrypt(tweak, tweak, &key2);

	cnt = len / 16;
	for (j = 0;;) {
		for (i = 0; i < 16; ++i) buf[i] = data[i]^tweak[i];
		AES_decrypt(buf, out, &key1);
		for (i = 0; i < 16; ++i) out[i] ^= tweak[i];
		++j;
		if (j == cnt)
			break;
		else {
			unsigned char Cin, Cout;
			unsigned x;
			Cin = 0;
			for (x = 0; x < 16; ++x) {
				Cout = (tweak[x] >> 7) & 1;
				tweak[x] = ((tweak[x] << 1) + Cin) & 0xFF;
				Cin = Cout;
			}
			if (Cout)
				tweak[0] ^= 135; // GF_128_FDBK;
		}
		data += 16;
		out += 16;
	}
}

void XTS_decrypt(unsigned char *double_key, unsigned char *out,
		unsigned char *data, unsigned len, int bits, int algorithm)
{
	unsigned char tweak[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned char buf[16];
	int i, j, cnt;
	AES_KEY akey1, akey2;
	Twofish_key tkey1, tkey2;
	uint8_t skey1[SERPENT_KS];
	uint8_t skey2[SERPENT_KS];

	switch (algorithm) {
		case 0:
			AES_set_decrypt_key(double_key, bits, &akey1);
			AES_set_encrypt_key(&double_key[bits / 8], bits, &akey2);
			AES_encrypt(tweak, tweak, &akey2);
			break;
		case 1:
			Twofish_prepare_key(double_key, 32, &tkey1);
			Twofish_prepare_key(&double_key[bits / 8], 32, &tkey2);
			Twofish_encrypt(&tkey2, tweak, tweak);
			break;
		case 2:
			serpent_set_key(double_key, skey1);
			serpent_set_key(&double_key[bits / 8], skey2);
			serpent_encrypt(tweak, tweak, skey2);
			break;
	}

	cnt = len / 16;
	for (j = 0;;) {
		for (i = 0; i < 16; ++i)
			buf[i] = data[i] ^ tweak[i];
		switch (algorithm) {
			case 0:
				AES_decrypt(buf, out, &akey1);
				break;
			case 1:
				Twofish_decrypt(&tkey1, buf, out);
				break;
			case 2:
				serpent_decrypt(buf, out, skey1);
				break;
		}
		for (i = 0; i < 16; ++i)
			out[i] ^= tweak[i];
		++j;
		if (j == cnt)
			break;
		else {
			unsigned char Cin, Cout;
			unsigned x;
			Cin = 0;
			for (x = 0; x < 16; ++x) {
				Cout = (tweak[x] >> 7) & 1;
				tweak[x] = ((tweak[x] << 1) + Cin) & 0xFF;
				Cin = Cout;
			}
			if (Cout)
				tweak[0] ^= 135; // GF_128_FDBK;
		}
		data += 16;
		out += 16;
	}
}

void XTS_decrypt_custom_tweak(unsigned char *double_key, unsigned char *tweak,
		unsigned char *out, unsigned char *data, unsigned len, int
		bits, int algorithm)
{
	unsigned char buf[16];
	int i, j, cnt;
	AES_KEY akey1, akey2;
	Twofish_key tkey1, tkey2;
	uint8_t skey1[SERPENT_KS];
	uint8_t skey2[SERPENT_KS];

	switch (algorithm) {
		case 0:
			AES_set_decrypt_key(double_key, bits, &akey1);
			AES_set_encrypt_key(&double_key[bits / 8], bits, &akey2);
			AES_encrypt(tweak, tweak, &akey2);
			break;
		case 1:
			Twofish_prepare_key(double_key, 32, &tkey1);
			Twofish_prepare_key(&double_key[bits / 8], 32, &tkey2);
			Twofish_encrypt(&tkey2, tweak, tweak);
			break;
		case 2:
			serpent_set_key(double_key, skey1);
			serpent_set_key(&double_key[bits / 8], skey2);
			serpent_encrypt(tweak, tweak, skey2);
			break;
	}

	cnt = len / 16;
	for (j = 0;;) {
		for (i = 0; i < 16; ++i)
			buf[i] = data[i] ^ tweak[i];
		switch (algorithm) {
			case 0:
				AES_decrypt(buf, out, &akey1);
				break;
			case 1:
				Twofish_decrypt(&tkey1, buf, out);
				break;
			case 2:
				serpent_decrypt(buf, out, skey1);
				break;
		}
		for (i = 0; i < 16; ++i)
			out[i] ^= tweak[i];
		++j;
		if (j == cnt)
			break;
		else {
			unsigned char Cin, Cout;
			unsigned x;
			Cin = 0;
			for (x = 0; x < 16; ++x) {
				Cout = (tweak[x] >> 7) & 1;
				tweak[x] = ((tweak[x] << 1) + Cin) & 0xFF;
				Cin = Cout;
			}
			if (Cout)
				tweak[0] ^= 135; // GF_128_FDBK;
		}
		data += 16;
		out += 16;
	}
}

void AES_XTS_decrypt_custom_tweak(const unsigned char *double_key, unsigned
		char *tweak, unsigned char *out, const unsigned char *data,
		unsigned len, int bits)
{
	unsigned char buf[16];
	int i, j, cnt;
	AES_KEY key1, key2;

	AES_set_decrypt_key(double_key, bits, &key1);
	AES_set_encrypt_key(&double_key[bits / 8], bits, &key2);

	// first aes tweak, we do it right over tweak
	AES_encrypt(tweak, tweak, &key2);

	cnt = len / 16;
	for (j = 0;;) {
		for (i = 0; i < 16; ++i) buf[i] = data[i]^tweak[i];
		AES_decrypt(buf, out, &key1);
		for (i = 0; i < 16; ++i) out[i] ^= tweak[i];
		++j;
		if (j == cnt)
			break;
		else {
			unsigned char Cin, Cout;
			unsigned x;
			Cin = 0;
			for (x = 0; x < 16; ++x) {
				Cout = (tweak[x] >> 7) & 1;
				tweak[x] = ((tweak[x] << 1) + Cin) & 0xFF;
				Cin = Cout;
			}
			if (Cout)
				tweak[0] ^= 135; // GF_128_FDBK;
		}
		data += 16;
		out += 16;
	}
}
