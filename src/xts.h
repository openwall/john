#include "aes.h"
#include "twofish.h"
#include "serpent.h"

void XTS_decrypt(unsigned char *double_key, unsigned char *out,
		unsigned char *data, unsigned len, int bits, int algorithm);

void AES_XTS_decrypt(const unsigned char *double_key, unsigned char *out,
		const unsigned char *data, unsigned len, int bits);

void AES_XTS_decrypt_custom_tweak(const unsigned char *double_key, unsigned
		char *tweak, unsigned char *out, const unsigned char *data,
		unsigned len, int bits);

void Twofish_XTS_decrypt(unsigned char *double_key, unsigned char *out, const
		unsigned char *data, unsigned len, int bits);

void Serpent_XTS_decrypt(const unsigned char *double_key, unsigned char *out, const
		unsigned char *data, unsigned len, int bits);

void XTS_decrypt_custom_tweak(unsigned char *double_key, unsigned char *out,
		unsigned char *tweak, unsigned char *data, unsigned len, int
		bits, int algorithm);
