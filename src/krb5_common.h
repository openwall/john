#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "aes.h"

void nfold(unsigned int inbits, const unsigned char *in,
		unsigned int outbits, unsigned char *out);

void AES_cts_encrypt(const unsigned char *in, unsigned char *out, size_t len,
		const AES_KEY *key, unsigned char *ivec, const int encryptp);

void dk(unsigned char key_out[], unsigned char key_in[], size_t key_size,
		unsigned char ptext[], size_t ptext_size);

void krb_decrypt(const unsigned char ciphertext[], size_t ctext_size,
		unsigned char plaintext[], const unsigned char key[], size_t key_size);

#if 0 /* This is not used */
void krb_encrypt(const unsigned char ciphertext[], size_t ctext_size,
		unsigned char plaintext[], const unsigned char key[], size_t key_size);
#endif

int des_string_to_key_shishi(char *string, size_t stringlen,
		char *salt, size_t saltlen, unsigned char *outkey);
