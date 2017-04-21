#include <stdint.h>

#define MBEDTLS_ERR_CCM_BAD_INPUT      -0x000D /**< Bad input parameters to function. */
#define MBEDTLS_ERR_CCM_AUTH_FAILED    -0x000F /**< Authenticated decryption failed. */

int aes_ccm_auth_decrypt(const unsigned char *key, int bits, size_t length,
		const unsigned char *iv, size_t iv_len, const unsigned char
		*add, size_t add_len, const unsigned char *input, unsigned char
		*output, const unsigned char *tag, size_t tag_len);

int libcaes_crypt_ccm(unsigned char *key, int bits, int mode, const uint8_t
		*nonce, size_t nonce_size, const uint8_t *input_data, size_t
		input_data_size, uint8_t *output_data, size_t output_data_size);
