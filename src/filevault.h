#include "stdint.h"

/* Header structs taken from vilefault project */

typedef struct {
	unsigned char filler1[48];
	unsigned int kdf_iteration_count;
	unsigned int kdf_salt_len;
	unsigned char kdf_salt[48];
	unsigned char unwrap_iv[32];
	unsigned int len_wrapped_aes_key;
	unsigned char wrapped_aes_key[296];
	unsigned int len_hmac_sha1_key;
	unsigned char wrapped_hmac_sha1_key[300];
	unsigned int len_integrity_key;
	unsigned char wrapped_integrity_key[48];
	unsigned char filler6[484];
} cencrypted_v1_header;

typedef struct {
	unsigned char sig[8];
	uint32_t version;
	uint32_t enc_iv_size;
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t unk4;
	uint32_t unk5;
	unsigned char uuid[16];
	uint32_t blocksize;
	uint64_t datasize;
	uint64_t dataoffset;
	uint8_t filler1[24];
	uint32_t kdf_algorithm;
	uint32_t kdf_prng_algorithm;
	uint32_t kdf_iteration_count;
	uint32_t kdf_salt_len;	/* in bytes */
	uint8_t kdf_salt[32];
	uint32_t blob_enc_iv_size;
	uint8_t blob_enc_iv[32];
	uint32_t blob_enc_key_bits;
	uint32_t blob_enc_algorithm;
	uint32_t blob_enc_padding;
	uint32_t blob_enc_mode;
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[0x30];
} cencrypted_v2_pwheader;
