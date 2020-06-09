#include <stdint.h>

/* Header structs taken from vilefault project */

#if defined(__GNUC__) && !defined(__MINGW32__)
#define PACKED __attribute__ ((__packed__))
#else
#define PACKED
#pragma pack(push,1)
#endif

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
} PACKED cencrypted_v1_header;

typedef struct {
	unsigned char sig[8];
	uint32_t version;
	uint32_t enc_iv_size;
	uint32_t encMode;
	uint32_t encAlg;
	uint32_t keyBits;
	uint32_t prngalg;
	uint32_t prngkeysize;
	unsigned char uuid[16];
	uint32_t blocksize;
	uint64_t datasize;
	uint64_t dataoffset;
	uint32_t keycount;
} PACKED cencrypted_v2_header;

typedef struct {
	uint32_t header_type;
	uint32_t unk1;
	uint32_t header_offset;
	uint32_t unk2;
	uint32_t header_size;
} PACKED cencrypted_v2_key_header_pointer;

typedef struct {
	uint32_t algorithm;
	uint32_t prngalgo;
	uint32_t itercount;
	uint32_t salt_size;
	unsigned char salt[32];
	uint32_t iv_size;
	unsigned char iv[32];
	uint32_t blob_enc_keybits;
	uint32_t blob_enc_algo;
	uint32_t blob_enc_padding;
	uint32_t blob_enc_mode;
	uint32_t keyblobsize;
	unsigned char *keyblob;
} PACKED cencrypted_v2_password_header;

typedef struct {
	uint32_t salt_size;
	unsigned char salt[32];
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t keyblobsize;
	unsigned char keyblob[512];
} PACKED cencrypted_v2_private_key_header;

#if !defined(__GNUC__) || defined(__MINGW32__)
#pragma pack(pop)
#endif
