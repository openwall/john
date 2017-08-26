#include <stdint.h>

/* userKey is always 32-bytes long */
void serpent_set_key(const uint8_t userKey[], uint8_t *ks);
void serpent_encrypt(const uint8_t *inBlock, uint8_t *outBlock, uint8_t *ks);
void serpent_decrypt(const uint8_t *inBlock,  uint8_t *outBlock, uint8_t *ks);
