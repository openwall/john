#include "aes.h"

void AES_XTS_decrypt(const unsigned char *double_key, unsigned char *out,
                     const unsigned char *data, unsigned len, int bits);

