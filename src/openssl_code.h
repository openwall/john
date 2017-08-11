#include <string.h>

#define MAX_KEY_SIZE     256
#define IV_LEN           16

typedef enum {md5, sha1, sha256} hash_type;

void BytesToKey(int key_sz, hash_type h, const unsigned char *salt,
                       const unsigned char *data, int data_len, int count,
                       unsigned char *key, unsigned char *iv);
