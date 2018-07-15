#include <string.h>

#include "formats.h"
#include "arch.h"
#include "memory.h"
#include "common.h"
#include "loader.h"

#define BINARY_SIZE             0
#define FORMAT_TAG              "$pse$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
        int iterations;
        int salt_size;
        int encrypted_pin_size;
        unsigned char salt[32];
        unsigned char encrypted_pin[128];
};

extern struct fmt_tests sappse_tests[];

void *sappse_common_get_salt(char *ciphertext);
int sappse_common_valid(char *ciphertext, struct fmt_main *self);
unsigned int sappse_iteration_count(void *salt);
