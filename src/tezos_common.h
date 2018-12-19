/*
 * Common code for cracking Tezos Keys.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "common.h"
#include "formats.h"
#include "jumbo.h"

#define FORMAT_TAG              "$tezos$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
        uint32_t type;
        uint32_t iterations;
        uint32_t email_length;
        uint32_t mnemonic_length;
        uint32_t raw_address_length;
        char mnemonic[512];
        char email[256];
        char address[64];
        char raw_address[64];
};

extern struct fmt_tests tezos_tests[];

int tezos_valid(char *ciphertext, struct fmt_main *self);

void *tezos_get_salt(char *ciphertext);

unsigned int tezos_iteration_count(void *salt);
