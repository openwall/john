#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "feal8.h"

// #define EXPANDED_PWDLEN 57
#define EXPANDED_PWDLEN 64  // PLAINTEXT_LENGTH
#define META_KEYSCH_LEN 64
#define HASH_LEN 28

// static void print_block(unsigned char * bytes, int endpos, const char * szoveg);

void generate_hash(unsigned char * password, unsigned char seed,
	unsigned char * result_hash, unsigned int *g_seed, struct JtR_FEAL8_CTX *ctx);

// static int myrand(void);
