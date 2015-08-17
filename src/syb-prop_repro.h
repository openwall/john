#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// #define EXPANDED_PWDLEN 57
#define EXPANDED_PWDLEN 64  // PLAINTEXT_LENGTH
#define META_KEYSCH_LEN 64
#define HASH_LEN 28

void generate_hash(unsigned char * password, unsigned char seed,
	unsigned char * result_hash);
