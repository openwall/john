/*
 * keystore cracker patch for JtR, common code. 2016 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

// Note, salt length on GPU greatly reduced. We may need to adjust this
// larger if we hear of ITW hashes with salts larger than this.
#define SALT_LENGTH_GPU			4096
#define SALT_LENGTH_CPU			819200
#define BINARY_SIZE				20
#define BINARY_ALIGN			4
#define FORMAT_TAG			"$keystore$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)


void *keystore_common_get_binary(char *ciphertext);
int keystore_common_valid_cpu(char *ciphertext, struct fmt_main *self);
int keystore_common_valid_gpu(char *ciphertext, struct fmt_main *self);

extern struct fmt_tests keystore_common_tests[];
