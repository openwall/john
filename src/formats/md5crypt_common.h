/*
 * cryptmd5 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#define md5_salt_prefix "$1$"
#define apr1_salt_prefix "$apr1$"
#define smd5_salt_prefix "{smd5}"

#define md5_salt_prefix_len  (sizeof(md5_salt_prefix)-1)
#define apr1_salt_prefix_len (sizeof(apr1_salt_prefix)-1)
#define smd5_salt_prefix_len (sizeof(smd5_salt_prefix)-1)

int cryptmd5_common_valid(char *ciphertext, struct fmt_main *self);
