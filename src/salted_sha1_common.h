/*
 * salted_sha1 cracker patch for JtR, common code. 2015 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#if !defined (salted_sha1_common_h__)
#define salted_sha1_common_h__

#define NSLDAP_MAGIC         "{SSHA}"
#define NSLDAP_MAGIC_LENGTH  6
#define BINARY_SIZE          20
#define MAX_SALT_LEN         16  // bytes, the base64 representation is longer
#define CIPHERTEXT_LENGTH    ((BINARY_SIZE + 1 + MAX_SALT_LEN + 2) / 3 * 4)
#define CIPHERTEXT_LEN_MIN   (BINARY_SIZE / 3 * 4)

extern struct fmt_tests salted_sha1_common_tests[];
int salted_sha1_common_valid(char *ciphertext, struct fmt_main *self);

#endif // salted_sha1_common_h__
