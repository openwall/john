/*
 * cryptmd5 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

static const char md5_salt_prefix[] = "$1$";
static const char apr1_salt_prefix[] = "$apr1$";
static const char smd5_salt_prefix[] = "{smd5}";

int cryptmd5_common_valid(char *ciphertext, struct fmt_main *self);

