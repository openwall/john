/*
 * Common code for the krb5asrep format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "dyna_salt.h"

#define FORMAT_TAG              "$krb5asrep$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ETYPE_TAG_LEN           3  // "23$" / "18$"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt*)
#define SALT_ALIGN              sizeof(struct custom_salt*)

struct custom_salt {
	dyna_salt dsalt;
	unsigned char edata1[16];
	char salt[256];
	unsigned char etype;
	uint32_t edata2len;
	unsigned char *edata2;
};

extern int krb5_asrep_valid(char *ciphertext, struct fmt_main *self, int is_cpu_format);
extern char *krb5_asrep_split(char *ciphertext, int index, struct fmt_main *self);
extern void *krb5_asrep_get_salt(char *ciphertext);
extern unsigned int krb5_asrep_etype(void *salt);
