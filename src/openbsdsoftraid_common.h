/*
 * Common code for the OpenBSD-SoftRAID format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME                 ""
#define FORMAT_TAG                  "$openbsd-softraid$"
#define FORMAT_TAG_LEN              (sizeof(FORMAT_TAG)-1)
#define OPENBSD_SOFTRAID_SALTLENGTH 128
#define OPENBSD_SOFTRAID_KEYS       32
#define OPENBSD_SOFTRAID_KEYLENGTH  64  /* AES-XTS-256 keys are 512 bits long */
#define OPENBSD_SOFTRAID_MACLENGTH  20
#define BINARY_SIZE                 OPENBSD_SOFTRAID_MACLENGTH
#define BINARY_ALIGN                sizeof(uint32_t)

struct custom_salt {
	unsigned int num_iterations;
	unsigned char salt[OPENBSD_SOFTRAID_SALTLENGTH];
	unsigned char masked_keys[OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS];
	int kdf_type;
};

int openbsdsoftraid_valid(char* ciphertext, struct fmt_main *self, int is_cpu);
void *openbsdsoftraid_get_salt(char *ciphertext);
void *openbsdsoftraid_get_binary(char *ciphertext);
unsigned int openbsdsoftraid_get_kdf_type(void *salt);
unsigned int openbsdsoftraid_get_iteration_count(void *salt);
