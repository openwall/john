/*
 * Common code for the SSH format.
 */

#include <string.h>

#include "formats.h"

#define N                   8192
#define FORMAT_TAG          "$sshng$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

struct custom_salt {
        unsigned char salt[16];
        unsigned char ct[N];
        int cipher;
        int ctl;
        int sl;
        int rounds;
        int ciphertext_begin_offset;
};

extern int ssh_valid(char *ciphertext, struct fmt_main *self);
extern char *ssh_split(char *ciphertext, int index, struct fmt_main *self);
extern void *ssh_get_salt(char *ciphertext);
extern unsigned int ssh_iteration_count(void *salt);
extern unsigned int ssh_kdf(void *salt);
