/*
  SKEY_jtr.h

  S/Key dictionary attack module for Solar Designer's John the Ripper.

  This is the actual SKEY algorithm, internalized into JtR code. The
  libskey is only on a few systems, and very hard to find. This code
  may not be highly optimized, BUT it provides a basis for all systems
  to perform SKEY checks.

  Code added May 2014, JimF.  Released into public domain, and is usable
  in source or binary form, with or without modifications with no
  restrictions.

*/

#if !defined (__SKEY__JTR_H)
#define __SKEY__JTR_H

/* I DO NOT have these yet. These are just guesses. I need to find this information */
#define SKEY_MAX_HASHNAME_LEN 6
#define SKEY_MAX_SEED_LEN 32
#define SKEY_BINKEY_SIZE 8

extern char *jtr_skey_set_algorithm(char *buf);
extern void jtr_skey_keycrunch(unsigned char *saved_key, char *saved_salt_seed, char *saved_pass);
extern void jtr_skey_f(unsigned char *saved_key);

#define f(a) jtr_skey_f(a)
#define skey_set_algorithm(a) jtr_skey_set_algorithm(a)
#define keycrunch(a,b,c) jtr_skey_keycrunch(a,b,c)

#endif
