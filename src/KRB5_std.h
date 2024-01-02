/*
 * KRB5_std.h
 *
 *  Kerberos 5 module for John the Ripper, based on the
 *  KRB4 module by Dug Song.
 *
 * Author: Nasko Oskov <nasko at netsekure.org>
 *
 * Licensing:
 *
 *  The module contains code derived or copied from the Heimdal project.
 *
 *  Copyright (c) 1997-2000 Kungliga Tekniska Högskolan
 *  (Royal Institute of Technology, Stockholm, Sweden).
 *  All rights reserved.
 *
 *  Which is distribution of Kerberos based on M.I.T. implementation.
 *
 *  Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 */

#ifndef _KRB5_STD_H_
#define _KRB5_STD_H_

#include <openssl/des.h>

#define DES3_BLOCK_SIZE         8
#define DES3_KEY_SIZE           24
#define DES3_KEY_BITS           168
#define DES3_KEY_BITS_BYTES     DES3_KEY_BITS/8
#define DES3_KEY_SCHED_SIZE     (sizeof(DES_key_schedule) * 3)

#ifndef min
#define min(A, B) ((A) < (B) ? (A): (B))
#endif

#ifndef max
#define max(A, B) ((A) > (B) ? (A): (B))
#endif

typedef struct _krb5_key {
    char *key;
    char *schedule;
} krb5_key;

void des3_decrypt(krb5_key *key, char *cipher, char *plain, int len);

void str2key(char *user, char *realm, char *passwd, krb5_key *krb5key);

#endif // _KRB5_STD_H_
