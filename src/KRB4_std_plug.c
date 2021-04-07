/*
  KRB4_std.c

  Kerberos v4 jonks, from KTH krb4.

  $OpenBSD: str2key.c,v 1.6 1998/06/22 15:22:27 beck Exp $
  $KTH: str2key.c,v 1.10 1997/03/23 03:53:19 joda Exp $
*/

/* This defines the Andrew string_to_key function.  It accepts a password
 * string as input and converts its via a one-way encryption algorithm to a DES
 * encryption key.  It is compatible with the original Andrew authentication
 * service password database.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#ifdef KRB4_USE_SYSTEM_CRYPT
#define _XOPEN_SOURCE 4 /* for crypt(3) */
#define _XOPEN_SOURCE_EXTENDED
#define _XOPEN_VERSION 4
#define _XPG4_2
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#include "KRB4_std.h"

#ifndef des_fixup_key_parity
#define des_fixup_key_parity	DES_set_odd_parity
#endif

static void
mklower(char *s)
{
    for (; s[0] != '\0'; s++)
        if ('A' <= *s && *s <= 'Z')
            *s = *s - 'A' + 'a';
}

/*
 * Short passwords, i.e 8 characters or less.
 */
static void
afs_cmu_StringToKey (char *str, char *cell, DES_cblock *key)
{
    char  password[8+1];	/* crypt is limited to 8 chars anyway */
    int   i;
    int   passlen;

    strncpy (password, cell, 8);
    password[8] = '\0';
    passlen = strlen (str);
    if (passlen > 8) passlen = 8;

    for (i=0; i<passlen; i++)
        password[i] = str[i] ^ cell[i];	/* make sure cell is zero padded */

    for (i=0; i<8; i++)
        if (password[i] == '\0') password[i] = 'X';

    /* crypt only considers the first 8 characters of password but for some
       reason returns eleven characters of result (plus the two salt chars). */
#ifdef KRB4_USE_SYSTEM_CRYPT
    strncpy((char *)key, crypt(password, "p1") + 2, sizeof(DES_cblock));
#else
/* Use OpenSSL's DES_crypt() */
    strncpy((char *)key, DES_crypt(password, "p1") + 2, sizeof(DES_cblock));
#endif

    /* parity is inserted into the LSB so leftshift each byte up one bit.  This
       allows ascii characters with a zero MSB to retain as much significance
       as possible. */
    {   char *keybytes = (char *)key;
        unsigned int temp;

        for (i = 0; i < 8; i++) {
            temp = (unsigned int) keybytes[i];
            keybytes[i] = (unsigned char) (temp << 1);
        }
    }
    des_fixup_key_parity (key);
}

/*
 * Long passwords, i.e 9 characters or more.
 */
static void
afs_transarc_StringToKey (char *str, char *cell, DES_cblock *key)
{
    DES_key_schedule schedule;
    DES_cblock temp_key;
    DES_cblock ivec;
    char password[512];
    int  passlen;

    strncpy (password, str, sizeof(password));
    password[sizeof(password)-1] = '\0';
    if ((passlen = strlen (password)) < sizeof(password)-1)
        strncat (password, cell, sizeof(password)-passlen);
    if ((passlen = strlen(password)) > sizeof(password)) passlen = sizeof(password);

    memcpy(&ivec, "kerberos", 8);
    memcpy(&temp_key, "kerberos", 8);
    des_fixup_key_parity (&temp_key);
    DES_key_sched (&temp_key, &schedule);
    DES_cbc_cksum ((unsigned char *)password, &ivec, passlen, &schedule, &ivec);

    memcpy(&temp_key, &ivec, 8);
    des_fixup_key_parity (&temp_key);
    DES_key_sched (&temp_key, &schedule);
    DES_cbc_cksum ((unsigned char *)password, key, passlen, &schedule, &ivec);

    des_fixup_key_parity (key);
}

void
afs_string_to_key(char *str, char *cell, DES_cblock *key)
{
    char realm[REALM_SZ+1];
    strncpy(realm, cell, REALM_SZ);
    realm[REALM_SZ] = 0;
    mklower(realm);

    if (strlen(str) > 8)
        afs_transarc_StringToKey (str, realm, key);
    else
        afs_cmu_StringToKey (str, realm, key);
}

#endif /* HAVE_LIBCRYPTO */
