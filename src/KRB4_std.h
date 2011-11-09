/*
 * KRB4_std.h
 *
 * Kerberos v4 jonks, from KTH krb4.
 *
 * Dug Song <dugsong@monkey.org>
 */

#ifndef KRB4_STD_H
#define KRB4_STD_H

#define REALM_SZ	40

void afs_string_to_key(char *str, char *cell, DES_cblock *key);

#endif /* KRB4_STD_H */
