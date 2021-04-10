/*
 * Kerberos 5 module for John the Ripper, based on the
 * KRB4 module by Dug Song.
 *
 * Author: Nasko Oskov <nasko at netsekure.org>
 *
 * Licensing:
 *
 *  The module contains code derived or copied from the Heimdal project, which
 *  is distribution of Kerberos based on M.I.T. implementation.
 *
 *  Copyright (c) 1997-2000 Kungliga Tekniska Högskolan (Royal Institute of
 *  Technology, Stockholm, Sweden). All rights reserved.
 *
 *  Copyright (C) 1990 by the Massachusetts Institute of Technology.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_KRB5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_KRB5);
#else

#include <ctype.h> // required
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "memory.h"
#include "KRB5_std.h"

#define MAGIC_PREFIX        "$krb5$"
#define MAGIC_PREFIX_LEN    (sizeof(MAGIC_PREFIX)-1)
#define MAX_REALM_LEN       64
#define TGT_SIZE            228
#define MAX_USER_LEN        64
#define MAX_PASS_LEN        64

#define FORMAT_LABEL        "krb5"
#define FORMAT_NAME         "Kerberos v5 TGT"
#define ALGORITHM_NAME      "3DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define BINARY_ALIGN        MEM_ALIGN_NONE
#define SALT_SIZE           sizeof(struct salt)
#define SALT_ALIGN          MEM_ALIGN_NONE
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

/* This string is a bit too short - might give false positives */
#define KRBTGT              "krbtgt"


/**
 * structure to hold the self tests
 */
static struct fmt_tests    fmt_tests[] = {
    {"$krb5$oskov$ACM.UIUC.EDU$4730d7249765615d6f3652321c4fb76d09fb9cd06faeb0c31b8737f9fdfcde4bd4259c31cb1dff25df39173b09abdff08373302d99ac09802a290915243d9f0ea0313fdedc7f8d1fae0d9df8f0ee6233818d317f03a72c2e77b480b2bc50d1ca14fba85133ea00e472c50dbc825291e2853bd60a969ddb69dae35b604b34ea2c2265a4ffc72e9fb811da17c7f2887ccb17e2f87cd1f6c28a9afc0c083a9356a9ee2a28d2e4a01fc7ea90cc8836b8e25650c3a1409b811d0bad42a59aa418143291d42d7b1e6cb5b1876a4cc758d721323a762e943f774630385c9faa68df6f3a94422f97", "p4ssW0rd"},
    {"$krb5$oskov$ACM.UIUC.EDU$6cba0316d38e31ba028f87394792baade516afdfd8c5a964b6a7677adbad7815d778b297beb238394aa97a4d495adb7c9b7298ba7c2a2062fb6c9a4297f12f83755060f4f58a1ea4c7026df585cdfa02372ad619ab1a4ec617ad23e76d6e37e36268d9aa0abcf83f11fa8092b4328c5e6c577f7ec6f1c1684d9c99a309eee1f5bd764c4158a2cf311cded8794b2de83131c3dc51303d5300e563a2b7a230eac67e85b4593e561bf6b88c77b82c729e7ba7f3d2f99b8dc85b07873e40335aff4647833a87681ee557fbd1ffa1a458a5673d1bd3c1587eceeabaebf4e44c24d9a8ac8c1d89", "Nask0Oskov"},
    {NULL}
};

/**
 * struct to save the salt into
 */
struct salt {
    char    realm[MAX_REALM_LEN];
    char    user[MAX_USER_LEN];
    char    tgt_ebin[TGT_SIZE];
    char    passwd[MAX_PASS_LEN];
};


struct key {
    char    passwd[MAX_PASS_LEN];
    char    key[MAX_PASS_LEN];
    DES_key_schedule sched[3];
};

static struct salt *psalt = NULL;
static struct key skey;

static char username[MAX_USER_LEN];
static char realm[MAX_REALM_LEN];
static char password[MAX_PASS_LEN];

// initialization vector for des
static DES_cblock ivec;

static krb5_key _krb5key;
static krb5_key *krb5key = &_krb5key;

/**
 * hex2bin
 */
static char *hex2bin(char *src, unsigned char *dst, int outsize) {
    char *p, *pe;
    unsigned char *q, *qe, ch, cl;

    pe = src + strlen(src);
    qe = dst + outsize;

    for (p = src, q = dst; p < pe && q < qe && isxdigit((int)(unsigned char)*p); p += 2) {
	ch = p[0];
	cl = p[1];

        if ((ch >= '0') && (ch <= '9')) ch -= '0';
        else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
        else return p;

        if ((cl >= '0') && (cl <= '9')) cl -= '0';
        else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
        else return p+1;

        *q++ = (ch << 4) | cl;
    }
    return p;
}

/**
 * krb5_decrypt_compare
 *
 */
static int decrypt_compare() {
/* TGT_SIZE is not a multiple of DES block size; add space for one extra
 * DES block to make sure the OpenSSL routines will not overwrite stack
 * space beyond the end of plain[] when they operate on whole DES blocks. */
    char plain[TGT_SIZE + 8];
    int i;

    memset(krb5key->key, 0x00, DES3_KEY_SIZE);
    memset(krb5key->schedule, 0x00, DES3_KEY_SCHED_SIZE);

    strncpy_pad(username, psalt->user, MAX_USER_LEN, 0);
    strncpy_pad(realm, psalt->realm, MAX_REALM_LEN, 0);
    strncpy_pad(password, skey.passwd, MAX_PASS_LEN, 0);

    // do str2key
    str2key(username, realm, password, krb5key);

/* Possible optimization: we might not have to decrypt the entire thing */
    des3_decrypt(krb5key, psalt->tgt_ebin, plain, TGT_SIZE);

    for (i=0;i<TGT_SIZE;++i)
        if (plain[i] == 'k')
            if (strncmp(plain + i, KRBTGT, strlen(KRBTGT)) == 0) {
	            strncpy_pad(psalt->passwd, skey.passwd, MAX_PASS_LEN, 0);
                return 1;
            }
    return 0;
}

/**
 * void * krb5_salt
 *
 */
static void * get_salt(char *ciphertext) {
    static struct salt salt;
    char *data = ciphertext, *p;
    int n;

	memset(&salt, 0, sizeof(salt));
    // advance past the $krb5$ string - it was checked for in valid()
    data += MAGIC_PREFIX_LEN;

    // find and copy the user field
    p = strchr(data, '$');
    if (!p)
	return NULL;
    n = (p - data) + 1;
    if (n <= 1 || n >= sizeof(salt.user))
	return NULL;
    strnzcpy(salt.user, data, n);
    data = p + 1;

    // find and copy the realm field
    p = strchr(data, '$');
    if (!p)
	return NULL;
    n = (p - data) + 1;
    if (n <= 1 || n >= sizeof(salt.realm))
	return NULL;
    strnzcpy(salt.realm, data, n);
    data = p + 1;

    // copy over the TGT in a binary form to the salt struct
    p = hex2bin(data, (unsigned char *) salt.tgt_ebin, TGT_SIZE);
    if (*p || p - data != TGT_SIZE * 2)
	return NULL;

    return &salt;
}

/**
 * int valid
 *
 */
static int valid(char *ciphertext, struct fmt_main *self) {

    if (strncmp(ciphertext, MAGIC_PREFIX, MAGIC_PREFIX_LEN) != 0)
        return 0;

    return get_salt(ciphertext) ? 1 : 0;
}

/**
 * void set_salt
 *
 */
static void set_salt(void *salt) {
    psalt = (struct salt *) salt;
}

/**
 * void krb5_set_key
 *
 */
static void krb5_set_key(char *key, int index) {

    // copy the string key to the saved key
    memset(skey.passwd, 0x00, MAX_PASS_LEN);
    strnzcpy(skey.passwd, key, sizeof(skey.passwd));

}

/**
 * char * get_key
 *
 */
static char * get_key(int index) {
    return skey.passwd;
}

/**
 * void crypt_all
 *
 */
static int crypt_all(int *pcount, struct db_salt *salt)
{
	return *pcount;
}

/**
 * int cmp_all
 *
 */
static int cmp_all(void *binary, int count) {
    return decrypt_compare();
}

/**
 * int cmp_one
 *
 */
static int cmp_one(void *binary, int count) {

    return decrypt_compare();

}

/**
 * int cmp_exact
 *
 */
static int cmp_exact(char *source, int index)
{
    return 1;
}

/**
 * void init
 *
 */
static void init(struct fmt_main *self) {

    memset(&ivec, 0x00, sizeof(ivec));
    memset(&skey, 0x00, sizeof(skey));
    memset(krb5key, 0x00, sizeof(krb5_key));

    krb5key->key = (char *) mem_alloc(DES3_KEY_SIZE);
    krb5key->schedule = (char *) mem_alloc(DES3_KEY_SCHED_SIZE);
    memset(krb5key->key, 0x00, DES3_KEY_SIZE);
    memset(krb5key->schedule, 0x00, DES3_KEY_SCHED_SIZE);

}

static void done(void)
{
	MEM_FREE(krb5key->schedule);
	MEM_FREE(krb5key->key);
}

/**
 * fmt_main struct with KRB5 values
 */
struct fmt_main fmt_KRB5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ MAGIC_PREFIX },
		fmt_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		krb5_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */
