/*
 * Define functions to encode/decode SYSUAF password information as a
 * printable string suitable for use in a UNIX-style passwd file (i.e. no
 * colons)
 *
 * Copyright (c) 2011 by David L. Jones <jonesd/at/columbus.rr.com>, and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */
#ifndef _JOHN_UAF_ENCODE_H
#define _JOHN_UAF_ENCODE_H
#define UAF_ENCODE_SIZE 30
#if !AC_BUILT || HAVE_LIMITS_H
#include <limits.h>
#endif
#if UINT_MAX == ULONG_MAX
typedef unsigned long uaf_lword;
#else
#if UINT_MAX >= 2147483648
typedef unsigned int uaf_lword;		/* sizeof(long)==sizeof(long long)? */
#else
typedef unsigned long uaf_lword;	/* int < 32 bits, too short */
#endif
#endif
struct uaf_packed_text {
    unsigned short r40[4];		/* 12 chars, 3/word */
    char s[14];				/* Expanded to 1 char/byte */
};
#ifdef NOLONGLONG
#define HASH_INDEX(result,mask) result.info.hash.lw[LSL]&mask)
#else
#define HASH_INDEX(result,mask) result.info.hash.&mask)
#endif

#ifdef NOLONGLONG
#if !ARCH_LITTLE_ENDIAN
#define MSL 0
#define LSL 1		/* big endian ordering */
#else
#define MSL 1
#define LSL 0		/* little endian ordering */
#endif
typedef struct { unsigned long lw[2]; } uaf_qword;
#define UAF_QW_EQL(a,b) (((a).lw[0]==(b).lw[0]) && ((a).lw[1]==(b).lw[1]))
#define UAF_QW_GEQ(a,b) ((a).lw[MSL]>(b).lw[MSL]) || \
    ( ((a).lw[MSL]==(b).lw[MSL]) && ((a).lw[LSL]>=(b).lw[LSL]) )
#define UAF_QW_SET(a,n) (a).lw[LSL]=(n); (a).lw[MSL]=0
#define UAF_QW_ADD(q,l) { q.lw[LSL]+=l; if (q.lw[LSL] < l) q.lw[MSL]++; }
#define UAF_QW_AND(q,lwmask) ((q).lw[LSL]&lwmask)
#define UAF_QW_HINT_HASH(q,lwmask) (((q).lw[MSL]^(q).lw[LSL])&lwmask)
#else
typedef unsigned long long uaf_qword;
#define UAF_QW_EQL(a,b) (a==b)
#define UAF_QW_GEQ(a,b) (a>=b)
#define UAF_QW_SET(a,n) a=n
#define UAF_QW_ZEXT(a,n) a=n
#define UAF_QW_ADD(q,l) q += (l);
#define UAF_QW_AND(q,lwmask) ((q)&lwmask)
#define UAF_QW_HINT_HASH(q,lwmask) (((q)^((q)>>32))&lwmask)
#endif
struct uaf_hash_info {
    uaf_qword hash;			/* UAI$_PWd */
    long flags;				/* UAI$_FLAGS, only bits preseved: */
					/*     UAI$M_PWDMIX  */
					/*     UAI$M_EXTAUTH */
    unsigned short salt;		/* UAI$_SALT */
    unsigned char alg;			/* UAI$_ALGORITHM */
    unsigned char opt;			/* <0> = (flags&UAI$M_PWDMIX) */
    struct uaf_packed_text username;   /* RAD-50 encoded username */
};
/*
 * Structure is filled in with zero-terminated strings.
 */
struct uaf_account_info {
    char username[32];			/* Username, upcased */
    unsigned short uic[2];
    char owner[32];			/* Name of account owner */
    char home_dir[96];
    char shell[32];
};
/*
 * Basic functions for converting UAF information between binary form and
 * printable string (form used to store in passwd file).
 */
char *uaf_hash_encode (
	struct uaf_hash_info *pwd,	/* Input argument */
	char encoded[UAF_ENCODE_SIZE] );	/* Output buffer */

int uaf_hash_decode (
	char *encoded,			/* Input argument */
	struct uaf_hash_info *pwd );	/* Output buffer */
int uaf_packed_convert ( struct uaf_packed_text *username, int to_packed );
/*
 * Function to hash a clear text password with the salt value in a uaf_hash_info
 * structure and compare the result with the hash value stored there.
 */
int uaf_test_password (
	struct uaf_hash_info *pwd,
	const char *password,		/* clear text password */
	int replace_if, uaf_qword *hashed_password);		/* Update pwd if false */

int uaf_init ( void );			/* one-time init for hash func. */
/*
 * Wapper for system function to retrieve authorization information for SYSUAF
 * data file /
 * compute hash from password.  Return value is VMS status code.
 */
int uaf_getuai_info (
	const char *username, 		/* Username to find */
	struct uaf_hash_info *pwd,	/* Password info from UAF record */
	struct uaf_hash_info *pwd2,	/* secondary password info */
	struct uaf_account_info *acct );

#define UAF_RAW_REC_LENGTH 1412
#define UAF_RAW_REC_MIN_LENGTH 644
int uaf_extract_from_raw ( void *rec, int rec_len,
	struct uaf_hash_info *pwd,
	struct uaf_hash_info *pwd2,
	struct uaf_account_info *acct,
	char **acct_status,		/* Disuser, Expired, Valid */
	char **priv_summary );		/* Normal, All, Devour */
#endif
