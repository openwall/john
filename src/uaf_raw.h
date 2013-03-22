#ifndef UAF_RAW_H
#define UAF_RAW_H
/*
 * Record layout for OpenVMS sysuaf.dat records, distilled from UAF070.SDL
 * The native data file is a prolog 3 indexed file with variable length
 * records, maximum length=1412 (644 VMS, 768 user).  For use on a Unix system
 * the file needs to be converted /pad to fixed length records. Record is
 * only defined in detail up to the last field we are interested in (flags),
 * remainder (process quotas, hour restrictions, etc) is rolled into
 * fixed_fill array.
 *
 * Define composite types embedded in the record  text fields are either
 * blank filled (username, account type) or blank filled counted strings.
 */
#include <stddef.h>
typedef struct {
    unsigned char len;
    char s[31];
} vstring32;			/* counted string */
typedef struct {
    unsigned char len;
    char s[63];
} vstring64;			/* counted string */
typedef unsigned int uafrec_qword[2];	/* so alignment not messed up */
typedef int uafrec_bintime[2];	/* VMS binary time (100-nsec ticks) */
typedef struct uafrec_flags_def {
    unsigned disctly : 1;	/* no user control-Y */
    unsigned defcli : 1;	/* force default CLI */
    unsigned lockpwd : 1;
    unsigned restricted : 1;   /* 0000008 */
    unsigned disacnt : 1;
    unsigned diswelcome : 1;
    unsigned dismail : 1;
    unsigned nomail : 1;	/* 000080 */
    unsigned genpwd : 1;
    unsigned pwd_expired : 1;
    unsigned pwd2_expired : 1;
    unsigned audit : 1;		/* 000800 */
    unsigned disreport : 1;     /* 001000 */
    unsigned disreconnect : 1;
    unsigned autologin : 1;	/* auto-login only */
    unsigned disforce_pwd_change : 1;
    unsigned captive : 1;	/* 0010000 */
    unsigned disimage : 1;
    unsigned dispwddic : 1;
    unsigned dispwdhis : 1;
    unsigned devclsval : 1;	/* default classificaitonis valid  0100000 */
    unsigned extauth : 1;	/* use external authoriation */
    unsigned migratepwd : 1;	/* migrate UAF to external auth */
    unsigned vmsauth : 1;	/* allow VMS DOI even if extauth set */
    unsigned dispwdsynch : 1;	/* no ACME password sharing 1000000 */
    unsigned pwdmix : 1;	/* use mixed-case passwords 2000000 */
} uaf_flags_bitset;

struct uaf_rec {
    /*
     * Header section, 4 bytes.  User data is for use by third party
     * privileged applications.
     */
    unsigned char rtype;	/* record type: 1=user_id */
    unsigned char version;	/* current version: 1 */
    unsigned short usrdatoff;   /* byte offset to user data */
    /*
     * 3 index keys: username, UIC, UIC group (overlaps UIC).
     */
    char username[32];		/* blank filled, max of 12 used */
    struct {
	unsigned short int mem;
	unsigned short int grp;
    } uic;			/* user identification code */
    unsigned int sub_id;	/* User sub-identifier? */
    uafrec_qword parent_id;	/* ??? */
    /*
     * Account attributes expressed as text.
     */
    char account[32];		/* Only 8 used. */
    vstring32 owner;		/* Name of owner */
    vstring32 defdev;		/* default device */
    vstring64 defdir;		/* default directory */
    vstring64 lgicmd;		/* Login command file */
    vstring32 defcli;		/* Default CLI (DCL) */
    vstring32 clitables;
    /*
     * Authentication information.
     */
    uafrec_qword pwd, pwd2;	/* Hash of password and secondary password */
    unsigned short int logfails;
    unsigned short int salt;	/* random password salt */
    unsigned char encrypt, encrypt2;	/* Encryption algorithm */
    unsigned char pwd_length;	/* minimum password length */
    unsigned char fill_1;	/* Align to longoword */

    uafrec_bintime expiration;	/* account expiration date */
    uafrec_bintime pwd_lifetime;	/* password lifetime */
    uafrec_bintime pwd_date, pwd2_date;	/* date of last password change */
    uafrec_bintime lastlogin_i, lastlogin_n;
    /*
     * Account privileges (trucated).
     */
    uafrec_qword priv;		/* authorized privileges */
    uafrec_qword def_priv;		/* default privileges */
    char min_class[20];		/* Minimum security class */
    char max_class[20];
    union {
	uaf_flags_bitset flags;
	unsigned flagbits;
    };

    unsigned char fixed_fill[128+44];
    unsigned char user_fill[768];
};
#define UAF_REC_SIZE (sizeof(struct uaf_rec))
#define UAF_REC_MIN_USRDATOFF (offsetof(struct uaf_rec,user_fill))
#define UAF_RECTYPE_USER 1
#define UAF_REC_USER_VERSION 1

#define UAF_FLG_DISACNT
/*
 * consistency check.
 */
#ifdef VMS
#include <uaf070def>		/* 7.0 layout 'locked' for compatibility */
#pragma assert non_zero(sizeof(struct uaf_rec) == sizeof(uaf070)) \
	"uaf_rec is wrong size"
#endif
#endif
