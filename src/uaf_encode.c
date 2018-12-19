/*
 * Define functions to encode/decode SYSUAF password information as a
 * printable string suitable for use in a UNIX-style passwd file (i.e. no
 * colons).
 *
 * The password string is 29 characters of the form:
 *
 *    $V$hhhhhhhhhhhhuuuuuuuuuuuuuu
 *
 * where:
 *    $V$	    Tags field as VMS SYSUAF format.
 *    hhhhhhhhhhhhh (12 characters) Encodes the 64-bit password hash and 8-bit
 *                  algorithm code (e.g. PURDY_V) in 12 characters (6-bit/char).
 *    uuuuuuuuuuuuu (14 characters) Encodes 16-bit salt value and 12 character
 *		    username (stored as RAD-50) and 4 flags bits:
 *                     <0>  If set, mixed case password in use.
 *
 * The username is an implicit 'salt' for the VMS password hash algorithms so
 * that information must be carried along in the password string.
 *
 * Encoding is 6 bits per character:
 *
 *    0000000000111111111122222222223333333333444444444455555555556666
 *    0123456789012345678901234567890123456789012345678901234567890123
 *    -ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789abcedfghijklmnopqrstuvwxyz+
 *
 * Author:	David Jones
 * Date:	11-JUL-2209
 * Revised:	14-AUG-2009	Initialize P in main thread.
 * Revised:     11-SEP-2011	Update format description.
 * Revised:	23-SEP-2011	Add uaf_extract_from_raw() function.
 *
 * Copyright (c) 2011 by David L. Jones <jonesd/at/columbus.rr.com>, and
 * is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#ifndef _uaf_encode_plug_
#define _uaf_encode_plug_
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include "arch.h"
#ifdef VMS
#include <descrip.h>
#include <uaidef.h>
#include <starlet.h>
#define UAIsC_AD_II UAI_C_AD_II
#define UAIsC_PURDY UAI_C_PURDY
#define UAIsC_PURDY_V UAI_C_PURDY_V
#define UAIsC_PURDY_S UAI_C_PURDY_S
#define UAIsM_PWDMIX UAI_M_PWDMIX
#else
/*
 * Emulate symbols defined for VMS services.
 */
#define UAIsC_AD_II 0
#define UAIsC_PURDY 1
#define UAIsC_PURDY_V 2
#define UAIsC_PURDY_S 3
#define UAIsM_PWDMIX 0x2000000

struct dsc_descriptor_s {
    unsigned short int dsc_w_length;
    unsigned char dsc_b_dtype, dsc_b_char;
    char *dsc_a_pointer;
};
#define _DESCRIPTOR(x,s) struct dsc_descriptor_s x={sizeof(s), 1, 1, s}
#endif

#ifdef HAVE_PTHREADS
#include <pthread.h>
#define PTHREAD_MUTEX_INITIALIZER 0
#define pthread_mutex_lock(lckp) *lckp=1
#define pthread_mutex_unlock(lckp) *lckp=0
#endif   /* HAVE_PTHREADS */

#include "uaf_raw.h"
#include "uaf_encode.h"

/*
 * Declare static globals that don't change once initialized as well as
 * pthread objects used to sychronize access and/or initialization.
 */
#ifdef HAVE_PTHREADS
static pthread_mutex_t uaf_static = PTHREAD_MUTEX_INITIALIZER;
#endif
static const char *enc_set =
	"-ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789abcedfghijklmnopqrstuvwxyz+";
static const char *r50_set = " ABCDEFGHIJKLMNOPQRSTUVWXYZ$._0123456789";
#define SYSUAF_FMT "$V$%64q%8b%16w%64T%4b"
static int enc_map_ready = 0;
static unsigned short enc_map[256];
static unsigned short r50_map[256];
/*
 * Forward reference to main function that hashes a password as OpenVMS does
 * in its SYSUAF file.  Function takes same arguments as SYS$HASH_PASSWORD
 * system service but in different order.
 */
static int hash_password ( uaf_qword *, 	/* Receives result hash */
	struct dsc_descriptor_s *, 		/* Password */
	unsigned char, unsigned short,		/* Algorithm code and salt */
	struct dsc_descriptor_s *);		/* Username (eff. more salt) */

/****************************************************************************/
/* Internal helper functions.
 */
static void init_enc_map ( void )
{
    int i;
    memset ( enc_map, 0, sizeof(enc_map) );
    for ( i = 0; enc_set[i]; i++ ) {
	enc_map[(unsigned char) enc_set[i]] = i;
    }
    memset ( r50_map, 255, sizeof(r50_map) );
    for ( i = 0; r50_set[i]; i++ ) {
	r50_map[(unsigned char) r50_set[i]] = i;
    }
    enc_map_ready = 1;
}
/*
 * Pack 12-character usernames into 4 16-bit words.
 */
static void decode_T_field ( unsigned short text[4], unsigned char *s )
{
    int i, j;
    unsigned short a, ci[3];
    unsigned char *start;

    start = s;
    for ( i = 0; i < 4; i++ ) {
	a = text[i];
	ci[0] = a % 40;
	a = a / 40;
	ci[1] =  a % 40;
	ci[2] = a / 40;

	for ( j = 0; j < 3; j++ ) *s++ = r50_set[ci[j]];
    }
    while ( s > start ) {		/* trim trailing blanks */
	if ( s[-1] != ' ' ) break;
	--s;
    }
    *s = '\0';
}
static int encode_T_field ( unsigned char *s, unsigned short text[4] )
{
    int i, j, status;
    unsigned short c, ci[3];

    status = 1;
    /*
     * Produce 4 words of output.
     */
    for ( i = 0; i < 4; i++ ) {
	/*
	 * Map ASCII to a limited 40 character set to pack 3 characters in
	 * 16 bits (40^3 = 64000).
	 */
	for ( j = 0; j < 3; j++ ) {
	    unsigned short cindex;
	    if ( *s ) c = *s++; else c = ' ';
	    cindex = r50_map[c];
	    if ( cindex > 40 ) {
		cindex = r50_map['.'];
		status = 0;		/* remember invalid character seen. */
	    }

	    ci[j] = cindex;	/* value is offset */
	}
	text[i] = ci[2]*1600 + ci[1]*40 + ci[0];
    }
    return status;
}
/*
 * Encode buffers into string using format string. "$V$%64q%8b%16w%2l"
 */
static int encode_6bit ( void *buffer, size_t bufsize, const char *fmt, ... )
{
    va_list ap;
    int fpos, apos, out_count, field_size, arg_bytes;
    uaf_lword accum, zext;
    unsigned char *out, *arg;
    /*
     * Outer loop, parse format argument
     */
    out_count = 0;
    out = buffer;
    accum = 0;			/* accumulate bits for output */
    apos = 0;			/* Number of bits accumulated */
    va_start(ap,fmt);
    for ( fpos = 0; fmt[fpos]; fpos++ ) if ( fmt[fpos] == '%' ) {
	/*
	 * Interpret format directive, either % or nnt when nn is number
	 * of bits and t is type: q-quadqord, l-longword, w-word, b-byte.
     */
	fpos++;
	if ( fmt[fpos] == '%' ) {
	    out[out_count++] = '%';
	    continue;
	}

	for ( field_size = 0; isdigit((int)(unsigned char)fmt[fpos]); fpos++ ) {
		field_size = field_size*10 + (fmt[fpos]-'0');
	}
	arg = va_arg(ap, unsigned char *);

	switch ( fmt[fpos] ) {
	  case 'T':			/* quadword of rad-50 'Text' */
	  case 'q':
		arg_bytes = 8;
		break;
	  case 'l':
		arg_bytes = 4;
		break;
	  case 'w':
		arg_bytes = 2;
		break;
	  case 'b':
		arg_bytes = 1;
		break;
	  default:
		/* Invalid directive, ignored */
		arg_bytes = 0;
		break;
	}
        /*
	 * Input text string is rad-50 compressed quadword followed by
         * expanded string if  'T' format.
	 */
	if ( fmt[fpos] == 'T' ) {
	    encode_T_field ( arg+8, (unsigned short *) arg );
	}
	/*
	 * Produce field_size bits of output from arg_bytes input bytes.
	 * Zero fill if argument size less than field size.
	 */
	while ( field_size > 0 ) {
	    if ( arg_bytes > 0 ) {
		zext = *arg++;
		arg_bytes--;
	    } else {
		zext = 0;
	    }
	    accum = accum | (zext<<apos);
	    apos += (field_size > 8) ? 8 : field_size;
	    field_size -= 8;
	    while ( apos >= 6 ) {
		if ( (out_count+1) >= bufsize ) {
		    out[out_count] = 0;
		    return out_count;
		}
		out[out_count++] = enc_set[accum&63];
		accum = (accum>>6);
		apos = apos-6;
	    }
	}
    } else {
	/*
	 * Move character verbatim from format string to output,  flush
	 * partial encoding bits accumulated.
	 */
	while ( apos > 0 ) {
	    if ( (out_count+1) >= bufsize ) {
		out[out_count] = 0;
		return out_count;
	    }
	    out[out_count++] = enc_set[accum&63];
	    accum = accum>>6;
	    apos = (apos >= 6) ? apos-6 : 0;
	}
	out[out_count++] = (unsigned char) fmt[fpos];
    }
    va_end(ap);

    out[out_count] = 0;			/* terminate string */
    return out_count;

}
/*
 * Decode encoded buffer via format string.
 */
static int decode_6bit ( void *buffer, const char *fmt, ... )
{
    va_list ap;
    int fpos, apos, field_size, arg_bytes;
    uaf_lword accum;
    unsigned char *in, *arg;
    /*
     * Outer loop, parse format argument
     */
    in = buffer;
    accum = 0;			/* accumulate bits for output */
    apos = 0;			/* Number of bits accumulated */
    va_start(ap,fmt);
    for ( fpos = 0; fmt[fpos]; fpos++ ) if ( fmt[fpos] == '%' ) {
	/*
	 * Interpret format directive, either % or nnt when nn is number
	 * of bits and t is type: q-quadqord, l-longword, w-word, b-byte.
	 */
	fpos++;
	if ( fmt[fpos] == '%' ) {
	    if ( *in != '%' ) {
		return -1;
	    }
	    in++;
	    continue;
	}

	for ( field_size = 0; isdigit((int)(unsigned char)fmt[fpos]); fpos++ ) {
	    field_size = field_size*10 + (fmt[fpos]-'0');
	}
	arg = va_arg(ap, unsigned char *);

	switch ( fmt[fpos] ) {
	  case 'T':			/* rad-50 encoding of text */
	  case 'q':
		arg_bytes = 8;
		break;
	  case 'l':
		arg_bytes = 4;
		break;
	  case 'w':
		arg_bytes = 2;
		break;
	  case 'b':
		arg_bytes = 1;
		break;
	  default:
		/* Invalid directive, ignored */
		arg_bytes = 0;
		break;
	}
	/*
	 * Move field_size bits of input to argument buffer.
	 * Zero fill if field is less than argument size.
	 */
	while ( field_size > 0 ) {
	    while ( apos < 8 ) {
		if ( !*in ) break;		/* buffer short */
		accum |= (enc_map[*in++]<<apos);
		apos += 6;
	    }
	    if ( arg_bytes > 0 ) {
		*arg++ = accum&255;
		arg_bytes--;
		accum = (accum>>8);
		apos = (apos < 8) ? 0 : apos - 8;
	    }
	    field_size -= 8;
	}
	if ( arg_bytes > 0 )   {
	    /* Flush accumulated bits and zero remaining buffer */
	    while ( apos > 0 ) {
		*arg++ = accum&255;
		arg_bytes--;
		accum = (accum>>8);
		apos = (apos < 8) ? 0 : apos - 8;
	    }
	    while ( arg_bytes > 0 ) { *arg++ = 0; arg_bytes--; }
	}
	/*
	 * Convert T quadword back to ASCII zero-terminated string.
	 */
	if ( fmt[fpos] == 'T' ) {
	    decode_T_field ( (unsigned short *) (arg-8), arg );
	}
    } else {
	/*
	 * non-directive characters in format must match characters in
	 * input buffer.
	 */
	if ( *in != fmt[fpos] ) return -1;
	in++;
    }
    va_end(ap);

    return 0;

}
/****************************************************************************/
/* External functions.
 */
char *uaf_hash_encode (
	struct uaf_hash_info *pwd,	/* Input argument */
	char encoded[UAF_ENCODE_SIZE] )	/* Output buffer */
{
    /*
     * Collapse the preserved flags to a 4-bit field.
     */
    pwd->opt = 0;
    if ( pwd->flags & UAIsM_PWDMIX ) pwd->opt |= 1;
    /*
     * Encode the string.
     */
    encode_6bit ( encoded, UAF_ENCODE_SIZE, SYSUAF_FMT,
	&pwd->hash, &pwd->alg, &pwd->salt, &pwd->username, &pwd->opt );
    return encoded;
}

int uaf_hash_decode (
	char *encoded,			/* Input argument */
	struct uaf_hash_info *pwd )	/* Output buffer */
{
    int err;
    /*
     * Decode the string.
     */
    err = decode_6bit ( encoded, SYSUAF_FMT, &pwd->hash, &pwd->alg,
	&pwd->salt, &pwd->username, &pwd->opt );
    /*
     * expand 4-bit flags field into standard UAI$_FLAGS bits.
     */
    pwd->flags = ((pwd->opt&1) ? UAIsM_PWDMIX : 0);

    return (err==0);
}

int uaf_getuai_info (
	const char *username, 		/* Username to find */
	struct uaf_hash_info *pwd,	/* Password info from UAF record */
	struct uaf_hash_info *pwd2,	/* Secondary password info */
	struct uaf_account_info *acct )
{
   static long uai_ctx = -1;		/* protected by uaf_static mutex */
#ifdef VMS
     _DESCRIPTOR(username_dx,"");
    char owner[32];			/* counted string */
    char defdev[32];			/* counted string */
    char defdir[64];			/* counted string */
    char defcli[32];
#define ITEM_LIST_SIZE 12
    struct {
	unsigned short length, code;
	void *buffer;
	unsigned short *retlen;
    } item[ITEM_LIST_SIZE];
#define SET_ITEM(ITM,l,c,b,r) ITM.length=(l); ITM.code=(c); \
	ITM.buffer=(b); ITM.retlen=(r)
    unsigned short retlen[ITEM_LIST_SIZE];
    int status, i;
    /*
     * Build item list for GETUAI call, the acct argument is optional.
     */
    SET_ITEM(item[0], 8, UAIs_PWD, &pwd->hash, 0 );
    SET_ITEM(item[1], 4, UAIs_FLAGS, &pwd->flags, 0 );
    SET_ITEM(item[2], 2, UAIs_SALT, &pwd->salt, 0 );
    SET_ITEM(item[3], 1, UAIs_ENCRYPT, &pwd->alg, 0 );
    SET_ITEM(item[4], 8, UAIs_PWD2, &pwd2->hash, 0 );
    SET_ITEM(item[5], 2, UAIs_ENCRYPT2, &pwd2->alg, 0 );
    SET_ITEM(item[6], 0, 0, 0, 0 );
    for ( i = 0; (i < 12) && username[i]; i++ )
	pwd->username.s[i] = toupper(username[i]);
    pwd->username.s[i] = '\0';
    memcpy (pwd2->username.s, pwd->username.s, sizeof(pwd->username.s));
    if ( acct ) {
	strcpy ( acct->username, pwd->username.s );
	SET_ITEM(item[6], 4, UAIs_UIC, &acct->uic, 0 );
	SET_ITEM(item[7], 32, UAIs_OWNER, owner, &retlen[7] );  /* counted str! */
	SET_ITEM(item[8], 32, UAIs_DEFDEV, defdev, &retlen[8] );
	SET_ITEM(item[9], 64, UAIs_DEFDIR, defdir, &retlen[9] );
	SET_ITEM(item[10], 32, UAIs_DEFCLI, defcli, &retlen[10] );
	SET_ITEM(item[11], 0, 0, 0, 0 );
    }
    /*
     * Call system to get the information and fixup.  Serialize.
     */
    pthread_mutex_lock ( &uaf_static );
    username_dx.dsc_a_pointer = (char *) username;
    username_dx.dsc_w_length = strlen(username);
    status = SYS_GETUAI ( 0, &uai_ctx, &username_dx, item, 0, 0, 0 );
    pthread_mutex_unlock ( &uaf_static );
    if ( (status&1) == 0 ) {
	return status;
    }
    pwd2->salt = pwd->salt;	/* Fill in pwd2 */
    pwd2->flags = pwd->flags;
#define CONVERT_COUNTED(zs,cs) memcpy(zs,&cs[1],cs[0]); zs[cs[0]] = '\0'
    if ( acct ) {
	CONVERT_COUNTED(acct->owner, owner);
	CONVERT_COUNTED(acct->home_dir, defdev);
	memcpy ( &acct->home_dir[defdev[0]], &defdir[1], defdir[0] );
	acct->home_dir[defdev[0]+defdir[0]] = '\0';
	CONVERT_COUNTED(acct->shell, defcli);
    }
    return status;
#else
    if ( uai_ctx == -1 ) {
#ifdef HAVE_PTHREADS
        pthread_mutex_lock ( &uaf_static );	/* just to fool compiler */
	uai_ctx = -2;
        pthread_mutex_unlock ( &uaf_static );
#endif
    }
    return 0;			/* Non-VMS system, always fails */
#endif
}
/*
 * Convert string to RAD-50 packed format and vice versa.  Conversion is
 * unpacked-to-packed if to_packed argument is non-zero and packed-to-unpacked
 * if zero.  Return value is 1 on success and 0 if string has invalid
 * characters for conversion.
 */
int uaf_packed_convert ( struct uaf_packed_text *username, int to_packed )
{
    int status;
    if ( to_packed ) {
	status = encode_T_field ((unsigned char *) username->s, username->r40);
    } else {
	decode_T_field ( username->r40, (unsigned char*) username->s );
	status = 1;
    }
    return status;
}
/*
 * Hash caller-supplied password and compare with hash value stored
 * in uaf_hash_info structure.  Return value is 1 for match.
 */
int uaf_test_password (
	struct uaf_hash_info *pwd,
	const char *password,		/* clear text password */
	int replace_if, uaf_qword *hashed_password )		/* Update pwd if false */
{
    char uc_username[32], uc_password[32];
    _DESCRIPTOR(username_dx, uc_username );
    _DESCRIPTOR(password_dx,"");
    int status, i, ulen;
    memset(hashed_password, 0, sizeof(uaf_qword));
    /*
     * Build VMS descriptors for system service arguments.
     */
    ulen = strlen ( pwd->username.s );
    if ( ulen > sizeof(uc_username)-1 ) return 0;	/* name too long */
    strcpy ( uc_username, pwd->username.s );
    username_dx.dsc_w_length = ulen;

    password_dx.dsc_w_length = strlen(password);
    if ( pwd->flags & UAIsM_PWDMIX ) {	/* take password verbatim */
	password_dx.dsc_a_pointer = (char *) password;
    } else {
	/*
	 * Upcase password.
	 */
	password_dx.dsc_a_pointer = uc_password;
	if ( password_dx.dsc_w_length > sizeof(uc_password) )
		password_dx.dsc_w_length = sizeof(uc_password);
	for ( i = 0; i < password_dx.dsc_w_length; i++ )
		uc_password[i] = toupper ( ARCH_INDEX(password[i]) );
    }
    /*
     * Try private implementation first (optimized) and fall back
     * to OS routine if failed.
     */
    status = hash_password ( hashed_password,
		&password_dx, pwd->alg, pwd->salt, &username_dx );

    if ( ((status&1) == 0) ) {
	printf("Retry... (lgi$hpwd2 status %d)\n", status );
    }
    if ( pwd->flags & UAIsM_PWDMIX ) memset ( uc_password, 0, sizeof(uc_password) );

    if ( (status&1) == 0 ) return 0;

    if ( UAF_QW_EQL(*hashed_password,pwd->hash) ) return 1;

    // if ( replace_if ) pwd->hash = hashed_password;

    return 0;
}

/*
 * Pull in hash function definition from an included file.  May be overridden
 * to allow alternate implentations.
 */
#define UAF_INCLUDED_FROM_ENCODE 1
#ifndef UAF_HASH_FUNCTION_COMPILE_TEST
 #ifdef UAF_HASH_FUNCTION_SOURCE
  #include UAF_HASH_FUNCTION_SOURCE
 #else
#ifndef ONE_TIME
#define ONE_TIME
  #include "uaf_hash.c"
#endif
 #endif /* UAF_HASH_INCLUDE */
#endif

#endif
