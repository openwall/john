/*
 * Copyright (C) 2013 Dhiru Kholia
 * Modified "pgpdump" for JtR
 *
 * https://github.com/kazu-yamamoto/pgpdump
 *
 * cat pgpdump.c types.c tagfuncs.c packet.c subfunc.c signature.c keys.c buffer.c uatfunc.c > ~/combined.c
 *
 * Copyright (C) 2002 Kazuhiko Yamamoto
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
//#include <libgen.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>

#if !AC_BUILT
 #if !__MIC__
 #define HAVE_LIBZ 1
 #endif
 #include <string.h>
 #ifndef _MSC_VER
  #include <strings.h>
 #endif
#else
 #include "autoconfig.h"
 #if STRING_WITH_STRINGS
  #include <string.h>
  #include <strings.h>
 #elif HAVE_STRING_H
  #include <string.h>
 #elif HAVE_STRINGS_H
  #include <strings.h>
 #endif
#endif

#include "arch.h"
#ifdef HAVE_UNIXLIB_LOCAL_H
#include <unixlib/local.h>
int __riscosify_control = __RISCOSIFY_NO_PROCESS;
#define PATH_SEPC '.'
#else  /* HAVE_UNIXLIB_LOCAL_H */
#define PATH_SEPC '/'
#endif /* HAVE_UNIXLIB_LOCAL_H */

#define public extern
#define private static

typedef char * string;
typedef unsigned char byte;

#if HAVE_LIBZ
#include <zlib.h>
private int inflate_gzip(byte *, unsigned int);
private z_stream z;
#endif  /* HAVE_LIBZ */

// HAVE_LIBBZ2 is defined in autoconfig.h for autoconf builds.
// #define HAVE_LIBBZ2 1

#if HAVE_LIBBZ2
#include <bzlib.h>
private int inflate_bzip2(byte *, unsigned int);
private bz_stream bz;
#endif  /* HAVE_LIBBZ2 */

#if TIME_WITH_SYS_TIME
 #include <sys/time.h>
 #include <time.h>
#else
 #if HAVE_SYS_TIME_H
  #include <sys/time.h>
 #else
  #include <time.h>
 #endif
#endif

#ifdef _MSC_VER
#define HAVE_TZNAME 1
#endif

#if HAVE_STRUCT_TM_TM_ZONE
 #define tm_zone(tm) (tm->tm_zone)
#elif HAVE_TZNAME
 #define tm_zone(tm) (tzname[tm->tm_isdst])
#elif __MINGW32__
 #define tm_zone(tm) (tzname[tm->tm_isdst])
#else
 #ifndef tzname  /* For SGI. */
  extern string tzname[]; /* RS6000 and others reject char **tzname. */
 #endif
 #define tm_zone(tm) (tzname[tm->tm_isdst])
#endif

#include "jumbo.h"
#include "misc.h"
#include "params.h"
#include "memory.h"

#define YES 1
#define NO  0

#define NULL_VER -1

/* Global Stuff */

static unsigned char d[16384]; // used for RSA, more than big enough
static unsigned char u[16384]; // used for RSA, more than big enough
static unsigned char p[16384];
static unsigned char q[16384];
static unsigned char g[16384];
static unsigned char y[16384];
static unsigned char n[16384];
static unsigned char e[16384];
static unsigned char m_data[90000];  // FIXME: I think 8192 is biggest data per block ???
static char gecos[1024];
static char *last_hash;
static unsigned char m_salt[64];
static unsigned char iv[16];
static char *filename;
static int offset;
static int gpg_dbg;
static int dump_subkeys;
static int is_subkey;
static size_t m_flen;

static int m_spec;
static int m_algorithm;
//static int m_datalen;
static unsigned key_bits;
static unsigned d_bits;
static unsigned p_bits;
static unsigned q_bits;
static unsigned g_bits;
static unsigned y_bits;
static unsigned n_bits;
static unsigned u_bits;
static unsigned e_bits;
static int m_usage, m_hashAlgorithm, m_cipherAlgorithm, bs;
static int m_count;
static int hash_generated = 0;


/* Global data for read_radix64 and decode_radix64 functions, reset for each new file */
static int done_rr = NO;
static int done_dr = NO;
static unsigned int avail_dr = 0;
static int found_rr = NO;
static byte *qdr = NULL;

/*
 * pgpdump.c
 */

public void warning(const string, ...);
public void warn_exit(const string, ...);
public void skip(unsigned);
public void dump(unsigned);
public void pdump(unsigned);
public void kdump(unsigned);
public int give(const unsigned, unsigned char *, const unsigned);

/*
 * buffer.c
 */

public void Compressed_Data_Packet(int);

public void set_armor(void);
public void set_binary(void);

public int Getc(void);
public int Getc1(void);
public int Getc_getlen(void);
public void Getc_resetlen(void);

/*
 *  packet.c
 */

public void parse_packet(char *);
public void parse_signature_subpacket(string, int);
public void parse_userattr_subpacket(string, int);

/*
 * types.c
 */

public void pub_algs(unsigned int);
public void sym_algs(unsigned int);
public char *sym_algs2(unsigned int);
public int  iv_len(unsigned int);
public void comp_algs(unsigned int);
public char *hash_algs(unsigned int);
public void key_id(void);
public void fingerprint(void);
public void time4(string);
public void sig_creation_time4(string);
public void sig_expiration_time4(string);
public void key_creation_time4(string);
public void key_expiration_time4(string);
public void ver(int, int, int);
public int string_to_key(void);
public void multi_precision_integer(string);

/*
 * tagfunc.c
 */
public void Reserved(int);
public void Public_Key_Encrypted_Session_Key_Packet(int);
public void Symmetric_Key_Encrypted_Session_Key_Packet(int);
public void Symmetrically_Encrypted_Data_Packet(int,int,int,char*);
public void Marker_Packet(int);
public void Literal_Data_Packet(int);
public void Trust_Packet(int);
public void User_ID_Packet(int);
public void User_Attribute_Packet(int);
public void Symmetrically_Encrypted_and_MDC_Packet(int,int,int,char*);
public void Modification_Detection_Code_Packet(int);
public void Private_Packet(int);

/*
 * keys.c
 */

public void Public_Key_Packet(int);
public void Public_Subkey_Packet(int);
public void Secret_Key_Packet(int);
public void Secret_Subkey_Packet(int);

/*
 * signature.c
 */

public void One_Pass_Signature_Packet(int);
public void Signature_Packet(int);

/*
 * subfunc.c
 */

public void signature_creation_time(int);
public void signature_expiration_time(int);
public void exportable_certification(int);
public void trust_signature(int);
public void regular_expression(int);
public void revocable(int);
public void key_expiration_time(int);
public void additional_decryption_key(int);
public void preferred_symmetric_algorithms(int);
public void revocation_key(int);
public void issuer_key_ID(int);
public void notation_data(int);
public void preferred_hash_algorithms(int);
public void preferred_compression_algorithms(int);
public void key_server_preferences(int);
public void preferred_key_server(int);
public void primary_user_id(int);
public void policy_URL(int);
public void key_flags(int);
public void signer_user_id(int);
public void reason_for_revocation(int);
public void features(int);
public void signature_target(int);
public void embedded_signature(int);

/*
 * uatfunc.c
 */

public void image_attribute(int);

/*
 * pgpdump.c
 */
static int aflag;
//static int dflag;
//static int gflag;
//static int iflag;
static int lflag;
static int mflag;
//static int pflag;
static int uflag;

public void
warning(const string fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

public void
warn_exit(const string fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static int print_hex(unsigned char *str, int len, char *cp)
{
	int i;
	for (i = 0; i < len; ++i)
		cp += sprintf(cp, "%02x", str[i]);
	return len*2;
}

int gpg2john(int argc, char **argv)
{
	int i;
	int something_failed = 0;

	while (argc > 2 && (!strcmp(argv[1], "-d") || !strcmp(argv[1], "-S"))) {
		if (!strcmp(argv[1], "-d"))
			gpg_dbg = 1;
		else
			dump_subkeys = 1;
		for (i = 1; i < argc; ++i)
			argv[i] = argv[i+1];
		--argc;
	}
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-d] [-S] <GPG Secret Key File(s)>\n", argv[0]);
		fprintf(stderr, "   if -d is used, then debugging of the object types decoded is written\n");
		fprintf(stderr, "   if -S is used, then subkeys will also be output\n");
		exit(-1);
	}

	for (i = 1; i < argc; ++i) {
		FILE *fp;
		char *hash;
		char *marker = NULL;
		size_t ret = 0;

		/* reset global state */
		done_rr = NO;
		done_dr = NO;
		avail_dr = 0;
		found_rr = NO;
		qdr = NULL;
		hash_generated = 0;

		fprintf(stderr, "\nFile %s\n", argv[i]);
		filename = argv[i];
		fp = fopen(filename, "rb");
		if (!fp) {
			fprintf(stderr, "%s: %s!\n", filename, strerror(errno));
			something_failed = 1;
			continue;
		}
		jtr_fseek64(fp, 0, SEEK_END);
		m_flen = (size_t)jtr_ftell64(fp);
		jtr_fseek64(fp, 0, SEEK_SET);
		hash = mem_alloc((m_flen + 256) << 1);
		ret = fread(hash, m_flen, 1, fp);
		if (ret != 1) {
			fprintf(stderr, "%s: unable to load in memory!\n", filename);
			something_failed = 1;
		}
		marker = memmem(hash, m_flen, "---BEGIN", 8);
		if (marker) {
			if (m_flen - (int)(marker - hash) - 1 > 8) {
				marker = memmem(marker + 1, m_flen - (int)(marker - hash) - 1, "---BEGIN", 8);
				if (marker) {
					fprintf(stderr, "Error: Ensure that the input file %s "
					        "contains a single private key only.\n", filename);
					something_failed = 1;
				}
			}
		}
		fclose(fp);
		if (freopen(filename, "rb", stdin) == NULL)
			warn_exit("can't open %s.", filename);
		parse_packet(hash);
		if (last_hash && *last_hash) {
			char login[4096], *cp;
			const char *ext[] = {".gpg", ".pgp"};

			if (!gecos[0]) {
				cp = strip_suffixes(jtr_basename(filename), ext, 2);
				strnzcpy(gecos, cp, sizeof(gecos));
			}
			strnzcpy(login, gecos, sizeof(login));
			if ((cp = strchr(login, '('))) 	memset(cp, 0, 1);
			if ((cp = strrchr(login, '<'))) memset(cp, 0, 1);
			replace(login, ':', ' ');
			cp = &login[strlen(login) - 1];
			while (cp > login && *cp == ' ') *cp-- = 0;
			printf("%s:%s:::%s::%s\n", login, last_hash, gecos, filename);
			MEM_FREE(last_hash);
		}
		if (!hash_generated) {
			fprintf(stderr, "Error: No hash was generated for %s, ensure that the input file contains a single private key only.\n", filename);
			MEM_FREE(hash);
			something_failed = 1;
			continue;
		}
		MEM_FREE(hash);
	}

	if (something_failed)
		exit(EXIT_FAILURE);
	exit(EXIT_SUCCESS);
}

public void
skip(unsigned len)
{
	int i;
	for (i = 0; i < len; i++)
		Getc();
}

public void
dump(unsigned len)
{
	int i;
	for (i = 0; i < len; i++)
		fprintf(stderr, "%02x", Getc());
}

public int
give(const unsigned len, unsigned char *buf, const unsigned buf_size)
{
	int i, tmp;

	if (len > buf_size)
		warn_exit("Bad parameter: give(len=%u, buf=%p, buf_size=%u), len can not be bigger than buf_size.",
			len, buf, buf_size);

	for (i = 0; i < len; i++) {
		tmp = Getc();
		if (tmp == EOF)
			return -1;
		buf[i] = tmp;
	}
	return len;
}

public void
pdump(unsigned len)
{
	int i;
	for (i = 0; i < len; i++)
		fprintf(stderr, "%c", Getc());
}

public void
give_pdump(unsigned len)
{
	int i;

	if (len > sizeof(gecos))
		warn_exit("Bad parameter: give_pdump(len=%u), len can not be bigger than sizeof(gecos)=%u.",
			len, sizeof(gecos));

	for (i = 0; i < len; i++)
		gecos[i] = Getc();
	gecos[i] = 0;
}

public void
kdump(unsigned len)
{
        int i;
        fprintf(stderr, "0x");
        for (i = 0; i < len; i++)
                fprintf(stderr, "%02X", Getc());
}

/*
 * types.c
 */

private void time4_base(string, time_t *);
private time_t key_creation_time = 0;
private time_t sig_creation_time = 0;

/* private string
PUB_ALGS[] = {
	"unknown(pub 0)",
	"RSA Encrypt or Sign(pub 1)",
	"RSA Encrypt-Only(pub 2)",
	"RSA Sign-Only(pub 3)",
	"unknown(pub 4)",
	"unknown(pub 5)",
	"unknown(pub 6)",
	"unknown(pub 7)",
	"unknown(pub 8)",
	"unknown(pub 9)",
	"unknown(pub 10)",
	"unknown(pub 11)",
	"unknown(pub 12)",
	"unknown(pub 13)",
	"unknown(pub 14)",
	"unknown(pub 15)",
	"ElGamal Encrypt-Only(pub 16)",
	"DSA Digital Signature Algorithm(pub 17)",
	"Reserved for Elliptic Curve(pub 18)",
	"Reserved for ECDSA(pub 19)",
	"Reserved formerly ElGamal Encrypt or Sign(pub 20)",
	"Reserved for Diffie-Hellman (pub 21)",
}; */

#define PUB_ALGS_NUM (sizeof(PUB_ALGS) / sizeof(string))

public void
pub_algs(unsigned int type)
{
	/* printf("\tPub alg - ");
	if (type < PUB_ALGS_NUM)
		printf("%s", PUB_ALGS[type]);
	else
		printf("unknown(pub %u)", type);
	printf("\n"); */
}

private string
SYM_ALGS[] = {
	"Plaintext or unencrypted data(sym 0)",
	"IDEA(sym 1)",
	"Triple-DES(sym 2)",
	"CAST5(sym 3)",
	"Blowfish(sym 4)",
	"Reserved(sym 5)",
	"Reserved(sym 6)",
	"AES with 128-bit key(sym 7)",
	"AES with 192-bit key(sym 8)",
	"AES with 256-bit key(sym 9)",
	"Twofish with 256-bit key(sym 10)",
	"Camellia with 128-bit key(sym 11)",
	"Camellia with 192-bit key(sym 12)",
	"Camellia with 256-bit key(sym 13)",
};

#define SYM_ALGS_NUM (sizeof(SYM_ALGS) / sizeof(string))

public void
sym_algs(unsigned int type)
{
	if (gpg_dbg) fprintf(stderr, "\tSym alg - ");
	m_cipherAlgorithm = type;
	if (gpg_dbg) fprintf(stderr, "%s\n", sym_algs2(type));
}

public char *
sym_algs2(unsigned int type)
{
	static char S[48];
	if (type < SYM_ALGS_NUM)
		return SYM_ALGS[type];
	sprintf(S, "unknown(sym %u)", type);
	return S;
}

private int
IV_LEN[] = {
	0,      /* Plaintext */
	8,	/* IDEA */
	8,	/* Triple-DES */
	8,	/* CAST5 */
	8,	/* Blowfish */
	8,	/* SAFER-SK128 */
	8,	/* Reserved for DES/SK (AES) */
	16,	/* AES-128 */
	16,	/* AES-192 */
	16,	/* AES-256 */
	16,	/* Twofish */
	16,	/* Camellia-128 */
	16,	/* Camellia-192 */
	16,	/* Camellia-256 */
};

public int
iv_len(unsigned int type)
{
	(void) SYM_ALGS; /* Mutes a compiler warning in clang */

	if (type < SYM_ALGS_NUM)
		return IV_LEN[type];
	else
		return 0;
}

/* private string
COMP_ALGS[] = {
	"Uncompressed(comp 0)",
	"ZIP <RFC1951>(comp 1)",
	"ZLIB <RFC1950>(comp 2)",
	"BZip2(comp 3)",
}; */

#define COMP_ALGS_NUM (sizeof(COMP_ALGS) / sizeof(string))

public void
comp_algs(unsigned int type)
{
	/* printf("\tComp alg - ");
	if (type < COMP_ALGS_NUM)
		fprintf(stderr, "%s", COMP_ALGS[type]);
	else
		fprintf(stderr, "unknown(comp %u)", type);
	printf("\n"); */
}

private string
HASH_ALGS[] = {
	"unknown(hash 0)",
	"MD5(hash 1)",
	"SHA1(hash 2)",
	"RIPEMD160(hash 3)",
	"Reserved(hash 4)",
	"Reserved(hash 5)",
	"Reserved(hash 6)",
	"Reserved(hash 7)",
	"SHA256(hash 8)",
	"SHA384(hash 9)",
	"SHA512(hash 10)",
	"SHA224(hash 11)",
};

#define HASH_ALGS_NUM (sizeof(HASH_ALGS) / sizeof(string))

public char *
hash_algs(unsigned int type)
{
	static char S[48];
	if (type < HASH_ALGS_NUM)
		return HASH_ALGS[type];
	sprintf(S, "unknown(hash %u)", type);
	return S;
}

public void
key_id(void)
{
	if (gpg_dbg) fprintf(stderr, "\tKey ID - ");
	if (gpg_dbg)
		kdump(8);
	else
		skip(8);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
fingerprint(void)
{
	if (gpg_dbg) fprintf(stderr, "\tFingerprint - ");
	if (gpg_dbg)
		dump(20);
	else
		skip(20);
	if (gpg_dbg) fprintf(stderr, "\n");
}

private void
time4_base(string str, time_t *pt)
{
	struct tm* ptm;
	char* pat;
	// char* pyr;

	if (*pt < 0) {  /* 32 bit time_t and after 2038-01-19 */
		fprintf(stderr, "\t%s - cannot print date after 2038-01-19\n", str);
		return;
	}

	ptm = uflag ? gmtime(pt) : localtime(pt);

	pat = asctime(ptm);
	pat[19] = 0;
	// pyr = pat + 20;

	/* if (uflag)
		printf("\t%s - %s UTC %s", str, pat, pyr);
	else
		printf("\t%s - %s %s %s", str, pat, tm_zone(ptm), pyr); */
}

public void
time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	time4_base(str, &t);
}

public void
sig_creation_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	sig_creation_time = t;

	time4_base(str, &t);
}

public void
sig_expiration_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	t += sig_creation_time;

	time4_base(str, &t);
}

public void
key_creation_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	key_creation_time = t;

	time4_base(str, &t);
}

public void
key_expiration_time4(string str)
{
	int i;
	time_t t = 0;

	for (i = 0; i < 4; i++)
		t = t * 256 + Getc();

	t += key_creation_time;

	time4_base(str, &t);
}

public void
ver(int old, int new, int ver)
{
	/* if (new != NULL_VER && new == ver)
		// printf("New");
		;
	else if (old != NULL_VER && old == ver)
		// printf("Old");
		;
	else
		printf("Unknown");
	// printf(" version(%d)\n", ver); */
}

#define EXPBIAS 6

public int
string_to_key(void)
{
	int has_iv = YES;
	int type = Getc();
	int i;

	switch (type) {
	case 0:
		if (gpg_dbg) fprintf(stderr, "\tSimple string-to-key(s2k %d):\n", type);
		if (gpg_dbg) fprintf(stderr, "\t");
		m_spec = type;
		// hash_algs(Getc());
		m_hashAlgorithm = Getc();
		break;
	case 1:
		if (gpg_dbg) fprintf(stderr, "\tSalted string-to-key(s2k %d):\n", type);
		m_spec = type;
		m_count = 0; // ;(
		// hash_algs(Getc());
		m_hashAlgorithm = Getc();
		if (gpg_dbg) fprintf(stderr, "\t\tSalt - ");
		give(8, m_salt, sizeof(m_salt));
		if (gpg_dbg) {
			for (i = 0; i < 8; ++i) {
				fprintf(stderr, "%02x", m_salt[i]);
			}
			fprintf(stderr, "\n");
		}
		break;
	case 2:
		if (gpg_dbg) fprintf(stderr, "\tReserved string-to-key(s2k %d)\n", type);
		break;
	case 3:
		if (gpg_dbg) fprintf(stderr, "\tIterated and salted string-to-key(s2k %d):\n", type);
		if (gpg_dbg) fprintf(stderr, "\t");
		m_spec = type;
		m_hashAlgorithm = Getc();
		// hash_algs(Getc());
		if (gpg_dbg) fprintf(stderr, "\t\tSalt - ");
		give(8, m_salt, sizeof(m_salt));
		if (gpg_dbg) {
			for (i = 0; i < 8; ++i) {
				fprintf(stderr, "%02x", m_salt[i]);
			}
			fprintf(stderr, "\n");
		}
		{
			int count, c = Getc();
			count = (16 + (c & 15)) << ((c >> 4) + EXPBIAS);
			if (gpg_dbg) fprintf(stderr, "\t\tCount - %d(coded count %d)\n", count, c);
			m_count = count;
		}
		break;
	case 101:
		if (gpg_dbg) fprintf(stderr, "\tGnuPG string-to-key(s2k %d)\n", type);
		has_iv = NO;
		skip(5);
		break;
	default:
		fprintf(stderr, "\tUnknown string-to-key(s2k %d)\n", type);
	}
	return has_iv;
}

/* public void
multi_precision_integer(string str)
{
	int bytes;
	int bits = Getc() * 256;
	bits += Getc();
	bytes = (bits + 7) / 8;

	// fprintf(stderr, "\t%s(%d bits) - ", str, bits);
	dump(bytes);
	// printf("\n");
} */

public void
skip_multi_precision_integer(string str)
{
	int bytes;
	int bits = Getc() * 256;
	bits += Getc();
	bytes = (bits + 7) / 8;

	skip(bytes);
}

public unsigned
give_multi_precision_integer(unsigned char *buf, const unsigned buf_size, unsigned *key_bits)
{
	unsigned bytes;
	unsigned bits = Getc() * 256;
	bits += Getc();
	bytes = (bits + 7) / 8;
	*key_bits = bits;

	//if (gpg_dbg) fprintf(stderr, "\t%s(%d bits) - ", str, bits);
	if (gpg_dbg)
		dump(bytes);
	else
		give(bytes, buf, buf_size);
	if (gpg_dbg) fprintf(stderr, "\n");
	return bytes;
}
/*
 * tagfunc.c
 */

#define SYM_ALG_MODE_NOT_SPECIFIED  1
#define SYM_ALG_MODE_SYM_ENC        2
#define SYM_ALG_MODE_PUB_ENC        3

private int sym_alg_mode = SYM_ALG_MODE_NOT_SPECIFIED;
private void reset_sym_alg_mode();
private void set_sym_alg_mode(int);
private int get_sym_alg_mode();

private void
reset_sym_alg_mode()
{
	sym_alg_mode = SYM_ALG_MODE_NOT_SPECIFIED;
}

private void
set_sym_alg_mode(int mode)
{
	sym_alg_mode = mode;
}

private int
get_sym_alg_mode()
{
	return sym_alg_mode;
}

public void
Reserved(int len)
{
	skip(len);
}

public void
Public_Key_Encrypted_Session_Key_Packet(int len)
{
	int pub;
	ver(2, 3, Getc());
	key_id();
	pub = Getc();
	pub_algs(pub);
	switch (pub) {
	case 1:
	case 2:
	case 3:
		skip_multi_precision_integer("RSA m^e mod n");
		break;
	case 16:
	case 20:
		skip_multi_precision_integer("ElGamal g^k mod p");
		skip_multi_precision_integer("ElGamal m * y^k mod p");
		break;
	case 17:
		skip_multi_precision_integer("DSA ?");
		skip_multi_precision_integer("DSA ?");
		break;
	default:
		fprintf(stderr, "\t\tunknown(pub %d)\n", pub);
		skip(len - 10);
	}
	if (gpg_dbg) fprintf(stderr, "\t\t-> m = sym alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02\n");
	set_sym_alg_mode(SYM_ALG_MODE_PUB_ENC);
}

public void
Symmetric_Key_Encrypted_Session_Key_Packet(int len)
{
	int left = len, alg;
	ver(NULL_VER, 4, Getc());
	alg = Getc();
	sym_algs(alg);
	left -= 2;
	Getc_resetlen();
	string_to_key();
	left -= Getc_getlen();
	if (left != 0) {
		if (gpg_dbg) fprintf(stderr, "\tEncrypted session key\n");
		if (gpg_dbg) fprintf(stderr, "\t\t-> sym alg(1 bytes) + session key\n");
		skip(left);
	}
	set_sym_alg_mode(SYM_ALG_MODE_SYM_ENC);
}

public void
Symmetrically_Encrypted_Data_Packet(int len, int first, int partial, char *hash)
{
	int mode = get_sym_alg_mode();
	static char *cp;
	static uint64_t totlen;
	int abort = 0;

	if (first) {
		cp = hash;
		totlen = 0;
	}
	totlen += len;


	switch (mode) {
	case SYM_ALG_MODE_NOT_SPECIFIED:  // Such files can be generated by PGP 8.0 for Windows.
		printf("[DEBUG] Encrypted data [sym alg is IDEA, simple string-to-key]. This combination is not supported yet!\n");
		abort = 1;
		break;
	case SYM_ALG_MODE_SYM_ENC:
		if (gpg_dbg) fprintf(stderr, "Symmetrically_Encrypted_Data_Packet -> Encrypted data [sym alg is specified in sym-key encrypted session key]\n");
		break;
	case SYM_ALG_MODE_PUB_ENC:
		if (gpg_dbg) fprintf(stderr, "\tEncrypted data [sym alg is specified in pub-key encrypted session key]\n");
		break;
	}
	// https://www.ietf.org/rfc/rfc2440.txt
	//
	// The repetition of 16 bits in the 80 bits of random data prefixed to
	// the message allows the receiver to immediately check whether the
	// session key is incorrect. This is a decent verifier, the MDC isn't
	// used in Symmetrically Encrypted Data Packet (Tag 9) packets.
	//
	// The decrypted data will typically contain other packets (often
	// literal data packets or compressed data packets).

	if (give(len, m_data, sizeof(m_data)) != len)
		return;
	cp += print_hex(m_data, len, cp);

	if (abort)
		return;

	if (!partial) {
		// we only dump the packet out when we get the 'non-partial' packet (i.e. last one).

		// m_usage is not really used in gpg_fmt_plug.c for symmetric hashes,
		// let's hijack it for specifying tag values.
		m_usage = 9; // Symmetrically Encrypted Data Packet (these lack MDC)
		fprintf(stderr, "[gpg2john] MDC is missing, expect lots of false positives!\n");
		printf("$gpg$*%d*%"PRId64"*%s*%d*%d*%d*%d*%d*", m_algorithm, (int64_t)totlen, hash, m_spec, m_usage, m_hashAlgorithm, m_cipherAlgorithm, m_count);
		cp = hash;
		cp += print_hex(m_salt, 8, cp);
		printf("%s\n", hash);
		if (gpg_dbg)
			fprintf(stderr, "  Key being dumped: Symmetrically_Encrypted_and_MDC_Packet.   hashAlgo=%s cipherAlgo=%s\n", hash_algs(m_hashAlgorithm), sym_algs2(m_cipherAlgorithm));
		reset_sym_alg_mode();
		hash_generated = 1;
	}
}

public void
Marker_Packet(int len)
{
	if (gpg_dbg) fprintf(stderr, "\tString - ");
	if (mflag) {
		pdump(len);
	} else {
		if (gpg_dbg) fprintf(stderr, "...");
		skip(len);
	}
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
Literal_Data_Packet(int len)
{
	int format, flen, blen;

	format = Getc();
	fprintf(stderr, "\tFormat - ");
	switch (format) {
	case 'b':
		fprintf(stderr, "binary");
		break;
	case 't':
		fprintf(stderr, "text");
		break;
	case 'u':
		fprintf(stderr, "UTF-8 text");
		break;
	case 'l':
		/* RFC 1991 incorrectly define this as '1' */
		fprintf(stderr, "local");
		break;
	default:
		fprintf(stderr, "unknown");
	}
	fprintf(stderr, "\n");
	flen = Getc();
	fprintf(stderr, "\tFilename - ");
	pdump(flen);
	fprintf(stderr, "\n");
	time4("File modified time");
	blen = len - 6 - flen;
	fprintf(stderr, "\tLiteral - ");
	if (lflag) {
		pdump(blen);
	} else {
		fprintf(stderr, "...");
		skip(blen);
	}
	fprintf(stderr, "\n");
}

public void
Trust_Packet(int len)
{
	if (gpg_dbg) fprintf(stderr, "\tTrust - ");
	if (gpg_dbg)
		dump(len);
	else
		skip(len);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
User_ID_Packet(int len)
{
	if (gpg_dbg) fprintf(stderr, "\tUser ID - ");
	give_pdump(len);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
User_Attribute_Packet(int len)
{
	parse_userattr_subpacket("Sub", len);
}

public void
Symmetrically_Encrypted_and_MDC_Packet(int len, int first, int partial, char *hash)
{
	int mode = get_sym_alg_mode();
	static char *cp;
	static uint64_t totlen;

	if (first) {
		cp = hash;
		totlen = 0;
		if (gpg_dbg) {
			fprintf(stderr, "\tVer %d\n", Getc());
		} else {
			Getc(); // version (we only read this from the first packet. Not read from rest of the 'partial' packets.
		}
	} else
		++len;  // we want the 'full' length for subsquent partial packets, since the logic is len-1 we simply fake it out.
	totlen += (len-1);
	switch (mode) {
	case SYM_ALG_MODE_SYM_ENC:
		if (gpg_dbg) fprintf(stderr, "\tEncrypted data [sym alg is specified in sym-key encrypted session key]\n");
		break;
	case SYM_ALG_MODE_PUB_ENC:
		fprintf(stderr, "\tEncrypted data [sym alg is specified in pub-key encrypted session key]\n");
		fprintf(stderr, "SYM_ALG_MODE_PUB_ENC is not supported yet!\n");
		break;
	}
	if (give(len - 1, m_data, sizeof(m_data)) != len-1)
		return;
	cp += print_hex(m_data, len - 1, cp);

	if (!partial) {
		// we only dump the packet out when we get the 'non-partial' packet (i.e. last one).
		m_usage = 18; // Sym. Encrypted Integrity Protected Data Packet (Tag 18)
		printf("$gpg$*%d*%"PRId64"*%s*%d*%d*%d*%d*%d*", m_algorithm, (int64_t)totlen, hash, m_spec, m_usage, m_hashAlgorithm, m_cipherAlgorithm, m_count);
		cp = hash;
		cp += print_hex(m_salt, 8, cp);
		printf("%s\n", hash);
		if (gpg_dbg)
			fprintf(stderr, "  Key being dumped: Symmetrically_Encrypted_and_MDC_Packet.   hashAlgo=%s cipherAlgo=%s\n", hash_algs(m_hashAlgorithm), sym_algs2(m_cipherAlgorithm));
		reset_sym_alg_mode();
		hash_generated = 1;
	}
}

/* this function is not used because this packet appears only
   in encrypted packets. */
public void
Modification_Detection_Code_Packet(int len)
{
	if (gpg_dbg) fprintf(stderr, "\tMDC - SHA1(20 bytes)\n");
	skip(len);
}

public void
Private_Packet(int len)
{
	/* printf("\tPrivate - ");
	if (pflag) {
		dump(len);
	} else {
		printf("...");
		skip(len);
	}
	printf("\n"); */

	skip(len);
}

/*
 * packet.c
 */


typedef void (*funcptr)();

private int get_new_len(int);
private int is_partial(int);

#define BINARY_TAG_FLAG 0x80
#define NEW_TAG_FLAG    0x40
#define TAG_MASK        0x3f
#define PARTIAL_MASK    0x1f
#define TAG_COMPRESSED     8

#define OLD_TAG_SHIFT      2
#define OLD_LEN_MASK    0x03

#define CRITICAL_BIT	0x80
#define CRITICAL_MASK	0x7f

private string
TAG[] = {
	"Reserved",
	"Public-Key Encrypted Session Key Packet",
	"Signature Packet",
	"Symmetric-Key Encrypted Session Key Packet",
	"One-Pass Signature Packet",
	"Secret Key Packet",
	"Public Key Packet",
	"Secret Subkey Packet",
	"Compressed Data Packet",
	"Symmetrically Encrypted Data Packet",
	"Marker Packet",
	"Literal Data Packet",
	"Trust Packet",
	"User ID Packet",
	"Public Subkey Packet",
	"unknown",
	"unknown",
	"User Attribute Packet",
	"Symmetrically Encrypted and MDC Packet",
	"Modification Detection Code Packet",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"Private",
	"Private",
	"Private",
	"Private",
};
#define TAG_NUM (sizeof(TAG) * sizeof(string))

private void
(*tag_func[])() = {
	Reserved,
	Public_Key_Encrypted_Session_Key_Packet,
	Signature_Packet,
	Symmetric_Key_Encrypted_Session_Key_Packet,
	One_Pass_Signature_Packet,
	Secret_Key_Packet,
	Public_Key_Packet,
	Secret_Subkey_Packet,
	Compressed_Data_Packet,
	Symmetrically_Encrypted_Data_Packet,
	Marker_Packet,
	Literal_Data_Packet,
	Trust_Packet,
	User_ID_Packet,
	Public_Subkey_Packet,
	NULL,
	NULL,
	User_Attribute_Packet,
	Symmetrically_Encrypted_and_MDC_Packet,
	Modification_Detection_Code_Packet,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	Private_Packet,
	Private_Packet,
	Private_Packet,
	Private_Packet,
};

char *pkt_type(int tag) {
	switch(tag) {
	case 0: return "Reserved";
	case 1: return "Public_Key_Encrypted_Session_Key_Packet";
	case 2: return "Signature_Packet";
	case 3: return "Symmetric_Key_Encrypted_Session_Key_Packet";
	case 4: return "One_Pass_Signature_Packet";
	case 5: return "Secret_Key_Packet";
	case 6: return "Public_Key_Packet";
	case 7: return "Secret_Subkey_Packet";
	case 8: return "Compressed_Data_Packet";
	case 9: return "Symmetrically_Encrypted_Data_Packet";
	case 10: return "Marker_Packet";
	case 11: return "Literal_Data_Packet";
	case 12: return "Trust_Packet";
	case 13: return "User_ID_Packet";
	case 14: return "Public_Subkey_Packet";
	case 15: return "NULL";
	case 16: return "NULL";
	case 17: return "User_Attribute_Packet";
	case 18: return "Symmetrically_Encrypted_and_MDC_Packet";
	case 19: return "Modification_Detection_Code_Packet";
	case 20: return "NULL";
	case 21: return "NULL";
	case 22: return "NULL";
	case 23: return "NULL";
	case 24: return "NULL";
	case 25: return "NULL";
	case 26: return "NULL";
	case 27: return "NULL";
	case 28: return "NULL";
	case 29: return "NULL";
	case 30: return "NULL";
	case 31: return "NULL";
	case 32: return "NULL";
	case 33: return "NULL";
	case 34: return "NULL";
	case 35: return "NULL";
	case 36: return "NULL";
	case 37: return "NULL";
	case 38: return "NULL";
	case 39: return "NULL";
	case 40: return "NULL";
	case 41: return "NULL";
	case 42: return "NULL";
	case 43: return "NULL";
	case 44: return "NULL";
	case 45: return "NULL";
	case 46: return "NULL";
	case 47: return "NULL";
	case 48: return "NULL";
	case 49: return "NULL";
	case 50: return "NULL";
	case 51: return "NULL";
	case 52: return "NULL";
	case 53: return "NULL";
	case 54: return "NULL";
	case 55: return "NULL";
	case 56: return "NULL";
	case 57: return "NULL";
	case 58: return "NULL";
	case 59: return "NULL";
	case 60: return "NULL";
	case 61: return "Private_Packet";
	case 62: return "Private_Packet";
	case 63: return "Private_Packet";
	case 64: return "Private_Packet";
	default: return "Unk, past end!";
};

}
private string
SIGSUB[] = {
	"reserved(sub 0)",
	"reserved(sub 1)",
	"signature creation time(sub 2)",
	"signature expiration time(sub 3)",
	"exportable certification(sub 4)",
	"trust signature(sub 5)",
	"regular expression(sub 6)",
	"revocable(sub 7)",
	"reserved(sub 8)",
	"key expiration time(sub 9)",
	"additional decryption key(sub 10) WARNING: see CA-2000-18!!!",
	"preferred symmetric algorithms(sub 11)",
	"revocation key(sub 12)",
	"reserved(sub 13)",
	"reserved(sub 14)",
	"reserved(sub 15)",
	"issuer key ID(sub 16)",
	"reserved(sub 17)",
	"reserved(sub 18)",
	"reserved(sub 19)",
	"notation data(sub 20)",
	"preferred hash algorithms(sub 21)",
	"preferred compression algorithms(sub 22)",
	"key server preferences(sub 23)",
	"preferred key server(sub 24)",
	"primary User ID(sub 25)",
	"policy URL(sub 26)",
	"key flags(sub 27)",
	"signer's User ID(sub 28)",
	"reason for revocation(sub 29)",
        "features(sub 30)",
        "signature target(sub 31)",
	"embedded signature(sub 32)",
};
#define SIGSUB_NUM (sizeof(SIGSUB) / sizeof(string))

private funcptr
sigsub_func[] = {
	NULL,
	NULL,
	signature_creation_time,
	signature_expiration_time,
	exportable_certification,
	trust_signature,
	regular_expression,
	revocable,
	NULL,
	key_expiration_time,
	additional_decryption_key,
	preferred_symmetric_algorithms,
	revocation_key,
	NULL,
	NULL,
	NULL,
	issuer_key_ID,
	NULL,
	NULL,
	NULL,
	notation_data,
	preferred_hash_algorithms,
	preferred_compression_algorithms,
	key_server_preferences,
	preferred_key_server,
	primary_user_id,
	policy_URL,
	key_flags,
	signer_user_id,
	reason_for_revocation,
        features,
        signature_target,
	embedded_signature,
};

private string
UATSUB[] = {
	"unknown(sub 0)",
	"image attribute(sub 1)",
};
#define UATSUB_NUM (sizeof(UATSUB) / sizeof(string))

private funcptr
uatsub_func[] = {
	NULL,
	image_attribute,
};

private int
get_new_len(int c)
{
	int len;

	if (c < 192)
		len = c;
	else if (c < 224)
		len = ((c - 192) << 8) + Getc() + 192;
	else if (c == 255) {
	        len = (Getc() << 24);
	        len |= (Getc() << 16);
	        len |= (Getc() << 8);
	        len |= Getc();
	} else
		len = 1 << (c & PARTIAL_MASK);
	return len;
}

private int
is_partial(int c)
{
	if (c < 224 || c == 255)
		return NO;
	else
		return YES;
}

public void
parse_packet(char *hash)
{
	int c, tag, len = 0;
	int partial = NO;
	int have_packet = NO;

	c = getchar();
	ungetc(c, stdin);
	offset = 0;

	/* If the PGP packet is in the binary raw form, 7th bit of
	 * the first byte is always 1. If it is set, let's assume
	 * it is the binary raw form. Otherwise, let's assume
	 * it is encoded with radix64.
	 */
	if (c & BINARY_TAG_FLAG) {
		if (aflag)
			warn_exit("binary input is not allowed.");
		set_binary();
	} else
		set_armor();

	while ((c = Getc1()) != EOF) {
		have_packet = YES;
		partial = NO;
		tag = c & TAG_MASK;
		if (c & NEW_TAG_FLAG) {
			if (gpg_dbg) fprintf(stderr, "New: ");
			c = Getc();
			len = get_new_len(c);
			partial = is_partial(c);
		} else {
			int tlen;

			if (gpg_dbg) fprintf(stderr, "Old: ");
			tlen = c & OLD_LEN_MASK;
			tag >>= OLD_TAG_SHIFT;

			switch (tlen) {
			case 0:
				len = Getc();
				break;
			case 1:
				len = (Getc() << 8);
				len += Getc();
				break;
			case 2:
			        len = Getc() << 24;
			        len |= Getc() << 16;
			        len |= Getc() << 8;
			        len |= Getc();
				break;
			case 3:
				if (tag == TAG_COMPRESSED)
					len = 0;
				else
					len = EOF;
				break;
			}
		}
		if (tag < TAG_NUM) {
			if (gpg_dbg) fprintf(stderr, "%s(tag %d)", TAG[tag], tag);
		} else {
			fprintf(stderr, "unknown(tag %d)", tag);
		}

		if (partial == YES) {
			if (gpg_dbg) fprintf(stderr, "(%d bytes) partial start\n", len);
		} else if (tag == TAG_COMPRESSED) {
			fprintf(stderr, "\n");
		} else if (len == EOF) {
			fprintf(stderr, "(until eof)\n");
		}
		// else printf("(%d bytes)\n", len);

		if (tag < TAG_NUM && tag_func[tag] != NULL) {
			if (gpg_dbg)
				fprintf(stderr, "Packet type %d, len %d at offset %d  (Processing) (pkt-type %s) (Partial %s)\n", tag, len, offset, pkt_type(tag), partial?"yes":"no");
			(*tag_func[tag])(len, 1, partial, hash);	// first packet (possibly only one if partial is false).
		} else {
			if (gpg_dbg)
				fprintf(stderr, "Packet type %d, len %d at offset %d  (Skipping) (Partial %s)\n", tag, len, offset, partial?"yes":"no");
			skip(len);
		}
		while (partial == YES) {
			if (gpg_dbg) fprintf(stderr, "New: ");
			c = Getc();
			len = get_new_len(c);
			partial = is_partial(c);
			if (partial == YES) {
				if (gpg_dbg)
					fprintf(stderr, "\t(%d bytes) partial continue\n", len);
			}
			else {
				if (gpg_dbg)
					fprintf(stderr, "\t(%d bytes) partial end\n", len);
			}
			if (tag < TAG_NUM && tag_func[tag] != NULL) {
				if (gpg_dbg)
					fprintf(stderr, "Packet type %d, len %d at offset %d  (Processing) (pkt-type %s) (Partial %s)\n", tag, len, offset, pkt_type(tag), partial?"yes":"no");
				(*tag_func[tag])(len, 0, partial, hash);	// subsquent packets.
			} else
				skip(len);
		}
		if (len == EOF) return;
	}
	if ( have_packet == NO )
		warn_exit("unexpected end of file.");
}

public void
parse_signature_subpacket(string prefix, int tlen)
{
	int len, subtype;
	// int critical;

	while (tlen > 0) {
		len = Getc();
		if (len < 192)
			tlen--;
		else if (len < 255) {
			len = ((len - 192) << 8) + Getc() + 192;
			tlen -= 2;
		} else if (len == 255) {
		        len = Getc() << 24;
		        len |= Getc() << 16;
		        len |= Getc() << 8;
		        len |= Getc();
			tlen -= 5;
		}
		tlen -= len;
		subtype = Getc(); /* len includes this field byte */
		len--;

		/* Handle critical bit of subpacket type */
		// critical = NO;
		if (subtype & CRITICAL_BIT) {
			// critical = YES;
			subtype &= CRITICAL_MASK;
		}

		/* if (subtype < SIGSUB_NUM)
			printf("\t%s: %s%s", prefix, SIGSUB[subtype], critical ? "(critical)" : "");
		else
			printf("\t%s: unknown(sub %d%s)", prefix, subtype, critical ? ", critical" : "");
		printf("(%d bytes)\n", len); */
		(void) SIGSUB; /* mute a compiler warning in clang */
		if (subtype < SIGSUB_NUM && sigsub_func[subtype] != NULL)
			(*sigsub_func[subtype])(len);
		else
			skip(len);
	}
}

public void
parse_userattr_subpacket(string prefix, int tlen)
{
	int len, subtype;

	while (tlen > 0) {
		len = Getc();
		if (len < 192)
			tlen--;
		else if (len < 255) {
			len = ((len - 192) << 8) + Getc() + 192;
			tlen -= 2;
		} else if (len == 255) {
		        len = Getc() << 24;
		        len |= Getc() << 16;
		        len |= Getc() << 8;
		        len |= Getc();
			tlen -= 5;
		}
		tlen -= len;
		subtype = Getc();
		len--;  /* len includes this field byte */

		if (subtype < UATSUB_NUM)
			fprintf(stderr, "\t%s: %s", prefix, UATSUB[subtype]);
		else
			fprintf(stderr, "\t%s: unknown(sub %d)", prefix, subtype);
		if (gpg_dbg) fprintf(stderr, "(%d bytes)\n", len);
		if (subtype < UATSUB_NUM && uatsub_func[subtype] != NULL)
			(*uatsub_func[subtype])(len);
		else
			skip(len);
	}
}

/*
 * subfunc.c
 */


public void
signature_creation_time(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t");
	if (gpg_dbg)
		sig_creation_time4("Time");
	else
		skip(4);

}

public void
signature_expiration_time(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t");
	if (gpg_dbg)
		sig_expiration_time4("Time");
	else
		skip(4);
}

public void
exportable_certification(int len)
{
#if DEBUG
	printf("\t\tExportable - ");
	if (Getc() == 0)
		printf("No");
	else
		printf("Yes");
	printf("\n");
#else
	Getc();
#endif
}

public void
trust_signature(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t\tLevel - ");
	skip(1);
	if (gpg_dbg) fprintf(stderr, "\n");
	if (gpg_dbg) fprintf(stderr, "\t\tAmount - ");
	skip(1);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
regular_expression(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t\tRegex - ");
	if (gpg_dbg)
		pdump(len);
	else
		skip(len);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
revocable(int len)
{
#if DEBUG
	printf("\t\tRevocable - ");
	if (Getc() == 0)
		printf("No");
	else
		printf("Yes");
	printf("\n");
#else
	Getc();
#endif
}

public void
key_expiration_time(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t");
	if (gpg_dbg)
		key_expiration_time4("Time");
	else
		skip(4);
}

public void
additional_decryption_key(int len)
{
	int c = Getc();
	fprintf(stderr, "\t\tClass - ");
	switch (c) {
	case 0x80:
		fprintf(stderr, "Strong request");
		break;
	case 0x0:
		fprintf(stderr, "Normal");
		break;
	default:
		fprintf(stderr, "Unknown class(%02x)", c);
		break;
	}
	if (gpg_dbg) fprintf(stderr, "\n");
	if (gpg_dbg) fprintf(stderr, "\t");
	pub_algs(Getc());
	if (gpg_dbg) fprintf(stderr, "\t");
	fingerprint();
}

public void
preferred_symmetric_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (gpg_dbg) fprintf(stderr, "\t");
		sym_algs(Getc());
	}
}

public void
revocation_key(int len)
{
	int c = Getc();
	fprintf(stderr, "\t\tClass - ");
	if (c & 0x80)
		switch (c) {
		case 0x80:
			fprintf(stderr, "Normal");
			break;
		case 0xc0:
			fprintf(stderr, "Sensitive");
			break;
		default:
			fprintf(stderr, "Unknown class(%02x)", c);
			break;
		}
	else
		fprintf(stderr, "Unknown class(%02x)", c);

	fprintf(stderr, "\n");
	//fprintf(stderr, "\t");
	pub_algs(Getc());
	//fprintf(stderr, "\t");
	fingerprint();
}

public void
issuer_key_ID(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t");
	key_id();
}

public void
notation_data(int len)
{
	skip(len);

	/* int c, nlen, vlen, human = 0;
	printf("\t\tFlag - ");
	c = Getc();
	switch (c) {
	case 0x80:
		printf("Human-readable");
		human = 1;
		break;
	case 0x0:
		printf("Normal");
		break;
	default:
		printf("Unknown flag1(%02x)", c);
		break;
	}
	c = Getc();
	if (c != 0) printf("Unknown flag2(%02x)", c);
	c = Getc();
	if (c != 0) printf("Unknown flag3(%02x)", c);
	c = Getc();
	if (c != 0) printf("Unknown flag4(%02x)", c);
	printf("\n");
	nlen = Getc() * 256;
	nlen += Getc();
	vlen = Getc() * 256;
	vlen += Getc();
	printf("\t\tName - ");
	pdump(nlen);
	printf("\n");
	printf("\t\tValue - ");
	if (human)
		pdump(vlen);
	else
		dump(vlen);
	printf("\n"); */
}

public void
preferred_hash_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (gpg_dbg) fprintf(stderr, "\t");
		hash_algs(Getc());
	}
}

public void
preferred_compression_algorithms(int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (gpg_dbg) fprintf(stderr, "\t");
		comp_algs(Getc());
	}
}

public void
key_server_preferences(int len)
{
	// int c = Getc();
	Getc();
	/* printf("\t\tFlag - ");
	switch (c) {
	case 0x80:
		printf("No-modify");
		break;
	case 0x0:
		printf("Normal");
		break;
	default:
		printf("Unknown flag(%02x)", c);
		break;
	}
	printf("\n"); */
	skip(len - 1);
}

public void
preferred_key_server(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t\tURL - ");
	if (gpg_dbg)
		pdump(len);
	else
		skip(len);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
primary_user_id(int len)
{
#if DEBUG
	printf("\t\tPrimary - ");
	if (Getc() == 0)
		printf("No");
	else
		printf("Yes");
	printf("\n");
#else
	Getc();
#endif
}

public void
policy_URL(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t\tURL - ");
	if (gpg_dbg)
		pdump(len);
	else
		skip(len);
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
key_flags(int len)
{
	Getc();

	/* if (c & 0x01)
		printf("\t\tFlag - This key may be used to certify other keys\n");
	if (c & 0x02)
		printf("\t\tFlag - This key may be used to sign data\n");
	if (c & 0x04)
		printf("\t\tFlag - This key may be used to encrypt communications\n");
	if (c & 0x08)
		printf("\t\tFlag - This key may be used to encrypt storage\n");
	if (c & 0x10)
		printf("\t\tFlag - The private component of this key may have been split by a secret-sharing mechanism\n");
	if (c & 0x20)
		printf("\t\tFlag - This key may be used for authentication\n");
	if (c & 0x80)
		printf("\t\tFlag - The private component of this key may be in the possession of more than one person\n"); */
	skip(len-1);
}

public void
signer_user_id(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t");
	User_ID_Packet(len);
}

public void
reason_for_revocation(int len)
{
	int c = Getc();
	fprintf(stderr, "\t\tReason - ");
	switch (c) {
	case 0:
		fprintf(stderr, "No reason specified");
		break;
	case 1:
		fprintf(stderr, "Key is superceded");
		break;
	case 2:
		fprintf(stderr, "Key material has been compromised");
		break;
	case 3:
		fprintf(stderr, "Key is retired and no longer used");
		break;
	case 32:
		fprintf(stderr, "User ID information is no longer valid");
		break;
	default:
		fprintf(stderr, "Unknown reason(%2d)", c);
		break;
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "\t\tComment - ");
	pdump(len - 1);
	fprintf(stderr, "\n");
}

public void
features(int len)
{
#if DEBUG
	int c = Getc();
	if (c & 0x01)
		printf("\t\tFlag - Modification detection (packets 18 and 19)\n");
	if ((c & ~0xfe) == 0)
		printf("\t\tFlag - undefined\n");
#else
	Getc();
#endif
	skip(len - 1);
}

public void
signature_target(int len)
{
	if (gpg_dbg) fprintf(stderr, "\t");
	pub_algs(Getc());
	if (gpg_dbg) fprintf(stderr, "\t");
	hash_algs(Getc());
	if (gpg_dbg) fprintf(stderr, "\t\tTarget signature digest(%d bytes)\n", len - 2);
	skip(len - 2);
}

public void
embedded_signature(int len)
{
	Signature_Packet(len);
}

/*
 * signature.c
 */


private void hash2(void);
private void signature_multi_precision_integer(int, int);
private void signature_type(int);
private void new_Signature_Packet(int);
private void old_Signature_Packet(int);

private void
hash2(void)
{
	if (gpg_dbg) fprintf(stderr, "\tHash left 2 bytes - ");
	skip(2);
	if (gpg_dbg) fprintf(stderr, "\n");
}

private void
signature_multi_precision_integer(int pub, int len)
{
	switch (pub) {
	case 1:
	case 2:
	case 3:
		skip_multi_precision_integer("RSA m^d mod n");
		if (gpg_dbg) fprintf(stderr, "\t\t-> PKCS-1\n");
		break;
	case 16:
	case 20:
		skip_multi_precision_integer("ElGamal a = g^k mod p");
		skip_multi_precision_integer("ElGamal b = (h - a*x)/k mod p - 1");
		break;
	case 17:
		m_algorithm = pub;
		skip_multi_precision_integer("DSA r");
		skip_multi_precision_integer("DSA s");
		if (gpg_dbg) fprintf(stderr, "\t\t-> hash(DSA q bits)\n");
		break;
	default:
		if (gpg_dbg) fprintf(stderr, "\tUnknown signature(pub %d)\n", pub);
		skip(len);
		break;
	}
}

private void
signature_type(int type)
{
	/* printf("\tSig type - ");
	switch (type) {
	case 0x00:
		printf("Signature of a binary document(0x00).");
		break;
	case 0x01:
		printf("Signature of a canonical text document(0x01).");
		break;
	case 0x02:
		printf("Standalone signature(0x02).");
		break;
	case 0x10:
		printf("Generic certification of a User ID and Public Key packet(0x10).");
		break;
	case 0x11:
		printf("Persona certification of a User ID and Public Key packet.(0x11)");
		break;
	case 0x12:
		printf("Casual certification of a User ID and Public Key packet(0x12).");
		break;
	case 0x13:
		printf("Positive certification of a User ID and Public Key packet(0x13).");
		break;
	case 0x18:
		printf("Subkey Binding Signature(0x18).");
		break;
	case 0x19:
		printf("Primary Key Binding Signature(0x19).");
		break;
	case 0x1f:
		printf("Signature directly on a key(0x1f).");
		break;
	case 0x20:
		printf("Key revocation signature(0x20).");
		break;
	case 0x28:
		printf("Subkey revocation signature(0x28).");
		break;
	case 0x30:
		printf("Certification revocation signature(0x30).");
		break;
	case 0x40:
		printf("Timestamp signature(0x40).");
		break;
	case 0x50:
		printf("Third-Party Confirmation signature(0x50).");
		break;
	default:
		printf("unknown(%02x)", type);
		break;
	}
	printf("\n"); */
}

public void
One_Pass_Signature_Packet(int len)
{
	ver(NULL_VER, 3, Getc());
	signature_type(Getc());
	hash_algs(Getc());
	pub_algs(Getc());
	key_id();
	fprintf(stderr, "\tNext packet - ");
	if (Getc() == 0)
		fprintf(stderr, "another one pass signature");
	else
		fprintf(stderr, "other than one pass signature");
	fprintf(stderr, "\n");
}

public void
Signature_Packet(int len)
{
	int ver;

	ver = Getc();
	if (gpg_dbg) fprintf(stderr, "\tVer %d - ", ver);
	switch (ver) {
	case 2:
	case 3:
		if (gpg_dbg) fprintf(stderr, "old\n");
		old_Signature_Packet(len - 1);
		break;
	case 4:
		if (gpg_dbg) fprintf(stderr, "new\n");
		new_Signature_Packet(len - 1);
		break;
	default:
		if (gpg_dbg) fprintf(stderr, "unknown\n");
		skip(len - 1);
		break;
	}
}

private void
old_Signature_Packet(int len)
{
	int pub;

	fprintf(stderr, "\tHash material(%d bytes):\n", Getc());
	if (gpg_dbg) fprintf(stderr, "\t");
	signature_type(Getc());
	if (gpg_dbg) fprintf(stderr, "\t");
	if (gpg_dbg)
		time4("Creation time");
	else
		skip(4);
	key_id();
	pub = Getc();
	pub_algs(pub);
	hash_algs(Getc());
	hash2();
	signature_multi_precision_integer(pub, len - 19);
}

private void
new_Signature_Packet(int len)
{
	int pub, hsplen, usplen;

	signature_type(Getc());
	pub = Getc();
	pub_algs(pub);
	hash_algs(Getc());
	hsplen = Getc() * 256;
	hsplen += Getc();
	parse_signature_subpacket("Hashed Sub", hsplen);
	usplen = Getc() * 256;
	usplen += Getc();
	parse_signature_subpacket("Sub", usplen);
	hash2();
	signature_multi_precision_integer(pub, len - 9 - hsplen - usplen);
}

/*
 * keys.c
 */

private int PUBLIC;
private int VERSION;

private void old_Public_Key_Packet(void);
private void new_Public_Key_Packet(int);
private void IV(unsigned int);
private void plain_Secret_Key(int);
private void encrypted_Secret_Key(int, int);

public void
Public_Subkey_Packet(int len)
{
	Public_Key_Packet(len);
}

public void
Public_Key_Packet(int len)
{
	VERSION = Getc();
	if (gpg_dbg) fprintf(stderr, "\tVer %d - ", VERSION);
	switch (VERSION) {
	case 2:
	case 3:
		if (gpg_dbg) fprintf(stderr, "old\n");
		old_Public_Key_Packet();
		break;
	case 4:
		if (gpg_dbg) fprintf(stderr, "new\n");
		new_Public_Key_Packet(len - 1);
		break;
	default:
		warn_exit("unknown version (%d).", VERSION);
		break;
	}
}

private void
old_Public_Key_Packet(void)
{
	int days;
	if (gpg_dbg)
		time4("Public key creation time");
	else
		skip(4);
	days = Getc() * 256;
	days += Getc();
	if (gpg_dbg) fprintf(stderr, "\tValid days - %d[0 is forever]\n", days);
	PUBLIC = Getc();
	pub_algs(PUBLIC); /* PUBLIC should be 1 */
	// skip_multi_precision_integer("RSA n");
	// skip_multi_precision_integer("RSA e");
	give_multi_precision_integer(n, sizeof(n), &n_bits);
	give_multi_precision_integer(e, sizeof(e), &e_bits);
}

private void
new_Public_Key_Packet(int len)
{
	if (gpg_dbg)
		key_creation_time4("Public key creation time");
	else
		skip(4);

	PUBLIC = Getc();
	pub_algs(PUBLIC);
	switch (PUBLIC) {
	case 1:
	case 2:
	case 3:
		give_multi_precision_integer(n, sizeof(n), &n_bits);  // RSA n
		give_multi_precision_integer(e, sizeof(e), &e_bits);  // RSA e
		break;
	case 16:
	case 20:
		// ElGamal
		give_multi_precision_integer(p, sizeof(p), &p_bits);
		give_multi_precision_integer(g, sizeof(g), &g_bits);
		give_multi_precision_integer(y, sizeof(y), &y_bits);
		break;
	case 17:
		// multi_precision_integer("DSA p");
		give_multi_precision_integer(p, sizeof(p), &key_bits);
		give_multi_precision_integer(q, sizeof(q), &q_bits);
		give_multi_precision_integer(g, sizeof(g), &g_bits);
		give_multi_precision_integer(y, sizeof(y), &y_bits);
		break;
	default:
		fprintf(stderr, "\tUnknown public key(pub %d)\n", PUBLIC);
		skip(len - 5);
		break;
	}
}

private void
IV(unsigned int len)
{
	if (gpg_dbg) fprintf(stderr, "\tIV - ");
	if (gpg_dbg)
		dump(len);
	else
		give(len, iv, sizeof(iv));
	bs = len;
	if (gpg_dbg) fprintf(stderr, "\n");
}

public void
Secret_Subkey_Packet(int len)
{
	is_subkey = 1;
	Secret_Key_Packet(len);
	is_subkey = 0;
}

public void
Secret_Key_Packet(int len)
{
	int s2k, sym;

	Getc_resetlen();
	Public_Key_Packet(len);
	s2k = Getc();
	switch (s2k) {
	case 0:
		plain_Secret_Key(len - Getc_getlen());
		m_usage = s2k;
		break;
	case 254:
		sym = Getc();
		sym_algs(sym);
		m_usage = s2k;
		if (string_to_key() == YES) {
			IV(iv_len(sym));
		}
		encrypted_Secret_Key(len - Getc_getlen(), YES);
		break;
	case 255:
		sym = Getc();
		m_usage = s2k;
		sym_algs(sym);
		if (string_to_key() == YES)
			IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), NO);
		break;
	default:
		sym = s2k;
		m_usage = s2k;
		sym_algs(sym);
		if (gpg_dbg) fprintf(stderr, "\tSimple string-to-key for IDEA\n");
		IV(iv_len(sym));
		encrypted_Secret_Key(len - Getc_getlen(), NO);
		break;
	}
}

private void
plain_Secret_Key(int len)
{
	static char path[8192];
	char *base;
	strnzcpy(path, filename, sizeof(path));
	base = basename(path);

	switch (VERSION) {
	case 2:
	case 3:
		/* PUBLIC should be 1. */
		/* Tested by specifying a null passphrase. */
		// multi_precision_integer("RSA d");
		// multi_precision_integer("RSA p");
		// multi_precision_integer("RSA q");
		// multi_precision_integer("RSA u");
		give_multi_precision_integer(d, sizeof(d), &d_bits);
		give_multi_precision_integer(p, sizeof(p), &p_bits);
		give_multi_precision_integer(q, sizeof(q), &q_bits);
		give_multi_precision_integer(u, sizeof(u), &u_bits);
		fprintf(stderr, "%s contains plain RSA secret key packet!\n", base);
		if (gpg_dbg) fprintf(stderr, "\tChecksum - ");
		if (gpg_dbg)
			dump(2);
		else
			skip(2);
		if (gpg_dbg) fprintf(stderr, "\n");
		break;
	case 4:
		switch (PUBLIC) {
		case 1:
		case 2:
		case 3:
			// multi_precision_integer("RSA d");
			// multi_precision_integer("RSA p");
			// multi_precision_integer("RSA q");
			// multi_precision_integer("RSA u");
			give_multi_precision_integer(d, sizeof(d), &d_bits);
			give_multi_precision_integer(p, sizeof(p), &p_bits);
			give_multi_precision_integer(q, sizeof(q), &q_bits);
			give_multi_precision_integer(u, sizeof(u), &u_bits);
			fprintf(stderr, "%s contains plain RSA secret key packet!\n", base);
			break;
		case 16:
		case 20:
			skip_multi_precision_integer("ElGamal x");
			fprintf(stderr, "%s contains plain ElGamal secret key packet!\n", base);
			break;
		case 17:
			skip_multi_precision_integer("DSA x");
			fprintf(stderr, "%s contains plain DSA secret key packet!\n", base);
			break;
		default:
			fprintf(stderr, "\tUnknown secret key(pub %d)\n", PUBLIC);
			skip(len - 2);
			break;
		}
		if (gpg_dbg) fprintf(stderr, "\tChecksum - ");
		if (gpg_dbg)
			dump(2);
		else
			skip(2);
		if (gpg_dbg) fprintf(stderr, "\n");
		break;
	default:
		fprintf(stderr, "\tunknown version (%d)\n", VERSION);
		skip(len);
		break;
	}
}

private void
encrypted_Secret_Key(int len, int sha1)
{
	int used = 0;
	char *cp;
	char login[4096];
	const char *ext[] = {".gpg", ".pgp"};

	if (len < 0)
		warn_exit("Bad parameter: encrypted_Secret_Key(len=%d, sha1=%d), len can not be negative.",
			len, sha1);

	/* Use base of filename as login as last resort */
	/* /path/johndoe.gpg -> johndoe */
	if (!gecos[0]) {
		cp = strip_suffixes(jtr_basename(filename), ext, 2);
		strnzcpy(gecos, cp, sizeof(gecos));
	}

	/* login field is Real Name part of user data */
	strnzcpy(login, gecos, sizeof(login));

	if ((cp = strchr(login, '(')))
		memset(cp, 0, 1);
	if ((cp = strrchr(login, '<')))
		memset(cp, 0, 1);

	/* Don't allow our delimiter in there! */
	replace(login, ':', ' ');

	/* Ditch trailing spaces in login */
	cp = &login[strlen(login) - 1];
	while (cp > login && *cp == ' ')
		*cp-- = 0;

	if (gpg_dbg) fprintf(stderr, "Version is %d\n", VERSION);
	switch (VERSION) {
	case 2:
	case 3:
		/* PUBLIC should be 1.
		   Printable since an MPI prefix count is not encrypted. */
		// give_multi_precision_integer(d, &d_bits);
		// give_multi_precision_integer(p, &p_bits);
		// give_multi_precision_integer(q, &p_bits);
		// give_multi_precision_integer(u, &u_bits);
		if (give(len, m_data, sizeof(m_data)) != len) // we can't break down the "data" further into fields
			return;
		used += len;

		m_algorithm = PUBLIC;
		if (last_hash && *last_hash) {
			printf("%s:%s:::%s::%s\n", login, last_hash, gecos, filename);
			MEM_FREE(last_hash);
		}
		if (dump_subkeys || !is_subkey) {
			MEM_FREE(last_hash);
			last_hash = mem_alloc(len*2 + 512 + (n_bits + 7) / 4);
			cp = last_hash;
			if (m_usage == 1) {
				puts("[ERROR] We don't support 'Simple string-to-key for IDEA' S2K type yet.");
				return;
			}
			cp += sprintf(cp, "$gpg$*%d*%d*%d*", m_algorithm, len, n_bits);
			cp += print_hex(m_data, len, cp);
			cp += sprintf(cp, "*%d*%d*%d*%d*%d*", m_spec, m_usage, m_hashAlgorithm, m_cipherAlgorithm, bs);
			cp += print_hex(iv, bs, cp);
			cp += sprintf(cp, "*%d*", m_count);
			cp += print_hex(m_salt, 8, cp);
			if (m_usage == 1) { /* handle 2 byte checksum */
				cp += sprintf(cp, "*%d*", (n_bits + 7) / 8);
				cp += print_hex(n, (n_bits + 7) / 8, cp);
			}
			*cp = 0;
			hash_generated = 1;
			if (gpg_dbg)
				fprintf(stderr, "  Key being dumped: encrypted_Secret_Key (VERSION=%d/algo=%d/spec=%d).   hashAlgo=%s cipherAlgo=%s\n", VERSION, m_algorithm, m_spec, hash_algs(m_hashAlgorithm), sym_algs2(m_cipherAlgorithm));

		}
		break;
	case 4:
		switch (PUBLIC) {
		case 1:
		case 2:
		case 3:
			/* Encrypted RSA stuff */
			if (give(len, m_data, sizeof(m_data)) != len)   // we can't break down the "data" further into fields
				return;
			used += len;
			m_algorithm = PUBLIC;  // Encrypted RSA
			if (last_hash && *last_hash) {
				printf("%s:%s:::%s::%s\n", login, last_hash, gecos, filename);
				MEM_FREE(last_hash);
			}
			if (dump_subkeys || !is_subkey) {
				MEM_FREE(last_hash);
				last_hash = mem_alloc(len*2 + 512 + (n_bits + 7) / 4 );
				cp = last_hash;
				cp += sprintf(cp, "$gpg$*%d*%d*%d*", m_algorithm, len, n_bits);
				cp += print_hex(m_data, len, cp);
				cp += sprintf(cp, "*%d*%d*%d*%d*%d*", m_spec, m_usage, m_hashAlgorithm, m_cipherAlgorithm, bs);
				cp += print_hex(iv, bs, cp);
				cp += sprintf(cp, "*%d*", m_count);
				cp += print_hex(m_salt, 8, cp);
				if (m_usage == 255) { /* handle 2 byte checksum */
					// gpg --homedir . --s2k-mode 0 --simple-sk-checksum --s2k-cipher-algo IDEA --gen-key
					cp += sprintf(cp, "*%d*", (n_bits + 7) / 8);
					cp += print_hex(n, (n_bits + 7) / 8, cp);
				}
				*cp = 0;
				hash_generated = 1;
				if (gpg_dbg)
					fprintf(stderr, "  Key being dumped: encrypted_Secret_Key-RSA (VERSION=%d/algo=%d/spec=%d).   hashAlgo=%s cipherAlgo=%s\n", VERSION, m_algorithm, m_spec, hash_algs(m_hashAlgorithm), sym_algs2(m_cipherAlgorithm));
			}
			break;
		case 16:
		case 20:
			m_algorithm = PUBLIC;  // Encrypted ElGamal
			if (give(len, m_data, sizeof(m_data)) != len)
				return;
			used += len;
			if (last_hash && *last_hash) {
				printf("%s:%s:::%s::%s\n", login, last_hash, gecos, filename);
				MEM_FREE(last_hash);
			}
			if (dump_subkeys || !is_subkey) {
				MEM_FREE(last_hash);
				last_hash = mem_alloc(len*2 + 512 + (p_bits+g_bits+y_bits) / 4);
				cp = last_hash;
				cp += sprintf(cp, "$gpg$*%d*%d*%d*", m_algorithm, len, key_bits);
				cp += print_hex(m_data, len, cp);
				cp += sprintf(cp, "*%d*%d*%d*%d*%d*", m_spec, m_usage, m_hashAlgorithm, m_cipherAlgorithm, bs);
				cp += print_hex(iv, bs, cp);
				cp += sprintf(cp, "*%d*", m_count);
				cp += print_hex(m_salt, 8, cp);
				if (m_usage == 255) { /* handle 2 byte checksum */
					cp += sprintf(cp, "*%d*", (p_bits + 7) / 8);
					cp += print_hex(p, (p_bits + 7) / 8, cp);
					cp += sprintf(cp, "*%d*", (g_bits + 7) / 8);
					cp += print_hex(g, (g_bits + 7) / 8, cp);
					cp += sprintf(cp, "*%d*", (y_bits + 7) / 8);
					cp += print_hex(y, (y_bits + 7) / 8, cp);
				}
				*cp = 0;
				hash_generated = 1;
				if (gpg_dbg)
					fprintf(stderr, "  Key being dumped: encrypted_Secret_Key-ElGam (VERSION=%d/algo=%d/spec=%d).   hashAlgo=%s cipherAlgo=%s\n", VERSION, m_algorithm, m_spec, hash_algs(m_hashAlgorithm), sym_algs2(m_cipherAlgorithm));
			}
			break;
		case 17:
			m_algorithm = PUBLIC;  // Encrypted DSA
			if (give(len, m_data, sizeof(m_data)) != len)
				return;
			used += len;
			if (last_hash && *last_hash) {
				printf("%s:%s:::%s::%s\n", login, last_hash, gecos, filename);
				MEM_FREE(last_hash);
			}
			if (dump_subkeys || !is_subkey) {
				MEM_FREE(last_hash);
				last_hash = mem_alloc(len*2 + 512 + (key_bits+q_bits+g_bits+y_bits) / 4);
				cp = last_hash;
				cp += sprintf(cp, "$gpg$*%d*%d*%d*", m_algorithm, len, key_bits);
				cp += print_hex(m_data, len, cp);
				cp += sprintf(cp, "*%d*%d*%d*%d*%d*", m_spec, m_usage, m_hashAlgorithm, m_cipherAlgorithm, bs);
				cp += print_hex(iv, bs, cp);
				cp += sprintf(cp, "*%d*", m_count);
				cp += print_hex(m_salt, 8, cp);
				if (m_usage == 255) { /* handle 2 byte checksum */
					cp += sprintf(cp, "*%d*", (key_bits + 7) / 8);
					cp += print_hex(p, (key_bits + 7) / 8, cp);
					cp += sprintf(cp, "*%d*", (q_bits + 7) / 8);
					cp += print_hex(q, (q_bits + 7) / 8, cp);
					cp += sprintf(cp, "*%d*", (g_bits + 7) / 8);
					cp += print_hex(g, (g_bits + 7) / 8, cp);
					cp += sprintf(cp, "*%d*", (y_bits + 7) / 8);
					cp += print_hex(y, (y_bits + 7) / 8, cp);
				}
				*cp = 0;
				hash_generated = 1;
				if (gpg_dbg)
					fprintf(stderr, "  Key being dumped: encrypted_Secret_Key-DSA (VERSION=%d/algo=%d/spec=%d).   hashAlgo=%s cipherAlgo=%s\n", VERSION, m_algorithm, m_spec, hash_algs(m_hashAlgorithm), sym_algs2(m_cipherAlgorithm));
			}
			break;
		default:
			fprintf(stderr, "\tUnknown encrypted key(pub %d)\n", PUBLIC);
			break;
		}
#if DEBUG
		if (sha1 == YES)
			printf("\tEncrypted SHA1 hash\n");
		else
			printf("\tEncrypted checksum\n");
#endif
		skip(len - used);
		break;
	default:
		fprintf(stderr, "\tunknown version (%d)\n", VERSION);
		if (gpg_dbg)skip(len);
		break;
	}
}

/*
 * buffer.c
 */
typedef char * cast_t;

private int line_not_blank(byte *);
private int read_binary(byte *, unsigned int);
private int read_radix64(byte *, unsigned int);
private int decode_radix64(byte *, unsigned int);

#define NUL '\0'
#define CR  '\r'
#define LF  '\n'

#define OOB -1
#define EOP -2
#define ELF -3
#define ECR -4

private unsigned int MAGIC_COUNT = 0;
private unsigned int AVAIL_COUNT = 0;
private byte *NEXT_IN = NULL;

private int (*d_func1)(byte *, unsigned int);
private int (*d_func2)(byte *, unsigned int);
private int (*d_func3)(byte *, unsigned int);

private byte tmpbuf[BUFSIZ];
private byte d_buf1[BUFSIZ];
#if HAVE_LIBZ || HAVE_LIBBZ2
private byte d_buf2[BUFSIZ];
#endif
private byte d_buf3[BUFSIZ];

private signed char
base256[] = {
	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,ELF,OOB, OOB,ECR,OOB,OOB,

	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB,
      /*                                                -                / */
	OOB,OOB,OOB,OOB, OOB,OOB,OOB,OOB, OOB,OOB,OOB, 62, OOB,OOB,OOB, 63,
      /*  0   1   2   3    4   5   6   7    8   9                =        */
	 52, 53, 54, 55,  56, 57, 58, 59,  60, 61,OOB,OOB, OOB,EOP,OOB,OOB,
      /*      A   B   C    D   E   F   G    H   I   J   K    L   M   N   O*/
	OOB,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
      /*  P   Q   R   S    T   U   V   W    X   Y   Z                     */
	 15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,OOB, OOB,OOB,OOB,OOB,
      /*      a   b   c    d   e   f   g    h   i   j   k    l   m   n   o*/
	OOB, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
      /*  p   q   r   s    t   u   v   w    x   y   z                     */
	 41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,OOB, OOB,OOB,OOB,OOB,
};

private int
line_not_blank(byte *s)
{
	while (isspace(*s)) {
		if (*s == CR || *s == LF)
			return NO;
		s++;
	}
	return YES;
}

private int
read_binary(byte *p, unsigned int max)
{
	/* errno */
	return fread(p, sizeof(byte), max, stdin);
}

private int
read_radix64(byte *p, unsigned int max)
{
	int c, d, out = 0, lf = 0, cr = 0;
	byte *lim = p + max;

	if (done_rr == YES) return 0;

	if (found_rr == NO) {

	again:
		do {
			if (fgets((cast_t)tmpbuf, BUFSIZ, stdin) == NULL)
				warn_exit("can't find PGP armor boundary.");
		} while (strncmp("-----BEGIN PGP", (cast_t)tmpbuf, 14) != 0);

		if (strncmp("-----BEGIN PGP SIGNED", (cast_t)tmpbuf, 21) == 0)
			goto again;

		do {
			if (fgets((cast_t)tmpbuf, BUFSIZ, stdin) == NULL)
				warn_exit("can't find PGP armor.");
		} while (line_not_blank(tmpbuf) == YES);
		found_rr = YES;
	}

	while (p < lim) {
		c = getchar();
		if (c == EOF) {
			done_rr = YES;
			return out;
		}

		if (sizeof(base256) <= c)
			warn_exit("illegal radix64 character.");

		d = base256[c];
		switch (d) {
		case OOB:
			warning("illegal radix64 character.");
			goto skiptail;
		case EOP:
			/* radix64 surely matches this */
			goto skiptail;
		case ELF:
			if (++lf >= 2) goto skiptail;
			continue;
		case ECR:
			if (++cr >= 2) goto skiptail;
			continue;
		}
		lf = cr = 0;
		*p++ = d;
		out++;
	}
	return out;
 skiptail:
	while (getchar() != EOF);
	done_rr = YES;
	return out;
}


private int
decode_radix64(byte *p, unsigned int max)
{
	unsigned int i, size, out = 0;
	byte c1, c2, c3, c4, *r, *lim = p + max;

	if (done_dr == YES) return 0;

	while (p + 3 < lim) {
		if (avail_dr < 4) {
			r = qdr;
			qdr = d_buf1;
			for (i = 0; i < avail_dr; i++)
				*qdr++ = *r++;
			size = (*d_func1)(qdr, sizeof(d_buf1) - avail_dr);
			qdr = d_buf1;
			avail_dr += size;
			if (size == 0) {
				done_dr = YES;
				switch (avail_dr) {
				case 0:
					return out;
				case 1:
					warning("illegal radix64 length.");
					return out; /* anyway */
				case 2:
					c1 = *qdr++;
					c2 = *qdr++;
					*p++ = (c1 << 2) | ((c2 & 0x30) >> 4);
					return out + 1;
				case 3:
					c1 = *qdr++;
					c2 = *qdr++;
					c3 = *qdr++;
					*p++ = (c1 << 2) | ((c2 & 0x30) >> 4);
					*p++ = ((c2 & 0x0f) << 4) |
						((c3 & 0x3c) >> 2);
					return out + 2;
				}
			}
		}

		if (avail_dr >= 4) {
			c1 = *qdr++;
			c2 = *qdr++;
			c3 = *qdr++;
			c4 = *qdr++;
			*p++ = (c1 << 2) | ((c2 & 0x30) >> 4);
			*p++ = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
			*p++ = ((c3 & 0x03) << 6) | c4;
			avail_dr -= 4;
			out += 3;
		}
	}
	return out;
}

#if HAVE_LIBZ
private int
inflate_gzip(byte *p, unsigned int max)
{
	static int done = NO;
	int err, size, inflated = 0, old;

	if (done == YES) return 0;

	z.next_out = p;
	z.avail_out = max;

	while (z.avail_out != 0) {
		if (z.avail_in == 0) {
			size = (*d_func2)(d_buf2, sizeof(d_buf2));
			z.next_in  = d_buf2;
			z.avail_in = size;
			if (z.avail_in == 0)
				warn_exit("zlib error, truncated file?");
		}

		old = z.avail_out;
		err = inflate(&z, Z_SYNC_FLUSH);

		if (err != Z_OK && err != Z_STREAM_END)
			warn_exit("zlib inflate error (%d).", err);

		inflated = max - z.avail_out;

		if (old == z.avail_out && z.avail_in != 0)
			break;	// is this return valid ?

		if (err == Z_STREAM_END) {
			done = YES;
			/* 8 bytes (crc and isize) are left. */
			if (inflateEnd(&z) != Z_OK)
				warn_exit("zlib inflateEnd error.");
			break;
		}
	}

	return inflated;
}
#endif /* HAVE_LIBZ */

#if HAVE_LIBBZ2
private int
inflate_bzip2(byte *p, unsigned int max)
{
	static int done = NO;
	int err, size, inflated = 0, old;

	if (done == YES) return 0;

	bz.next_out = (cast_t)p;
	bz.avail_out = max;

	while (bz.avail_out != 0) {
		if (bz.avail_in == 0) {
			size = (*d_func2)(d_buf2, sizeof(d_buf2));
			bz.next_in  = (cast_t)d_buf2;
			bz.avail_in = size;
			if (bz.avail_in == 0)
				warn_exit("bzip2 error, truncated file?");
		}

		old = bz.avail_out;
		err = BZ2_bzDecompress(&bz);

		if (err != BZ_OK && err != BZ_STREAM_END)
			warn_exit("bzip2 BZ2_bzDecompress error (%d).", err);

		inflated = max - bz.avail_out;

		if (old == bz.avail_out && bz.avail_in != 0)
			break; // is this return 'valid' ?

		if (err == BZ_STREAM_END) {
			done = YES;
			/* 8 bytes (crc and isize) are left. */
			if (BZ2_bzDecompressEnd(&bz) != BZ_OK)
				warn_exit("bzip2 BZ2_bzDecompressEnd error.");
			break;
		}
	}

	return inflated;
}
#endif /* HAVE_LIBBZ2 */

public int
Getc1(void)
{
	byte c;

	if (AVAIL_COUNT == 0) {
		AVAIL_COUNT = (*d_func3)(d_buf3, sizeof(d_buf3));
		if (AVAIL_COUNT == 0)
			return EOF;
		NEXT_IN = d_buf3;
	}

	AVAIL_COUNT--;
	MAGIC_COUNT++;
	c = *NEXT_IN;
	NEXT_IN++;
	offset++;
	return c;
}

public int
Getc(void)
{
	int c = Getc1();
	if (c == EOF)
		warn_exit("unexpected end of file.");
	return c;
}

public int
Getc_getlen(void)
{
	return MAGIC_COUNT;
}

public void
Getc_resetlen(void)
{
	MAGIC_COUNT = 0;
}

public void
set_armor(void)
{
	d_func1 = read_radix64;
	d_func2 = NULL;
	d_func3 = decode_radix64;
}

public void
set_binary(void)
{
	d_func1 = NULL;
	d_func2 = NULL;
	d_func3 = read_binary;
}

/*
 * Assuming Compressed_Data_Packet ends at the end of file
 */

public void
Compressed_Data_Packet(int len)
{
#if HAVE_LIBZ || HAVE_LIBBZ2
	unsigned int alg = Getc();
	int err = 0; // both Z_OK and BZ_OK are 0
	private int (*func)(byte *, unsigned int);

	comp_algs(alg);

#if HAVE_LIBZ
	z.zalloc = (alloc_func)0;
	z.zfree = (free_func)0;
	z.opaque = (voidpf)0;
#endif /* HAVE_LIBZ */
#if HAVE_LIBBZ2
	bz.bzalloc = (void *)0;
	bz.bzfree = (void *)0;
	bz.opaque = (void *)0;
#endif /* HAVE_LIBBZ2 */

	/*
	 * 0 uncompressed
	 * 1 ZIP without zlib header (RFC 1951)
	 *	inflateInit2 (strm, -13)
	 * 2 ZLIB with zlib header (RFC 1950)
	 *	inflateInit  (strm)
	 * 3 BZIP2 (http://sources.redhat.com/bzip2/)
	 */

	switch (alg) {
	case 0:
		return;
#if HAVE_LIBZ
	case 1:
		err = inflateInit2(&z, -13);
		if (err != Z_OK) warn_exit("zlib inflateInit error.");
		func = inflate_gzip;
		break;
	case 2:
		err = inflateInit(&z);
		if (err != Z_OK) warn_exit("zlib inflateInit error.");
		func = inflate_gzip;
		break;
#endif /* HAVE_LIBZ */
#if HAVE_LIBBZ2
	case 3:
		err = BZ2_bzDecompressInit(&bz, 0, 0);
		if (err != BZ_OK) warn_exit("bzip2 BZ2_bzDecompressInit error.");
		func = inflate_bzip2;
		break;
#endif /* HAVE_LIBBZ2 */
	default:
		warn_exit("unknown compress algorithm.");
	}

#if HAVE_LIBZ
	z.next_in  = d_buf2;
	z.avail_in = AVAIL_COUNT;
	z.next_out = 0;
	z.avail_out = sizeof(d_buf2);
#endif /* HAVE_LIBZ */
#if HAVE_LIBBZ2
	bz.next_in  = (cast_t)d_buf2;
	bz.avail_in = AVAIL_COUNT;
	bz.next_out = 0;
	bz.avail_out = sizeof(d_buf2);
#endif /* HAVE_LIBBZ2 */

	memcpy(d_buf2, NEXT_IN, AVAIL_COUNT);
	AVAIL_COUNT = 0;

	if (d_func1 == NULL) {
		d_func1 = NULL;
		d_func2 = read_binary;
		d_func3 = func;
	} else {
		d_func1 = read_radix64;
		d_func2 = decode_radix64;
		d_func3 = func;
	}
#else /* HAVE_LIBZ || HAVE_LIBBZ2 */
	comp_algs(Getc());
	warn_exit("can't uncompress without zlib/bzip2.");
#endif /* HAVE_LIBZ || HAVE_LIBBZ2 */
}

/*
 * uatfunc.c
 */


public void
image_attribute(int len)
{
	int hlenlo, hlen, hver;

	hlenlo = Getc(); /* little-endian */
	hlen = Getc() * 256 + hlenlo;
	hver = Getc();
	if (hver == 1) {
		int enc = Getc();
		fprintf(stderr, "\t\tImage encoding - %s(enc %d)\n",
			enc == 1 ? "JPEG" : "Unknown",
			enc);
		fprintf(stderr, "\t\tImage data(%d bytes)\n", len - hlen);
		skip(len - 4);
	} else {
		fprintf(stderr, "\t\tUnknown header version(ver %d)\n", hver);
		fprintf(stderr, "\t\tUnknown data(%d bytes)\n", len - hlen);
		skip(len - 3);
	}
}
