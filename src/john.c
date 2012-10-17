/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2004,2006,2009-2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum (and various others?)
 */

#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "params.h"

#if defined(_OPENMP) && OMP_FALLBACK
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "tty.h"
#include "signals.h"
#include "common.h"
#include "idle.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#include "charset.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"
#include "mkv.h"
#include "external.h"
#include "batch.h"
#include "dynamic.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#ifdef _OPENMP
#include <omp.h>
#endif /* _OPENMP */
#endif /* HAVE_MPI */
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include "unicode.h"
#include "plugin.h"
#ifdef CL_VERSION_1_0
#include "common-opencl.h"
#endif
#ifdef HAVE_CUDA
extern void cuda_device_list();
#endif
#ifdef NO_JOHN_BLD
#define JOHN_BLD "unk-build-type"
#else
#include "john_build_rule.h"
#endif

#ifdef HAVE_MPI
#ifdef _OPENMP
#define _MP_VERSION " MPI + OMP"
#else
#define _MP_VERSION " MPI"
#endif
#else
#ifdef _OPENMP
#define _MP_VERSION " OMP"
#else
#define _MP_VERSION ""
#endif
#endif

#if CPU_DETECT
extern int CPU_detect(void);
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_BF;
extern struct fmt_main fmt_AFS, fmt_LM;
#ifdef HAVE_CRYPT
extern struct fmt_main fmt_crypt;
#endif
extern struct fmt_main fmt_trip;
extern struct fmt_main fmt_dummy;

// can be done as a _plug format now. But I have not renamed the plugin file just yet.
extern struct fmt_main fmt_django;

#if OPENSSL_VERSION_NUMBER >= 0x10001000
extern struct fmt_main fmt_truecrypt;
extern struct fmt_main fmt_truecrypt_sha512;
extern struct fmt_main fmt_truecrypt_whirlpool;
#endif

#if defined(__GNUC__) && defined(__SSE2__)
extern struct fmt_main sha1_fmt_ng;
#endif

#ifdef HAVE_SKEY
extern struct fmt_main fmt_SKEY;
#endif

#ifdef HAVE_NSS
extern struct fmt_main mozilla_fmt;
extern int mozilla2john(int argc, char **argv);
#endif
#ifdef HAVE_KRB5
extern struct fmt_main fmt_KRB5_kinit;
extern struct fmt_main fmt_krb5_18;
#endif
extern int hccap2john(int argc, char **argv);

#ifdef CL_VERSION_1_0
extern struct fmt_main fmt_opencl_NSLDAPS;
extern struct fmt_main fmt_opencl_rawMD4;
extern struct fmt_main fmt_opencl_rawMD5;
extern struct fmt_main fmt_opencl_NT;
extern struct fmt_main fmt_opencl_rawSHA1;
extern struct fmt_main fmt_opencl_cryptMD5;
extern struct fmt_main fmt_opencl_phpass;
extern struct fmt_main fmt_opencl_mysqlsha1;
extern struct fmt_main fmt_opencl_cryptsha256;
extern struct fmt_main fmt_opencl_cryptsha512;
extern struct fmt_main fmt_opencl_mscash2;
extern struct fmt_main fmt_opencl_wpapsk;
extern struct fmt_main fmt_opencl_keychain;
extern struct fmt_main fmt_opencl_agilekeychain;
extern struct fmt_main fmt_opencl_strip;
extern struct fmt_main fmt_opencl_zip;
extern struct fmt_main fmt_opencl_encfs;
extern struct fmt_main fmt_opencl_odf;
extern struct fmt_main fmt_opencl_sxc;
extern struct fmt_main fmt_opencl_gpg;
extern struct fmt_main fmt_opencl_dmg;
extern struct fmt_main fmt_opencl_xsha512;
extern struct fmt_main fmt_opencl_rawsha512;
extern struct fmt_main fmt_opencl_rawsha512_ng;
extern struct fmt_main fmt_opencl_bf;
extern struct fmt_main fmt_opencl_pwsafe;
extern struct fmt_main fmt_opencl_DES;
extern struct fmt_main fmt_opencl_office2007;
extern struct fmt_main fmt_opencl_office2010;
extern struct fmt_main fmt_opencl_office2013;
extern struct fmt_main fmt_opencl_NTLMv2;
#endif
#ifdef HAVE_CUDA
extern struct fmt_main fmt_cuda_cryptmd5;
extern struct fmt_main fmt_cuda_phpass;
extern struct fmt_main fmt_cuda_cryptsha256;
extern struct fmt_main fmt_cuda_cryptsha512;
extern struct fmt_main fmt_cuda_mscash;
extern struct fmt_main fmt_cuda_mscash2;
extern struct fmt_main fmt_cuda_rawsha256;
extern struct fmt_main fmt_cuda_rawsha224;
extern struct fmt_main fmt_cuda_xsha512;
extern struct fmt_main fmt_cuda_wpapsk;
extern struct fmt_main fmt_cuda_rawsha512;
extern struct fmt_main fmt_cuda_pwsafe;
#endif

extern struct fmt_main fmt_ssh;
extern struct fmt_main fmt_pfx;
extern struct fmt_main fmt_pdf;
extern struct fmt_main rar_fmt;
extern struct fmt_main zip_fmt;
extern struct fmt_main fmt_wpapsk;

#include "fmt_externs.h"

extern struct fmt_main fmt_hmacMD5;
extern struct fmt_main fmt_hmacSHA1;
extern struct fmt_main fmt_rawSHA0;

extern int unique(int argc, char **argv);
extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int undrop(int argc, char **argv);
#ifndef _MSC_VER
/* XXX: What's wrong with having these along with MSC? Perhaps this restriction
 * was meant to apply to some of these only? Maybe SSH only? */
extern int ssh2john(int argc, char **argv);
extern int pfx2john(int argc, char **argv);
extern int keychain2john(int argc, char **argv);
extern int keepass2john(int argc, char **argv);
extern int rar2john(int argc, char **argv);
extern int racf2john(int argc, char **argv);
extern int pwsafe2john(int argc, char **argv);
#endif
extern int pdf2john(int argc, char **argv);
extern int zip2john(int argc, char **argv);

static struct db_main database;
static struct fmt_main dummy_format;

static int exit_status = 0;

static void john_register_one(struct fmt_main *format)
{
	if (options.format)
	if (strcmp(options.format, format->params.label)) return;

	fmt_register(format);
}

static void john_register_all(void)
{
	int i, cnt;
	struct fmt_main *selfs;

	if (options.format) strlwr(options.format);

	// NOTE, this MUST happen, before ANY format that links a 'thin' format to dynamic.
	// Since gen(27) and gen(28) are MD5 and MD5a formats, we build the
	// generic format first
	cnt = dynamic_Register_formats(&selfs);

	john_register_one(&fmt_DES);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_LM);

	for (i = 0; i < cnt; ++i)
		john_register_one(&(selfs[i]));

#include "fmt_registers.h"

	john_register_one(&fmt_hmacMD5);
	john_register_one(&fmt_hmacSHA1);
	john_register_one(&fmt_rawSHA0);

	john_register_one(&fmt_django);
#if OPENSSL_VERSION_NUMBER >= 0x10001000
	john_register_one(&fmt_truecrypt);
	john_register_one(&fmt_truecrypt_sha512);
	john_register_one(&fmt_truecrypt_whirlpool);
#endif

#if defined(__GNUC__) && defined(__SSE2__)
	john_register_one(&sha1_fmt_ng);
#endif

#ifdef HAVE_NSS
	john_register_one(&mozilla_fmt);
#endif
#ifdef HAVE_KRB5
	john_register_one(&fmt_KRB5_kinit);
	john_register_one(&fmt_krb5_18);
#endif

#ifdef HAVE_CRYPT
	john_register_one(&fmt_crypt);
#endif
	john_register_one(&fmt_trip);
#ifdef HAVE_SKEY
	john_register_one(&fmt_SKEY);
#endif

	john_register_one(&fmt_ssh);
	john_register_one(&fmt_pfx);
	john_register_one(&fmt_pdf);
	john_register_one(&fmt_wpapsk);
#ifndef _MSC_VER
	john_register_one(&rar_fmt);
#endif
	john_register_one(&zip_fmt);
	john_register_one(&fmt_dummy);

#ifdef CL_VERSION_1_0
	john_register_one(&fmt_opencl_NSLDAPS);
	john_register_one(&fmt_opencl_rawMD4);
	john_register_one(&fmt_opencl_rawMD5);
	john_register_one(&fmt_opencl_NT);
	john_register_one(&fmt_opencl_rawSHA1);
	john_register_one(&fmt_opencl_cryptMD5);
	john_register_one(&fmt_opencl_phpass);
	john_register_one(&fmt_opencl_mysqlsha1);
	john_register_one(&fmt_opencl_cryptsha256);
	john_register_one(&fmt_opencl_cryptsha512);
	john_register_one(&fmt_opencl_mscash2);
	john_register_one(&fmt_opencl_wpapsk);
	john_register_one(&fmt_opencl_keychain);
	john_register_one(&fmt_opencl_agilekeychain);
	john_register_one(&fmt_opencl_strip);
	john_register_one(&fmt_opencl_zip);
	john_register_one(&fmt_opencl_encfs);
	john_register_one(&fmt_opencl_odf);
	john_register_one(&fmt_opencl_sxc);
	john_register_one(&fmt_opencl_gpg);
	john_register_one(&fmt_opencl_dmg);
	john_register_one(&fmt_opencl_xsha512);
	john_register_one(&fmt_opencl_rawsha512);
	john_register_one(&fmt_opencl_rawsha512_ng);
	john_register_one(&fmt_opencl_bf);
	john_register_one(&fmt_opencl_pwsafe);
	john_register_one(&fmt_opencl_DES);
	john_register_one(&fmt_opencl_office2007);
	john_register_one(&fmt_opencl_office2010);
	john_register_one(&fmt_opencl_office2013);
	john_register_one(&fmt_opencl_NTLMv2);
#endif

#ifdef HAVE_CUDA
	john_register_one(&fmt_cuda_cryptmd5);
	john_register_one(&fmt_cuda_phpass);
	john_register_one(&fmt_cuda_cryptsha256);
	john_register_one(&fmt_cuda_cryptsha512);
	john_register_one(&fmt_cuda_mscash);
	john_register_one(&fmt_cuda_mscash2);
	john_register_one(&fmt_cuda_rawsha256);
	john_register_one(&fmt_cuda_rawsha224);
	john_register_one(&fmt_cuda_xsha512);
	john_register_one(&fmt_cuda_wpapsk);
	john_register_one(&fmt_cuda_rawsha512);
	john_register_one(&fmt_cuda_pwsafe);
#endif

#ifdef HAVE_DL
	if (options.fmt_dlls)
	register_dlls ( options.fmt_dlls,
		cfg_get_param(SECTION_OPTIONS, NULL, "plugin"),
		john_register_one );
#endif

	if (!fmt_list) {
#ifdef HAVE_MPI
		if (mpi_id == 0)
#endif
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_log_format(void)
{
	int min_chunk, chunk;

#ifdef HAVE_MPI
	if (mpi_p > 1)
		log_event("- MPI mode: %u nodes, this one running on %s", mpi_p, mpi_name);
#endif
	/* make sure the format is properly initialized */
	fmt_init(database.format);

	log_event("- Hash type: %.100s (lengths up to %d%s)",
		database.format->params.format_name,
		database.format->params.plaintext_length,
		(database.format == &fmt_DES || database.format == &fmt_LM) ?
		", longer passwords split" : "");

	log_event("- Algorithm: %.100s",
		database.format->params.algorithm_name);

	chunk = min_chunk = database.format->params.max_keys_per_crypt;
	if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
	    chunk < SINGLE_HASH_MIN)
			chunk = SINGLE_HASH_MIN;
	if (chunk > 1)
		log_event("- Candidate passwords %s be buffered and "
			"tried in chunks of %d",
			min_chunk > 1 ? "will" : "may",
			chunk);
}

static char *john_loaded_counts(void)
{
	static char s_loaded_counts[80];

	if (database.password_count == 1)
		return "1 password hash";

	sprintf(s_loaded_counts,
		database.salt_count > 1 ?
		"%d password hashes with %d different salts" :
		"%d password hashes with no different salts",
		database.password_count,
		database.salt_count);

	return s_loaded_counts;
}

static void john_load(void)
{
	struct list_entry *current;

#ifndef _MSC_VER
	umask(077);
#endif

	if (options.flags & FLG_EXTERNAL_CHK)
		ext_init(options.external, NULL);

	if (options.flags & FLG_MAKECHR_CHK) {
		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&database, &options.loader);

		if (options.flags & FLG_PASSWD) {
			ldr_show_pot_file(&database, options.loader.activepot);

			database.options->flags |= DB_PLAINTEXTS;
			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));
		} else {
			database.options->flags |= DB_PLAINTEXTS;
			ldr_show_pot_file(&database, options.loader.activepot);
		}

		return;
	}

	if (options.flags & FLG_STDOUT) {
		ldr_init_database(&database, &options.loader);
		database.format = &dummy_format;
		memset(&dummy_format, 0, sizeof(dummy_format));
		dummy_format.params.plaintext_length = options.length;
		dummy_format.params.flags = FMT_CASE | FMT_8_BIT;
	}

	if (options.flags & FLG_PASSWD) {
		int total;

		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			ldr_show_pot_file(&database, options.loader.activepot);

			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));

			printf("%s%d password hash%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "es" : "",
				database.password_count -
				database.guess_count);

			return;
		}

		if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK) &&
		    status.pass <= 1)
			options.loader.flags |= DB_WORDS;
		else
		if (mem_saving_level) {
			options.loader.flags &= ~DB_LOGIN;
			options.loader.max_wordfile_memory = 0;
		}

		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		// Unicode (UTF-16) formats may lack UTF-8 support (initially)
		if (options.utf8 && database.password_count &&
		    database.format->params.flags & FMT_UNICODE &&
		    !(database.format->params.flags & FMT_UTF8)) {
			fprintf(stderr, "This format does not yet support UTF-8 conversion\n");
				error();
		}

		if ((options.flags & FLG_CRACKING_CHK) &&
		    database.password_count) {
			log_init(LOG_NAME, NULL, options.session);
			if (status_restored_time)
				log_event("Continuing an interrupted session");
			else
				log_event("Starting a new session");
			log_event("Loaded a total of %s", john_loaded_counts());
			/* make sure the format is properly initialized */
			fmt_init(database.format);
			printf("Loaded %s (%s [%s])\n",
				john_loaded_counts(),
				database.format->params.format_name,
				database.format->params.algorithm_name);

			// Tell External our max length
			if (options.flags & FLG_EXTERNAL_CHK)
				ext_init(options.external, &database);
		}

		if (database.password_count) {
			if (database.format->params.flags & FMT_UNICODE)
				options.store_utf8 = cfg_get_bool(SECTION_OPTIONS,
			        NULL, "UnicodeStoreUTF8", 0);
			else
				options.store_utf8 = cfg_get_bool(SECTION_OPTIONS,
			        NULL, "CPstoreUTF8", 0);
		}
		if (!options.utf8) {
			if (options.report_utf8 && options.log_passwords)
				log_event("- Passwords in this logfile are UTF-8 encoded");

			if (options.store_utf8)
				log_event("- Passwords will be stored UTF-8 encoded in .pot file");
		}

		total = database.password_count;
		ldr_load_pot_file(&database, options.loader.activepot);
		ldr_fix_database(&database);

		if (!database.password_count) {
			log_discard();
			printf("No password hashes %s (see FAQ)\n",
			    total ? "left to crack" : "loaded");
		} else
		if (database.password_count < total) {
			log_event("Remaining %s", john_loaded_counts());
			printf("Remaining %s\n", john_loaded_counts());
		}

		if (options.regen_lost_salts) {
			extern void build_fake_salts_for_regen_lost(struct db_salt *);
			build_fake_salts_for_regen_lost(database.salts);
		}

		if ((options.flags & FLG_PWD_REQ) && !database.salts) exit(0);
	}
}

#if CPU_DETECT
static void CPU_detect_or_fallback(char **argv, int make_check)
{
	if (!CPU_detect()) {
#if CPU_REQ
#if CPU_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error CPU_FALLBACK is incompatible with the current DOS and Win32 code
#endif
		if (!make_check) {
#define CPU_FALLBACK_PATHNAME JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY
			execv(CPU_FALLBACK_PATHNAME, argv);
			perror("execv: " CPU_FALLBACK_PATHNAME);
		}
#endif
		fprintf(stderr, "Sorry, %s is required\n", CPU_NAME);
		if (make_check)
			exit(0);
		error();
#endif
	}
}
#else
#define CPU_detect_or_fallback(argv, make_check)
#endif

/*
 * FIXME: Should all the john_list_*() functions get an additional stream parameter,
 *        so that they can write to stderr instead of stdout in case fo an error?
 */
static void john_list_options()
{
	puts("help[:WHAT], subformats, inc-modes, rules, externals, ext-filters,");
	puts("ext-filters-only, ext-modes, build-info, hidden-options, encodings,");
	puts("formats, format-details, format-all-details, format-methods[:WHICH],");
	// With "opencl-devices, cuda-devices, <conf section name>" added,
	// the resulting line will get too long
	// printf("sections, parameters:SECTION, list-data:SECTION, ");
	puts("sections, parameters:SECTION, list-data:SECTION,");
#ifdef CL_VERSION_1_0
	printf("opencl-devices, ");
#endif
#ifdef HAVE_CUDA
	printf("cuda-devices, ");
#endif
	/* NOTE: The following must end the list. Anything listed after
	   <conf section name> will be ignored by current
	   bash completion scripts. */

	/* FIXME: Should all the section names get printed instead?
	 *        But that would require a valid config.
	 */
	puts("<conf section name>");
}

static void john_list_help_options()
{
	puts("help, format-methods, parameters, list-data");
}

static void john_list_method_names()
{
	puts("init, prepare, valid, split, binary, salt, binary_hash, salt_hash, set_salt,");
	puts("set_key, get_key, clear_keys, crypt_all, get_hash, cmp_all, cmp_one, cmp_exact");
}

static void john_init(char *name, int argc, char **argv)
{
	int show_usage = 0;
	int make_check = (argc == 2 && !strcmp(argv[1], "--make_check"));
	if (make_check)
		argv[1] = "--test=0";

	CPU_detect_or_fallback(argv, make_check);

	status_init(NULL, 1);
	if (argc < 2 ||
            (argc == 2 &&
             (!strcasecmp(argv[1], "--help") ||
              !strcasecmp(argv[1], "-h") ||
              !strcasecmp(argv[1], "-help"))))
	{
		john_register_all(); /* for printing by opt_init() */
		show_usage = 1;
	}
	opt_init(name, argc, argv, show_usage);

	/*
	 * --list=? needs to be supported, because it has been supported in the released
	 * john-1.7.9-jumbo-6 version, and it is used by the bash completion script.
	 * --list=? is, however, not longer mentioned in doc/OPTIONS and in the usage
	 * output. Instead, --list=help is.
	 */
	if (options.listconf &&
	    (!strcasecmp(options.listconf, "help") ||
	     !strcmp(options.listconf, "?")))
	{
		john_list_options();
		exit(0);
	}
	if (options.listconf &&
	    (!strcasecmp(options.listconf, "help:help") ||
	     !strcasecmp(options.listconf, "help:")))
	{
		john_list_help_options();
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "help:format-methods"))
	{
		john_list_method_names();
		exit(0);
	}
	if (options.listconf && !strncasecmp(options.listconf, "help:", 5))
	{
		if (strcasecmp(options.listconf, "help:parameters") &&
		    strcasecmp(options.listconf, "help:list-data"))
		{
			fprintf(stderr,
			        "%s is not a --list option that supports additional values.\nSupported options:\n",
			        options.listconf+5);
			john_list_help_options();
			exit(1);
		}
	}
	if (options.listconf && !strcasecmp(options.listconf, "hidden-options"))
	{
		puts("--help                    print usage summary, just like running the command");
		puts("                          without any parameters");
		puts("--subformat=FORMAT        pick a benchmark format for --format=crypt");
		puts("--mkpc=N                  force a lower max. keys per crypt");
		puts("--length=N                force a lower max. length");
		puts("--field-separator-char=C  use 'C' instead of the ':' in input and pot files");
		puts("--fix-state-delay=N       performance tweak, see documentation");
		puts("--log-stderr              log to screen instead of file\n");
		puts("--raw-always-valid=C      if C is 'Y' or 'y', then the dynamic format will");
		puts("                          always treat raw hashes as valid.");
		puts("--progress-every=N        emit a status line every N seconds\n");
		exit(0);
	}

	if (!make_check) {
#if defined(_OPENMP) && OMP_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error OMP_FALLBACK is incompatible with the current DOS and Win32 code
#endif
		if (!getenv("JOHN_NO_OMP_FALLBACK") &&
		    omp_get_max_threads() <= 1) {
#define OMP_FALLBACK_PATHNAME JOHN_SYSTEMWIDE_EXEC "/" OMP_FALLBACK_BINARY
			execv(OMP_FALLBACK_PATHNAME, argv);
			perror("execv: " OMP_FALLBACK_PATHNAME);
		}
#endif

		path_init(argv);

		if (options.listconf && !strcasecmp(options.listconf,
		                                    "build-info"))
		{
			puts("Version: " JOHN_VERSION);
			puts("Build: " JOHN_BLD _MP_VERSION);
			printf("Arch: %d-bit %s\n", ARCH_BITS,
			       ARCH_LITTLE_ENDIAN ? "LE" : "BE");
#if JOHN_SYSTEMWIDE
			puts("System-wide exec: " JOHN_SYSTEMWIDE_EXEC);
			puts("System-wide home: " JOHN_SYSTEMWIDE_HOME);
			puts("Private home: " JOHN_PRIVATE_HOME);
#endif
			printf("$JOHN is %s\n", path_expand("$JOHN/"));
			printf("Format interface version: %d\n", FMT_MAIN_VERSION);
			puts("Rec file version: " RECOVERY_V);
			puts("Charset file version: " CHARSET_V);
			printf("CHARSET_MIN: %d (0x%02x)\n", CHARSET_MIN,
			       CHARSET_MIN);
			printf("CHARSET_MAX: %d (0x%02x)\n", CHARSET_MAX,
			       CHARSET_MAX);
			printf("CHARSET_LENGTH: %d\n", CHARSET_LENGTH);
			printf("Max. Markov mode level: %d\n", MAX_MKV_LVL);
			printf("Max. Markov mode password length: %d\n", MAX_MKV_LEN);
#ifdef __VERSION__
		printf("Compiler version: %s\n", __VERSION__);
#endif
#ifdef __GNUC__
			printf("gcc version: %d.%d.%d\n", __GNUC__,
			       __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
#ifdef __ICC
			printf("icc version: %d\n", __ICC);
#endif
#ifdef __clang_version__
			printf("clang version: %s\n", __clang_version__);
#endif
#ifdef OPENSSL_VERSION_NUMBER
			// The man page suggests the type of OPENSSL_VERSION_NUMBER is long,
			// gcc insists it is int.
			printf("OpenSSL library version: %lx", (unsigned long)OPENSSL_VERSION_NUMBER);
			// FIXME: How do I detect a missing library?
			// Even if if is extremely unlikely that openssl is missing,
			// at least flush all output buffers...
			fflush(NULL);
			if ((unsigned long)OPENSSL_VERSION_NUMBER != (unsigned long)SSLeay())
				printf("\t(loaded: %lx)", (unsigned long)SSLeay());
			printf("\n");
#endif
			exit(0);
		}
	}

	if (options.listconf && !strcasecmp(options.listconf, "encodings"))
	{
		listEncodings();
		exit(0);
	}
#ifdef CL_VERSION_1_0
	if (options.listconf && !strcasecmp(options.listconf, "opencl-devices"))
	{
		listOpenCLdevices();
		exit(0);
	}
#endif
#ifdef HAVE_CUDA
	if (options.listconf && !strcasecmp(options.listconf, "cuda-devices"))
	{
		cuda_device_list();
		exit(0);
	}
#endif

	if (!make_check) {
		if (options.config)
		{
			path_init_ex(options.config);
			cfg_init(options.config, 1);
			cfg_init(CFG_FULL_NAME, 1);
			cfg_init(CFG_ALT_NAME, 0);
		}
		else
		{
#if JOHN_SYSTEMWIDE
			cfg_init(CFG_PRIVATE_FULL_NAME, 1);
			cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
			cfg_init(CFG_FULL_NAME, 1);
			cfg_init(CFG_ALT_NAME, 0);
		}
	}

	/* This is --crack-status. We toggle here, so if it's enabled in
	   john.conf, we can disable it using the command line option */
	if (cfg_get_bool(SECTION_OPTIONS, NULL, "CrackStatus", 0))
		options.flags ^= FLG_CRKSTAT;

	initUnicode(UNICODE_UNICODE); /* Init the unicode system */

	john_register_all(); /* maybe restricted to one format by options */
	if ((options.subformat && !strcasecmp(options.subformat, "list")) ||
	    (options.listconf && !strcasecmp(options.listconf, "subformats")))
	{
		dynamic_DISPLAY_ALL_FORMATS();
		/* NOTE if we have other 'generics', like sha1, sha2, rc4, ...
		 * then EACH of them should have a DISPLAY_ALL_FORMATS()
		 * function and we can call them here. */
		exit(0);
	}

	if (options.listconf && !strcasecmp(options.listconf, "inc-modes"))
	{
		cfg_print_subsections("Incremental", NULL, NULL, 0);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "rules"))
	{
		cfg_print_subsections("List.Rules", NULL, NULL, 0);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "externals"))
	{
		cfg_print_subsections("List.External", NULL, NULL, 0);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "sections"))
	{
		cfg_print_section_names(0);
		exit(0);
	}
	if (options.listconf &&
	    !strncasecmp(options.listconf, "parameters", 10) &&
	    (options.listconf[10] == '=' || options.listconf[10] == ':') &&
	    options.listconf[11] != '\0')
	{
		cfg_print_section_params(&options.listconf[11], NULL);
		exit(0);
	}
	if (options.listconf &&
	    !strncasecmp(options.listconf, "list-data", 9) &&
	    (options.listconf[9] == '=' || options.listconf[9] == ':') &&
	    options.listconf[10] != '\0')
	{
		cfg_print_section_list_lines(&options.listconf[10], NULL);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "ext-filters"))
	{
		cfg_print_subsections("List.External", "filter", NULL, 0);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "ext-filters-only"))
	{
		cfg_print_subsections("List.External", "filter", "generate", 0);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "ext-modes"))
	{
		cfg_print_subsections("List.External", "generate", NULL, 0);
		exit(0);
	}

	if (options.listconf &&
	    !strcasecmp(options.listconf, "formats")) {
		int column;
		struct fmt_main *format;
		int i, dynamics = 0;
		char **formats_list;

		i = 0;
		format = fmt_list;
		while ((format = format->next))
			i++;

		formats_list = malloc(sizeof(char*) * i);

		i = 0;
		format = fmt_list;
		do {
			char *label = format->params.label;
			if (!strncmp(label, "dynamic", 7)) {
				if (dynamics++)
					continue;
				else
					label = "dynamic_n";
			}
			formats_list[i++] = label;
		} while ((format = format->next));
		formats_list[i] = NULL;

		column = 0;
		i = 0;
		do {
			int length;
			char *label = formats_list[i++];
			length = strlen(label) + 2;
			column += length;
			if (column > 78) {
				printf("\n");
				column = length;
			}
			printf("%s%s", label, formats_list[i] ? ", " : "\n");
		} while (formats_list[i]);
		MEM_FREE(formats_list);
		exit(0);
	}
	if (options.listconf &&
	    !strcasecmp(options.listconf, "format-details")) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ntests = 0;

			if(format->params.tests) {
				while (format->params.tests[ntests++].ciphertext);
				ntests--;
			}
			printf("%s\t%d\t%d\t%d\t%08x\t%d\t%s\t%s\t%s\t%d\t%d\t%d\n",
			       format->params.label,
			       format->params.plaintext_length,
			       format->params.min_keys_per_crypt,
			       format->params.max_keys_per_crypt,
			       format->params.flags,
			       ntests,
			       format->params.algorithm_name,
			       format->params.format_name,
			       format->params.benchmark_comment,
			       format->params.benchmark_length,
			       format->params.binary_size,
			       ((format->params.flags & FMT_DYNAMIC) && format->params.salt_size) ?
			       // salts are handled internally within the format. We want to know the 'real' salt size
			       // dynamic will alway set params.salt_size to 0 or sizeof a pointer.
			       dynamic_real_salt_length(format) : format->params.salt_size);
		} while ((format = format->next));
		exit(0);
	}
	if (options.listconf &&
	    !strcasecmp(options.listconf, "format-all-details")) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ntests = 0;

			if(format->params.tests) {
				while (format->params.tests[ntests++].ciphertext);
				ntests--;
			}
			/*
			 * attributes should be printed in the same sequence
			 * as with format-details, but human-readable
			 */
			printf("Format label                    \t%s\n", format->params.label);
			printf("Max. password length in bytes   \t%d\n", format->params.plaintext_length);
			printf("Min. keys per crypt             \t%d\n", format->params.min_keys_per_crypt);
			printf("Max. keys per crypt             \t%d\n", format->params.max_keys_per_crypt);
			printf("Flags\n");
			printf(" Case sensitive                 \t%s\n", (format->params.flags & FMT_CASE) ? "yes" : "no");
			printf(" Supports 8-bit characters      \t%s\n", (format->params.flags & FMT_8_BIT) ? "yes" : "no");
			printf(" Converts 8859-1 to UTF-16/UCS-2\t%s\n", (format->params.flags & FMT_UNICODE) ? "yes" : "no");
			printf(" Honours --encoding=NAME        \t%s\n", (format->params.flags & FMT_UTF8) ? "yes" : "no");
			printf(" False positives possible       \t%s\n", (format->params.flags & FMT_NOT_EXACT) ? "yes" : "no");
			printf(" Uses a bitslice implementation \t%s\n", (format->params.flags & FMT_BS) ? "yes" : "no");
			printf(" The split() method unifies case\t%s\n", (format->params.flags & FMT_SPLIT_UNIFIES_CASE) ? "yes" : "no");
			printf(" A $dynamic$ format             \t%s\n", (format->params.flags & FMT_DYNAMIC) ? "yes" : "no");
#ifdef _OPENMP
			printf(" Parallelized with OpenMP       \t%s\n", (format->params.flags & FMT_OMP) ? "yes" : "no");
#endif
			printf("Number of test cases for --test \t%d\n", ntests);
			printf("Algorithm name                  \t%s\n", format->params.algorithm_name);
			printf("Format name                     \t%s\n", format->params.format_name);
			printf("Benchmark comment               \t%s\n", format->params.benchmark_comment);
			printf("Benchmark length                \t%d\n", format->params.benchmark_length);
			printf("Binary size                     \t%d\n", format->params.binary_size);
			printf("Salt size                       \t%d\n",
			       ((format->params.flags & FMT_DYNAMIC) && format->params.salt_size) ?
			       // salts are handled internally within the format. We want to know the 'real' salt size/
			       // dynamic will alway set params.salt_size to 0 or sizeof a pointer.
			       dynamic_real_salt_length(format) : format->params.salt_size);
			printf("\n");
		} while ((format = format->next));
		exit(0);
	}
	if (options.listconf &&
	    !strncasecmp(options.listconf, "format-methods", 14)) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ShowIt = 1, i;
			if (options.listconf[14] == '=' || options.listconf[14] == ':') {
				ShowIt = 0;
				if (!strcasecmp(&options.listconf[15], "set_key")   ||
					!strcasecmp(&options.listconf[15], "get_key")   ||
					!strcasecmp(&options.listconf[15], "crypt_all") ||
					!strcasecmp(&options.listconf[15], "cmp_all")   ||
					!strcasecmp(&options.listconf[15], "cmp_one")  ||
					!strcasecmp(&options.listconf[15], "cmp_exact"))
					ShowIt = 1;
				else if (strcasecmp(&options.listconf[15], "init") && strcasecmp(&options.listconf[15], "prepare") &&
					strcasecmp(&options.listconf[15], "valid") && strcasecmp(&options.listconf[15], "split") &&
					strcasecmp(&options.listconf[15], "binary") && strcasecmp(&options.listconf[15], "clear_keys") &&
					strcasecmp(&options.listconf[15], "salt") && strcasecmp(&options.listconf[15], "get_hash") &&
					strcasecmp(&options.listconf[15], "get_hash[0]") && strcasecmp(&options.listconf[15], "get_hash[1]") &&
					strcasecmp(&options.listconf[15], "get_hash[2]") && strcasecmp(&options.listconf[15], "get_hash[3]") &&
					strcasecmp(&options.listconf[15], "get_hash[4]") && strcasecmp(&options.listconf[15], "get_hash[5]") &&
					strcasecmp(&options.listconf[15], "set_salt") && strcasecmp(&options.listconf[15], "binary_hash") &&
					strcasecmp(&options.listconf[15], "binary_hash[0]") && strcasecmp(&options.listconf[15], "binary_hash[1]") &&
					strcasecmp(&options.listconf[15], "binary_hash[2]") && strcasecmp(&options.listconf[15], "binary_hash[3]") &&
					strcasecmp(&options.listconf[15], "binary_hash[3]") && strcasecmp(&options.listconf[15], "binary_hash[5]") &&
					strcasecmp(&options.listconf[15], "salt_hash"))
				{
					fprintf(stderr, "Error, invalid option (invalid method name) %s\n", options.listconf);
					fprintf(stderr, "Valid method names are:\n");
					john_list_method_names();
					exit(1);
				}
				if (format->methods.init != fmt_default_init && !strcasecmp(&options.listconf[15], "init"))
					ShowIt = 1;
				if (format->methods.prepare != fmt_default_prepare && !strcasecmp(&options.listconf[15], "prepare"))
					ShowIt = 1;
				if (format->methods.valid != fmt_default_valid && !strcasecmp(&options.listconf[15], "valid"))
					ShowIt = 1;
				if (format->methods.split != fmt_default_split && !strcasecmp(&options.listconf[15], "split"))
					ShowIt = 1;
				if (format->methods.binary != fmt_default_binary && !strcasecmp(&options.listconf[15], "binary"))
					ShowIt = 1;
				if (format->methods.salt != fmt_default_salt && !strcasecmp(&options.listconf[15], "salt"))
					ShowIt = 1;
				if (format->methods.clear_keys != fmt_default_clear_keys && !strcasecmp(&options.listconf[15], "clear_keys"))
					ShowIt = 1;
				for (i = 0; i < 6; ++i) {
					char Buf[20];
					sprintf(Buf, "get_hash[%d]", i);
					if (format->methods.get_hash[i] && format->methods.get_hash[i] != fmt_default_get_hash && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.get_hash[0] && format->methods.get_hash[0] != fmt_default_get_hash && !strcasecmp(&options.listconf[15], "get_hash"))
					ShowIt = 1;

				for (i = 0; i < 6; ++i) {
					char Buf[20];
					sprintf(Buf, "binary_hash[%d]", i);
					if (format->methods.binary_hash[i] && format->methods.binary_hash[i] != fmt_default_binary_hash && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.binary_hash[0] && format->methods.binary_hash[0] != fmt_default_binary_hash && !strcasecmp(&options.listconf[15], "binary_hash"))
					ShowIt = 1;
				if (format->methods.salt_hash != fmt_default_salt_hash && !strcasecmp(&options.listconf[15], "salt_hash"))
					ShowIt = 1;
				if (format->methods.set_salt != fmt_default_set_salt && !strcasecmp(&options.listconf[15], "set_salt"))
					ShowIt = 1;
			}
			if (ShowIt) {
				int i;
				printf("Methods overridden for:   %s [%s] %s\n", format->params.label, format->params.algorithm_name, format->params.format_name);
				if (format->methods.init != fmt_default_init)
					printf("\tinit()\n");
				if (format->methods.prepare != fmt_default_prepare)
					printf("\tprepare()\n");
				if (format->methods.valid != fmt_default_valid)
					printf("\tvalid()\n");
				if (format->methods.split != fmt_default_split)
					printf("\tsplit()\n");
				if (format->methods.binary != fmt_default_binary)
					printf("\tbinary()\n");
				if (format->methods.salt != fmt_default_salt)
					printf("\tsalt()\n");
				for (i = 0; i < 6; ++i)
					if (format->methods.binary_hash[i] != fmt_default_binary_hash) {
						if (format->methods.binary_hash[i])
							printf("\t\tbinary_hash[%d]()\n", i);
						else
							printf("\t\tbinary_hash[%d]()  (NULL pointer)\n", i);
					}
				if (format->methods.salt_hash != fmt_default_salt_hash)
					printf("\tsalt_hash()\n");
				if (format->methods.set_salt != fmt_default_set_salt)
					printf("\tset_salt()\n");
				// there is no default for set_key() it must be defined.
				printf("\tset_key()\n");
				// there is no default for get_key() it must be defined.
				printf("\tget_key()\n");
				if (format->methods.clear_keys != fmt_default_clear_keys)
					printf("\tclear_keys()\n");
				for (i = 0; i < 6; ++i)
					if (format->methods.get_hash[i] != fmt_default_get_hash) {
						if (format->methods.get_hash[i])
							printf("\t\tget_hash[%d]()\n", i);
						else
							printf("\t\tget_hash[%d]()  (NULL pointer)\n", i);
					}
				// there is no default for crypt_all() it must be defined.
				printf("\tcrypt_all()\n");
				// there is no default for cmp_all() it must be defined.
				printf("\tcmp_all()\n");
				// there is no default for cmp_one() it must be defined.
				printf("\tcmp_one()\n");
				// there is no default for cmp_exact() it must be defined.
				printf("\tcmp_exact()\n");
				printf("\n\n");
			}
		} while ((format = format->next));
		exit(0);
	}
	/*
	 * Other --list=help:WHAT are processed earlier, but these require
	 * a valid config:
	 */
	if (options.listconf && !strcasecmp(options.listconf, "help:parameters"))
	{
		cfg_print_section_names(1);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "help:list-data"))
	{
		cfg_print_section_names(2);
		exit(0);
	}

	/* --list last resort: list subsections of any john.conf section name */
	if (options.listconf)
	{
		//printf("Subsections of [%s]:\n", options.listconf);
		if (cfg_print_subsections(options.listconf, NULL, NULL, 1))
			exit(0);
		else {
			fprintf(stderr, "Section [%s] not found.\n", options.listconf);
			/* Just in case the user specified an invalid value
			 * like help or list...
			 * print the same list as with --list=?, but exit(1)
			 */
			john_list_options();
			exit(1);
		}
	}

#ifdef CL_VERSION_1_0
	if (!options.ocl_platform) {
		if ((options.ocl_platform =
		     cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, "Platform")))
			platform_id = atoi(options.ocl_platform);
		else
			platform_id = -1;
	}
	if (!options.gpu_device) {
		if ((options.gpu_device =
		     cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, "Device")))
			ocl_gpu_id = atoi(options.gpu_device);
		else
			ocl_gpu_id = -1;
	}
	if (platform_id == -1 || ocl_gpu_id == -1)
		opencl_find_gpu(&ocl_gpu_id, &platform_id);
#endif

	common_init();
	sig_init();

	john_load();

	if (options.encodingStr && options.encodingStr[0])
		log_event("- %s input encoding enabled", options.encodingStr);
}

static void john_run(void)
{
	if (options.flags & FLG_TEST_CHK)
		exit_status = benchmark_all() ? 1 : 0;
	else
	if (options.flags & FLG_MAKECHR_CHK)
		do_makechars(&database, options.charset);
	else
	if (options.flags & FLG_CRACKING_CHK) {
		int remaining = database.password_count;

		if (!(options.flags & FLG_STDOUT)) {
			status_init(NULL, 1);
			log_init(LOG_NAME, options.loader.activepot, options.session);
			john_log_format();
			if (idle_requested(database.format))
				log_event("- Configured to use otherwise idle "
					"processor cycles only");
		}
		tty_init(options.flags & FLG_STDIN_CHK);

#if defined(HAVE_MPI) && defined(_OPENMP)
		if (database.format->params.flags & FMT_OMP &&
		    omp_get_max_threads() > 1 && mpi_p > 1) {
			if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIOMPmutex", 1)) {
				if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIOMPverbose", 1) &&
				   mpi_id == 0)
					fprintf(stderr, "MPI in use, disabling OMP (see doc/README.mpi)\n");
				omp_set_num_threads(1);
			} else
				if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI, "MPIOMPverbose", 1) &&
				   mpi_id == 0)
					fprintf(stderr, "Note: Running both MPI and OMP (see doc/README.mpi)\n");
		}
#endif
		if (options.flags & FLG_SINGLE_CHK)
			do_single_crack(&database);
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES) != 0);
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_MKV_CHK)
			do_markov_crack(&database, options.mkv_param);
		else
		if (options.flags & FLG_EXTERNAL_CHK)
			do_external_crack(&database);
		else
		if (options.flags & FLG_BATCH_CHK)
			do_batch_crack(&database);

		status_print();
		tty_done();

		if (database.password_count < remaining) {
			char *might = "Warning: passwords printed above might";
			char *partial = " be partial";
			char *not_all = " not be all those cracked";
			switch (database.options->flags &
			    (DB_SPLIT | DB_NODUP)) {
			case DB_SPLIT:
#ifdef HAVE_MPI
				if (mpi_id == 0)
#endif
				fprintf(stderr, "%s%s\n", might, partial);
				break;
			case DB_NODUP:
#ifdef HAVE_MPI
				if (mpi_id == 0)
#endif
				fprintf(stderr, "%s%s\n", might, not_all);
				break;
			case (DB_SPLIT | DB_NODUP):
#ifdef HAVE_MPI
				if (mpi_id == 0)
#endif
				fprintf(stderr, "%s%s and%s\n",
				    might, partial, not_all);
			}
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fputs("Use the \"--show\" option to display all of "
			    "the cracked passwords reliably\n", stderr);
		}
	}
}

static void john_done(void)
{
	path_done();

	if ((options.flags & FLG_CRACKING_CHK) &&
	    !(options.flags & FLG_STDOUT)) {
		if (event_abort)
			log_event(timer_abort ?
			          "Session aborted" :
			          "Session stopped (max run-time reached)");
		else
			log_event("Session completed");
	}
	log_done();
	check_abort(0);
	cleanup_tiny_memory();
}

int main(int argc, char **argv)
{
	char *name;

#ifdef _MSC_VER
   // Send all reports to STDOUT
   _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
   _CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDOUT );
   _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
   _CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDOUT );
   _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
   _CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDOUT );
#endif

#ifdef __DJGPP__
	if (--argc <= 0) return 1;
	if ((name = strrchr(argv[0], '/')))
		strcpy(name + 1, argv[1]);
	name = argv[1];
	argv[1] = argv[0];
	argv++;
#else
	if (!argv[0])
		name = "john";
	else
	if ((name = strrchr(argv[0], '/')))
		name++;
#if defined(__CYGWIN32__) || defined (__MINGW32__) || defined (_MSC_VER)
	else
	if ((name = strrchr(argv[0], '\\')))
		name++;
#endif
	else
		name = argv[0];
#endif

#if defined(__CYGWIN32__) || defined (__MINGW32__) || defined (_MSC_VER)
	strlwr(name);
	if (strlen(name) > 4 && !strcmp(name + strlen(name) - 4, ".exe"))
		name[strlen(name) - 4] = 0;
#endif

	if (!strcmp(name, "unshadow")) {
		CPU_detect_or_fallback(argv, 0);
		return unshadow(argc, argv);
	}

	if (!strcmp(name, "unafs")) {
		CPU_detect_or_fallback(argv, 0);
		return unafs(argc, argv);
	}

	if (!strcmp(name, "undrop")) {
		CPU_detect_or_fallback(argv, 0);
		return undrop(argc, argv);
	}

	if (!strcmp(name, "unique")) {
		CPU_detect_or_fallback(argv, 0);
		return unique(argc, argv);
	}

#ifndef _MSC_VER
	if (!strcmp(name, "ssh2john")) {
		CPU_detect_or_fallback(argv, 0);
		return ssh2john(argc, argv);
	}

	if (!strcmp(name, "pfx2john")) {
		CPU_detect_or_fallback(argv, 0);
		return pfx2john(argc, argv);
	}

	if (!strcmp(name, "keychain2john")) {
		CPU_detect_or_fallback(argv, 0);
		return keychain2john(argc, argv);
	}

	if (!strcmp(name, "keepass2john")) {
		CPU_detect_or_fallback(argv, 0);
		return keepass2john(argc, argv);
	}

	if (!strcmp(name, "rar2john")) {
		CPU_detect_or_fallback(argv, 0);
		return rar2john(argc, argv);
	}

	if (!strcmp(name, "racf2john")) {
		CPU_detect_or_fallback(argv, 0);
		return racf2john(argc, argv);
	}

	if (!strcmp(name, "pwsafe2john")) {
		CPU_detect_or_fallback(argv, 0);
		return pwsafe2john(argc, argv);
	}
#endif

#ifdef HAVE_NSS
	if (!strcmp(name, "mozilla2john")) {
		CPU_detect_or_fallback(argv, 0);
		return mozilla2john(argc, argv);
	}
#endif

	if (!strcmp(name, "pdf2john")) {
		CPU_detect_or_fallback(argv, 0);
		return pdf2john(argc, argv);
	}

	if (!strcmp(name, "zip2john")) {
		CPU_detect_or_fallback(argv, 0);
		return zip2john(argc, argv);
	}
	if (!strcmp(name, "hccap2john")) {
		CPU_detect_or_fallback(argv, 0);
		return hccap2john(argc, argv);
	}

#ifdef HAVE_MPI
	mpi_setup(argc, argv);
#else
	if (getenv("OMPI_COMM_WORLD_SIZE"))
	if (atoi(getenv("OMPI_COMM_WORLD_SIZE")) > 1)
		fprintf(stderr, "WARNING: Running under MPI, but this is NOT an MPI build of John.\n");
#endif
	john_init(name, argc, argv);

	/* --max-run-time and --progress-every disregards load time */
	timer_abort = options.max_run_time + 1;
	timer_status = options.status_interval;

	john_run();
	john_done();

#ifdef _MSC_VER
	_CrtDumpMemoryLeaks();
#endif

	return exit_status;
}
