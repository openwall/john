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
#include "unicode.h"
#include "plugin.h"
#ifdef CL_VERSION_1_0
#include "common-opencl.h"
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

extern struct fmt_main fmt_MD5gen;

#if OPENSSL_VERSION_NUMBER >= 0x00908000
extern struct fmt_main fmt_rawSHA224;
extern struct fmt_main fmt_rawSHA256;
extern struct fmt_main fmt_rawSHA384;
extern struct fmt_main fmt_rawSHA512;

extern struct fmt_main fmt_hmacSHA224;
extern struct fmt_main fmt_hmacSHA256;
extern struct fmt_main fmt_hmacSHA384;
extern struct fmt_main fmt_hmacSHA512;

extern struct fmt_main fmt_XSHA512;

extern struct fmt_main fmt_hmailserver;
extern struct fmt_main fmt_SybaseASE;
extern struct fmt_main fmt_dragonfly3_64;
extern struct fmt_main fmt_dragonfly4_64;
extern struct fmt_main fmt_dragonfly3_32;
extern struct fmt_main fmt_dragonfly4_32;
extern struct fmt_main fmt_drupal7;
extern struct fmt_main fmt_cryptsha256;
extern struct fmt_main fmt_cryptsha512;
#endif

#ifdef HAVE_SKEY
extern struct fmt_main fmt_SKEY;
#endif

#ifdef HAVE_NSS
extern struct fmt_main mozilla_fmt;
extern int mozilla2john(int argc, char **argv);
#endif

#ifdef CL_VERSION_1_0
extern struct fmt_main fmt_opencl_NSLDAPS;
extern struct fmt_main fmt_opencl_rawMD5;
extern struct fmt_main fmt_opencl_NT;
extern struct fmt_main fmt_opencl_rawSHA1;
extern struct fmt_main fmt_opencl_cryptMD5;
extern struct fmt_main fmt_opencl_phpass;
extern struct fmt_main fmt_opencl_mysqlsha1;
extern struct fmt_main fmt_opencl_cryptsha512;
extern struct fmt_main fmt_opencl_mscash2;
extern struct fmt_main fmt_opencl_wpapsk;
extern struct fmt_main fmt_opencl_xsha512;
extern struct fmt_main fmt_opencl_rawsha512;
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

#endif

extern struct fmt_main fmt_ssh;
extern struct fmt_main fmt_pdf;
extern struct fmt_main rar_fmt;
extern struct fmt_main zip_fmt;

#include "fmt_externs.h"

extern struct fmt_main fmt_hmacMD5;
extern struct fmt_main fmt_hmacSHA1;

extern int unique(int argc, char **argv);
extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int undrop(int argc, char **argv);
#ifndef _MSC_VER
extern int ssh2john(int argc, char **argv);
extern int pdf2john(int argc, char **argv);
extern int rar2john(int argc, char **argv);
extern int racf2john(int argc, char **argv);
extern int pwsafe2john(int argc, char **argv);
#endif
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
	struct fmt_main *pFmts;

	if (options.format) strlwr(options.format);

	// NOTE, this MUST happen, before ANY format that links a 'thin' format to dynamic.
	// Since gen(27) and gen(28) are MD5 and MD5a formats, we build the
	// generic format first
	cnt = dynamic_Register_formats(&pFmts);

	john_register_one(&fmt_DES);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_LM);

	for (i = 0; i < cnt; ++i)
		john_register_one(&(pFmts[i]));

#include "fmt_registers.h"

	john_register_one(&fmt_hmacMD5);
	john_register_one(&fmt_hmacSHA1);

#if OPENSSL_VERSION_NUMBER >= 0x00908000
	john_register_one(&fmt_rawSHA224);
	john_register_one(&fmt_rawSHA256);
	john_register_one(&fmt_rawSHA384);
	john_register_one(&fmt_rawSHA512);

	john_register_one(&fmt_hmacSHA224);
	john_register_one(&fmt_hmacSHA256);
	john_register_one(&fmt_hmacSHA384);
	john_register_one(&fmt_hmacSHA512);

	john_register_one(&fmt_XSHA512);

	john_register_one(&fmt_hmailserver);
	john_register_one(&fmt_SybaseASE);
	john_register_one(&fmt_dragonfly3_64);
	john_register_one(&fmt_dragonfly4_64);
	john_register_one(&fmt_dragonfly3_32);
	john_register_one(&fmt_dragonfly4_32);
	john_register_one(&fmt_drupal7);
	john_register_one(&fmt_cryptsha256);
	john_register_one(&fmt_cryptsha512);
#endif

#ifdef HAVE_NSS
	john_register_one(&mozilla_fmt);
#endif

#ifdef HAVE_CRYPT
	john_register_one(&fmt_crypt);
#endif
	john_register_one(&fmt_trip);
#ifdef HAVE_SKEY
	john_register_one(&fmt_SKEY);
#endif

	john_register_one(&fmt_ssh);
	john_register_one(&fmt_pdf);
#ifndef _MSC_VER
	john_register_one(&rar_fmt);
#endif
	john_register_one(&zip_fmt);
	john_register_one(&fmt_dummy);

#ifdef CL_VERSION_1_0
	john_register_one(&fmt_opencl_NSLDAPS);
	john_register_one(&fmt_opencl_rawMD5);
	john_register_one(&fmt_opencl_NT);
	john_register_one(&fmt_opencl_rawSHA1);
	john_register_one(&fmt_opencl_cryptMD5);
	john_register_one(&fmt_opencl_phpass);
	john_register_one(&fmt_opencl_mysqlsha1);
	john_register_one(&fmt_opencl_cryptsha512);
	john_register_one(&fmt_opencl_mscash2);
	john_register_one(&fmt_opencl_wpapsk);
	john_register_one(&fmt_opencl_xsha512);
	john_register_one(&fmt_opencl_rawsha512);
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

static void john_init(char *name, int argc, char **argv)
{
	int make_check = (argc == 2 && !strcmp(argv[1], "--make_check"));
	if (make_check)
		argv[1] = "--test=0";

	CPU_detect_or_fallback(argv, make_check);

	status_init(NULL, 1);
	if (argc < 2)
		john_register_all(); /* for printing by opt_init() */
	opt_init(name, argc, argv);

	if (options.listconf && !strcasecmp(options.listconf, "?"))
	{
		puts("inc-modes, rules, externals, ext-filters, ext-filters-only,");
		puts("ext-modes, build-info, hidden-options, <conf section name>");
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "hidden-options"))
	{
		puts("--list=NAME               list configuration, rules, etc");
		puts("--mkpc=N                  force a lower max. keys per crypt");
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
			puts("Rec file version: " RECOVERY_V);
			printf("CHARSET_MIN: %d (0x%02x)\n", CHARSET_MIN,
			       CHARSET_MIN);
			printf("CHARSET_MAX: %d (0x%02x)\n", CHARSET_MAX,
			       CHARSET_MAX);
			printf("CHARSET_LENGTH: %d\n", CHARSET_LENGTH);
#ifdef __GNUC__
			printf("gcc version: %d.%d.%d\n", __GNUC__,
			       __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
#ifdef __ICC
			printf("icc version: %d\n", __ICC);
#endif
			exit(0);
		}

		if (options.flags & FLG_CONFIG_CLI)
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

	if (options.subformat && !strcasecmp(options.subformat, "list"))
	{
		dynamic_DISPLAY_ALL_FORMATS();
		/* NOTE if we have other 'generics', like sha1, sha2, rc4, ...
		 * then EACH of them should have a DISPLAY_ALL_FORMATS()
		 * function and we can call them here. */
		exit(0);
	}

	if (options.listconf && !strcasecmp(options.listconf, "inc-modes"))
	{
		cfg_print_subsections("Incremental", NULL, NULL);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "rules"))
	{
		cfg_print_subsections("List.Rules", NULL, NULL);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "externals"))
	{
		cfg_print_subsections("List.External", NULL, NULL);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "ext-filters"))
	{
		cfg_print_subsections("List.External", "filter", NULL);
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "ext-filters-only"))
	{
		cfg_print_subsections("List.External", "filter", "generate");
		exit(0);
	}
	if (options.listconf && !strcasecmp(options.listconf, "ext-modes"))
	{
		cfg_print_subsections("List.External", "generate", NULL);
		exit(0);
	}
	/* Catch-all for any other john.conf section name :-) */
	if (options.listconf)
	{
		cfg_print_subsections(options.listconf, NULL, NULL);
		exit(0);
	}

	initUnicode(UNICODE_UNICODE); /* Init the unicode system */

	john_register_all(); /* maybe restricted to one format by options */
	common_init();
	sig_init();

	john_load();

	if (options.encodingStr && options.encodingStr[0])
		log_event("- %s input encoding enabled", options.encodingStr);

#ifdef CL_VERSION_1_0
	if (!options.ocl_platform)
	if ((options.ocl_platform =
	     cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, "Platform")))
		platform_id = atoi(options.ocl_platform);

	if (!options.ocl_device)
	if ((options.ocl_device =
	     cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, "Device")))
		gpu_id = atoi(options.ocl_device);
#endif
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
			if(cfg_get_bool(SECTION_OPTIONS, NULL, "MPIOMPmutex", 1)) {
				if(cfg_get_bool(SECTION_OPTIONS, NULL, "MPIOMPverbose", 1) &&
				   mpi_id == 0)
					fprintf(stderr, "MPI in use, disabling OMP (see doc/README.mpi)\n");
				omp_set_num_threads(1);
			} else
				if(cfg_get_bool(SECTION_OPTIONS, NULL, "MPIOMPverbose", 1) &&
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
			do_markov_crack(&database, options.mkv_level, options.mkv_start, options.mkv_end, options.mkv_maxlen, options.mkv_minlevel, options.mkv_minlen);
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

 	if (!strcmp(name, "pdf2john")) {
		CPU_detect_or_fallback(argv, 0);
		return pdf2john(argc, argv);
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

	if (!strcmp(name, "zip2john")) {
		CPU_detect_or_fallback(argv, 0);
		return zip2john(argc, argv);
	}

#ifdef HAVE_MPI
	mpi_setup(argc, argv);
#endif
	john_init(name, argc, argv);
	john_run();
	john_done();

#ifdef _MSC_VER
	_CrtDumpMemoryLeaks();
#endif

	return exit_status;
}
