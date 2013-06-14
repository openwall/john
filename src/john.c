/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2004,2006,2009-2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by JimF and magnum (and various others?)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * Please note that although this main john.c file is under the cut-down BSD
 * license above (so that you may reuse sufficiently generic pieces of code
 * from this file under these relaxed terms), some other source files that it
 * uses are under GPLv2.  For licensing terms for John the Ripper as a whole,
 * see doc/LICENSE.
 */

#define NEED_OS_FORK
#include "os.h"

#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#else
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <errno.h>
#include <string.h>
#ifndef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdlib.h>
#include <sys/stat.h>
#if OS_FORK
#include <sys/wait.h>
#endif

#include "params.h"

#ifdef _OPENMP
#include <omp.h>
static int john_omp_threads_orig = 0;
static int john_omp_threads_new;
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
#include "recovery.h"
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
#include "fake_salts.h"
#include "listconf.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

#include <openssl/opensslv.h>
#include "unicode.h"
#include "plugin.h"
#ifdef HAVE_OPENCL
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
extern struct fmt_main fmt_NT;

// can be done as a _plug format now. But I have not renamed the plugin file just yet.
extern struct fmt_main fmt_django;

#if OPENSSL_VERSION_NUMBER >= 0x10001000
extern struct fmt_main fmt_truecrypt;
extern struct fmt_main fmt_truecrypt_sha512;
extern struct fmt_main fmt_truecrypt_whirlpool;
#endif

#ifdef __SSE2__
extern struct fmt_main fmt_rawSHA256_ng;
extern struct fmt_main fmt_rawSHA512_ng;
#ifndef _MSC_VER
extern struct fmt_main fmt_sha1_ng;
#endif
#endif
#ifdef MMX_COEF_SHA256
extern struct fmt_main fmt_rawSHA256_ng_i;
#endif
#ifdef MMX_COEF_SHA512
extern struct fmt_main fmt_rawSHA512_ng_i;
#endif

#ifdef HAVE_SKEY
extern struct fmt_main fmt_SKEY;
#endif

#ifdef HAVE_NSS
extern struct fmt_main fmt_mozilla;
extern int mozilla2john(int argc, char **argv);
#endif
#ifdef HAVE_KRB5
extern struct fmt_main fmt_krb5_18;
extern struct fmt_main fmt_KRB5_kinit;
#endif
extern int hccap2john(int argc, char **argv);

#ifdef HAVE_OPENCL
extern struct fmt_main fmt_opencl_DES;
extern struct fmt_main fmt_opencl_NSLDAPS;
extern struct fmt_main fmt_opencl_NT;
extern struct fmt_main fmt_opencl_NTLMv2;
extern struct fmt_main fmt_opencl_agilekeychain;
extern struct fmt_main fmt_opencl_bf;
extern struct fmt_main fmt_opencl_cisco4;
extern struct fmt_main fmt_opencl_cryptMD5;
extern struct fmt_main fmt_opencl_cryptsha256;
extern struct fmt_main fmt_opencl_cryptsha512;
extern struct fmt_main fmt_opencl_dmg;
extern struct fmt_main fmt_opencl_encfs;
extern struct fmt_main fmt_opencl_gpg;
extern struct fmt_main fmt_opencl_keychain;
extern struct fmt_main fmt_opencl_krb5pa_sha1;
extern struct fmt_main fmt_opencl_mscash2;
extern struct fmt_main fmt_opencl_mysqlsha1;
extern struct fmt_main fmt_opencl_odf;
extern struct fmt_main fmt_opencl_odf_aes;
extern struct fmt_main fmt_opencl_office2007;
extern struct fmt_main fmt_opencl_office2010;
extern struct fmt_main fmt_opencl_office2013;
extern struct fmt_main fmt_opencl_phpass;
extern struct fmt_main fmt_opencl_pwsafe;
extern struct fmt_main fmt_opencl_rar;
extern struct fmt_main fmt_opencl_rawMD4;
extern struct fmt_main fmt_opencl_rawMD5;
extern struct fmt_main fmt_opencl_rawSHA1;
extern struct fmt_main fmt_opencl_rawsha256;
extern struct fmt_main fmt_opencl_rawsha512;
extern struct fmt_main fmt_opencl_rawsha512_ng;
extern struct fmt_main fmt_opencl_strip;
extern struct fmt_main fmt_opencl_sxc;
extern struct fmt_main fmt_opencl_wpapsk;
extern struct fmt_main fmt_opencl_xsha512;
extern struct fmt_main fmt_opencl_xsha512_ng;
extern struct fmt_main fmt_opencl_zip;
extern struct fmt_main fmt_opencl_blockchain;
extern struct fmt_main fmt_opencl_keyring;
#endif
#ifdef HAVE_CUDA
extern struct fmt_main fmt_cuda_cryptmd5;
extern struct fmt_main fmt_cuda_cryptsha256;
extern struct fmt_main fmt_cuda_cryptsha512;
extern struct fmt_main fmt_cuda_mscash2;
extern struct fmt_main fmt_cuda_mscash;
extern struct fmt_main fmt_cuda_phpass;
extern struct fmt_main fmt_cuda_pwsafe;
extern struct fmt_main fmt_cuda_rawsha224;
extern struct fmt_main fmt_cuda_rawsha256;
extern struct fmt_main fmt_cuda_rawsha512;
extern struct fmt_main fmt_cuda_wpapsk;
extern struct fmt_main fmt_cuda_xsha512;
#endif

extern struct fmt_main fmt_pfx;
extern struct fmt_main fmt_rar;
extern struct fmt_main fmt_ssh;
extern struct fmt_main fmt_wpapsk;
extern struct fmt_main fmt_zip;

#include "fmt_externs.h"

extern struct fmt_main fmt_hmacMD5;
extern struct fmt_main fmt_hmacSHA1;
extern struct fmt_main fmt_rawSHA0;

extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int unique(int argc, char **argv);
extern int undrop(int argc, char **argv);
#ifndef _MSC_VER
/* XXX: What's wrong with having these along with MSC? Perhaps this restriction
 * was meant to apply to some of these only? Maybe SSH only?
 *
 * NOPE, most will not compile at all. They use libs, headers, and other features (and poor coding)
 * that simply will not build or link under VC. (Jim)
 */
extern int ssh2john(int argc, char **argv);
extern int pfx2john(int argc, char **argv);
extern int keychain2john(int argc, char **argv);
extern int kwallet2john(int argc, char **argv);
extern int keepass2john(int argc, char **argv);
extern int keyring2john(int argc, char **argv);
extern int rar2john(int argc, char **argv);
extern int racf2john(int argc, char **argv);
extern int pwsafe2john(int argc, char **argv);
extern int dmg2john(int argc, char **argv);
extern int putty2john(int argc, char **argv);
extern int keystore2john(int argc, char **argv);
extern int truecrypt_volume2john(int argc, char **argv);
#endif
extern int zip2john(int argc, char **argv);

int john_main_process = 1;
#if OS_FORK
int john_child_count = 0;
int *john_child_pids = NULL;
#endif
static int children_ok = 1;

static struct db_main database;
static struct fmt_main dummy_format;

static int exit_status = 0;

static void john_register_one(struct fmt_main *format)
{
	if (options.format) {
		int len = strlen(options.format) - 1;

		if (options.format[len] == '*') {
			// Wildcard, as in wpapsk*
			if (strncasecmp(options.format, format->params.label, len)) return;
		}
		else if (!strcasecmp(options.format, "dynamic")) {
			if ( (format->params.flags & FMT_DYNAMIC) == 0) return;
		}
		else if (!strcasecmp(options.format, "cpu")) {
			if (strstr(format->params.label, "-opencl") ||
			    strstr(format->params.label, "-cuda")) return;
		}
		else if (!strcasecmp(options.format, "gpu")) {
			if (!strstr(format->params.label, "-opencl") &&
			    !strstr(format->params.label, "-cuda")) return;
		}
		else if (!strcasecmp(options.format, "opencl")) {
			if (!strstr(format->params.label, "-opencl")) return;
		}
		else if (!strcasecmp(options.format, "cuda")) {
			if (!strstr(format->params.label, "cuda")) return;
		}
		else if (strcasecmp(options.format, format->params.label)) return;
	}

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
	john_register_one(&fmt_LM);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_trip);
	john_register_one(&fmt_dummy);
	john_register_one(&fmt_NT);

	for (i = 0; i < cnt; ++i)
		john_register_one(&(selfs[i]));

#ifdef __SSE2__
	john_register_one(&fmt_rawSHA256_ng);
	john_register_one(&fmt_rawSHA512_ng);
#endif
#ifdef MMX_COEF_SHA256
	john_register_one(&fmt_rawSHA256_ng_i);
#endif
#ifdef MMX_COEF_SHA512
	john_register_one(&fmt_rawSHA512_ng_i);
#endif

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

#if defined (__SSE2__) && !defined(_MSC_VER)
	john_register_one(&fmt_sha1_ng);
#endif

#ifdef HAVE_NSS
	john_register_one(&fmt_mozilla);
#endif
#ifdef HAVE_KRB5
	john_register_one(&fmt_krb5_18);
	john_register_one(&fmt_KRB5_kinit);
#endif

#ifdef HAVE_SKEY
	john_register_one(&fmt_SKEY);
#endif

	john_register_one(&fmt_pfx);
	john_register_one(&fmt_rar);
	john_register_one(&fmt_ssh);
	john_register_one(&fmt_wpapsk);
	john_register_one(&fmt_zip);

#ifdef HAVE_OPENCL
	if (any_opencl_device_exists()) {
		john_register_one(&fmt_opencl_NSLDAPS);
		john_register_one(&fmt_opencl_NT);
		john_register_one(&fmt_opencl_NTLMv2);
		john_register_one(&fmt_opencl_agilekeychain);
		john_register_one(&fmt_opencl_cisco4);
		john_register_one(&fmt_opencl_cryptMD5);
		john_register_one(&fmt_opencl_cryptsha256);
		john_register_one(&fmt_opencl_cryptsha512);
		john_register_one(&fmt_opencl_dmg);
		john_register_one(&fmt_opencl_encfs);
		john_register_one(&fmt_opencl_gpg);
		john_register_one(&fmt_opencl_keychain);
		john_register_one(&fmt_opencl_krb5pa_sha1);
		john_register_one(&fmt_opencl_mscash2);
		john_register_one(&fmt_opencl_mysqlsha1);
		john_register_one(&fmt_opencl_odf);
		john_register_one(&fmt_opencl_odf_aes);
		john_register_one(&fmt_opencl_office2007);
		john_register_one(&fmt_opencl_office2010);
		john_register_one(&fmt_opencl_office2013);
		john_register_one(&fmt_opencl_phpass);
		john_register_one(&fmt_opencl_pwsafe);
		john_register_one(&fmt_opencl_rar);
		john_register_one(&fmt_opencl_rawMD4);
		john_register_one(&fmt_opencl_rawMD5);
		john_register_one(&fmt_opencl_rawSHA1);
		john_register_one(&fmt_opencl_rawsha256);
		john_register_one(&fmt_opencl_rawsha512);
		john_register_one(&fmt_opencl_rawsha512_ng);
		john_register_one(&fmt_opencl_strip);
		john_register_one(&fmt_opencl_sxc);
		john_register_one(&fmt_opencl_wpapsk);
		john_register_one(&fmt_opencl_xsha512);
		john_register_one(&fmt_opencl_xsha512_ng);
		john_register_one(&fmt_opencl_zip);
		john_register_one(&fmt_opencl_blockchain);
		john_register_one(&fmt_opencl_keyring);
		/* The following two need to be last until they are fixed
		   for new --device handling */
		john_register_one(&fmt_opencl_bf);
		john_register_one(&fmt_opencl_DES);
	}
#endif

#ifdef HAVE_CUDA
	john_register_one(&fmt_cuda_cryptmd5);
	john_register_one(&fmt_cuda_cryptsha256);
	john_register_one(&fmt_cuda_cryptsha512);
	john_register_one(&fmt_cuda_mscash);
	john_register_one(&fmt_cuda_mscash2);
	john_register_one(&fmt_cuda_phpass);
	john_register_one(&fmt_cuda_pwsafe);
	john_register_one(&fmt_cuda_rawsha224);
	john_register_one(&fmt_cuda_rawsha256);
	john_register_one(&fmt_cuda_rawsha512);
	john_register_one(&fmt_cuda_wpapsk);
	john_register_one(&fmt_cuda_xsha512);
#endif
#ifdef HAVE_CRYPT
	john_register_one(&fmt_crypt);
#endif

#ifdef HAVE_DL
	if (options.fmt_dlls)
	register_dlls ( options.fmt_dlls,
		cfg_get_param(SECTION_OPTIONS, NULL, "plugin"),
		john_register_one );
#endif

	if (!fmt_list) {
		if (john_main_process)
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_log_format(void)
{
	int min_chunk, chunk;

#ifdef HAVE_MPI
	if (mpi_p > 1)
		log_event("- MPI: Node %u/%u running on %s", mpi_id + 1, mpi_p, mpi_name);
#endif
	/* make sure the format is properly initialized */
	fmt_init(database.format);

	log_event("- Hash type: %.100s%s%.100s (lengths up to %d%s)",
	    database.format->params.label,
	    database.format->params.format_name[0] ? ", " : "",
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

#ifdef _OPENMP
static void john_omp_init(void)
{
	john_omp_threads_new = omp_get_max_threads();
	if (!john_omp_threads_orig)
		john_omp_threads_orig = john_omp_threads_new;
}

#if OMP_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error OMP_FALLBACK is incompatible with the current DOS and Win32 code
#endif
#define HAVE_JOHN_OMP_FALLBACK
static void john_omp_fallback(char **argv) {
	if (!getenv("JOHN_NO_OMP_FALLBACK") && john_omp_threads_new <= 1) {
		rec_done(-2);
#define OMP_FALLBACK_PATHNAME JOHN_SYSTEMWIDE_EXEC "/" OMP_FALLBACK_BINARY
		execv(OMP_FALLBACK_PATHNAME, argv);
		perror("execv: " OMP_FALLBACK_PATHNAME);
	}
}
#endif

static void john_omp_maybe_adjust_or_fallback(char **argv)
{
	if (options.fork && !getenv("OMP_NUM_THREADS")) {
		john_omp_threads_new /= options.fork;
		if (john_omp_threads_new < 1)
			john_omp_threads_new = 1;
		omp_set_num_threads(john_omp_threads_new);
		john_omp_init();
#ifdef HAVE_JOHN_OMP_FALLBACK
		john_omp_fallback(argv);
#endif
	}
}

static void john_omp_show_info(void)
{
#ifdef HAVE_MPI
	if (mpi_p == 1)
#endif
	if (!options.fork && john_omp_threads_orig > 1 &&
	    database.format && !rec_restoring_now) {
		const char *msg = NULL;
		if (!(database.format->params.flags & FMT_OMP))
			msg = "no OpenMP support";
		else if ((database.format->params.flags & FMT_OMP_BAD))
			msg = "poor OpenMP scalability";
		if (msg)
#if OS_FORK
			fprintf(stderr, "Warning: %s for this hash type, "
			    "consider --fork=%d\n",
			    msg, john_omp_threads_orig);
#else
			fprintf(stderr, "Warning: %s for this hash type\n",
			    msg);
#endif
	}

/*
 * Only show OpenMP info if one of the following is true:
 * - we have a format detected for the loaded hashes and it is OpenMP-enabled;
 * - we're doing --test and no format is specified (so we will test all,
 * including some that are presumably OpenMP-enabled);
 * - we're doing --test and the specified format is OpenMP-enabled.
 */
	{
		int show = 0;
		if (database.format &&
		    (database.format->params.flags & FMT_OMP))
			show = 1;
		else if ((options.flags & (FLG_TEST_CHK | FLG_FORMAT)) ==
		    FLG_TEST_CHK)
			show = 1;
		else if ((options.flags & FLG_TEST_CHK) &&
		    (fmt_list->params.flags & FMT_OMP))
			show = 1;

		if (!show)
			return;
	}

#ifdef HAVE_MPI
	/*
	 * If OMP_NUM_THREADS is set, we assume the user knows what
	 * he is doing. Here's how to pass it to remote hosts:
	 * mpirun -x OMP_NUM_THREADS=4 -np 4 -host ...
	 */
	if (mpi_p > 1) {
		if(getenv("OMP_NUM_THREADS") == NULL &&
		   cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI,
		                "MPIOMPmutex", 1)) {
			if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI,
			                "MPIOMPverbose", 1) && mpi_id == 0)
				fprintf(stderr, "MPI in use, disabling OMP "
				        "(see doc/README.mpi)\n");
			omp_set_num_threads(1);
		} else
			if(cfg_get_bool(SECTION_OPTIONS, SUBSECTION_MPI,
			                "MPIOMPverbose", 1) && mpi_id == 0)
				fprintf(stderr, "Note: Running both MPI and OMP"
				        " (see doc/README.mpi)\n");
	} else
#endif
	if (options.fork) {
#if OS_FORK
		if (john_omp_threads_new > 1)
			fprintf(stderr,
			    "Will run %d OpenMP threads per process "
			    "(%u total across %u processes)\n",
			    john_omp_threads_new,
			    john_omp_threads_new * options.fork, options.fork);
		else if (john_omp_threads_orig > 1)
			fputs("Warning: OpenMP was disabled due to --fork; "
			    "a non-OpenMP build may be faster\n", stderr);
#endif
	} else {
		if (john_omp_threads_new > 1)
			fprintf(stderr,
			    "Will run %d OpenMP threads\n",
			    john_omp_threads_new);
	}

	if (john_omp_threads_orig == 1)
		if (john_main_process)
		fputs("Warning: OpenMP is disabled; "
		    "a non-OpenMP build may be faster\n", stderr);
}
#endif

#if OS_FORK
static void john_fork(void)
{
	int i, pid;
	int *pids;

	fflush(stdout);
	fflush(stderr);

#ifdef HAVE_MPI
/*
 * We already initialized MPI before knowing this is actually a fork session.
 * So now we need to tear that "1-node MPI session" down before forking, or
 * all sorts of funny things might happen.
 */
	mpi_teardown();
#endif
/*
 * It may cost less memory to reset john_main_process to 0 before fork()'ing
 * the children than to do it in every child process individually (triggering
 * copy-on-write of the entire page).  We then reset john_main_process back to
 * 1 in the parent, but this only costs one page, not one page per child.
 */
	john_main_process = 0;

	pids = mem_alloc_tiny((options.fork - 1) * sizeof(*pids),
	    sizeof(*pids));

	for (i = 1; i < options.fork; i++) {
		switch ((pid = fork())) {
		case -1:
			pexit("fork");

		case 0:
			options.node_min += i;
			options.node_max = options.node_min;
			if (rec_restoring_now) {
				unsigned int node_id = options.node_min;
				rec_done(-2);
				rec_restore_args(1);
				if (node_id != options.node_min + i)
					fprintf(stderr,
					    "Inconsistent crash recovery file:"
					    " %s\n", rec_name);
				options.node_min = options.node_max = node_id;
			}
			sig_init_child();
			return;

		default:
			pids[i - 1] = pid;
		}
	}

	john_main_process = 1;
	john_child_pids = pids;
	john_child_count = options.fork - 1;

	options.node_max = options.node_min;
}

/*
 * This is the "equivalent" of john_fork() for MPI runs. We are mostly
 * mimicing a -fork run, especially for resuming a session.
 */
#ifdef HAVE_MPI
static void john_set_mpi(void)
{
	options.node_min += mpi_id;
	options.node_max = options.node_min;

	if (mpi_p > 1) {
		if (!john_main_process) {
			if (rec_restoring_now) {
				unsigned int node_id = options.node_min;
				rec_done(-2);
				rec_restore_args(1);
				if (node_id != options.node_min + mpi_id)
					fprintf(stderr,
					    "Inconsistent crash recovery file:"
					    " %s\n", rec_name);
				options.node_min = options.node_max = node_id;
			}
		}
	}
	fflush(stdout);
	fflush(stderr);
}
#endif

static void john_wait(void)
{
	int waiting_for = john_child_count;

	log_event("Waiting for %d child%s to terminate",
	    waiting_for, waiting_for == 1 ? "" : "ren");
	fprintf(stderr, "Waiting for %d child%s to terminate\n",
	    waiting_for, waiting_for == 1 ? "" : "ren");

/*
 * Although we may block on wait(2), we still have signal handlers and a timer
 * in place, so we're relaying keypresses to child processes via signals.
 */
	while (waiting_for) {
		int i, status;
		int pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR)
				perror("wait");
		} else
		for (i = 0; i < john_child_count; i++) {
			if (john_child_pids[i] == pid) {
				john_child_pids[i] = 0;
				waiting_for--;
				children_ok = children_ok &&
				    WIFEXITED(status) && !WEXITSTATUS(status);
				break;
			}
		}
	}

/* Close and possibly remove our .rec file now */
	rec_done((children_ok && !event_abort) ? -1 : -2);
}
#endif

#ifdef HAVE_MPI
static void john_mpi_wait(void)
{
	if (!database.password_count)
		fprintf(stderr, "%d: All hashes cracked! Abort remaining"
		        " nodes manually!\n", mpi_id + 1);

	if (nice(20) < 0)
		fprintf(stderr, "%d: nice() failed\n", mpi_id + 1);

	if (john_main_process)
		mpi_teardown();

/* Close and possibly remove our .rec file now */
	rec_done((children_ok && !event_abort) ? -1 : -2);
}
#endif

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
		dummy_format.methods.clear_keys = &fmt_default_clear_keys;
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

			if (john_main_process)
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
			options.loader.max_wordfile_memory = 1;
		}

		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		/* Unicode (UTF-16) formats may lack encoding support. We
		   must stop the user from trying to use it because it will
		   just result in false negatives. */
		if (database.password_count &&
		    !options.ascii && !options.iso8859_1 &&
		    database.format->params.flags & FMT_UNICODE &&
		    !(database.format->params.flags & FMT_UTF8)) {
				if (john_main_process)
				fprintf(stderr, "This format does not yet "
				        "support other encodings than"
				        " ISO-8859-1\n");
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
			if (john_main_process)
			printf("Loaded %s (%s%s%s [%s])\n",
			    john_loaded_counts(),
			    database.format->params.label,
			    database.format->params.format_name[0] ? ", " : "",
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
			if (john_main_process)
			printf("No password hashes %s (see FAQ)\n",
			    total ? "left to crack" : "loaded");
		} else
		if (database.password_count < total) {
			log_event("Remaining %s", john_loaded_counts());
			if (john_main_process)
			printf("Remaining %s\n", john_loaded_counts());
		}

		if ((options.flags & FLG_PWD_REQ) && !database.salts) exit(0);

		if (options.regen_lost_salts)
			build_fake_salts_for_regen_lost(database.salts);
	}

#ifdef _OPENMP
	john_omp_show_info();
#endif

	if (options.node_count) {
		if (options.node_min != options.node_max) {
			log_event("- Node numbers %u-%u of %u%s",
			    options.node_min, options.node_max,
#ifndef HAVE_MPI
			    options.node_count, options.fork ? " (fork)" : "");
#else
			    options.node_count, options.fork ? " (fork)" :
				    mpi_p > 1 ? " (MPI)" : "");
#endif
			if (john_main_process)
			fprintf(stderr, "Node numbers %u-%u of %u%s\n",
			    options.node_min, options.node_max,
#ifndef HAVE_MPI
			    options.node_count, options.fork ? " (fork)" : "");
#else
			    options.node_count, options.fork ? " (fork)" :
				    mpi_p > 1 ? " (MPI)" : "");
#endif
		} else {
			log_event("- Node number %u of %u",
			    options.node_min, options.node_count);
			if (john_main_process)
			fprintf(stderr, "Node number %u of %u\n",
			    options.node_min, options.node_count);
		}

#if OS_FORK
		if (options.fork)
			john_fork();
#endif
#ifdef HAVE_MPI
		if (mpi_p > 1)
			john_set_mpi();
#endif
		/* Re-init the unicode system. After resuming a forked or
		   MPI session, this is needed because the whole options
		   struct is reset. */
		initUnicode(UNICODE_UNICODE);
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
		fprintf(stderr, "Sorry, %s is required for this build\n",
		    CPU_NAME);
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
	int show_usage = 0;
	int make_check = (argc == 2 && !strcmp(argv[1], "--make_check"));
	if (make_check)
		argv[1] = "--test=0";

	CPU_detect_or_fallback(argv, make_check);

#ifdef _OPENMP
	john_omp_init();
#endif

	if (!make_check) {
#ifdef HAVE_JOHN_OMP_FALLBACK
		john_omp_fallback(argv);
#endif

		path_init(argv);
	}

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

	if (options.listconf)
		listconf_parse_early();

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

#ifdef _OPENMP
	john_omp_maybe_adjust_or_fallback(argv);
#endif

	initUnicode(UNICODE_UNICODE); /* Init the unicode system */

	john_register_all(); /* maybe restricted to one format by options */

	if ((options.subformat && !strcasecmp(options.subformat, "list")) ||
	    options.listconf)
		listconf_parse_late();

#ifdef HAVE_OPENCL
	if (any_opencl_device_exists())
		init_opencl_devices();
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
			char *where = fmt_self_test(database.format);
			if (where) {
				fprintf(stderr, "Self test failed (%s)\n",
				    where);
				error();
			}
			database.format->methods.reset(&database);
			log_init(LOG_NAME, options.loader.activepot, options.session);
			status_init(NULL, 1);
			john_log_format();
			if (idle_requested(database.format))
				log_event("- Configured to use otherwise idle "
					"processor cycles only");
		}
		tty_init(options.flags & FLG_STDIN_CHK);

		/* WPA-PSK and WoW both have min-length 8. Until the format
		   struct can hold this information, we need this hack here. */
		if (database.format->params.label &&
		    (!strncmp(database.format->params.label, "wpapsk", 6) ||
		     !strncmp(database.format->params.label, "wowsrp", 6)) &&
		    options.force_minlength < 8) {
			options.force_minlength = 8;
			if (john_main_process)
				fprintf(stderr,
				        "Note: minimum length forced to 8\n");

			/* Now we need to re-check this */
			if (options.force_maxlength &&
			    options.force_maxlength < options.force_minlength) {
				if (john_main_process)
					fprintf(stderr, "Invalid option: "
					        "--max-length smaller than "
					        "minimum length for format\n");
				error();
			}
		}

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

#if OS_FORK
		if (options.fork && john_main_process)
			john_wait();
#endif

#ifdef HAVE_MPI
		if (mpi_p > 1)
			john_mpi_wait();
#endif

		tty_done();

		if (john_main_process && database.password_count < remaining) {
			char *might = "Warning: passwords printed above might";
			char *partial = " be partial";
			char *not_all = " not be all those cracked";
			switch (database.options->flags &
			    (DB_SPLIT | DB_NODUP)) {
			case DB_SPLIT:
				fprintf(stderr, "%s%s\n", might, partial);
				break;
			case DB_NODUP:
				fprintf(stderr, "%s%s\n", might, not_all);
				break;
			case (DB_SPLIT | DB_NODUP):
				fprintf(stderr, "%s%s and%s\n",
				    might, partial, not_all);
			}
			fputs("Use the \"--show\" option to display all of "
			    "the cracked passwords reliably\n", stderr);
		}
	}
}

static void john_done(void)
{
	unsigned int time = status_get_time();

	if ((options.flags & (FLG_CRACKING_CHK | FLG_STDOUT)) ==
	    FLG_CRACKING_CHK) {
		if (event_abort) {
			log_event((time < timer_abort) ?
			          "Session aborted" :
			          "Session stopped (max run-time reached)");
			/* We have already printed to stderr from signals.c */
		} else if (children_ok) {
			log_event("Session completed");
			if (john_main_process)
				fprintf(stderr, "Session completed\n");
		} else {
			const char *msg =
			    "Main process session completed, "
			    "but some child processes failed";
			log_event("%s", msg);
			fprintf(stderr, "%s\n", msg);
			exit_status = 1;
		}
		fmt_done(database.format);
	}
	log_done();
#ifdef HAVE_OPENCL
	if (!(options.flags & FLG_FORK) || john_main_process)
		//Release OpenCL stuff.
		clean_opencl_environment();
#endif

	path_done();

	check_abort(0);
	cleanup_tiny_memory();
}

int main(int argc, char **argv)
{
	char *name;
	unsigned int time;

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
#if HAVE_WINDOWS_H
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

	if (!strcmp(name, "putty2john")) {
		CPU_detect_or_fallback(argv, 0);
		return putty2john(argc, argv);
	}

	if (!strcmp(name, "pfx2john")) {
		CPU_detect_or_fallback(argv, 0);
		return pfx2john(argc, argv);
	}

	if (!strcmp(name, "keychain2john")) {
		CPU_detect_or_fallback(argv, 0);
		return keychain2john(argc, argv);
	}

	if (!strcmp(name, "kwallet2john")) {
		CPU_detect_or_fallback(argv, 0);
		return kwallet2john(argc, argv);
	}

	if (!strcmp(name, "keepass2john")) {
		CPU_detect_or_fallback(argv, 0);
		return keepass2john(argc, argv);
	}

	if (!strcmp(name, "keyring2john")) {
		CPU_detect_or_fallback(argv, 0);
		return keyring2john(argc, argv);
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

	if (!strcmp(name, "keystore2john")) {
		CPU_detect_or_fallback(argv, 0);
		return keystore2john(argc, argv);
	}

	if (!strcmp(name, "truecrypt_volume2john")) {
		CPU_detect_or_fallback(argv, 0);
		return truecrypt_volume2john(argc, argv);
	}
#if !defined (__MINGW32__)
	if (!strcmp(name, "dmg2john")) {
		CPU_detect_or_fallback(argv, 0);
		return dmg2john(argc, argv);
	}
#endif
#endif

#ifdef HAVE_NSS
	if (!strcmp(name, "mozilla2john")) {
		CPU_detect_or_fallback(argv, 0);
		return mozilla2john(argc, argv);
	}
#endif

#ifndef _MSC_VER
	if (!strcmp(name, "zip2john")) {
		CPU_detect_or_fallback(argv, 0);
		return zip2john(argc, argv);
	}
	if (!strcmp(name, "hccap2john")) {
		CPU_detect_or_fallback(argv, 0);
		return hccap2john(argc, argv);
	}
#endif

#ifdef HAVE_MPI
	mpi_setup(argc, argv);
#else
	if (getenv("OMPI_COMM_WORLD_SIZE"))
	if (atoi(getenv("OMPI_COMM_WORLD_SIZE")) > 1) {
		fprintf(stderr, "ERROR: Running under MPI, but this is NOT an MPI build of John.\n");
		error();
	}
#endif
	john_init(name, argc, argv);

	/* --max-run-time and --progress-every disregards load time */
	time = status_get_time();
	if (options.max_run_time)
		timer_abort = time + options.max_run_time;
	if (options.status_interval)
		timer_status = time + options.status_interval;

	john_run();
	john_done();

#ifdef _MSC_VER
	_CrtDumpMemoryLeaks();
#endif

	return exit_status;
}
