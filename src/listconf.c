/*
 * Copyright (c) 2012, 2013 Frank Dittrich, JimF and magnum
 *
 * This software is hereby released to the general public under the following
 * terms:  Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
/* need to know if HAVE_LIBGMP is set, for autoconfig build */
#include "autoconfig.h"
#endif

#define _GNU_SOURCE 1 /* Try to elicit RTLD_DEFAULT */

#if HAVE_OPENCL
#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif
#if !AC_BUILT
 #include <string.h>
 #ifndef _MSC_VER
  #include <strings.h>
 #endif
#else
 #if STRING_WITH_STRINGS
  #include <string.h>
  #include <strings.h>
 #elif HAVE_STRING_H
  #include <string.h>
 #elif HAVE_STRINGS_H
  #include <strings.h>
 #endif
#endif

#if HAVE_LIBCRYPTO
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#endif

#if HAVE_LIBDL
#include <dlfcn.h>
#elif HAVE_WINDOWS_H
#define JTR_DLSYM_ONLY 1
#include "Win32-dlfcn-port.h"
#define HAVE_LIBDL 1
#endif

#if HAVE_LIBGMP && !__MIC__
#if HAVE_GMP_GMP_H
#include <gmp/gmp.h>
#else
#include <gmp.h>
#endif
#endif

#if __GLIBC__
#include <gnu/libc-version.h>
#endif

#include "arch.h"
#include "simd-intrinsics.h"
#include "jumbo.h"
#include "params.h"
#include "path.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "dynamic.h"
#include "dynamic_types.h"
#include "config.h"
#include "bench.h"
#include "timer.h"
#include "misc.h"
#include "regex.h"
#include "opencl_common.h"
#include "mask_ext.h"
#include "john.h"
#include "version.h"
#include "listconf.h" /* must be included after version.h and misc.h */

#ifdef NO_JOHN_BLD
#define JOHN_BLD "unk-build-type"
#else
#include "john_build_rule.h"
#endif

#if CPU_DETECT
extern char CPU_req_name[];
#endif

#define SINGLE_MAX_WORDS(len) MIN(SINGLE_IDX_MAX, SINGLE_BUF_MAX / len + 1)

/*
 * FIXME: Should all the listconf_list_*() functions get an additional stream
 * parameter, so that they can write to stderr instead of stdout in case fo an
 * error?
 */
static void listconf_list_options()
{
	puts("help[:WHAT], subformats, inc-modes, rules, externals, ext-modes, ext-hybrids,");
	puts("ext-filters, ext-filters-only, build-info, encodings, formats, format-classes,");
	puts("format-details, format-all-details, format-methods[:WHICH], format-tests,");
	printf("sections, parameters:SECTION, list-data:SECTION, ");
#if HAVE_OPENCL
	puts("opencl-devices,");
#endif
	/* NOTE: The following must end the list. Anything listed after
	   <conf section name> will be ignored by current
	   bash completion scripts. */

	/* FIXME: Should all the section names get printed instead?
	 *        But that would require a valid config.
	 */
	puts("<conf section name>");
}

static void listconf_list_help_options()
{
	puts("help, format-methods, parameters, list-data");
}

static void listconf_list_method_names()
{
	puts("init, done, reset, prepare, valid, split, binary, salt, tunable_cost_value,");
	puts("source, binary_hash, salt_hash, salt_compare, set_salt, set_key, get_key,");
	puts("clear_keys, crypt_all, get_hash, cmp_all, cmp_one, cmp_exact");
}

static void listconf_list_build_info(void)
{
	char DebuggingOptions[512], *cpdbg=DebuggingOptions;
#ifdef __GNU_MP_VERSION
	int gmp_major, gmp_minor, gmp_patchlevel;
#endif
	puts("Version: " JTR_GIT_VERSION);
	puts("Build: " JOHN_BLD _MP_VERSION OCL_STRING ZTEX_STRING DEBUG_STRING ASAN_STRING UBSAN_STRING);
#ifdef SIMD_COEF_32
	printf("SIMD: %s, interleaving: MD4:%d MD5:%d SHA1:%d SHA256:%d SHA512:%d\n",
	       SIMD_TYPE,
	       SIMD_PARA_MD4, SIMD_PARA_MD5, SIMD_PARA_SHA1,
	       SIMD_PARA_SHA256, SIMD_PARA_SHA512);
#endif
#if JOHN_SYSTEMWIDE
	puts("System-wide exec: " JOHN_SYSTEMWIDE_EXEC);
	puts("System-wide home: " JOHN_SYSTEMWIDE_HOME);
	puts("Private home: " JOHN_PRIVATE_HOME);
#endif
#if CPU_REQ
	printf("CPU tests: %s\n", CPU_req_name);
#endif
#if CPU_FALLBACK
	puts("CPU fallback binary: " CPU_FALLBACK_BINARY);
#endif
#if OMP_FALLBACK
	puts("OMP fallback binary: " OMP_FALLBACK_BINARY);
#endif
	printf("$JOHN is %s\n", path_expand("$JOHN/"));
	printf("Format interface version: %d\n", FMT_MAIN_VERSION);
	printf("Max. number of reported tunable costs: %d\n", FMT_TUNABLE_COSTS);
	puts("Rec file version: " RECOVERY_V);
	puts("Charset file version: " CHARSET_V);
	printf("CHARSET_MIN: %d (0x%02x)\n", CHARSET_MIN, CHARSET_MIN);
	printf("CHARSET_MAX: %d (0x%02x)\n", CHARSET_MAX, CHARSET_MAX);
	printf("CHARSET_LENGTH: %d\n", CHARSET_LENGTH);
	printf("SALT_HASH_SIZE: %u\n", SALT_HASH_SIZE);
	printf("SINGLE_IDX_MAX: %u\n", SINGLE_IDX_MAX);
	printf("SINGLE_BUF_MAX: %u\n", SINGLE_BUF_MAX);
	printf("Effective limit: ");
	if (sizeof(SINGLE_KEYS_TYPE) < 4 || sizeof(SINGLE_KEYS_UTYPE) < 4) {
		if (SINGLE_MAX_WORDS(125) < SINGLE_MAX_WORDS(16))
			printf("Max. KPC %d at length 16, down to %d at length 125\n",
			       SINGLE_MAX_WORDS(16), SINGLE_MAX_WORDS(125));
		else
			printf("Max. KPC %d\n", SINGLE_MAX_WORDS(125));
	} else
		printf("Number of salts vs. SingleMaxBufferSize\n");
	printf("Max. Markov mode level: %d\n", MAX_MKV_LVL);
	printf("Max. Markov mode password length: %d\n", MAX_MKV_LEN);

#if __ICC
	printf("icc version: %d.%d.%d (gcc %d.%d.%d compatibility)\n",
	       __ICC / 100, (__ICC % 100) / 10, __ICC % 10,
	       __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__clang_version__)
	printf("clang version: %s (gcc %d.%d.%d compatibility)\n",
	       __clang_version__,
	       __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif __GNUC__
	printf("gcc version: %d.%d.%d\n", __GNUC__,
	       __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif _MSC_VER
/*
 * See https://msdn.microsoft.com/en-us/library/b0084kay.aspx
 * Currently, _MSC_BUILD is not reported, but we could convert
 * _MSC_FULL_VER 150020706 and _MSC_BUILD 1 into a string
 * "15.00.20706.01".
 */
#ifdef _MSC_FULL_VER
	printf("Microsoft compiler version: %d\n", _MSC_FULL_VER);
#else
	printf("Microsoft compiler version: %d\n", _MSC_VER);
#endif
#ifdef __CLR_VER
	puts("Common Language Runtime version: " __CLR_VER);
#endif
#elif defined(__VERSION__)
	printf("Compiler version: %s\n", __VERSION__);
#endif

#ifdef __GLIBC_MINOR__
#ifdef __GLIBC__
	printf("GNU libc version: %d.%d (loaded: %s)\n",
	       __GLIBC__, __GLIBC_MINOR__, gnu_get_libc_version());
#endif
#endif

#if HAVE_OPENCL
	printf("OpenCL headers version: %s\n",get_opencl_header_version());
#endif
#if HAVE_LIBCRYPTO
	printf("Crypto library: OpenSSL\n");
#else
	printf("Crypto library: None\n");
#endif

#if HAVE_LIBDL && defined(RTLD_DEFAULT)

#if defined SSLEAY_VERSION && !defined OPENSSL_VERSION
#define OPENSSL_VERSION SSLEAY_VERSION
#elif defined OPENSSL_VERSION && !defined SSLEAY_VERSION
#define SSLEAY_VERSION OPENSSL_VERSION
#endif

#ifdef OPENSSL_VERSION_NUMBER
	printf("OpenSSL library version: %09lx", (unsigned long)OPENSSL_VERSION_NUMBER);
	if (dlsym(RTLD_DEFAULT, "OpenSSL_version_num")) {
		unsigned long (*OpenSSL_version_num)(void) =
			dlsym(RTLD_DEFAULT, "OpenSSL_version_num");

		if (OPENSSL_VERSION_NUMBER != OpenSSL_version_num())
			printf("\t(loaded: %09lx)", OpenSSL_version_num());
	} else if (dlsym(RTLD_DEFAULT, "SSLeay")) {
		unsigned long (*SSLeay)(void) = dlsym(RTLD_DEFAULT, "SSLeay");

		if (OPENSSL_VERSION_NUMBER != SSLeay())
			printf("\t(loaded: %09lx)", SSLeay());
	}
	printf("\n");
#endif
#ifdef OPENSSL_VERSION_TEXT
	printf("%s", OPENSSL_VERSION_TEXT);
	if (dlsym(RTLD_DEFAULT, "OpenSSL_version")) {
		const char* (*OpenSSL_version)(int) =
			dlsym(RTLD_DEFAULT, "OpenSSL_version");

		if (strcmp(OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION)))
			printf("\t(loaded: %s)", OpenSSL_version(OPENSSL_VERSION));
	} else if (dlsym(RTLD_DEFAULT, "SSLeay_version")) {
		const char* (*SSLeay_version)(int) = dlsym(RTLD_DEFAULT, "SSLeay_version");
		if (strcmp(OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION)))
			printf("\t(loaded: %s)", SSLeay_version(SSLEAY_VERSION));
	}
	printf("\n");
#endif
#endif /* HAVE_LIBDL && defined(RTLD_DEFAULT) */

#ifdef __GNU_MP_VERSION
	printf("GMP library version: %d.%d.%d",
	       __GNU_MP_VERSION, __GNU_MP_VERSION_MINOR, __GNU_MP_VERSION_PATCHLEVEL);
	/* version strings prior to 4.3.0 did omit the patch level when it was 0 */
	gmp_patchlevel = 0;
	sscanf(gmp_version, "%d.%d.%d", &gmp_major, &gmp_minor, &gmp_patchlevel);
	if (gmp_major != __GNU_MP_VERSION || gmp_minor != __GNU_MP_VERSION_MINOR ||
	    gmp_patchlevel != __GNU_MP_VERSION_PATCHLEVEL)
		printf("\t(loaded: %d.%d.%d)",
		       gmp_major, gmp_minor, gmp_patchlevel);
	printf("\n");
#endif

#if HAVE_REXGEN
	// JS_REGEX_BUILD_VERSION not reported here.
	// It was defined as 122 in an earlier version, but is
	// currently defined as DEV (yes, without quotes!)
	printf("Regex library version: %d.%d\t(loaded: %s)\n",
	       JS_REGEX_MAJOR_VERSION, JS_REGEX_MINOR_VERSION,
	       rexgen_version());
#endif
#if defined(F_SETLK) && defined(F_SETLKW) && defined(F_UNLCK)	  \
	&& defined(F_RDLCK) && defined(F_WRLCK)
	puts("File locking: fcntl()");
#else
	puts("File locking: NOT supported by this build - do not run concurrent sessions!");
#endif
	printf("fseek(): " STR_MACRO(jtr_fseek64) "\n");
	printf("ftell(): " STR_MACRO(jtr_ftell64) "\n");
	printf("fopen(): " STR_MACRO(jtr_fopen) "\n");
#if HAVE_MEMMEM
#define memmem_func	"System's"
#else
#define memmem_func	"JtR internal"
#endif
	printf("memmem(): " memmem_func "\n");

	clk_tck_init();
#if defined(_SC_CLK_TCK) || !defined(CLK_TCK)
	printf("times(2) sysconf(_SC_CLK_TCK) is %ld\n", clk_tck);
#else
	printf("times(2) CLK_TCK is %ld\n", clk_tck);
#endif
#if defined (__MINGW32__) || defined (_MSC_VER)
	printf("Using clock(3) for timers, resolution %ss\n", human_prefix_small(1.0 / CLOCKS_PER_SEC));
#else
	printf("Using times(2) for timers, resolution %ss\n", human_prefix_small(1.0 / clk_tck));
#endif
	int latency;
	uint64_t precision = john_timer_stats(&latency);

	printf("HR timer: %s, %s %ss\n", john_nano_clock, latency ? "latency" : "resolution",
	       human_prefix_small(precision / 1000000000.0));

	int64_t total_mem = host_total_mem();

	if (total_mem >= 0)
		printf("Total physical host memory: %sB\n", human_prefix(total_mem));
	else
		puts("Total physical host memory: unknown");

	int64_t avail_mem = host_avail_mem();

	if (avail_mem >= 0)
		printf("Available physical host memory: %sB\n", human_prefix(avail_mem));
	else
		puts("Available physical host memory: unknown");

	printf("Terminal locale string: %s\n", john_terminal_locale);
	printf("Parsed terminal locale: %s\n", cp_id2name(options.terminal_enc));

// OK, now append debugging options, BUT only output  something if
// one or more of them is set. IF none set, be silent.
#if defined (DEBUG)
	cpdbg += sprintf(cpdbg, "\t'#define DEBUG' set\n");
#endif
#ifdef WITH_ASAN
	cpdbg += sprintf(cpdbg, "\tASan (Address Sanitizer debugging)\n");
#endif
#ifdef WITH_UBSAN
	cpdbg += sprintf(cpdbg, "\tUbSan (Undefined Behavior Sanitizer debugging)\n");
#endif
	if (DebuggingOptions != cpdbg) {
		printf("Built with these debugging options\n%s\n", DebuggingOptions);
	}
}

void listconf_parse_early(void)
{
/*
 * --list=? needs to be supported, because it has been supported in the released
 * john-1.7.9-jumbo-6 version, and it is used by the bash completion script.
 * --list=? is, however, not longer mentioned in doc/OPTIONS and in the usage
 * output. Instead, --list=help is.
 */
	if ((!strcasecmp(options.listconf, "help") ||
	                         !strcmp(options.listconf, "?"))) {
		listconf_list_options();
		exit(EXIT_SUCCESS);
	}

	if ((!strcasecmp(options.listconf, "help:help") ||
	                         !strcasecmp(options.listconf, "help:"))) {
		listconf_list_help_options();
		exit(EXIT_SUCCESS);
	}

	if (!strcasecmp(options.listconf, "help:format-methods"))
	{
		listconf_list_method_names();
		exit(EXIT_SUCCESS);
	}
	if (!strncasecmp(options.listconf, "help:", 5))
	{
		if (strcasecmp(options.listconf, "help:parameters") &&
		    strcasecmp(options.listconf, "help:list-data"))
		{
			fprintf(stderr,
			        "%s is not a --list option that supports additional values.\nSupported options:\n",
			        options.listconf+5);
			listconf_list_help_options();
			exit(EXIT_FAILURE);
		}
	}

	if (!strcasecmp(options.listconf, "hidden-options"))
	{
		opt_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcasecmp(options.listconf, "build-info"))
	{
		listconf_list_build_info();
		exit(EXIT_SUCCESS);
	}

	if (!strcasecmp(options.listconf, "encodings"))
	{
		if (options.format)
			error_msg("--format not allowed with \"--list=%s\"\n", options.listconf);

		listEncodings(stdout);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "format-classes"))
	{
		puts(fmt_class_list);
		exit(EXIT_SUCCESS);
	}
}

/*
 * List names of tunable cost parameters
 * Separator differs for --list=format-all-details (", ")
 * and --list=format-details (",")
 */
void list_tunable_cost_names(struct fmt_main *format, char *separator)
{
	int i;

	for (i = 0; i < FMT_TUNABLE_COSTS; ++i) {
		if (format->params.tunable_cost_name[i]) {
			if (i)
				printf("%s", separator);
			printf("%s", format->params.tunable_cost_name[i]);
		}
	}
}

char *get_test(struct fmt_main *format, int ntests)
{
	int i, new_len = 0;

	// See if any of the fields are filled in. If so, the we should return
	// the ciphertext in passwd type format (user:pw:x:x:x...).
	// Otherwise simply return param.ciphertext.
	for (i = 0; i < 9; ++i) {
		if (i == 1) {
			if (!format->params.tests[ntests].fields[i])
				format->params.tests[ntests].fields[i] = format->params.tests[ntests].ciphertext;
		} else
			if (format->params.tests[ntests].fields[i] && (format->params.tests[ntests].fields[i])[0] )
				new_len += strlen(format->params.tests[ntests].fields[i]);
	}
	if (new_len) {
		char *Buf, *cp;
		int len = strlen(format->params.tests[ntests].fields[1])+12+new_len;
		Buf = mem_alloc_tiny(len, 1);
		cp = Buf;
		for (i = 0; i < 9; ++i) {
			if (format->params.tests[ntests].fields[i] && (format->params.tests[ntests].fields[i])[0] ) {
				int x = strnzcpyn(cp, format->params.tests[ntests].fields[i], len);
				cp += x;
				len -= (x+1);
			}
			*cp++ = ':';
		}
		while (*--cp == ':')
			*cp = 0; // nul terminate string and drop trailing ':'
		return Buf;
	} else
		return format->params.tests[ntests].ciphertext;
}

#ifdef DYNAMIC_DISABLED
#define dynamic_real_salt_length(format) 0
#endif

void listconf_parse_late(void)
{
#ifndef DYNAMIC_DISABLED
	if ((options.subformat && !strcasecmp(options.subformat, "list")) ||
	    (options.listconf && !strcasecmp(options.listconf, "subformats")))
	{
		if (options.format)
			error_msg("--format not allowed with \"--list=subformats\"\n");

		dynamic_DISPLAY_ALL_FORMATS();
/* NOTE if we have other 'generics', like sha1, sha2, rc4... then EACH of them
   should have a DISPLAY_ALL_FORMATS() function and we can call them here. */
		exit(EXIT_SUCCESS);
	}
#endif
#if HAVE_OPENCL
	if (!strcasecmp(options.listconf, "opencl-devices"))
	{
		opencl_list_devices();
		exit(EXIT_SUCCESS);
	}
	/* For other --list options that happen in listconf_parse_late()
	   we want to mute some GPU output */
	if (options.listconf) {
		options.flags |= FLG_VERBOSITY;
		options.verbosity = 1;
	}
#endif
	if (!strcasecmp(options.listconf, "inc-modes"))
	{
		cfg_print_subsections("Incremental", NULL, NULL, 0);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "rules"))
	{
		cfg_print_subsections("List.Rules", NULL, NULL, 0);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "externals"))
	{
		cfg_print_subsections("List.External", NULL, NULL, 0);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "sections"))
	{
		cfg_print_section_names(0);
		exit(EXIT_SUCCESS);
	}
	if (!strncasecmp(options.listconf, "parameters", 10) &&
	    (options.listconf[10] == '=' || options.listconf[10] == ':') &&
	    options.listconf[11] != '\0')
	{
		cfg_print_section_params(&options.listconf[11], NULL);
		exit(EXIT_SUCCESS);
	}
	if (!strncasecmp(options.listconf, "list-data", 9) &&
	    (options.listconf[9] == '=' || options.listconf[9] == ':') &&
	    options.listconf[10] != '\0')
	{
		cfg_print_section_list_lines(&options.listconf[10], NULL);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "ext-filters"))
	{
		cfg_print_subsections("List.External", "filter", NULL, 0);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "ext-filters-only"))
	{
		cfg_print_subsections("List.External", "filter", "generate", 0);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "ext-modes"))
	{
		cfg_print_subsections("List.External", "generate", NULL, 0);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "ext-hybrids"))
	{
		cfg_print_subsections("List.External", "new", NULL, 0);
		exit(EXIT_SUCCESS);
	}

	if (!strcasecmp(options.listconf, "formats")) {
		struct fmt_main *format;
		int column = 0, dynamics = 0;
		int grp_dyna, total = 0, add_comma = 0;
		char *format_option = options.format ? options.format : options.format_list;

		grp_dyna = !format_option || (!strcasestr(format_option, "disabled") && !strcasestr(format_option, "dynamic"));

		format = fmt_list;
		do {
			int length;
			const char *label = format->params.label;

			total++;

			if (grp_dyna && !strncmp(label, "dynamic", 7)) {
				if (dynamics++)
					continue;
				else
					label = "dynamic_n";
			}

			length = strlen(label) + 2;
			column += length;
			if (add_comma)
				printf(", ");
			else
				add_comma = 1;
			if (column > 78) {
				printf("\n");
				column = length;
			}
			printf("%s", label);
		} while ((format = format->next));
		printf("\n");

		fflush(stdout);
		fprintf(stderr, "%d formats", total);
		if (dynamics)
			fprintf(stderr, " (%d dynamic formats shown as just \"dynamic_n\" here)", dynamics);
		fprintf(stderr, "\n");

		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "format-details")) {
		struct fmt_main *format;

#if HAVE_OPENCL
/* This will make the majority of OpenCL formats also do "quick" run.
   But if LWS or GWS was already set, we do not overwrite. */
		setenv("LWS", "1", 0);
		setenv("GWS", "1", 0);
#endif

#if 0
		puts("label\tmaxlen\tmin/\tmaxkpc\tflags\tntests\talgorithm_name\tformat_name\tbench comment\tbench len\tbin size\tsalt size"
		     "\tcosts"
		     "\tminlen");
#endif

		format = fmt_list;
		do {
			int ntests = 0;
			char buf[LINE_BUFFER_SIZE + 1];

/* Some formats change max plaintext length when
   encoding is used, or KPC when under OMP */
			if (!strstr(format->params.label, "-ztex"))
				fmt_init(format);

			if (format->params.tests) {
				while (format->params.tests[ntests++].ciphertext);
				ntests--;
			}
			printf("%s\t%d\t%d\t%d\t%08x\t%d\t%s\t%s\t%s\t0x%x\t%d\t%d",
			       format->params.label,
			       format->params.plaintext_length,
			       format->params.min_keys_per_crypt,
			       format->params.max_keys_per_crypt,
			       format->params.flags,
			       ntests,
			       format->params.algorithm_name,
			       format->params.format_name,
			       format->params.benchmark_comment[0] == ' ' ?
			       &format->params.benchmark_comment[1] :
			       format->params.benchmark_comment,
			       format->params.benchmark_length,
			       format->params.binary_size,
			       ((format->params.flags & FMT_DYNAMIC) && format->params.salt_size) ?
/* salts are handled internally within the format. We want to know the
   'real' salt size. Dynamic will always set params.salt_size to 0 or sizeof
   a pointer. */
			       dynamic_real_salt_length(format) : format->params.salt_size);
			printf("\t");
			list_tunable_cost_names(format, ",");
			printf("\t%d\t%s\n",
			       format->params.plaintext_min_length,
/*
 * Since the example ciphertext should be the last line in the
 * --list=format-all-details output, it should also be the last column
 * here.
 * Even if this means tools processing --list=format-details output
 * have to check the number of columns if they want to use the example
 * ciphertext.
 *
 * ciphertext example will be silently $SOURCE_HASH$'ed if needed.
 */
			       ntests ?
			       ldr_pot_source(get_test(format, 0), buf) : "");

			fmt_done(format);

		} while ((format = format->next));
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "format-all-details")) {
		struct fmt_main *format;

#if HAVE_OPENCL
/* This will make the majority of OpenCL formats also do "quick" run.
   But if LWS or GWS was already set, we do not overwrite. */
		setenv("LWS", "1", 0);
		setenv("GWS", "1", 0);
#endif
		format = fmt_list;
		do {
			int ntests = 0;
			int enc_len, utf8_len;

/* Some formats change max plaintext length when encoding is used,
   or KPC when under OMP */
			if (!strstr(format->params.label, "-ztex"))
				fmt_init(format);

			utf8_len = enc_len = format->params.plaintext_length;
			if (options.target_enc == UTF_8)
				utf8_len /= 3;

			if (format->params.tests) {
				while (format->params.tests[ntests++].ciphertext);
				ntests--;
			}
/*
 * According to doc/OPTIONS, attributes should be printed in
 * the same sequence as with format-details, but human-readable.
 */
			printf("Format label                         %s\n", format->params.label);
/*
 * Indented (similar to the flags), because this information is not printed
 * for --list=format-details
 */
			printf(" Disabled in configuration file      %s\n",
			       cfg_get_bool(SECTION_DISABLED,
			                    SUBSECTION_FORMATS,
			                    format->params.label, 0)
			       ? "yes" : "no");
			printf("Min. password length                 %d\n", format->params.plaintext_min_length);
			if (!(format->params.flags & FMT_8_BIT) ||
			    options.target_enc != UTF_8 ||
			    !strncasecmp(format->params.label, "LM", 2) ||
			    !strcasecmp(format->params.label, "netlm") ||
			    !strcasecmp(format->params.label, "nethalflm") ||
			    !strcasecmp(format->params.label, "sapb")) {
				/* Not using UTF-8 so length is not ambiguous */
				printf("Max. password length                 %d\n", enc_len);
			} else if (!fmt_raw_len || fmt_raw_len == enc_len) {
				/* Example: Office and thin dynamics */
				printf("Max. password length                 %d [worst case UTF-8] to %d [ASCII]\n", utf8_len, enc_len);
			} else if (enc_len == 3 * fmt_raw_len) {
				/* Example: NT */
				printf("Max. password length                 %d\n", utf8_len);
			} else {
				/* Example: SybaseASE */
				printf("Max. password length                 %d [worst case UTF-8] to %d [ASCII]\n", utf8_len, fmt_raw_len);
			}
			printf("Min. keys per crypt                  %d\n", format->params.min_keys_per_crypt);
			printf("Max. keys per crypt                  %d\n", format->params.max_keys_per_crypt);
			printf("Flags\n");
			printf(" Case sensitive                      %s\n", (format->params.flags & FMT_CASE) ? "yes" : "no");
			printf(" Truncates at max. length            %s\n", (format->params.flags & FMT_TRUNC) ? "yes" : "no");
			printf(" Supports 8-bit characters           %s\n", (format->params.flags & FMT_8_BIT) ? "yes" : "no");
			printf(" Converts internally to UTF-16/UCS-2 %s\n", (format->params.flags & FMT_UNICODE) ? "yes" : "no");
			printf(" Honours --encoding=NAME             %s\n",
			       (format->params.flags & FMT_ENC) ? "yes" :
			       (format->params.flags & FMT_UNICODE) ? "no" : "n/a");
			printf(" Collisions possible (as in likely)  %s\n",
			       (format->params.flags & FMT_NOT_EXACT) ? "yes" : "no");
			printf(" Uses a bitslice implementation      %s\n", (format->params.flags & FMT_BS) ? "yes" : "no");
			printf(" The split() method unifies case     %s\n", (format->params.flags & FMT_SPLIT_UNIFIES_CASE) ? "yes" : "no");
			printf(" Supports very long hashes           %s\n", (format->params.flags & FMT_HUGE_INPUT) ? "yes" : "no");
			if (format->params.flags & FMT_MASK)
				printf(" Internal mask generation            yes (device target: %dx)\n", mask_int_cand_target);
			else
				printf(" Internal mask generation            no\n");

#ifndef DYNAMIC_DISABLED
			if (format->params.flags & FMT_DYNAMIC) {
#if SIMD_COEF_32
				private_subformat_data *p = (private_subformat_data *)format->private.data;
				if (p->pSetup->flags & MGF_FLAT_BUFFERS)
					printf(" A $dynamic$ format                  yes (Flat buffer SIMD)\n");
				else {
					if (p->pSetup->flags & MGF_NOTSSE2Safe)
					printf(" A $dynamic$ format                  yes (No SIMD)\n");
					else
					printf(" A $dynamic$ format                  yes (Interleaved SIMD)\n");
				}
#else
				printf(" A $dynamic$ format                  yes\n");
#endif
			} else
				printf(" A $dynamic$ format                  no\n");
#endif
			printf(" A dynamic sized salt                %s\n", (format->params.flags & FMT_DYNA_SALT) ? "yes" : "no");
#ifdef _OPENMP
			printf(" Parallelized with OpenMP            %s\n", (format->params.flags & FMT_OMP) ? "yes" : "no");
			if (format->params.flags & FMT_OMP)
				printf("  Poor OpenMP scalability            %s\n", (format->params.flags & FMT_OMP_BAD) ? "yes" : "no");
#endif
			printf("Number of test vectors               %d\n", ntests);
			printf("Algorithm name                       %s\n", format->params.algorithm_name);
			printf("Format name                          %s\n", format->params.format_name);
			printf("Benchmark comment                    %s\n", format->params.benchmark_comment[0] == ' ' ? &format->params.benchmark_comment[1] : format->params.benchmark_comment);
			printf("Benchmark length                     %d (0x%x, %s)\n",
			       format->params.benchmark_length & 0x7f,
			       format->params.benchmark_length,
			       format->params.benchmark_length & 0x100 ?
			       "raw" : format->params.benchmark_length & 0x200 ?
			       "shorter speedup" : "many salts speedup");
			printf("Binary size                          %d\n", format->params.binary_size);
			printf("Salt size                            %d\n",
			       ((format->params.flags & FMT_DYNAMIC) && format->params.salt_size) ?
/* salts are handled internally within the format. We want to know the
   'real' salt size dynamic will always set params.salt_size to 0 or
   sizeof a pointer. */
			       dynamic_real_salt_length(format) : format->params.salt_size);
			printf("Tunable cost parameters              ");
			list_tunable_cost_names(format, ", ");
			printf("\n");

/*
 * The below should probably stay as last line of output if adding more
 * information.
 *
 * ciphertext example will be $SOURCE_HASH$'ed if needed, with a notice.
 */
			if (ntests) {
				char *ciphertext = get_test(format, 0);
				char buf[LINE_BUFFER_SIZE + 1];

				printf("Example ciphertext%s  %s\n",
				       strlen(ciphertext) > MAX_CIPHERTEXT_SIZE ?
				       " (truncated here)" :
				       "                 ", ldr_pot_source(ciphertext, buf));
			}
			printf("\n");

			fmt_done(format);

		} while ((format = format->next));
		exit(EXIT_SUCCESS);
	}
	if (!strncasecmp(options.listconf, "format-methods", 14)) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ShowIt = 1, i;

			if (!strstr(format->params.label, "-ztex"))
				fmt_init(format);

			if (options.listconf[14] == '=' || options.listconf[14] == ':') {
				ShowIt = 0;
				if (!strcasecmp(&options.listconf[15], "valid")     ||
				    !strcasecmp(&options.listconf[15], "set_key")   ||
				    !strcasecmp(&options.listconf[15], "get_key")   ||
				    !strcasecmp(&options.listconf[15], "crypt_all") ||
				    !strcasecmp(&options.listconf[15], "cmp_all")   ||
				    !strcasecmp(&options.listconf[15], "cmp_one")   ||
				    !strcasecmp(&options.listconf[15], "cmp_exact"))
					ShowIt = 1;
				else if (strcasecmp(&options.listconf[15], "init") &&
				         strcasecmp(&options.listconf[15], "done") &&
				         strcasecmp(&options.listconf[15], "reset") &&
				         strcasecmp(&options.listconf[15], "prepare") &&
				         strcasecmp(&options.listconf[15], "split") &&
				         strcasecmp(&options.listconf[15], "binary") &&
				         strcasecmp(&options.listconf[15], "clear_keys") &&
				         strcasecmp(&options.listconf[15], "salt") &&
				         strcasecmp(&options.listconf[15], "tunable_cost_value") &&
				         strcasecmp(&options.listconf[15], "tunable_cost_value[0]") &&
#if FMT_TUNABLE_COSTS > 1
				         strcasecmp(&options.listconf[15], "tunable_cost_value[1]") &&
#if FMT_TUNABLE_COSTS > 2
				         strcasecmp(&options.listconf[15], "tunable_cost_value[2]") &&
#endif
#endif
					 strcasecmp(&options.listconf[15], "source") &&
				         strcasecmp(&options.listconf[15], "get_hash") &&
				         strcasecmp(&options.listconf[15], "get_hash[0]") &&
					 strcasecmp(&options.listconf[15], "get_hash[1]") &&
				         strcasecmp(&options.listconf[15], "get_hash[2]") &&
				         strcasecmp(&options.listconf[15], "get_hash[3]") &&
				         strcasecmp(&options.listconf[15], "get_hash[4]") &&
				         strcasecmp(&options.listconf[15], "get_hash[5]") &&
				         strcasecmp(&options.listconf[15], "get_hash[6]") &&
				         strcasecmp(&options.listconf[15], "set_salt") &&
				         strcasecmp(&options.listconf[15], "binary_hash") &&
				         strcasecmp(&options.listconf[15], "binary_hash[0]") &&
				         strcasecmp(&options.listconf[15], "binary_hash[1]") &&
				         strcasecmp(&options.listconf[15], "binary_hash[2]") &&
				         strcasecmp(&options.listconf[15], "binary_hash[3]") &&
				         strcasecmp(&options.listconf[15], "binary_hash[4]") &&
				         strcasecmp(&options.listconf[15], "binary_hash[5]") &&
					 strcasecmp(&options.listconf[15], "binary_hash[6]") &&
				         strcasecmp(&options.listconf[15], "salt_hash") &&
				         strcasecmp(&options.listconf[15], "salt_compare"))
				{
					fprintf(stderr, "Error, invalid option (invalid method name) %s\n", options.listconf);
					fprintf(stderr, "Valid method names are:\n");
					listconf_list_method_names();
					exit(EXIT_FAILURE);
				}
				if (format->methods.init != fmt_default_init && !strcasecmp(&options.listconf[15], "init"))
					ShowIt = 1;
				if (format->methods.done != fmt_default_done && !strcasecmp(&options.listconf[15], "done"))
					ShowIt = 1;

				if (format->methods.reset != fmt_default_reset && !strcasecmp(&options.listconf[15], "reset"))
					ShowIt = 1;

				if (format->methods.prepare != fmt_default_prepare && !strcasecmp(&options.listconf[15], "prepare"))
					ShowIt = 1;
				if (format->methods.split != fmt_default_split && !strcasecmp(&options.listconf[15], "split"))
					ShowIt = 1;
				if (format->methods.binary != fmt_default_binary && !strcasecmp(&options.listconf[15], "binary"))
					ShowIt = 1;
				if (format->methods.salt != fmt_default_salt && !strcasecmp(&options.listconf[15], "salt"))
					ShowIt = 1;

				for (i = 0; i < FMT_TUNABLE_COSTS; ++i) {
					char Buf[32];
					sprintf(Buf, "tunable_cost_value[%d]", i);
					if (format->methods.tunable_cost_value[i] && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.tunable_cost_value[0] && !strcasecmp(&options.listconf[15], "tunable_cost_value"))
					ShowIt = 1;

				if (format->methods.source != fmt_default_source && !strcasecmp(&options.listconf[15], "source"))
					ShowIt = 1;
				if (format->methods.clear_keys != fmt_default_clear_keys && !strcasecmp(&options.listconf[15], "clear_keys"))
					ShowIt = 1;
				for (i = 0; i < PASSWORD_HASH_SIZES; ++i) {
					char Buf[25];
					sprintf(Buf, "get_hash[%d]", i);
					if (format->methods.get_hash[i] && format->methods.get_hash[i] != fmt_default_get_hash && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.get_hash[0] && format->methods.get_hash[0] != fmt_default_get_hash && !strcasecmp(&options.listconf[15], "get_hash"))
					ShowIt = 1;

				for (i = 0; i < PASSWORD_HASH_SIZES; ++i) {
					char Buf[25];
					sprintf(Buf, "binary_hash[%d]", i);
					if (format->methods.binary_hash[i] && format->methods.binary_hash[i] != fmt_default_binary_hash && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.binary_hash[0] && format->methods.binary_hash[0] != fmt_default_binary_hash && !strcasecmp(&options.listconf[15], "binary_hash"))
					ShowIt = 1;
				if (format->methods.salt_hash != fmt_default_salt_hash && !strcasecmp(&options.listconf[15], "salt_hash"))
					ShowIt = 1;
				if (format->methods.salt_compare != NULL && !strcasecmp(&options.listconf[15], "salt_compare"))
					ShowIt = 1;
				if (format->methods.set_salt != fmt_default_set_salt && !strcasecmp(&options.listconf[15], "set_salt"))
					ShowIt = 1;
			}
			if (ShowIt) {
				int i;
				printf("Methods overridden for:   %s [%s] %s\n", format->params.label, format->params.algorithm_name, format->params.format_name);
				if (format->methods.init != fmt_default_init)
					printf("\tinit()\n");
				if (format->methods.done != fmt_default_done)
					printf("\tdone()\n");
				if (format->methods.reset != fmt_default_reset)
					printf("\treset()\n");
				if (format->methods.prepare != fmt_default_prepare)
					printf("\tprepare()\n");
				printf("\tvalid()\n");
				if (format->methods.split != fmt_default_split)
					printf("\tsplit()\n");
				if (format->methods.binary != fmt_default_binary)
					printf("\tbinary()\n");
				if (format->methods.salt != fmt_default_salt)
					printf("\tsalt()\n");
				for (i = 0; i < FMT_TUNABLE_COSTS; ++i)
/*
 * Here, a NULL value serves as default,
 * so any existing function should be printed
 */
					if (format->methods.tunable_cost_value[i])
						printf("\t\ttunable_cost_value[%d]()\n", i);
				if (format->methods.source != fmt_default_source)
					printf("\tsource()\n");
				for (i = 0; i < PASSWORD_HASH_SIZES; ++i)
					if (format->methods.binary_hash[i] != fmt_default_binary_hash) {
						if (format->methods.binary_hash[i])
							printf("\t\tbinary_hash[%d]()\n", i);
					}
				if (format->methods.salt_hash != fmt_default_salt_hash)
					printf("\tsalt_hash()\n");
/* salt_compare is always NULL for default */
				if (format->methods.salt_compare != NULL)
					printf("\tsalt_compare()\n");
				if (format->methods.set_salt != fmt_default_set_salt)
					printf("\tset_salt()\n");
// there is no default for set_key() it must be defined.
				printf("\tset_key()\n");
// there is no default for get_key() it must be defined.
				printf("\tget_key()\n");
				if (format->methods.clear_keys != fmt_default_clear_keys)
					printf("\tclear_keys()\n");
// there is no default for crypt_all() it must be defined.
				printf("\tcrypt_all()\n");
				for (i = 0; i < PASSWORD_HASH_SIZES; ++i)
					if (format->methods.get_hash[i] != fmt_default_get_hash) {
						if (format->methods.get_hash[i])
							printf("\t\tget_hash[%d]()\n", i);
					}
// there is no default for cmp_all() it must be defined.
				printf("\tcmp_all()\n");
// there is no default for cmp_one() it must be defined.
				printf("\tcmp_one()\n");
// there is no default for cmp_exact() it must be defined.
				printf("\tcmp_exact()\n");
				printf("\n\n");
			}
			fmt_done(format);
		} while ((format = format->next));
		exit(EXIT_SUCCESS);
	}
	if (!strncasecmp(options.listconf, "format-tests", 12)) {
		struct fmt_main *format;
		format = fmt_list;

#if HAVE_OPENCL
		/* This will make the majority of OpenCL formats
		   also do "quick" run. But if LWS or
		   GWS was already set, we do not overwrite. */
		setenv("LWS", "1", 0);
		setenv("GWS", "1", 0);
#endif
		do {
			int ntests = 0;

			/*
			 * fmt_init() and fmt_done() required for encoding
			 * support, because some formats (like Raw-MD5u)
			 * change their tests[] depending on the encoding.
			 */
			if (!strstr(format->params.label, "-ztex"))
				fmt_init(format);

			if (format->params.tests) {
				while (format->params.tests[ntests].ciphertext) {
					int skip = 0;
/*
 * defining a config variable to allowing --field-separator-char=
 * with a fallback to either ':' or '\t' is probably overkill
 */
					const char separator = '\t';
					char *ciphertext = get_test(format, ntests);
/*
 * one of the scrypt tests has tabs and new lines in ciphertext
 * and password.
 */
					if (strchr(format->params.tests[ntests].plaintext, '\x0a')) {
						skip = 1;
						fprintf(stderr,
						        "Test %s %d: plaintext contains line feed\n",
						        format->params.label, ntests);
					}
					if (strchr(ciphertext, '\x0a') ||
					    strchr(ciphertext, separator)) {
						skip |= 2;
						fprintf(stderr,
						        "Test %s %d: ciphertext contains line feed or separator character '%c'\n",
						        format->params.label, ntests, separator);
					}
/*
 * if they are both unsuitable or it's a magic internal-only test vector,
 * simply do not output a line at all
 */
					if (skip != 3 &&
					    !strstr(ciphertext, "$elftest") &&
					    !strstr(ciphertext, "\1\1\1\1\1\1\1\1")) {
						printf("%s%c%d",
							   format->params.label, separator, ntests);
						if (skip < 2) {
							printf("%c%s",
								   separator,
								   ciphertext);
							if (!skip)
								printf("%c%s",
									   separator,
									   format->params.tests[ntests].plaintext);
						}
						printf("\n");
					}
					ntests++;
				}
			}
			if (!ntests)
				printf("%s lacks test vectors\n",
				       format->params.label);

			fmt_done(format);

		} while ((format = format->next));
		exit(EXIT_SUCCESS);
	}
	/*
	 * Other --list=help:WHAT are processed in listconf_parse_early(), but
	 * these require a valid config:
	 */
	if (!strcasecmp(options.listconf, "help:parameters"))
	{
		cfg_print_section_names(1);
		exit(EXIT_SUCCESS);
	}
	if (!strcasecmp(options.listconf, "help:list-data"))
	{
		cfg_print_section_names(2);
		exit(EXIT_SUCCESS);
	}

	/* --list last resort: list subsections of any john.conf section name */

	//printf("Subsections of [%s]:\n", options.listconf);
	if (cfg_print_subsections(options.listconf, NULL, NULL, 1))
		exit(EXIT_SUCCESS);
	else {
		fprintf(stderr, "Section [%s] not found.\n", options.listconf);
		/* Just in case the user specified an invalid value
		 * like help or list...
		 * print the same list as with --list=?, but exit(EXIT_FAILURE)
		 */
		listconf_list_options();
		exit(EXIT_FAILURE);
	}
}
