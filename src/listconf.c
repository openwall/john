/*
 * Copyright (c) 2012, 2013 Frank Dittrich, JimF and magnum
 *
 * This software is hereby released to the general public under the following
 * terms:  Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _MSC_VER
#include <strings.h>
#endif
#include <string.h>
#include <openssl/crypto.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "dynamic.h"
#include "config.h"

#ifdef HAVE_NSS
#include "nss.h"
//#include "nssutil.h"
#include "nspr.h"
#endif
#ifdef HAVE_GMP
#include "gmp.h"
#endif

#ifdef NO_JOHN_BLD
#define JOHN_BLD "unk-build-type"
#else
#include "john_build_rule.h"
#endif

#ifdef HAVE_CUDA
extern char *get_cuda_header_version();
extern void cuda_device_list();
#endif
#ifdef HAVE_OPENCL
#include "common-opencl.h"
#endif
#include "memdbg.h"

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

/*
 * FIXME: Should all the listconf_list_*() functions get an additional stream
 * parameter, so that they can write to stderr instead of stdout in case fo an
 * error?
 */
static void listconf_list_options()
{
	puts("help[:WHAT], subformats, inc-modes, rules, externals, ext-filters,");
	puts("ext-filters-only, ext-modes, build-info, hidden-options, encodings,");
	puts("formats, format-details, format-all-details, format-methods[:WHICH],");
	// With "opencl-devices, cuda-devices, <conf section name>" added,
	// the resulting line will get too long
	puts("format-tests, sections, parameters:SECTION, list-data:SECTION,");
#ifdef HAVE_OPENCL
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

static void listconf_list_help_options()
{
	puts("help, format-methods, parameters, list-data");
}

static void listconf_list_method_names()
{
#if FMT_MAIN_VERSION > 11
	puts("init, done, reset, prepare, valid, split, binary, salt, tunable_cost_value,");
#else
	puts("init, done, reset, prepare, valid, split, binary, salt,");
#endif
	puts("source, binary_hash, salt_hash, set_salt, set_key, get_key, clear_keys,");
	puts("crypt_all, get_hash, cmp_all, cmp_one, cmp_exact");
}

static void listconf_list_build_info(void)
{
#ifdef __GNU_MP_VERSION
	int gmp_major, gmp_minor, gmp_patchlevel;
#endif
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
#if FMT_MAIN_VERSION > 11
	printf("Max. number of reported tunable costs: %d\n", FMT_TUNABLE_COSTS);
#endif
	puts("Rec file version: " RECOVERY_V);
	puts("Charset file version: " CHARSET_V);
	printf("CHARSET_MIN: %d (0x%02x)\n", CHARSET_MIN, CHARSET_MIN);
	printf("CHARSET_MAX: %d (0x%02x)\n", CHARSET_MAX, CHARSET_MAX);
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
#ifdef HAVE_CUDA
	printf("CUDA library version: %s\n",get_cuda_header_version());
#endif
#ifdef HAVE_OPENCL
	printf("OpenCL library version: %s\n",get_opencl_header_version());
#endif
#ifdef OPENSSL_VERSION_NUMBER
	printf("OpenSSL library version: %09lx", (unsigned long)OPENSSL_VERSION_NUMBER);
	if (OPENSSL_VERSION_NUMBER != SSLeay())
		printf("\t(loaded: %09lx)", (unsigned long)SSLeay());
	printf("\n");
#endif
#ifdef OPENSSL_VERSION_TEXT
	printf("%s", OPENSSL_VERSION_TEXT);
	if (strcmp(OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION)))
		printf("\t(loaded: %s)", SSLeay_version(SSLEAY_VERSION));
	printf("\n");
#endif
#ifdef __GNU_MP_VERSION
	// print GMP version info if HAVE_GMP has been set in Makefile
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
#ifdef NSS_VERSION
	// <major>.<minor>[.<patch_level>[.<build_number>]][ <ECC>][ <Beta>]
	printf("NSS library version: %s\n", NSS_VERSION);
#endif
// NSS_VERSION and NSSUTIL_VERSION always seem to match.
// At least, I didn't find any differences on Fedora 16/17/18 systems.
#ifdef PR_VERSION
	printf("NSPR library version: %s\n", PR_VERSION);
#endif
#ifdef HAVE_KRB5
	// I have no idea how to get version info
	printf("Kerberos version 5 support enabled\n");
#endif
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
		exit(0);
	}

	if ((!strcasecmp(options.listconf, "help:help") ||
	                         !strcasecmp(options.listconf, "help:"))) {
		listconf_list_help_options();
		exit(0);
	}

	if (!strcasecmp(options.listconf, "help:format-methods"))
	{
		listconf_list_method_names();
		exit(0);
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
			exit(1);
		}
	}
	if (!strcasecmp(options.listconf, "hidden-options"))
	{
		opt_print_hidden_usage();
		exit(0);
	}

	if (!strcasecmp(options.listconf, "build-info"))
	{
		listconf_list_build_info();
		exit(0);
	}

	if (!strcasecmp(options.listconf, "encodings"))
	{
		listEncodings();
		exit(0);
	}
#ifdef HAVE_OPENCL
	if (!strcasecmp(options.listconf, "opencl-devices"))
	{
		opencl_list_devices();
		exit(0);
	}
#endif
#ifdef HAVE_CUDA
	if (!strcasecmp(options.listconf, "cuda-devices"))
	{
		cuda_device_list();
		exit(0);
	}
#endif
}

#if FMT_MAIN_VERSION > 11
/* 
 * List names of tunable cost parameters
 * Separator differs for --list=format-all-details (", ")
 * and --list=format-details (",")
 */
void list_tunable_cost_names(struct fmt_main *format, char *separator)
{
	int i;

	for (i = 0; i < FMT_TUNABLE_COSTS; ++i) {
		if(format->params.tunable_cost_name[i]) {
			if (i)
				printf("%s", separator);
			printf("%s", format->params.tunable_cost_name[i]);
		}
	}
}
#endif

void listconf_parse_late(void)
{
	if ((options.subformat && !strcasecmp(options.subformat, "list")) ||
	    (options.listconf && !strcasecmp(options.listconf, "subformats")))
	{
		dynamic_DISPLAY_ALL_FORMATS();
		/* NOTE if we have other 'generics', like sha1, sha2, rc4, ...
		 * then EACH of them should have a DISPLAY_ALL_FORMATS()
		 * function and we can call them here. */
		exit(0);
	}

	if (!strcasecmp(options.listconf, "inc-modes"))
	{
		cfg_print_subsections("Incremental", NULL, NULL, 0);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "rules"))
	{
		cfg_print_subsections("List.Rules", NULL, NULL, 0);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "externals"))
	{
		cfg_print_subsections("List.External", NULL, NULL, 0);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "sections"))
	{
		cfg_print_section_names(0);
		exit(0);
	}
	if (!strncasecmp(options.listconf, "parameters", 10) &&
	    (options.listconf[10] == '=' || options.listconf[10] == ':') &&
	    options.listconf[11] != '\0')
	{
		cfg_print_section_params(&options.listconf[11], NULL);
		exit(0);
	}
	if (!strncasecmp(options.listconf, "list-data", 9) &&
	    (options.listconf[9] == '=' || options.listconf[9] == ':') &&
	    options.listconf[10] != '\0')
	{
		cfg_print_section_list_lines(&options.listconf[10], NULL);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "ext-filters"))
	{
		cfg_print_subsections("List.External", "filter", NULL, 0);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "ext-filters-only"))
	{
		cfg_print_subsections("List.External", "filter", "generate", 0);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "ext-modes"))
	{
		cfg_print_subsections("List.External", "generate", NULL, 0);
		exit(0);
	}

	if (!strcasecmp(options.listconf, "formats")) {
		struct fmt_main *format;
		int column = 0, dynamics = 0;
		int grp_dyna;

		grp_dyna = options.format ?
			strcmp(options.format, "dynamic") ?
			0 : strstr(options.format, "*") != 0 : 1;

		format = fmt_list;
		do {
			int length;
			char *label = format->params.label;
			if (grp_dyna && !strncmp(label, "dynamic", 7)) {
				if (dynamics++)
					continue;
				else
					label = "dynamic_n";
			}
			length = strlen(label) + 2;
			column += length;
			if (column > 78) {
				printf("\n");
				column = length;
			}
			printf("%s%s", label, format->next ? ", " : "\n");
		} while ((format = format->next));
		exit(0);
	}
	if (!strcasecmp(options.listconf, "format-details")) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ntests = 0;

			if (format->params.tests) {
				while (format->params.tests[ntests++].ciphertext);
				ntests--;
			}
			printf("%s\t%d\t%d\t%d\t%08x\t%d\t%s\t%s\t%s\t%d\t%d\t%d",
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
			       // salts are handled internally within the format. We want to know the 'real' salt size
			       // dynamic will alway set params.salt_size to 0 or sizeof a pointer.
			       dynamic_real_salt_length(format) : format->params.salt_size);
#if FMT_MAIN_VERSION > 11
			printf("\t");
			list_tunable_cost_names(format, ",");
#endif
			/* 
			 * Since the example ciphertext should be the last line in the
			 * --list=format-all-details output, it should also be the last column
			 * here.
			 * Even if this means tools processing --list=format-details output
			 * have to check the number of columns if they want to use the example 
			 * ciphertext.
			 */
			printf("\t%.256s\n",
			       /*
			        * ciphertext example will be silently truncated
			        * to 256 characters here
			        */
			       ntests ?
			       format->params.tests[0].ciphertext : "");
		} while ((format = format->next));
		exit(0);
	}
	if (!strcasecmp(options.listconf, "format-all-details")) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ntests = 0;

			if (format->params.tests) {
				while (format->params.tests[ntests++].ciphertext);
				ntests--;
			}
			/*
			 * attributes should be printed in the same sequence
			 * as with format-details, but human-readable
			 */
			printf("Format label                         %s\n", format->params.label);
			printf("Max. password length in bytes        %d\n", format->params.plaintext_length);
			printf("Min. keys per crypt                  %d\n", format->params.min_keys_per_crypt);
			printf("Max. keys per crypt                  %d\n", format->params.max_keys_per_crypt);
			printf("Flags\n");
			printf(" Case sensitive                      %s\n", (format->params.flags & FMT_CASE) ? "yes" : "no");
			printf(" Supports 8-bit characters           %s\n", (format->params.flags & FMT_8_BIT) ? "yes" : "no");
			printf(" Converts 8859-1 to UTF-16/UCS-2     %s\n", (format->params.flags & FMT_UNICODE) ? "yes" : "no");
			printf(" Honours --encoding=NAME             %s\n", (format->params.flags & FMT_UTF8) ? "yes" : "no");
			printf(" False positives possible            %s\n", (format->params.flags & FMT_NOT_EXACT) ? "yes" : "no");
			printf(" Uses a bitslice implementation      %s\n", (format->params.flags & FMT_BS) ? "yes" : "no");
			printf(" The split() method unifies case     %s\n", (format->params.flags & FMT_SPLIT_UNIFIES_CASE) ? "yes" : "no");
			printf(" A $dynamic$ format                  %s\n", (format->params.flags & FMT_DYNAMIC) ? "yes" : "no");
#ifdef _OPENMP
			printf(" Parallelized with OpenMP            %s\n", (format->params.flags & FMT_OMP) ? "yes" : "no");
			if (format->params.flags & FMT_OMP)
				printf("  Poor OpenMP scalability            %s\n", (format->params.flags & FMT_OMP_BAD) ? "yes" : "no");
#endif
			printf("Number of test vectors               %d\n", ntests);
			printf("Algorithm name                       %s\n", format->params.algorithm_name);
			printf("Format name                          %s\n", format->params.format_name);
			printf("Benchmark comment                    %s\n", format->params.benchmark_comment[0] == ' ' ? &format->params.benchmark_comment[1] : format->params.benchmark_comment);
			printf("Benchmark length                     %d\n", format->params.benchmark_length);
			printf("Binary size                          %d\n", format->params.binary_size);
			printf("Salt size                            %d\n",
			       ((format->params.flags & FMT_DYNAMIC) && format->params.salt_size) ?
			       // salts are handled internally within the format. We want to know the 'real' salt size/
			       // dynamic will alway set params.salt_size to 0 or sizeof a pointer.
			       dynamic_real_salt_length(format) : format->params.salt_size);
#if FMT_MAIN_VERSION > 11
			printf("Tunable cost parameters              ");
			list_tunable_cost_names(format, ", ");
			printf("\n");
#endif

			/*
			 * The below should probably stay as last line of
			 * output if adding more information.
			 *
			 * ciphertext example will be truncated to 512
			 * characters here, with a notice.
			 */
			if (ntests)
			printf("Example ciphertext%s  %.512s\n",
			       strlen(format->params.tests[0].ciphertext) > 512
			       ? " (truncated here)" : "                 ",
			       format->params.tests[0].ciphertext);
			printf("\n");
		} while ((format = format->next));
		exit(0);
	}
	if (!strncasecmp(options.listconf, "format-methods", 14)) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ShowIt = 1, i;
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
#if FMT_MAIN_VERSION > 11
				         strcasecmp(&options.listconf[15], "tunable_cost_value") &&
				         strcasecmp(&options.listconf[15], "tunable_cost_value[0]") &&
#if FMT_TUNABLE_COSTS > 1
				         strcasecmp(&options.listconf[15], "tunable_cost_value[1]") &&
#if FMT_TUNABLE_COSTS > 2
				         strcasecmp(&options.listconf[15], "tunable_cost_value[2]") &&
#endif
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
				         strcasecmp(&options.listconf[15], "salt_hash"))
				{
					fprintf(stderr, "Error, invalid option (invalid method name) %s\n", options.listconf);
					fprintf(stderr, "Valid method names are:\n");
					listconf_list_method_names();
					exit(1);
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

#if FMT_MAIN_VERSION > 11
				for (i = 0; i < FMT_TUNABLE_COSTS; ++i) {
					char Buf[30];
					sprintf(Buf, "tunable_cost_value[%d]", i);
					if (format->methods.tunable_cost_value[i] && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.tunable_cost_value[0] && !strcasecmp(&options.listconf[15], "tunable_cost_value"))
					ShowIt = 1;
#endif

				if (format->methods.source != fmt_default_source && !strcasecmp(&options.listconf[15], "source"))
					ShowIt = 1;
				if (format->methods.clear_keys != fmt_default_clear_keys && !strcasecmp(&options.listconf[15], "clear_keys"))
					ShowIt = 1;
				for (i = 0; i < PASSWORD_HASH_SIZES; ++i) {
					char Buf[20];
					sprintf(Buf, "get_hash[%d]", i);
					if (format->methods.get_hash[i] && format->methods.get_hash[i] != fmt_default_get_hash && !strcasecmp(&options.listconf[15], Buf))
						ShowIt = 1;
				}
				if (format->methods.get_hash[0] && format->methods.get_hash[0] != fmt_default_get_hash && !strcasecmp(&options.listconf[15], "get_hash"))
					ShowIt = 1;

				for (i = 0; i < PASSWORD_HASH_SIZES; ++i) {
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
				printf("\tvalid()\n");
				if (format->methods.split != fmt_default_split)
					printf("\tsplit()\n");
				if (format->methods.binary != fmt_default_binary)
					printf("\tbinary()\n");
				if (format->methods.salt != fmt_default_salt)
					printf("\tsalt()\n");
#if FMT_MAIN_VERSION > 11
				for (i = 0; i < FMT_TUNABLE_COSTS; ++i)
					/*
					 * Here, a NULL value serves as default,
					 * so any existing function should be printed
					 */
					if (format->methods.tunable_cost_value[i])
						printf("\t\ttunable_cost_value[%d]()\n", i);
#endif
				for (i = 0; i < PASSWORD_HASH_SIZES; ++i)
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
				for (i = 0; i < PASSWORD_HASH_SIZES; ++i)
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
	if (!strncasecmp(options.listconf, "format-tests", 12)) {
		struct fmt_main *format;
		format = fmt_list;
		do {
			int ntests = 0;

			/*
			 * fmt_init() and fmt_done() required for --encoding=
			 * support, because some formats (like Raw-MD5u)
			 * change their tests[] depending on the encoding.
			 */
			fmt_init(format);

			if (format->params.tests) {
				while (format->params.tests[ntests].ciphertext) {
					int i;
					int skip = 0;
					/*
					 * defining a config variable ot allowing --field-separator-char=
					 * with a fallback to either ':' or '\t' is probably overkill
					 */
					const char separator = '\t';
					char *ciphertext;

					ciphertext = format->params.tests[ntests].ciphertext;
					if (ciphertext[ 0] == '\0')
						ciphertext = format->methods.prepare(format->params.tests[ntests].fields,
						                                     format);
					/*
					 * one of the scrypt tests has tabs and new lines in ciphertext
					 * and password.
					 */
					for (i = 0; format->params.tests[ntests].plaintext[i]; i++)
						if (format->params.tests[ntests].plaintext[i] == '\x0a') {
							skip = 1;
							fprintf(stderr,
							        "Test %s %d: plaintext contains line feed\n",
							        format->params.label, ntests);
							break;
						}
					for (i = 0; ciphertext[i]; i++) {
						if (ciphertext[i] == '\x0a' ||
						    ciphertext[i] == separator) {
							skip = 2;
							fprintf(stderr,
							        "Test %s %d: ciphertext contains line feed or separator character '%c'\n",
							        format->params.label, ntests, separator);
							break;
						}
					}
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
					ntests++;
				}
			}
			if (!ntests)
				printf("%s lacks test vectors\n",
				       format->params.label);

			fmt_done(format);

		} while ((format = format->next));
		exit(0);
	}
	/*
	 * Other --list=help:WHAT are processed in listconf_parse_early(), but
	 * these require a valid config:
	 */
	if (!strcasecmp(options.listconf, "help:parameters"))
	{
		cfg_print_section_names(1);
		exit(0);
	}
	if (!strcasecmp(options.listconf, "help:list-data"))
	{
		cfg_print_section_names(2);
		exit(0);
	}

	/* --list last resort: list subsections of any john.conf section name */

	//printf("Subsections of [%s]:\n", options.listconf);
	if (cfg_print_subsections(options.listconf, NULL, NULL, 1))
		exit(0);
	else {
		fprintf(stderr, "Section [%s] not found.\n", options.listconf);
		/* Just in case the user specified an invalid value
		 * like help or list...
		 * print the same list as with --list=?, but exit(1)
		 */
		listconf_list_options();
		exit(1);
	}
}
