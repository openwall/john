/*
 * This software is Copyright (c) 2013-2014 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#ifdef AC_BUILT
#include "autoconfig.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "params.h"
#include "unicode.h"
#include "memdbg.h"

// gcc -Wall -O3 -s -DNOT_JOHN -D_JOHN_MISC_NO_LOG cprepair.c unicode.c misc.c -o ../run/cprepair

static int sup, noguess, potfile;
static int inv_cp, auto_cp;
struct options_main options;

#undef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 0x10000

void dump_stuff_msg(const void *msg, void *x, unsigned int size)
{
	unsigned int i;

	printf("%s : ", (char *)msg);
	for (i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i]);
		if ( (i%4)==3 )
		printf(" ");
	}
	printf("\n");
}

/* There should be legislation against adding a BOM to UTF-8 */
inline static char *skip_bom(char *string)
{
	if (!memcmp(string, "\xEF\xBB\xBF", 3))
		string += 3;
	return string;
}

inline static int valid_ansi(const UTF16 *source)
{
	while (*source)
		if (*source++ & 0xff00)
			return 0;
	return 1;
}

inline static int contains_ascii_letters(const char *s)
{
	const UTF8 *source = (UTF8*)s;

	source--;
	while (*++source)
		if ((*source >= 'a' && *source <= 'z') ||
		    (*source >= 'A' && *source <= 'Z'))
			return 1;
	return 0;
}

static void usage(char *name, int retcode)
{
	printf("Codepage repair (c) magnum 2014\nUsage: %s [options] [file] [...]\n", name);
	puts("\nOptions:");
	puts(" -i <cp>   Codepage to use for 8-bit input");
	puts(" -f <cp>   Alternate codepage when no ASCII letters (a-z, A-Z) seen");
	puts(" -n        Do not guess (leave 8-bit as-is)");
	puts(" -s        Suppress lines that does not need fixing.");
	puts(" -l        List supported encodings.");
	puts(" -d        Debug (show conversions).");
	puts(" -p        Only convert stuff after first ':' (.pot file).");
	puts("\nCode pages default to CP1252 (MS Latin-1).");
	puts("Double-conversions are handled automatically.");
	puts("UTF-8 BOMs are stripped with no mercy. They should never be used, ever.");
	exit(retcode);
}

static int process_file(char *name)
{
	FILE *fh;
	char orig[3 * LINE_BUFFER_SIZE + 1];

	if (!strcmp(name, "-")) {
		fh = stdin;
	} else {
		if (!(fh = fopen(name, "r"))) {
			perror("fopen");
			exit(0);
		}
	}

	while (!feof(fh)) {
		if (fgets(orig, sizeof(orig) - 1, fh)) {
			int len = -1;
			UTF16 u16[LINE_BUFFER_SIZE + 1];
			UTF8 u8buf[3 * LINE_BUFFER_SIZE + 1], *u8;
			char *out, *p, *plain, *convin;
			int valid;

			if ((p = strchr(orig, '\r'))) {
				*p++ = 0;
				len = (int)(p - orig);
				if (len > 3 * LINE_BUFFER_SIZE) {
					len = 3 * LINE_BUFFER_SIZE;
					orig[len] = 0;
				}
			} else
			if ((p = strchr(orig, '\n'))) {
				*p++ = 0;
				len = (int)(p - orig - 1);
				if (len > 3 * LINE_BUFFER_SIZE) {
					len = 3 * LINE_BUFFER_SIZE;
					orig[len] = 0;
				}
			}

			if (options.verbosity == VERB_MAX)
				dump_stuff_msg(orig, orig, len);

			plain = strchr(orig, ':');
			if (potfile && plain) {
				len -= (++plain - orig);
				convin = plain;
				if (options.verbosity == VERB_MAX)
					dump_stuff_msg(convin, convin, len);
			} else
				convin = skip_bom(orig);

			out = convin;
			valid = valid_utf8((UTF8*)convin);

			if (!valid) {
				if (noguess) {
					out = convin;
				} else {
					if (auto_cp != inv_cp)
						options.internal_cp =
							options.target_enc =
							contains_ascii_letters(convin) ?
							inv_cp : auto_cp;
					else
						options.internal_cp =
							options.target_enc =
							inv_cp;
					initUnicode(0);

					enc_to_utf16(u16, sizeof(u16), (UTF8*)convin, len);
					out = (char*)utf16_to_utf8_r(u8buf, sizeof(u8buf), u16);
					if (options.verbosity > VERB_DEFAULT &&
					    strcmp(convin, out))
						printf("%s -> ", orig);
				}
			} else if (valid > 1) {
				char dd[3 * LINE_BUFFER_SIZE + 1];

				/* Unroll any number of double-conversions */
				strcpy (dd, convin);
				while (*convin) {
					out = dd;
					utf8_to_utf16(u16, sizeof(u16),
					              (UTF8*)dd, len);
					if (!valid_ansi(u16))
						break;
					options.internal_cp =
						options.target_enc =
						ISO_8859_1;
					initUnicode(0);
					u8 = utf16_to_enc_r(u8buf,
						sizeof(u8buf), u16);
					if (!strcmp((char*)u8, dd) ||
					    !valid_utf8(u8))
						break;
					strcpy(dd, (char*)u8);
					if (options.verbosity == VERB_MAX)
						fprintf(stderr, "Double-encoding\n");
				}

				if (options.verbosity > VERB_DEFAULT &&
				    strcmp(convin, out))
					printf("%s => ", convin);
			}

			if (!sup || (strcmp(convin, out))) {
				if (potfile && plain > orig) {
					*--plain = 0;
					printf("%s:%s\n", orig, out);
				} else
					puts(out);
			}
		}
	}
	fclose(fh);

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	signed char c;

	options.verbosity = VERB_DEFAULT;

	while ((c = getopt(argc, argv, "si:f:hldpn")) != -1) {
		switch (c) {
		case 's':
			sup = 1;
			break;
		case 'd':
			options.verbosity++;
			break;
		case 'p':
			potfile++;
			break;
		case 'n':
			noguess = 1;
			break;
		case 'f':
			auto_cp = cp_name2id(optarg);
			break;
		case 'i':
			inv_cp = cp_name2id(optarg);
			break;
		case 'l':
			puts("Supported encodings:");
			listEncodings(stdout);
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			usage(argv[0], EXIT_SUCCESS);
			break;
		default:
			usage(argv[0], EXIT_FAILURE);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	options.input_enc = UTF_8;

	if (!auto_cp)
		auto_cp = CP1252;

	if (!inv_cp)
		inv_cp = CP1252;

	if (argc == 0)
		return process_file("-");
	else
	while (*argv) {
		int ret;

		if (options.verbosity > VERB_DEFAULT)
			printf("filename: %s\n", *argv);
		ret = process_file(*argv++);
		if (ret != EXIT_SUCCESS)
			return ret;
	}

	return EXIT_SUCCESS;
}
