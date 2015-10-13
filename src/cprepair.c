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

#include "unicode.h"
#include "memdbg.h"

// gcc -Wall -O3 -s -DNOT_JOHN -D_JOHN_MISC_NO_LOG cprepair.c unicode.c misc.c -o ../run/cprepair

static int sup, noguess, potfile;
static int inv_cp, auto_cp;
struct options_main options;
struct pers_opts pers_opts;

#undef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 0x10000

void dump_stuff_msg(const void *msg, void *x, unsigned int size)
{
	unsigned int i;

	printf("%s : ", (char *)msg);
	for(i=0;i<size;i++)
	{
		printf("%.2x", ((unsigned char*)x)[i]);
		if( (i%4)==3 )
		printf(" ");
	}
	printf("\n");
}

/* There should be legislation against adding a BOM to UTF-8 */
static inline char *skip_bom(char *string)
{
	if (!memcmp(string, "\xEF\xBB\xBF", 3))
		string += 3;
	return string;
}

/*
 * Check if a string is valid UTF-8.  Returns true if the string is valid
 * UTF-8 encoding, including pure 7-bit data or an empty string.
 *
 * The probability of a random string of bytes which is not pure ASCII being
 * valid UTF-8 is 3.9% for a two-byte sequence, and decreases exponentially
 * for longer sequences.  ISO/IEC 8859-1 is even less likely to be
 * mis-recognized as UTF-8:  The only non-ASCII characters in it would have
 * to be in sequences starting with either an accented letter or the
 * multiplication symbol and ending with a symbol.
 *
 * returns 0 if data is not valid UTF-8
 * returns 1 if data is pure ASCII (which is obviously valid)
 * returns >1 if data is valid and in fact contains UTF-8 sequences
 *
 * Actually in the last case, the return is the number of proper UTF-8
 * sequences, so it can be used as a quality measure. A low number might be
 * a false positive, a high number most probably isn't.
 */
#define valid_utf8 _validut8
static inline int valid_utf8(const UTF8 *source)
{
	UTF8 a;
	int length, ret = 1;
	const UTF8 *srcptr;

	while (*source) {
		if (*source < 0x80) {
			source++;
			continue;
		}

		length = opt_trailingBytesUTF8[*source & 0x3f] + 1;
		srcptr = source + length;

		switch (length) {
		default:
			return 0;
			/* Everything else falls through when valid */
		case 4:
			if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return 0;
		case 3:
			if ((a = (*--srcptr)) < 0x80 || a > 0xBF) return 0;
		case 2:
			if ((a = (*--srcptr)) > 0xBF) return 0;

			switch (*source) {
				/* no fall-through in this inner switch */
			case 0xE0: if (a < 0xA0) return 0; break;
			case 0xED: if (a > 0x9F) return 0; break;
			case 0xF0: if (a < 0x90) return 0; break;
			case 0xF4: if (a > 0x8F) return 0; break;
			default:   if (a < 0x80) return 0;
			}

		case 1:
			if (*source >= 0x80 && *source < 0xC2) return 0;
		}
		if (*source > 0xF4)
			return 0;

		source += length;
		ret++;
	}
	return ret;
}

static inline int valid_ansi(const UTF16 *source)
{
	while (*source)
		if (*source++ & 0xff00)
			return 0;
	return 1;
}

static inline int contains_ascii_letters(const char *s)
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

			if (options.verbosity > 4)
				dump_stuff_msg(orig, orig, len);

			plain = strchr(orig, ':');
			if (potfile && plain) {
				len -= (++plain - orig);
				convin = plain;
				if (options.verbosity > 4)
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
						pers_opts.internal_cp =
							pers_opts.target_enc =
							contains_ascii_letters(convin) ?
							inv_cp : auto_cp;
					else
						pers_opts.internal_cp =
							pers_opts.target_enc =
							inv_cp;
					initUnicode(0);

					enc_to_utf16(u16, sizeof(u16), (UTF8*)convin, len);
					out = (char*)utf16_to_utf8_r(u8buf, sizeof(u8buf), u16);
					if (options.verbosity > 3 && strcmp(convin, out))
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
					pers_opts.internal_cp =
						pers_opts.target_enc =
						ISO_8859_1;
					initUnicode(0);
					u8 = utf16_to_enc_r(u8buf,
						sizeof(u8buf), u16);
					if (!strcmp((char*)u8, dd) ||
					    !valid_utf8(u8))
						break;
					strcpy(dd, (char*)u8);
					if (options.verbosity > 4)
						fprintf(stderr, "Double-encoding\n");
				}

				if (options.verbosity > 3 &&
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
	char c;

	options.verbosity = 3;

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

	pers_opts.input_enc = UTF_8;

	if (!auto_cp)
		auto_cp = CP1252;

	if (!inv_cp)
		inv_cp = CP1252;

	if (argc == 0)
		return process_file("-");
	else
	while (*argv) {
		int ret;

		if (options.verbosity > 3)
			printf("filename: %s\n", *argv);
		ret = process_file(*argv++);
		if (ret != EXIT_SUCCESS)
			return ret;
	}

	return EXIT_SUCCESS;
}
