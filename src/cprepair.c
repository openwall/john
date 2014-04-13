/*
 * This software is Copyright (c) 2013-2014 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "unicode.h"

// gcc -Wall -O3 -s -DNOT_JOHN -D_JOHN_MISC_NO_LOG cprepair.c unicode.c misc.c -o ../run/cprepair

static int sup, debug, noguess, potfile;
static int inv_cp, val_cp;
struct options_main options;
struct pers_opts pers_opts;

#undef LINE_BUFFER_SIZE
#define LINE_BUFFER_SIZE 0x10000

#define valid_utf8 _validut8

static inline int valid_utf8(const UTF8 *source)
{
	UTF8 a;
	int length;
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
			case 0xE0:
				if (a < 0xA0) return 0;
				break;
			case 0xED:
				if (a > 0x9F) return 0;
				break;
			case 0xF0:
				if (a < 0x90) return 0;
				break;
			case 0xF4:
				if (a > 0x8F) return 0;
				break;
			default:
				if (a < 0x80) return 0;
			}

		case 1:
			if (*source >= 0x80 && *source < 0xC2) return 0;
		}
		if (*source > 0xF4)
			return 0;

		source += length;
	}
	return 1;
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
		if ((*source > 'a' && *source < 'z') ||
		    (*source > 'A' && *source < 'Z'))
			return 1;
	return 0;
}

static void usage(char *name, int retcode)
{
	printf("Codepage repair (c) magnum 2014\nUsage: %s [options] [file] [...]\n", name);
	puts("\nOptions:");
	puts(" -v <cp>   Codepage to use for lines that are double-encoded to UTF-8");
	puts(" -i <cp>   Codepage to use for 8-bit input");
	puts(" -n        Do not guess (leave 8-bit as-is)");
	puts(" -s        Suppress lines that does not need fixing.");
	puts(" -l        List supported encodings.");
	puts(" -d        Debug (show conversions).");
	puts(" -p        Only convert stuff after first ':' (.pot file).");
	puts("\nCode pages default to CP1252 (MS Latin-1).");
	exit(retcode);
}

static int process_file(char *name)
{
	FILE *fh;
	char orig[3 * LINE_BUFFER_SIZE + 1];

	if (!strcmp(name, "-")) {
		fh = stdin;
	} else {
		fh = fopen(name, "r");
		if (fh < 0) {
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

			if ((p = strchr(orig, '\n'))) {
				*p++ = 0;
				len = (int)(p - orig);
				if (len > 3 * LINE_BUFFER_SIZE) {
					len = 3 * LINE_BUFFER_SIZE;
					orig[len] = 0;
				}
			}
			if ((p = strchr(orig, '\r'))) {
				*p++ = 0;
				len = (int)(p - orig);
				if (len > 3 * LINE_BUFFER_SIZE) {
					len = 3 * LINE_BUFFER_SIZE;
					orig[len] = 0;
				}
			}

			plain = strchr(orig, ':');
			if (potfile && plain) {
				len -= (++plain - orig);
				convin = plain;
			} else
				convin = orig;

			//if (debug > 2) printf("Length %d ", len);

			if (!valid_utf8((UTF8*)convin)) {
				if (noguess) {
					out = convin;
					if (debug)
						printf("has %sASCII letters, enc is unknown: %s\n",
						       contains_ascii_letters(convin) ?
						       "" : "no ", convin);
				} else {
					pers_opts.input_enc =
						pers_opts.intermediate_enc =
						pers_opts.target_enc =
						inv_cp;
					initUnicode(0);

					enc_to_utf16(u16, sizeof(u16), (UTF8*)convin, len);
					out = (char*)utf16_to_utf8_r(u8buf, sizeof(u8buf), u16);
					if (debug && strcmp(convin, out)) {
						if (debug > 1)
							printf("has %sASCII letters, enc is guessed %s: ",
							       contains_ascii_letters(convin) ?
							       "" : "no ", cp_id2name(pers_opts.input_enc));
						printf("%s -> ", orig);
					}
				}
			} else {
				utf8_to_utf16(u16, sizeof(u16),
				              (UTF8*)convin, len);
				if (valid_ansi(u16)) {
					pers_opts.input_enc =
						pers_opts.intermediate_enc =
						pers_opts.target_enc =
						val_cp;
					initUnicode(0);
					u8 = utf16_to_enc_r(u8buf,
					                    sizeof(u8buf), u16);
					if (valid_utf8(u8))
						out = (char*)u8;
					else
						out = convin;
				} else
					out = convin;
				if (debug && strcmp(convin, out))
					printf("%s => ", convin);
			}
			if (!sup || strcmp(convin, out)) {
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

	while ((c = getopt(argc, argv, "si:v:hldpn")) != -1) {
		switch (c) {
		case 's':
			sup = 1;
			break;
		case 'd':
			debug++;
			break;
		case 'p':
			potfile++;
			break;
		case 'n':
			noguess = 1;
			break;
		case 'i':
			inv_cp = cp_name2id(optarg);
			break;
		case 'v':
			val_cp = cp_name2id(optarg);
			break;
		case 'l':
			puts("Supported encodings:");
			listEncodings();
			return EXIT_SUCCESS;
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

	if (!val_cp)
		val_cp = CP1252;

	if (!inv_cp)
		inv_cp = CP1252;

	if (argc == 0)
		return process_file("-");
	else
	while (*argv) {
		int ret;

		if (debug) printf("filename: %s\n", *argv);
		ret = process_file(*argv++);
		if (ret != EXIT_SUCCESS)
			return ret;
	}

	return EXIT_SUCCESS;
}
