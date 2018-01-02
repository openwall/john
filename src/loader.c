/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003,2005,2010-2012,2015 by Solar Designer
 *
 * ...with heavy changes in the jumbo patch, by magnum and various authors
 */
#if AC_BUILT
#include "autoconfig.h"
#endif

#define LDR_WARN_AMBIGUOUS

#include <stdio.h>
// needs to be above sys/stat.h for mingw, if -std=c99 used.
#include "jumbo.h"
#include <sys/stat.h>
#include "os.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#ifdef _MSC_VER
#define S_ISDIR(a) ((a) & _S_IFDIR)
#endif
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "signals.h"
#include "formats.h"
#include "dyna_salt.h"
#include "loader.h"
#include "options.h"
#include "config.h"
#include "unicode.h"
#include "dynamic.h"
#include "fake_salts.h"
#include "john.h"
#include "cracker.h"
#include "logger.h" /* Beware: log_init() happens after most functions here */
#include "base64_convert.h"
#include "md5.h"
#include "single.h"
#include "memdbg.h"

#ifdef HAVE_CRYPT
extern struct fmt_main fmt_crypt;
#endif

/*
 * If this is set, we are loading john.pot so we should
 * probably not emit warnings from valid().
 */
int ldr_in_pot = 0;

/*
 * If this is set, we are populating the test db
 */
static int ldr_loading_testdb = 0;

/*
 * this is set during salt_sort, so it knows the size
 */
static int ldr_fmt_salt_size;

/*
 * Flags for read_file().
 */
#define RF_ALLOW_MISSING		1
#define RF_ALLOW_DIR			2

/*
 * Fast "Strlen" for fields[f]
 */
#define SPLFLEN(f)	(fields[f][0] ? fields[f+1] - fields[f] - 1 : 0)

static char *no_username = "?";
#ifdef HAVE_FUZZ
int pristine_gecos;
int single_skip_login;
#else
static int pristine_gecos;
static int single_skip_login;
#endif

/*
 * There should be legislation against adding a BOM to UTF-8, not to
 * mention calling UTF-16 a "text file".
 */
static MAYBE_INLINE char *check_bom(char *string)
{
	static int warned;

	if (((unsigned char*)string)[0] < 0xef)
		return string;

	if (!memcmp(string, "\xEF\xBB\xBF", 3)) {
		if (options.input_enc == UTF_8)
			string += 3;
		else if (john_main_process && !warned++) {
			fprintf(stderr,
			        "Warning: UTF-8 BOM seen in input file - You probably want --input-encoding=UTF8\n");
		}
	}
	if (options.input_enc == UTF_8 &&
	    (!memcmp(string, "\xFE\xFF", 2) || !memcmp(string, "\xFF\xFE", 2))) {
		if (john_main_process)
			fprintf(stderr,
			        "Error: UTF-16 BOM seen in input file.\n");
		error();
	}
	return string;
}

/*
 * We have made changes so that long lines (greater than MAX_CIPHERTEXT_SIZE)
 * will now get 'trimmed' when put into the .pot file. Here is the trimming
 * method:
 *    input:    $hashtype$abcdefghijk..........qrstuvwxzy$something$else
 *    pot:      $hashtype$abcdefghijk.......$SOURCE_HASH$<md5 of full hash>
 * this way we can fully compare this .pot record (against the full input line)
 */
int ldr_pot_source_cmp(const char *pot_entry, const char *full_source) {
	MD5_CTX ctx;
	unsigned char srcH[16], potH[16];
	const char *p;

	if (!strcmp(pot_entry, full_source))
		return 0;
	p = strstr(pot_entry, "$SOURCE_HASH$");
	if (!p)
		return 1; /* can not be a match */
	if (strncmp(full_source, pot_entry, p - pot_entry))
		return 1; /* simple str compare shows they are not the same */
	/* ok, this could be a match.  Now we check the hashes */
	MD5_Init(&ctx);
	MD5_Update(&ctx, full_source, strlen(full_source));
	MD5_Final(srcH, &ctx);
	p += 13;
	base64_convert(p, e_b64_hex, 32, potH, e_b64_raw, 16, 0, 0);

	return memcmp(srcH, potH, 16);
}

/*
 * not static function.  Used by cracker.c This function builds a proper
 * source line to be written to the .pot file. This string MAY be the
 * original source line, OR it may be a chopped down (shortened) source
 * line with a hash tacked on. However, it will always be shorter or equal
 * to (LINE_BUFFER_SIZE - PLAINTEXT_BUFFER_SIZE)
 */
const char *ldr_pot_source(const char *full_source,
                           char buffer[LINE_BUFFER_SIZE + 1])
{
	MD5_CTX ctx;
	int len;
	char *p = buffer;
	unsigned char mbuf[16];

	if (strnlen(full_source, MAX_CIPHERTEXT_SIZE + 1) <= MAX_CIPHERTEXT_SIZE)
		return full_source;

	/*
	 * We create a .pot record that is MAX_CIPHERTEXT_SIZE long
	 * but that has a hash of the full source
	 */
	len = POT_BUFFER_CT_TRIM_SIZE;
	memcpy(p, full_source, len);
	p += len;
	memcpy(p, "$SOURCE_HASH$", 13);
	p += 13;
	MD5_Init(&ctx);
	MD5_Update(&ctx, full_source, strlen(full_source));
	MD5_Final(mbuf, &ctx);
	base64_convert(mbuf, e_b64_raw, 16, p, e_b64_hex, 33, 0, 0);
	p += 32;
	*p = 0;
	return buffer;
}

/* returns true or false depending if this ciphertext is a trimmed .pot line */
int ldr_isa_pot_source(const char *ciphertext) {
	if (!ldr_in_pot)
		return 0;
	return (strstr(ciphertext, "$SOURCE_HASH$") != NULL);
}

static void read_file(struct db_main *db, char *name, int flags,
	void (*process_line)(struct db_main *db, char *line))
{
	struct stat file_stat;
	FILE *file;
	char line_buf[LINE_BUFFER_SIZE], *line, *ex_size_line;
	int warn_enc;

	warn_enc = john_main_process && (options.target_enc != ASCII) &&
		cfg_get_bool(SECTION_OPTIONS, NULL, "WarnEncoding", 0);

	if (flags & RF_ALLOW_DIR) {
		if (stat(name, &file_stat)) {
			if (flags & RF_ALLOW_MISSING)
				if (errno == ENOENT) return;
			pexit("stat: %s", path_expand(name));
		} else
			if (S_ISDIR(file_stat.st_mode)) return;
	}

	if (!(file = fopen(path_expand(name), "r"))) {
		if ((flags & RF_ALLOW_MISSING) && errno == ENOENT) return;
		pexit("fopen: %s", path_expand(name));
	}

	dyna_salt_init(db->format);
	while ((ex_size_line = fgetll(line_buf, sizeof(line_buf), file))) {
		line = check_bom(ex_size_line);

		if (warn_enc) {
			char *u8check;

			if (!(flags & RF_ALLOW_MISSING) ||
			    !(u8check =
			      strchr(line, options.loader.field_sep_char)))
				u8check = line;

			if (((flags & RF_ALLOW_MISSING) &&
			     options.store_utf8) ||
			    ((flags & RF_ALLOW_DIR) &&
			     options.input_enc == UTF_8)) {
				if (!valid_utf8((UTF8*)u8check)) {
					warn_enc = 0;
					fprintf(stderr, "Warning: invalid UTF-8"
					        " seen reading %s\n", name);
				}
			} else if (options.input_enc != UTF_8 &&
			           (line != line_buf ||
			            valid_utf8((UTF8*)u8check) > 1)) {
				warn_enc = 0;
				fprintf(stderr, "Warning: UTF-8 seen reading "
				        "%s\n", name);
			}
		}
		process_line(db, line);
		if (ex_size_line != line_buf)
			MEM_FREE(ex_size_line);
		check_abort(0);
	}
	if (name == options.activepot)
		crk_pot_pos = jtr_ftell64(file);

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");
}

void ldr_init_database(struct db_main *db, struct db_options *db_options)
{
	db->loaded = 0;

	db->real = db;
	db->pw_size = sizeof(struct db_password);
	db->salt_size = sizeof(struct db_salt);
	if (!(db_options->flags & DB_WORDS)) {
		db->pw_size -= sizeof(struct list_main *);
		if (db_options->flags & DB_LOGIN) {
			if (!options.show_uid_in_cracks)
				db->pw_size -= sizeof(char *);
		} else
			db->pw_size -= sizeof(char *) * 2;
		db->salt_size -= sizeof(struct db_keys *);
	}

	db->options = mem_alloc_copy(db_options,
	    sizeof(struct db_options), MEM_ALIGN_WORD);

	if (db->options->flags & DB_WORDS)
		db->options->flags |= DB_LOGIN;

	db->salts = NULL;

	db->password_hash = NULL;
	db->password_hash_func = NULL;

	if (db_options->flags & DB_CRACKED) {
		db->salt_hash = NULL;

		db->cracked_hash = mem_calloc(
			CRACKED_HASH_SIZE, sizeof(struct db_cracked *));
	} else {
		db->salt_hash = mem_alloc(
			SALT_HASH_SIZE * sizeof(struct db_salt *));
		memset(db->salt_hash, 0,
			SALT_HASH_SIZE * sizeof(struct db_salt *));

		db->cracked_hash = NULL;
	}

	list_init(&db->plaintexts);

	db->salt_count = db->password_count = db->guess_count = 0;

	db->format = NULL;
}

/*
 * Allocate a hash table for use by the loader itself.  We use this for two
 * purposes: to detect and avoid loading of duplicate hashes when DB_WORDS is
 * not set, and to remove previously-cracked hashes (found in john.pot).  We
 * allocate, use, and free this hash table prior to deciding on the sizes of
 * and allocating the per-salt hash tables to be used while cracking.
 */
static void ldr_init_password_hash(struct db_main *db)
{
	int (*func)(void *binary);
	int size_num = PASSWORD_HASH_SIZE_FOR_LDR;
	size_t size;

	if (size_num >= 2 && mem_saving_level >= 2) {
		size_num--;
		if (mem_saving_level >= 3)
			size_num--;
	}

	do {
		func = db->format->methods.binary_hash[size_num];
		if (func && func != fmt_default_binary_hash)
			break;
	} while (--size_num >= 0);
	if (size_num < 0)
		size_num = 0;
	db->password_hash_func = func;
	size = (size_t)password_hash_sizes[size_num] *
		sizeof(struct db_password *);
	db->password_hash = mem_alloc(size);
	memset(db->password_hash, 0, size);
}

static char *ldr_get_field(char **ptr, char field_sep_char)
{
	static char *last;
	char *res, *pos;

	if (!*ptr) return last;

	if ((pos = strchr(res = *ptr, field_sep_char))) {
		*pos++ = 0; *ptr = pos;
	} else {
		pos = res;
		do {
			if (*pos == '\r' || *pos == '\n') *pos = 0;
		} while (*pos++);
		last = pos - 1;
		*ptr = NULL;
	}

	return res;
}

static int ldr_check_list(struct list_main *list, char *s1, char *s2)
{
	struct list_entry *current;
	char *data;

	if (!(current = list->head) || ldr_loading_testdb)
		return 0;

	if (*current->data == '-') {
		data = current->data + 1;
		do {
			if (!strcmp(s1, data) || !strcmp(s2, data)) return 1;
			if ((current = current->next)) data = current->data;
		} while (current);
	} else {
		do {
			data = current->data;
			if (!strcmp(s1, data) || !strcmp(s2, data)) return 0;
		} while ((current = current->next));
		return 1;
	}

	return 0;
}

static MAYBE_INLINE int ldr_check_shells(struct list_main *list, char *shell)
{
	char *name;

	if (list->head) {
		if ((name = strrchr(shell, '/'))) name++; else name = shell;
		return ldr_check_list(list, shell, name);
	}

	return 0;
}

static void ldr_set_encoding(struct fmt_main *format)
{
	if ((!options.target_enc || options.default_target_enc) &&
	    !options.internal_cp) {
		if (!strncasecmp(format->params.label, "LM", 2) ||
		    !strcasecmp(format->params.label, "netlm") ||
		    !strcasecmp(format->params.label, "nethalflm")) {
			options.target_enc =
				cp_name2id(cfg_get_param(SECTION_OPTIONS,
				                         NULL,
				                         "DefaultMSCodepage"));
			if (options.target_enc)
				options.default_target_enc = 1;
			else
				options.target_enc = options.input_enc;
		} else if (options.internal_cp &&
		           (format->params.flags & FMT_UNICODE) &&
		           (format->params.flags & FMT_UTF8)) {
			options.target_enc = options.internal_cp;
		}
	}

	/* For FMT_NOT_EXACT, --show=left should only list hashes we
	   did not find any candidate for */
	if (options.loader.showuncracked)
		format->params.flags &= ~FMT_NOT_EXACT;

	if ((options.flags & FLG_SHOW_CHK) || options.loader.showuncracked) {
		initUnicode(UNICODE_UNICODE);
		return;
	}

	/* john.conf alternative for --internal-codepage */
	if (options.flags &
	    (FLG_RULES | FLG_SINGLE_CHK | FLG_BATCH_CHK | FLG_MASK_CHK))
	if ((!options.target_enc || options.target_enc == UTF_8) &&
	    !options.internal_cp) {
		if (!(options.internal_cp =
			cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL,
			                         "DefaultInternalCodepage"))))
			options.internal_cp =
			    cp_name2id(cfg_get_param(SECTION_OPTIONS, NULL,
			                         "DefaultInternalEncoding"));
	}

	/* Performance opportunity - avoid unneccessary conversions */
	if (options.internal_cp && options.internal_cp != UTF_8 &&
	    (!options.target_enc || options.target_enc == UTF_8)) {
		if ((format->params.flags & FMT_UNICODE) &&
		    (format->params.flags & FMT_UTF8))
			options.target_enc = options.internal_cp;
	}

	initUnicode(UNICODE_UNICODE);
}

static char *escape_json(char *in)
{
	char *ret;
	size_t num = 0;
	uint8_t c;
	uint8_t *p = (uint8_t*)in;

	while ((c = *p++)) {
		if (c == '\\' || c == '"')
			num++;
		else if (c < ' ')
			num += 5;
	}
	if (!num)
		return in;

	num += (p - (uint8_t*)in);
	ret = mem_alloc_tiny(num, MEM_ALIGN_NONE);

	p = (uint8_t*)ret - 1;
	while ((*++p = *in++)) {
		if (*p == '\\')
			*++p = '\\';
		else if (*p == '"') {
			*p = '\\';
			*++p = '"';
		} else if (*p < ' ') {
			const char* const hex = "0123456789abcdef";
			uint8_t c = *p;

			*p = '\\';
			*++p = 'u';
			*++p = '0';
			*++p = '0';
			*++p = hex[ARCH_INDEX(c >> 4)];
			*++p = hex[ARCH_INDEX(c & 0xf)];
		}
	}
	return ret;
}

static int ldr_split_line(char **login, char **ciphertext,
	char **gecos, char **home, char **uid,
	char *source, struct fmt_main **format,
	struct db_options *db_opts, char *line)
{
	struct fmt_main *alt;
	char *fields[10], *gid, *shell;
	int i, retval;
	int huge_line = 0;
	static int line_no = 0;

	fields[0] = *login = ldr_get_field(&line, db_opts->field_sep_char);
	fields[1] = *ciphertext = ldr_get_field(&line, db_opts->field_sep_char);

	line_no++;

/* Check for NIS stuff */
	if (((*login)[0] == '+' && (!(*login)[1] || (*login)[1] == '@')) &&
	    (*ciphertext)[0] != '$' && strnlen(*ciphertext, 10) < 10 &&
	    strncmp(*ciphertext, "$dummy$", 7)) {
		if (db_opts->showtypes) {
			int fs = db_opts->field_sep_char;

			if (db_opts->showtypes_json) {
				printf("%s{\"lineNo\":%d,",
				       line_no == 1 ? "[" : ",\n",
				       line_no);
				if (**login)
					printf("\"login\":\"%s\",",
					       escape_json(*login));
				if (**ciphertext)
					printf("\"ciphertext\":\"%s\",",
					       escape_json(*ciphertext));
				printf("\"consistencyMark\":2}");
			} else
				printf("%s%c%s%c2%c\n",
				       *login, fs, *ciphertext, fs,/* 2, */fs);
		}
		return 0;
	}

	if (!**ciphertext && !line) {
/* Possible hash on a line on its own (no colons) */
		char *p = *login;
/* Skip leading and trailing whitespace */
		while (*p == ' ' || *p == '\t') p++;
		*ciphertext = p;
		p += strlen(p) - 1;
		while (p > *ciphertext && (*p == ' ' || *p == '\t')) p--;
		p++;
/* Some valid dummy or plaintext hashes may be shorter than 10 characters,
 * so don't subject them to the length checks. */
		if (((*ciphertext)[0] != '$' ||
		    (strncmp(*ciphertext, "$dummy$", 7) &&
		    strncmp(*ciphertext, "$0$", 3))) &&
		    p - *ciphertext != 10 /* not tripcode */) {
/* Check for a special case: possibly a traditional crypt(3) hash with
 * whitespace in its invalid salt.  Only support such hashes at the very start
 * of a line (no leading whitespace other than the invalid salt). */
			if (p - *ciphertext == 11 && *ciphertext - *login == 2)
				(*ciphertext)--;
			if (p - *ciphertext == 12 && *ciphertext - *login == 1)
				(*ciphertext)--;
			if (p - *ciphertext < 13) {
				if (db_opts->showtypes) {
					int fs = db_opts->field_sep_char;

					if (db_opts->showtypes_json) {
						printf("%s{\"lineNo\":%d,",
						       line_no == 1 ? "[" : ",\n",
						       line_no);
						if (**ciphertext)
							printf("\"ciphertext\":\"%s\",",
							       escape_json(*ciphertext));
						printf("\"consistencyMark\":3}");
					} else
						printf("%c%s%c3%c\n",
						       /* empty, */
						       fs, *ciphertext,
						       fs, /* 3, */
						       fs);
				}
				return 0;
			}
		}
		*p = 0;
		fields[0] = *login = no_username;
		fields[1] = *ciphertext;
		if (strnlen(*ciphertext, LINE_BUFFER_SIZE + 1) >
		    LINE_BUFFER_SIZE) {
			huge_line = 1;
		}
	}

	if (source)
		strcpy(source, line ? line : "");

/*
 * This check is just a loader performance optimization, so that we can parse
 * fewer fields when we know we won't need the rest.  It should be revised or
 * removed when there are formats that use higher-numbered fields in prepare().
 */
	if ((db_opts->flags & DB_WORDS) || db_opts->shells->head) {
		/* Parse all fields */
		for (i = 2; i < 10; i++)
			fields[i] = ldr_get_field(&line,
			                          db_opts->field_sep_char);
	} else {
		/* Parse some fields only */
		for (i = 2; i < 4; i++)
			fields[i] = ldr_get_field(&line,
			                          db_opts->field_sep_char);
		// Next line needed for l0phtcrack (in Jumbo)
		for (; i < 6; i++)
			fields[i] = ldr_get_field(&line,
			                          db_opts->field_sep_char);
		for (; i < 10; i++)
			fields[i] = "/";
	}

	/* /etc/passwd */
	*uid = fields[2];
	*gecos = fields[4];
	*home = fields[5];

	if (fields[0] == no_username && !db_opts->showtypes)
		goto find_format;

	gid = fields[3];
	shell = fields[6];

	if (SPLFLEN(1) > LINE_BUFFER_SIZE) {
		huge_line = 1;
	}
	else if (SPLFLEN(2) == 32 || SPLFLEN(3) == 32) {
		/* PWDUMP */
		/* user:uid:LMhash:NThash:comment:homedir: */
		*uid = fields[1];
		*ciphertext = fields[2];
		if (!strncmp(*ciphertext, "NO PASSWORD", 11))
			*ciphertext = "";
		gid = shell = "";
		*gecos = fields[4];
		*home = fields[5];

		/* Re-introduce the previously removed uid field */
		if (source) {
			int shift = strlen(*uid);
			memmove(source + shift + 1, source, strlen(source) + 1);
			memcpy(source, *uid, shift);
			source[shift] = db_opts->field_sep_char;
		}
	}
	else if (SPLFLEN(1) == 0 && SPLFLEN(3) >= 16 && SPLFLEN(4) >= 32 &&
	         SPLFLEN(5) >= 16) {
		/* l0phtcrack-style input
		   user:::lm response:ntlm response:challenge
		   user::domain:srvr challenge:ntlmv2 response:client challenge
		 */
		*uid = gid = *home = shell = "";
		*gecos = fields[2]; // in case there's a domain name here
	}
	else if (fields[5][0] != '/' &&
	    ((!strcmp(fields[5], "0") && !strcmp(fields[6], "0")) ||
	    fields[8][0] == '/' ||
	    fields[9][0] == '/')) {
		/* /etc/master.passwd */
		*gecos = fields[7];
		*home = fields[8];
		shell = fields[9];
	}

	if (ldr_check_list(db_opts->users, *login, *uid)) return 0;
	if (ldr_check_list(db_opts->groups, gid, gid)) return 0;
	if (ldr_check_shells(db_opts->shells, shell)) return 0;

	if (db_opts->showtypes) {
		int fs = db_opts->field_sep_char;
		/* Flag: the format is not the first valid format. The
		 * first format should not print the first field
		 * separator. */
		int not_first_format = 0;
		/* \0 and \n are not possible in any field. */
		/* field_sep_char should not be possible in any field too.
		 * But it is possible with --field-separator-char=/ due to
		 * default value "/" for home field. Also ? may come from
		 * empty login. */
		/* Flag: no fields contain \n or field separator. */
		int bad_char = 0;
#ifndef DYNAMIC_DISABLED
		int bare_always_valid = 0;
		if ((options.dynamic_bare_hashes_always_valid == 'Y')
		    || (options.dynamic_bare_hashes_always_valid != 'N'
			&& cfg_get_bool(SECTION_OPTIONS, NULL, "DynamicAlwaysUseBareHashes", 1)))
			bare_always_valid = 1;
#endif
		/* We output 1 or 0, so 0 and 1 are bad field separators. */
		if (fs == '0' || fs == '1')
			bad_char = 1;
#define check_field_separator(str) bad_char |= strchr((str), fs) || strchr((str), '\n')
		/* To suppress warnings, particularly from
		 * generic crypt's valid() (c3_fmt.c). */
		ldr_in_pot = 1;
		/* The format:
		 * Once for each hash even if it can't be loaded (7 fields):
		 *   login,
		 *   ciphertext,
		 *   uid,
		 *   gid,
		 *   gecos,
		 *   home,
		 *   shell.
		 * For each valid format (may be nothing):
		 *   label,
		 *   is format disabled? (1/0),
		 *   is format dynamic? (1/0),
		 *   does format use the ciphertext field as is? (1/0),
		 *   canonical hash or hashes (if there are several parts).
		 * All fields above are separated by field_sep_char.
		 * Formats are separated by empty field.
		 * Additionally on the end:
		 *   separator,
		 *   line consistency mark (0/1/2/3):
		 *     0 - the line is consistent and can be parsed easily,
		 *     1 - field separator char occurs in fields, line can't
		 *         be parsed easily,
		 *     2 - the line was skipped as bad NIS stuff, only login
		 *         and ciphertext are shown,
		 *     3 - the line was skipped parsing descrypt with
		 *         invalid salt, only ciphertext is shown (together
		 *         with empty login); empty lines fall here,
		 *   separator.
		 * The additional field_sep_char at the end of line does not
		 * break numeration of fields but allows parser to get
		 * field_sep_char from the line.
		 * A parser have to check the last 3 chars.
		 * If the format does not use the ciphertext field as is,
		 * then a parser have to match input line with output line
		 * by number of line.
		 */
		if (db_opts->showtypes_json) {
			printf("%s{\"lineNo\":%d,",
			       line_no == 1 ? "[" : ",\n",
			       line_no);
			if (strcmp(*login, "?"))
				printf("\"login\":\"%s\",",
				       escape_json(*login));
			if (**ciphertext)
				printf("\"ciphertext\":\"%s\",",
				       escape_json(*ciphertext));
			if (**uid)
				printf("\"uid\":\"%s\",",
				       escape_json(*uid));
			if (*gid)
				printf("\"gid\":\"%s\",",
				       escape_json(gid));
			if (**gecos && strcmp(*gecos, "/"))
				printf("\"gecos\":\"%s\",",
				       escape_json(*gecos));
			if (**home && strcmp(*home, "/"))
				printf("\"home\":\"%s\",",
				       escape_json(*home));
			if (*shell && strcmp(shell, "/"))
				printf("\"shell\":\"%s\",",
				       escape_json(shell));
			printf("\"rowFormats\":[");
		} else
			printf("%s%c%s%c%s%c%s%c%s%c%s%c%s",
			       *login,
			       fs, *ciphertext,
			       fs, *uid,
			       fs, gid,
			       fs, *gecos,
			       fs, *home,
			       fs, shell);

		check_field_separator(*login);
		check_field_separator(*ciphertext);
		check_field_separator(*uid);
		check_field_separator(gid);
		check_field_separator(*gecos);
		check_field_separator(*home);
		check_field_separator(shell);
		/* Fields above may be empty. */
		/* Empty fields are separators after this point. */
		alt = fmt_list;
		do {
			char *prepared;
			int disabled = 0;
			int prepared_eq_ciphertext;
			int valid;
			int part;
			int is_dynamic = ((alt->params.flags & FMT_DYNAMIC) == FMT_DYNAMIC);

			if (huge_line && !(alt->params.flags & FMT_HUGE_INPUT))
				continue;
/* We enforce DynamicAlwaysUseBareHashes for each format. By default
 * dynamics do that only if a bare hash occurs on the first line. */
#ifndef DYNAMIC_DISABLED
			if (bare_always_valid)
				dynamic_allow_rawhash_fixup = 1;
#endif
			prepared = alt->methods.prepare(fields, alt);
			if (!prepared)
				continue;
			prepared_eq_ciphertext = (*ciphertext == prepared || !strcmp(*ciphertext, prepared));
			valid = alt->methods.valid(prepared, alt);
			if (!valid)
				continue;
			ldr_set_encoding(alt);
			/* Empty field between valid formats */
			if (not_first_format) {
				if (db_opts->showtypes_json)
					printf(",{");
				else
					printf("%c", fs);
			} else if (db_opts->showtypes_json)
				printf("{");
			not_first_format = 1;
			if (db_opts->showtypes_json) {
				printf("\"label\":\"%s\",",
				       alt->params.label);
				if (disabled)
					printf("\"disabled\":true,");
				if (is_dynamic)
					printf("\"dynamic\":true,");
				if (prepared_eq_ciphertext)
					printf("\"prepareEqCiphertext\":true,");
				printf("\"canonHash\":[");
			} else
				printf("%c%s%c%d%c%d%c%d",
				       fs, alt->params.label,
				       fs, disabled,
				       fs, is_dynamic,
				       fs, prepared_eq_ciphertext);
			check_field_separator(alt->params.label);
			/* Canonical hash or hashes (like halves of LM) */
			for (part = 0; part < valid; part++) {
				char *split = alt->methods.split(prepared, part, alt);

				if (db_opts->showtypes_json)
					printf("%s\"%s\"",
					       part ? "," : "",
					       escape_json(split));
				else
					printf("%c%s", fs, split);
				check_field_separator(split);
			}
			if (db_opts->showtypes_json)
				printf("]}");
		} while ((alt = alt->next));
		if (db_opts->showtypes_json) {
			if (bad_char)
				printf("],\"consistencyMark\":%d}", bad_char);
			else
				printf("]}");
		} else
			printf("%c%d%c\n", fs, bad_char, fs);
		return 0;
#undef check_field_separator
	}

find_format:
	if (*format) {
		char *prepared;
		int valid;

		if (huge_line && !((*format)->params.flags & FMT_HUGE_INPUT))
			prepared = NULL;
		else
			prepared = (*format)->methods.prepare(fields, *format);
		if (prepared)
			valid = (*format)->methods.valid(prepared, *format);
		else
			valid = 0;

		if (valid) {
			*ciphertext = prepared;
#ifdef HAVE_FUZZ
			if (options.flags & FLG_FUZZ_CHK) {
				ldr_set_encoding(*format);
				fmt_init(*format);
			}
#endif
			return valid;
		}

#ifdef HAVE_FUZZ
		if (options.flags & FLG_FUZZ_CHK)
			return valid;
#endif

		ldr_set_encoding(*format);

		alt = fmt_list;
		do {
			if (huge_line &&
			    !(alt->params.flags & FMT_HUGE_INPUT))
				continue;

			if (alt == *format)
				continue;
			if (alt->params.flags & FMT_WARNED)
				continue;
#ifdef HAVE_CRYPT
#if 1 /* Jumbo has "all" crypt(3) formats implemented */
			if (alt == &fmt_crypt)
				continue;
#else
			if (alt == &fmt_crypt &&
#ifdef __sun
			    strncmp(*ciphertext, "$md5$", 5) &&
			    strncmp(*ciphertext, "$md5,", 5) &&
#endif
			    strncmp(*ciphertext, "$5$", 3) &&
			    strncmp(*ciphertext, "$6$", 3))
				continue;
#endif
#endif
			prepared = alt->methods.prepare(fields, alt);
			if (alt->methods.valid(prepared, alt)) {
				alt->params.flags |= FMT_WARNED;
				if (john_main_process)
				fprintf(stderr,
				    "Warning: only loading hashes of type "
				    "\"%s\", but also saw type \"%s\"\n"
				    "Use the \"--format=%s\" option to force "
				    "loading hashes of that type instead\n",
				    (*format)->params.label,
				    alt->params.label,
				    alt->params.label);
				break;
			}
		} while ((alt = alt->next));

		return 0;
	}

	retval = -1;
	if ((alt = fmt_list))
	do {
		char *prepared;
		int valid;

		if (huge_line && !(alt->params.flags & FMT_HUGE_INPUT))
			continue;
#ifdef HAVE_CRYPT
/*
 * Only probe for support by the current system's crypt(3) if this is forced
 * from the command-line or/and if the hash encoding string looks like one of
 * those that are only supported in that way.  Avoid the probe in other cases
 * because it may be slow and undesirable (false detection is possible).
 */
#if 1 /* Jumbo has "all" crypt(3) formats implemented */
		if (alt == &fmt_crypt && fmt_list != &fmt_crypt)
			continue;
#else
		if (alt == &fmt_crypt &&
		    fmt_list != &fmt_crypt /* not forced */ &&
#ifdef __sun
		    strncmp(*ciphertext, "$md5$", 5) &&
		    strncmp(*ciphertext, "$md5,", 5) &&
#endif
		    strncmp(*ciphertext, "$5$", 3) &&
		    strncmp(*ciphertext, "$6$", 3))
			continue;
#endif
#endif

		prepared = alt->methods.prepare(fields, alt);
		if (!prepared)
			continue;
		valid = alt->methods.valid(prepared, alt);
		if (!valid)
			continue;

		if (retval < 0) {
			retval = valid;
			*ciphertext = prepared;
			ldr_set_encoding(alt);
#ifdef HAVE_OPENCL
			if (options.acc_devices->count && options.fork &&
			    strstr(alt->params.label, "-opencl"))
				*format = alt;
			else
#endif
			fmt_init(*format = alt);
#ifdef LDR_WARN_AMBIGUOUS
			if (!source) /* not --show */
				continue;
#endif
			break;
		}
#ifdef LDR_WARN_AMBIGUOUS
		if (john_main_process)
		fprintf(stderr,
		    "Warning: detected hash type \"%s\", but the string is "
		    "also recognized as \"%s\"\n"
		    "Use the \"--format=%s\" option to force loading these "
		    "as that type instead\n",
		    (*format)->params.label, alt->params.label,
		    alt->params.label);
#endif
	} while ((alt = alt->next));

	return retval;
}

static char* ldr_conv(char *word)
{
	if (options.input_enc == UTF_8 && options.internal_cp != UTF_8) {
		static char u8[PLAINTEXT_BUFFER_SIZE + 1];

		word = utf8_to_cp_r(word, u8, PLAINTEXT_BUFFER_SIZE);
	}
	return word;
}

static void ldr_split_string(struct list_main *dst, char *src)
{
	char *word, *pos;
	char c;

	pos = src;
	do {
		word = pos;
		while (*word && CP_isSeparator[ARCH_INDEX(*word)]) word++;
		if (!*word) break;

		pos = word;
		while (!CP_isSeparator[ARCH_INDEX(*pos)]) pos++;
		c = *pos;
		*pos = 0;
		list_add_global_unique(dst, single_seed, word);
		*pos++ = c;
	} while (c && dst->count < LDR_WORDS_MAX);
}

static struct list_main *ldr_init_words(char *login, char *gecos, char *home)
{
	struct list_main *words;
	char *pos;

	list_init(&words);

	if (*login && login != no_username && !single_skip_login)
		list_add(words, ldr_conv(login));
	ldr_split_string(words, ldr_conv(gecos));
	if (login != no_username && !single_skip_login)
		ldr_split_string(words, ldr_conv(login));
	if (pristine_gecos && *gecos)
		list_add_global_unique(words, single_seed, ldr_conv(gecos));
	if ((pos = strrchr(home, '/')) && pos[1])
		list_add_global_unique(words, single_seed, ldr_conv(&pos[1]));

	list_add_list(words, single_seed);

	return words;
}

#ifdef HAVE_FUZZ
void ldr_load_pw_line(struct db_main *db, char *line)
#else
static void ldr_load_pw_line(struct db_main *db, char *line)
#endif
{
	static int skip_dupe_checking = 0;
	struct fmt_main *format;
	int index, count;
	char *login, *ciphertext, *gecos, *home, *uid;
	char *piece;
	void *binary, *salt;
	int salt_hash, pw_hash;
	struct db_salt *current_salt, *last_salt;
	struct db_password *current_pw, *last_pw;
	struct list_main *words;
	size_t pw_size;
	int i;

#ifdef HAVE_FUZZ
	char *line_sb;

	line_sb = line;
	if (options.flags & FLG_FUZZ_CHK)
		line_sb = check_bom(line);
	count = ldr_split_line(&login, &ciphertext, &gecos, &home, &uid,
		NULL, &db->format, db->options, line_sb);
#else
	count = ldr_split_line(&login, &ciphertext, &gecos, &home, &uid,
		NULL, &db->format, db->options, line);
#endif
	if (count <= 0) return;
	if (count >= 2) db->options->flags |= DB_SPLIT;

	format = db->format;
	dyna_salt_init(format);

	words = NULL;

	if (!db->password_hash) {
		ldr_init_password_hash(db);
		if (cfg_get_bool(SECTION_OPTIONS, NULL,
		                 "NoLoaderDupeCheck", 0)) {
			skip_dupe_checking = 1;
			if (john_main_process)
				fprintf(stderr, "No dupe-checking performed "
				        "when loading hashes.\n");
		}
	}

	for (index = 0; index < count; index++) {
		piece = format->methods.split(ciphertext, index, format);

		binary = format->methods.binary(piece);
		pw_hash = db->password_hash_func(binary);

		if (options.flags & FLG_REJECT_PRINTABLE) {
			int i = 0;

			while (isprint((int)((unsigned char*)binary)[i]) &&
			       i < format->params.binary_size)
				i++;

			if (i == format->params.binary_size) {
				if (john_main_process)
				fprintf(stderr, "rejecting printable binary"
				        " \"%.*s\" (%s)\n",
				        format->params.binary_size,
				        (char*)binary, piece);
				continue;
			}
		}

		if (!(db->options->flags & DB_WORDS) && !skip_dupe_checking) {
			int collisions = 0;
			if ((current_pw = db->password_hash[pw_hash]))
			do {
				if (!memcmp(binary, current_pw->binary,
				    format->params.binary_size) &&
				    !strcmp(piece, format->methods.source(
				    current_pw->source, current_pw->binary))) {
					db->options->flags |= DB_NODUP;
					break;
				}
				if (++collisions <= LDR_HASH_COLLISIONS_MAX)
					continue;

				if (john_main_process) {
					if (format->params.binary_size)
					fprintf(stderr, "Warning: "
					    "excessive partial hash "
					    "collisions detected\n%s",
					    db->password_hash_func !=
					    fmt_default_binary_hash ? "" :
					    "(cause: the \"format\" lacks "
					    "proper binary_hash() function "
					    "definitions)\n");
					else
					fprintf(stderr, "Warning: "
					    "check for duplicates partially "
					    "bypassed to speedup loading\n");
				}
				skip_dupe_checking = 1;
				current_pw = NULL; /* no match */
				break;
			} while ((current_pw = current_pw->next_hash));

			if (current_pw) continue;
		}

		salt = format->methods.salt(piece);
		dyna_salt_create(salt);
		salt_hash = format->methods.salt_hash(salt);

		if ((current_salt = db->salt_hash[salt_hash])) {
			do {
				if (!dyna_salt_cmp(current_salt->salt, salt, format->params.salt_size))
					break;
			}  while ((current_salt = current_salt->next));
		}

		if (!current_salt) {
			last_salt = db->salt_hash[salt_hash];
			current_salt = db->salt_hash[salt_hash] =
				mem_alloc_tiny(db->salt_size, MEM_ALIGN_WORD);
			current_salt->next = last_salt;

			current_salt->salt = mem_alloc_copy(salt,
				format->params.salt_size,
				format->params.salt_align);

			for (i = 0; i < FMT_TUNABLE_COSTS && format->methods.tunable_cost_value[i] != NULL; ++i)
				current_salt->cost[i] = format->methods.tunable_cost_value[i](current_salt->salt);

			current_salt->index = fmt_dummy_hash;
			current_salt->bitmap = NULL;
			current_salt->list = NULL;
			current_salt->hash = &current_salt->list;
			current_salt->hash_size = -1;

			current_salt->count = 0;

			if (db->options->flags & DB_WORDS)
				current_salt->keys = NULL;

			db->salt_count++;
		} else
			dyna_salt_remove(salt);

		current_salt->count++;
		db->password_count++;

/* If we're not allocating memory for the "login" field, we may as well not
 * allocate it for the "source" field if the format doesn't need it. */
		pw_size = db->pw_size;
		if (!(db->options->flags & DB_LOGIN) &&
		    format->methods.source != fmt_default_source)
			pw_size -= sizeof(char *);

		last_pw = current_salt->list;
		current_pw = current_salt->list = mem_alloc_tiny(
			pw_size, MEM_ALIGN_WORD);
		current_pw->next = last_pw;

		last_pw = db->password_hash[pw_hash];
		db->password_hash[pw_hash] = current_pw;
		current_pw->next_hash = last_pw;

/* If we're not going to use the source field for its usual purpose yet we had
 * to allocate memory for it (because we need at least one field after it), see
 * if we can pack the binary value in it. */
		if ((db->options->flags & DB_LOGIN) &&
		    format->methods.source != fmt_default_source &&
		    sizeof(current_pw->source) >= format->params.binary_size)
			current_pw->binary = memcpy(&current_pw->source,
				binary, format->params.binary_size);
		else
			current_pw->binary = mem_alloc_copy(binary,
				format->params.binary_size,
				format->params.binary_align);

		if (format->methods.source == fmt_default_source)
			current_pw->source = str_alloc_copy(piece);

		if (db->options->flags & DB_WORDS) {
			if (!words)
				words = ldr_init_words(login, gecos, home);
			current_pw->words = words;
		}

		if (db->options->flags & DB_LOGIN) {
			if (login != no_username && index == 0)
				login = ldr_conv(login);

			if (options.show_uid_in_cracks)
				current_pw->uid = str_alloc_copy(uid);

			if (count >= 2 && count <= 9) {
				current_pw->login = mem_alloc_tiny(
					strlen(login) + 3, MEM_ALIGN_NONE);
				sprintf(current_pw->login, "%s:%d",
					login, index + 1);
			} else
			if (login == no_username)
				current_pw->login = login;
			else
			if (words && *login)
				current_pw->login = words->head->data;
			else
				current_pw->login = str_alloc_copy(login);
		}
	}
}

void ldr_load_pw_file(struct db_main *db, char *name)
{
	static int init;

	if (!init) {
		struct cfg_list *conf_seeds;

		list_init(&single_seed);

		if (options.seed_word)
			ldr_split_string(single_seed,
			                 ldr_conv(options.seed_word));

		if (options.seed_file) {
			FILE *file;
			char *name = path_expand(options.seed_file);
			char line[LINE_BUFFER_SIZE];

			if (!(file = fopen(name, "r")))
				pexit("fopen: %s", name);
			while (fgetl(line, sizeof(line), file))
				list_add_unique(single_seed, ldr_conv(line));
			if (fclose(file))
				pexit("fclose");
		}

		if ((conf_seeds = cfg_get_list("List.Single:", "SeedWords"))) {
			struct cfg_line *word;

			if ((word = conf_seeds->head))
			do {
				list_add_unique(single_seed,
				                ldr_conv(word->data));
			} while ((word = word->next));
		}

		pristine_gecos = cfg_get_bool(SECTION_OPTIONS, NULL,
		                              "PristineGecos", 0);
		single_skip_login = cfg_get_bool(SECTION_OPTIONS, NULL,
		                                 "SingleSkipLogin", 0);
		init = 1;
	}

	read_file(db, name, RF_ALLOW_DIR, ldr_load_pw_line);
}

int ldr_trunc_valid(char *ciphertext, struct fmt_main *format)
{
	int i;

	if (!ldr_in_pot || !format->params.signature[0] ||
	    !strstr(ciphertext, "$SOURCE_HASH$"))
		goto plain_valid;

	for (i = 0; i < FMT_SIGNATURES && format->params.signature[i]; ++i) {
		if (!strncmp(ciphertext, format->params.signature[i],
		    strlen(format->params.signature[i])) &&
		    strnlen(ciphertext, MAX_CIPHERTEXT_SIZE + 1) <=
		    MAX_CIPHERTEXT_SIZE &&
		    ldr_isa_pot_source(ciphertext))
			return 1;
	}

plain_valid:
	return format->methods.valid(ciphertext, format);
}

static void ldr_load_pot_line(struct db_main *db, char *line)
{
	struct fmt_main *format = db->format;
	char *ciphertext;
	void *binary;
	int hash;
	int need_removal;
	struct db_password *current;

	ciphertext = ldr_get_field(&line, db->options->field_sep_char);
	if (ldr_trunc_valid(ciphertext, format) != 1) return;
	ciphertext = format->methods.split(ciphertext, 0, format);
	binary = format->methods.binary(ciphertext);
	hash = db->password_hash_func(binary);
	need_removal = 0;

	if ((current = db->password_hash[hash]))
	do {
		if (options.regen_lost_salts)
			ldr_pot_possible_fixup_salt(current->source,
			                            ciphertext);
		if (!current->binary) /* already marked for removal */
			continue;
		/*
		 * If hash is zero, this may be a $SOURCE_HASH$ line that we
		 * can't treat with memcmp().
		 */
		if (hash || !ldr_isa_pot_source(ciphertext))
		if (memcmp(binary, current->binary, format->params.binary_size))
			continue;
		if (ldr_pot_source_cmp(ciphertext,
		    format->methods.source(current->source, current->binary)))
			continue;
		current->binary = NULL; /* mark for removal */
		need_removal = 1;
	} while ((current = current->next_hash));

	if (need_removal)
		db->options->flags |= DB_NEED_REMOVAL;
}

struct db_main *ldr_init_test_db(struct fmt_main *format, struct db_main *real)
{
	struct fmt_main *real_list = fmt_list;
	struct fmt_main fake_list;
	struct db_main *testdb;
	struct fmt_tests *current;
	extern volatile int bench_running;

	if (!(current = format->params.tests))
		return NULL;

	memcpy(&fake_list, format, sizeof(struct fmt_main));
	fake_list.next = NULL;
	fmt_list = &fake_list;

	testdb = mem_alloc(sizeof(struct db_main));

	fmt_init(format);
	dyna_salt_init(format);
	ldr_init_database(testdb, &options.loader);
	testdb->options->field_sep_char = ':';
	testdb->real = real;
	testdb->format = format;
	ldr_init_password_hash(testdb);

	ldr_loading_testdb = 1;
	bench_running++;
	while (current->ciphertext) {
		char *ex_len_line = NULL;
		char _line[LINE_BUFFER_SIZE], *line = _line;
		int i, pos = 0;

		/*
		 * FIXME: Change the "200" and "300" to something less arbitrary
		 * or document why they are used.
		 */
		if (strnlen(current->ciphertext, LINE_BUFFER_SIZE) >
		    LINE_BUFFER_SIZE - 200) {
			ex_len_line =
				mem_alloc(strlen(current->ciphertext) + 300);
			line = ex_len_line;
		}
		if (!current->fields[0])
			current->fields[0] = "?";
		if (!current->fields[1])
			current->fields[1] = current->ciphertext;
		for (i = 0; i < 10; i++)
			if (current->fields[i])
				pos += sprintf(&line[pos], "%s%c",
				               current->fields[i],
				               testdb->options->field_sep_char);

		ldr_load_pw_line(testdb, line);
		current++;
		MEM_FREE(ex_len_line);
	}
	bench_running--;

	ldr_fix_database(testdb);
	ldr_loading_testdb = 0;

	if (options.verbosity == VERB_MAX && john_main_process)
		fprintf(stderr,
		        "Loaded %d hashes with %d different salts to test db from test vectors\n",
		        testdb->password_count, testdb->salt_count);

	fmt_list = real_list;
	return testdb;
}

void ldr_free_test_db(struct db_main *db)
{
	if (db) {
		if (db->format &&
		    (db->format->params.flags & FMT_DYNA_SALT) == FMT_DYNA_SALT)
		{
			struct db_salt *psalt = db->salts;
			while (psalt) {
				dyna_salt_remove(psalt->salt);
				psalt = psalt->next;
			}
		}
		MEM_FREE(db->salt_hash);
		MEM_FREE(db->cracked_hash);
		MEM_FREE(db);
	}
}

void ldr_load_pot_file(struct db_main *db, char *name)
{
	if (db->format && !(db->format->params.flags & FMT_NOT_EXACT)) {
		ldr_in_pot = 1;
		read_file(db, name, RF_ALLOW_MISSING, ldr_load_pot_line);
		ldr_in_pot = 0;
	}
}

/*
 * The following are several functions called by ldr_fix_database().
 * They assume that the per-salt hash tables have not yet been initialized.
 */

/*
 * Glue the salt_hash[] buckets together and into the salts list.  The loader
 * needs the hash table, but then we free it and the cracker uses the list.
 */
static void ldr_init_salts(struct db_main *db)
{
	struct db_salt **tail, *current;
	int hash, ctr = 0;

	for (hash = 0, tail = &db->salts; hash < SALT_HASH_SIZE; hash++)
	if ((current = db->salt_hash[hash])) {
		*tail = current;
		ctr = 0;
		do {
			ctr++;
			tail = &current->next;
		} while ((current = current->next));
#ifdef DEBUG_HASH
		if (ctr)
			printf("salt hash %08x, %d salts\n", hash, ctr);
#endif
	}
}

/* Compute sequential_id. */
static void ldr_init_sqid(struct db_main *db)
{
	struct db_salt *current;
	int ctr = 0;

	if ((current = db->salts))
	do {
		current->sequential_id = ctr++;
	} while ((current = current->next));
}

/* #define DEBUG_SALT_SORT */

/*
 * This was done as a structure to allow more data to be
 * placed into it, beyond just the simple pointer. The
 * pointer is really all that is needed.  However, when
 * building with the structure containing just a pointer,
 * we get no (or very little) degredation over just an
 * array of pointers.  The compiler treats them the same.
 * so for ease of debugging, I have left this as a simple
 * structure
 */
typedef struct salt_cmp_s
{
	struct db_salt *p;
#ifdef DEBUG_SALT_SORT
	/* used by JimF in debugging.  Left in for now */
	int org_idx;
	char str[36];
#endif
} salt_cmp_t;

/*
 * there is no way to pass this pointer to the sort function, so
 * we set it before calling sort.
 */
static int (*fmt_salt_compare)(const void *x, const void *y);

/*
 * This helper function will stay in loader.  It is what the qsort
 * function calls.  This function is smart enough to know how to
 * parse a salt_cmp_t. It does that, to find the real salt values,
 * and then calls the formats salt_compare passing in just the salts.
 * It is an extra layer of indirection, but keeps the function from
 * having to know about our structure, or the db_salt structure. There
 * is very little additional overhead, in this 2nd layer of indirection
 * since qsort is pretty quick, and does not call compare any more than
 * is needed to partition sort the data.
 */
static int ldr_salt_cmp(const void *x, const void *y) {
	salt_cmp_t *X = (salt_cmp_t *)x;
	salt_cmp_t *Y = (salt_cmp_t *)y;
	int cmp = fmt_salt_compare(X->p->salt, Y->p->salt);
	return cmp;
}

static int ldr_salt_cmp_num(const void *x, const void *y) {
	salt_cmp_t *X = (salt_cmp_t *)x;
	salt_cmp_t *Y = (salt_cmp_t *)y;
	int cmp = dyna_salt_cmp(X->p->salt, Y->p->salt, ldr_fmt_salt_size);
	return cmp;
}

static void ldr_gen_salt_md5(struct db_salt *s, int dynamic) {
	if (dynamic) {
		dynamic_salt_md5(s);
		return;
	}
	dyna_salt_md5(s, ldr_fmt_salt_size);
}
/*
 * If there are more than 1 salt AND the format exports a salt_compare
 * function, then we reorder the salt array into the order the format
 * wants them in.  The rationale is usually that the format can
 * gain speed if some of the salts are grouped together.  This was first
 * done for the WPAPSK format so that the format could group all ESSID's
 * in the salts. So the PBKDF2 is computed once (for the first instance
 * of the ESSID), then all of the other salts which are different but
 * have the same ESSID will not have to perform the very costly PBKDF2.
 * The format is designed to work that way, IF the salts come to it in
 * the right order.
 *
 * Later, a bug was found in dynamic (hopefully not in other formats)
 * where formats like md5(md5($p).$s) would fail if there were salts of
 * varying length within the same input file. The longer salts would
 * leave stale data. If we sort the salts based on salt string length,
 * this issue goes away with no performance overhead.  So this function
 * is now also used for dynamic.
 *
 * we sort salts always, so that they are put into a deterministic order.
 * That way, we can restore a session and skip ahead until we find the
 * last salt being worked on. Without a deterministic sort, that logic
 * would fail under many situations.
 *
 */
static void ldr_sort_salts(struct db_main *db)
{
	int i;
	struct db_salt *s;
#ifndef DEBUG_SALT_SORT
	salt_cmp_t *ar;
#else
	salt_cmp_t ar[100];  /* array is easier to debug in VC */
#endif
	if (db->salt_count < 2)
		return;

	log_event("Sorting salts, for performance");

	fmt_salt_compare = db->format->methods.salt_compare;
#ifndef DEBUG_SALT_SORT
	ar = (salt_cmp_t *)mem_alloc(sizeof(salt_cmp_t)*db->salt_count);
#endif
	s = db->salts;

	/* load our array of pointers. */
	for (i = 0; i < db->salt_count; ++i) {
		ar[i].p = s;
#ifdef DEBUG_SALT_SORT
		ar[i].org_idx = i;
		strncpy(ar[i].str, (char*)s->salt, 36);
		ar[i].str[35] = 0; /*just in case*/
#endif
		s = s->next;
	}

	ldr_fmt_salt_size = db->format->params.salt_size;

	dyna_salt_init(db->format);
	if (fmt_salt_compare)
		qsort(ar, db->salt_count, sizeof(ar[0]), ldr_salt_cmp);
	else /* Most used salt first */
		qsort(ar, db->salt_count, sizeof(ar[0]), ldr_salt_cmp_num);

	/* Reset salt hash table, if we still have one */
	if (db->salt_hash) {
		memset(db->salt_hash, 0,
		       SALT_HASH_SIZE * sizeof(struct db_salt *));
	}

	/* finally, we re-build the linked list of salts */
	db->salts = ar[0].p;
	s = db->salts;
	ldr_gen_salt_md5(s, (db->format->params.flags & FMT_DYNAMIC) == FMT_DYNAMIC);
	for (i = 1; i <= db->salt_count; ++i) {
		/* Rebuild salt hash table, if we still had one */
		if (db->salt_hash) {
			int hash;

			hash = db->format->methods.salt_hash(s->salt);
			if (!db->salt_hash[hash])
				db->salt_hash[hash] = s;
		}
		if (i < db->salt_count) {
			s->next = ar[i].p;
			s = s->next;
			ldr_gen_salt_md5(s, (db->format->params.flags & FMT_DYNAMIC) == FMT_DYNAMIC);
		}
	}
	s->next = 0;

#ifndef DEBUG_SALT_SORT
	MEM_FREE(ar);
#else
	/* setting s here, allows me to debug quick-watch s=s->next
	 * over and over again while watching the char* value of s->salt
	 */
	s = db->salts;
#endif
}

/*
 * Emit the output for --show=left.
 */
static void ldr_show_left(struct db_main *db, struct db_password *pw)
{
	char uid_sep[2] = { 0 };
	char *uid_out = "";
	char *pw_source = db->format->methods.source(pw->source, pw->binary);
	char *login = (db->options->flags & DB_LOGIN) ? pw->login : "?";

#ifndef DYNAMIC_DISABLED
	/* Note for salted dynamic, we 'may' need to fix up the salts to
	 * make them properly usable. */
	if (!strncmp(pw_source, "$dynamic_", 9))
		pw_source = dynamic_FIX_SALT_TO_HEX(pw_source);
#endif
	if (options.show_uid_in_cracks && pw->uid && *pw->uid) {
		uid_sep[0] = db->options->field_sep_char;
		uid_out = pw->uid;
	}
	if (options.target_enc != UTF_8 && options.report_utf8)
	{
		char utf8login[PLAINTEXT_BUFFER_SIZE + 1];

		cp_to_utf8_r(login, utf8login,
		             PLAINTEXT_BUFFER_SIZE);
		printf("%s%c%s%s%s\n", utf8login, db->options->field_sep_char,
		       pw_source, uid_sep, uid_out);
	} else
		printf("%s%c%s%s%s\n", login, db->options->field_sep_char,
		       pw_source, uid_sep, uid_out);
}

/*
 * Remove the previously-cracked hashes marked with "binary = NULL" by
 * ldr_load_pot_line().
 */
static void ldr_remove_marked(struct db_main *db)
{
	struct db_salt *current_salt, *last_salt;
	struct db_password *current_pw, *last_pw;

	if (!options.loader.showuncracked &&
	    !(db->options->flags & DB_NEED_REMOVAL))
		return;

	last_salt = NULL;
	if ((current_salt = db->salts))
	do {
		last_pw = NULL;
		if ((current_pw = current_salt->list))
		do {
			if (!current_pw->binary) {
				db->password_count--;
				current_salt->count--;

				if (last_pw)
					last_pw->next = current_pw->next;
				else
					current_salt->list = current_pw->next;
			} else {
				last_pw = current_pw;
				if (options.loader.showuncracked)
					ldr_show_left(db, current_pw);
			}
		} while ((current_pw = current_pw->next));

		if (!current_salt->list) {
			db->salt_count--;
			dyna_salt_remove(current_salt->salt);
			if (last_salt)
				last_salt->next = current_salt->next;
			else
				db->salts = current_salt->next;
		} else
			last_salt = current_salt;
	} while ((current_salt = current_salt->next));

	db->options->flags &= ~DB_NEED_REMOVAL;
}

/*
 * Remove salts with too few or too many password hashes.
 */
static void ldr_filter_salts(struct db_main *db)
{
	struct db_salt *current, *last;
	int min = db->options->min_pps;
	int max = db->options->max_pps;

	if (!max) {
		if (!min) return;
		max = ~(unsigned int)0 >> 1;
	}

	last = NULL;
	if ((current = db->salts))
	do {
		if (current->count < min || current->count > max) {
			dyna_salt_remove(current->salt);
			if (last)
				last->next = current->next;
			else
				db->salts = current->next;

			db->salt_count--;
			db->password_count -= current->count;
		} else
			last = current;
	} while ((current = current->next));
}

/*
 * check if cost values for a particular salt match
 * what has been requested with the --costs= option
 */
static int ldr_cost_ok(struct db_salt *salt, unsigned int *min_cost, unsigned int *max_cost)
{
	int i;

	for (i = 0; i < FMT_TUNABLE_COSTS; i++) {
		if (salt->cost[i] < min_cost[i] || salt->cost[i] > max_cost[i])
			return 0;
	}
	return 1;
}


/*
 * Remove salts with too low or too high value for a particular tunable cost
 */
static void ldr_filter_costs(struct db_main *db)
{
	struct db_salt *current, *last;

	last = NULL;
	if ((current = db->salts))
	do {
		if (!ldr_cost_ok(current, db->options->min_cost,
		                          db->options->max_cost)) {
			dyna_salt_remove(current->salt);
			if (last)
				last->next = current->next;
			else
				db->salts = current->next;
			db->salt_count--;
			db->password_count -= current->count;
		} else
			last = current;
	} while ((current = current->next));
}

/*
 * Allocate memory for and initialize the hash table for this salt if needed.
 * Also initialize salt->count (the number of password hashes for this salt).
 */
static void ldr_init_hash_for_salt(struct db_main *db, struct db_salt *salt)
{
	struct db_password *current;
	int (*hash_func)(void *binary);
	size_t bitmap_size, hash_size;
	int hash;

	if (salt->hash_size < 0) {
		salt->count = 0;
		if ((current = salt->list))
		do {
			current->next_hash = NULL; /* unused */
			salt->count++;
		} while ((current = current->next));

		return;
	}

	bitmap_size = password_hash_sizes[salt->hash_size];
	{
		size_t size = (bitmap_size +
		    sizeof(*salt->bitmap) * 8 - 1) /
		    (sizeof(*salt->bitmap) * 8) * sizeof(*salt->bitmap);
		salt->bitmap = mem_alloc_tiny(size, sizeof(*salt->bitmap));
		memset(salt->bitmap, 0, size);
	}

	hash_size = bitmap_size >> PASSWORD_HASH_SHR;
	if (hash_size > 1) {
		size_t size = hash_size * sizeof(struct db_password *);
		salt->hash = mem_alloc_tiny(size, MEM_ALIGN_WORD);
		memset(salt->hash, 0, size);
	}

	salt->index = db->format->methods.get_hash[salt->hash_size];

	hash_func = db->format->methods.binary_hash[salt->hash_size];

	salt->count = 0;
	if ((current = salt->list))
	do {
		hash = hash_func(current->binary);
		salt->bitmap[hash / (sizeof(*salt->bitmap) * 8)] |=
		    1U << (hash % (sizeof(*salt->bitmap) * 8));
		if (hash_size > 1) {
			hash >>= PASSWORD_HASH_SHR;
			current->next_hash = salt->hash[hash];
			salt->hash[hash] = current;
		} else
			current->next_hash = current->next;
		salt->count++;
	} while ((current = current->next));
}

/*
 * Decide on whether to use a hash table and on its size for each salt, call
 * ldr_init_hash_for_salt() to allocate and initialize the hash tables.
 */
static void ldr_init_hash(struct db_main *db)
{
	struct db_salt *current;
	int threshold, size;

	threshold = password_hash_thresholds[0];
	if (db->format && (db->format->params.flags & FMT_BS)) {
/*
 * Estimate the complexity of DES_bs_get_hash() for each computed hash (but
 * comparing it against less than 1 loaded hash on average due to the use of a
 * hash table) vs. the complexity of DES_bs_cmp_all() for all computed hashes
 * at once (but calling it for each loaded hash individually).
 */
		threshold = 5 * ARCH_BITS / ARCH_BITS_LOG + 1;
	}

	if ((current = db->salts))
	do {
		size = -1;
		if (current->count >= threshold && mem_saving_level < 3)
			for (size = PASSWORD_HASH_SIZES - 1; size >= 0; size--)
				if (current->count >=
				    password_hash_thresholds[size] &&
				    db->format->methods.binary_hash[size] &&
				    db->format->methods.binary_hash[size] !=
				    fmt_default_binary_hash)
					break;

		if (mem_saving_level >= 2)
			size--;

		current->hash_size = size;
		ldr_init_hash_for_salt(db, current);
#ifdef DEBUG_HASH
		if (current->hash_size > 0)
			printf("salt %08x, binary hash size 0x%x (%d), "
			       "num ciphertexts %d\n",
			       *(unsigned int*)current->salt,
			       password_hash_sizes[current->hash_size],
			       current->hash_size, current->count);
		else
			printf("salt %08x, no binary hash, "
			       "num ciphertexts %d\n",
			       *(unsigned int*)current->salt, current->count);
#endif
	} while ((current = current->next));
}

/*
 * compute cost ranges after all unneeded salts have been removed
 */
static void ldr_cost_ranges(struct db_main *db)
{
	int i;
	struct db_salt *current;

	for (i = 0; i < FMT_TUNABLE_COSTS; ++i) {
		db->min_cost[i] = UINT_MAX;
		db->max_cost[i] = 0;
	}

	if ((current = db->salts))
	do {
		for (i = 0; i < FMT_TUNABLE_COSTS && db->format->methods.tunable_cost_value[i] != NULL; ++i) {
			if (current->cost[i] < db->min_cost[i])
				db->min_cost[i] = current->cost[i];
			if (current->cost[i] > db->max_cost[i])
				db->max_cost[i] = current->cost[i];
		}
	} while ((current = current->next));
}

void ldr_fix_database(struct db_main *db)
{
	int total = db->password_count;

	ldr_init_salts(db);
	MEM_FREE(db->password_hash);
	if (!db->format ||
	    db->format->methods.salt_hash == fmt_default_salt_hash ||
	    mem_saving_level >= 2) /* Otherwise kept for faster pot sync */
		MEM_FREE(db->salt_hash);

	if (!ldr_loading_testdb) {
		ldr_filter_salts(db);
		ldr_filter_costs(db);
		ldr_remove_marked(db);
	}
	ldr_cost_ranges(db);
	ldr_sort_salts(db);
	ldr_init_hash(db);

	ldr_init_sqid(db);

	db->loaded = 1;

	if (options.loader.showuncracked) {
		total -= db->password_count;
		if (john_main_process)
			fprintf(stderr, "%s%d password hash%s cracked,"
			        " %d left\n", total ? "\n" : "", total,
			        total != 1 ? "es" : "", db->password_count);
		MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
		exit(0);
	}
}

static int ldr_cracked_hash(char *ciphertext)
{
	unsigned int hash, extra;
	unsigned char *p = (unsigned char *)ciphertext;
	unsigned char tmp[POT_BUFFER_CT_TRIM_SIZE + 1];
	int len;

	/* these checks handle .pot chopped plaintext */
	len = strnlen(ciphertext, MAX_CIPHERTEXT_SIZE);
	if (len >= MAX_CIPHERTEXT_SIZE || strstr(ciphertext, "$SOURCE_HASH$")) {
		memcpy(tmp, ciphertext, POT_BUFFER_CT_TRIM_SIZE);
		tmp[POT_BUFFER_CT_TRIM_SIZE] = 0;
		p = tmp;
	}

	hash = p[0] | 0x20; /* ASCII case insensitive */
	if (!hash)
		goto out;
	extra = p[1] | 0x20;
	if (!extra)
#if CRACKED_HASH_SIZE >= 0x100
		goto out;
#else
		goto out_and;
#endif

	p += 2;
	while (*p) {
		hash <<= 1; extra <<= 1;
		hash += p[0] | 0x20;
		if (!p[1]) break;
		extra += p[1] | 0x20;
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> CRACKED_HASH_LOG;
			extra ^= extra >> (CRACKED_HASH_LOG - 1);
			hash &= CRACKED_HASH_SIZE - 1;
		}
	}

	hash -= extra;
	hash ^= extra << (CRACKED_HASH_LOG / 2);

	hash ^= hash >> CRACKED_HASH_LOG;

#if CRACKED_HASH_LOG <= 15
	hash ^= hash >> (2 * CRACKED_HASH_LOG);
#endif
#if CRACKED_HASH_LOG <= 10
	hash ^= hash >> (3 * CRACKED_HASH_LOG);
#endif

#if CRACKED_HASH_SIZE < 0x100
out_and:
#endif
	hash &= CRACKED_HASH_SIZE - 1;

out:
	return hash;
}

static void ldr_show_pot_line(struct db_main *db, char *line)
{
	char *ciphertext, *pos;
	int hash;
	struct db_cracked *current, *last;

	ciphertext = ldr_get_field(&line, db->options->field_sep_char);

	if (line) {
		pos = line;
		do {
			if (*pos == '\r' || *pos == '\n') *pos = 0;
		} while (*pos++);

		if (db->options->flags & DB_PLAINTEXTS) {
			list_add(db->plaintexts, line);
			return;
		}
/*
 * Jumbo-specific; split() needed for legacy pot entries so we need to
 * enumerate formats and call valid(). This also takes care of the situation
 * where a specific format was requested.
 */
		if (!(options.flags & FLG_MAKECHR_CHK)) {
			struct fmt_main *format = fmt_list;

			do {
				if (ldr_trunc_valid(ciphertext, format) == 1)
					break;
			} while((format = format->next));

			if (!format)
				return;

			ciphertext =
				format->methods.split(ciphertext, 0, format);
		}
		hash = ldr_cracked_hash(ciphertext);

		last = db->cracked_hash[hash];
		current = db->cracked_hash[hash] =
			mem_alloc_tiny(sizeof(struct db_cracked),
			MEM_ALIGN_WORD);
		current->next = last;

		current->ciphertext = str_alloc_copy(ciphertext);
		current->plaintext = str_alloc_copy(line);
	}
}

void ldr_show_pot_file(struct db_main *db, char *name)
{
	ldr_in_pot = 1;
	read_file(db, name, RF_ALLOW_MISSING, ldr_show_pot_line);
	ldr_in_pot = 0;
}

static void ldr_show_pw_line(struct db_main *db, char *line)
{
	int show, loop;
	char *source = NULL;
	char *orig_line = NULL;
	struct fmt_main *format;
	char *(*split)(char *ciphertext, int index, struct fmt_main *self);
	int index, count, unify;
	char *login, *ciphertext, *gecos, *home, *uid;
	char *piece;
	int pass, found, chars;
	int hash;
	struct db_cracked *current;
	char *utf8login = NULL;
	char joined[PLAINTEXT_BUFFER_SIZE + 1] = "";
	size_t line_size = strlen(line) + 1;

	source = mem_alloc(line_size);
	orig_line = mem_alloc(line_size);

	if (db->options->showinvalid)
		strnzcpy(orig_line, line, line_size);
	format = NULL;
	count = ldr_split_line(&login, &ciphertext, &gecos, &home, &uid,
		source, &format, db->options, line);
	if (!count) goto free_and_return;

/* If we are just showing the invalid, then simply run that logic */
	if (db->options->showinvalid) {
		if (count == -1) {
			db->password_count++;
			printf("%s\n", orig_line);
		} else
			db->guess_count += count;
		goto free_and_return;
	}

/* If just one format was forced on the command line, insist on it */
	if (!fmt_list->next && !format) goto free_and_return;

/* DB_PLAINTEXTS is set when we --make-charset rather than --show */
	show = !(db->options->flags & DB_PLAINTEXTS);

	if ((loop = (options.flags & FLG_LOOPBACK_CHK) ? 1 : 0))
		show = 0;

	if (format) {
		split = format->methods.split;
		unify = format->params.flags & FMT_SPLIT_UNIFIES_CASE;
		if (format->params.flags & FMT_UNICODE) {
			static int setting = -1;
			if (setting < 0)
				setting = cfg_get_bool(SECTION_OPTIONS, NULL,
				    "UnicodeStoreUTF8", 0);
			options.store_utf8 = setting;
		} else {
			static int setting = -1;
			if (setting < 0)
				setting = options.target_enc != ASCII &&
				    cfg_get_bool(SECTION_OPTIONS, NULL,
				    "CPstoreUTF8", 0);
			options.store_utf8 = setting;
		}
	} else {
		split = fmt_default_split;
		count = 1;
		unify = 0;
	}

	if (options.target_enc != UTF_8 &&
	    !options.store_utf8 && options.report_utf8) {
		size_t login_size = strlen(login) + 1;
		char *utf8source;

		utf8login = mem_alloc(4 * login_size);
		utf8source = mem_alloc(line_size + 3 * login_size);
		login = cp_to_utf8_r(login, utf8login, 4 * login_size);
		line_size += 3 * login_size;
		source = mem_realloc(source, line_size);
		cp_to_utf8_r(source, utf8source, line_size);
		strnzcpy(source, utf8source, line_size);
		MEM_FREE(utf8source);
	}

	if (!*ciphertext) {
		found = 1;
		if (show) printf("%s%cNO PASSWORD",
		                 login, db->options->field_sep_char);

		db->guess_count++;
	} else
	for (found = pass = 0; pass == 0 || (pass == 1 && found); pass++)
	for (index = 0; index < count; index++) {
		piece = split(ciphertext, index, format);
		if (unify)
			piece = strcpy(mem_alloc(strlen(piece) + 1), piece);

		hash = ldr_cracked_hash(piece);

		if ((current = db->cracked_hash[hash]))
		do {
			char *pot = current->ciphertext;

			if (!ldr_pot_source_cmp(pot, piece))
				break;
/* This extra check, along with ldr_cracked_hash() being case-insensitive,
 * is only needed for matching some pot file records produced by older
 * versions of John and contributed patches where split() didn't unify the
 * case of hex-encoded hashes. */
			if (unify &&
			    format->methods.valid(pot, format) == 1 &&
			    !strcmp(split(pot, 0, format), piece))
				break;
		} while ((current = current->next));

		if (unify)
			MEM_FREE(piece);

		if (pass) {
			chars = 0;
			if (show || loop) {
				if (format)
					chars = format->params.plaintext_length;
				if (index < count - 1 && current &&
				    (options.store_utf8 ?
				     (int)strlen8((UTF8*)current->plaintext) :
				     (int)strlen(current->plaintext)) != chars)
					current = NULL;
			}

			if (current) {
				if (show) {
					printf("%s", current->plaintext);
				} else if (loop) {
					strcat(joined, current->plaintext);
				} else
					list_add(db->plaintexts,
						current->plaintext);

				db->guess_count++;
			} else
			if (!loop)
			while (chars--)
				putchar('?');
		} else
		if (current) {
			found = 1;
			if (show) printf("%s%c", login,
			                 db->options->field_sep_char);
			break;
		}
	}

	if (found && show) {
		if (source[0])
			printf("%c%s", db->options->field_sep_char, source);
		putchar('\n');
	}
	else if (*joined && found && loop) {
		char *plain = enc_strlwr(ldr_conv(joined));

		/* list_add_unique is O(n^2) */
		if (db->plaintexts->count < 0x10000)
			list_add_unique(db->plaintexts, plain);
		else if (strcmp(db->plaintexts->tail->data, plain))
			list_add(db->plaintexts, plain);
	}
	if (format || found) db->password_count += count;

free_and_return:
	MEM_FREE(source);
	MEM_FREE(orig_line);
	MEM_FREE(utf8login);
}

void ldr_show_pw_file(struct db_main *db, char *name)
{
	read_file(db, name, RF_ALLOW_DIR, ldr_show_pw_line);
}
