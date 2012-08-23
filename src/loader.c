/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003,2005,2010-2012 by Solar Designer
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "signals.h"
#include "formats.h"
#include "loader.h"

#ifdef HAVE_CRYPT
extern struct fmt_main fmt_crypt;
int ldr_in_pot = 0;
#endif

/*
 * Flags for read_file().
 */
#define RF_ALLOW_MISSING		1
#define RF_ALLOW_DIR			2

/*
 * Word separator characters for ldr_split_words(), used on GECOS fields.
 */
#define issep \
	"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\177"

static char issep_map[0x100];
static int issep_initialized = 0;

static char *no_username = "?";

static void read_file(struct db_main *db, char *name, int flags,
	void (*process_line)(struct db_main *db, char *line))
{
	struct stat file_stat;
	FILE *file;
	char line[LINE_BUFFER_SIZE];

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

	while (fgets(line, sizeof(line), file)) {
		process_line(db, line);
		check_abort(0);
	}

	if (ferror(file)) pexit("fgets");

	if (fclose(file)) pexit("fclose");
}

static void ldr_init_issep(void)
{
	char *pos;

	if (issep_initialized) return;

	memset(issep_map, 0, sizeof(issep_map));

	memset(issep_map, 1, 33);
	for (pos = issep; *pos; pos++)
		issep_map[ARCH_INDEX(*pos)] = 1;

	issep_initialized = 1;
}

void ldr_init_database(struct db_main *db, struct db_options *options)
{
	db->loaded = 0;

	db->options = mem_alloc_copy(options,
	    sizeof(struct db_options), MEM_ALIGN_WORD);

	db->salts = NULL;

	db->password_hash = NULL;
	db->password_hash_func = NULL;

	if (options->flags & DB_CRACKED) {
		db->salt_hash = NULL;

		db->cracked_hash = mem_alloc(
			CRACKED_HASH_SIZE * sizeof(struct db_cracked *));
		memset(db->cracked_hash, 0,
			CRACKED_HASH_SIZE * sizeof(struct db_cracked *));
	} else {
		db->salt_hash = mem_alloc(
			SALT_HASH_SIZE * sizeof(struct db_salt *));
		memset(db->salt_hash, 0,
			SALT_HASH_SIZE * sizeof(struct db_salt *));

		db->cracked_hash = NULL;

		if (options->flags & DB_WORDS) {
			options->flags |= DB_LOGIN;

			ldr_init_issep();
		}
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
	int size = PASSWORD_HASH_SIZE_FOR_LDR;

	if (size > 0 && mem_saving_level >= 2)
		size--;

	do {
		func = db->format->methods.binary_hash[size];
		if (func && func != fmt_default_binary_hash)
			break;
	} while (--size >= 0);
	if (size < 0)
		size = 0;
	db->password_hash_func = func;
	size = password_hash_sizes[size] * sizeof(struct db_password *);
	db->password_hash = mem_alloc(size);
	memset(db->password_hash, 0, size);
}

static char *ldr_get_field(char **ptr)
{
	char *res, *pos;

	if (!*ptr) return "";

	if ((pos = strchr(res = *ptr, ':'))) {
		*pos++ = 0; *ptr = pos;
	} else {
		pos = res;
		do {
			if (*pos == '\r' || *pos == '\n') *pos = 0;
		} while (*pos++);
		*ptr = NULL;
	}

	return res;
}

static int ldr_check_list(struct list_main *list, char *s1, char *s2)
{
	struct list_entry *current;
	char *data;

	if (!(current = list->head)) return 0;

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

static int ldr_check_shells(struct list_main *list, char *shell)
{
	char *name;

	if (list->head) {
		if ((name = strrchr(shell, '/'))) name++; else name = shell;
		return ldr_check_list(list, shell, name);
	}

	return 0;
}

static int ldr_split_line(char **login, char **ciphertext,
	char **gecos, char **home,
	char *source, struct fmt_main **format,
	struct db_options *options, char *line)
{
	struct fmt_main *alt;
	char *fields[10], *uid, *gid, *shell;
	int i, retval;

	fields[0] = *login = ldr_get_field(&line);
	fields[1] = *ciphertext = ldr_get_field(&line);

/* Check for NIS stuff */
	if ((!strcmp(*login, "+") || !strncmp(*login, "+@", 2)) &&
	    strlen(*ciphertext) < 10 && strncmp(*ciphertext, "$dummy$", 7))
		return 0;

	if (!**ciphertext && !line) {
/* Possible hash on a line on its own (no colons) */
		char *p = *login;
/* Skip leading and trailing whitespace */
		while (*p == ' ' || *p == '\t') p++;
		*ciphertext = p;
		p += strlen(p) - 1;
		while (p > *ciphertext && (*p == ' ' || *p == '\t')) p--;
		p++;
/* Some valid dummy hashes may be shorter than 10 characters, so don't subject
 * them to the length checks. */
		if (strncmp(*ciphertext, "$dummy$", 7) &&
		    p - *ciphertext != 10 /* not tripcode */) {
/* Check for a special case: possibly a traditional crypt(3) hash with
 * whitespace in its invalid salt.  Only support such hashes at the very start
 * of a line (no leading whitespace other than the invalid salt). */
			if (p - *ciphertext == 11 && *ciphertext - *login == 2)
				(*ciphertext)--;
			if (p - *ciphertext == 12 && *ciphertext - *login == 1)
				(*ciphertext)--;
			if (p - *ciphertext < 13)
				return 0;
		}
		*p = 0;
		fields[0] = *login = no_username;
		fields[1] = *ciphertext;
	}

	if (source)
		strcpy(source, line ? line : "");

/*
 * This check is just a loader performance optimization, so that we can parse
 * fewer fields when we know we won't need the rest.  It should be revised or
 * removed when there are formats that use higher-numbered fields in prepare().
 */
	if ((options->flags & DB_WORDS) || options->shells->head) {
		/* Parse all fields */
		for (i = 2; i < 10; i++)
			fields[i] = ldr_get_field(&line);
	} else {
		/* Parse some fields only */
		for (i = 2; i < 4; i++)
			fields[i] = ldr_get_field(&line);
		for (; i < 10; i++)
			fields[i] = "/";
	}

	/* /etc/passwd */
	uid = fields[2];
	gid = fields[3];
	*gecos = fields[4];
	*home = fields[5];
	shell = fields[6];

	if (fields[5][0] != '/' &&
	    ((!strcmp(fields[5], "0") && !strcmp(fields[6], "0")) ||
	    fields[8][0] == '/' ||
	    fields[9][0] == '/')) {
		/* /etc/master.passwd */
		*gecos = fields[7];
		*home = fields[8];
		shell = fields[9];
	} else if (fields[3] - fields[2] == 32 + 1) {
		/* PWDUMP */
		uid = fields[1];
		*ciphertext = fields[2];
		if (!strncmp(*ciphertext, "NO PASSWORD", 11))
			*ciphertext = "";
		gid = shell = "";
		*gecos = fields[4];
		*home = fields[5];

		/* Re-introduce the previously removed uid field */
		if (source) {
			int shift = strlen(uid);
			memmove(source + shift + 1, source, strlen(source) + 1);
			memcpy(source, uid, shift);
			source[shift] = ':';
		}
	}

	if (ldr_check_list(options->users, *login, uid)) return 0;
	if (ldr_check_list(options->groups, gid, gid)) return 0;
	if (ldr_check_shells(options->shells, shell)) return 0;

	if (*format) {
		char *prepared;
		int valid;

		prepared = (*format)->methods.prepare(fields, *format);
		if (prepared)
			valid = (*format)->methods.valid(prepared, *format);
		else
			valid = 0;

		if (valid) {
			*ciphertext = prepared;
			return valid;
		}

		alt = fmt_list;
		do {
			if (alt == *format)
				continue;
			if (alt->params.flags & FMT_WARNED)
				continue;
#ifdef HAVE_CRYPT
			if (alt == &fmt_crypt &&
#ifdef __sun
			    strncmp(*ciphertext, "$md5$", 5) &&
			    strncmp(*ciphertext, "$md5,", 5) &&
#endif
			    strncmp(*ciphertext, "$5$", 3) &&
			    strncmp(*ciphertext, "$6$", 3))
				continue;
#endif
			prepared = alt->methods.prepare(fields, alt);
			if (alt->methods.valid(prepared, alt)) {
				alt->params.flags |= FMT_WARNED;
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

#ifdef HAVE_CRYPT
/*
 * Only probe for support by the current system's crypt(3) if this is forced
 * from the command-line or/and if the hash encoding string looks like one of
 * those that are only supported in that way.  Avoid the probe in other cases
 * because it may be slow and undesirable (false detection is possible).
 */
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

		prepared = alt->methods.prepare(fields, alt);
		if (!prepared)
			continue;
		valid = alt->methods.valid(prepared, alt);
		if (!valid)
			continue;

		if (retval < 0) {
			retval = valid;
			*ciphertext = prepared;
			fmt_init(*format = alt);
#ifdef LDR_WARN_AMBIGUOUS
			if (!source) /* not --show */
				continue;
#endif
			break;
		}
#ifdef LDR_WARN_AMBIGUOUS
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

static void ldr_split_string(struct list_main *dst, char *src)
{
	char *word, *pos;
	char c;

	pos = src;
	do {
		word = pos;
		while (*word && issep_map[ARCH_INDEX(*word)]) word++;
		if (!*word) break;

		pos = word;
		while (!issep_map[ARCH_INDEX(*pos)]) pos++;
		c = *pos;
		*pos = 0;
		list_add_unique(dst, word);
		*pos++ = c;
	} while (c && dst->count < LDR_WORDS_MAX);
}

static struct list_main *ldr_init_words(char *login, char *gecos, char *home)
{
	struct list_main *words;
	char *pos;

	list_init(&words);

	if (*login && login != no_username)
		list_add(words, login);
	ldr_split_string(words, gecos);
	if (login != no_username)
		ldr_split_string(words, login);

	if ((pos = strrchr(home, '/')) && pos[1])
		list_add_unique(words, pos + 1);

	return words;
}

static void ldr_load_pw_line(struct db_main *db, char *line)
{
	static int skip_dupe_checking = 0;
	struct fmt_main *format;
	int index, count;
	char *login, *ciphertext, *gecos, *home;
	char *piece;
	void *binary, *salt;
	int salt_hash, pw_hash;
	struct db_salt *current_salt, *last_salt;
	struct db_password *current_pw, *last_pw;
	struct list_main *words;
	size_t pw_size, salt_size;

	count = ldr_split_line(&login, &ciphertext, &gecos, &home,
		NULL, &db->format, db->options, line);
	if (count <= 0) return;
	if (count >= 2) db->options->flags |= DB_SPLIT;

	format = db->format;

	words = NULL;

	if (db->options->flags & DB_WORDS) {
		pw_size = sizeof(struct db_password);
		salt_size = sizeof(struct db_salt);
	} else {
		if (db->options->flags & DB_LOGIN)
			pw_size = sizeof(struct db_password) -
				sizeof(struct list_main *);
		else
			pw_size = sizeof(struct db_password) -
				(sizeof(char *) + sizeof(struct list_main *));
		salt_size = sizeof(struct db_salt) -
			sizeof(struct db_keys *);
	}

	if (!db->password_hash)
		ldr_init_password_hash(db);

	for (index = 0; index < count; index++) {
		piece = format->methods.split(ciphertext, index, format);

		binary = format->methods.binary(piece);
		pw_hash = db->password_hash_func(binary);

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
				skip_dupe_checking = 1;
				current_pw = NULL; /* no match */
				break;
			} while ((current_pw = current_pw->next_hash));

			if (current_pw) continue;
		}

		salt = format->methods.salt(piece);
		salt_hash = format->methods.salt_hash(salt);

		if ((current_salt = db->salt_hash[salt_hash]))
		do {
			if (!memcmp(current_salt->salt, salt,
			    format->params.salt_size))
				break;
		} while ((current_salt = current_salt->next));

		if (!current_salt) {
			last_salt = db->salt_hash[salt_hash];
			current_salt = db->salt_hash[salt_hash] =
				mem_alloc_tiny(salt_size, MEM_ALIGN_WORD);
			current_salt->next = last_salt;

			current_salt->salt = mem_alloc_copy(salt,
				format->params.salt_size,
				format->params.salt_align);

			current_salt->index = fmt_dummy_hash;
			current_salt->bitmap = NULL;
			current_salt->list = NULL;
			current_salt->hash = &current_salt->list;
			current_salt->hash_size = -1;

			current_salt->count = 0;

			if (db->options->flags & DB_WORDS)
				current_salt->keys = NULL;

			db->salt_count++;
		}

		current_salt->count++;
		db->password_count++;

		last_pw = current_salt->list;
		current_pw = current_salt->list = mem_alloc_tiny(
			pw_size, MEM_ALIGN_WORD);
		current_pw->next = last_pw;

		last_pw = db->password_hash[pw_hash];
		db->password_hash[pw_hash] = current_pw;
		current_pw->next_hash = last_pw;

/* If we're not going to use the source field for its usual purpose, see if we
 * can pack the binary value in it. */
		if (format->methods.source != fmt_default_source &&
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
	read_file(db, name, RF_ALLOW_DIR, ldr_load_pw_line);
}

static void ldr_load_pot_line(struct db_main *db, char *line)
{
	struct fmt_main *format = db->format;
	char *ciphertext;
	void *binary;
	int hash;
	struct db_password *current;

	ciphertext = ldr_get_field(&line);
	if (format->methods.valid(ciphertext, format) != 1) return;

	ciphertext = format->methods.split(ciphertext, 0, format);
	binary = format->methods.binary(ciphertext);
	hash = db->password_hash_func(binary);

	if ((current = db->password_hash[hash]))
	do {
		if (!current->binary) /* already marked for removal */
			continue;
		if (memcmp(binary, current->binary, format->params.binary_size))
			continue;
		if (strcmp(ciphertext,
		    format->methods.source(current->source, current->binary)))
			continue;
		current->binary = NULL; /* mark for removal */
	} while ((current = current->next_hash));
}

void ldr_load_pot_file(struct db_main *db, char *name)
{
	if (db->format) {
#ifdef HAVE_CRYPT
		ldr_in_pot = 1;
#endif
		read_file(db, name, RF_ALLOW_MISSING, ldr_load_pot_line);
#ifdef HAVE_CRYPT
		ldr_in_pot = 0;
#endif
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
	int hash;

	for (hash = 0, tail = &db->salts; hash < SALT_HASH_SIZE; hash++)
	if ((current = db->salt_hash[hash])) {
		*tail = current;
		do {
			tail = &current->next;
		} while ((current = current->next));
	}
}

/*
 * Remove the previously-cracked hashes marked with "binary = NULL" by
 * ldr_load_pot_line().
 */
static void ldr_remove_marked(struct db_main *db)
{
	struct db_salt *current_salt, *last_salt;
	struct db_password *current_pw, *last_pw;

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
			} else
				last_pw = current_pw;
		} while ((current_pw = current_pw->next));

		if (!current_salt->list) {
			db->salt_count--;

			if (last_salt)
				last_salt->next = current_salt->next;
			else
				db->salts = current_salt->next;
		} else
			last_salt = current_salt;
	} while ((current_salt = current_salt->next));
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
	int bitmap_size, hash_size;
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
	} while ((current = current->next));
}

void ldr_fix_database(struct db_main *db)
{
	ldr_init_salts(db);
	MEM_FREE(db->password_hash);
	MEM_FREE(db->salt_hash);

	ldr_filter_salts(db);
	ldr_remove_marked(db);

	ldr_init_hash(db);

	db->loaded = 1;
}

static int ldr_cracked_hash(char *ciphertext)
{
	unsigned int hash = 0;
	char *p = ciphertext;

	while (*p) {
		hash <<= 1;
		hash += (unsigned char)*p++ | 0x20; /* ASCII case insensitive */
		if (hash >> (2 * CRACKED_HASH_LOG - 1)) {
			hash ^= hash >> CRACKED_HASH_LOG;
			hash &= CRACKED_HASH_SIZE - 1;
		}
	}

	hash ^= hash >> CRACKED_HASH_LOG;
	hash &= CRACKED_HASH_SIZE - 1;

	return hash;
}

static void ldr_show_pot_line(struct db_main *db, char *line)
{
	char *ciphertext, *pos;
	int hash;
	struct db_cracked *current, *last;

	ciphertext = ldr_get_field(&line);

	if (line) {
/* If just one format was forced on the command line, insist on it */
		if (!fmt_list->next &&
		    !fmt_list->methods.valid(ciphertext, fmt_list))
			return;

		pos = line;
		do {
			if (*pos == '\r' || *pos == '\n') *pos = 0;
		} while (*pos++);

		if (db->options->flags & DB_PLAINTEXTS) {
			list_add(db->plaintexts, line);
			return;
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
#ifdef HAVE_CRYPT
	ldr_in_pot = 1;
#endif
	read_file(db, name, RF_ALLOW_MISSING, ldr_show_pot_line);
#ifdef HAVE_CRYPT
	ldr_in_pot = 0;
#endif
}

static void ldr_show_pw_line(struct db_main *db, char *line)
{
	int show;
	char source[LINE_BUFFER_SIZE];
	struct fmt_main *format;
	char *(*split)(char *ciphertext, int index, struct fmt_main *self);
	int index, count, unify;
	char *login, *ciphertext, *gecos, *home;
	char *piece;
	int pass, found, chars;
	int hash;
	struct db_cracked *current;

	format = NULL;
	count = ldr_split_line(&login, &ciphertext, &gecos, &home,
		source, &format, db->options, line);
	if (!count) return;

/* If just one format was forced on the command line, insist on it */
	if (!fmt_list->next && !format) return;

	show = !(db->options->flags & DB_PLAINTEXTS);

	if (format) {
		split = format->methods.split;
		unify = format->params.flags & FMT_SPLIT_UNIFIES_CASE;
	} else {
		split = fmt_default_split;
		count = 1;
		unify = 0;
	}

	if (!*ciphertext) {
		found = 1;
		if (show) printf("%s:NO PASSWORD", login);

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
			if (!strcmp(pot, piece))
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
			if (show) {
				if (format)
					chars = format->params.plaintext_length;
				if (index < count - 1 && current &&
				    (int)strlen(current->plaintext) != chars)
					current = NULL;
			}

			if (current) {
				if (show) {
					printf("%s", current->plaintext);
				} else
					list_add(db->plaintexts,
						current->plaintext);

				db->guess_count++;
			} else
			while (chars--)
				putchar('?');
		} else
		if (current) {
			found = 1;
			if (show) printf("%s:", login);
			break;
		}
	}

	if (found && show) {
		if (source[0])
			printf(":%s", source);
		else
			putchar('\n');
	}

	if (format || found) db->password_count += count;
}

void ldr_show_pw_file(struct db_main *db, char *name)
{
	read_file(db, name, RF_ALLOW_DIR, ldr_show_pw_line);
}
