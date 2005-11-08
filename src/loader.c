/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003,2005 by Solar Designer
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

	db->options = mem_alloc_copy(sizeof(struct db_options),
		MEM_ALIGN_WORD, options);

	db->salts = NULL;

	if (options->flags & DB_CRACKED) {
		db->salt_hash = NULL;
		db->password_hash = NULL;

		db->cracked_hash = mem_alloc(
			CRACKED_HASH_SIZE * sizeof(struct db_cracked *));
		memset(db->cracked_hash, 0,
			CRACKED_HASH_SIZE * sizeof(struct db_cracked *));
	} else {
		db->salt_hash = mem_alloc(
			SALT_HASH_SIZE * sizeof(struct db_salt *));
		memset(db->salt_hash, 0,
			SALT_HASH_SIZE * sizeof(struct db_salt *));

		db->password_hash = mem_alloc(LDR_HASH_SIZE);
		memset(db->password_hash, 0, LDR_HASH_SIZE);

		db->cracked_hash = NULL;

		if (options->flags & DB_WORDS) {
			options->flags |= DB_LOGIN;

			ldr_init_issep();
		}
	}

	if (!options->max_pps)
		db->options->max_pps = (unsigned int)~0 >> 1;

	list_init(&db->plaintexts);

	db->salt_count = db->password_count = db->guess_count = 0;

	db->format = NULL;
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
	char *uid = NULL, *gid = NULL, *shell = NULL;
	char *tmp;
	int count;

	*login = ldr_get_field(&line);
	if (!strcmp(*login, "+") || !strncmp(*login, "+@", 2)) return 0;

	if (!*(*ciphertext = ldr_get_field(&line))) if (!line) return 0;

	if (source) strcpy(source, line ? line : "");

	uid = ldr_get_field(&line);

	if (strlen(uid) == 32) {
		tmp = *ciphertext;
		*ciphertext = uid;
		uid = tmp;

		if (!strncmp(*ciphertext, "NO PASSWORD", 11))
			*ciphertext = "";

		if (source) sprintf(source, "%s:%s", uid, line);
	}

	if (options->flags & DB_WORDS || options->shells->head) {
		gid = ldr_get_field(&line);
		do {
			*gecos = ldr_get_field(&line);
			*home = ldr_get_field(&line);
			shell = ldr_get_field(&line);
		} while (!**gecos &&
			!strcmp(*home, "0") && !strcmp(shell, "0"));
	} else
	if (options->groups->head) {
		gid = ldr_get_field(&line);
	}

	if (ldr_check_list(options->users, *login, uid)) return 0;
	if (ldr_check_list(options->groups, gid, gid)) return 0;
	if (ldr_check_shells(options->shells, shell)) return 0;

	if (*format) return (*format)->methods.valid(*ciphertext);

	if ((*format = fmt_list))
	do {
		if ((count = (*format)->methods.valid(*ciphertext))) {
			fmt_init(*format);
			return count;
		}
	} while ((*format = (*format)->next));

	return -1;
}

static void ldr_split_string(struct list_main *dst, char *src)
{
	char *word, *pos;

	pos = src;
	do {
		word = pos;
		while (*word && issep_map[ARCH_INDEX(*word)]) word++;
		if (!*word) break;

		pos = word;
		while (!issep_map[ARCH_INDEX(*pos)]) pos++;
		if (*pos) *pos++ = 0;

		list_add_unique(dst, word);
	} while (*pos && dst->count < LDR_WORDS_MAX);
}

static struct list_main *ldr_init_words(char *login, char *gecos, char *home)
{
	struct list_main *words;
	char *pos;

	list_init(&words);

	list_add(words, login);
	ldr_split_string(words, gecos);
	ldr_split_string(words, login);

	if ((pos = strrchr(home, '/')))
		list_add_unique(words, pos + 1);

	return words;
}

static void ldr_load_pw_line(struct db_main *db, char *line)
{
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

	for (index = 0; index < count; index++) {
		piece = format->methods.split(ciphertext, index);

		binary = format->methods.binary(piece);
		pw_hash = LDR_HASH_FUNC(binary);

		if ((current_pw = db->password_hash[pw_hash]))
		do {
			if (!memcmp(current_pw->binary, binary,
			    format->params.binary_size)) {
				if (!(db->options->flags & DB_WORDS) ||
				    !strcmp(current_pw->login, login)) break;
			}
		} while ((current_pw = current_pw->next_hash));

		if (current_pw) continue;

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

			current_salt->salt = mem_alloc_copy(
				format->params.salt_size, MEM_ALIGN_WORD,
				salt);

			current_salt->index = fmt_dummy_hash;
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

		current_pw->binary = mem_alloc_copy(
			format->params.binary_size, MEM_ALIGN_WORD, binary);

		current_pw->source = str_alloc_copy(piece);

		if (db->options->flags & DB_WORDS) {
			if (!words)
				words = ldr_init_words(login, gecos, home);
			current_pw->words = words;
		}

		if (db->options->flags & DB_LOGIN) {
			if (count > 1) {
				current_pw->login = mem_alloc_tiny(
					strlen(login) + 3, MEM_ALIGN_NONE);
				sprintf(current_pw->login, "%s:%d",
					login, index + 1);
			} else
			if (words)
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
	if (format->methods.valid(ciphertext) != 1) return;

	binary = format->methods.binary(format->methods.split(ciphertext, 0));
	hash = LDR_HASH_FUNC(binary);

	if ((current = db->password_hash[hash]))
	do {
		if (current->binary && !memcmp(current->binary, binary,
		    format->params.binary_size))
			current->binary = NULL;
	} while ((current = current->next_hash));
}

void ldr_load_pot_file(struct db_main *db, char *name)
{
	if (db->format)
		read_file(db, name, RF_ALLOW_MISSING, ldr_load_pot_line);
}

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

static void ldr_filter_salts(struct db_main *db)
{
	struct db_salt *current, *last;

	last = NULL;
	if ((current = db->salts))
	do {
		if (current->count < db->options->min_pps ||
		    current->count > db->options->max_pps) {
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

void ldr_update_salt(struct db_main *db, struct db_salt *salt)
{
	struct db_password *current;
	int (*hash_func)(void *binary);
	int hash;

	if (salt->hash_size < 0) {
		salt->count = 0;
		if ((current = salt->list))
		do {
			current->next_hash = current->next;
			salt->count++;
		} while ((current = current->next));

		return;
	}

	memset(salt->hash, 0,
		password_hash_sizes[salt->hash_size] *
		sizeof(struct db_password *));

	hash_func = db->format->methods.binary_hash[salt->hash_size];

	salt->count = 0;
	if ((current = salt->list))
	do {
		hash = hash_func(current->binary);
		current->next_hash = salt->hash[hash];
		salt->hash[hash] = current;
		salt->count++;
	} while ((current = current->next));
}

static void ldr_init_hash(struct db_main *db)
{
	struct db_salt *current;
	int size;

	if ((current = db->salts))
	do {
		for (size = 2; size >= 0; size--)
		if (current->count >= password_hash_thresholds[size]) break;

		if ((db->format->params.flags & FMT_BS) && !size) size = -1;

		if (size >= 0 && mem_saving_level < 2) {
			current->hash = mem_alloc_tiny(
				password_hash_sizes[size] *
				sizeof(struct db_password *),
				MEM_ALIGN_WORD);

			current->hash_size = size;

			current->index = db->format->methods.get_hash[size];
		}

		ldr_update_salt(db, current);
	} while ((current = current->next));
}

void ldr_fix_database(struct db_main *db)
{
	ldr_init_salts(db);
	MEM_FREE(db->password_hash);
	MEM_FREE(db->salt_hash);

	ldr_remove_marked(db);
	ldr_filter_salts(db);

	ldr_init_hash(db);

	db->loaded = 1;
}

static int ldr_cracked_hash(char *ciphertext)
{
	int hash = 0;

	while (*ciphertext) {
		hash <<= 1;
		hash ^= *ciphertext++ | 0x20; /* ASCII case insensitive */
	}

	hash ^= hash >> CRACKED_HASH_LOG;
	hash ^= hash >> (2 * CRACKED_HASH_LOG);
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
	read_file(db, name, RF_ALLOW_MISSING, ldr_show_pot_line);
}

static void ldr_show_pw_line(struct db_main *db, char *line)
{
	int show;
	char source[LINE_BUFFER_SIZE];
	struct fmt_main *format;
	char *(*split)(char *ciphertext, int index);
	int index, count;
	char *login, *ciphertext, *gecos, *home;
	char *piece;
	int pass, found, chars;
	int hash;
	struct db_cracked *current;

	format = NULL;
	count = ldr_split_line(&login, &ciphertext, &gecos, &home,
		source, &format, db->options, line);
	if (!count) return;

	show = !(db->options->flags & DB_PLAINTEXTS);

	if (format) {
		split = format->methods.split;
	} else {
		split = fmt_default_split;
		count = 1;
	}

	if (!*ciphertext) {
		found = 1;
		if (show) printf("%s:NO PASSWORD", login);

		db->guess_count++;
	} else
	for (found = pass = 0; pass == 0 || (pass == 1 && found); pass++)
	for (index = 0; index < count; index++) {
		piece = split(ciphertext, index);
		if (split != fmt_default_split)
			piece = strcpy(mem_alloc(strlen(piece) + 1), piece);

		hash = ldr_cracked_hash(piece);

		if ((current = db->cracked_hash[hash]))
		do {
			if (!strcmp(current->ciphertext, piece))
				break;
/* This extra check, along with ldr_cracked_hash() being case-insensitive,
 * is only needed for matching some pot file records produced by older
 * versions of John and contributed patches where split() didn't unify the
 * case of hex-encoded hashes. */
			if (split != fmt_default_split &&
			    format->methods.valid(current->ciphertext) == 1 &&
			    !strcmp(split(current->ciphertext, 0), piece))
				break;
		} while ((current = current->next));

		if (split != fmt_default_split)
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
