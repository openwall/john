/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2009,2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define _POSIX_SOURCE /* for fileno(3) */
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "misc.h"
#include "math.h"
#include "params.h"
#include "common.h"
#include "path.h"
#include "signals.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "rpp.h"
#include "rules.h"
#include "external.h"
#include "cracker.h"
#include "john.h"

static FILE *word_file = NULL;
static int progress = 0;

static int rec_rule;
static long rec_pos; /* ftell(3) is defined to return a long */
static unsigned long rec_line;

static int rule_number, rule_count;
static unsigned long line_number;
static int length;
static struct rpp_context *rule_ctx;

static void save_state(FILE *file)
{
	fprintf(file, "%d\n%ld\n%lu\n", rec_rule, rec_pos, rec_line);
}

static int restore_rule_number(void)
{
	if (rule_ctx)
	for (rule_number = 0; rule_number < rec_rule; rule_number++)
	if (!rpp_next(rule_ctx)) {
		fprintf(stderr, "Restored rule number is out of range - "
		    "has the configuration file changed?\n");
		return 1;
	}

	return 0;
}

static MAYBE_INLINE int skip_lines(unsigned long n, char *line)
{
	if (n) {
		line_number += n;

		do {
			if (!fgetl(line, LINE_BUFFER_SIZE, word_file))
				return 1;
		} while (--n);
	}

	return 0;
}

static void restore_line_number(void)
{
	char line[LINE_BUFFER_SIZE];
	if (skip_lines(rec_pos, line)) {
		if (ferror(word_file))
			pexit("fgets");
		fprintf(stderr, "fgets: Unexpected EOF\n");
		error();
	}
}

static int restore_state(FILE *file)
{
	if (fscanf(file, "%d\n%ld\n", &rec_rule, &rec_pos) != 2)
		return 1;
	rec_line = 0;
	if (rec_version >= 4 && fscanf(file, "%lu\n", &rec_line) != 1)
		return 1;
	if (rec_rule < 0 || rec_pos < 0)
		return 1;

	if (restore_rule_number())
		return 1;

	if (word_file == stdin) {
		restore_line_number();
	} else {
		if (fseek(word_file, rec_pos, SEEK_SET))
			pexit("fseek");
		line_number = rec_line;
	}

	return 0;
}

static void fix_state(void)
{
	rec_rule = rule_number;
	rec_line = line_number;

	if (word_file == stdin)
		rec_pos = line_number;
	else
	if ((rec_pos = ftell(word_file)) < 0) {
#ifdef __DJGPP__
		if (rec_pos != -1)
			rec_pos = 0;
		else
#endif
			pexit("ftell");
	}
}

static int get_progress(void)
{
	struct stat file_stat;
	long pos;
	int64 x100;

	if (!word_file) return progress;

	if (word_file == stdin) return -1;

	if (fstat(fileno(word_file), &file_stat)) pexit("fstat");

	if ((pos = ftell(word_file)) < 0) {
#ifdef __DJGPP__
		if (pos != -1)
			pos = 0;
		else
#endif
			pexit("ftell");
	}

	mul32by32(&x100, pos, 100);
	return
		(rule_number * 100 +
		div64by32lo(&x100, file_stat.st_size + 1)) / rule_count;
}

static char *dummy_rules_apply(char *word, char *rule, int split, char *last)
{
	word[length] = 0;
	if (strcmp(word, last))
		return strcpy(last, word);
	return NULL;
}

void do_wordlist_crack(struct db_main *db, char *name, int rules)
{
	union {
		char buffer[2][LINE_BUFFER_SIZE + CACHE_BANK_SHIFT];
		ARCH_WORD dummy;
	} aligned;
	char *line = aligned.buffer[0], *last = aligned.buffer[1];
	struct rpp_context ctx;
	char *prerule, *rule, *word;
	char *(*apply)(char *word, char *rule, int split, char *last);
	int dist_rules, dist_switch;
	unsigned long my_words, their_words, my_words_left;

	log_event("Proceeding with wordlist mode");

	if (name) {
		if (!(word_file = fopen(path_expand(name), "r")))
			pexit("fopen: %s", path_expand(name));
		log_event("- Wordlist file: %.100s", path_expand(name));
	} else {
		word_file = stdin;
		log_event("- Reading candidate passwords from stdin");
	}

	length = db->format->params.plaintext_length;

	if (rules) {
		if (rpp_init(rule_ctx = &ctx, SUBSECTION_WORDLIST)) {
			log_event("! No wordlist mode rules found");
			if (john_main_process)
				fprintf(stderr,
				    "No wordlist mode rules found in %s\n",
				    cfg_name);
			error();
		}

		rules_init(length);
		rule_count = rules_count(&ctx, -1);

		log_event("- %d preprocessed word mangling rules", rule_count);

		apply = rules_apply;
	} else {
		rule_ctx = NULL;
		rule_count = 1;

		log_event("- No word mangling rules");

		apply = dummy_rules_apply;
	}

	rule_number = 0;
	line_number = 0;

	status_init(get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	prerule = rule = "";
	if (rules)
		prerule = rpp_next(&ctx);

/* A string that can't be produced by fgetl(). */
	last[0] = '\n';
	last[1] = 0;

	dist_rules = 0;
	dist_switch = rule_count; /* never */
	my_words = ~0UL; /* all */
	their_words = 0;
	if (options.node_count) {
		int rule_rem = rule_count % options.node_count;
		const char *now, *later = "";
		dist_switch = rule_count - rule_rem;
		if (!rule_rem || rule_number < dist_switch) {
			dist_rules = 1;
			now = "rules";
			if (rule_rem)
				later = ", then switch to distributing words";
		} else {
			dist_switch = rule_count; /* never */
			my_words = options.node_max - options.node_min + 1;
			their_words = options.node_count - my_words;
			now = "words";
		}
		log_event("- Will distribute %s across nodes%s", now, later);
	}

	my_words_left = my_words;
	if (their_words) {
		if (line_number) {
/* Restored session.  line_number is right after a word we've actually used. */
			int for_node = line_number % options.node_count + 1;
			if (for_node < options.node_min ||
			    for_node > options.node_max) {
/* We assume that line_number is at the beginning of other nodes' block */
				if (skip_lines(their_words, line) &&
/* Check for error since a mere EOF means next rule (the loop below should see
 * the EOF again, and it will skip to next rule if applicable) */
				    ferror(word_file))
					prerule = NULL;
			} else {
				my_words_left =
				    options.node_max - for_node + 1;
			}
		} else {
/* New session.  Skip lower-numbered nodes' lines. */
			if (skip_lines(options.node_min - 1, line))
				prerule = NULL;
		}
	}

	if (prerule)
	do {
		if (rules) {
			if (dist_rules) {
				int for_node =
				    rule_number % options.node_count + 1;
				if (for_node < options.node_min ||
				    for_node > options.node_max)
					goto next_rule;
			}
			if ((rule = rules_reject(prerule, -1, last, db))) {
				if (strcmp(prerule, rule))
					log_event("- Rule #%d: '%.100s'"
						" accepted as '%.100s'",
						rule_number + 1, prerule, rule);
				else
					log_event("- Rule #%d: '%.100s'"
						" accepted",
						rule_number + 1, prerule);
			} else {
				log_event("- Rule #%d: '%.100s' rejected",
					rule_number + 1, prerule);
				goto next_rule;
			}
		}

		while (fgetl(line, LINE_BUFFER_SIZE, word_file)) {
			line_number++;

			if (line[0] != '#') {
process_word:
				if ((word = apply(line, rule, -1, last))) {
					last = word;

					if (ext_filter(word))
					if (crk_process_key(word)) {
						rules = 0;
						break;
					}
				}
next_word:
				if (--my_words_left)
					continue;
				if (skip_lines(their_words, line))
					break;
				my_words_left = my_words;
				continue;
			}

			if (strncmp(line, "#!comment", 9))
				goto process_word;
			goto next_word;
		}

		if (ferror(word_file))
			break;

		if (rules) {
next_rule:
			if (!(rule = rpp_next(&ctx))) break;
			rule_number++;

			if (rule_number >= dist_switch) {
				log_event("- Switching to distributing words");
				dist_rules = 0;
				dist_switch = rule_count; /* not anymore */
				my_words =
				    options.node_max - options.node_min + 1;
				their_words = options.node_count - my_words;
			}

			line_number = 0;
			if (fseek(word_file, 0, SEEK_SET))
				pexit("fseek");

			if (their_words &&
			    skip_lines(options.node_min - 1, line))
				break;
		}

		my_words_left = my_words;
	} while (rules);

	crk_done();
	rec_done(event_abort || (status.pass && db->salts));

	if (ferror(word_file)) pexit("fgets");

	if (name) {
		if (event_abort)
			progress = get_progress();
		else
			progress = 100;

		if (fclose(word_file)) pexit("fclose");
		word_file = NULL;
	}
}
