/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "misc.h"
#include "math.h"
#include "params.h"
#include "path.h"
#include "signals.h"
#include "loader.h"
#include "status.h"
#include "recovery.h"
#include "rpp.h"
#include "rules.h"
#include "external.h"
#include "cracker.h"

static FILE *word_file = NULL;
static int progress = 0;

static int rec_rule;
static long rec_pos;

static int rule_number, rule_count, line_number;
static int length;
static struct rpp_context *rule_ctx;

static void save_state(FILE *file)
{
	fprintf(file, "%d\n%ld\n", rec_rule, rec_pos);
}

static int restore_rule_number(void)
{
	if (rule_ctx)
	for (rule_number = 0; rule_number < rec_rule; rule_number++)
	if (!rpp_next(rule_ctx)) return 1;

	return 0;
}

static void restore_line_number(void)
{
	char line[LINE_BUFFER_SIZE];

	for (line_number = 0; line_number < rec_pos; line_number++)
	if (!fgets(line, sizeof(line), word_file)) {
		if (ferror(word_file)) pexit("fgets"); else {
			fprintf(stderr, "fgets: Unexpected EOF\n");
			error();
		}
	}
}

static int restore_state(FILE *file)
{
	if (fscanf(file, "%d\n%ld\n", &rec_rule, &rec_pos) != 2) return 1;

	if (restore_rule_number()) return 1;

	if (word_file == stdin)
		restore_line_number();
	else
		if (fseek(word_file, rec_pos, SEEK_SET)) pexit("fseek");

	return 0;
}

static void fix_state(void)
{
	rec_rule = rule_number;

	if (word_file == stdin)
		rec_pos = line_number;
	else
	if ((rec_pos = ftell(word_file)) < 0) {
#ifdef __DJGPP__
		if (rec_pos != -1) rec_pos = 0; else
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
		if (pos != -1) pos = 0; else
#endif
			pexit("ftell");
	}

	mul32by32(&x100, pos, 100);
	return
		(rule_number * 100 +
		div64by32lo(&x100, file_stat.st_size + 1)) / rule_count;
}

static char *dummy_rules_apply(char *word, char *rule, int split)
{
	word[length] = 0;

	return word;
}

void do_wordlist_crack(struct db_main *db, char *name, int rules)
{
	char line[LINE_BUFFER_SIZE];
	struct rpp_context ctx;
	char *rule, *word;
	char last[RULE_WORD_SIZE];
	char *(*apply)(char *word, char *rule, int split);

	if (name) {
		if (!(word_file = fopen(path_expand(name), "r")))
			pexit("fopen: %s", path_expand(name));
	} else
		word_file = stdin;

	length = db->format->params.plaintext_length;

	if (rules) {
		if (rpp_init(rule_ctx = &ctx, SUBSECTION_WORDLIST)) {
			fprintf(stderr, "No wordlist mode rules found in %s\n",
				cfg_name);
			error();
		}

		rules_init(length);
		rule_count = rules_count(&ctx, -1);

		apply = rules_apply;
	} else {
		rule_ctx = NULL;
		rule_count = 1;

		apply = dummy_rules_apply;
	}

	line_number = rule_number = 0;

	status_init(get_progress, !status.pass);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	if (rules) rule = rpp_next(&ctx); else rule = "";

	memset(last, ' ', length + 1);
	last[length + 2] = 0;

	if (rule)
	do {
		if (!rules || (rule = rules_reject(rule, db)))
		while (fgetl(line, sizeof(line), word_file)) {
			line_number++;

			if (line[0] == '#')
			if (!strncmp(line, "#!comment", 9)) continue;

			if ((word = apply(line, rule, -1)))
			if (strcmp(word, last)) {
				strcpy(last, word);

				if (ext_filter(word))
				if (crk_process_key(word)) {
					rules = 0;
					break;
				}
			}
		}

		if (rules) {
			if (!(rule = rpp_next(&ctx))) break;
			rule_number++;

			line_number = 0;
			if (fseek(word_file, 0, SEEK_SET)) pexit("fseek");
		}
	} while (rules);

	crk_done();
	rec_done(event_abort);

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
