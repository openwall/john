/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002 by Solar Designer
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "path.h"
#include "memory.h"
#include "list.h"
#include "tty.h"
#include "signals.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "options.h"
#include "config.h"
#include "bench.h"
#include "charset.h"
#include "single.h"
#include "wordlist.h"
#include "inc.h"
#include "external.h"
#include "batch.h"

#if CPU_DETECT
extern int CPU_detect(void);
#endif

extern struct fmt_main fmt_DES, fmt_BSDI, fmt_MD5, fmt_BF;
extern struct fmt_main fmt_AFS, fmt_LM;

extern int unshadow(int argc, char **argv);
extern int unafs(int argc, char **argv);
extern int unique(int argc, char **argv);

static struct db_main database;
static struct fmt_main dummy_format;

static void john_register_one(struct fmt_main *format)
{
	if (options.format)
	if (strcmp(options.format, format->params.label)) return;

	fmt_register(format);
}

static void john_register_all(void)
{
	if (options.format) strlwr(options.format);

	john_register_one(&fmt_DES);
	john_register_one(&fmt_BSDI);
	john_register_one(&fmt_MD5);
	john_register_one(&fmt_BF);
	john_register_one(&fmt_AFS);
	john_register_one(&fmt_LM);

	if (!fmt_list) {
		fprintf(stderr, "Unknown ciphertext format name requested\n");
		error();
	}
}

static void john_load(void)
{
	struct list_entry *current;

	umask(077);

	if (options.flags & FLG_EXTERNAL_CHK)
		ext_init(options.external);

	if (options.flags & FLG_MAKECHARS_CHK) {
		options.loader.flags |= DB_CRACKED;
		ldr_init_database(&database, &options.loader);

		if (options.flags & FLG_PASSWD) {
			ldr_show_pot_file(&database, LOG_NAME);

			database.options->flags |= DB_PLAINTEXTS;
			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));
		} else {
			database.options->flags |= DB_PLAINTEXTS;
			ldr_show_pot_file(&database, LOG_NAME);
		}

		return;
	}

	if (options.flags & FLG_STDOUT) {
		ldr_init_database(&database, &options.loader);
		database.format = &dummy_format;
		memset(&dummy_format, 0, sizeof(dummy_format));
		dummy_format.params.plaintext_length = options.length;
		dummy_format.params.flags = FMT_CASE | FMT_8_BIT;
	}

	if (options.flags & FLG_PASSWD) {
		if (options.flags & FLG_SHOW_CHK) {
			options.loader.flags |= DB_CRACKED;
			ldr_init_database(&database, &options.loader);

			ldr_show_pot_file(&database, LOG_NAME);

			if ((current = options.passwd->head))
			do {
				ldr_show_pw_file(&database, current->data);
			} while ((current = current->next));

			printf("%s%d password%s cracked, %d left\n",
				database.guess_count ? "\n" : "",
				database.guess_count,
				database.guess_count != 1 ? "s" : "",
				database.password_count -
				database.guess_count);

			return;
		}

		if (options.flags & (FLG_SINGLE_CHK | FLG_BATCH_CHK))
			options.loader.flags |= DB_WORDS;
		else
		if (mem_saving_level)
			options.loader.flags &= ~DB_LOGIN;
		ldr_init_database(&database, &options.loader);

		if ((current = options.passwd->head))
		do {
			ldr_load_pw_file(&database, current->data);
		} while ((current = current->next));

		ldr_load_pot_file(&database, LOG_NAME);

		ldr_fix_database(&database);

		printf("Loaded %d password%s%s",
			database.password_count,
			database.password_count != 1 ? "s" : "",
			database.password_count ? "" : ", exiting...");
		if (database.password_count > 1) {
			printf(" with ");
			printf(database.salt_count != 1 ? "%d" : "no",
				database.salt_count);
			printf(" different salts");
		}
		if (database.password_count)
			printf(" (%s [%s])\n",
				database.format->params.format_name,
				database.format->params.algorithm_name);
		else
			putchar('\n');

		if ((options.flags & FLG_PWD_REQ) && !database.salts) exit(0);
	}
}

static void john_init(int argc, char **argv)
{
#if CPU_DETECT
	if (!CPU_detect()) {
#if CPU_REQ
#if CPU_FALLBACK
#if defined(__DJGPP__) || defined(__CYGWIN32__)
#error CPU_FALLBACK is incompatible with the current DOS and Win32 code
#endif
		execv(JOHN_SYSTEMWIDE_EXEC "/" CPU_FALLBACK_BINARY, argv);
		perror("execv");
#endif
		fprintf(stderr, "Sorry, %s is required\n", CPU_NAME);
		error();
#endif
	}
#endif

	path_init(argv);

#if JOHN_SYSTEMWIDE
	cfg_init(CFG_PRIVATE_FULL_NAME, 1);
	cfg_init(CFG_PRIVATE_ALT_NAME, 1);
#endif
	cfg_init(CFG_FULL_NAME, 1);
	cfg_init(CFG_ALT_NAME, 0);

	status_init(NULL, 1);
	opt_init(argc, argv);

	john_register_all();
	common_init();

	sig_init();

	john_load();
}

static void john_run(void)
{
	if (options.flags & FLG_TEST_CHK)
		benchmark_all();
	else
	if (options.flags & FLG_MAKECHARS_CHK)
		do_makechars(&database, options.charset);
	else
	if (options.flags & FLG_CRACKING_CHK) {
		if (!(options.flags & FLG_STDOUT)) log_init(LOG_NAME);
		tty_init();

		if (options.flags & FLG_SINGLE_CHK)
			do_single_crack(&database);
		else
		if (options.flags & FLG_WORDLIST_CHK)
			do_wordlist_crack(&database, options.wordlist,
				(options.flags & FLG_RULES) != 0);
		else
		if (options.flags & FLG_INC_CHK)
			do_incremental_crack(&database, options.charset);
		else
		if (options.flags & FLG_EXTERNAL_CHK)
			do_external_crack(&database);
		else
		if (options.flags & FLG_BATCH_CHK)
			do_batch_crack(&database);

		status_print();
		tty_done();
		if (!(options.flags & FLG_STDOUT)) log_done();
	}
}

static void john_done(void)
{
	path_done();

	check_abort();
}

int main(int argc, char **argv)
{
	char *name;

#ifdef __DJGPP__
	if (--argc <= 0) return 1;
	if ((name = strrchr(argv[0], '/')))
		strcpy(name + 1, argv[1]);
	name = argv[1];
	argv[1] = argv[0];
	argv++;
#else
	if (!argv[0])
		name = "";
	else
	if ((name = strrchr(argv[0], '/')))
		name++;
	else
		name = argv[0];
#endif

#ifdef __CYGWIN32__
	if (strlen(name) > 4)
	if (!strcmp(strlwr(name) + strlen(name) - 4, ".exe"))
		name[strlen(name) - 4] = 0;
#endif

	if (!strcmp(name, "unshadow"))
		return unshadow(argc, argv);

	if (!strcmp(name, "unafs"))
		return unafs(argc, argv);

	if (!strcmp(name, "unique"))
		return unique(argc, argv);

	john_init(argc, argv);
	john_run();
	john_done();

	return 0;
}
