/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2004,2006,2011,2013 by Solar Designer
 *
 * ...with changes in the jumbo patch, by magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "params.h"
#include "os.h" /* Needed for signals.h */
#include "signals.h"
#include "compiler.h"
#include "loader.h"
#include "logger.h"
#include "status.h"
#include "recovery.h"
#include "options.h"
#include "config.h"
#include "cracker.h"
#include "john.h"
#include "external.h"
#include "mask.h"
#include "options.h"
#include "memdbg.h"

static char int_word[PLAINTEXT_BUFFER_SIZE];
static char rec_word[PLAINTEXT_BUFFER_SIZE];

/*
 * A "sequence number" for distributing the candidate passwords across nodes.
 * It is OK if this number overflows once in a while, as long as this happens
 * in the same way for all nodes (must be same size unsigned integer type).
 */
static unsigned int seq, rec_seq;

unsigned int ext_flags = 0;
static char *ext_mode;

static c_int ext_word[PLAINTEXT_BUFFER_SIZE];
c_int ext_abort, ext_status, ext_cipher_limit, ext_minlen, ext_maxlen;
c_int ext_time;

static struct c_ident ext_ident_status = {
	NULL,
	"status",
	&ext_status
};

static struct c_ident ext_ident_abort = {
	&ext_ident_status,
	"abort",
	&ext_abort
};

static struct c_ident ext_ident_cipher_limit = {
	&ext_ident_abort,
	"cipher_limit",
	&ext_cipher_limit
};

static struct c_ident ext_ident_minlen = {
	&ext_ident_cipher_limit,
	"req_minlen",
	&ext_minlen
};

static struct c_ident ext_ident_maxlen = {
	&ext_ident_minlen,
	"req_maxlen",
	&ext_maxlen
};

static struct c_ident ext_ident_time = {
	&ext_ident_maxlen,
	"session_start_time",
	&ext_time
};

static struct c_ident ext_globals = {
	&ext_ident_time,
	"word",
	ext_word
};

static void *f_generate;
void *f_filter = NULL;

static struct cfg_list *ext_source;
static struct cfg_line *ext_line;
static int ext_pos;
static double progress = -1;
static int maxlen = PLAINTEXT_BUFFER_SIZE - 1;

static double get_progress(void)
{
	// This is a dummy function just for getting the DONE
	// timestamp from status.c - it will return -1 all
	// the time except when a mode is finished
	emms();

	return progress;
}

static int ext_getchar(void)
{
	unsigned char c;

	if (!ext_line || !ext_line->data) return -1;

	if ((c = (unsigned char)ext_line->data[ext_pos++])) return c;

	ext_line = ext_line->next;
	ext_pos = 0;
	return '\n';
}

static void ext_rewind(void)
{
	ext_line = ext_source->head;
	ext_pos = 0;
}

int ext_has_function(char *mode, char *function)
{
	if (!(ext_source = cfg_get_list(SECTION_EXT, mode))) {
		if (john_main_process)
			fprintf(stderr, "Unknown external mode: %s\n", mode);
		error();
	}
	if (c_compile(ext_getchar, ext_rewind, &ext_globals)) {
		if (!ext_line) ext_line = ext_source->tail;

		if (john_main_process)
			fprintf(stderr, "Compiler error in %s at line %d: %s\n",
			ext_line->cfg_name, ext_line->number,
			c_errors[c_errno]);
		error();
	}
	return (c_lookup(function) != NULL);
}

void ext_init(char *mode, struct db_main *db)
{
	if (db != NULL && db->format != NULL) {
		/* This is second time we are called, just update max length */
		ext_cipher_limit = maxlen =
			db->format->params.plaintext_length - mask_add_len;
		if (mask_num_qw > 1) {
			ext_cipher_limit /= mask_num_qw;
			maxlen /= mask_num_qw;
		}
		return;
	} else
		ext_cipher_limit = options.length;

	ext_time = (int) time(NULL);

	ext_maxlen = options.req_maxlength;
	if (options.req_minlength > 0)
		ext_minlen = options.req_minlength;
	else
		ext_minlen = 0;

	if (!(ext_source = cfg_get_list(SECTION_EXT, mode))) {
		if (john_main_process)
			fprintf(stderr, "Unknown external mode: %s\n", mode);
		error();
	}

	if (c_compile(ext_getchar, ext_rewind, &ext_globals)) {
		if (!ext_line) ext_line = ext_source->tail;

		if (john_main_process)
			fprintf(stderr,
			    "Compiler error in %s at line %d: %s\n",
			    ext_line->cfg_name, ext_line->number,
			    c_errors[c_errno]);
		error();
	}

	ext_word[0] = 0;
	c_execute(c_lookup("init"));

	f_generate = c_lookup("generate");
	f_filter = c_lookup("filter");

	if ((ext_flags & EXT_REQ_GENERATE) && !f_generate) {
		if (john_main_process)
			fprintf(stderr,
			    "No generate() for external mode: %s\n", mode);
		error();
	}
	if ((ext_flags & EXT_REQ_GENERATE) && !c_lookup("restore")) {
		if (ext_flags & EXT_REQ_RESTORE) {
			if (john_main_process)
				fprintf(stderr,
				        "No restore() for external mode: %s\n",
				        mode);
			error();
		} else if (john_main_process)
				fprintf(stderr,
				        "Warning: external mode '%s' can't be"
				        " resumed if aborted\n", mode);
	}
	if ((ext_flags & EXT_REQ_FILTER) && !f_filter) {
		if (john_main_process)
			fprintf(stderr,
			    "No filter() for external mode: %s\n", mode);
		error();
	}
	if (john_main_process &&
	    (ext_flags & (EXT_USES_GENERATE | EXT_USES_FILTER)) ==
	    EXT_USES_FILTER && f_generate)
	if (john_main_process)
		fprintf(stderr, "Warning: external mode defines generate(), "
		    "but is only used for filter()\n");

	ext_mode = mode;
}

int ext_filter_body(char *in, char *out)
{
	unsigned char *internal;
	c_int *external;

	internal = (unsigned char *)in;
	external = ext_word;
	external[0] = internal[0];
	external[1] = internal[1];
	external[2] = internal[2];
	external[3] = internal[3];
	if (external[0] && external[1] && external[2] && external[3])
	do {
		if (!(external[4] = internal[4]))
			break;
		if (!(external[5] = internal[5]))
			break;
		if (!(external[6] = internal[6]))
			break;
		if (!(external[7] = internal[7]))
			break;
		internal += 4;
		external += 4;
	} while (1);

	c_execute_fast(f_filter);

	if (!ext_word[0] && in[0]) return 0;

	internal = (unsigned char *)out;
	external = ext_word;
	internal[0] = external[0];
	internal[1] = external[1];
	internal[2] = external[2];
	internal[3] = external[3];
	if (external[0] && external[1] && external[2] && external[3])
	do {
		if (!(internal[4] = external[4]))
			break;
		if (!(internal[5] = external[5]))
			break;
		if (!(internal[6] = external[6]))
			break;
		if (!(internal[7] = external[7]))
			break;
		internal += 4;
		external += 4;
	} while (1);

	out[maxlen] = 0;
	return 1;
}

static void save_state(FILE *file)
{
	unsigned char *ptr;

	fprintf(file, "%u\n", rec_seq);
	ptr = (unsigned char *)rec_word;
	do {
		fprintf(file, "%d\n", (int)*ptr);
	} while (*ptr++);
}

static int restore_state(FILE *file)
{
	int c;
	unsigned char *internal;
	c_int *external;
	int count;

	if (rec_version >= 4 && fscanf(file, "%u\n", &seq) != 1)
		return 1;

	internal = (unsigned char *)int_word;
	external = ext_word;
	count = 0;
	do {
		if (fscanf(file, "%d\n", &c) != 1) return 1;
		if (++count >= PLAINTEXT_BUFFER_SIZE) return 1;
	} while ((*internal++ = *external++ = c));

	c_execute(c_lookup("restore"));

	return 0;
}

static void fix_state(void)
{
	strcpy(rec_word, int_word);
	rec_seq = seq;
}

void do_external_crack(struct db_main *db)
{
	unsigned char *internal;
	c_int *external;
	int my_words, their_words;

	log_event("Proceeding with external mode: %.100s", ext_mode);

	internal = (unsigned char *)int_word;
	external = ext_word;
	while (*external)
		*internal++ = *external++;
	*internal = 0;

	seq = 0;

	status_init(&get_progress, 0);

	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);

	my_words = options.node_max - options.node_min + 1;
	their_words = options.node_min - 1;

	if (seq) {
/* Restored session.  seq is right after a word we've actually used. */
		int for_node = seq % options.node_count + 1;
		if (for_node < options.node_min ||
		        for_node > options.node_max) {
/* We assume that seq is at the beginning of other nodes' block */
			their_words = options.node_count - my_words;
		} else {
			my_words = options.node_max - for_node + 1;
			their_words = 0;
		}
	}

	do {
		c_execute_fast(f_generate);
		if (!ext_word[0])
			break;

		if (options.node_count) {
			seq++;
			if (their_words) {
				their_words--;
				continue;
			}
			if (--my_words == 0) {
				my_words =
					options.node_max - options.node_min + 1;
				their_words = options.node_count - my_words;
			}
		}

		if (f_filter) {
			c_execute_fast(f_filter);
			if (!ext_word[0])
				continue;
		}

		int_word[0] = ext_word[0];
		if ((int_word[1] = ext_word[1])) {
			internal = (unsigned char *)&int_word[2];
			external = &ext_word[2];
			do {
				if (!(internal[0] = external[0]))
					break;
				if (!(internal[1] = external[1]))
					break;
				if (!(internal[2] = external[2]))
					break;
				if (!(internal[3] = external[3]))
					break;
				internal += 4;
				external += 4;
			} while (1);
		}

		int_word[maxlen] = 0;
		if (options.flags & FLG_MASK_STACKED) {
			if (do_mask_crack(int_word))
				break;
		} else
		if (crk_process_key(int_word)) break;
	} while (1);

	if (!event_abort)
		progress = 100; // For reporting DONE after a no-ETA run

	crk_done();
	rec_done(event_abort);
}
