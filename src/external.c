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
#include "regex.h"
#include "unicode.h"

/*
 * int_hybrid_base_word is set to the original word before call to new().
 * This is needed, so that we can store this proper word for a resume.
 */
static char int_hybrid_base_word[PLAINTEXT_BUFFER_SIZE];
static char hybrid_actual_completed_base_word[PLAINTEXT_BUFFER_SIZE];
static char int_word[PLAINTEXT_BUFFER_SIZE];
static char rec_word[PLAINTEXT_BUFFER_SIZE];
static char hybrid_rec_word[PLAINTEXT_BUFFER_SIZE];

#if HAVE_REXGEN
static char *regex_alpha;
static int regex_case;
static char *regex;
#endif

/*
 * A "sequence number" for distributing the candidate passwords across nodes.
 * It is OK if this number overflows once in a while, as long as this happens
 * in the same way for all nodes (must be same size unsigned integer type).
 */
static unsigned int seq, rec_seq;
static unsigned int hybrid_rec_seq;
static unsigned int hybrid_resume;
static unsigned int hybrid_actual_completed_resume;
static unsigned int hybrid_actual_completed_total;

unsigned int ext_flags = 0;
static char *ext_mode;

static c_int ext_word[PLAINTEXT_BUFFER_SIZE];
c_int ext_abort, ext_status; /* cracker needs to know about these */
static c_int ext_cipher_limit, ext_minlen, ext_maxlen;
static c_int ext_hybrid_resume, ext_hybrid_total;
static c_int ext_time, ext_utf32, ext_target_utf8;

static struct c_ident ext_ident_status = {
	NULL,
	"status",
	&ext_status
};

static struct c_ident ext_ident_hybrid_resume = {
	&ext_ident_status,
	"hybrid_resume",
	&ext_hybrid_resume
};

static struct c_ident ext_ident_hybrid_total = {
	&ext_ident_hybrid_resume,
	"hybrid_total",
	&ext_hybrid_total
};

static struct c_ident ext_ident_utf32 = {
	&ext_ident_hybrid_total,
	"utf32",
	&ext_utf32
};

static struct c_ident ext_ident_target_utf8 = {
	&ext_ident_utf32,
	"target_utf8",
	&ext_target_utf8
};

static struct c_ident ext_ident_abort = {
	&ext_ident_target_utf8,
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
static void *f_next = NULL;
void *f_new = NULL;
void *f_filter = NULL;

static struct cfg_list *ext_source;
static struct cfg_line *ext_line;
static int ext_pos;
static double progress = -1;
static int maxlen = PLAINTEXT_BUFFER_SIZE - 1;

static double get_progress(void)
{
	/*
	 * This is a dummy function just for getting the DONE timestamp
	 * from status.c - it will return -1 all the time except when a
	 * mode is finished
	 */
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

int ext_has_function(const char *mode, const char *function)
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
	ext_minlen = options.eff_minlength;
	maxlen = options.eff_maxlength;
	ext_cipher_limit = (db && db->format) ? db->format->params.plaintext_length : maxlen;
	ext_target_utf8 = (options.target_enc <= CP_UNDEF || options.target_enc == UTF_8);

	/* This is second time we are called, just update the above */
	if (db && db->format)
		return;

	ext_time = (int) time(NULL);

	ext_maxlen = options.req_maxlength;

#if HAVE_REXGEN
	/* Hybrid regex */
	if ((regex = prepare_regex(options.regex, &regex_case, &regex_alpha))) {
		if (maxlen)
			maxlen--;
		if (ext_minlen)
			ext_minlen--;
	}
#endif
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
	f_new = c_lookup("new");
	f_next = c_lookup("next");

	if (f_new && !f_next) {
		if (john_main_process)
			fprintf(stderr,
			    "No next() when new() found for external mode: "
			    "%s\n", mode);
		error();
	}

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
	/* in 'filter' mode, it may be a filter run, OR a hybrid run */
	if ((ext_flags & EXT_REQ_FILTER) && f_next && f_new) {
		; /* next() and new() can be used instead of filter() */
	} else if ((ext_flags & EXT_REQ_FILTER) && !f_filter) {
		if (john_main_process)
			fprintf(stderr,
			    "No filter() for external mode: %s\n", mode);
		error();
	}
	if (f_new && options.flags & FLG_SINGLE_CHK) {
		if (john_main_process)
			fprintf(stderr,
			        "Single mode can't be used with hybrid external mode\n");
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

	if (ext_utf32) {
		enc_to_utf32((UTF32*)ext_word, PLAINTEXT_BUFFER_SIZE,
		             (UTF8*)in, strlen(in));
	} else {
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
	}

	c_execute_fast(f_filter);

	if (!ext_word[0] && in[0]) return 0;

	if (ext_utf32) {
		utf32_to_enc((UTF8*)int_word, maxlen, (UTF32*)ext_word);
	} else {
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
	}
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

static void save_state_hybrid(FILE *file)
{
	unsigned char *ptr;
	ptr = (unsigned char *)hybrid_actual_completed_base_word;
	fprintf(file, "ext-v1\n%u %u %u\n", hybrid_actual_completed_resume,
	        hybrid_actual_completed_total, (unsigned)strlen((char*)ptr));
	while (*ptr)
		fprintf(file, "%d ", (int)*ptr++);
	fprintf(file, "\n");
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

	if (ext_utf32)
		enc_to_utf32((UTF32*)ext_word, PLAINTEXT_BUFFER_SIZE,
		             (UTF8*)int_word, strlen(int_word));
	c_execute(c_lookup("restore"));

	return 0;
}

int ext_restore_state_hybrid(const char *sig, FILE *file)
{
	int tot = -1, ver, c, cnt = 0, count = 0;
	char buf[128+PLAINTEXT_BUFFER_SIZE];
	unsigned char *cp, *internal;
	c_int *external;

	if (strncmp(sig, "ext-v", 5))
		return 1;
	if (sscanf(sig, "ext-v%d", &ver) == 1 && ver == 1) {
		fgetl(buf, sizeof(buf), file);
		if (sscanf(buf, "%d %d %d\n", &hybrid_resume, &tot, &cnt) != 3)
			return 1;
		ext_hybrid_total = -1;
		ext_hybrid_resume = hybrid_resume;
		internal = (unsigned char*)int_word;
		external = ext_word;
		cp = (unsigned char*)int_hybrid_base_word;
		do {
			if (fscanf(file, "%d ", &c) != 1)
				break;
			if (++count >= PLAINTEXT_BUFFER_SIZE) return 1;
			*internal++ = *external++ = *cp++ = c;
		} while (c && cnt != count);
		*internal = 0;
		*external = 0;
		if (cnt != count) return 1;
		if (ext_utf32)
			enc_to_utf32((UTF32*)ext_word, PLAINTEXT_BUFFER_SIZE,
				     (UTF8*)int_word, strlen(int_word));
		c_execute(c_lookup("restore"));
		if (ext_hybrid_total > 0 && ext_hybrid_total == tot)
			hybrid_resume = 0; /* the script handled resuming. */
		return 0;
	}
	return 1;
}

static void fix_state(void)
{
	if (hybrid_rec_word[0]) {
		strcpy(rec_word, hybrid_rec_word);
		rec_seq = hybrid_rec_seq;
		hybrid_rec_word[0] = 0;
		return;
	}
	strcpy(rec_word, int_word);
	rec_seq = seq;
}

void ext_hybrid_fix_state(void)
{
	strcpy(hybrid_rec_word, int_word);
	hybrid_rec_seq = seq;

	hybrid_actual_completed_resume = ext_hybrid_resume;
	hybrid_actual_completed_total  = ext_hybrid_total;
	strcpy(hybrid_actual_completed_base_word, int_hybrid_base_word);
}

void do_external_crack(struct db_main *db)
{
	unsigned char *internal;
	c_int *external;
	int my_words, their_words;

	log_event("Proceeding with external mode: %.100s", ext_mode);

	if (ext_utf32 && ext_target_utf8)
		maxlen = MIN(4 * maxlen, db->format->params.plaintext_length);

	if (rec_restored && john_main_process) {
		fprintf(stderr, "Proceeding with external:%s", ext_mode);
		if (options.rule_stack)
			fprintf(stderr, ", rules-stack:%s", options.rule_stack);
		if (options.req_minlength >= 0 || options.req_maxlength)
			fprintf(stderr, ", lengths: %d-%d",
			        options.eff_minlength + mask_add_len,
			        options.eff_maxlength + mask_add_len);
		fprintf(stderr, "\n");
	}

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

		if (ext_utf32) {
			utf32_to_enc((UTF8*)int_word, maxlen, (UTF32*)ext_word);
		} else {
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
		}
#if HAVE_REXGEN
		if (regex) {
			if (do_regex_hybrid_crack(db, regex, int_word,
			                          regex_case, regex_alpha))
				break;
			ext_hybrid_fix_state();
		} else
#endif
		if (options.flags & FLG_MASK_STACKED) {
			if (do_mask_crack(int_word))
				break;
		} else
		if (crk_process_key(int_word)) break;
	} while (1);

	if (!event_abort)
		progress = 100; /* For reporting DONE after a no-ETA run */

	crk_done();
	rec_done(event_abort);
}


/*
 * NOTE, we do absolutely NO node splitting here.  If running MPI or fork,
 * then each word will only be sent to ONE thread. Thus that thread has
 * to process ALL candidates that the external script will build
 */


extern void(*crk_fix_state)(void);
void(*saved_crk_fix_state)(void);
void save_fix_state(void(*new_crk_fix_state)(void))
{
	saved_crk_fix_state = crk_fix_state;
	crk_fix_state = new_crk_fix_state;
}
void restore_fix_state(void)
{
	crk_fix_state = saved_crk_fix_state;
}

char *external_hybrid_next() {
	char *internal;
	c_int *external;
	c_execute_fast(f_next);
	if (ext_word[0]) {
		if (ext_utf32) {
			utf32_to_enc((UTF8*)int_word, maxlen, (UTF32*)ext_word);
		} else {
			internal = (char *)int_word;
			external = ext_word;
			while (*external)
				*internal++ = *external++;
			*internal = 0;
		}
		return int_word;
	}
	return 0;
}

char *external_hybrid_start(const char *base_word) {
	char *cp, *internal;
	c_int *external;
	strcpy(int_hybrid_base_word, base_word);
	cp = (char*)base_word;
	internal = (char *)int_word;
	external = ext_word;
	while (*cp)
		*internal++ = *external++ = *cp++;
	*internal = 0;
	*external = 0;
	c_execute_fast(f_new);
	return external_hybrid_next();
}

int do_external_hybrid_crack(struct db_main *db, const char *base_word) {
	static int first=1;
	int retval = 0;
	unsigned char *internal, *cp;
	c_int *external;
	int do_load = 1;
	int just_restored = 0;

	/* Save off fix_state to use hybrid fix state */
	save_fix_state(ext_hybrid_fix_state);

	if (first) {
		strcpy(int_hybrid_base_word, base_word);
		rec_init_hybrid(save_state_hybrid);
		crk_set_hybrid_fix_state_func_ptr(ext_hybrid_fix_state);
		first = 0;
		just_restored = rec_restored;
		if (rec_restored) {
			++ext_hybrid_resume;
			if (!hybrid_resume)
				do_load = 0;
		}
	} else {
		ext_hybrid_resume = 0;
	}

	if (do_load) {
		strcpy(int_hybrid_base_word, base_word);
		ext_hybrid_total = -1;
		cp = (unsigned char*)base_word;
		internal = (unsigned char *)int_word;
		external = ext_word;
		while (*cp)
			*internal++ = *external++ = *cp++;
		*internal = 0;
		*external = 0;
	}

	if (hybrid_resume) {
		c_execute_fast(f_new);
		while (hybrid_resume) {
			c_execute_fast(f_next);
			--hybrid_resume;
			if (ext_word[0] == 0) {
				hybrid_resume = 0;
				ext_hybrid_resume = 0;
				restore_fix_state();
				return 0;
			}
		}
	} else if (!just_restored)
		c_execute_fast(f_new);

	/* gets the next word, OR if word[0] is null, this word is done */
	c_execute_fast(f_next);
	while (ext_word[0]) {
		c_int ext_word_0 = ext_word[0];

		if (ext_utf32) {
			utf32_to_enc((UTF8*)int_word, maxlen, (UTF32*)ext_word);
		} else {
			internal = (unsigned char *)int_word;
			external = ext_word;
			while (*external)
				*internal++ = *external++;
			*internal = 0;
		}

		if (options.flags & FLG_MASK_CHK) {
			if (do_mask_crack(int_word)) {
				retval = 1;
				goto out;
			}
		} else if (ext_filter((char*)int_word)) {
			int_word[maxlen] = 0;
			if (crk_process_key((char *)int_word)) {
				retval = 1;
				goto out;
			}
		} else {
			/* Filter skip, and next() skip use the 'same' bail */
			/* out flag (i.e. int_word[0]==0. So since this was */
			/* a filter skip, we just reset ext_word[0] back to */
			/* what it was and continue. We want to just skip   */
			/* the word not break from the entire cracking loop */
			ext_word[0] = ext_word_0;
		}

		/* gets the next word */
		++ext_hybrid_resume;
		c_execute_fast(f_next);

	}
out:;

	restore_fix_state();

	return retval;
}
