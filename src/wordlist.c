/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2009,2013,2017 by Solar Designer
 *
 * Heavily modified by JimF, magnum and maybe by others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#ifndef sparc
#undef _POSIX_SOURCE
#define _POSIX_SOURCE /* for fileno(3) */
#endif
#endif

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "os.h"

#if !AC_BUILT
 #include <string.h>
 #ifndef _MSC_VER
  #include <strings.h>
 #endif
#else
 #if STRING_WITH_STRINGS
  #include <string.h>
  #include <strings.h>
 #elif HAVE_STRING_H
  #include <string.h>
 #elif HAVE_STRINGS_H
  #include <strings.h>
 #endif
#endif

#include <errno.h>

#include "arch.h"
#include "mem_map.h"
#include "memory.h"
#include "jumbo.h"
#include "misc.h"
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
#include "unicode.h"
#include "regex.h"
#include "mask.h"
#include "pseudo_intrinsics.h"
#include "mgetl.h"

static int dist_rules;

static FILE *word_file = NULL;
static double progress = 0;

static int rec_rule;
static int64_t rec_pos;
static int64_t rec_line;
static int hybrid_rec_rule;
static int64_t hybrid_rec_pos;
static int64_t hybrid_rec_line;

static int rule_number, rule_count;
static int64_t line_number, loop_line_no;
static int length;
static struct rpp_context *rule_ctx;

// used for file in 'memory buffer' mode (ready to use array)
static char *word_file_str, **words;
static int64_t nWordFileLines;

static int file_is_fifo;

static void save_state(FILE *file)
{
	fprintf(file, "%d\n%" PRId64 "\n%" PRId64 "\n",
	        rec_rule, (int64_t)rec_pos, (int64_t)rec_line);
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

static MAYBE_INLINE int skip_lines(int64_t n, char *line)
{
	if (n) {
		line_number += n;

		if (!nWordFileLines)
		do {
			if (!GET_LINE(line, word_file))
				return 1;
		} while (--n);
	}

	return 0;
}

static void restore_line_number(void)
{
	union {
		char buffer[LINE_BUFFER_SIZE];
#if MGETL_HAS_SIMD
		vtype dummy;
#else
		ARCH_WORD dummy;
#endif
	} aligned;
	char *line = aligned.buffer;

	if (skip_lines(rec_pos, line)) {
		if (ferror(word_file))
			pexit("fgets");
		fprintf(stderr, "fgets: Unexpected EOF\n");
		error();
	}
}

static int restore_state(FILE *file)
{
	int64_t rule, line, pos;

	if (fscanf(file, "%"PRId64"\n%"PRId64"\n", &rule, &pos) != 2)
		return 1;
	rec_rule = rule;
	rec_pos = pos;
	rec_line = 0;
	if (rec_version >= 4) {
		if (fscanf(file, "%"PRId64"\n", &line) != 1)
			return 1;
		rec_line = line;
	}
	if (rec_rule < 0 || rec_pos < 0)
		return 1;

	if (restore_rule_number())
		return 1;

	if (word_file == stdin || file_is_fifo) {
		restore_line_number();
	} else
	if (!nWordFileLines) {
		if (mem_map) {
			union {
				char buffer[LINE_BUFFER_SIZE];
#if MGETL_HAS_SIMD
				vtype dummy;
#else
				ARCH_WORD dummy;
#endif
			} aligned;
			char *line = aligned.buffer;

			skip_lines(rec_line, line);
			rec_pos = 0;
		} else if (rec_line && !rec_pos) {
			/* from mem_map build does not have rec_pos */
			int64_t i = rec_line;
			char line[LINE_BUFFER_SIZE];
			jtr_fseek64(word_file, 0, SEEK_SET);
			while (i--)
				if (!fgetl(line, sizeof(line), word_file))
					pexit(STR_MACRO(jtr_fseek64));
			rec_pos = jtr_ftell64(word_file);
		} else
		if (jtr_fseek64(word_file, rec_pos, SEEK_SET))
			pexit(STR_MACRO(jtr_fseek64));
		line_number = rec_line;
	}
	else
		line_number = rec_line;

	return 0;
}

static void fix_state(void)
{
	if (hybrid_rec_rule || hybrid_rec_line || hybrid_rec_pos) {
		rec_rule = hybrid_rec_rule;
		rec_line = hybrid_rec_line;
		rec_pos = hybrid_rec_pos;
		hybrid_rec_rule = hybrid_rec_line = hybrid_rec_pos = 0;

		return;
	}

	if (options.flags & FLG_REGEX_CHK)
		return;

	rec_rule = rule_number;
	rec_line = line_number;

	if (word_file == stdin || file_is_fifo)
		rec_pos = line_number;
	else
	if (!mem_map && !nWordFileLines &&
	    (rec_pos = jtr_ftell64(word_file)) < 0) {
#ifdef __DJGPP__
		if (rec_pos != -1)
			rec_pos = 0;
		else
#endif
			pexit(STR_MACRO(jtr_ftell64));
	}
}

void wordlist_hybrid_fix_state(void)
{
	hybrid_rec_rule = rule_number;
	hybrid_rec_line = line_number;

	if (word_file == stdin || file_is_fifo)
		hybrid_rec_pos = line_number;
	else
	if (!mem_map && !nWordFileLines &&
	    (hybrid_rec_pos = jtr_ftell64(word_file)) < 0) {
#ifdef __DJGPP__
		if (hybrid_rec_pos != -1)
			hybrid_rec_pos = 0;
		else
#endif
			pexit(STR_MACRO(jtr_ftell64));
	}
}

static double get_progress(void)
{
	struct stat file_stat;
	int64_t pos;
	uint64_t size;
	uint64_t mask_mult = mask_tot_cand ? mask_tot_cand : 1;

	emms();

	if (progress)
		return progress;

	if (!word_file || word_file == stdin || file_is_fifo)
		return -1;

	if (nWordFileLines) {
		pos = line_number;
		size = nWordFileLines;
	} else if (mem_map) {
		pos = map_pos - mem_map;
		size = map_end - mem_map;
	} else {
		if (fstat(fileno(word_file), &file_stat))
			pexit("fstat");
		pos = jtr_ftell64(word_file);
		jtr_fseek64(word_file, 0, SEEK_END);
		size = jtr_ftell64(word_file);
		jtr_fseek64(word_file, pos, SEEK_SET);

		if (pos < 0) {
#ifdef __DJGPP__
			if (pos != -1)
				pos = 0;
			else
#endif
				pexit(STR_MACRO(jtr_ftell64));
		}
	}

	return (100.0 * ((rule_number * size * mask_mult) + pos * mask_mult) /
	        (rule_count * size * mask_mult));
}

static char *dummy_rules_apply(char *word, char *rule, int split, char *last)
{
	return word;
}

/*
 * There should be legislation against adding a BOM to UTF-8, not to
 * mention calling UTF-16 a "text file".
 */
static MAYBE_INLINE void check_bom(char *line)
{
	if (((unsigned char*)line)[0] < 0xef)
		return;

	if (!memcmp(line, "\xEF\xBB\xBF", 3)) {
		static int warned;

		if (options.input_enc == UTF_8)
			memmove(line, line + 3, strlen(line) - 2);
		else if (!warned++)
			fprintf(stderr, "Warning: UTF-8 BOM seen in wordlist. You probably want --input-encoding=UTF8\n");
	}

	if (options.input_enc == UTF_8  && (!memcmp(line, "\xFE\xFF", 2) || !memcmp(line, "\xFF\xFE", 2))) {
		static int warned;

		if (!warned++)
			fprintf(stderr,
			        "Warning: UTF-16 BOM seen in wordlist. File may not be read properly unless you re-encode it\n");
	}
}

/*
 * This function does two separate things (either or both) just to confuse you.
 * 1. In case we're in loopback mode, skip ciphertext and field separator.
 * 2. Convert to target encoding, if applicable.
 *
 * It does both within the existing buffer - i.e. "right aligned" to the
 * original EOL (the end result is guaranteed to fit).
 */
static MAYBE_INLINE char *convert(char *line)
{
	char *p;

	if (options.flags & FLG_LOOPBACK_CHK) {
		if ((p = strchr(line, options.loader.field_sep_char)))
			line = p + 1;
		else
			line += strlen(line);
	}

	if (options.input_enc != options.target_enc) {
		UTF16 u16[LINE_BUFFER_SIZE + 1];
		char *cp, *s, *d;
		char e;
		int len;

		len = strcspn(line, "\n\r");
		e = line[len];
		line[len] = 0;
		utf8_to_utf16(u16, LINE_BUFFER_SIZE, (UTF8*)line, len);
		line[len] = e;
		cp = utf16_to_cp(u16);
		d = &line[len];
		s = &cp[strlen(cp)];
		while (s > cp)
			*--d = *--s;
		line = d;
	}
	return line;
}

static unsigned int hash_log, hash_size, hash_mask;
#define ENTRY_END_HASH	0xFFFFFFFF
#define ENTRY_END_LIST	0xFFFFFFFE

/* Copied from unique.c (and modified) */
static MAYBE_INLINE unsigned int line_hash(char *line)
{
	unsigned int hash, extra;
	char *p;

	p = line + 2;
	hash = (unsigned char)line[0];
	if (!hash)
		goto out;
	extra = (unsigned char)line[1];
	if (!extra)
		goto out;

	while (*p) {
		hash <<= 5;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
		extra *= hash | 1812433253;
		extra += (unsigned char)p[1];
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> hash_log;
			extra ^= extra >> hash_log;
			hash &= hash_mask;
		}
	}

	hash -= extra;
	hash ^= extra << (hash_log / 2);

	hash ^= hash >> hash_log;

out:
	hash &= hash_mask;
	return hash;
}

typedef struct {
	unsigned int next;
	unsigned int line;
} element_st;

static struct {
	unsigned int *hash;
	element_st *data;
} buffer;

static MAYBE_INLINE int wbuf_unique(char *line)
{
	static unsigned int index = 0;
	unsigned int current, last, linehash;

	linehash = line_hash(line);
	current = buffer.hash[linehash];
	last = current;
	while (current != ENTRY_END_HASH) {
		if (!strcmp(line, word_file_str + buffer.data[current].line))
			break;
		last = current;
		current = buffer.data[current].next;
	}
	if (current != ENTRY_END_HASH)
		return 0;

	if (last == ENTRY_END_HASH)
		buffer.hash[linehash] = index;
	else
		buffer.data[last].next = index;

	buffer.data[index].line = line - word_file_str;
	buffer.data[index].next = ENTRY_END_HASH;
	index++;

	return 1;
}

void do_wordlist_crack(struct db_main *db, const char *name, int rules)
{
	union {
		char buffer[2][LINE_BUFFER_SIZE + CACHE_BANK_SHIFT];
#if MGETL_HAS_SIMD
		vtype dummy;
#else
		ARCH_WORD dummy;
#endif
	} aligned;
	char *line = aligned.buffer[0];
	char *last = aligned.buffer[1];
	struct rpp_context ctx;
	char *prerule="", *rule="", *word="";
	char *(*apply)(char *word, char *rule, int split, char *last) = NULL;
	int dist_switch=0;
	uint64_t my_words=0, their_words=0, my_words_left=0;
	int64_t i, file_len = 0;
	int pipe_input = 0, max_pipe_words = 0, rules_keep = 0;
	int init_once = 1;
#if HAVE_WINDOWS_H
	IPC_Item *pIPC=NULL;
#endif
	char msg_buf[128];
	int forceLoad = 0, default_wordlist = 0;
	int dupeCheck = (options.flags & FLG_DUPESUPP) ? 1 : 0;
	int loopBack = (options.flags & FLG_LOOPBACK_CHK) ? 1 : 0;
	int do_lmloop = loopBack && db->plaintexts->head;
	uint64_t my_size = 0;
	uint64_t myWordFileLines = 0;
	int skip_length = options.force_maxlength;
	int min_length = options.eff_minlength;
#if HAVE_REXGEN
	char *regex_alpha = 0;
	int regex_case = 0;
	char *regex = 0;
#endif

	if (john_main_process)
		log_event("Proceeding with %s mode",
		          loopBack ? "loopback" : "wordlist");

	if (options.activewordlistrules && john_main_process) {
		if (loopBack)
			fprintf(stderr, "Permutation rules: %s\n",
			        options.activewordlistrules);
		log_event("- Rules: %.100s", options.activewordlistrules);
	}

#if HAVE_REXGEN
	regex = prepare_regex(options.regex, &regex_case, &regex_alpha);
#endif

	length = options.eff_maxlength;

	/* If we did not give a name for loopback mode,
	   we use the active pot file */
	if (loopBack && !name)
		name = options.wordlist = options.activepot;

	/* These will ignore --save-memory */
	if (loopBack || dupeCheck ||
	    (!options.max_wordfile_memory &&
	     (options.flags & FLG_RULES_CHK)))
		forceLoad = 1;

	/* If we did not give a name for wordlist mode,
	   we use the "batch mode" one from john.conf */
	if (!name && !(options.flags & (FLG_STDIN_CHK | FLG_PIPE_CHK))) {
		/* Print what file --wordlist mode uses when it runs using the
		   pre-configured wordlist (optional parameter not informed) */
		default_wordlist = 1;
		if (!(name = cfg_get_param(SECTION_OPTIONS, NULL, "Wordlist")))
		if (!(name = cfg_get_param(SECTION_OPTIONS, NULL, "Wordfile")))
			name = options.wordlist = WORDLIST_NAME;
	}

	static unsigned int prev_g;
	static unsigned long long prev_p;
	if (rules && cfg_get_bool(SECTION_OPTIONS, NULL, "PerRuleStats", 0)) {
		rules = 2;
		prev_g = status.guess_count;
		prev_p = status.cands;
	}

	if (((options.flags & FLG_BATCH_CHK) || rec_restored || default_wordlist) && john_main_process) {
		fprintf(stderr, "Proceeding with wordlist:%s",
		        loopBack ? "loopback" :
		        name ? path_expand(name) : "stdin");
		if (options.flags & FLG_RULES_CHK) {
			if (options.rule_stack)
				fprintf(stderr, ", rules:(%s x %s)",
				        options.activewordlistrules, options.rule_stack);
			else
				fprintf(stderr, ", rules:%s", options.activewordlistrules);
		} else if (options.rule_stack)
			fprintf(stderr, ", rules-stack:%s", options.rule_stack);
		if (options.flags & FLG_MASK_CHK)
			fprintf(stderr, ", hybrid mask:%s", options.mask ?
			        options.mask : options.eff_mask);
		if (options.req_minlength >= 0 || options.req_maxlength)
			fprintf(stderr, ", lengths: %d-%d",
			        options.eff_minlength + mask_add_len,
			        options.eff_maxlength + mask_add_len);
		fprintf(stderr, "\n");
	}

	if (name) {
		struct stat st;

		if (!(word_file = jtr_fopen(path_expand(name), "rb")))
			pexit(STR_MACRO(jtr_fopen)": %s", path_expand(name));

		if (fstat(fileno(word_file), &st))
			pexit("fstat");

		file_is_fifo = ((st.st_mode & S_IFMT) == S_IFIFO);

		if (john_main_process)
			log_event("- %s %s: %.100s", loopBack ? "Loopback pot" : "Wordlist",
			          file_is_fifo ? "FIFO" : "file",
			          path_expand(name));
	} else
		file_is_fifo = 0;

	if (name && !file_is_fifo) {
		char *cp, csearch;
		int64_t ourshare = 0;
#ifdef HAVE_MMAP
		int mmap_max =
			cfg_get_int(SECTION_OPTIONS, NULL,
			            "WordlistMemoryMapMaxSize");

		if (mmap_max == -1)
			mmap_max = 1 << 10;
#endif
		jtr_fseek64(word_file, 0, SEEK_END);
		if ((file_len = jtr_ftell64(word_file)) == -1)
			pexit(STR_MACRO(jtr_ftell64));
		jtr_fseek64(word_file, 0, SEEK_SET);
		if (file_len == 0 && !loopBack) {
			if (john_main_process)
				fprintf(stderr, "Error, dictionary file is "
				        "empty\n");
			error();
		}

#ifdef HAVE_MMAP
		if (mmap_max && mmap_max >= (file_len >> 20)) {
			if (john_main_process)
				log_event("- memory mapping wordlist (%"PRId64" bytes)",
				          (int64_t)file_len);
#if (SIZEOF_SIZE_T < 8)
/*
 * Now even though we are 64 bit file size, we must still deal with some
 * 32 bit functions ;)
 */
			mem_map = MAP_FAILED;
			if (file_len < ((1LL)<<32))
#endif
			mem_map = mmap(NULL, file_len,
			               PROT_READ, MAP_SHARED,
			               fileno(word_file), 0);
			if (mem_map == MAP_FAILED) {
				mem_map = NULL;
#ifdef DEBUG
				fprintf(stderr, "wordlist: memory mapping failed (%s) (non-fatal)\n",
				        strerror(errno));
#endif
				log_event("- memory mapping failed (%s) - but we'll do fine without it.",
				          strerror(errno));
			} else {
				map_pos = mem_map;
				map_end = mem_map + file_len;
				map_scan_end = map_end - VSCANSZ;
			}
		}
#endif

		ourshare = options.node_count ?
			(file_len / options.node_count) *
			(options.node_max - options.node_min + 1)
			: file_len;

		if (ourshare < options.max_wordfile_memory &&
		    mem_saving_level < 2 &&
		    (options.flags & FLG_RULES_CHK))
			forceLoad = 1;

		/* If it's worth it we make a ready-to-use buffer with the
		   (possibly converted) contents ready to use as an array.
		   Disabled for external filter - it would trash the buffer. */
		if (!(options.flags & FLG_EXTERNAL_CHK) && forceLoad) {
			char *aep;

			// Load only this node's share of words to memory
			if (mem_map && options.node_count > 1 &&
			    (file_len > options.node_count * (length * 100))) {
				/* Check net size for our share. */
				for (nWordFileLines = 0;; ++nWordFileLines) {
					char *lp;
					int for_node = nWordFileLines %
						options.node_count + 1;
					int skip =
						for_node < options.node_min ||
						for_node > options.node_max;

					if (!mgetl(line))
						break;
					check_bom(line);
					if (!strncmp(line, "#!comment", 9))
						continue;
					lp = convert(line);
					if (!rules)
						lp[length] = 0;
					if (!skip)
						my_size += strlen(lp) + 1;
				}
				map_pos = mem_map;

				// Now copy just our share to memory
				word_file_str =
					mem_alloc_tiny(my_size +
					               LINE_BUFFER_SIZE + 1,
					               MEM_ALIGN_NONE);
				i = 0;
				for (myWordFileLines = 0;; ++myWordFileLines) {
					char *lp;
					int for_node = myWordFileLines %
						options.node_count + 1;
					int skip =
						for_node < options.node_min ||
						for_node > options.node_max;

					if (!mgetl(line))
						break;
					check_bom(line);
					if (!strncmp(line, "#!comment", 9))
						continue;
					lp = convert(line);
					if (!rules)
						lp[length] = 0;
					if (!skip) {
						strcpy(&word_file_str[i], lp);
						i += strlen(lp);
						word_file_str[i++] = '\n';
					}
					if (i > my_size) {
						fprintf(stderr,
						        "Error: wordlist grew "
						        "as we read it - "
						        "aborting\n");
						error();
					}
				}
				if (nWordFileLines != myWordFileLines)
					fprintf(stderr, "Warning: wordlist changed as"
					        " we read it\n");
				log_event("- loaded this node's share of "
				          "wordfile %s into memory "
				          "(%"PRIu64" bytes of %"PRId64", max_size="Zu
				          " avg/node)", name, my_size,
				          (int64_t)file_len,
				          options.max_wordfile_memory);
				if (john_main_process)
				fprintf(stderr,"Each node loaded 1/%d "
				        "of wordfile to memory (about "
				        "%"PRIu64" %s/node)\n",
				        options.node_count,
				        my_size > 1<<23 ?
				        my_size >> 20 : my_size >> 10,
				        my_size > 1<<23 ? "MB" : "KB");
				file_len = my_size;
			}
			else {
				if (john_main_process) {
					log_event("- loading wordfile %s into memory "
					          "(%"PRId64" bytes, max_size="Zu")",
					          name, (int64_t)file_len,
					          options.max_wordfile_memory);
					if (options.node_count > 1)
						fprintf(stderr,"Each node loaded the whole "
						        "wordfile to memory\n");
				}
				word_file_str =
					mem_alloc_tiny((size_t)file_len +
					               LINE_BUFFER_SIZE + 1,
					               MEM_ALIGN_NONE);
				if (fread(word_file_str, 1, (size_t)file_len,
				          word_file) != file_len) {
					if (ferror(word_file))
						pexit("fread");
					fprintf(stderr,
					        "fread: Unexpected EOF\n");
					error();
				}
				if (memchr(word_file_str, 0, (size_t)file_len)) {
					static int warned;

					if (!warned++)
						fprintf(stderr, "Warning: Wordlist contains NUL bytes, lines may be truncated.\n");
				}
			}
			aep = word_file_str + file_len;
			*aep = 0;
			csearch = '\n';
			cp = memchr(word_file_str, csearch, (size_t)file_len);
			if (!cp)
			{
				csearch = '\r';
				cp = memchr(word_file_str, csearch, (size_t)file_len);
			}
			for (nWordFileLines = 0; cp; ++nWordFileLines)
				cp = memchr(&cp[1], csearch, (size_t)(file_len -
				            (cp - word_file_str) - 1));
			if (aep[-1] != csearch)
				++nWordFileLines;
			words = mem_alloc((nWordFileLines + 1) * sizeof(char*));
			log_event("- wordfile had %"PRId64" lines and required %"PRId64
			          " bytes for index.",
			          (int64_t)nWordFileLines,
			          (int64_t)(nWordFileLines * sizeof(char*)));

			i = 0;
			cp = word_file_str;

			if (csearch == '\n')
				while (*cp == '\r') cp++;

			if (dupeCheck) {
				hash_log = 1;
				while (((1 << hash_log) < (nWordFileLines))
				       && hash_log < 27)
					hash_log++;
				hash_size = (1 << hash_log);
				hash_mask = (hash_size - 1);
				log_event("- dupe suppression: hash size %u, "
					"temporarily allocating %"PRId64" bytes",
					hash_size,
					(hash_size * sizeof(unsigned int)) +
					((int64_t)nWordFileLines *
					 sizeof(element_st)));
				buffer.hash = mem_alloc(hash_size *
				                        sizeof(unsigned int));
				buffer.data = mem_alloc(nWordFileLines *
				                        sizeof(element_st));
				memset(buffer.hash, 0xff, hash_size *
				       sizeof(unsigned int));
			}

			do
			{
				char *ep, ec;
				if (i > nWordFileLines) {
					fprintf(stderr, "Warning: wordlist "
					        "contains inconsequent "
					        "newlines, some words may be "
					        "skipped\n");
					log_event("- Warning: wordlist contains"
					          " inconsequent newlines, some"
					          " words may be skipped");
					i--;
					break;
				}
				if (!myWordFileLines) {
					check_bom(cp);
					cp = convert(cp);
				}
				ep = cp;
				while ((ep < aep) && *ep && *ep != '\n' && *ep != '\r')
					ep++;
				ec = *ep;
				*ep = 0;
				if (strncmp(cp, "#!comment", 9)) {
					if (!rules) {
						if (min_length && ep - cp < min_length)
							goto skip;
						/*
						 * Over --max-length are always skipped, while over
						 * format's length are truncated if FMT_TRUNC.
						 */
						if (skip_length && ep - cp > skip_length)
							goto skip;
						if (ep - cp >= length)
							cp[length] = 0;
					} else
						if (ep - cp >= LINE_BUFFER_SIZE)
							cp[LINE_BUFFER_SIZE-1] = 0;
					if (dupeCheck) {
						/* Full suppression of dupes
						   after truncation */
						if (wbuf_unique(cp))
							words[i++] = cp;
					} else {
						/* Just suppress consecutive
						   candidates */
						if (!i || strcmp(cp, words[i-1]))
							words[i++] = cp;
					}
				}
skip:
				cp = ep + 1;
				if (ec == '\r' && *cp == '\n') cp++;
				if (ec == '\n' && *cp == '\r') cp++;
			} while (cp < aep);
			if ((int64_t)nWordFileLines - i > 0)
				log_event("- suppressed %"PRId64" duplicate lines "
				          "and/or comments from wordlist.",
				          (int64_t)nWordFileLines - i);
			MEM_FREE(buffer.hash);
			MEM_FREE(buffer.data);
			nWordFileLines = i;
		}
	} else {
/*
 * Ok, we can be in --stdin or --pipe mode.  In --stdin, we simply copy over
 * the stdin file handle, and deal with it like a 'normal' word_file file (one
 * line at a time.  For --pipe mode, we read up to mem-buffer size, but that
 * may not be the end. We then set a value, so that when we are 'done' in the
 * loop, we jump back up.  Doing this, allows --pipe to have rules run on them.
 * in --stdin mode, we can NOT perform rules, due to we can not fseek stdin in
 * most OS's.
 */
		if (!file_is_fifo)
			word_file = stdin;

		if (options.flags & FLG_STDIN_CHK) {
			log_event("- Reading candidate passwords from stdin");
		} else {
			pipe_input = 1;
#if HAVE_WINDOWS_H
			if (options.sharedmemoryfilename != NULL) {
				init_sharedmem(options.sharedmemoryfilename);
				rules_keep = rules;
				max_pipe_words = IPC_MM_MAX_WORDS+2;
				words = mem_alloc(max_pipe_words*sizeof(char*));
				goto MEM_MAP_LOAD;
			}
#endif
			if (options.max_wordfile_memory < 0x20000)
				options.max_wordfile_memory = 0x20000;
			if (length < 16)
				max_pipe_words = (options.max_wordfile_memory/length);
			else
				max_pipe_words = (options.max_wordfile_memory/16);

			word_file_str = mem_alloc_tiny(options.max_wordfile_memory, MEM_ALIGN_NONE);
			words = mem_alloc(max_pipe_words * sizeof(char*));
			rules_keep = rules;

			init_once = 0;

			status_init(get_progress, 0);

			rec_restore_mode(restore_state);
			rec_init(db, save_state);

			crk_init(db, fix_state, NULL);

GRAB_NEXT_PIPE_LOAD:
#if HAVE_WINDOWS_H
			if (options.sharedmemoryfilename != NULL)
				goto MEM_MAP_LOAD;
#endif
			{
				char *cpi, *cpe;

				if (options.verbosity >= VERB_DEBUG)
				log_event("- Reading next block of candidate passwords from stdin pipe");

				rules = rules_keep;
				nWordFileLines = 0;
				cpi = word_file_str;
				cpe = (cpi + options.max_wordfile_memory) - (LINE_BUFFER_SIZE + 1);
				while (nWordFileLines < max_pipe_words) {
					if (!fgetl(cpi, LINE_BUFFER_SIZE, word_file)) {
						pipe_input = 0;
						break;
					}
					check_bom(cpi);
					cpi = convert(cpi);
					if (strncmp(cpi, "#!comment", 9)) {
						int len = strlen(cpi);
						if (!rules) {
							if (min_length && len < min_length) {
								cpi += (len + 1);
								if (cpi > cpe)
									break;
								continue;
							}
							/*
							 * Over --max-length are always skipped, while over
							 * format's length are truncated if FMT_TRUNC.
							 */
							if (skip_length && len > skip_length) {
								cpi += (len + 1);
								if (cpi > cpe)
									break;
								continue;
							}
							cpi[length] = 0;
							if (!nWordFileLines || strcmp(cpi, words[nWordFileLines-1])) {
								words[nWordFileLines++] = cpi;
								cpi += (len + 1);
								if (cpi > cpe)
									break;
							}
						} else {
							words[nWordFileLines++] = cpi;
							cpi += (len + 1);
							if (cpi > cpe)
								break;
						}
					}
				}
				if (options.verbosity >= VERB_DEBUG) {
					sprintf(msg_buf, "- Read block of %"PRId64" "
					        "candidate passwords from pipe",
					        (int64_t)nWordFileLines);
					log_event("%s", msg_buf);
				}
			}
#if HAVE_WINDOWS_H
			goto SKIP_MEM_MAP_LOAD;
MEM_MAP_LOAD:
			rules = rules_keep;
			nWordFileLines = 0;
			if (options.verbosity == VERB_DEBUG)
				log_event("- Reading next block of candidate from the memory mapped file");
			release_sharedmem_object(pIPC);
			pIPC = next_sharedmem_object();
			if (!pIPC || pIPC->n == 0) {
				pipe_input = 0;
				shutdown_sharedmem();
				goto EndOfFile;
			} else {
				int i;
				nWordFileLines = pIPC->n;
				words[0] = pIPC->Data;
				for (i = 1; i < nWordFileLines; ++i) {
					words[i] =
						words[i-1] + pIPC->WordOff[i-1];
				}
			}
SKIP_MEM_MAP_LOAD:
			; /* Needed for the label */
#endif
		}
	}

REDO_AFTER_LMLOOP:

	if (rules) {
		if (rpp_init(rule_ctx = &ctx, options.activewordlistrules)) {
			if (john_main_process) {
				log_event("! No \"%s\" mode rules found",
				          options.activewordlistrules);
				fprintf(stderr, "No \"%s\" mode rules found in %s\n",
				        options.activewordlistrules, cfg_name);
			}
			error();
		}

		rules_init(db, length);
		rule_count = rules_count(&ctx, -1);

		if (do_lmloop || !db->plaintexts->head) {
			if (rules_stacked_after)
				log_event("- Total %u (%d x %u) preprocessed word mangling rules",
				          rule_count * crk_stacked_rule_count,
				          rule_count, crk_stacked_rule_count);
			else
				log_event("- %d preprocessed word mangling rules", rule_count);
		}


		apply = rules_apply;
	} else {
		rule_ctx = NULL;
		rule_count = 1;

		if (john_main_process)
			log_event("- No word mangling rules");

		apply = dummy_rules_apply;
	}

	rule_number = 0;
	line_number = 0;
	loop_line_no = 0;

	if (init_once) {
		init_once = 0;
		rpp_real_run = 1;

		status_init(get_progress, 0);

		rec_restore_mode(restore_state);
		if (do_lmloop && ((nWordFileLines && rec_line) ||
		                  (!nWordFileLines && rec_pos)))
			do_lmloop = 0;
		rec_init(db, save_state);

		crk_init(db, fix_state, NULL);
	}

	prerule = rule = "";
	if (rules)
		prerule = rpp_next(&ctx);

/* A string that can't be produced by fgetl(). */
	last = aligned.buffer[1];
	last[0] = '\n';
	last[1] = 0;

	dist_rules = 0;
	dist_switch = rule_count; /* never */
	my_words = ~0UL; /* all */
	their_words = 0;
	/* myWordFileLines indicates we already have OUR share of words in
	   memory buffer, so no further skipping. */
	if (options.node_count && !myWordFileLines) {
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
		if (john_main_process)
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
		struct list_entry *joined;

		if (rules) {
			if (dist_rules && strncmp(prerule, "!!", 2)) {
				int for_node =
				    rule_number % options.node_count + 1;
				if (for_node < options.node_min ||
				    for_node > options.node_max)
					goto next_rule;
			}
			if ((rule = rules_reject(prerule, -1, last, db))) {
				if (strcmp(prerule, rule)) {
					if (!rules_mute)
					log_event("- Rule #%d: '%.100s'"
						" accepted as '%.100s'",
						rule_number + 1, prerule, rule);
				} else {
					if (!rules_mute)
					log_event("- Rule #%d: '%.100s'"
						" accepted",
						rule_number + 1, prerule);
				}
			} else {
				if (!rules_mute && strncmp(prerule, "!!", 2))
					log_event("- Rule #%d: '%.100s' rejected",
					          rule_number + 1, prerule);
				goto next_rule;
			}
		}

		/* Process loopback LM passwords that were put together
		   at start of session */
		if (rule && do_lmloop && (joined = db->plaintexts->head))
		do {
			if (options.node_count && !dist_rules) {
				int for_node = loop_line_no %
					options.node_count + 1;
				int skip = for_node < options.node_min
					|| for_node > options.node_max;
				if (skip) {
					loop_line_no++;
					continue;
				}
			}
			loop_line_no++;
			if ((word = apply(joined->data, rule, -1, last))) {
				last = word;
#if HAVE_REXGEN
				if (regex) {
					if (do_regex_hybrid_crack(db, regex,
					                          word,
					                          regex_case,
					                          regex_alpha))
					{
						rule = NULL;
						rules = 0;
						pipe_input = 0;
						do_lmloop = 0;
						break;
					}
					wordlist_hybrid_fix_state();
				} else
#endif
				if (f_new) {
					if (do_external_hybrid_crack(db, word))
					{
						rule = NULL;
						rules = 0;
						pipe_input = 0;
						do_lmloop = 0;
						break;
					}
					wordlist_hybrid_fix_state();
				} else
				if (options.flags & FLG_MASK_CHK) {
					if (do_mask_crack(word)) {
						rule = NULL;
						rules = 0;
						pipe_input = 0;
						do_lmloop = 0;
						break;
					}
				} else
				if (ext_filter(word))
				if (crk_process_key(word)) {
					rule = NULL;
					rules = 0;
					pipe_input = 0;
					do_lmloop = 0;
					break;
				}
			}
		} while ((joined = joined->next));

		else if (rule && nWordFileLines)
		while (line_number < nWordFileLines) {
			if (options.node_count && !myWordFileLines)
			if (!dist_rules) {
				int for_node = line_number %
					options.node_count + 1;
				int skip = for_node < options.node_min ||
					for_node > options.node_max;
				if (skip) {
					line_number++;
					continue;
				}
			}
#if ARCH_ALLOWS_UNALIGNED
			line = words[line_number];
#else
			strcpy(line, words[line_number]);
#endif
			line_number++;

			if ((word = apply(line, rule, -1, last))) {
				last = word;
#if HAVE_REXGEN
				if (regex) {
					if (do_regex_hybrid_crack(db, regex,
					                          word,
					                          regex_case,
					                          regex_alpha))
					{
						rule = NULL;
						rules = 0;
						pipe_input = 0;
						break;
					}
					wordlist_hybrid_fix_state();
				} else
#endif
				if (f_new) {
					if (do_external_hybrid_crack(db, word))
					{
						rule = NULL;
						rules = 0;
						pipe_input = 0;
						break;
					}
					wordlist_hybrid_fix_state();
				} else
				if (options.flags & FLG_MASK_CHK) {
					if (do_mask_crack(word)) {
						rule = NULL;
						rules = 0;
						pipe_input = 0;
						break;
					}
				} else
				if (ext_filter(word))
				if (crk_process_key(word)) {
					rules = 0;
					pipe_input = 0;
					break;
				}
			}
		}

		else if (rule)
		while (GET_LINE(line, word_file)) {

			line_number++;
			check_bom(line);

			if (line[0] != '#') {
process_word:
				if (options.input_enc != options.target_enc
				    || loopBack) {
					char *conv = convert(line);
					int len = strlen(conv);
					memmove(line, conv, len + 1);
				}
				if (!rules) {
					if (min_length || skip_length) {
						int len = strlen(line);
						if (min_length && len < min_length)
							goto next_word;
						/*
						 * Over --max-length are always skipped, while over
						 * format's length are truncated if FMT_TRUNC.
						 */
						if (skip_length && len > skip_length)
							goto next_word;
					}
					line[length] = 0;

					if (!strcmp(line, last))
						goto next_word;
				}

				if ((word = apply(line, rule, -1, last))) {
					if (rules)
						last = word;
					else
						strcpy(last, word);
#if HAVE_REXGEN
					if (regex) {
						if (do_regex_hybrid_crack(
							    db, regex, word,
							    regex_case,
							    regex_alpha)) {
							rule = NULL;
							rules = 0;
							pipe_input = 0;
							break;
						}
						wordlist_hybrid_fix_state();
					} else
#endif
					if (f_new) {
						if (do_external_hybrid_crack(db, word))
						{
							rule = NULL;
							rules = 0;
							pipe_input = 0;
							break;
						}
						wordlist_hybrid_fix_state();
					} else
					if (options.flags & FLG_MASK_CHK) {
						if (do_mask_crack(word)) {
							rule = NULL;
							rules = 0;
							pipe_input = 0;
							break;
						}
					} else
					if (ext_filter(word))
					if (crk_process_key(word)) {
						rules = 0;
						pipe_input = 0;
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

#if HAVE_WINDOWS_H
EndOfFile:
#endif
		if (rules) {
next_rule:
			if (rules > 1 && prerule) {
				unsigned int g = status.guess_count - prev_g;
				unsigned long long p = status.cands - prev_p;
				double score = p ? (g ? (double)g * g : 1e-9) / (double)p : 0;
				double pg = (double)(p ? p : 1e9) / (g ? g : 1e-9);
				log_event("- Score %.18f for %.2f p/g %ug %llup during rule #%d :%.100s",
					score, pg, g, p, rule_number + 1, prerule);
				prev_g = status.guess_count;
				prev_p = status.cands;
			}

			if (!(rule = rpp_next(&ctx))) break;
			rule_number++;

			if (options.node_count && rule_number >= dist_switch) {
				log_event("- Switching to distributing words");
				dist_rules = 0;
				dist_switch = rule_count; /* not anymore */
				my_words =
				    options.node_max - options.node_min + 1;
				their_words = options.node_count - my_words;
			}

			line_number = 0;
			if (!nWordFileLines && word_file != stdin && !file_is_fifo) {
				if (mem_map)
					map_pos = mem_map;
				else
				if (jtr_fseek64(word_file, 0, SEEK_SET))
					pexit(STR_MACRO(jtr_fseek64));
			}
			if (their_words &&
			    skip_lines(options.node_min - 1, line))
				break;
		}

		my_words_left = my_words;
	} while (rules);

	if (do_lmloop && !event_abort) {
		log_event("- Done with reassembled LM halves");
		do_lmloop = 0;
		goto REDO_AFTER_LMLOOP;
	}

	if (pipe_input)
		goto GRAB_NEXT_PIPE_LOAD;

	crk_done();
	rec_done(event_abort || (status.pass && db->salts));

	if (ferror(word_file)) pexit("fgets");

	if (max_pipe_words)  // pipe_input was already cleared.
		MEM_FREE(words);

	if (name) {
		if (!event_abort)
			progress = 100;
		else
			progress = get_progress();

		MEM_FREE(words);
#ifdef HAVE_MMAP
		if (mem_map)
			munmap(mem_map, file_len);
		map_pos = map_end = NULL;
#endif
		if (fclose(word_file))
			pexit("fclose");
		word_file = NULL;
	}
}
