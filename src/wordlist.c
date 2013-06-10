/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2009,2013 by Solar Designer
 *
 * Heavily modified by JimF, magnum and maybe by others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#define _POSIX_SOURCE /* for fileno(3) */
#include <stdio.h>
#include <sys/stat.h>
#include "os.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>

#if HAVE_WINDOWS_H
#include "win32_memmap.h"
#undef MEM_FREE
#endif

#include "arch.h"
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
#include "memory.h"

static int dist_rules;

static FILE *word_file = NULL;
static int progress = 0, hund_progress = 0;

static int rec_rule;
static long rec_pos; /* ftell(3) is defined to return a long */
static unsigned long rec_line;

static int rule_number, rule_count;
static unsigned long line_number;
static int length;
static struct rpp_context *rule_ctx;

// used for file in 'memory map' mode
static char *word_file_str, **words;
static unsigned int nWordFileLines;

static struct db_main *_db;

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

		if (!nWordFileLines)
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
		if (!nWordFileLines)
		if (fseek(word_file, rec_pos, SEEK_SET))
			pexit("fseek");
		line_number = rec_line;
	}

	return 0;
}

static int fix_state_delay;

static void fix_state(void)
{
	if (++fix_state_delay < _db->options->max_fix_state_delay)
		return;
	fix_state_delay=0;

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

static int get_progress(int *hundth_perc)
{
	struct stat file_stat;
	long pos;
	int hundredXpercent, percent;

	if (!word_file) {
		*hundth_perc = hund_progress;
		return progress;
	}

	if (word_file == stdin) {
		*hundth_perc = 0;
		return -1;
	}

	if (fstat(fileno(word_file), &file_stat)) pexit("fstat");
	if (nWordFileLines) {
		pos = line_number;
	}
	else {
		if ((pos = ftell(word_file)) < 0) {
#ifdef __DJGPP__
			if (pos != -1)
				pos = 0;
			else
#endif
				pexit("ftell");
		}
	}

	if (nWordFileLines) {
		hundredXpercent = (int)((10000LL * (rule_number *
		                  (long long)nWordFileLines + pos)) /
		                  (rule_count * (long long)nWordFileLines));
	} else {
		hundredXpercent = (int)((10000LL * (rule_number *
		                  (long long)file_stat.st_size + pos)) /
		                  (rule_count * (long long)file_stat.st_size));
	}
	percent = hundredXpercent / 100;
	*hundth_perc = hundredXpercent - (percent*100);
	return percent;
}

static char *dummy_rules_apply(char *word, char *rule, int split, char *last)
{
	return word;
}

static MAYBE_INLINE char *potword(char *line)
{
	char *p;

	p = strchr(line, options.field_sep_char);
	return p ? p + 1 : line;
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
		hash <<= 3; extra <<= 2;
		hash += (unsigned char)p[0];
		if (!p[1]) break;
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

void do_wordlist_crack(struct db_main *db, char *name, int rules)
{
	union {
		char buffer[2][LINE_BUFFER_SIZE + CACHE_BANK_SHIFT];
		ARCH_WORD dummy;
	} aligned;
	char *line = aligned.buffer[0];
	char *last = aligned.buffer[1];
	struct rpp_context ctx;
	char *prerule, *rule, *word;
	char *(*apply)(char *word, char *rule, int split, char *last) = NULL;
	int dist_switch;
	unsigned long my_words, their_words, my_words_left;
	long file_len;
	int i, pipe_input = 0, max_pipe_words = 0, rules_keep = 0;
	int init_once = 1;
#if HAVE_WINDOWS_H
	IPC_Item *pIPC=NULL;
#endif
	char msg_buf[128];
	int forceLoad = 0;
	int dupeCheck = (options.flags & FLG_DUPESUPP) ? 1 : 0;
	int loopBack = (options.flags & FLG_LOOPBACK_CHK) ? 1 : 0;
	char file_line[LINE_BUFFER_SIZE];
	long my_size = 0;
	unsigned int myWordFileLines = 0;
	int maxlength = options.force_maxlength;
	int minlength = (options.force_minlength >= 0) ?
		options.force_minlength : 0;

	log_event("Proceeding with wordlist mode");

	_db = db;

	length = db->format->params.plaintext_length;
	if (options.force_maxlength && options.force_maxlength < length)
		length = options.force_maxlength;

	if (!mem_saving_level &&
	    (dupeCheck || !db->options->max_wordfile_memory))
		forceLoad = 1;

	/* If we did not give a name for loopback mode,
	   we use the active pot file */
	if (loopBack) {
		dupeCheck = 1;
		if (!name)
			name = options.loader.activepot;
	}

	/* If we did not give a name for wordlist mode,
	   we use the "batch mode" one from john.conf */
	if (!name && !(options.flags & (FLG_STDIN_CHK | FLG_PIPE_CHK)))
	if (!(name = cfg_get_param(SECTION_OPTIONS, NULL, "Wordlist")))
	if (!(name = cfg_get_param(SECTION_OPTIONS, NULL, "Wordfile")))
		name = WORDLIST_NAME;

	if (name) {
		char *cp, csearch;
		int ourshare = 0;

		if (loopBack) {
			if (john_main_process)
				fprintf(stderr, "Loop-back mode: Reading "
				        "candidates from pot file %s\n", name);
			log_event("- Using loop-back mode:");
		}

		if (!(word_file = fopen(path_expand(name), "rb")))
			pexit("fopen: %s", path_expand(name));
		log_event("- Wordlist file: %.100s", path_expand(name));

		/* this will both get us the file length, and tell us
		   of 'invalid' files (i.e. too big in Win32 or other
		   32 bit OS's.  A file between 2gb and 4gb returns
		   a negative number.  NOTE john craps out on files
		   this big.  The file needs cut before running through
		   through john */
		fseek(word_file, 0, SEEK_END);
		file_len = ftell(word_file);
		fseek(word_file, 0, SEEK_SET);
		if (file_len < 0)
		{
			if (john_main_process)
				fprintf(stderr, "Error, dictionary file is too"
				        " large for john to read (probably a "
				        "32 bit OS issue)\n");
			error();
		}
		if (file_len == 0)
		{
			if (john_main_process)
				fprintf(stderr, "Error, dictionary file is "
				        "empty\n");
			error();
		}
		if (file_len < db->options->max_wordfile_memory)
			forceLoad = 1;
		/* If the file is < max_wordfile_memory, then we work from a
		   memory map of the file. But this is disabled if we are also
		   using an external filter, as a modification of a word could
		   trash the buffer. It's also disabled by --save-mem=N */
		ourshare = options.node_count ?
			(file_len / options.node_count) *
			(options.node_max - options.node_min + 1)
			: file_len;
		if (options.node_count >= 1000000000)
			ourshare = 0;
		if (options.node_count != 1000000000)
		if (!(options.flags & FLG_EXTERNAL_CHK) && !mem_saving_level)
		if ((options.node_count > 1 &&
		     file_len > options.node_count * (length * 100) &&
		     ourshare < db->options->max_wordfile_memory) ||
		    file_len < db->options->max_wordfile_memory || forceLoad) {
			char *aep;

			// Load only this node's share of words to memory
			if (options.node_count > 1 &&
			    (file_len > options.node_count * (length * 100)
			     && forceLoad)) {
				/* Check net size for our share. */
				for (nWordFileLines = 0;; ++nWordFileLines) {
					char *lp;
					if (!fgets(file_line, sizeof(file_line),
					           word_file))
					{
						if (ferror(word_file))
							pexit("fgets");
						else
							break;
					}
					if (!strncmp(line, "#!comment", 9))
						continue;
					if (loopBack)
						lp = potword(file_line);
					else
						lp = file_line;
					if (!rules) {
						lp[length] = '\n';
						lp[length + 1] = 0;
					}
					{
						int for_node = nWordFileLines % options.node_count + 1;
						int skip = for_node < options.node_min ||
						    for_node > options.node_max;
						if (!skip)
							my_size += strlen(lp);
					}
				}
				fseek(word_file, 0, SEEK_SET);

				// Now copy just our share to memory
				word_file_str = mem_alloc_tiny(my_size + LINE_BUFFER_SIZE + 1, MEM_ALIGN_NONE);
				i = 0;
				for (myWordFileLines = 0;; ++myWordFileLines) {
					char *lp;
					if (!fgets(file_line, sizeof(file_line), word_file)) {
						if (ferror(word_file))
							pexit("fgets");
						else
							break;
					}
					if (!strncmp(line, "#!comment", 9))
						continue;
					if (loopBack)
						lp = potword(file_line);
					else
						lp = file_line;
					if (!rules) {
						lp[length] = '\n';
						lp[length + 1] = 0;
					}
					{
						int for_node = myWordFileLines % options.node_count + 1;
						int skip = for_node < options.node_min ||
						    for_node > options.node_max;
						if (!skip) {
							strcpy(&word_file_str[i], lp);
							i += (int)strlen(lp);
						}
					}
					if (i > my_size) {
						fprintf(stderr, "Error: wordlist grew as we read it - aborting\n");
						error();
					}
				}
				if (nWordFileLines != myWordFileLines)
					fprintf(stderr, "Warning: wordlist changed as we read it\n");
				log_event("- loaded this node's share of wordfile %s into memory "
				          "(%lu bytes of %lu, max_size=%u avg/node)",
				          name, my_size, file_len, db->options->max_wordfile_memory);
				if (john_main_process)
					fprintf(stderr,"Each node loaded 1/%d "
					        "of wordfile to memory (about "
					        "%lu %s/node)\n",
				        options.node_count,
				        my_size > 1<<23 ? my_size >> 20 : my_size >> 10,
				        my_size > 1<<23 ? "MB" : "KB");
				aep = word_file_str + my_size;
				file_len = my_size;
			}
			else {
				log_event("- loading wordfile %s into memory (%lu bytes, max_size=%u)",
				          name, file_len, db->options->max_wordfile_memory);
				if (options.node_count > 1 && john_main_process)
					fprintf(stderr,"Each node loaded the whole wordfile to memory\n");
				word_file_str = mem_alloc_tiny(file_len + LINE_BUFFER_SIZE + 1, MEM_ALIGN_NONE);
				if (fread(word_file_str, 1, file_len, word_file) != file_len) {
					if (ferror(word_file))
						pexit("fread");
					fprintf(stderr, "fread: Unexpected EOF\n");
					error();
				}
				if (memchr(word_file_str, 0, file_len)) {
					fprintf(stderr, "Error: wordlist contains NULL bytes - aborting\n");
					error();
				}
			}
			aep = word_file_str + file_len;
			*aep = 0;
			csearch = '\n';
			cp = memchr(word_file_str, csearch, file_len);
			if (!cp)
			{
				csearch = '\r';
				cp = memchr(word_file_str, csearch, file_len);
			}
			for (nWordFileLines = 0; cp; ++nWordFileLines)
				cp = memchr(&cp[1], csearch, file_len - (cp - word_file_str) - 1);
			if (aep[-1] != csearch)
				++nWordFileLines;
			words = mem_alloc( (nWordFileLines+1) * sizeof(char*));
			log_event("- wordfile had %u lines and required %lu bytes for index.", nWordFileLines, (unsigned long)(nWordFileLines * sizeof(char*)));

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
				log_event("- dupe suppression: hash size %u, temporarily allocating %zd bytes",
				          hash_size,
				          (hash_size * sizeof(unsigned int)) +
				          (nWordFileLines * sizeof(element_st)));
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
					fprintf(stderr, "Warning: wordlist contains inconsequent newlines, some words may be skipped\n");
					log_event("- Warning: wordlist contains inconsequent newlines, some words may be skipped");
					i--;
					break;
				}
				if (loopBack)
					cp = potword(cp);
				ep = cp;
				while ((ep < aep) && *ep && *ep != '\n' && *ep != '\r') ep++;
				ec = *ep;
				*ep = 0;
				if (strncmp(cp, "#!comment", 9)) {
					if (!rules) {
						if (minlength && ep - cp < minlength)
							goto skip;
						/* Over --max-length are skipped,
						   while over format's length are truncated. */
						if (maxlength && ep - cp > maxlength)
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
			if ((long long)nWordFileLines - i > 0)
				log_event("- suppressed %u duplicate lines and/or comments from wordlist.", nWordFileLines - i);
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
		word_file = stdin;
		if (options.flags & FLG_STDIN_CHK) {
			log_event("- Reading candidate passwords from stdin");
		} else {
			pipe_input = 1;
#if HAVE_WINDOWS_H
			if (db->options->sharedmemoryfilename != NULL) {
				init_sharedmem(db->options->sharedmemoryfilename);
				rules_keep = rules;
				max_pipe_words = IPC_MM_MAX_WORDS+2;
				words = mem_alloc(max_pipe_words*sizeof(char*));
				goto MEM_MAP_LOAD;
			}
#endif
			if (db->options->max_wordfile_memory < 0x20000)
				db->options->max_wordfile_memory = 0x20000;
			if (length < 16)
				max_pipe_words = (db->options->max_wordfile_memory/length);
			else
				max_pipe_words = (db->options->max_wordfile_memory/16);

			word_file_str = mem_alloc_tiny(db->options->max_wordfile_memory, MEM_ALIGN_NONE);
			words = mem_alloc(max_pipe_words * sizeof(char*));
			rules_keep = rules;

GRAB_NEXT_PIPE_LOAD:;
#if HAVE_WINDOWS_H
			if (db->options->sharedmemoryfilename != NULL)
				goto MEM_MAP_LOAD;
#endif
			{
				char *cpi, *cpe;

				log_event("- Reading next block of candidate passwords from stdin pipe");

				rules = rules_keep;
				nWordFileLines = 0;
				cpi = word_file_str;
				cpe = (cpi + db->options->max_wordfile_memory) - (LINE_BUFFER_SIZE+1);
				while (nWordFileLines < max_pipe_words) {
					if (!fgetl(cpi, LINE_BUFFER_SIZE, word_file)) {
						pipe_input = 0;
						break;
					}
					if (strncmp(cpi, "#!comment", 9)) {
						int len = strlen(cpi);
						if (!rules) {
							if (minlength && len < minlength) {
								cpi += (len + 1);
								if (cpi > cpe)
									break;
								continue;
							}
							/* Over --max-length are skipped,
							   while over format's length are truncated. */
							if (maxlength && len > maxlength) {
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
				sprintf(msg_buf, "- Read block of %d candidate passwords from pipe", nWordFileLines);
				log_event("%s", msg_buf);
			}
#if HAVE_WINDOWS_H
			goto SKIP_MEM_MAP_LOAD;
MEM_MAP_LOAD:;
			{
				rules = rules_keep;
				nWordFileLines = 0;
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
						words[i] = words[i-1] + pIPC->WordOff[i-1];
					}
				}
			}
SKIP_MEM_MAP_LOAD:;
#endif
		}
	}

	if (rules) {
		if (rpp_init(rule_ctx = &ctx, db->options->activewordlistrules)) {
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

	if (init_once) {
		init_once = 0;

		status_init(get_progress, 0);

		rec_restore_mode(restore_state);
		rec_init(db, save_state);

		crk_init(db, fix_state, NULL);
	}

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

		if (rule && nWordFileLines)
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

				if (ext_filter(word))
				if (crk_process_key(word)) {
					rules = 0;
					pipe_input = 0;
					break;
				}
			}
		}

		else if (rule)
		while (fgetl(line, LINE_BUFFER_SIZE, word_file)) {
			line_number++;

			if (line[0] != '#') {
process_word:
				if (loopBack)
					memmove(line, potword(line),
					        strlen(potword(line)) + 1);

				if (!rules) {
					if (minlength || maxlength) {
						int len = strlen(line);
						if (minlength && len < minlength)
							continue;
						/* --max-length skips */
						if (maxlength && len > maxlength)
							continue;
					}
					line[length] = 0;
				}
				if (!strcmp(line, last))
					continue;

				if ((word = apply(line, rule, -1, last))) {
					strcpy(last, word);

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
			if (!nWordFileLines && word_file != stdin)
			if (fseek(word_file, 0, SEEK_SET))
				pexit("fseek");

			if (their_words &&
			    skip_lines(options.node_min - 1, line))
				break;
		}

		my_words_left = my_words;
	} while (rules);

	if (pipe_input)
		goto GRAB_NEXT_PIPE_LOAD;

	crk_done();
	rec_done(event_abort || (status.pass && db->salts));

	if (ferror(word_file)) pexit("fgets");

	if (name) {
		if (event_abort)
			progress = get_progress(&hund_progress);
		else
			progress = 100;

		MEM_FREE(words);
		if (fclose(word_file)) pexit("fclose");
		word_file = NULL;
	}
}
