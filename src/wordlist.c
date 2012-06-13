/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2003,2004,2006,2009 by Solar Designer
 *
 * Heavily modified by JimF, magnum and maybe by others.
 */

#define _POSIX_SOURCE /* for fileno(3) */

#include <stdio.h>
#include <sys/stat.h>
#ifndef _MSC_VER
#include <unistd.h>
#include <strings.h>
#else
#pragma warning ( disable : 4996 )
#endif
#include <string.h>

#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
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
#include "rpp.h"
#include "rules.h"
#include "external.h"
#include "cracker.h"
#include "memory.h"
#include "options.h"

#ifdef HAVE_MPI
#include "john-mpi.h"

static int distributeWords, distributeRules, myrulecount;
#endif

static FILE *word_file = NULL;
static int progress = 0, hund_progress = 0;

static int rec_rule;
static long rec_pos;

static int rule_number, rule_count, line_number;
static int length;
static struct rpp_context *rule_ctx;

// used for file in 'memory map' mode
static char *word_file_str, **words;

static unsigned int nWordFileLines, nCurLine;

static struct db_main *_db;

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
		if (ferror(word_file))
			pexit("fgets");
		else {
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
	else {
		if (nWordFileLines) {
			for (nCurLine = 0; nCurLine < nWordFileLines; ++nCurLine) {
				if (words[nCurLine] - words[0] >= rec_pos)
					break;
			}
		}
		else {
			if (fseek(word_file, rec_pos, SEEK_SET)) pexit("fseek");
#ifdef HAVE_MPI
			line_number = rec_pos ? mpi_id : 0;    // we just need the correct modulus
#endif
		}
	}

	return 0;
}

static int fix_state_delay;

static void fix_state(void)
{
	if (nWordFileLines) {
		rec_rule = rule_number;
		if (nCurLine)
			rec_pos = words[nCurLine-1] - words[0];
		else
			rec_pos = words[nCurLine] - words[0];
		return;
	}

	if (++fix_state_delay < _db->options->max_fix_state_delay)
		return;
	fix_state_delay=0;

	rec_rule = rule_number;

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
#ifndef HAVE_MPI
	double x100, tmp;
#endif

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
		pos = rec_pos;
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

#ifdef HAVE_MPI
	if (distributeRules)
		hundredXpercent = (int)((long long)(10000 * (rule_number / mpi_p * file_stat.st_size + pos)) /
		                        (long long)(myrulecount * file_stat.st_size));
	else
		hundredXpercent = (int)((long long)(10000 * (rule_number * file_stat.st_size + pos)) /
		                        (long long)(rule_count * file_stat.st_size));
#else
	x100 = ((double)pos) * 10000.;
	// a double 'tmp' var is required, as I have seen the compiler
	// optimize away the next statement if assigned to an int
	tmp = (((double)rule_number)*10000. + x100/(file_stat.st_size+1)) / rule_count;
	// safe int assignment.  tmp will be from 0 to 10000.00
	hundredXpercent = (int)tmp;
#endif
	percent = hundredXpercent / 100;
	*hundth_perc = hundredXpercent - (percent*100);
	return percent;
}

static char *dummy_rules_apply(const char *word, char *rule, int split, char *last)
{
	return (char*)word;
}

static inline const char *potword(const char *line)
{
	const char *p;

	p = strchr(line, options.field_sep_char);
	return p ? p + 1 : line;
}

static int hash_log, hash_size, hash_mask;
#define ENTRY_END_HASH	0xFFFFFFFF
#define ENTRY_END_LIST	0xFFFFFFFE

/* Copied from unique.c (and modified) */
static unsigned int line_hash(char *line)
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

	hash &= hash_mask;
out:
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

static inline int wbuf_unique(char *line)
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
#if ARCH_ALLOWS_UNALIGNED
	const char *line = aligned.buffer[0];
#else
	// for unaligned, we have to strcpy INTO line, so we can not have it be 'const'
	char *line = aligned.buffer[0];
#endif
	char *last = aligned.buffer[1];
	struct rpp_context ctx;
	char *prerule="", *rule, *word;
	char *(*apply)(const char *word, char *rule, int split, char *last)=NULL;
	long file_len;
	int i, pipe_input=0, max_pipe_words=0, rules_keep=0, init_this_time=1, really_done=0;
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
	IPC_Item *pIPC=NULL;
#endif
	char msg_buf[128];
	int forceLoad = 0;
	int potfile = 0;

#ifdef HAVE_MPI
	char file_line[LINE_BUFFER_SIZE];
	long my_size = 0;
	unsigned int myWordFileLines = 0;
#endif

	log_event("Proceeding with wordlist mode");

	_db = db;

	length = db->format->params.plaintext_length;

	if (db->options->max_wordfile_memory == 0)
		forceLoad = 1;

	/* If we did not give a name, we read the default pot file */
	if (!name && !(options.flags & (FLG_STDIN_CHK | FLG_PIPE_CHK))) {
		name = options.loader.activepot;
		potfile = 1;
		fprintf(stderr, "Closed-loop mode: Reading candidates from %s\n", name);
		if (!forceLoad && (db->options->max_wordfile_memory ==
		     (WORDLIST_BUFFER_DEFAULT >> mem_saving_level)))
			db->options->max_wordfile_memory = 0x40000000 >>
				mem_saving_level;
	}

	if (name) {
		char *cp, csearch;

		if (!(word_file = fopen(path_expand(name), "rb")))
			pexit("fopen: %s", path_expand(name));
		log_event("- Wordlist file: %.100s", path_expand(name));

		/* This lets us use a potfile as a wordlist - it will
		   automatically adopt and just read the password
		   column - and discard dupes. */
		if (!potfile && name && strlen(name) > 4 &&
		    (!strcasecmp(name + strlen(name) - 4, ".pot")))
		{
			potfile = 1;
			fprintf(stderr, "Closed-loop mode: Reading candidates from pot file\n");
			if (!forceLoad && (db->options->max_wordfile_memory ==
			     (WORDLIST_BUFFER_DEFAULT >> mem_saving_level)))
				db->options->max_wordfile_memory = 0x40000000 >>
					mem_saving_level;
		}

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
			fprintf(stderr, "Error, dictionary file is too large for john to read (probably a 32 bit OS issue)\n");
			error();
		}
		if (file_len == 0)
		{
			fprintf(stderr, "Error, dictionary file is empty\n");
			error();
		}
		/* If the file is < max_wordfile_memory, then we work from a
		   memory map of the file. But this is disabled if we are also
		   using an external filter, as a modification of a word could
		   trash the buffer */
		if (!(options.flags & FLG_EXTERNAL_CHK))
#ifdef HAVE_MPI
		if ((mpi_p > 1 && file_len > mpi_p * 100 && file_len / mpi_p <
		     db->options->max_wordfile_memory) ||
		    (file_len < db->options->max_wordfile_memory || forceLoad))
		{
			// Load only this node's share of words to memory
			char *aep;

			if (mpi_p > 1 && (file_len > mpi_p * 100 || forceLoad))
			{
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
					if (potfile)
						lp = (char*)potword(file_line);
					else
						lp = file_line;
					if (!rules)
						lp[length] = 0;
					if (nWordFileLines % mpi_p == mpi_id)
						my_size += strlen(lp);
				}
				fseek(word_file, 0, SEEK_SET);

				// Now copy just our share to memory
				word_file_str = mem_alloc(my_size + LINE_BUFFER_SIZE + 1);
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
					if (potfile)
						lp = (char*)potword(file_line);
					else
						lp = file_line;
					if (!rules)
						lp[length] = 0;
					if (myWordFileLines % mpi_p == mpi_id) {
						strcpy(&word_file_str[i], lp);
						i += strlen(lp);
					}
				}
				log_event("- loaded this node's share of wordfile %s into memory "
				          "(%lu bytes of %lu, max_size=%u avg/node)",
				          name, my_size, file_len, db->options->max_wordfile_memory);
				if (mpi_id == 0)
					fprintf(stderr,"MPI: each node loaded 1/%d of wordfile to memory (about %lu %s/node)\n",
					        mpi_p,
					        my_size > 1<<23 ? my_size >> 20 : my_size >> 10,
					        my_size > 1<<23 ? "MB" : "KB");
				aep = word_file_str + my_size;
				file_len = my_size;
			}
			else {
				log_event("- loading wordfile %s into memory (%lu bytes, max_size=%u)",
				          name, file_len, db->options->max_wordfile_memory);
				if (mpi_p > 1 && mpi_id == 0)
					fprintf(stderr,"MPI: each node loaded the whole wordfile to memory\n");
				word_file_str = mem_alloc(file_len + LINE_BUFFER_SIZE + 1);
				if (fread(word_file_str, 1, file_len, word_file) != file_len) {
					if (ferror(word_file))
						pexit("fread");
					fprintf(stderr, "fread: Unexpected EOF\n");
					error();
				}
			}
#else
		if (file_len < db->options->max_wordfile_memory || forceLoad)
		{
			char *aep;

			/* probably should only be debug message, but I left it in */
			log_event("loading wordfile %s into memory (%lu bytes, max_size=%u)", name, file_len, db->options->max_wordfile_memory);

			word_file_str = mem_alloc(file_len + LINE_BUFFER_SIZE + 1);
			if (fread(word_file_str, 1, file_len, word_file) != file_len) {
				if (ferror(word_file))
					pexit("fread");
				fprintf(stderr, "fread: Unexpected EOF\n");
				error();
			}
#endif
			aep = word_file_str + file_len;
			*aep = 0;
			csearch = '\n';
			cp = memchr(word_file_str, csearch, file_len);
			if (!cp)
			{
				csearch = '\r';
				cp = memchr(word_file_str, csearch, file_len);
			}
			for (nWordFileLines = 1; cp; ++nWordFileLines)
				cp = memchr(&cp[1], csearch, file_len - (cp - word_file_str) - 1);
			words = mem_alloc( (nWordFileLines+1) * sizeof(char*));
			log_event("wordfile had %u lines and required %lu bytes for index.", nWordFileLines, (unsigned long)(nWordFileLines * sizeof(char*)));

			i = 0;
			cp = word_file_str;

			hash_log = 8; // minimum 8 unless we modify line_hash()
			while (((1 << hash_log) < (nWordFileLines>>1)) &&
			       hash_log < 23)
				hash_log++;
			hash_size = (1 << hash_log);
			hash_mask = (hash_size - 1);
			log_event("Size %d log 1<<%d mask %08x, %d lines, allocating %zd bytes\n", hash_size, hash_log, hash_mask, nWordFileLines, (hash_size * sizeof(unsigned int)) + (nWordFileLines * sizeof(element_st)));
			buffer.hash = mem_alloc(hash_size * sizeof(unsigned int));
			buffer.data = mem_alloc(nWordFileLines * sizeof(element_st));
			memset(buffer.hash, 0xff, hash_size * sizeof(unsigned int));

			do
			{
				char *ep, ec;
				if (potfile)
					cp = (char*)potword(cp);
				ep = cp;
				while ((ep < aep) && *ep && *ep != '\n' && *ep != '\r') ep++;
				ec = *ep;
				*ep = 0;
				if (strncmp(cp, "#!comment", 9)) {
					if (!rules) {
						if (ep - cp >= length)
							cp[length] = 0;
						if (wbuf_unique(cp)) {
							words[i++] = cp;
							if (i == nWordFileLines)
								break;
						}
					} else {
						if (ep - cp >= LINE_BUFFER_SIZE)
							cp[LINE_BUFFER_SIZE-1] = 0;
						if (wbuf_unique(cp)) {
							words[i++] = cp;
							if (i == nWordFileLines)
								break;
						}
					}
				} else
					nWordFileLines--;
				cp = ep + 1;
				if (ec == '\r' && *cp == '\n') cp++;
			} while (cp < aep);
			if (nWordFileLines - i)
				fprintf(stderr, "Suppressed %u duplicate lines.\n", nWordFileLines - i);
			free(buffer.hash);
			free(buffer.data);
			nWordFileLines = i;
			nCurLine=0;
		}
	} else {
		/* Ok, we can be in --stdin or --pipe mode.  In --stdin, we simply copy over the
		 * stdin file handle, and deal with it like a 'normal' word_file file (one line
		 * at a time.  For --pipe mode, we read up to mem-buffer size, but that may not
		 * be the end. We then set a value, so that when we are 'done' in the loop, we
		 * jump back up.  Doing this, allows --pipe to have rules run on them. in --stdin
		 * mode, we can NOT perform rules, due to we can not fseek stdin in most OS's
		 */
 		word_file = stdin;
		if (options.flags & FLG_STDIN_CHK) {
			log_event("- Reading candidate passwords from stdin");
		} else {
			pipe_input = 1;
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
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

			word_file_str = mem_alloc(db->options->max_wordfile_memory);
			words = mem_alloc(max_pipe_words * sizeof(char*));
			rules_keep = rules;

GRAB_NEXT_PIPE_LOAD:;
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
			if (db->options->sharedmemoryfilename != NULL)
				goto MEM_MAP_LOAD;
#endif
			{
				char *cpi, *cpe;

				log_event("- Reading next block of candidate passwords from stdin pipe");

				// the second (and subsquent) times through, we do NOT call init functions.
				if (nWordFileLines)
					init_this_time = 0;

				rules = rules_keep;
				nWordFileLines = 0;
				cpi = word_file_str;
				cpe = (cpi + db->options->max_wordfile_memory) - (LINE_BUFFER_SIZE+1);
				while (nWordFileLines < max_pipe_words) {
					if (!fgetl(cpi, LINE_BUFFER_SIZE, word_file)) {
						pipe_input = 0; /* We are now done.  After processing, do NOT goto the GRAB_NEXT... again */
						break;
					}
					if (strncmp(cpi, "#!comment", 9)) {
						if (!rules) {
							cpi[length] = 0;
							if (!nWordFileLines || strcmp(cpi, words[nWordFileLines-1])) {
								words[nWordFileLines++] = cpi;
								cpi += (strlen(cpi)+1);
								if (cpi > cpe)
									break;
							}
						} else {
							words[nWordFileLines++] = cpi;
							cpi += (strlen(cpi)+1);
							if (cpi > cpe)
								break;
						}
					}
				}
				sprintf(msg_buf, "- Read block of %d candidate passwords from pipe", nWordFileLines);
				log_event("%s", msg_buf);
			}
#if defined (_MSC_VER) || defined (__MINGW32__) || defined (__CYGWIN32__)
			goto SKIP_MEM_MAP_LOAD;
MEM_MAP_LOAD:;
			{
				if (nWordFileLines)
					init_this_time = 0;
				rules = rules_keep;
				nWordFileLines = 0;
				log_event("- Reading next block of candidate from the memory mapped file");
				release_sharedmem_object(pIPC);
				pIPC = next_sharedmem_object();
				if (!pIPC || pIPC->n == 0) {
					pipe_input = 0; /* We are now done.  After processing, do NOT goto the GRAB_NEXT... again */
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
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "No wordlist mode rules found in %s\n",
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

#ifdef HAVE_MPI
	if (mpi_p > 1) {
		// Leapfrogging rules is less overhead unless we have wordfile in memory

		// Do not leapfrog at all if we have a split wordlist in memory
		if (!myWordFileLines) {

			// If less rules than nodes, leapfrog words
			if (rule_count < mpi_p)
				distributeWords = 1;
			else
				distributeRules = 1;

			// Magic debug numbers (should be replaced by proper options)
			// use --mem=0 to force split wordlist (no leapfrogging)
			// use --mem=1 to force leapfrogging of words
			// use --mem=2 to force leapfrogging of rules
			if (db->options->max_wordfile_memory == 1) {
				distributeWords = 1;
				distributeRules = 0;
			}
			if (rule_count >= mpi_p && db->options->max_wordfile_memory == 2) {
				distributeWords = 0;
				distributeRules = 1;
			}
		}

		// Tell user what was chosen.
		if (distributeWords) {
			log_event("MPI hack active: will process 1/%u of words", mpi_p);
			if (mpi_id == 0) fprintf(stderr,"MPI: each node processing 1/%u of words\n", mpi_p);
		}
		if (distributeRules) {
			myrulecount = (int)(rule_count / mpi_p) + (rule_count % mpi_p > mpi_id ? 1 : 0);
			log_event("MPI hack active: will process 1/%u of rules, total %d for this node", mpi_p, myrulecount);
			if (mpi_id == 0) fprintf(stderr,"MPI: each node processing 1/%u of %d rules. (%seven split)\n",
			                         mpi_p, rule_count, rule_count % mpi_p ? "un" : "");
		}
	}
#endif
	rule_number = 0; nCurLine = 0;

	if (init_this_time) {
		line_number = 0;

		status_init(get_progress, 0);

		rec_restore_mode(restore_state);
		rec_init(db, save_state);

		crk_init(db, fix_state, NULL);
	}

	if (rules) prerule = rpp_next(&ctx); else prerule = "";
	rule = "";

/* A string that can't be produced by fgetl(). */
	last[0] = '\n';
	last[1] = 0;

	if (prerule)
	do {
		if (rules) {
#ifdef HAVE_MPI
			// MPI distribution - leapfrog rules
			if (distributeRules && rule_number % mpi_p != mpi_id)
				rule = NULL;
			else
#endif
			if ((rule = rules_reject(prerule, -1, last, db))) {
				if (strcmp(prerule, rule))
					log_event("- Rule #%d: '%.100s'"
						" accepted as '%.100s'",
						rule_number + 1, prerule, rule);
				else
					log_event("- Rule #%d: '%.100s'"
						" accepted",
						rule_number + 1, prerule);
			} else
				log_event("- Rule #%d: '%.100s' rejected",
					rule_number + 1, prerule);
		}

		if (rule)
		while (1) {
			if (nWordFileLines) {
				if (nCurLine == nWordFileLines)
					break;
#ifdef HAVE_MPI
				if (!distributeWords || line_number % mpi_p == mpi_id)
#endif
#if ARCH_ALLOWS_UNALIGNED
				line = words[nCurLine++];
#else
				strcpy(line, words[nCurLine++]);
#endif
			}
			else {
				do {
					if (!fgetl((char*)line, LINE_BUFFER_SIZE, word_file))
						goto EndOfFile;
				} while (!strncmp(line, "#!comment", 9));

				if (potfile)
					memmove((char*)line, potword(line), strlen(potword(line)) + 1);

				if (!rules)
					((char*)line)[length] = 0;

				if (!strcmp(line, last)) {
					line_number++; // needed for MPI sync
					continue;
				}
			}
#ifdef HAVE_MPI
			// MPI distribution - leapfrog words
			if (line_number++ % mpi_p != mpi_id && distributeWords)
				continue;
#else
			line_number++;
#endif

			if ((word = apply(line, rule, -1, last))) {
				if (nWordFileLines)
					last = word;
				else
					strcpy(last, word);

				if (ext_filter(word))
				if (crk_process_key(word)) {
					rules = 0;
					really_done=1; /* keep us from relooping, if in -pipe mode */
					break;
				}
			}
		}

EndOfFile:
		if (rules) {
			if (!(rule = rpp_next(&ctx)))
				break;

			rule_number++;
			line_number = 0;

			if (nWordFileLines)
				nCurLine = 0;
			else
				if (fseek(word_file, 0, SEEK_SET)) pexit("fseek");
		}
	} while (rules);

	if (pipe_input && !really_done)
		goto GRAB_NEXT_PIPE_LOAD;

	crk_done();
	rec_done(event_abort || (status.pass && db->salts));

	if (ferror(word_file)) pexit("fgets");

	if (name) {
		if (event_abort)
			progress = get_progress(&hund_progress);
		else
			progress = 100;

		MEM_FREE(word_file_str);
		MEM_FREE(words);
		if (fclose(word_file)) pexit("fclose");
		word_file = NULL;
	}
}
