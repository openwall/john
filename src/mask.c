/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 * Copyright (c) 2013 by magnum
 * Copyright (c) 2014 by Sayantan Datta
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h> /* for fprintf(stderr, ...) */
#include <string.h>

#include "misc.h" /* for error() */
#include "logger.h"
#include "recovery.h"
#include "os.h"
#include "signals.h"
#include "status.h"
#include "options.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "mask.h"
#include "unicode.h"

#include "memdbg.h"

static parsed_ctx parsed_mask;
static cpu_mask_context cpu_mask_ctx, rec_ctx;

static double cand;

/*
 * A "sequence number" for distributing the candidate passwords across nodes.
 * It is OK if this number overflows once in a while, as long as this happens
 * in the same way for all nodes (must be same size unsigned integer type).
 */
static unsigned int seq, rec_seq;

#define BUILT_IN_CHARSET "aluds"

#define store_op(k, i) \
	parsed_mask->stack_op_br[k] = i;

#define store_cl(k, i) \
	parsed_mask->stack_cl_br[k] = i;

#define load_op(i) \
	parsed_mask->stack_op_br[i]

#define load_cl(i) \
	parsed_mask->stack_cl_br[i]

#define load_qtn(i) \
	parsed_mask->stack_qtn[i]

/*
 * valid braces:
 * [abcd], [[[[[abcde], []]abcde]]], [[[ab]cdefr]]
 * invalid braces:
 * [[ab][c], parsed as two separate ranges [[ab] and [c]
 * [[ab][, error, sets parse_ok to 0.
 */
static void parse_braces(char *mask, parsed_ctx *parsed_mask) {

	int i, j ,k;
	int cl_br_enc;

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		store_cl(i, -1);
		store_op(i, -1);
	}

	j = k = 0;
	while (j < strlen(mask)) {

		for (i = j; i < strlen(mask); i++)
			if (mask[i] == '[')
				break;

		if (i < strlen(mask))
		/* store first opening brace for kth placeholder */
			store_op(k, i);

		i++;

		cl_br_enc = 0;
		for (;i < strlen(mask); i++) {
			if (mask[i] == ']') {
			/* store last closing brace for kth placeholder */
				store_cl(k, i);
				cl_br_enc = 1;
			}
			if (mask[i] == '[' && cl_br_enc)
				break;
		}

		j = i;
		k++;
	}

	parsed_mask->parse_ok = 1;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++)
		if ((load_op(i) == -1) ^ (load_cl(i) == -1))
			parsed_mask->parse_ok = 0;
}

/*
 * Stores the valid ? placeholders in a stack_qtn
 * valid:
 * -if outside [] braces and
 * -if ? is immediately followed by the identifier such as
 * ?a for all printable ASCII.
 */
static void parse_qtn(char *mask, parsed_ctx *parsed_mask) {
	int i, j, k;

	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++)
		parsed_mask->stack_qtn[i] = -1;

	for (i = 0, k = 0; i < strlen(mask); i++) {
		if (mask[i] == '?')
			if (i + 1 < strlen(mask))
				if (memchr(BUILT_IN_CHARSET, mask[i + 1],
				    strlen(BUILT_IN_CHARSET))) {
					j = 0;
					while (load_op(j) != -1 &&
					       load_cl(j) != -1) {
						if (i > load_op(j) &&
						    i < load_cl(j))
							goto cont;
						j++;
					}
					parsed_mask->stack_qtn[k++] = i;
				}
		cont:;
	}
}

static int search_stack(parsed_ctx *parsed_mask, int loc) {
	int t;

	for (t = 0; load_op(t) != -1; t++)
		if (load_op(t) <= loc && load_cl(t) >= loc)
			return load_cl(t);

	for (t = 0; load_qtn(t) != -1; t++)
		if (load_qtn(t) == loc)
			return loc + 1;
	return 0;
}

/*
 * Maps the postion of a range in a mask to its actual postion in a key.
 * Offset for wordlist + mask is not taken into account.
 */
static int calc_pos_in_key(char *mask, parsed_ctx *parsed_mask, int mask_loc) {
	int i, ret_pos;

	i = ret_pos = 0;
	while (i < mask_loc) {
		int t;
		t = search_stack(parsed_mask, i);
		i = t ? t + 1: i + 1;
		ret_pos++;
	}

	return ret_pos;
}

static void init_cpu_mask(char *mask, parsed_ctx *parsed_mask,
			  cpu_mask_context *cpu_mask_ctx) {
	int i, qtn_ctr, op_ctr, cl_ctr ;

#define count(i) cpu_mask_ctx->ranges[i].count
#define swap(a, b) { x = a; a = b; b = x; }
#define fill_range() 							\
	if (a > b)							\
		swap(a, b);						\
	for (x = a; x <= b; x++) 					\
		if (!memchr((const char*)cpu_mask_ctx->ranges[i].chars, \
		    x, count(i)))					\
			cpu_mask_ctx->ranges[i].chars[count(i)++] = x;


	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		cpu_mask_ctx->ranges[i].start =
		cpu_mask_ctx->ranges[i].count =
		cpu_mask_ctx->ranges[i].pos =
		cpu_mask_ctx->ranges[i].iter =
		cpu_mask_ctx->active_positions[i] = 0;
		cpu_mask_ctx->ranges[i].next = MAX_NUM_MASK_PLHDR;
	}
	cpu_mask_ctx->count = cpu_mask_ctx->offset = 0;

	qtn_ctr = op_ctr = cl_ctr = 0;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		if ((unsigned int)load_op(op_ctr) <
		    (unsigned int)load_qtn(qtn_ctr)) {
			int j;

			cpu_mask_ctx->
			ranges[i].pos = calc_pos_in_key(mask,
						        parsed_mask,
				                        load_op(op_ctr));

			for (j = load_op(op_ctr) + 1; j < load_cl(cl_ctr);) {
				int a , b;
				if (mask[j] == '\\' &&
				    j + 8 < load_cl(cl_ctr) &&
				    sscanf(mask + j, "\\x%02x-\\x%02x", &a, &b)
				    == 2) {
					int x;
					fill_range();
					j = j + 8;
				}
				else if (mask[j] == '-' &&
					 j + 1 < load_cl(cl_ctr) &&
					 j - 1 > load_op(op_ctr)) {
					int x;
		/* Remove the character mask[j-1] added in previous iteration */
					count(i)--;

					a = mask[j - 1];
					b = mask[j + 1];

					fill_range();

					j++;
				}
				else if (!memchr((const char*)
				         cpu_mask_ctx->ranges[i].chars,
		                         (int)mask[j], count(i)))
						cpu_mask_ctx->
						ranges[i].
						chars[count(i)++] = mask[j];

				j++;
			}

			op_ctr++;
			cl_ctr++;
			cpu_mask_ctx->count++;
		}
		else if ((unsigned int)load_op(op_ctr) >
		         (unsigned int)load_qtn(qtn_ctr))  {
			int j;

			cpu_mask_ctx->
			ranges[i].pos = calc_pos_in_key(mask,
							parsed_mask,
							load_qtn(qtn_ctr));

			switch(mask[load_qtn(qtn_ctr) + 1]) {
				case 'a': cpu_mask_ctx->ranges[i].start = 32;
					  for (j = 0; j < 95; j++)
						cpu_mask_ctx->
						ranges[i].chars[j] = 32 + j;
					  count(i) = 95;
					  break;
				case 'l': cpu_mask_ctx->ranges[i].start = 97;
					  for (j = 0; j < 26; j++)
						cpu_mask_ctx->
						ranges[i].chars[j] = 97 + j;
					  count(i) = 26;
					  break;
				case 'u': cpu_mask_ctx->ranges[i].start = 65;
					  for (j = 0; j < 26; j++)
						cpu_mask_ctx->
						ranges[i].chars[j] = 65 + j;
					  count(i) = 26;
					  break;
				case 'd': cpu_mask_ctx->ranges[i].start = 48;
					  for (j = 0; j < 10; j++)
						cpu_mask_ctx->
						ranges[i].chars[j] = 48 + j;
					  count(i) = 10;
					  break;
				case 's': for (j = 32; j <= 47; j++)
						cpu_mask_ctx->
						ranges[i].chars[count(i)++] = j;
				          for (j = 58; j <= 64; j++)
						cpu_mask_ctx->
						ranges[i].chars[count(i)++] = j;
					  for (j = 91; j <= 96; j++)
						cpu_mask_ctx->
						ranges[i].chars[count(i)++] = j;
					  for (j = 123; j <= 126; j++)
						cpu_mask_ctx->
						ranges[i].chars[count(i)++] = j;
					  break;
/*
 * Note: To add more cases, also append the new symbol to string BUILT_IN_CHARSET.
 */
				default:  fprintf(stderr,
						  "Unrecognized placeholder ?%c.\n",
						   mask[load_qtn(qtn_ctr) + 1]);
					  error();
			}
			qtn_ctr++;
			cpu_mask_ctx->count++;
		}
	}
#undef count
#undef swap
#undef fill_range
	for (i = 0; i < cpu_mask_ctx->count - 1; i++) {
		cpu_mask_ctx->ranges[i].next = i + 1;
		cpu_mask_ctx->active_positions[i] = 1;
	}
	cpu_mask_ctx->ranges[i].next = MAX_NUM_MASK_PLHDR;
	cpu_mask_ctx->active_positions[i] = 1;
}

/*
 * Returns the template of the keys corresponding to the mask.
 * Wordlist + mask not taken into account.
 */
static char* generate_template_key(char *mask, parsed_ctx *parsed_mask) {
	char *template_key = (char*)mem_alloc(0x400);
	int i, k, t;
	i = 0, k = 0;

	while (i < strlen(mask)) {
		if ((t = search_stack(parsed_mask, i))){
			template_key[k++] = '#';
			i = t + 1;
		}
		else
			template_key[k++] = mask[i++];
	}
	template_key[k] = '\0';

	return template_key;
}

/* Handle intermediate encoding. */
static char* mask_cp_to_utf8(char *in)
{
	static char out[PLAINTEXT_BUFFER_SIZE + 1];

	if (pers_opts.intermediate_enc != UTF_8 &&
	    pers_opts.intermediate_enc != pers_opts.target_enc)
		return cp_to_utf8_r(in, out, PLAINTEXT_BUFFER_SIZE);

	return in;
}

static void generate_keys(char *template_key, cpu_mask_context *cpu_mask_ctx,
			  int my_words, int their_words) {
	int i, j, k, ps1 = MAX_NUM_MASK_PLHDR, ps2 = MAX_NUM_MASK_PLHDR,
	    ps3 = MAX_NUM_MASK_PLHDR, ps;
	int offset = cpu_mask_ctx->offset, num_active_postions = 0;

	for (i = 0; i < cpu_mask_ctx->count; i++)
		if ((int)(cpu_mask_ctx->active_positions[i])) {
			ps1 = i;
			break;
		}

#define ranges(i) cpu_mask_ctx->ranges[i]

	ps2 = cpu_mask_ctx->ranges[ps1].next;
	ps3 = cpu_mask_ctx->ranges[ps2].next;

	for (i = 0; i < cpu_mask_ctx->count; i++)
		if ((int)(cpu_mask_ctx->active_positions[i]))
			num_active_postions++;

	if (!num_active_postions)
		fprintf(stdout, "%s\n", template_key);

#define inner_loop_body() {						\
	template_key[ranges(ps1).pos + offset] = ranges(ps1).chars[i];  \
	if (options.node_count) {					\
		seq++;							\
		if (their_words) {					\
			their_words--;					\
			continue;					\
		}							\
		if (--my_words == 0) {					\
			my_words =					\
				options.node_max - options.node_min + 1;\
			their_words = options.node_count - my_words;	\
		}							\
	}								\
	if (ext_filter(template_key))					\
		if (crk_process_key(mask_cp_to_utf8(template_key)))	\
			goto done;					\
	}

	else if (num_active_postions == 1) {
		for (i = 0; i < ranges(ps1).count; i++)
			inner_loop_body();
	}

	else if (num_active_postions == 2) {
		for (j = 0; j < ranges(ps2).count; j++) {
			template_key[ranges(ps2).pos + offset] =
			ranges(ps2).chars[j];
			for (i = 0; i < ranges(ps1).count; i++)
				inner_loop_body();
		}
	}

	else if (num_active_postions > 2) {
		ps = ranges(ps3).next;

	/* Initialize the reaming placeholders other than the first three */
		while (ps != MAX_NUM_MASK_PLHDR) {
			template_key[ranges(ps).pos + offset] =
			ranges(ps).chars[ranges(ps).iter];
			ps = ranges(ps).next;
		}

		while (1) {
			/* Iterate over first three placeholders */
			for (k = 0; k < ranges(ps3).count; k++) {
				template_key[ranges(ps3).pos + offset] =
					ranges(ps3).chars[k];
				for (j = 0; j < ranges(ps2).count; j++) {
					template_key[ranges(ps2).pos + offset] =
						ranges(ps2).chars[j];
					for (i = 0; i < ranges(ps1).count; i++)
						inner_loop_body();
				}
			}

			ps = ranges(ps3).next;

			/*
			 * Calculate next state of remaing placeholders, working
			 * similar to counters.
			 */
			while(1) {

				if (ps == MAX_NUM_MASK_PLHDR) goto done;
				if ((++(ranges(ps).iter)) == ranges(ps).count) {
					ranges(ps).iter = 0;
					template_key[ranges(ps).pos + offset] =
						ranges(ps).chars[ranges(ps).iter];
					ps = ranges(ps).next;
				}
				else {
					template_key[ranges(ps).pos + offset] =
						ranges(ps).chars[ranges(ps).iter];
					break;
				}
			}
		}
#undef ranges
	}
	done: ;
}

/* Skips iteration for postions stored in arr */
static void skip_position(cpu_mask_context *cpu_mask_ctx, int *arr) {
	if (arr != NULL) {
		int k = 0;
		while (arr[k] >= 0 && arr[k] < cpu_mask_ctx->count) {
			int j, i, flag1 = 0, flag2 = 0;
			cpu_mask_ctx->active_positions[arr[k]] = 0;
			cpu_mask_ctx->ranges[arr[k]].next = MAX_NUM_MASK_PLHDR;

			for (j = arr[k] - 1; j >= 0; j--)
				if ((int)(cpu_mask_ctx->active_positions[j])) {
					flag1 = 1;
					break;
				}

			for (i = arr[k] + 1; i < cpu_mask_ctx->count; i++)
				if ((int)(cpu_mask_ctx->active_positions[i])) {
					flag2 = 1;
					break;
				}

			if (flag1)
				cpu_mask_ctx->ranges[j].next =
					flag2?i:MAX_NUM_MASK_PLHDR;
			k++;
		}
	}
}

static double get_progress(void)
{
	double try;

	emms();

	try = ((unsigned long long)status.cands.hi << 32) + status.cands.lo;

	if (!cand)
		return -1;

	return 100.0 * try / cand;
}

static void save_state(FILE *file)
{
	int i;

	fprintf(file, "%u\n", rec_seq);
	fprintf(file, "%d\n", rec_ctx.count);
	fprintf(file, "%d\n", rec_ctx.offset);
	for (i = 0; i < rec_ctx.count; i++)
		fprintf(file, "%hhu\n", rec_ctx.ranges[i].iter);
}

static int restore_state(FILE *file)
{
	int i;

	if (fscanf(file, "%u\n", &seq) != 1)
		return 1;
	if (fscanf(file, "%d\n", &cpu_mask_ctx.count) != 1)
		return 1;
	if (fscanf(file, "%d\n", &cpu_mask_ctx.offset) != 1)
		return 1;
	for (i = 0; i < cpu_mask_ctx.count; i++)
		if (fscanf(file, "%hhu\n", &cpu_mask_ctx.ranges[i].iter) != 1)
			return 1;
	return 0;
}

static void fix_state(void)
{
	int i;
	rec_seq = seq;
	rec_ctx.count = cpu_mask_ctx.count;
	rec_ctx.offset = cpu_mask_ctx.offset;
	for (i = 0; i < rec_ctx.count; i++)
		rec_ctx.ranges[i].iter = cpu_mask_ctx.ranges[i].iter;
}

void do_mask_crack(struct db_main *db, char *mask)
{
	int my_words, their_words;
	int i;
	char *template_key;

	/* We do not yet support min/max-len */
	if (options.force_minlength >= 0 || options.force_maxlength) {
		fprintf(stderr, "Mask mode: --min-length and --max-length currently not supported\n");
		error();
	}

	log_event("Proceeding with mask mode");

	parse_braces(mask, &parsed_mask);
	if (parsed_mask.parse_ok)
		parse_qtn(mask, &parsed_mask);
	else {
		fprintf(stderr, "Parsing unsuccessful\n");
		error();
	}

	init_cpu_mask(mask, &parsed_mask, &cpu_mask_ctx);

	/*
	 * Warning: NULL to be raplaced by an array containing information
	 * regarding GPU portion of mask.
	 */
	skip_position(&cpu_mask_ctx, NULL);
	template_key = generate_template_key(mask, &parsed_mask);

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

	cand = 1;
	for (i = 0; i < cpu_mask_ctx.count; i++)
		if ((int)(cpu_mask_ctx.active_positions[i]))
			cand *= cpu_mask_ctx.ranges[i].count;
	if (options.node_count)
		cand *= (double)(options.node_max - options.node_min + 1) /
			options.node_count;

	generate_keys(template_key, &cpu_mask_ctx, my_words, their_words);

	// For reporting DONE regardless of rounding errors
	if (!event_abort)
		cand = ((unsigned long long)status.cands.hi << 32) +
			status.cands.lo;

	crk_done();

	rec_done(event_abort);

	MEM_FREE(template_key);
}
