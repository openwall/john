/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h> /* for fprintf(stderr, ...) */
#include <stdlib.h> /* for qsort */

#include "misc.h" /* for error() */
#include "logger.h"
#include "status.h"
#include "options.h"
#include "rpp.h"
#include "external.h"
#include "cracker.h"
#include "john.h"
#include "mask.h"
#include "loader.h"

#define MASK_DEBUG 0

static struct mask_context msk_ctx;
unsigned char *mask_offset_buffer;

  /* calculates nCr combinations */
void combinationUtil(void *arr, int data[], int start, int end, int index, int r, int target, int *isOptimal);

int checkRange(struct mask_context *ctx, int rangePos) {
	unsigned char start = ctx -> ranges[rangePos].chars[0];
	int i;

	/* Check if all values are consecutive in the given range */
	for (i = 1; i < (ctx -> ranges[rangePos].count); i++) {
		if (((ctx -> ranges[rangePos].chars[i]) - start) == i ) continue;
		break;
	}

	if (i == (ctx -> ranges[rangePos].count)) {
		ctx -> ranges[rangePos].start =  start;

		return 1;
	}

	for (i = 1; i < (ctx -> ranges[rangePos].count); i++) {
		if ((start - (ctx -> ranges[rangePos].chars[i])) == i ) continue;
		break;
	}

	if (i == (ctx -> ranges[rangePos].count)) {
		ctx -> ranges[rangePos].start =  ctx -> ranges[rangePos].chars[--i];
		return 1;
	}

	/* If all chars are not consecutive */
	if ((ctx -> ranges[rangePos].count) <= MAX_GPU_CHARS) {
		ctx -> ranges[rangePos].start = 0;
		return 1;
	}

	return 0;
}

int checkSelectRanges(struct mask_context *ctx, int *data, int r) {
	int i, flag = 1;
	for (i = 0; i < r; i++)
	    flag &= checkRange(ctx, data[i]);
	return flag;
}

void calcCombination(void *arr, int n, int target)
{
    int data[n], isOptimal = 0x7fffffff, i;
    ((struct mask_context*)arr) -> count = 0x7fffffff;

    /* Fix the maximum number of ranges that can be calculated on GPU to 3 */
    for(i = 1; i<= MAX_GPU_RANGES; i++)
		combinationUtil(arr, data, 0, n-1, 0, i, target, &isOptimal);

}

void combinationUtil(void *arr, int data[], int start, int end, int index, int r, int target, int *isOptimal) {
	int i;

	if (index == r)	{
		int j, tmp = 1;
		for ( j = 0; j < r; j++)
			tmp *= ((struct mask_context*)arr) -> ranges[data[j]].count;
		tmp -= target;
		tmp = tmp < 0 ? -tmp : tmp;

		if (tmp <= *isOptimal) {
			if ((r < ((struct mask_context*)arr) -> count) || (tmp < *isOptimal)) {
				if(!checkSelectRanges(((struct mask_context*)arr), data, r)) return;
				((struct mask_context*)arr) -> count = r;
				for ( j = 0; j < r; j++)
					((struct mask_context*)arr) -> activeRangePos[j] = data[j];
				*isOptimal = tmp;
			}
		}
		return;
	}

	for (i = start; i <= end && end-i+1 >= r-index; i++) {
		data[index] = ((struct mask_context*)arr) -> ranges[i].pos ;
		combinationUtil(arr, data, i+1, end, index+1, r, target, isOptimal);
	}
}

static void set_mask(struct rpp_context *rpp_ctx, struct db_main *db, unsigned char flg_wrd) {

	int i;

	for(i = 0; i < rpp_ctx->count; i++ ) {
		memcpy(msk_ctx.ranges[i].chars, rpp_ctx->ranges[i].chars, 0x100);
		msk_ctx.ranges[i].count = rpp_ctx->ranges[i].count;
		msk_ctx.ranges[i].pos = rpp_ctx->ranges[i].pos - rpp_ctx->output;
	}

	calcCombination(&msk_ctx, rpp_ctx -> count, db -> max_int_keys);
	msk_ctx.flg_wrd = flg_wrd;
	memcpy(db ->msk_ctx, &msk_ctx, sizeof(struct mask_context));
#if MASK_DEBUG
	int j;
	for(i = 0; i < msk_ctx.count; i++){
			for(j = 0; j < msk_ctx.ranges[msk_ctx.activeRangePos[i]].count; j++)
				printf("%c ",msk_ctx.ranges[msk_ctx.activeRangePos[i]].chars[j]);
			printf("\n");
			//checkRange(&msk_ctx, msk_ctx.activeRangePos[i]) ;
			printf("START:%c",msk_ctx.ranges[msk_ctx.activeRangePos[i]].start);
			printf("\n");
	}
#endif


}

void do_mask_crack(struct db_main *db, char *mask, char *wordlist)
{
	struct rpp_context rpp_ctx, rpp_ctx_restore;
	char word[128], *mask_word, line[128];
	FILE *file = NULL;
	int flag;
	unsigned int index, length;
	size_t mask_offset;

	if (options.node_count) {
		if (john_main_process)
			fprintf(stderr, "--mask is not yet compatible with --node and --fork\n");
		error();
	}

	log_event("Proceeding with mask mode");

	rpp_init_mask(&rpp_ctx, mask);

	status_init(NULL, 0);

#if 0
	rec_restore_mode(restore_state);
	rec_init(db, save_state);

	crk_init(db, fix_state, NULL);
#else
	crk_init(db, NULL, NULL);
#endif
	rpp_process_rule(&rpp_ctx);

	if (rpp_ctx.count > MASK_RANGES_MAX) {
		fprintf(stderr, "mask mode error: Increase MASK_RANGES_MAX value to RULE_RANGES_MAX.\n");
		error();
	}

	if (wordlist)
		file = fopen ((const char*)wordlist, "r" );
	else
		file = NULL;

	db->msk_ctx = (struct mask_context*) mem_alloc(sizeof(struct mask_context));

	if (db -> max_int_keys)
		set_mask(&rpp_ctx, db, (file!=NULL));

	if((db -> format))
		length = db->format->params.max_keys_per_crypt;
	else
		length = 1;

	length = length ? length : 1;

	mask_offset_buffer = (unsigned char*)mem_calloc(length);

	if(file != NULL) {
#if MASK_DEBUG
		fprintf(stdout, "Using:wordlist:%d\n",length );
#endif
		rpp_ctx_restore = rpp_ctx;
		index = 0;
		 while (fgets(line, sizeof(line), file) != NULL) {
				memcpy(word, line, 128);
				mask_offset = strlen(word) - 1;
				while ((mask_word = msk_next(&rpp_ctx, &msk_ctx, &flag))) {
					if (ext_filter(mask_word)) {
						memcpy(word + mask_offset, mask_word, MASK_RANGES_MAX);
						mask_offset_buffer[index] = mask_offset;
						index++;
						if(index == length)
							index = 0;
						if (crk_process_key(word))
							goto close_file;
					}
				}
				rpp_ctx = rpp_ctx_restore;
				flag = 0;
		}

close_file:		fclose (file);
	}

	else {
#if MASK_DEBUG
		fprintf(stdout, "NOT Using:wordlist\n");
#endif
		flag = 0;
		while ((mask_word = msk_next(&rpp_ctx, &msk_ctx, &flag))) {
			if (ext_filter(mask_word))
				if (crk_process_key(mask_word))
					break;
		}
	}

	crk_done();
	MEM_FREE(db -> msk_ctx);
	MEM_FREE(mask_offset_buffer);

#if 0
	rec_done(event_abort);
#endif
}
