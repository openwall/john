/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdlib.h>

#include "../mask_ext.h"

#include "jtr_mask.h"
#include "pkt_comm/word_gen.h"

/*
 * Word generator configuration - used by devices
 */
struct word_gen word_gen;


/*
static int static_gpu_locations[MASK_FMT_INT_PLHDR];

	// Got the following code from some opencl_* implementations.
	// Could not discover when any of static_gpu_locations are other than -1.
	// Some opencl_* implementation operate without static_gpu_locations.
	//
	int i;
	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (static_gpu_locations[i] != -1) {
			fprintf(stderr,"!=> Unexpected mask data: static_gpu_locations: ");
			int j;
			for (j = 0; j < MASK_FMT_INT_PLHDR; j++)
				fprintf(stderr,"%d ", static_gpu_locations[j]);
			fprintf(stderr,"\n");
			break;
		}
*/


void mask_print()
{
	fprintf(stderr, "==========\n> num_int_cand:%d static:%d\n",
			mask_int_cand.num_int_cand, mask_gpu_is_static);

	mask_cpu_context *mask = mask_int_cand.int_cpu_mask_ctx;
	fprintf(stderr, "> ps1:%d count:%d cpu_count:%d offset:%d\n",
			mask->ps1, mask->count, mask->cpu_count, mask->offset);

	int i;
	for (i = 0; i < MAX_NUM_MASK_PLHDR; i++) {
		mask_range *range = mask->ranges + i;
		if (!range->count)
			break;
		fprintf(stderr, "> Range %d: count %d, pos %d, offset %d\n",
				i, range->count, range->pos, range->offset);
	}

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		if (mask_skip_ranges[i] == -1)
			continue;
		mask_range *range = mask_int_cand.int_cpu_mask_ctx->ranges
				+ mask_skip_ranges[i];
		fprintf(stderr, "i:%d\tskip_ranges[i]:%d\toff:%d\tpos:%d\n",
				i,mask_skip_ranges[i], range->offset, range->pos);
	}
}


void mask_set_range_info(unsigned char *range_info)
{
	// In mask_mode, it inserts placeholders into the key.
	// Such as if the key is 'pwd', mask is '?d?w?d?d' then
	// set_key() gets '#pwd##' as an argument ('#' signs used).
	// Some mask data, such as int_cpu_mask_ctx->ranges[i].offset
	// is updated at every set_key() invocation.
	//
	// *-opencl implementations grab mask data and adds 4 bytes
	// of data (MASK_FMT_INT_PLHDR is 4) to every key.
	// Example follows.
	//
	//	int i;
	//	saved_int_key_loc[index] = 0;
	//	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
	//		if (mask_skip_ranges[i] != -1)  {
	//			saved_int_key_loc[index] |= ((mask_int_cand.
	//			int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
	//			mask_int_cand.int_cpu_mask_ctx->
	//			ranges[mask_skip_ranges[i]].pos) & 0xff) << (i << 3);
	//		}
	//		else
	//			saved_int_key_loc[index] |= 0x80 << (i << 3);
	//	}

	// OK. Devices with pkt_comm_v2 use same approach.
	//
	int i;
	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		int range_num = mask_skip_ranges[i];
		if (range_num == -1)
			break;

		// This range isn't unrolled on CPU, template key contains '#'
		mask_range *range = mask_int_cand.int_cpu_mask_ctx->ranges + range_num;

		// Device takes new position for the range.
		// That shouldn't be less than range's original position.
		// If 2+ ranges are moved to the same position
		// (shouldn't happen) then the result is undefined.
		int new_pos = range->pos + range->offset;
		if (new_pos > 0x7f) {
			fprintf(stderr, "Error: Mask placeholder in position %d\n",
					new_pos);
			error();
		}

		// Bit 7 indicates range is active.
		range_info[i] = 0x80 | new_pos;
	}

	// If less than MASK_FMT_INT_PLHDR ranges are active
	// then range_info bytes are terminated with '\0'.
	if (i < MASK_FMT_INT_PLHDR)
		range_info[i] = 0;
}


// Creates configuration for on-board word generator
// using mask data
struct word_gen *mask_convert_to_word_gen()
{
	if (mask_is_inactive())
		return &word_gen_words_pass_by;

	int dst_range_num = 0;
	int i;
	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		int range_num = mask_skip_ranges[i];
		if (range_num == -1)
			break;

		mask_range *range = mask_int_cand.int_cpu_mask_ctx->ranges + range_num;
		word_gen.ranges[dst_range_num].num_chars = range->count;
		word_gen.ranges[dst_range_num].start_idx = 0;
		memcpy(word_gen.ranges[dst_range_num].chars,
				range->chars, range->count);
		dst_range_num++;
	}

	if (!dst_range_num) {
		fprintf(stderr, "mask_convert_to_word_gen: failed\n");
		exit(-1);
	}

	word_gen.num_ranges = dst_range_num;

	return &word_gen;
}

// Reconstructs plaintext out of template key, range_info and
// ID of generated candidate.
// Assuming global mask didn't change since that.
// Designed for use in get_key(). 'key' is modified in place.
// If mask is not used or was deinitialized, then 'key'
// is not modified.
//
// This must be a good alternative to bitmap-like implementation,
// providing reasonable memory-to-CPU tradeoff.
//
void mask_reconstruct_plaintext(
		char *key,
		unsigned char *range_info,
		unsigned int gen_id)
{
	if (mask_is_inactive() || !mask_skip_ranges)
		return;

	unsigned int total_count = gen_id;
	int i;
	for (i = MASK_FMT_INT_PLHDR - 1; i >= 0; i--) {
		int range_num = mask_skip_ranges[i];
		if (range_num == -1)
			continue;

		mask_range *range = mask_int_cand.int_cpu_mask_ctx->ranges + range_num;
		int char_index = total_count % range->count;
		total_count /= range->count;

		if (!range_info[i]) {
			// This shouldn't happen
			fprintf(stderr, "mask_reconstruct_plaintext: inconsistent data,"
					" key: '%s', gen_id=%d\n", key, gen_id);
			mask_print();
			break;
		}
		unsigned char new_pos = range_info[i] & 0x7f;
		key[new_pos] = range->chars[char_index];
	}
}
