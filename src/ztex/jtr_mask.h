/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _JTR_MASK_H_
#define _JTR_MASK_H_

#include "../mask_ext.h"

/*
 * Functions to access mask data.
 */

inline static int mask_is_inactive()
{
	return mask_int_cand.num_int_cand == 1;
}

inline static unsigned int mask_num_cand()
{
	return mask_int_cand.num_int_cand;
}

// Displays mask data in human-readable form (for debugging)
void mask_print();

// Gets mask data for current template key. Converts into 'range_info' data
// for remote devices and stores in the location pointed to by 'range_info'.
// Designed for use in set_key().
void mask_set_range_info(unsigned char *range_info);

// Gets mask data. Converts into the configuration
// for word generators on remote devices.
// If mask is not used, creates generator configuration that
// would pass-by plaintext candidates.
// Returns pointer to 'static struct word_gen'.
struct word_gen *mask_convert_to_word_gen();

// Reconstructs plaintext out of template key, range_info and
// ID of generated candidate. 'key' is modified in place.
void mask_reconstruct_plaintext(
		char *key,
		unsigned char *range_info,
		unsigned int gen_id);

#endif
