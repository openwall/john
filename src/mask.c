/*
 * Copyright (c) 2013 myrice
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "cracker.h"
#include "mask.h"

static char alpha_low_set[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

static char alpha_up_set[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
};

static char num_set[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

enum mask_t {
    constant = 0,
    low_char,
    up_char,
    number
};

static void fix_state()
{

}

static void mask_generate(char *param)
{

	char key[PLAINTEXT_BUFFER_SIZE+1];
	enum mask_t mask_type[PLAINTEXT_BUFFER_SIZE]; // record mask type in every position
	unsigned maskset_num[PLAINTEXT_BUFFER_SIZE]; // record total mask set number in every position
	unsigned maskset_pos[PLAINTEXT_BUFFER_SIZE]; // record mask set position with current key
	unsigned key_len = 0;
	int index;
	int first_mask_index = -1, last_mask_index = -1;

	char *ch = param;

	// Initial the key
	memset(maskset_pos, 0, sizeof(maskset_pos));
	while (*ch) {
		if (*ch == '?') {
			ch++;
			if (first_mask_index == -1)
				first_mask_index = key_len;
			last_mask_index = key_len;
			switch (*ch) {
			case 'l':
				mask_type[key_len] = low_char;
				key[key_len] = alpha_low_set[0];
				maskset_num[key_len] = 26;
				break;
			case 'u':
				mask_type[key_len] = up_char;
				key[key_len] = alpha_up_set[0];
				maskset_num[key_len] = 26;
				break;
			case 'd':
				mask_type[key_len] = number;
				key[key_len] = num_set[0];
				maskset_num[key_len] = 10;
				break;
			default:
				printf("mask type not recognized!\n");
				assert(0);
			}
		} else { // constant character
			key[key_len] = *ch;
			mask_type[key_len] = constant;
			maskset_num[key_len] = 0;
		}
		ch++;
		key_len++;
		assert(key_len < PLAINTEXT_BUFFER_SIZE);
	}
	key[key_len] = '\0';

	if (first_mask_index == -1) { //No mask
		crk_process_key(key);
		return;
	}

	do {
		switch (mask_type[last_mask_index]) {
			case low_char:
				key[last_mask_index] = alpha_low_set[maskset_pos[last_mask_index]];
				break;
			case up_char:
				key[last_mask_index] = alpha_up_set[maskset_pos[last_mask_index]];
				break;
			case number:
				key[last_mask_index] = num_set[maskset_pos[last_mask_index]];
				break;
		}
		crk_process_key(key);
		maskset_pos[last_mask_index]++;
		if (maskset_pos[last_mask_index] == maskset_num[last_mask_index]) {
			if (last_mask_index==first_mask_index) return;
			maskset_pos[last_mask_index] = 0;
			switch (mask_type[last_mask_index]) {
				case low_char:
					key[last_mask_index] = alpha_low_set[0];
					break;
				case up_char:
					key[last_mask_index] = alpha_up_set[0];
					break;
				case number:
					key[last_mask_index] = num_set[0];
					break;
			}
			// Ok, now work towards 'front', stopping when we reach the next
			// non-constant that is NOT maxed out.  Each time we meet a non-
			// const that is maxed out, we reset it to its starting value.
			// when we reach the first non-maxed out non-const, we increment it
			// by 1, and start counting from the 'last' index (in the outer loop)
			index = last_mask_index-1;
			while (index >= first_mask_index) {
				if (mask_type[index] == constant) {
					--index;
					continue;
				}
				++maskset_pos[index];
				if (maskset_pos[index] == maskset_num[index]) {
					maskset_pos[index] = 0;
					switch (mask_type[index]) {
						case low_char:
							key[index] = alpha_low_set[0];
							break;
						case up_char:
							key[index] = alpha_up_set[0];
							break;
						case number:
							key[index] = num_set[0];
							break;
					}
					if (index == first_mask_index)
						return; // we are done.  We have maxed out our first index.

					--index;
					continue;
				}
				// ok, we found a non-maxed out non-const.  increment it, then break to start
				// counting from the last_mask_index again.
				switch (mask_type[index]) {
					case low_char:
						key[index] = alpha_low_set[maskset_pos[index]];
						break;
					case up_char:
						key[index] = alpha_up_set[maskset_pos[index]];
						break;
					case number:
						key[index] = num_set[maskset_pos[index]];
						break;
				}
				break;
			}
		}
	} while (1); //while (index <= last_mask_index && index >= first_mask_index);
}

void do_mask_crack(struct db_main *db, char *param)
{
    crk_init(db, fix_state, NULL);

    mask_generate(param);
    crk_done();

}
