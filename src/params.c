/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98,2010,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "params.h"

unsigned int password_hash_sizes[PASSWORD_HASH_SIZES] = {
	PASSWORD_HASH_SIZE_0,
	PASSWORD_HASH_SIZE_1,
	PASSWORD_HASH_SIZE_2,
	PASSWORD_HASH_SIZE_3,
	PASSWORD_HASH_SIZE_4,
	PASSWORD_HASH_SIZE_5,
	PASSWORD_HASH_SIZE_6
};

unsigned int password_hash_thresholds[PASSWORD_HASH_SIZES] = {
	PASSWORD_HASH_THRESHOLD_0,
	PASSWORD_HASH_THRESHOLD_1,
	PASSWORD_HASH_THRESHOLD_2,
	PASSWORD_HASH_THRESHOLD_3,
	PASSWORD_HASH_THRESHOLD_4,
	PASSWORD_HASH_THRESHOLD_5,
	PASSWORD_HASH_THRESHOLD_6
};
