/*
 * This software is Copyright (c) 2017, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "formats.h"

#define FORMAT_TAG      "$dmg$"
#define FORMAT_TAG_LEN  (sizeof(FORMAT_TAG) - 1)

extern struct fmt_tests dmg_tests[];

int dmg_valid(char *ciphertext, struct fmt_main *self);
