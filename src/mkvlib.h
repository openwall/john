/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#ifndef _JOHN_MKVLIB_H
#define _JOHN_MKVLIB_H

#include <stdint.h>

#define UNK_STR 255

struct s_pwd {
	unsigned int level;
	unsigned int len;
	unsigned int index;
	unsigned char password[MAX_MKV_LEN + 1];
};

extern unsigned char *proba1;
extern unsigned char *proba2;
extern uint64_t *nbparts;
extern unsigned char *first;
extern unsigned char charsorted[256 * 256];

extern unsigned int gmax_level;
extern unsigned int gmax_len;
extern unsigned int gmin_level;
extern unsigned int gmin_len;
extern uint64_t gidx;
extern uint64_t gstart;
extern uint64_t gend;

void print_pwd(uint64_t index, struct s_pwd *pwd,
               unsigned int max_lvl, unsigned int max_len);
uint64_t nb_parts(unsigned char lettre, unsigned int len,
                            unsigned int level, unsigned int max_lvl, unsigned int max_len);
void init_probatables(const char *filename);
#endif
