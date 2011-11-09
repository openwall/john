/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */
#ifndef _EMMINTRIN_H_INCLUDED
#define __m128i void
#endif

void md5cryptsse(unsigned char * buf, unsigned char * salt, char * out, int md5_type);
void SSEmd5body(__m128i* data, unsigned int * out, int init);
void SSEmd4body(__m128i* data, unsigned int * out, int init);
void SSESHA1body(__m128i* data, unsigned int * out, unsigned int * reload_state, int input_layout_output); // if reload_state null, then 'normal' init performed.
