/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*
* hccap format was introduced by oclHashcat-plus, and it is described here: http://hashcat.net/wiki/hccap
*/
#ifndef _WPAPSK_H
#define _WPAPSK_H

#define HCCAP_SIZE		392
#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

#define BINARY_SIZE		sizeof(mic_t)
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(hccap_t)
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

typedef struct
{
  char          essid[36];
  unsigned char mac1[6];
  unsigned char mac2[6];
  unsigned char nonce1[32];
  unsigned char nonce2[32];
  unsigned char eapol[256];
  int           eapol_size;
  int           keyver;
  unsigned char keymic[16];
} hccap_t;

typedef struct 
{
  unsigned char keymic[16];
} mic_t;

typedef struct {
	uint8_t length;
	uint8_t v[15];
} wpapsk_password;

typedef struct {
	uint32_t v[8];
} wpapsk_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[15];
} wpapsk_salt;

static const char wpapsk_prefix[] = "$WPAPSK$";

#endif