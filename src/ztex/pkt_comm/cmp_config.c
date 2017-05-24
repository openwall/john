/*
 * This software is Copyright (c) 2016 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "../../formats.h"
#include "../../loader.h"

#include "../device_bitstream.h"
#include "pkt_comm.h"
#include "cmp_config.h"

//
// Expecting salt and binaries are stored in network byte order
//
// Warning: global cmp_config
//
extern struct fmt_params *jtr_fmt_params;

extern struct device_bitstream *jtr_bitstream;

struct cmp_config cmp_config = { 
	-1 // using sequential_id's that start from 0
};


static int memcmp_reverse(const void *a, const void *b, size_t n)
{
	if (!n)
		return 0;
		
	const unsigned char *a_ptr = (const unsigned char *)a + n - 1;
	const unsigned char *b_ptr = (const unsigned char *)b + n - 1;
	
	while (n > 0) {
		if (*a_ptr != *b_ptr)
			return *a_ptr - *b_ptr;
		a_ptr--;
		b_ptr--;
		n--;
	}
	return 0;
}

static int compare_binaries(const void *a, const void *b)
{
	return memcmp_reverse(
		(*(struct db_password **)a)->binary,
		(*(struct db_password **)b)->binary,
		jtr_fmt_params->binary_size);
}


//struct cmp_config *
void cmp_config_new(struct db_salt *salt)
{
	//struct cmp_config *cmp_config = malloc(sizeof(struct cmp_config));
	//if (!cmp_config) {
	//	fprintf(stderr, "cmp_config_new: malloc()\n");
	//	exit(-1);
	//}
	int num_hashes = salt->count;
	if (num_hashes > jtr_bitstream->cmp_entries_max) {
		num_hashes = jtr_bitstream->cmp_entries_max;
		fprintf(stderr, "Warning: salt with %d hashes, device supports max. %d hashes/salt, extra hashes ignored\n",
				salt->count, jtr_bitstream->cmp_entries_max);
	}

	if (!num_hashes) {
		fprintf(stderr, "cmp_config_new: num_hashes == 0\n");
		exit(-1);
	}
	
	if (!cmp_config.pw || cmp_config.num_hashes_max < num_hashes) {
		if (cmp_config.pw)
			free(cmp_config.pw);
			
		int size = num_hashes * sizeof(struct db_password *);
		cmp_config.pw = malloc(size);
		if (!cmp_config.pw) {
			fprintf(stderr, "cmp_config_new: malloc(%d) failed\n", size);
			exit(-1);
		}
		cmp_config.num_hashes_max = num_hashes;
	}
	
	cmp_config.id = salt->sequential_id;
	cmp_config.salt = salt->salt;
	cmp_config.num_hashes = num_hashes;
	
	int offset = 0;
	struct db_password *pw;
	for (pw = salt->list; pw; pw = pw->next) {
		// FMT_REMOVE
		if (!pw->binary)
			continue;
		cmp_config.pw[offset++] = pw;
	}

	if (cmp_config.num_hashes == 1)
		return;
		
	// sort hashes in ascending order
	qsort(cmp_config.pw, cmp_config.num_hashes,
			sizeof(struct db_password *), compare_binaries);
}


struct pkt *pkt_cmp_config_new(struct cmp_config *cmp_config)
{
	int binary_size = jtr_fmt_params->binary_size;
	int salt_size = jtr_fmt_params->salt_size;
	
	int size = 3 + salt_size + cmp_config->num_hashes * binary_size;
	char *data = malloc(size);
	if (!data) {
		pkt_error("pkt_cmp_config_new(): unable to allocate %d bytes\n",
				size);
		return NULL;
	}

	int offset = 0;

	// PKT_TYPE_CMP_CONFIG. Salt starts at offset 0.
	memcpy(data + offset, cmp_config->salt, salt_size);
	offset += salt_size;

	if (cmp_config->num_hashes > jtr_bitstream->cmp_entries_max
			|| !cmp_config->num_hashes) {
		pkt_error("pkt_cmp_config_new(): bad num_hashes=%d\n",
				cmp_config->num_hashes);
		return NULL;
	}
	
	// PKT_TYPE_CMP_CONFIG. After salt - num_hashes (2 bytes).
	data[offset++] = cmp_config->num_hashes;
	data[offset++] = cmp_config->num_hashes >> 8;

	// PKT_TYPE_CMP_CONFIG. After num_hashes - sorted binaries.
	int i;
	for (i = 0; i < cmp_config->num_hashes; i++) {
		memcpy(data + offset, cmp_config->pw[i]->binary, binary_size);
		offset += binary_size;
	}

	// PKT_TYPE_CMP_CONFIG. 0xCC is the last byte in the packet.
	data[offset++] = 0xCC;
	
	struct pkt *pkt = pkt_new(PKT_TYPE_CMP_CONFIG, data, offset);
	/*
	for (i=0; i < offset; i++) {
		if ( !((i-4)%5) )
			printf("\n");
		printf("0x%02x ", data[i] & 0xff);
	}
	printf("data_len: %d\n", offset);
	*/
	return pkt;
}

