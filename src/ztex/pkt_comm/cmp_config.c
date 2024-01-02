/*
 * This software is Copyright (c) 2016-2017 Denis Burykin
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


// Create 'struct cmp_config' w/o comparator data (no hashes sent from host)
void cmp_config_nocompar_new(struct db_salt *salt, void *salt_ptr, int salt_len)
{
	cmp_config.id = salt->sequential_id;

	int cost_num;
	for (cost_num = 0; cost_num < FMT_TUNABLE_COSTS; cost_num ++) {
		if (jtr_fmt_params->tunable_cost_name[cost_num])
			cmp_config.tunable_costs[cost_num] = salt->cost[cost_num];
		else
			cmp_config.tunable_costs[cost_num] = 0;
	}

	cmp_config.salt_ptr = salt_ptr;
	cmp_config.salt_len = salt_len;

	cmp_config.num_hashes = 0;
}


//struct cmp_config *
void cmp_config_new(struct db_salt *salt, void *salt_ptr, int salt_len)
{
	//struct cmp_config *cmp_config = malloc(sizeof(struct cmp_config));
	//if (!cmp_config) {
	//	fprintf(stderr, "cmp_config_new: malloc()\n");
	//	exit(-1);
	//}
	static int warning_num_hashes = 0;
	int num_hashes = salt->count;
	if (num_hashes > jtr_bitstream->cmp_entries_max) {
		num_hashes = jtr_bitstream->cmp_entries_max;
		if (!warning_num_hashes) {
			fprintf(stderr, "Warning: salt with %d hashes, device supports "
				"max. %d hashes/salt, extra hashes ignored\n",
				salt->count, jtr_bitstream->cmp_entries_max);
			warning_num_hashes = 1;
		}
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

	int cost_num;
	for (cost_num = 0; cost_num < FMT_TUNABLE_COSTS; cost_num ++) {
		if (jtr_fmt_params->tunable_cost_name[cost_num])
			cmp_config.tunable_costs[cost_num] = salt->cost[cost_num];
		else
			cmp_config.tunable_costs[cost_num] = 0;
	}

	// db_salt->salt depends on host system (e.g. different on 32 and 64-bit).
	// salt length may also vary.
	// Format has to provide binary salt in arch-independent form,
	// typically network-byte order, and provide correct salt_len.
	//cmp_config.salt = salt->salt;
	cmp_config.salt_ptr = salt_ptr;
	cmp_config.salt_len = salt_len;

	cmp_config.num_hashes = 0;

	int offset = 0;
	struct db_password *pw;
	for (pw = salt->list; pw; pw = pw->next) {
		// FMT_REMOVE issue.
		// pw->binary is excluded from the list and(or) NULL'ed
		// on any successful guess, regardless of FMT_REMOVE flag.
		if (!pw->binary)
			continue;
		cmp_config.pw[offset++] = pw;
		cmp_config.num_hashes ++;
		if (cmp_config.num_hashes == jtr_bitstream->cmp_entries_max)
			break;
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

	int size = 3 + cmp_config->salt_len
			+ cmp_config->num_hashes * binary_size
			+ 4 * FMT_TUNABLE_COSTS;
	char *data = malloc(size);
	if (!data) {
		pkt_error("pkt_cmp_config_new(): unable to allocate %d bytes\n",
				size);
		return NULL;
	}

	int offset = 0;

	// PKT_TYPE_CMP_CONFIG. Salt starts at offset 0.
	memcpy(data + offset, cmp_config->salt_ptr, cmp_config->salt_len);
	offset += cmp_config->salt_len;
#if 0
	if (cmp_config->num_hashes > jtr_bitstream->cmp_entries_max
			|| !cmp_config->num_hashes) {
		pkt_error("pkt_cmp_config_new(): bad num_hashes=%d\n",
				cmp_config->num_hashes);
		return NULL;
	}
#endif
	// If format has tunable costs - send after salt
	// (4 bytes each tunable cost value)
	int tunable_cost_num;
	for (tunable_cost_num = 0; tunable_cost_num < FMT_TUNABLE_COSTS;
				tunable_cost_num ++) {
		unsigned int cost = cmp_config->tunable_costs[tunable_cost_num];
		if (!cost)
			break;

		data[offset++] = cost;
		data[offset++] = cost >> 8;
		data[offset++] = cost >> 16;
		data[offset++] = cost >> 24;
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
