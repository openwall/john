/*
 * Comparator Configuration for remote devices.
 *
 * This software is Copyright (c) 2016-2017 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _CMP_CONFIG_H_
#define _CMP_CONFIG_H_

#include "../../formats.h"

#define PKT_TYPE_CMP_CONFIG		0x03

// Warning: global cmp_config

struct cmp_config {
	int id; // db_salt->sequential_id
	//unsigned char *salt;
	void *salt_ptr; // salt to send to device, of length salt_len
	int salt_len;
	unsigned int tunable_costs[FMT_TUNABLE_COSTS];
	int num_hashes;
	int num_hashes_max; // save on malloc/free
	struct db_password **pw;
};

extern struct cmp_config cmp_config;

// Comparator Configuration in CPU memory.
// Contains pointers to 'struct db_password' which contain
// hashes ("binaries").
// pointers are sorted by hash binary values (ascending order)
//
// Used for:
// - creation of cmp_config packets for remote devices
// - getting results with get_password() function.
//
// TODO: probably we can have sorted db_passwords's in db_salt?

void cmp_config_new(struct db_salt *salt, void *salt_ptr, int salt_len);

// Same as above, num_hashes=0
void cmp_config_nocompar_new(struct db_salt *salt, void *salt_ptr, int salt_len);

// Creates CMP_CONFIG packet for on-device comparator
struct pkt *pkt_cmp_config_new(struct cmp_config *cmp_config);

#endif
