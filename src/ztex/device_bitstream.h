/*
 * This software is Copyright (c) 2016-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
#ifndef _DEVICE_BITSTREAM_H_
#define _DEVICE_BITSTREAM_H_

#include "pkt_comm/pkt_comm.h"

#define	NUM_PROGCLK_MAX		4

struct device_bitstream {
	// bitstream ID (check is performed by querying operating bitstream)
	unsigned short type;
	char *path;
	// parameters for high-speed packet communication (pkt_comm)
	struct pkt_comm_params pkt_comm_params;
	// device computing performance (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	// For hashes with variable computing difficulty, this is set at runtime.
	unsigned int candidates_per_crypt;
	// keys_per_crypt setting for self-test
	unsigned int test_keys_per_crypt;
	// keys/crypt_all_interval for all devices - link layer performance issue.
	// As keys are of variable size, this is a rough upper limit.
	unsigned int abs_max_keys_per_crypt;
	// Max. number of entries in onboard comparator
	int cmp_entries_max;
	// Min. number of keys for effective device utilization
	// per jtr_device (affects slow algorithms)
	int min_keys;
	// Min. number of template keys for effective utilization
	// (e.g. several on-device candidate generators)
	int min_template_keys;
	// Number of programmable clocks; startup frequencies (in MHz)
	int num_progclk;
	int freq[NUM_PROGCLK_MAX];
	// Label is used in john.conf for setting frequency
	// and other bitstream-specific properties
	char *label;
	// Initialization data is sent from the host after GSR
	char *init_data;
	int init_len;
};


#endif
