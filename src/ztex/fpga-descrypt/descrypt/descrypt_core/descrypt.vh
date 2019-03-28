/*
 * This software is Copyright (c) 2016,2019 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */
`ifndef _DESCRYPT_VH_
`define _DESCRYPT_VH_


`define SALT_NBITS 12
`define SALT_MSB `SALT_NBITS - 1

`define CRYPT_COUNT 25
`define CRYPT_COUNTER_NBITS 5

// Hash storage. MSB=9: 1023 hashes
`define RAM_ADDR_MSB 10

// Each core has up to NUM_BATCHES in flight, each batch
// contain NUM_CRYPT_INSTANSES items.
// * 1 batch in descrypt instances
// * 1 batch in comparator
// * 1-2 batches in core's output registers
`define NUM_BATCHES 4
`define NUM_BATCHES_MSB `MSB(`NUM_BATCHES-1)

// Arbiter processes that many pkt_id's at once.
`define NUM_PKTS 2
`define NUM_PKTS_MSB `MSB(`NUM_PKTS-1)

// Max. number of batches in packet
`define PKT_BATCHES_MSB 31

// Compare only first 35 bits of hash (64 is a remnant
// from earlier versions, may not work)
`define COMPARE_35_BIT
`ifdef COMPARE_35_BIT
	`define DIN_MSB 56
	`define HASH_MSB 34
`else
	`define DIN_MSB 64
	`define HASH_MSB 63
`endif

`define GLOBAL_SALT_MSB	11
`define GLOBAL_SALT_LSB	10

`endif
