/*
 * Initialization Data
 *
 * This software is Copyright (c) 2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#define PKT_TYPE_INIT_DATA	0x05
#define PKT_TYPE_CONFIG 	0x06

// Creates outgoing packet, type PKT_TYPE_INIT.
// The packet typically contains initialization data,
// it must be sent as the 1st packet after FPGA reset with GSR.
//struct pkt *pkt_init_data_new(unsigned char *data, int len);

// Same as above, initialization data is 1 byte
struct pkt *pkt_init_data_1b_new(char data_1b);

// creates PKT_TYPE_CONFIG
struct pkt *pkt_config_new(char subtype, char *data, int len);
