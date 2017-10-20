/*
 * This software is Copyright (c) 2014 magnum and is hereby released to the
 * general public under the following terms: Redistribution and use in source
 * and binary forms, with or without modifications, are permitted.
 *
 * Some (or all) versions of Cygwin (and WinPcap) does not have ethernet.h.
 * For our uses (pointer arithmetics to get to the upper layers), this should
 * be enough.
 *
 * Thanks to Brian Dessent (http://cygwin.com/ml/cygwin/2003-07/msg01772.html)
 */

#if !__JTR_ETHERNET_H && !__NET_ETHERNET_H && !_SYS_ETHERNET_H
#define __JTR_ETHERNET_H 1

#include <stdint.h>

#define ether_header jtr_ether_header
struct ether_header
{
	uint8_t  ether_dhost[6];
	uint8_t  ether_shost[6];
	uint16_t ether_type;
} __attribute__ ((__packed__));

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800
#endif

#endif /* _*_ETHERNET_H */
