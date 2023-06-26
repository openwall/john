// http://www.willhackforsushi.com/code/eapmd5pass/1.4/eapmd5pass-1.4.tgz
//
// cat radiotap.h utils.h byteswap.h eapmd5pass.h ieee80211.h ieee8021x.h ietfproto.h utils.c eapmd5pass.c > combined.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <pcap.h>
#include <errno.h>
#include <getopt.h>

#include "md5.h"

/* $FreeBSD: src/sys/net80211/ieee80211_radiotap.h,v 1.5 2005/01/22 20:12:05 sam Exp $ */
/* $NetBSD: ieee80211_radiotap.h,v 1.11 2005/06/22 06:16:02 dyoung Exp $ */

/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef RADIOTAP_H
#define RADIOTAP_H

/* Kluge the radiotap linktype for now if we don't have it */
#ifndef LNX_ARPHRD_IEEE80211_RADIOTAP
#define LNX_ARPHRD_IEEE80211_RADIOTAP 803
#endif

/* Radiotap header version (from official NetBSD feed) */
#define IEEE80211RADIOTAP_VERSION	"1.5"
/* Base version of the radiotap packet header data */
#define PKTHDR_RADIOTAP_VERSION		0

/* The radio capture header precedes the 802.11 header. */
struct ieee80211_radiotap_header {
	uint8_t	       it_version;	/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	uint8_t        it_pad;
	uint16_t       it_len;          /* length of the whole
					 * header in bytes, including
					 * int_version, it_pad,
					 * it_len, and data fields.
					 */
	uint32_t       it_present;      /* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
};

/* Name                                 Data type       Units
 * ----                                 ---------       -----
 *
 * IEEE80211_RADIOTAP_TSFT              u_int64_t       microseconds
 *
 *      Value in microseconds of the MAC's 64-bit 802.11 Time
 *      Synchronization Function timer when the first bit of the
 *      MPDU arrived at the MAC. For received frames, only.
 *
 * IEEE80211_RADIOTAP_CHANNEL           2 x u_int16_t   MHz, bitmap
 *
 *      Tx/Rx frequency in MHz, followed by flags (see below).
 *
 * IEEE80211_RADIOTAP_FHSS              u_int16_t       see below
 *
 *      For frequency-hopping radios, the hop set (first byte)
 *      and pattern (second byte).
 *
 * IEEE80211_RADIOTAP_RATE              u_int8_t        500kb/s
 *
 *      Tx/Rx data rate
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_DBM_ANTNOISE      int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF noise power at the antenna, decibel difference from one
 *      milliwatt.
 *
 * IEEE80211_RADIOTAP_DB_ANTSIGNAL      u_int8_t        decibel (dB)
 *
 *      RF signal power at the antenna, decibel difference from an
 *      arbitrary, fixed reference.
 *
 * IEEE80211_RADIOTAP_DB_ANTNOISE       u_int8_t        decibel (dB)
 *
 *      RF noise power at the antenna, decibel difference from an
 *      arbitrary, fixed reference point.
 *
 * IEEE80211_RADIOTAP_LOCK_QUALITY      u_int16_t       unitless
 *
 *      Quality of Barker code lock. Unitless. Monotonically
 *      nondecreasing with "better" lock strength. Called "Signal
 *      Quality" in datasheets.  (Is there a standard way to measure
 *      this?)
 *
 * IEEE80211_RADIOTAP_TX_ATTENUATION    u_int16_t       unitless
 *
 *      Transmit power expressed as unitless distance from max
 *      power set at factory calibration.  0 is max power.
 *      Monotonically nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DB_TX_ATTENUATION u_int16_t       decibels (dB)
 *
 *      Transmit power expressed as decibel distance from max power
 *      set at factory calibration.  0 is max power.  Monotonically
 *      nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DBM_TX_POWER      int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      Transmit power expressed as dBm (decibels from a 1 milliwatt
 *      reference). This is the absolute power level measured at
 *      the antenna port.
 *
 * IEEE80211_RADIOTAP_FLAGS             u_int8_t        bitmap
 *
 *      Properties of transmitted and received frames. See flags
 *      defined below.
 *
 * IEEE80211_RADIOTAP_ANTENNA           u_int8_t        antenna index
 *
 *      Unitless indication of the Rx/Tx antenna for this packet.
 *      The first antenna is antenna 0.
 *
 * IEEE80211_RADIOTAP_FCS           	u_int32_t       data
 *
 *	FCS from frame in network byte order.
 */
enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_FCS = 14,
	IEEE80211_RADIOTAP_EXT = 31,
};

/* Channel flags. */
#define	IEEE80211_CHAN_TURBO	0x0010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x0020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x0040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x0080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x0100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x0200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x0800	/* GFSK channel (FHSS PHY) */

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
						 * during CFP
						 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
						 * with short
						 * preamble
						 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
						 * with fragmentation
						 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */

/* Ugly macro to convert literal channel numbers into their mhz equivalents
 * There are certianly some conditions that will break this (like feeding it '30')
 * but they shouldn't arise since nothing talks on channel 30. */
#define ieee80211chan2mhz(x) \
	(((x) <= 14) ? \
	(((x) == 14) ? 2484 : ((x) * 5) + 2407) : \
	((x) + 1000) * 5)

#endif /* RADIOTAP_H */

/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* Prototypes */
void to_upper (char *s);
int str2hex (char *string, uint8_t *hexstr, int len);
/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef BYTESWAP_H
#define BYTESWAP_H

#define __swab16(x) \
({ \
        uint16_t __x = (x); \
        ((uint16_t)( \
                (((uint16_t)(__x) & (uint16_t)0x00ffU) << 8) | \
                (((uint16_t)(__x) & (uint16_t)0xff00U) >> 8) )); \
})

#define __swab32(x) \
({ \
        uint32_t __x = (x); \
        ((uint32_t)( \
                (((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
                (((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
                (((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
                (((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) )); \
})

#define __swab64(x) \
({ \
        uint64_t __x = (x); \
        ((uint64_t)( \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

#ifdef WORDS_BIGENDIAN
#warning "Compiling for big-endian"
#define le16_to_cpu(x) __swab16(x)
#define le32_to_cpu(x) __swab32(x)
#define le64_to_cpu(x) __swab64(x)
#else
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#endif

#endif /* BYTESWAP_H */
/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef EAPMD5PASS_H
#define EAPMD5PASS_H

#define DOT11_OFFSET_DOT11     0
#define DOT11_OFFSET_TZSP      29
#define DOT11_OFFSET_PRISMAVS  144

#define PCAP_DONOTBLOCK 1

#define IEEE802_MACLEN 6

#define PCAP_LOOP_CNT -1

#define SNAPLEN 2312
#define PROMISC 1
#define TIMEOUT 500

struct eapmd5pass_data {
	uint8_t         bssid[6];
	char		wordfile[1024];
	unsigned int	mcastid;
	uint8_t         bssidset;
	int		recovered_pass;

	/* Parser tracking values */
	uint8_t		namefound;
	uint8_t		chalfound;
	uint8_t		respfound;
	uint8_t		succfound;
	uint8_t		eapid;

	/* Extracted from EAP-MD5 exchange */
	char		username[64];
	uint8_t		challenge[16];
	uint8_t		response[16];
	uint8_t		respeapid;
};

static void cleanexit(int signum);
void usage();
int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h);
void assess_packet(char *user, struct pcap_pkthdr *h, uint8_t *pkt);
void eapmd5_nexttarget(struct eapmd5pass_data *em);
int extract_eapusername(uint8_t *eap, int eaplen, struct eapmd5pass_data *em);
int extract_eapchallenge(uint8_t *eap, int eaplen, struct eapmd5pass_data *em);
int extract_eapresponse(uint8_t *eap, int eaplen, struct eapmd5pass_data *em);
int extract_eapsuccess(uint8_t *eap, int eaplen, struct eapmd5pass_data *em);
static void break_pcaploop(int signum);
int main(int argc, char *argv[]);

#endif
/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef IEEE80211_H
#define IEEE80211_H

#define DOT11HDR_A1_LEN 10
#define DOT11HDR_A3_LEN 24
#define DOT11HDR_A4_LEN 30
#define DOT11HDR_MAC_LEN 6
#define DOT11HDR_MINLEN DOT11HDR_A1_LEN

#define DOT11_FC_TYPE_MGMT 0
#define DOT11_FC_TYPE_CTRL 1
#define DOT11_FC_TYPE_DATA 2

#define DOT11_FC_SUBTYPE_ASSOCREQ    0
#define DOT11_FC_SUBTYPE_ASSOCRESP   1
#define DOT11_FC_SUBTYPE_REASSOCREQ  2
#define DOT11_FC_SUBTYPE_REASSOCRESP 3
#define DOT11_FC_SUBTYPE_PROBEREQ    4
#define DOT11_FC_SUBTYPE_PROBERESP   5
#define DOT11_FC_SUBTYPE_BEACON      8
#define DOT11_FC_SUBTYPE_ATIM        9
#define DOT11_FC_SUBTYPE_DISASSOC    10
#define DOT11_FC_SUBTYPE_AUTH        11
#define DOT11_FC_SUBTYPE_DEAUTH      12

#define DOT11_FC_SUBTYPE_PSPOLL      10
#define DOT11_FC_SUBTYPE_RTS         11
#define DOT11_FC_SUBTYPE_CTS         12
#define DOT11_FC_SUBTYPE_ACK         13
#define DOT11_FC_SUBTYPE_CFEND       14
#define DOT11_FC_SUBTYPE_CFENDACK    15

#define DOT11_FC_SUBTYPE_DATA            0
#define DOT11_FC_SUBTYPE_DATACFACK       1
#define DOT11_FC_SUBTYPE_DATACFPOLL      2
#define DOT11_FC_SUBTYPE_DATACFACKPOLL   3
#define DOT11_FC_SUBTYPE_DATANULL        4
#define DOT11_FC_SUBTYPE_CFACK           5
#define DOT11_FC_SUBTYPE_CFACKPOLL       6
#define DOT11_FC_SUBTYPE_CFACKPOLLNODATA 7
#define DOT11_FC_SUBTYPE_QOSDATA         8
/* 9 - 11 reserved as of 11/7/2005 - JWRIGHT */
#define DOT11_FC_SUBTYPE_QOSNULL         12

struct dot11hdr {
	union {
		struct {
			uint8_t		version:2;
			uint8_t		type:2;
			uint8_t		subtype:4;
			uint8_t		to_ds:1;
			uint8_t		from_ds:1;
			uint8_t		more_frag:1;
			uint8_t		retry:1;
			uint8_t		pwrmgmt:1;
			uint8_t		more_data:1;
			uint8_t		protected:1;
			uint8_t		order:1;
		} __attribute__ ((packed)) fc;

		uint16_t	fchdr;
	} u1;

	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];

	union {
		struct {
			uint16_t	fragment:4;
			uint16_t	sequence:12;
		} __attribute__ ((packed)) seq;

		uint16_t	seqhdr;
	} u2;

} __attribute__ ((packed));

#define dot11hdra3 dot11hdr
#define ieee80211 dot11hdr

struct ieee80211_qos {
	uint8_t priority:3;
	uint8_t reserved3:1;
	uint8_t eosp:1;
	uint8_t ackpol:2;
	uint8_t reserved1:1;
	uint8_t reserved2;
} __attribute__ ((packed));
#define DOT11HDR_QOS_LEN 2


struct ieee8022 {
	uint8_t    dsap;
	uint8_t    ssap;
	uint8_t    control;
	uint8_t    oui[3];
	uint16_t   type;
} __attribute__ ((packed));
#define DOT2HDR_LEN sizeof(struct ieee8022)

#define IEEE8022_SNAP 0xaa
#define IEEE8022_TYPE_IP 0x0800
#define IEEE8022_TYPE_DOT1X 0x888e
#define IEEE8022_TYPE_ARP 0x0806


#endif
/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef IEEE8021X_H
#define IEEE8021X_H

/* The 802.1X header indicates a version, type and length */
struct ieee8021x {
	uint8_t    version;
	uint8_t    type;
	uint16_t   len;
} __attribute__ ((packed));
#define DOT1XHDR_LEN sizeof(struct ieee8021x)

#define DOT1X_VERSION1 1
#define DOT1X_VERSION2 2
#define DOT1X_TYPE_EAP 0

#endif
/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef IETFPROTO_H
#define IETFPROTO_H

/* EAP message constants */
#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4

/* EAP types, more at http://www.iana.org/assignments/eap-numbers */
#define EAP_TYPE_EAP	0
#define EAP_TYPE_ID     1
#define EAP_TYPE_MD5    4

struct eap_hdr {
	uint8_t    code; /* 1=request, 2=response, 3=success, 4=failure? */
	uint8_t    identifier;
	uint16_t   length; /* Length of the entire EAP message */

	/* The following fields may not be present in all EAP frames */
	uint8_t    type;
	uint8_t    flags;
	uint32_t   totallen;
} __attribute__ ((packed));
#define EAPHDR_MIN_LEN 4

#endif
/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <ctype.h>

void to_upper (char *s)
{
	char *p;
	char offset;

	offset = 'A' - 'a';
	for (p = s; *p != '\0'; p++) {
		if (islower(*p)) {
			*p += offset;
		}
	}
}

/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* pcap descriptor */
pcap_t *p = NULL;
struct pcap_pkthdr *h;
uint8_t *dot11packetbuf;
int __verbosity = 0;
int offset = 0; /* Offset of pcap data to beginning of frame */
long pcount = 0; /* Total number of packets observed */
struct eapmd5pass_data em;

static void cleanexit(int signum)
{
	if (p != NULL) {
		pcap_close(p);
	}

	if (em.recovered_pass > 0) {
		exit(0);
	} else {
		exit(1);
	}
}

/* Determine radiotap data length (including header) and return offset for the
   beginning of the 802.11 header */
int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h)
{
	struct ieee80211_radiotap_header *rtaphdr;
	int rtaphdrlen = 0;

	/* Grab a packet to examine radiotap header */
	if (pcap_next_ex(p, &h, (const u_char **)&dot11packetbuf) > -1) {

		rtaphdr = (struct ieee80211_radiotap_header *)dot11packetbuf;
		rtaphdrlen = le16_to_cpu(rtaphdr->it_len); /* rtap is LE */

		/* Sanity check on header length */
		if (rtaphdrlen > (h->len - DOT11HDR_MINLEN)) {
			return -2; /* Bad radiotap data */
		}

		return rtaphdrlen;
	}

	return -1;
}

static void print_hex(unsigned char *str, int len)
{
        int i;

        for (i = 0; i < len; i++)
                printf("%02x", str[i]);
}

void assess_packet(char *user, struct pcap_pkthdr *h, uint8_t *pkt)
{
	struct dot11hdr *dot11;
	struct ieee8021x *dot1xhdr;
	struct ieee8022 *dot2hdr;
	struct eap_hdr *eaphdr;
	uint8_t *bssidaddrptr;
	int plen, poffset;
	struct eapmd5pass_data *em;
	extern long pcount;

	em = (struct eapmd5pass_data *)user;

	pcount++; /* Global packet counter */
	if (__verbosity > 2) {
		printf("Checking Frame: %ld....\n",pcount);
	}

	if (offset < 0)
		return;

	 if (offset + sizeof(struct dot11hdr) > h->caplen)
                return;

	poffset = offset;
	plen = h->len - offset;
	if (plen > DOT11HDR_A3_LEN) {
		dot11 = (struct dot11hdr *)(pkt+offset);
	} else {
		if (__verbosity > 1) {
			printf("\tDiscarding too-small frame (%d).\n", plen);
		}
		return;
	}

	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 1) {
		/* Ignore WDS frames */
		if (__verbosity > 2) {
			printf("\tDiscarding WDS frame.\n");
		}
		return;
	} else if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0) {
		/* From the DS */
		bssidaddrptr = dot11->addr2;
	} else if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1) {
		/* To the DS, interesting to us */
		bssidaddrptr = dot11->addr1;
	} else { /* fromds = 0, tods = 0 */
		/* Ad-hoc, can this be used with PEAP? */
		bssidaddrptr = dot11->addr3;
	}

	if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not type data.\n");
		}
		return;
	}

	/* Discard traffic for other BSSID's if one was specified; otherwise,
	   all networks are fair game. */
	if (em->bssidset) {
		if (memcmp(em->bssid, bssidaddrptr, IEEE802_MACLEN) != 0) {
			return;
		}
	}

	poffset += DOT11HDR_A3_LEN;
	plen -= DOT11HDR_A3_LEN;

	if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_QOSDATA) {
		/* Move another 2 bytes past QoS header */
		poffset += DOT11HDR_QOS_LEN;
		plen -= DOT11HDR_QOS_LEN;
	} else if (dot11->u1.fc.subtype != DOT11_FC_SUBTYPE_DATA) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not-applicable subtype: "
					"%02x.\n", dot11->u1.fc.subtype);
		}
		return;
	}

	if (plen <= 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame with no payload.\n");
		}
		return;
	}


	/* IEEE 802.2 header */
	dot2hdr = (struct ieee8022 *)(pkt+poffset);
	poffset += DOT2HDR_LEN;
	plen -= DOT2HDR_LEN;

	if (poffset + sizeof(struct ieee8022) > h->caplen)
		return;

	if (plen <= 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame with partial 802.2 header.\n");
		}
		return;
	}

	/* Check 802.2 header for embedded IEEE 802.1x authentication */
	if (dot2hdr->dsap != IEEE8022_SNAP || dot2hdr->ssap != IEEE8022_SNAP) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, invalid 802.2 header.\n");
		}
		return;
	}
	if (ntohs(dot2hdr->type) != IEEE8022_TYPE_DOT1X) {
		if (__verbosity > 2) {
			printf("\tDicarding frame, embedded protocol is not "
					"IEEE 802.1x (%04x).\n", dot2hdr->type);
		}
		return;
	}


	/* IEEE 802.1x header */
	dot1xhdr = (struct ieee8021x *)(pkt + poffset);
	plen -= DOT1XHDR_LEN;
	poffset += DOT1XHDR_LEN;
	if (poffset + sizeof(struct ieee8021x) > h->caplen)
		return;

	if (plen <= 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, too short for 802.1x (%d).\n",
					h->len - offset);
		}
		return;
	}

	if (dot1xhdr->version != DOT1X_VERSION1 &&
			dot1xhdr->version != DOT1X_VERSION2) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not an 802.1x packet.\n");
		}
		return;
	}

	if (dot1xhdr->type != DOT1X_TYPE_EAP) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not an EAP packet.\n");
		}
		return;
	}

	/* EAP header contents */
	eaphdr = (struct eap_hdr *)(pkt + poffset);

	if ((plen - EAPHDR_MIN_LEN) < 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, too short for EAP (%d).\n",
					h->len - offset);
		}
		return;
	}

	if (eaphdr->type != EAP_TYPE_ID && eaphdr->type != EAP_TYPE_MD5 &&
			eaphdr->type != EAP_TYPE_EAP) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not EAP Identification or "
					"EAP-MD5.\n");
		}
		return;
	}

	/* Try to extract username */
	if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1 &&
			eaphdr->type == EAP_TYPE_ID) {
		if (extract_eapusername((pkt+poffset), plen, em) == 0) {
			if (__verbosity > 2) {
				printf("\tFound Username!\n");
			}
			em->namefound=1;
			return;
		}
	}

	/* Try to extract the challenge */
	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0 &&
			eaphdr->type == EAP_TYPE_MD5 &&
			em->namefound == 1 &&
			em->chalfound == 0) {
		if (extract_eapchallenge((pkt+poffset), plen, em) == 0) {
			if (__verbosity > 2) {
				printf("\tFound Challenge!\n");
			}

			em->chalfound = 1;
			return;
		}
	}

	/* Try to extract the response */
	if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1 &&
			eaphdr->type == EAP_TYPE_MD5 &&
			em->namefound == 1 &&
			em->chalfound == 1 &&
			em->respfound == 0) {
		if (extract_eapresponse((pkt+poffset), plen, em) == 0) {
			if (__verbosity > 2) {
				printf("\tFound Response!\n");
			}

			em->respfound = 1;
			return;
		}
	}

	/* Try to extract the success message */
	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0 &&
			em->namefound == 1 &&
			em->chalfound == 1 &&
			em->respfound == 1) {
		if (__verbosity > 2) {
			printf("\tFound Possible EAP Success!\n");
		}

		if (extract_eapsuccess((pkt+poffset), plen, em) == 0) {
			em->succfound = 1;
			/* printf("Collected all data necessary to attack "
					"password for \"%s\", starting attack."
					"\n", em->username); */
			printf("%s:$chap$%d*", em->username, em->respeapid);
			print_hex(em->challenge, 16);
			printf("*");
			print_hex(em->response, 16);
			printf("\n");
			eapmd5_nexttarget(em);
			return;
		} else {
			if (__verbosity >2) {
				printf("\tCould not confirm EAP Success\n");
			}
		}
	}

	return;
}

void eapmd5_nexttarget(struct eapmd5pass_data *em)
{
	/* Reset tracking values for the next attack */
	em->namefound = 0;
	em->chalfound = 0;
	em->respfound = 0;
	em->succfound = 0;
	return;
}

int extract_eapusername(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;
	int usernamelen;
	int eaplen;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code != EAP_RESPONSE) {
		return 1;
	}

	if (eaphdr->type != EAP_TYPE_ID) {
		return 1;
	}

	eaplen = ntohs(eaphdr->length);
	if (eaplen > len) {
		return 1;
	}

	/* 5 bytes for EAP header information without identity information */
	usernamelen = (eaplen - 5);
	if (usernamelen < 0)
		return 1;

	usernamelen = (eaplen > sizeof(em->username))
		? sizeof(em->username) : usernamelen;
	memcpy(em->username, (eap+5), usernamelen);
	em->username[usernamelen] = 0;

	return 0;
}

int extract_eapchallenge(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;
	int eaplen;
	int offset;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code != EAP_REQUEST) {
		return 1;
	}

	if (eaphdr->type != EAP_TYPE_MD5) {
		return 1;
	}

	eaplen = ntohs(eaphdr->length);
	if (eaplen > len) {
		return 1;
	}

	/* 5th byte offset is the value-size parameter */
	if ((eap[5]) != 16) {
		return 1;
	}

	len -= 6;
	offset = 6;

	if (len <= 0) {
		return 1;
	}

	memcpy(em->challenge, (eap+offset), 16);
	return 0;
}


int extract_eapresponse(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;
	int eaplen;
	int offset;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code != EAP_RESPONSE) {
		return 1;
	}

	if (eaphdr->type != EAP_TYPE_MD5) {
		return 1;
	}

	eaplen = ntohs(eaphdr->length);
	if (eaplen > len) {
		return 1;
	}

	/* 5th byte offset is the value-size parameter */
	if ((eap[5]) != 16) {
		return 1;
	}

	len -= 6;
	offset = 6;

	if (len <= 0) {
		return 1;
	}

	memcpy(em->response, (eap+offset), 16);
	em->respeapid = eaphdr->identifier;
	return 0;
}

int extract_eapsuccess(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code == EAP_FAILURE) {
		/* Reset tracking values for next exchange */
		eapmd5_nexttarget(em);
	}

	if (eaphdr->code == EAP_SUCCESS) {
		return 0;
	}

	return 1;
}

/* Called by signal SIGALRM */
static void break_pcaploop(int signum)
{
	if (__verbosity > 2) {
		printf("Calling pcap_breakloop.\n");
	}
	pcap_breakloop(p);
}

#ifdef HAVE_LIBFUZZER
int main_dummy(int argc, char **argv)
#else
int main(int argc, char *argv[])
#endif
{
	char errbuf[PCAP_ERRBUF_SIZE], iface[17], pcapfile[1024];
	int opt = 0, datalink = 0, ret = 0;
	extern struct eapmd5pass_data em;

	memset(&em, 0, sizeof(em));
	memset(pcapfile, 0, sizeof(pcapfile));

	// printf("eapmd5pass - Dictionary attack against EAP-MD5\n");
	while ((opt = getopt(argc, argv, "r:vVh?")) != -1) {
		switch(opt) {
			case 'r':
				/* Read from pcap file */
				strncpy(pcapfile, optarg, sizeof(pcapfile)-1);
				break;
			case 'v':
				__verbosity++;
				break;
			case 'V':
				printf("eapmd5pass - 1.0\n$Id: eapmd5pass.c,v 1.4 2008/02/10 02:24:34 jwright Exp $\n");
				return(0);
				break;
			default:
				printf("Usage: %s -r <pcap file>\n", argv[0]);
				return(-1);
				break;
		}
	}

	/* Register signal handlers */
	signal(SIGINT, cleanexit);
	signal(SIGTERM, cleanexit);
	signal(SIGQUIT, cleanexit);

	/* Test for minimum number of arguments */
	if (argc < 3) {
		// usage();
		printf("Usage: %s -r <pcap file>\n", argv[0]);
		return -1;
	}

	optind = 0;

	if (strlen(pcapfile) > 0) {
		/* User has specified a libpcap file for reading */
		p = pcap_open_offline(pcapfile, errbuf);
	} else {
		p = pcap_open_live(iface, SNAPLEN, PROMISC, TIMEOUT, errbuf);
	}

	if (p == NULL) {
		fprintf(stderr, "Unable to open pcap device, %s\n", errbuf);
		perror("pcap_open");
		return -1;
	}

	/* Set non-blocking */
	/* if (pcap_setnonblock(p, PCAP_DONOTBLOCK, errbuf) != 0) {
		fprintf(stderr, "Error placing pcap interface in non-blocking "
				"mode.\n");
		perror("pcap_setnonblock");
		pcap_close(p);
		goto bailout;
	} */
	/* Examine header length to determine offset of the 802.11 header */
	datalink = pcap_datalink(p);
	switch(datalink) {

		case DLT_IEEE802_11_RADIO: /* Variable length header */
			offset = radiotap_offset(p, h);
			if (offset < sizeof(struct ieee80211_radiotap_header)) {
				fprintf(stderr, "Unable to determine offset from "
						"radiotap header (%d).\n", offset);
				// usage();
				goto bailout;
			}
			break;

		case DLT_IEEE802_11:
			offset = DOT11_OFFSET_DOT11;
			break;

#ifdef DLT_TZSP
		case DLT_TZSP:
			offset = DOT11_OFFSET_TZSP;
			break;
#endif

#ifdef DLT_PRISM_HEADER
		case DLT_PRISM_HEADER:
			offset = DOT11_OFFSET_PRISMAVS;
			break;
#endif

		default:
			fprintf(stderr, "Unrecognized datalink type %d.\n", datalink);
			// usage();
			goto bailout;
	}

	/* Loop for each packet received */
	signal(SIGALRM, break_pcaploop);

	/* We need a different routine for handling read from pcapfile vs. live
	   interface, because pcap_dispatch returns 0 for EOF on pcapfile, or
	   no packets retrieved due to blocking on a live interface */
	if (strlen(pcapfile) > 0) {
		ret = pcap_dispatch(p, PCAP_LOOP_CNT,
				(pcap_handler)assess_packet, (u_char *)&em);
		if (ret != 0) {
			/* Error reading from packet capture file */
			fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(p));
			goto bailout;
		}

	} else { /* live packet capture */

		while(1) {
			ret = pcap_dispatch(p, PCAP_LOOP_CNT,
					(pcap_handler)assess_packet,
					(u_char *)&em);
			if (ret == 0) {
				/* No packets read, sleep and continue */
				usleep(250000);
				continue;
			} else if (ret == -1) {
				fprintf(stderr, "pcap_loop: %s",
						pcap_geterr(p));
				break;
			} else if (ret == -2) {
				/* returned -2, pcap_breakloop called */
				break;
			} else {
				/* Packet retrieved successfully, continue */
				continue;
			}
		}
	}

	if (__verbosity) {
		printf("Total packets observed: %ld\n", pcount);
	}

bailout:

	pcap_close(p);

	if (em.recovered_pass > 0) {
		return 0;
	} else {
		return 1;
	}
}

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";
	char *argv[] = {"dummy", "-r", name, "/dev/null", NULL};

	fd = mkstemp(name);
	if (fd < 0) {
		fprintf(stderr, "Problem detected while creating the input file, %s, aborting!\n", strerror(errno));
		exit(-1);
	}
	write(fd, data, size);
	close(fd);
	main_dummy(4, argv);
	remove(name);

        return 0;
}
#endif
