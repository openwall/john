/*
 * This software is Copyright (c) 2013 Jim Fougeron jfoug AT cox dot net,
 * Copyright (c) 2013 Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2014-2018 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * Structs and data (some from wireshark, airodump-ng and hcxtool suite)
 */

#ifdef _MSC_VER
#define inline _inline
#endif

#include <stdint.h>

#include "arch.h"
#include "johnswap.h"
#include "hccap.h"

/*
 * Most data structures must be byte aligned, since we work on 'raw' data in
 * structures and do not load structures record by record.
 */
#pragma pack(1)

#define TCPDUMP_MAGIC           0xa1b2c3d4
#define TCPDUMP_CIGAM           0xd4c3b2a1

#define PCAPNGBLOCKTYPE         0x0a0d0d0a
#define PCAPNGMAGICNUMBER       0x1a2b3c4d
#define PCAPNGMAGICNUMBERBE     0x4d3c2b1a

#define LINKTYPE_ETHERNET       1
#define LINKTYPE_IEEE802_11     105
#define LINKTYPE_PRISM_HEADER   119
#define LINKTYPE_RADIOTAP_HDR   127
#define LINKTYPE_PPI_HDR        192

/* PCAP main file header */
typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number 0xA1B2C3D4 (or 0xD4C3B2A1 BE) */
	uint16_t version_major;  /* major version number 0x0200 */
	uint16_t version_minor;  /* minor version number 0x0400 */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

/* PCAP packet header */
typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t snap_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/* Header of all pcapng blocks */
typedef struct block_header_s {
	uint32_t	block_type;	/* block type */
	uint32_t	total_length;	/* block length */
} block_header_t;
#define	BH_SIZE (sizeof(block_header_t))

/* Header of all pcapng options */
typedef struct option_header_s {
	uint16_t		option_code;	/* option code - depending of block (0 - end of opts, 1 - comment are in common) */
	uint16_t		option_length;	/* option length - length of option in bytes (will be padded to 32bit) */
} option_header_t;
#define	OH_SIZE (sizeof(option_header_t))

/* Section Header Block (SHB) - ID 0x0A0D0D0A */
typedef struct section_header_block_s {
	uint32_t	byte_order_magic;	/* byte order magic - indicates swapped data */
	uint16_t	major_version;		/* major version of pcapng (1 atm) */
	uint16_t	minor_version;		/* minor version of pcapng (0 atm) */
	int64_t	section_length;		/* length of section - can be -1 (parsing necessary) */
} section_header_block_t;
#define	SHB_SIZE (sizeof(section_header_block_t))

/* Interface Description Block (IDB) - ID 0x00000001 */
typedef struct interface_description_block_s {
	uint16_t	linktype;	/* the link layer type (was -network- in classic pcap global header) */
	uint16_t	reserved;	/* 2 bytes of reserved data */
	uint32_t	snaplen;	/* maximum number of bytes dumped from each packet (was -snaplen- in classic pcap global header */
} interface_description_block_t;
#define	IDB_SIZE (sizeof(interface_description_block_t))

/* Packet Block (PB) - ID 0x00000002 (OBSOLETE - EPB should be used instead) */
typedef struct packet_block_s {
	uint16_t	interface_id;	/* the interface the packet was captured from - identified by interface description block in current section */
	uint16_t	drops_count;	/* packet dropped by IF and OS since prior packet */
	uint32_t	timestamp_high;	/* high bytes of timestamp */
	uint32_t	timestamp_low;	/* low bytes of timestamp */
	uint32_t	caplen;	/* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
	uint32_t	len;	/* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} packet_block_t;
#define	PB_SIZE (sizeof(packet_block_t))

/* Simple Packet Block (SPB) - ID 0x00000003 */
typedef struct simple_packet_block_s {
	uint32_t	len;  /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} simple_packet_block_t;
#define	SPB_SIZE (sizeof(simple_packet_block_t))

/* Name Resolution Block (NRB) - ID 0x00000004 */
typedef struct name_resolution_block_s {
	uint16_t	record_type;    /* type of record (ipv4 / ipv6) */
	uint16_t	record_length;  /* length of record value */
} name_resolution_block_t;
#define	NRB_SIZE (sizeof(name_resolution_block_t))

/* Interface Statistics Block - ID 0x00000005 */
typedef struct interface_statistics_block_s {
	uint32_t	interface_id;     /* the interface the stats refer to - identified by interface description block in current section */
	uint32_t	timestamp_high;   /* high bytes of timestamp */
	uint32_t	timestamp_low;    /* low bytes of timestamp */
} interface_statistics_block_t;
#define	ISB_SIZE (sizeof(interface_statistics_block_t))

/* Enhanced Packet Block (EPB) - ID 0x00000006 */
typedef struct enhanced_packet_block_s {
	uint32_t	interface_id;     /* the interface the packet was captured from - identified by interface description block in current section */
	uint32_t	timestamp_high;   /* high bytes of timestamp */
	uint32_t	timestamp_low;    /* low bytes of timestamp */
	uint32_t	caplen;           /* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
	uint32_t	len;              /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
} enhanced_packet_block_t;
#define	EPB_SIZE (sizeof(enhanced_packet_block_t))

/* Ok, here are the struct we need to decode 802.11 for JtR */
typedef struct ieee802_1x_frame_hdr_s {
	uint16_t frame_ctl;
	uint16_t duration;
	uint8_t  addr1[6]; // RA (receiver)
	uint8_t  addr2[6]; // TA (transmitter)
	uint8_t  addr3[6]; // SA (original sender)
	uint16_t seq;
//	int8_t   addr4[6]; // optional DA (final destination) (if toDS && fromDS)
//	uint16_t qos_ctl; // optional (if X then it is set)
//	uint16_t ht_ctl;  // optional (if X then it is set)
//	int8_t   body[1];
} ieee802_1x_frame_hdr_t;

/* bitmap of the ieee802_1x_frame_hdr_s.frame_ctl */
typedef struct ieee802_1x_frame_ctl_s {
	uint16_t version  : 2;
	uint16_t type     : 2;
	uint16_t subtype  : 4;
	uint16_t toDS     : 1;
	uint16_t fromDS   : 1;
	uint16_t morefrag : 1;
	uint16_t retry    : 1;
	uint16_t powman   : 1;
	uint16_t moredata : 1;
	uint16_t protfram : 1;
	uint16_t order    : 1;
} ieee802_1x_frame_ctl_t;

/* This is the structure for the EAPOL data within the packet. */
typedef struct ieee802_1x_eapol_s {
	uint8_t ver; // 1, 2 ?
	uint8_t type; // key == 3
	uint16_t length;  // in BE format
	uint8_t key_descr; // should be 2 for EAPOL RSN KEY ?
	union {
		struct {
			uint16_t KeyDescr	: 3; //
			uint16_t KeyType	: 1; // 1 is pairwise key
			uint16_t KeyIdx	: 2; // should be 0
			uint16_t Install	: 1; // should be 0
			uint16_t KeyACK	: 1; // 1=set 0=nope
			uint16_t KeyMIC	: 1; // 1 set, 0 nope
			uint16_t Secure	: 1;
			uint16_t Error	: 1;
			uint16_t Reqst	: 1;
			uint16_t EncKeyDat: 1;
		} key_info;
		uint16_t key_info_u16;	// union used for swapping
	};
	uint16_t key_len;
	uint64_t replay_cnt;
	uint8_t wpa_nonce[32];
	uint8_t wpa_keyiv[16];
	uint8_t wpa_keyrsc[8];
	uint8_t wpa_keyid[8];
	uint8_t wpa_keymic[16];
	uint16_t wpa_keydatlen;
} ieee802_1x_eapol_t;

typedef struct keydata_s {
	uint8_t tagtype;
	uint8_t taglen;
	uint8_t oui[3];
	uint8_t oui_type;
	uint8_t data[1];
} keydata_t;

typedef struct eapol_keydata_s {
	ieee802_1x_eapol_t auth;
	keydata_t tag[1];
} eapol_keydata_t;

typedef struct ieee802_1x_auth_s {
	uint16_t algo;
	uint16_t seq;
	uint16_t status;
} ieee802_1x_auth_t;

typedef struct ieee802_1x_beacon_tag_s {
	uint8_t  tagtype;
	uint8_t  taglen;
	uint8_t  tag[1];
/* we have to 'walk' from 1 tag to next, since the tag itself is var length. */
} ieee802_1x_beacon_tag_t;

/*
 * This is the structure for a 802.11 control 'beacon' packet.
 * A probe response packet looks the same.
 * We only use this packet to get the ESSID.
 */
typedef struct ieee802_1x_beacon_data_s {
	uint32_t time1;
	uint32_t time2;
	uint16_t interval;
	uint16_t caps;
	ieee802_1x_beacon_tag_t tags[1];
} ieee802_1x_beacon_data_t;

typedef struct ieee802_1x_assocreq_s {
	uint16_t capa;
	uint16_t interval;
	ieee802_1x_beacon_tag_t tags[1];
} ieee802_1x_assocreq_t;

typedef struct ieee802_1x_reassocreq_s {
	uint16_t capa;
	uint16_t interval;
	uint8_t  addr3[6];
	ieee802_1x_beacon_tag_t tags[1];
} ieee802_1x_reassocreq_t;

typedef struct eapext_s {
	uint8_t  version;
	uint8_t  type;
	uint16_t len;
	uint8_t  eapcode;
	uint8_t  eapid;
	uint16_t eaplen;
	uint8_t  eaptype;
} eapext_t;
#define EAP_CODE_RESP       2
#define EAP_TYPE_ID         1

inline static uint16_t swap16u(uint16_t v) {
	return ((v>>8)|((v&0xFF)<<8));
}
inline static uint32_t swap32u(uint32_t v) {
	return JOHNSWAP(v);
}
inline static uint64_t swap64u(uint64_t v) {
	return JOHNSWAP64(v);
}

typedef struct essid_s {
	int prio; /* On name conflict, prio <= old_prio will overwrite */
	int essid_len;
	char essid[32 + 1];
	uint8_t bssid[6];
} essid_t;

/*
 * This type structure is used to keep track of EAPOL packets, as they are read
 * from a PCAP file.  we need to get certain 'paired' packets, to be able to
 * create the input file for JtR (i.e. the 4-way to make the hash input for
 * JtR). The packets that are needed are:  M1/M2 or M2/M3.  These MUST be
 * paired, and matched to each other.  The match 'rules' are:
 *
 * - The packets MUST be sequential (sequential EAPOL's, per AP/STA pair)
 * - If a M1/M2 pair, they BOTH must have the exact same replay_cnt
 * - If the match is a M2/M3, then the M2 replay_cnt must be exactly one less
 *   than the replay_cnt in the M3.
 *
 * If any of the above 3 rules (actually only 2 of the 3, since the M1/M2 and
 * M2/M3 rules are only used in proper context), then we do NOT have a valid
 * 4-way.
 *
 * During run, every time we see a M1 for a given AP/STA pair, we 'forget' all
 * other packets for it.  When we see a M2, we forget all M3 and M4's.  Also,
 * for a M2, we see if we have a M1.  If so, we see if that M1 satisfies the
 * replay_cnt rule.  If that is the case, then we have a 'possible' valid
 * 4-way.  We do write the results.  However, at this time, we are not 100%
 * 'sure' we have a valid 4-way.  We CAN get a M1/M2 pair, even if the STA
 * trying to validate used the wrong password.  If all we see is the M1/M2,
 * then we do not KNOW for sure, if that STA was able to validate itself.  If
 * there was a M1 but it did not match, we simply drop it.
 *
 * Finally, when we get a M3, we dump the M1 and M4's.  We check for a M2 that
 * is valid.  If the M2 is valid, then we are SURE that we have a valid 4-way.
 * The M3 would not be sent, unless the router was happy that the connecting
 * AP knows the PW.
 */
typedef struct handshake_s {
	uint64_t ts64;
	int eapol_size;
	ieee802_1x_eapol_t *eapol;
} handshake_t;

typedef struct WPA4way_s {
	uint64_t rc;
	uint32_t anonce_msb;
	uint32_t anonce_lsb;
	int8_t fuzz;
	uint8_t endian; /* 0 == unknown, 1 == BE, 2 == LE */
	int handshake_done;
	int pmkid_done;
	handshake_t M[5];
	uint8_t bssid[6];
	uint8_t staid[6];
} WPA4way_t;

/* Support for loading airodump-ng ivs2 files. */
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC              "\xAE\x78\xD1\xFF"
#define IVS2_EXTENSION          "ivs"
#define IVS2_VERSION             1

/* BSSID const. length of 6 bytes; can be together with all the other types */
#define IVS2_BSSID      0x0001

/* ESSID var. length; alone, or with BSSID */
#define IVS2_ESSID      0x0002

/* WPA structure, const. length; alone, or with BSSID */
#define IVS2_WPA        0x0004

/* IV+IDX+KEYSTREAM, var. length; alone or with BSSID */
#define IVS2_XOR        0x0008

/*
 * [IV+IDX][i][l][XOR_1]..[XOR_i][weight]
 * holds i possible keystreams for the same IV with a length of l for each
 * keystream (l max 32) and an array "int weight[16]" at the end
 */
#define IVS2_PTW        0x0010

// unencrypted packet
#define IVS2_CLR        0x0020

struct ivs2_filehdr
{
    uint16_t version;
};

struct ivs2_pkthdr
{
    uint16_t  flags;
    uint16_t  len;
};

/*
 * WPA handshake in ivs2 format. From airodump-ng src/include/eapol.h
 */
#pragma pack() /* NOTE, THIS IS NOT PACKED! */
struct ivs2_WPA_hdsk
{
    uint8_t stmac[6];     /* supplicant MAC           */
    uint8_t snonce[32];   /* supplicant nonce         */
    uint8_t anonce[32];   /* authenticator nonce      */
    uint8_t keymic[16];   /* eapol frame MIC          */
    uint8_t eapol[256];   /* eapol frame contents     */
    uint32_t eapol_size;  /* eapol frame size         */
    uint8_t keyver;       /* key version (TKIP / AES) */
    uint8_t state;        /* handshake completion     */
};

static void dump_hex(char *msg, void *x, unsigned int size)
{
	unsigned int i;

	fprintf(stderr, "%s : ", msg);

	for (i = 0; i < size; i++) {
		fprintf(stderr, "%.2x", ((uint8_t*)x)[i]);
		if ((i % 4) == 3)
			fprintf(stderr, " ");
	}
	fprintf(stderr, "\n");
}

#define safe_realloc(p, len) do {	  \
		if (!(p = realloc(p, len))) { \
			fprintf(stderr, "%s:%d: realloc of "Zu" bytes failed\n", \
			        __FILE__, __LINE__, (size_t)len); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)

#define safe_malloc(p, len) do {	  \
		if (!(p = malloc(len))) { \
			fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n", \
			        __FILE__, __LINE__, (size_t)len); \
			exit(EXIT_FAILURE); \
		} \
	} while (0)
