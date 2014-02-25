// structs and data (from wireshark, and ethernet structures)
//
//

#ifdef _MSC_VER
#define inline _inline
#endif

typedef unsigned long long uint64;
typedef   signed long long int64;
typedef unsigned int       uint32;
typedef   signed int       int32;
typedef unsigned short     uint16;
typedef   signed short     int16;
typedef unsigned char      uint8;
typedef   signed char      int8;

#include "johnswap.h"

// All data structures MUST be byte aligned, since we work on 'raw' data in structures
// and do not load structures record by record.
#pragma pack(1)

// Borrowed from cap2hccap's pcap.h
#define TCPDUMP_MAGIC           0xA1B2C3D4
#define TCPDUMP_CIGAM           0xD4C3B2A1
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC              "\xAE\x78\xD1\xFF"

#define LINKTYPE_ETHERNET       1
#define LINKTYPE_IEEE802_11     105
#define LINKTYPE_PRISM_HEADER   119
#define LINKTYPE_RADIOTAP_HDR   127
#define LINKTYPE_PPI_HDR        192

// PCAP main file header
typedef struct pcap_hdr_s {
	uint32 magic_number;   /* magic number 0xA1B2C3D4 (or 0xD4C3B2A1 if file in BE format) */
	uint16 version_major;  /* major version number 0x0200 */
	uint16 version_minor;  /* minor version number 0x0400 */
	int32  thiszone;       /* GMT to local correction */
	uint32 sigfigs;        /* accuracy of timestamps */
	uint32 snaplen;        /* max length of captured packets, in octets */
	uint32 network;        /* data link type */
} pcap_hdr_t;
// PCAP packet header
typedef struct pcaprec_hdr_s {
	uint32 ts_sec;         /* timestamp seconds */
	uint32 ts_usec;        /* timestamp microseconds */
	uint32 incl_len;       /* number of octets of packet saved in file */
	uint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

// Ok, here are the struct we need to decode 802.11 for JtR
typedef struct ether_frame_hdr_s {
	uint16 frame_ctl;
	uint16 duration;
	uint8  addr1[6];
	uint8  addr2[6];
	uint8  addr3[6];
	uint16 seq;
//	int8   addr[6]; // optional (if X then it is set)
//	uint16 qos_ctl; // optional (if X then it is set)
//	uint16 ht_ctl;  // optional (if X then it is set)
//	int8   body[1];
} ether_frame_hdr_t;

typedef struct ether_frame_ctl_s { // bitmap of the ether_frame_hdr_s.frame_ctl
	uint16 version  : 2;
	uint16 type     : 2;
	uint16 subtype  : 4;
	uint16 toDS     : 1;
	uint16 fromDS   : 1;
	uint16 morefrag : 1;
	uint16 retry    : 1;
	uint16 powman   : 1;
	uint16 moredata : 1;
	uint16 protfram : 1;
	uint16 order    : 1;
} ether_frame_ctl_t;

// THIS is the structure for the EAPOL data within the packet.
typedef struct ether_auto_802_1x_s {
	uint8 ver; // 1 ?
	uint8 key;
	uint16 length;  // in BE format
	uint8 key_descr; // should be 2 for EAPOL RSN KEY ?
	union {
		struct {
			uint16 KeyDescr	: 3; //
			uint16 KeyType	: 1; // 1 is pairwise key
			uint16 KeyIdx	: 2; // should be 0
			uint16 Install	: 1; // should be 0
			uint16 KeyACK	: 1; // 1=set 0=nope
			uint16 KeyMIC	: 1; // 1 set, 0 nope
			uint16 Secure	: 1;
			uint16 Error	: 1;
			uint16 Reqst	: 1;
			uint16 EncKeyDat: 1;
		}key_info;
		uint16 key_info_u16;	// union used for swapping, to work around worthless gcc warning.
	};
	uint16 key_len;
	uint64 replay_cnt;
	uint8 wpa_nonce[32];
	uint8 wpa_keyiv[16];
	uint8 wpa_keyrsc[8];
	uint8 wpa_keyid[8];
	uint8 wpa_keymic[16];
	uint16 wpa_keydatlen;
} ether_auto_802_1x_t;

typedef struct ether_beacon_tag_s {
	uint8  tagtype;
	uint8  taglen;
	uint8  tag[1];
	// we have to 'walk' from 1 tag to next, since the tag itself is
	// var length.
} ether_beacon_tag_t;

// This is the structure for a 802.11 control 'beacon' packet.
// NOTE, we only use this packet to get the SSID.
typedef struct ether_beacon_data_s {
	uint32 time1;
	uint32 time2;
	uint16 interval;
	uint16 caps;
	// ok, now here we have a array of 'tagged params'.
	// these are variable sized, so we have to 'specially' walk them.
	ether_beacon_tag_t tags[1];
} ether_beacon_data_t;
#pragma pack()

static inline uint16 swap16u(uint16 v) {
	return ((v>>8)|((v&0xFF)<<8));
}
static inline uint32 swap32u(uint32 v) {
	return JOHNSWAP(v);
}
static inline uint64 swap64u(uint64 v) {
	return JOHNSWAP64(v);
}

// This type structure is used to keep track of EAPOL packets, as they are read
// from a PCAP file.  we need to get certain 'paired' packets, to be able to create
// the input file for JtR (i.e. the 4-way to make the hash input for JtR). The packets
// that are needed are:   msg1 and msg2  or msg2 and msg3.  These MUST be paired, and
// matched to each other.  The match 'rules' are:
// the packets MUST be sequential (only eapol messages being looked at, so sequential epol's)
// if the match is a msg1-msg2, then both MUST have exact same If a msg1-msg2 pair,
//   they BOTH must have the exact same ether_auto_802_1x_t.replay_cnt
// if the match is a msg2-msg3, then the msg2 ether_auto_802_1x_t.replay_cnt must be exactly
//   one less than the ether_auto_802_1x_t.replay_cnt in the msg3.
// if any of the above 3 rules (actually only 2 of the 3, since the msg1-msg2 and msg2-msg3
//   rules are only used in proper context), then we do NOT have a valid 4-way.
// During run, every time we see a msg1, we 'forget' all other packets.  When we see a msg2,
//   we forget all msg3 and msg4's.  Also, for a msg2, we see if we have a msg1.  If so, we
//   see if that msg1 satisfies the replay_cnt rule.  If that is the case, then we have a
//   'possible' valid 4-way. We do write the results.  However, at this time, we are not
//   100% 'sure' we have a valid 4-way.  We CAN get a msg1/msg2 pair, even if the AP trying
//   to validate, did not know the password.  If all we see is the msg1/msg2, then we do not
//   KNOW for sure, if that AP was able to validate itself.   If there was a msg1 but it did
//   not match, we simply drop it.  Finally, when we get a msg3, we dump the msg1 and msg4's.
//   We check for a msg2 that is valid.  If the msg2 is valid, then we are SURE that we have
//   a valid 4-way.  The msg3 would not be sent, unless the router was happy that the
//   the connecting AP knows the PW, unless the router was written to always 'fake' reply,
//   but that is likely against 802.11 rules.  The only thing I could think might do this,
//   is some honey-pot router, looking for hackers. A real router is not going to give a
//   msg3 unless the 4-way is going along fine.
typedef struct WPA4way_s {
	char ssid[36];
	char essid[18];
	char bssid[18];
	uint8 *packet1;
	uint8 *packet2;
	uint8 *orig_2;
	uint8 *packet3;
	uint8 *packet4;
	int fully_cracked;
	int hopefully_cracked; // we have a 1 & 2
	int eapol_sz;
}WPA4way_t;

// Here are the structures needed to store the data that make up the 4-way handshake.
// we harvest this data to make JtR input strings.

// this struct IS the struct in JtR. So we load it up, the do a base-64 convert to save.
typedef struct
{
	char          essid[36];  // Note, we do not 'write' this one, it is the salt.
	unsigned char mac1[6];    // the base-64 data we write, starts from this element forward.
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];
	unsigned char eapol[256];
	int           eapol_size;
	int           keyver;
	unsigned char keymic[16];
} hccap_t;
