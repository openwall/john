//
// structs and data (from wireshark, and ethernet structures)
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

#include "arch.h"
#include "johnswap.h"
#include "hccap.h"

// All data structures MUST be byte aligned, since we work on 'raw' data in
// structures and do not load structures record by record.
#pragma pack(1)

#define TCPDUMP_MAGIC           0xA1B2C3D4
#define TCPDUMP_CIGAM           0xD4C3B2A1

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
typedef struct ieee802_1x_frame_hdr_s {
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
} ieee802_1x_frame_hdr_t;

typedef struct ieee802_1x_frame_ctl_s { // bitmap of the ieee802_1x_frame_hdr_s.frame_ctl
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
} ieee802_1x_frame_ctl_t;

// THIS is the structure for the EAPOL data within the packet.
typedef struct ieee802_1x_eapol_s {
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
		} key_info;
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
} ieee802_1x_eapol_t;

typedef struct ieee802_1x_auth_s {
	uint16 algo;
	uint16 seq;
	uint16 status;
} ieee802_1x_auth_t;
#pragma pack()

typedef struct ieee802_1x_beacon_tag_s {
	uint8  tagtype;
	uint8  taglen;
	uint8  tag[1];
	// we have to 'walk' from 1 tag to next, since the tag itself is
	// var length.
} ieee802_1x_beacon_tag_t;

// This is the structure for a 802.11 control 'beacon' packet.
// A probe response packet looks the same.
// NOTE, we only use this packet to get the ESSID.
typedef struct ieee802_1x_beacon_data_s {
	uint32 time1;
	uint32 time2;
	uint16 interval;
	uint16 caps;
	// ok, now here we have a array of 'tagged params'.
	// these are variable sized, so we have to 'specially' walk them.
	ieee802_1x_beacon_tag_t tags[1];
} ieee802_1x_beacon_data_t;
#pragma pack()

typedef struct ieee802_1x_assocreq_s {
	uint16 capa;
	uint16 interval;
	ieee802_1x_beacon_tag_t tags[1];
} ieee802_1x_assocreq_t;
#pragma pack()

typedef struct ieee802_1x_reassocreq_s {
	uint16 capa;
	uint16 interval;
	uint8  addr3[6];
	ieee802_1x_beacon_tag_t tags[1];
} ieee802_1x_reassocreq_t;
#pragma pack()

inline static uint16 swap16u(uint16 v) {
	return ((v>>8)|((v&0xFF)<<8));
}
inline static uint32 swap32u(uint32 v) {
	return JOHNSWAP(v);
}
inline static uint64 swap64u(uint64 v) {
	return JOHNSWAP64(v);
}

/* This type structure is used to keep track of EAPOL packets, as they are read
 * from a PCAP file.  we need to get certain 'paired' packets, to be able to
 * create the input file for JtR (i.e. the 4-way to make the hash input for
 * JtR). The packets that are needed are:  M1/M2 or M2/M3.  These MUST be
 * paired, and matched to each other.  The match 'rules' are:
 *
 * - The packets MUST be sequential (sequential EAPOL's, per AP)
 * - If a M1/M2 pair, they BOTH must have the exact same replay_cnt
 * - If the match is a M2/M3, then the M2 replay_cnt must be exactly one less
 *   than the replay_cnt in the M3.
 *
 * If any of the above 3 rules (actually only 2 of the 3, since the M1/M2 and
 * M2/M3 rules are only used in proper context), then we do NOT have a valid
 * 4-way.
 *
 * During run, every time we see a M1 for a given AP, we 'forget' all other
 * packets for it.  When we see a M2, we forget all M3 and M4's.  Also, for a
 * M2, we see if we have a M1.  If so, we see if that M1 satisfies the
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
	uint8 *packet;
	int packet_len;
	int isQoS;
	uint32 ts_sec;
	uint32 ts_usec;
} handshake_t;

typedef struct WPA4way_s {
	char essid[36];
	char bssid[18];
	char sta[18];
	handshake_t M[5];
	int fully_cracked;
	int hopefully_cracked; // we have a 1 & 2
	int eapol_sz;
	int prio; // lower prio will overwrite higher
} WPA4way_t;

// Support for loading airodump-ng ivs2 files.
#define IVSONLY_MAGIC           "\xBF\xCA\x84\xD4"
#define IVS2_MAGIC              "\xAE\x78\xD1\xFF"
#define IVS2_EXTENSION          "ivs"
#define IVS2_VERSION             1

// BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID      0x0001

// ESSID var. length; alone, or with BSSID
#define IVS2_ESSID      0x0002

// wpa structure, const. length; alone, or with BSSID
#define IVS2_WPA        0x0004

// IV+IDX+KEYSTREAM, var. length; alone or with BSSID
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
    uint16 version;
};

struct ivs2_pkthdr
{
    uint16  flags;
    uint16  len;
};

// WPA handshake in ivs2 format
struct ivs2_WPA_hdsk
{
    uint8 stmac[6];     /* supplicant MAC           */
    uint8 snonce[32];   /* supplicant nonce         */
    uint8 anonce[32];   /* authenticator nonce      */
    uint8 keymic[16];   /* eapol frame MIC          */
    uint8 eapol[256];   /* eapol frame contents     */
    uint32 eapol_size;  /* eapol frame size         */
    uint8 keyver;       /* key version (TKIP / AES) */
    uint8 state;        /* handshake completion     */
};

static void dump_hex(char *msg, void *x, unsigned int size)
{
	unsigned int i;

	fprintf(stderr, "%s : ", msg);

	for (i = 0; i < size; i++) {
		fprintf(stderr, "%.2x", ((uint8*)x)[i]);
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
