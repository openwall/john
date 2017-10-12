/*
 * This software is Copyright (c) 2013 Jim Fougeron jfoug AT cox dot net,
 * Copyright (c) 2013 Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2014 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

//#define WPADEBUG 1
#define IGNORE_MSG1 0
#define IGNORE_MSG2 0
#define IGNORE_MSG3 0

#include "wpapcap2john.h"
#include "jumbo.h"
#include "memdbg.h"

static size_t max_essids = 1024; /* Will grow automagically */

static int GetNextPacket(FILE *in);
static int ProcessPacket();
static void HandleBeacon(uint16 subtype, int has_ht);
static void Handle4Way(int is_qos);
static void DumpAuth(int idx, int ap_msg, int sta_msg);

static uint32 start_t, start_u, cur_t, cur_u;
static uint32 pkt_num;
static pcaprec_hdr_t pkt_hdr;
static uint8 *full_packet;
static uint8 *packet;
static uint8 *new_p;
static int bROT;
static WPA4way_t *wpa;    /* alloced/realloced to max_essids*/
static int nwpa = 0;
static int rctime = 10*60;
static const char cpItoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const char *filename;
static unsigned int link_type, ShowIncomplete = 1, IgnoreRepCnt;
static int warn_wpaclean;
static int warn_snaplen;
static int verbosity = 1;

// These 2 functions output data properly for JtR, in base-64 format. These
// were taken from hccap2john.c source, and modified for this project.
static int code_block(unsigned char *in, unsigned char b, char *cp)
{
	int cnt = 0;
	*cp++ = cpItoa64[in[0] >> 2];
	*cp++ = cpItoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	if (b) {
		*cp++ = cpItoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*cp++ = cpItoa64[in[2] & 0x3f];
		++cnt;
	} else
		*cp++ = cpItoa64[((in[1] & 0x0f) << 2)];
	*cp = 0;
	return cnt+3;
}

static void to_bssid(char bssid[18], uint8 *p)
{
	sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
	        p[0],p[1],p[2],p[3],p[4],p[5]);
}

static void to_dashed(char bssid[18], uint8 *p)
{
	sprintf(bssid, "%02x-%02x-%02x-%02x-%02x-%02x",
	        p[0],p[1],p[2],p[3],p[4],p[5]);
}

static void to_compact(char bssid[13], uint8 *p)
{
	sprintf(bssid, "%02x%02x%02x%02x%02x%02x",
	        p[0],p[1],p[2],p[3],p[4],p[5]);
}

// Convert WPA handshakes from aircrack-ng (airodump-ng) IVS2 to JtR format
static int convert_ivs(FILE *f_in)
{
	struct ivs2_filehdr fivs2;
	struct ivs2_pkthdr ivs2;
	struct ivs2_WPA_hdsk *wivs2;
	hccap_t hccap;
	unsigned int i;
	unsigned char buffer[66000];
	size_t length, pos;
	unsigned int pktlen;
	unsigned char bssid[6];
	int bssidFound = 0;
	char essid[32 + 1];
	int essidFound = 0;
	unsigned char *p, *w;

	fseek(f_in, 0, SEEK_END);
	length = ftell(f_in);
	fseek(f_in, 0, SEEK_SET);

	if (fread(buffer, 1, 4, f_in) != 4) {
		fprintf(stderr, "%s: fread file header failed\n", filename);
		return(1);
	}

	if (memcmp(buffer, IVSONLY_MAGIC, 4) == 0) {
		fprintf(stderr, "%s: old version .ivs file, no WPA2 handshakes\n", filename);
		return(1);
	}

	if (memcmp(buffer, IVS2_MAGIC, 4) != 0) {
		fprintf(stderr, "%s: not an .%s file\n", filename, IVS2_EXTENSION);
		return(1);
	}

	if (fread(&fivs2, 1, sizeof(struct ivs2_filehdr), f_in) != (size_t) sizeof(struct ivs2_filehdr)) {
		fprintf(stderr, "%s: fread file header failed", filename);
		return(1);
	}

	if (fivs2.version > IVS2_VERSION) {
		fprintf(stderr, "%s: wrong %s version: %d. Supported up to version %d.\n", filename, IVS2_EXTENSION, fivs2.version, IVS2_VERSION);
		return(1);
	}

	pos = ftell(f_in);

	while (pos < length) {
		if (fread(&ivs2, 1, sizeof(struct ivs2_pkthdr), f_in) != sizeof(struct ivs2_pkthdr)) {
			fprintf(stderr, "%s: Error reading header at pos "Zu" of "Zu"\n", filename, pos, length);
			return 1;
		}

		pos +=  sizeof(struct ivs2_pkthdr);

		pktlen = (unsigned int)ivs2.len;
		if (pktlen+pos > length) {
			fprintf(stderr, "%s: Invalid packet length %u at "Zu"\n", filename, pktlen, pos-sizeof(struct ivs2_pkthdr));
			return 1;
		}

		if (fread(&buffer, 1, pktlen, f_in) != pktlen) {
			fprintf(stderr, "%s: Error reading data (%u) at pos "Zu" of "Zu"\n", filename, pktlen, pos, length);
			return 1;
		}

		// Show "packet" headers
		// printf("%ld : %d - %02x\n", pos, pktlen, (unsigned int)ivs2.flags);

		p = buffer;
		if (ivs2.flags & IVS2_BSSID) {
			memcpy(bssid, p, 6);
			p += 6;

			fprintf(stderr, "%s: BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n", filename, p[0], p[1], p[2], p[3], p[4], p[5]);
			bssidFound = 1;
		}
		if (ivs2.flags & IVS2_ESSID) {
			unsigned int ofs = (p - buffer);
			unsigned int len = pktlen - ofs;

			if (len <= 0 || len > 32) {
				printf("Invalid ESSID length (%d)\n", len);
				return 1;
			}

			memcpy(essid, p, len);
			essid[len] = 0;

			essidFound = 1;

			fprintf(stderr,"ESSID: '%s' (%d bytes)\n", essid, len);
			p += len;
		}

		if (ivs2.flags & IVS2_WPA) {
			char buf[8];
			int ofs = (p - buffer);
			int len = pktlen - ofs;
			char sta_mac[18], ap_mac[18], gecos[13];

			if (len != sizeof(struct ivs2_WPA_hdsk)) {
				fprintf(stderr, "%s: Invalid WPA handshake length (%d vs %d)\n", filename, len, (int)sizeof(struct ivs2_WPA_hdsk));
				return 1;
			}

			if (!bssidFound) {
				fprintf(stderr, "%s: Got WPA handshake but we don't have BSSID\n", filename);
				return 1;
			}

			if (!essidFound) {
				fprintf(stderr, "%s: Got WPA handshake but we don't have SSID\n", filename);
				return 1;
			}

			wivs2 = (struct ivs2_WPA_hdsk*)p;

			fprintf(stderr, "WPA handshake keyver=%d eapolSize=%d\n\n", wivs2->keyver, wivs2->eapol_size);

			printf("%s:$WPAPSK$%s#", essid, essid);

			memset(&hccap, 0, sizeof(hccap_t));
			hccap.keyver = wivs2->keyver;

			memcpy(hccap.mac1, bssid, 6);
			memcpy(hccap.mac2, wivs2->stmac, 6);

			memcpy(hccap.nonce1, wivs2->snonce,32);
			memcpy(hccap.nonce2, wivs2->anonce,32);
			memcpy(hccap.keymic, wivs2->keymic, 16);
			hccap.eapol_size = wivs2->eapol_size;

			if (hccap.eapol_size > sizeof(((hccap_t*)(NULL))->eapol)) {
				fprintf(stderr,
				        "%s: eapol size %u (too large), skipping packet\n",
				        filename, hccap.eapol_size);
				return 1;
			}
			memcpy(hccap.eapol, wivs2->eapol, wivs2->eapol_size);

			// print struct in base64 format
			w = (unsigned char*)&hccap;
			for (i=36; i+3 < sizeof(hccap_t); i += 3) {
				code_block(&w[i], 1, buf);
				printf("%s", buf);
			}
			code_block(&w[i], 0, buf);
			printf("%s", buf);
			to_compact(gecos, hccap.mac1);
			to_dashed(ap_mac, hccap.mac1);
			to_dashed(sta_mac, hccap.mac2);
			printf(":%s:%s:%s::WPA", sta_mac, ap_mac, gecos);
			if (hccap.keyver > 1)
				printf("%d", hccap.keyver);
			printf("::%s\n", filename);
			fflush(stdout);

			p += len;
		}

		if (p < buffer+pktlen) {
			fprintf(stderr, "%s: Unable to parse all data, unsupported flag? (%02x)\n", filename, (int)ivs2.flags);
		}

		pos += pktlen;
	}

	return 0;
}

static void dump_any_unver() {
	int printed = 0;
	int i;

	for (i = 0; i < nwpa; i++) {
		int first = 0, second = 0;

		if (!wpa[i].M[0].packet)
			continue;

		if (wpa[i].M[1].packet)
			first = 1;
		if (wpa[i].M[2].packet)
			second = 2;
		if (wpa[i].M[3].packet)
			first = 3;
		if (wpa[i].M[4].packet)
			second = 4;

		if (first && second) {
			if (!printed++)
				fprintf(stderr, "Dumping unverified auths\n");
			DumpAuth(i, first, second);
			MEM_FREE(wpa[i].M[1].packet);
			MEM_FREE(wpa[i].M[2].packet);
			MEM_FREE(wpa[i].M[3].packet);
			MEM_FREE(wpa[i].M[4].packet);
		}
	}
}

static int Process(FILE *in)
{
	pcap_hdr_t main_hdr;

	if (fread(&main_hdr, 1, sizeof(pcap_hdr_t), in) != sizeof(pcap_hdr_t)) {
		fprintf(stderr,
			"%s: Error, could not read enough bytes to get a common 'main' pcap header\n",
			filename);
		return 0;
	}
	if (main_hdr.magic_number == 0xa1b2c3d4)
		bROT = 0;
	else if (main_hdr.magic_number == 0xd4c3b2a1)
		bROT = 1;
	else {
		if (convert_ivs(in)) {
			fprintf(stderr, "%s: not a pcap file\n", filename);
			return 0;
		}
		return 1;
	}

	if (bROT) {
		main_hdr.magic_number = swap32u(main_hdr.magic_number);
		main_hdr.version_major = swap16u(main_hdr.version_major);
		main_hdr.version_minor = swap16u(main_hdr.version_minor);
		main_hdr.sigfigs = swap32u(main_hdr.sigfigs);
		main_hdr.snaplen = swap32u(main_hdr.snaplen);
		main_hdr.network = swap32u(main_hdr.network);
	}
	link_type = main_hdr.network;
	if (link_type == LINKTYPE_IEEE802_11)
		fprintf(stderr, "\nFile %s: raw 802.11\n", filename);
	else if (link_type == LINKTYPE_PRISM_HEADER)
		fprintf(stderr, "\nFile %s: Prism headers stripped\n", filename);
	else if (link_type == LINKTYPE_RADIOTAP_HDR)
		fprintf(stderr, "\nFile %s: Radiotap headers stripped\n", filename);
	else if (link_type == LINKTYPE_PPI_HDR)
		fprintf(stderr, "\nFile %s: PPI headers stripped\n", filename);
	else if (link_type == LINKTYPE_ETHERNET)
		fprintf(stderr, "\nFile %s: Ethernet headers, non-monitor mode. Use of -e option likely required.\n", filename);
	else {
		fprintf(stderr, "\nFile %s: No 802.11 wireless traffic data (network %d)\n", filename, link_type);
		return 0;
	}

	while (GetNextPacket(in)) {
		if (!ProcessPacket()) {
			break;
		}
	}
	fprintf(stderr, "File %s: End of data\n", filename);
	if (ShowIncomplete)
		dump_any_unver();
	return 1;
}

static int GetNextPacket(FILE *in)
{
	size_t read_size;

	if (fread(&pkt_hdr, 1, sizeof(pkt_hdr), in) != sizeof(pkt_hdr)) return 0;

	if (bROT) {
		pkt_hdr.ts_sec = swap32u(pkt_hdr.ts_sec);
		pkt_hdr.ts_usec = swap32u(pkt_hdr.ts_usec);
		pkt_hdr.incl_len = swap32u(pkt_hdr.incl_len);
		pkt_hdr.orig_len = swap32u(pkt_hdr.orig_len);
	}

	if (pkt_hdr.ts_sec == 0 && pkt_hdr.ts_usec == 0 && !warn_wpaclean++)
		fprintf(stderr,
        "**\n** Warning: %s seems to be processed with some dubious tool like 'wpaclean'. Important information may be lost.\n**\n", filename);

	if (pkt_hdr.orig_len > pkt_hdr.incl_len && !warn_snaplen++)
		fprintf(stderr, "**\n** Warning: %s seems to be recorded with insufficient snaplen, packet was %u bytes but only %u bytes were recorded\n**\n", filename, pkt_hdr.orig_len, pkt_hdr.incl_len);

	if (!start_t) {
		start_t = pkt_hdr.ts_sec;
		start_u = pkt_hdr.ts_usec;
	}
	cur_t = pkt_hdr.ts_sec - start_t;
	cur_u = pkt_hdr.ts_usec - start_u;

	while (cur_u > 999999) {
		cur_t--;
		cur_u += 1000000;
	}

	MEM_FREE(full_packet);
	safe_malloc(full_packet, pkt_hdr.incl_len);
	read_size = fread(full_packet, 1, pkt_hdr.incl_len, in);
	if (read_size < pkt_hdr.incl_len)
		fprintf(stderr, "%s: truncated last packet\n", filename);

	return (read_size == pkt_hdr.incl_len);
}

// Fake 802.11 header. We use this when indata is Ethernet (not monitor mode)
// in order to fake a packet we can process
static uint8 fake802_11[] = {
	0x88, 0x02, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00
};

// Type 0 subtypes
static const char* const ctl_subtype[16] = {
	"Association request",     // 0
	"Association response",    // 1
	"Reassociation request",   // 2
	"Reassociation response",  // 3
	"Probe request",           // 4
	"Probe response",          // 5
	"Subtype 6",               // 6
	"Subtype 7",               // 7
	"Beacon",                  // 8
	"ATIM",                    // 9
	"Disassociation",          // 10
	"Authentication",          // 11
	"Deauthentication",        // 12
	"Action",                  // 13
	"Action no ack",           // 14
	"Subtype 15"
};

// Ok, this function is the main packet processor.  NOTE, when we are done
// reading packets (i.e. we have done what we want), we return 0, and
// the program will exit gracefully.  It is not an error, it is just an
// indication we have completed (or that the data we want is not here).
static int ProcessPacket()
{
	ieee802_1x_frame_hdr_t *pkt;
	ieee802_1x_frame_ctl_t *ctl;
	unsigned int frame_skip = 0;
	int has_ht;

	packet = full_packet;

	// Skip Prism frame if present
	if (link_type == LINKTYPE_PRISM_HEADER) {
		if (pkt_hdr.incl_len < 8)
			return 0;
		if (packet[7] == 0x40)
			frame_skip = 64;
		else {
			frame_skip = *(unsigned int*)&packet[4];
#if !ARCH_LITTLE_ENDIAN
			frame_skip = JOHNSWAP(frame_skip);
#endif
		}
		if (frame_skip < 8 || frame_skip >= pkt_hdr.incl_len)
			return 0;
		packet += frame_skip;
		pkt_hdr.incl_len -= frame_skip;
		pkt_hdr.orig_len -= frame_skip;
	}

	// Skip Radiotap frame if present
	if (link_type == LINKTYPE_RADIOTAP_HDR) {
		if (pkt_hdr.incl_len < 4)
			return 0;
		frame_skip = *(unsigned short*)&packet[2];
#if !ARCH_LITTLE_ENDIAN
		frame_skip = JOHNSWAP(frame_skip);
#endif
		if (frame_skip == 0 || frame_skip >= pkt_hdr.incl_len)
			return 0;
		packet += frame_skip;
		pkt_hdr.incl_len -= frame_skip;
		pkt_hdr.orig_len -= frame_skip;
	}

	// Skip PPI frame if present
	if (link_type == LINKTYPE_PPI_HDR) {
		if (pkt_hdr.incl_len < 4)
			return 0;
		frame_skip = *(unsigned short*)&packet[2];
#if !ARCH_LITTLE_ENDIAN
		frame_skip = JOHNSWAP(frame_skip);
#endif
		if (frame_skip <= 0 || frame_skip >= pkt_hdr.incl_len)
			return 0;

		// Kismet logged broken PPI frames for a period
		if (frame_skip == 24 && *(unsigned short*)&packet[8] == 2)
			frame_skip = 32;

		if (frame_skip == 0 || frame_skip >= pkt_hdr.incl_len)
			return 0;
		packet += frame_skip;
		pkt_hdr.incl_len -= frame_skip;
		pkt_hdr.orig_len -= frame_skip;
	}

	// Handle Ethernet EAPOL data if present. This is typically a pcap
	// sniffed in non-monitor-mode.
	// We strip the ethernet header and add a fake 802.11 header instead.
	if (link_type == LINKTYPE_ETHERNET &&
	    packet[12] == 0x88 && packet[13] == 0x8e) {
		int new_len = pkt_hdr.incl_len - 12 + sizeof(fake802_11);
		ieee802_1x_eapol_t *auth;

#if WPADEBUG
		//dump_hex("Ethernet packet, will fake 802.11.\nOriginal", packet, pkt_hdr.incl_len);
#endif
		safe_realloc(new_p, new_len);
		// Start with some fake 802.11 header data
		memcpy(new_p, fake802_11, sizeof(fake802_11));
		// Put original src and dest in the fake 802.11 header
		memcpy(new_p + 4, packet, 12);
		// Add original EAPOL data
		memcpy(new_p + sizeof(fake802_11), packet + 12, pkt_hdr.incl_len - 12);

		auth = (ieee802_1x_eapol_t*)&packet[14];
		auth->key_info_u16 = swap16u(auth->key_info_u16);
		// Add the BSSID to the 802.11 header
		if (auth->key_info.KeyACK)
			memcpy(new_p + 16, packet, 6);
		else
			memcpy(new_p + 16, packet + 6, 6);

		pkt_hdr.incl_len += sizeof(fake802_11) - 12;
		pkt_hdr.orig_len += sizeof(fake802_11) - 12;
		packet = new_p;
	}

	// our data is in *packet with pkt_hdr being the pcap packet header for this packet.
	pkt = (ieee802_1x_frame_hdr_t*)packet;

	if (verbosity > 1) {
		char src[18], dst[18];

		if (verbosity > 2)
			dump_hex("802.11 packet", pkt, pkt_hdr.incl_len);

		to_bssid(dst, &packet[4]);
		if (pkt_hdr.incl_len >= 16)
			to_bssid(src, &packet[10]);
		else
			strcpy(src, "                 ");
		if (verbosity > 2)
			fprintf(stderr, "%4d %2d.%06u  %s -> %s %-4d ", ++pkt_num, pkt_hdr.ts_sec, pkt_hdr.ts_usec, src, dst, pkt_hdr.incl_len);
		else
			fprintf(stderr, "%4d %2d.%06u  %s -> %s %-4d ", ++pkt_num, cur_t, cur_u, src, dst, pkt_hdr.incl_len);
	}

	if (pkt_hdr.incl_len < 2) {
		if (verbosity > 1)
			fprintf(stderr, "Truncated data\n");
		return 0;
	}

	ctl = (ieee802_1x_frame_ctl_t *)&pkt->frame_ctl;

	has_ht = (ctl->order == 1); // 802.11n, 4 extra bytes MAC header

	if (has_ht && verbosity > 1)
		fprintf(stderr, "[802.11n] ");

	// Type 0 is management,
	// Beacon is subtype 8 and probe response is subtype 5
	// probe request is 4, assoc request is 0, reassoc is 2
	if (ctl->type == 0) {
		HandleBeacon(ctl->subtype, has_ht);
		return 1;
	}
	// if not beacon or probe response, then look only for EAPOL 'type'
	if (ctl->type == 2) { // type 2 is data
		uint8 *p = packet;
		int bQOS = (ctl->subtype & 8) != 0;

		if ((ctl->toDS ^ ctl->fromDS) != 1) {
			// eapol will ONLY be direct toDS or direct fromDS.
			if (verbosity > 1)
				fprintf(stderr, "Invalid EAPOL src/dst\n");
			return 1;
		}
		if (sizeof(ieee802_1x_frame_hdr_t)+6+2+(bQOS?2:0)+(has_ht?4:0) >= pkt_hdr.incl_len) {
			if (verbosity > 1)
				fprintf(stderr, "QoS Null or malformed EAPOL\n");
			return 1;
		}
		// Ok, find out if this is a EAPOL packet or not.

		p += sizeof(ieee802_1x_frame_hdr_t);
		if (bQOS)
			p += 2;
		// p now points to the start of the LLC (logical link control) structure.
		// this is 8 bytes long, and the last 2 bytes are the 'type' field.  What
		// we are looking for is 802.1X authentication packets. These are 0x888e
		// in value.  We are running from an LE point of view, so should look for 0x8e88
		p += 6;
		if (*((uint16*)p) == 0x8e88) {
			Handle4Way(bQOS);	// this packet was a eapol packet.
			return 1;
		}
	}

	if (verbosity > 1) {
		int ts = (ctl->type << 4) | ctl->subtype;

		if (ctl->type == 0)
			fprintf(stderr, "%s\n", ctl_subtype[ctl->subtype]);
		else if (ts == 0x15)
			fprintf(stderr, "VHT NDP Announcement\n");
		else if (ts == 0x18)
			fprintf(stderr, "Block Ack Req\n");
		else if (ts == 0x19)
			fprintf(stderr, "Block Ack\n");
		else if (ts == 0x1b)
			fprintf(stderr, "RTS\n");
		else if (ts == 0x1c)
			fprintf(stderr, "CTS\n");
		else if (ts == 0x1d)
			fprintf(stderr, "Ack\n");
		else if (ts >= 0x20 && ts <= 0x23)
			fprintf(stderr, "Data\n");
		else if (ts > 0x23 && ts < 0x30)
			fprintf(stderr, "QoS Data\n");
		else
			fprintf(stderr, "Type %d subtype %d\n", ctl->type, ctl->subtype);
	}

	return 1;
}

static void e_fail(void)
{
	fprintf(stderr, "Incorrect -e option.\n");
	exit(EXIT_FAILURE);
}

static void alloc_error()
{
	fprintf(stderr, "ERROR: Too many ESSIDs seen (%d), out of memory\n", nwpa);
	exit(EXIT_FAILURE);
}

// Dynamically allocate more memory for input data.
// Make sure newly allocated memory is initialized with zeros.
static void allocate_more_memory(void)
{
	size_t old_max = max_essids;

	max_essids *= 2;
	wpa = realloc(wpa, sizeof(WPA4way_t) * max_essids);
	if (!wpa)
		alloc_error();
	memset(wpa + old_max, 0, sizeof(WPA4way_t) * old_max);
}

static void ManualBeacon(char *essid_bssid)
{
	char *essid = essid_bssid;
	char *bssid = strchr(essid_bssid, ':');

	if (!bssid)
		e_fail();

	*bssid++ = 0;
	if (strlen(essid) > 32 || strlen(bssid) != 17)
		e_fail();

	bssid = strupr(bssid);
	fprintf(stderr, "Learned BSSID %s ESSID '%s' from command-line option\n",
	        bssid, essid);
	strcpy(wpa[nwpa].essid, essid);
	strcpy(wpa[nwpa].bssid, bssid);
	if (++nwpa >= max_essids)
		allocate_more_memory();
}

static void HandleBeacon(uint16 subtype, int has_ht)
{
	const uint8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	ieee802_1x_frame_hdr_t *pkt = (ieee802_1x_frame_hdr_t*)packet;
	ieee802_1x_beacon_tag_t *tag;
	uint8 *pFinal = &packet[pkt_hdr.incl_len];
	char essid[32 + 1];
	char bssid[18];
	int prio = 0;
	int i;

	if (subtype == 8 || subtype == 5) { // beacon or probe response
		ieee802_1x_beacon_data_t *pDat = (ieee802_1x_beacon_data_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		tag = pDat->tags;
		prio = (subtype == 8 ? 5 : 3);
	} else if (subtype == 4) { // probe request
		tag = (ieee802_1x_beacon_tag_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		prio = 4;
	} else if (subtype == 0) { // association request
		ieee802_1x_assocreq_t *pDat = (ieee802_1x_assocreq_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		tag = pDat->tags;
		prio = 2;
	} else if (subtype == 2) { // re-association request
		ieee802_1x_reassocreq_t *pDat = (ieee802_1x_reassocreq_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		tag = pDat->tags;
		prio = 1;
	} else if (subtype == 11) {
		ieee802_1x_auth_t *p = (ieee802_1x_auth_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		if (p->algo == 0)
			fprintf(stderr, "WPA authentication, status %04x\n", p->status);
		else if (p->algo == 1)
			fprintf(stderr, "WEP authentication, status %04x\n", p->status);
		else
			fprintf(stderr, "Authentication %04x, status %04x\n", p->algo, p->status);
		return;
	} else {
		if (verbosity > 1)
			fprintf(stderr, "%s\n", ctl_subtype[subtype]);
		return;
	}

	// addr1 should be broadcast for beacon, unicast for probe response
	// addr2 is source addr (should be same as BSSID)
	// addr3 is BSSID (routers MAC)

	// ok, walk the tags

	while (((uint8*)tag) < pFinal) {
		char *x = (char*)tag;
		if (x + 2 > (char*)pFinal || x + 2 + tag->taglen > (char*)pFinal)
			break;
		if (tag->tagtype == 0) {
			if (tag->taglen == 0 || tag->taglen > 32) {
				to_bssid(bssid, pkt->addr3);
				fprintf(stderr, "%s %s ESSID",
				        ctl_subtype[subtype],
				        tag->taglen ? "with invalid length" : "for any");
				if (memcmp(pkt->addr1, pkt->addr3, 6))
					fprintf(stderr, " (BSSID %s)\n", bssid);
				else
					fprintf(stderr, "\n");
				return;
			}
			memcpy(essid, tag->tag, tag->taglen);
			essid[tag->taglen] = 0;
			break;
		}
		x += tag->taglen + 2;
		tag = (ieee802_1x_beacon_tag_t *)x;
	}
	if (strlen(essid) == 0) {
		if (verbosity > 1)
			fprintf(stderr, "%s with ESSID length 0\n", ctl_subtype[subtype]);
		return;
	}
	if (pkt->addr3 + 6 > pFinal) {
		if (verbosity > 1)
			fprintf(stderr, "%s with malformed data\n", ctl_subtype[subtype]);
		return;
	}
	to_bssid(bssid, pkt->addr3);

	if (!memcmp(pkt->addr3, bcast, 6)) {
		fprintf(stderr, "Broadcast %s '%s'\n",
		        ctl_subtype[subtype], essid);
		return;
	}

	// Check if already in db, or older entry has worse prio
	for (i = nwpa - 1; i >= 0; --i) {
		if (!strcmp(bssid, wpa[i].bssid) && !strcmp(essid, wpa[i].essid)) {
			if (wpa[i].prio > prio) {
				fprintf(stderr, "%s '%s' at %s (prio %d -> %d)\n",
				        ctl_subtype[subtype], wpa[i].essid, wpa[i].bssid,
				        wpa[i].prio, prio);
				wpa[i].prio = prio;
			} else {
				fprintf(stderr, "%s '%s' at %s\n", ctl_subtype[subtype],
				        wpa[i].essid, wpa[i].bssid);
			}
			return;
		} else if (!strcmp(bssid, wpa[i].bssid)) {
			if (wpa[i].prio >= prio) {
				fprintf(stderr, "%s '%s' at %s (renamed, old '%s' prio %d, new prio %d)\n", ctl_subtype[subtype], essid, wpa[i].bssid, wpa[i].essid, wpa[i].prio, prio);
				break;
			}
		}
	}

	wpa[nwpa].prio = prio;
	strcpy(wpa[nwpa].essid, essid);
	strcpy(wpa[nwpa].bssid, bssid);

	fprintf(stderr, "%s '%s' at %s\n", ctl_subtype[subtype], essid, bssid);

	if (++nwpa >= max_essids)
		allocate_more_memory();
}

static int is_zero(void *ptr, size_t len)
{
	unsigned char *p = ptr;

	while (len--)
		if (*p++)
			return 0;
	return 1;
}

static void Handle4Way(int is_qos)
{
	ieee802_1x_frame_hdr_t *pkt = (ieee802_1x_frame_hdr_t*)packet;
	int i, ess = -1;
	uint8 *p = (uint8*)&packet[sizeof(ieee802_1x_frame_hdr_t)];
	uint8 *end = packet + pkt_hdr.incl_len;
	ieee802_1x_eapol_t *auth;
	int msg = 0;
	char bssid[18];
	char nonce[9];
	uint64 rc;

	// Find the ESSID in our db.  If we can NOT find it, do not proceed.
	// Also, if we find it, we may determine that we're done with it already

	to_bssid(bssid, pkt->addr3);
	for (i = nwpa - 1; i >= 0; --i) {
		if (!strcmp(bssid, wpa[i].bssid)) {
			ess = i;
			break;
		}
	}
	if (ess == -1) {
		fprintf(stderr, "EAPOL for BSSID %s - unknown ESSID. Perhaps -e option needed?\n", bssid);
		return;
	}

	// Ok, after pkt,  uint16 QOS control (should be 00 00)
	if (is_qos)
		p += 2;

	// we are now at Logical-Link Control. (8 bytes long).
	// LLC check not needed here any more.  We do it in the packet cracker
	// section, before calling this function.  We just need to skip the 8 byte
	// LLC.
	//if (memcmp(p, "\xaa\xaa\x3\0\0\0\x88\x8e", 8)) return; // not a 4way
	p += 8;

	// p now points to the 802.1X Authentication structure.
	auth = (ieee802_1x_eapol_t*)p;
	if (p + sizeof(ieee802_1x_eapol_t) > end) {
		if (verbosity > 1)
			fprintf(stderr, "EAPOL truncated?\n");
		return;
	}
	if ((auth->length = swap16u(auth->length)) == 0) {
		if (verbosity > 1)
			fprintf(stderr, "Zero length\n");
		return;
	}
	//*(uint16*)&(auth->key_info) = swap16u(*(uint16*)&(auth->key_info));
	auth->key_info_u16 = swap16u(auth->key_info_u16);
	auth->key_len  = swap16u(auth->key_len);
	auth->replay_cnt  = swap64u(auth->replay_cnt);
	auth->wpa_keydatlen  = swap16u(auth->wpa_keydatlen);

	sprintf(nonce, "%02x%02x%02x%02x", auth->wpa_nonce[28], auth->wpa_nonce[29], auth->wpa_nonce[30], auth->wpa_nonce[31]);
	rc = auth->replay_cnt;

	if (!auth->key_info.KeyACK) {
		if (auth->key_info.Secure || auth->wpa_keydatlen == 0)
			msg = 4;
		else
			msg = 2;
	} else {
		if (auth->key_info.Install)
			msg = 3;
		else
			msg = 1;
	}

	if (wpa[ess].fully_cracked) {
		if (verbosity > 1)
			fprintf(stderr, "EAPOL M%u, %cnonce %s rc %llu (4-way already seen)%s\n", msg, (msg == 1 || msg == 3) ? 'a' : 's', nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		return;  // no reason to go on.
	}

	if (msg == 4 && is_zero(auth->wpa_nonce, 32)) {
		if (verbosity > 1)
			fprintf(stderr, "Spurious M4 snonce nulled rc %llu\n", rc);
		return;
	}

// If we see M1 followed by M2 which have same replay_cnt, we have a likely
// auth. Or we want a M2 followed by a M3 that are 1 replay count apart
// which means we DO have an auth.
// The M3 is not returned unless the M2 (which came from the client), IS
// valid. So, we get the anonce from either the M1 or the M3 packet.

// For our first run, we output ALL valid auths found in the file. That way,
// I can validate that any auths which were produced by aircrack-ng are valid
// or not.  aircrack-ng WILL generate some invalid auths.  Also, I want to flag
// "unknown" auths as just that, unk.  These are M1-M2's which do not have valid
// M3-M4's.  They may be valid, but may also be a client with the wrong password

	if (msg == 1 && !IGNORE_MSG1) {
		if (verbosity > 1)
			fprintf(stderr, "EAPOL M1 anonce %s rc %llu%s\n", nonce, rc,
			        auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		else
			if (auth->key_info.KeyDescr == 3)
				fprintf(stderr, "Found AES cipher with AES-128-CMAC MIC, 802.11w with WPA2-PSK-SHA256 (PMF) is being used.\n");
		wpa[ess].M[0].packet = NULL;
		MEM_FREE(wpa[ess].M[1].packet);
		MEM_FREE(wpa[ess].M[2].packet);
		MEM_FREE(wpa[ess].M[3].packet);
		MEM_FREE(wpa[ess].M[4].packet);
		safe_malloc(wpa[ess].M[1].packet, pkt_hdr.incl_len);
		wpa[ess].M[1].isQoS = is_qos;
		memcpy(wpa[ess].M[1].packet, packet, pkt_hdr.incl_len);
		wpa[ess].M[1].packet_len = pkt_hdr.incl_len;
		wpa[ess].M[1].ts_sec = cur_t;
		wpa[ess].M[1].ts_usec = cur_u;
	}

	else if (msg == 2 && !IGNORE_MSG2) {
		// Some sanitiy checks
		if (pkt_hdr.incl_len < sizeof(ieee802_1x_frame_hdr_t) + (is_qos ? 10 : 8)) {
			fprintf(stderr, "%s: header len %u, wanted to subtract "Zu", skipping packet\n",
				filename, pkt_hdr.incl_len, sizeof(ieee802_1x_frame_hdr_t) + (is_qos ? 10 : 8));
			return;
		}

		// see if we have a M1 that 'matches'.
		MEM_FREE(wpa[ess].M[2].packet);
		MEM_FREE(wpa[ess].M[3].packet);
		MEM_FREE(wpa[ess].M[4].packet);
		safe_malloc(wpa[ess].M[2].packet, pkt_hdr.incl_len);
		wpa[ess].M[2].isQoS = is_qos;
		memcpy(wpa[ess].M[2].packet, packet, pkt_hdr.incl_len);
		wpa[ess].M[2].packet_len = pkt_hdr.incl_len;
		wpa[ess].M[2].ts_sec = cur_t;
		wpa[ess].M[2].ts_usec = cur_u;
		wpa[ess].M[0].packet = wpa[ess].M[2].packet;
		wpa[ess].M[0].packet_len = wpa[ess].M[2].packet_len;
		wpa[ess].M[0].isQoS = is_qos;

		// This is canonical for any encapsulations
		wpa[ess].eapol_sz = auth->length + 4;

		if (wpa[ess].eapol_sz > sizeof(((hccap_t*)(NULL))->eapol)) {
			fprintf(stderr, "%s: eapol size %u (too large), skipping packet\n",
			        filename, wpa[ess].eapol_sz);
			wpa[ess].eapol_sz = 0;
			MEM_FREE(wpa[ess].M[2].packet);
			wpa[ess].M[0].packet = NULL;
			return;
		}

		if (wpa[ess].M[1].packet) {
			ieee802_1x_eapol_t *auth2 = auth, *auth1;
			p = (uint8*)wpa[ess].M[1].packet;
			if (wpa[ess].M[1].isQoS)
				p += 2;
			p += 8;
			p += sizeof(ieee802_1x_frame_hdr_t);
			auth1 = (ieee802_1x_eapol_t*)p;
			if (auth1->replay_cnt == auth2->replay_cnt) {
				fprintf(stderr, "EAPOL M2 (matching M1 seen), snonce %s rc %llu for ESSID %s%s\n", nonce, rc, wpa[ess].essid, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
			} else if (IgnoreRepCnt && (wpa[ess].M[2].ts_sec >= wpa[ess].M[1].ts_sec && wpa[ess].M[2].ts_sec - wpa[ess].M[1].ts_sec < rctime)) {
				fprintf(stderr, "EAPOL M2 w/ M1 hit, snonce %s rc %llu for ESSID %s (rc mismatch)%s\n", nonce, rc, wpa[ess].essid, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
			} else {
				if (verbosity > 1)
					fprintf(stderr, "EAPOL M2 (no matching M1 seen) snonce %s rc %llu %s\n", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
			}
			return;
		} else {
			if (verbosity > 1)
				fprintf(stderr, "%sM2 snonce %s rc %llu%s\n", wpa[ess].M[1].packet ? "" : "Spurious ", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		}

	}

	else if (msg == 3 && !IGNORE_MSG3) {
		// Either we have a M2 that 'matches', (1 less than our replay count)
		// or we get a matching M4 in the future (with non-zeroed data)
		MEM_FREE(wpa[ess].M[4].packet);
		safe_malloc(wpa[ess].M[3].packet, pkt_hdr.incl_len);
		wpa[ess].M[3].isQoS = is_qos;
		memcpy(wpa[ess].M[3].packet, packet, pkt_hdr.incl_len);
		wpa[ess].M[3].packet_len = pkt_hdr.incl_len;
		wpa[ess].M[3].ts_sec = cur_t;
		wpa[ess].M[3].ts_usec = cur_u;

		if (wpa[ess].M[2].packet) {
			ieee802_1x_eapol_t *auth3 = auth, *auth2;
			p = (uint8*)wpa[ess].M[2].packet;
			if (wpa[ess].M[2].isQoS)
				p += 2;
			p += 8;
			p += sizeof(ieee802_1x_frame_hdr_t);
			auth2 = (ieee802_1x_eapol_t*)p;
			if (auth2->replay_cnt + 1 == auth3->replay_cnt) {
				ieee802_1x_eapol_t *auth1;
				if (wpa[ess].M[1].packet) {
					p = (uint8*)wpa[ess].M[1].packet;
					if (wpa[ess].M[1].isQoS)
						p += 2;
					p += 8;
					p += sizeof(ieee802_1x_frame_hdr_t);
					auth1 = (ieee802_1x_eapol_t*)p;
				}
				// If we saw the M1, its nonce must match the M3 nonce and we
				// are 100% sure. If we didn't see it, we are only 99% sure.
				if (!wpa[ess].M[1].packet || !memcmp(auth1->wpa_nonce, auth3->wpa_nonce, 32)) {
					fprintf(stderr, "EAPOL M3 (M2 seen, M1%s seen), anonce %s rc %llu for BSSID %s ESSID '%s'%s\n",
					        wpa[ess].M[1].packet ? "" : " not", nonce, rc,
					        wpa[ess].bssid, wpa[ess].essid,
					        auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
					DumpAuth(ess, 3, 2);
					wpa[ess].fully_cracked = 1;

					// clear this, so we do not hit the same 3 packet and output exact same 2/3 combo.
					wpa[ess].M[0].packet = NULL;
					MEM_FREE(wpa[ess].M[1].packet);
					MEM_FREE(wpa[ess].M[2].packet);
					MEM_FREE(wpa[ess].M[3].packet);
					MEM_FREE(wpa[ess].M[4].packet);
				} else {
					if (verbosity > 1)
						fprintf(stderr, "EAPOL M3 (no M2 seen) anonce %s rc %llu %s\n", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
				}
			} else if (IgnoreRepCnt && (wpa[ess].M[3].ts_sec >= wpa[ess].M[2].ts_sec && wpa[ess].M[3].ts_sec - wpa[ess].M[2].ts_sec < rctime)) {
				ieee802_1x_eapol_t *auth1;

				if (wpa[ess].M[1].packet) {
					p = (uint8*)wpa[ess].M[1].packet;
					if (wpa[ess].M[1].isQoS)
						p += 2;
					p += 8;
					p += sizeof(ieee802_1x_frame_hdr_t);
					auth1 = (ieee802_1x_eapol_t*)p;
				}
				// If we saw the M1, its nonce must match the M3 nonce and we
				// are 100% sure. If we didn't see it, we are only 99% sure.
				if (!wpa[ess].M[1].packet || !memcmp(auth1->wpa_nonce, auth3->wpa_nonce, 32)) {
					fprintf(stderr, "EAPOL M3 (M2 seen, M1%s seen), anonce %s rc %llu for BSSID %s ESSID '%s' (rc mismatch)%s\n",
					        wpa[ess].M[1].packet ? "" : " not", nonce, rc,
					        wpa[ess].bssid, wpa[ess].essid,
					        auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
					DumpAuth(ess, 3, 2);
					wpa[ess].fully_cracked = 1;

					// clear this, so we do not hit the same 3 packet and output exact same 2/3 combo.
					wpa[ess].M[0].packet = NULL;
					MEM_FREE(wpa[ess].M[1].packet);
					MEM_FREE(wpa[ess].M[2].packet);
					MEM_FREE(wpa[ess].M[3].packet);
					MEM_FREE(wpa[ess].M[4].packet);
				} else {
					if (verbosity > 1)
						fprintf(stderr, "EAPOL M3 (no M2 seen) anonce %s rc %llu %s\n", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
				}
			}
		} else {
			if (verbosity > 1)
				fprintf(stderr, "EAPOL M3 (no M2 seen) anonce %s rc %llu%s\n", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		}
	}

	else if (msg == 4) {
		// Some sanitiy checks
		if (pkt_hdr.incl_len < sizeof(ieee802_1x_frame_hdr_t) + (is_qos ? 10 : 8)) {
			fprintf(stderr, "%s: header len %u, wanted to subtract "Zu", skipping packet\n",
				filename, pkt_hdr.incl_len, sizeof(ieee802_1x_frame_hdr_t) + (is_qos ? 10 : 8));
			return;
		}

		// see if we have a M1 or M3 that 'matches'.
		MEM_FREE(wpa[ess].M[2].packet);
		MEM_FREE(wpa[ess].M[4].packet);
		safe_malloc(wpa[ess].M[4].packet, pkt_hdr.incl_len);
		wpa[ess].M[4].isQoS = is_qos;
		memcpy(wpa[ess].M[4].packet, packet, pkt_hdr.incl_len);
		wpa[ess].M[4].packet_len = pkt_hdr.incl_len;
		wpa[ess].M[4].ts_sec = cur_t;
		wpa[ess].M[4].ts_usec = cur_u;
		wpa[ess].M[0].packet = wpa[ess].M[4].packet;
		wpa[ess].M[0].packet_len = wpa[ess].M[4].packet_len;
		wpa[ess].M[0].isQoS = is_qos;

		// This is canonical for any encapsulations
		wpa[ess].eapol_sz = auth->length + 4;

		if (wpa[ess].eapol_sz > sizeof(((hccap_t*)(NULL))->eapol)) {
			fprintf(stderr, "%s: eapol size %u (too large), skipping packet\n",
			        filename, wpa[ess].eapol_sz);
			wpa[ess].eapol_sz = 0;
			MEM_FREE(wpa[ess].M[4].packet);
			wpa[ess].M[0].packet = NULL;
			return;
		}

		if (wpa[ess].M[3].packet) {
			ieee802_1x_eapol_t *auth4 = auth, *auth3;
			int pkt = wpa[ess].M[3].packet ? 3 : 1;

			p = (uint8*)wpa[ess].M[pkt].packet;
			if (wpa[ess].M[pkt].isQoS)
				p += 2;
			p += 8;
			p += sizeof(ieee802_1x_frame_hdr_t);
			auth3 = (ieee802_1x_eapol_t*)p;
			if (auth3->replay_cnt == auth4->replay_cnt) {
				fprintf(stderr, "EAPOL M4 (matching M3 seen), snonce %s rc %llu for ESSID %s%s\n", nonce, rc, wpa[ess].essid, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
				DumpAuth(ess, 3, 4);
				wpa[ess].fully_cracked = 1;

				// clear this, so we do not hit the same 4 packet and output exact same 3/4 combo.
				wpa[ess].M[0].packet = NULL;
				MEM_FREE(wpa[ess].M[1].packet);
				MEM_FREE(wpa[ess].M[2].packet);
				MEM_FREE(wpa[ess].M[3].packet);
				MEM_FREE(wpa[ess].M[4].packet);
				return;
			}
		}
		if (wpa[ess].M[1].packet) {
			int pkt = wpa[ess].M[3].packet ? 3 : 1;
			ieee802_1x_eapol_t *auth4 = auth, *auth1;

			p = (uint8*)wpa[ess].M[pkt].packet;
			if (wpa[ess].M[pkt].isQoS)
				p += 2;
			p += 8;
			p += sizeof(ieee802_1x_frame_hdr_t);
			auth1 = (ieee802_1x_eapol_t*)p;
			if ((auth1->replay_cnt + 1) == auth4->replay_cnt) {
				fprintf(stderr, "EAPOL M4 (matching M1 seen), snonce %s rc %llu for ESSID %s%s\n", nonce, rc, wpa[ess].essid, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
				DumpAuth(ess, 1, 4);
				wpa[ess].fully_cracked = 1;

				// clear this, so we do not hit the same 4 packet and output exact same 3/4 combo.
				wpa[ess].M[0].packet = NULL;
				MEM_FREE(wpa[ess].M[1].packet);
				MEM_FREE(wpa[ess].M[2].packet);
				MEM_FREE(wpa[ess].M[3].packet);
				MEM_FREE(wpa[ess].M[4].packet);
				return;
			} else {
				if (verbosity > 1)
					fprintf(stderr, "EAPOL M4 (no matching M1/M3 seen) snonce %s rc %llu %s\n", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
			}

		} else {
			if (verbosity > 1)
				fprintf(stderr, "%sM4 snonce %s rc %llu%s\n", (wpa[ess].M[1].packet || wpa[ess].M[3].packet) ? "" : "Spurious ", nonce, rc, auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		}
	} else
		fprintf(stderr, "not EAPOL\n");
}

#if HAVE___MINGW_ALIGNED_MALLOC && !defined (MEMDBG_ON)
char *strdup_MSVC(const char *str)
{
	char * s;
	s = (char*)__mingw_aligned_malloc(strlen(str)+1, (sizeof(long long)));
	if (s != NULL)
		strcpy(s, str);
	return s;
}
#endif

// We pick anonce from M1 or M3. Everything else should be from M2, or
// possibly from M4 unless it's zeroed out. In a pinch we can allegedly
// use EAPOL from M3 but then nonce fuzzing is impossible.
//
// hccapx "message pair value"
// val  msgs   EAPOL  fuzzing possible  rc match  used here
//   0  M1/M2   M2      yes               yes       yes
//   1  M1/M4   M4      yes               yes       yes
//   2  M2/M3   M2      yes               yes       yes
//   3  M2/M3   M3      no                yes       no
//   4  M3/M4   M3      no                yes       no
//   5  M3/M4   M4      yes               yes       yes
// 128  M1/M2   M2      yes               no        no
// 129  M1/M4   M4      yes               no        no
// 130  M2/M3   M2      yes               no        no
// 131  M2/M3   M3      no                no        no
// 132  M3/M4   M3      no                no        no
// 133  M3/M4   M4      yes               no        no
static void DumpAuth(int ess, int ap_msg, int sta_msg)
{
	ieee802_1x_eapol_t *auth13, *auth24;
	uint8 *p24 = (uint8*)wpa[ess].M[sta_msg].packet;
	uint8 *p = p24;
	uint8 *end = (uint8*)wpa[ess].M[sta_msg].packet + wpa[ess].M[sta_msg].packet_len;
	uint8 *p13;
	hccap_t	hccap;
	int i;
	uint8 *w;
	char sta_mac[18+1], ap_mac[18+1], gecos[13+1];
	char TmpKey[2048], *cp = TmpKey;
	int latest = sta_msg;

	cp += sprintf(cp, "%s:$WPAPSK$%s#", wpa[ess].essid, wpa[ess].essid);
	if (!p24) {
		fprintf(stderr, "ERROR, M%u null\n", sta_msg);
		return;
	}
	if (wpa[ess].M[sta_msg].isQoS)
		p += 2;
	p += 8;
	p += sizeof(ieee802_1x_frame_hdr_t);
	auth24 = (ieee802_1x_eapol_t*)p;

	if (!wpa[ess].M[ap_msg].packet) {
		fprintf(stderr, "ERROR, M%u null\n", ap_msg);
		return;
	}
	p = wpa[ess].M[ap_msg].packet;
	end = (uint8*)wpa[ess].M[ap_msg].packet + wpa[ess].M[ap_msg].packet_len;

	p13 = p;
	if (wpa[ess].M[ap_msg].isQoS)
		p += 2;
	p += 8;
	p += sizeof(ieee802_1x_frame_hdr_t);
	auth13 = (ieee802_1x_eapol_t*)p;

	memset(&hccap, 0, sizeof(hccap_t));
	hccap.keyver = auth24->key_info.KeyDescr;
	memcpy(hccap.mac1, ((ieee802_1x_frame_hdr_t*)p24)->addr1, 6);
	memcpy(hccap.mac2, ((ieee802_1x_frame_hdr_t*)p13)->addr1, 6);
	memcpy(hccap.nonce1, auth24->wpa_nonce,32);
	memcpy(hccap.nonce2, auth13->wpa_nonce,32);
	memcpy(hccap.keymic, auth24->wpa_keymic, 16);
	p = wpa[ess].M[0].packet;
	end = p + wpa[ess].M[0].packet_len;
	if (wpa[ess].M[0].isQoS)
		p += 2;
	p += 8;
	p += sizeof(ieee802_1x_frame_hdr_t);
	auth24 = (ieee802_1x_eapol_t*)p;
	hccap.eapol_size = wpa[ess].eapol_sz;
	if (p + hccap.eapol_size > end) {
		// more checks like this should be added to this function
		fprintf(stderr, "%s() malformed data in %s?\n", __FUNCTION__, filename);
		dump_hex("Full packet", wpa[ess].M[0].packet, wpa[ess].M[0].packet_len);
		fprintf(stderr, "\n");
		return;
	}
	memcpy(hccap.eapol, auth24, hccap.eapol_size);
	memset(hccap.eapol + offsetof(ieee802_1x_eapol_t, wpa_keymic), 0, 16);

	w = (uint8 *)&hccap;
	for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
		cp += code_block(&w[i], 1, cp);
	cp += code_block(&w[i], 0, cp);

	to_compact(gecos, hccap.mac1);
	to_dashed(ap_mac, hccap.mac1);
	to_dashed(sta_mac, hccap.mac2);
	cp += sprintf(cp, ":%s:%s:%s::WPA", sta_mac, ap_mac, gecos);
	if (hccap.keyver > 1)
		cp += sprintf(cp, "%d", hccap.keyver);
	cp += sprintf(cp, ":%sverified:%s", (ap_msg == 1 && sta_msg == 2) ? "not " : "", filename);

	if (wpa[ess].M[ap_msg].ts_sec >= wpa[ess].M[sta_msg].ts_sec &&
	    wpa[ess].M[ap_msg].ts_usec > wpa[ess].M[sta_msg].ts_usec)
		latest = ap_msg;
	fprintf(stderr, "Dumping M%u/M%u at %u.%06u BSSID %s ESSID '%s'\n",
	        ap_msg, sta_msg, wpa[ess].M[latest].ts_sec, wpa[ess].M[latest].ts_usec, wpa[ess].bssid, wpa[ess].essid);
	printf("%s\n", TmpKey);
	fflush(stdout);
}

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";
	FILE *in;
	char *base;

	fd = mkstemp(name);  // this approach is somehow faster than the fmemopen way
	if (fd < 0) {
		fprintf(stderr, "Problem detected while creating the input file, %s, aborting!\n", strerror(errno));
		exit(-1);
	}
	write(fd, data, size);
	close(fd);

	wpa = calloc(max_essids, sizeof(WPA4way_t));

	in = fopen(filename = name, "rb");
	if (in) {
		if ((base = strrchr(filename, '/')))
			filename = ++base;
		Process(in);
		fclose(in);
	} else
		fprintf(stderr, "Error, file %s not found\n", name);
	fprintf(stderr, "\n%d ESSIDS processed\n", nwpa);
	remove(name);

	free(wpa);

	return 0;
}
#endif

#ifdef HAVE_LIBFUZZER
int main_dummy(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	FILE *in;
	int i;
	char *base;

	wpa = calloc(max_essids, sizeof(WPA4way_t));

	if (!wpa)
		alloc_error();

	if (sizeof(struct ivs2_filehdr) != 2  || sizeof(struct ivs2_pkthdr) != 4 ||
	    sizeof(struct ivs2_WPA_hdsk) != 356 || sizeof(hccap_t) != 356+36) {
		fprintf(stderr, "Internal error: struct sizes wrong.\n");
		return 2;
	}

	if (argc > 1 && !strcmp(argv[1], "-c")) {
		ShowIncomplete = 0;
		argv[1] = argv[0];
		argv++; argc--;
	}

	while (argc > 1 && !strcmp(argv[1], "-v")) {
		verbosity++;
		argv[1] = argv[0];
		argv++; argc--;
	}

	if (argc > 1 && !strcmp(argv[1], "-r")) {
		IgnoreRepCnt = 1;
		argv[1] = argv[0];
		argv++; argc--;
	}

	while (argc > 2 && !strcmp(argv[1], "-e")) {
		argv[1] = argv[0];
		argv++; argc--;
		ManualBeacon(argv[1]);
		argv[1] = argv[0];
		argv++; argc--;
	}

	if (argc < 2)
		return !!fprintf(stderr,
"Converts PCAP or IVS2 files to JtR format.\n"
"Supported encapsulations: 802.11, Prism, Radiotap and PPI.\n"
"Usage: %s [-c] [-v] [-r] [-e essid:bssid [-e ...]] <file[s]>\n"
"\n-c\tShow only complete auths (incomplete ones might be wrong passwords\n"
"\tbut we can crack what passwords were tried).\n"
"-v\tBump verbosity\n"
"-r\tIgnore replay-count (for use with nonce fuzzing)\n"
"-e\tManually add Name:MAC pair(s) in case the file lacks beacons.\n"
"\teg. -e \"Magnum WIFI:6d:61:67:6e:75:6d\"\n\n",
		                 argv[0]);

	for (i = 1; i < argc; i++) {
		int j;

		// Re-init between pcap files
		warn_snaplen = 0;
		warn_wpaclean = 0;
		start_t = start_u = 0;
		pkt_num = 0;
		for (j = 0; j < nwpa; j++)
			wpa[j].prio = 5;

		in = fopen(filename = argv[i], "rb");
		if (in) {
			if ((base = strrchr(filename, '/')))
				filename = ++base;
			Process(in);
			fclose(in);
		} else
			fprintf(stderr, "Error, file %s not found\n", argv[i]);
	}
	fprintf(stderr, "\n%d ESSIDS processed\n", nwpa);
	MEM_FREE(new_p);
	return 0;
}
