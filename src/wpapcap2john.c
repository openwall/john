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

//#define WPADEBUG 1

#include "wpapcap2john.h"
#include "jumbo.h"
#include "memdbg.h"

static size_t max_essids = 1024; /* Will grow automagically */

static int GetNextPacket(FILE *in);
static int ProcessPacket();
static void HandleBeacon(uint16 subtype);
static void Handle4Way(int bIsQOS);
static void DumpAuth(int idx, int one_three, int bIsQOS);

static uint32 start_t, start_u, cur_t, cur_u;
static pcaprec_hdr_t pkt_hdr;
static uint8 *full_packet;
static uint8 *packet;
static uint8 *new_p;
static int bROT;
static WPA4way_t *wpa;    /* alloced/realloced to max_essids*/
static char **unVerified; /* alloced/realloced to max_essids*/
static int nwpa = 0;
static int nunVer = 0;
static const char cpItoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const char *filename;
static unsigned int link_type, ShowIncomplete = 1;
static int warn_wpaclean;

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
	char essid[500];
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

			printf ("%s:$WPAPSK$%s#", essid, essid);

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
				printf ("%s", buf);
			}
			code_block(&w[i], 0, buf);
			printf ("%s", buf);
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
	if (nunVer) {
		int i;
		fprintf(stderr, "Dumping %d unverified auths\n", nunVer);
		for (i = 0; i < nunVer; ++i) {
			printf("%s\n", unVerified[i]);
			MEM_FREE(unVerified[i]);
		}
	}
	nunVer = 0;
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
	if (!start_t) {
		start_t = pkt_hdr.ts_sec;
		start_u = pkt_hdr.ts_usec;
	}
	cur_t = pkt_hdr.ts_sec-start_t;
	if (start_u > pkt_hdr.ts_usec) {
		--cur_t;
		cur_u = 1000000-(start_u-pkt_hdr.ts_usec);
	} else
		cur_u = pkt_hdr.ts_usec-start_u;

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

// Ok, this function is the main packet processor.  NOTE, when we are done
// reading packets (i.e. we have done what we want), we return 0, and
// the program will exit gracefully.  It is not an error, it is just an
// indication we have completed (or that the data we want is not here).
static int ProcessPacket()
{
	ieee802_1x_frame_hdr_t *pkt;
	ieee802_1x_frame_ctl_t *ctl;
	unsigned int frame_skip = 0;

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
		ieee802_1x_auth_t *auth;

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

		auth = (ieee802_1x_auth_t*)&packet[14];
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

#if WPADEBUG
	//dump_hex("802.11 packet", pkt, pkt_hdr.incl_len);
#endif

	if (pkt_hdr.incl_len < 2)
		return 0;
	ctl = (ieee802_1x_frame_ctl_t *)&pkt->frame_ctl;

	//fprintf(stderr, "Type %d subtype %d\n", ctl->type, ctl->subtype);

	// Type 0 is management,
	// Beacon is subtype 8 and probe response is subtype 5
	// probe request is 4, assoc request is 0, reassoc is 2
	if (ctl->type == 0 && (ctl->subtype == 0 || ctl->subtype == 2 ||
	                       ctl->subtype == 4 || ctl->subtype == 5 ||
	                       ctl->subtype == 8)) {
		HandleBeacon(ctl->subtype);
		return 1;
	}
	// if not beacon or probe response, then look only for EAPOL 'type'
	if (ctl->type == 2) { // type 2 is data
		uint8 *p = packet;
		int bQOS = (ctl->subtype & 8) != 0;
		if ((ctl->toDS ^ ctl->fromDS) != 1)// eapol will ONLY be direct toDS or direct fromDS.
			return 1;
		if (sizeof(ieee802_1x_frame_hdr_t)+6+2+(bQOS?2:0) >= pkt_hdr.incl_len)
			return 1;
		// Ok, find out if this is a EAPOL packet or not.

		p += sizeof(ieee802_1x_frame_hdr_t);
		if (bQOS)
			p += 2;
		// p now points to the start of the LLC (logical link control) structure.
		// this is 8 bytes long, and the last 2 bytes are the 'type' field.  What
		// we are looking for is 802.11X authentication packets. These are 0x888e
		// in value.  We are running from an LE point of view, so should look for 0x8e88
		p += 6;
		if (*((uint16*)p) == 0x8e88)
			Handle4Way(bQOS);	// this packet was a eapol packet.
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
	unVerified = realloc(unVerified, sizeof(char*) * max_essids);
	if (!wpa || !unVerified)
		alloc_error();
	memset(wpa + old_max, 0, sizeof(WPA4way_t) * old_max);
	memset(unVerified + old_max, 0, sizeof(char*) * old_max);
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

static const char* const ctl_subtype[9] = {
	"association request",     // 0
	"1",                       // 1
	"reassociation request",   // 2
	"3",                       // 3
	"unicast probe request",   // 4
	"probe response",          // 5
	"6",                       // 6
	"7",                       // 7
	"beacon"                   // 8
};

static void HandleBeacon(uint16 subtype)
{
	const uint8 bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	ieee802_1x_frame_hdr_t *pkt = (ieee802_1x_frame_hdr_t*)packet;
	ieee802_1x_beacon_tag_t *tag;
	uint8 *pFinal = &packet[pkt_hdr.incl_len];
	char essid[36] = { 0 };
	char bssid[18];
	int prio = 0;
	int i;

	if (subtype == 8 || subtype == 5) { // beacon or probe response
		ieee802_1x_beacon_data_t *pDat = (ieee802_1x_beacon_data_t*)&packet[sizeof(ieee802_1x_frame_hdr_t)];
		tag = pDat->tags;
		prio = (subtype == 8 ? 5 : 3);
	} else if (subtype == 4 && memcmp(pkt->addr1, bcast, 6)) {
		// unicast probe request
		tag = (ieee802_1x_beacon_tag_t*)&packet[sizeof(ieee802_1x_frame_hdr_t)];
		prio = 4;
	} else if (subtype == 0) { // association request
		ieee802_1x_assocreq_t *pDat = (ieee802_1x_assocreq_t*)&packet[sizeof(ieee802_1x_frame_hdr_t)];
		tag = pDat->tags;
		prio = 2;
	} else if (subtype == 2) { // re-association request
		ieee802_1x_reassocreq_t *pDat = (ieee802_1x_reassocreq_t*)&packet[sizeof(ieee802_1x_frame_hdr_t)];
		tag = pDat->tags;
		prio = 1;
	} else
		return;

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
				fprintf(stderr, "Invalid BSSID %s ESSID '%s' from %s\n",
				        bssid, tag->tag, ctl_subtype[subtype]);
				return;
			}
			memcpy(essid, tag->tag, tag->taglen);
			break;
		}
		x += tag->taglen + 2;
		tag = (ieee802_1x_beacon_tag_t *)x;
	}
	if (strlen(essid) == 0)
		return;
	if (pkt->addr3 + 6 > pFinal)
		return;
	to_bssid(bssid, pkt->addr3);

	// Check if already in db, or older entry has worse prio
	for (i = nwpa - 1; i >= 0; --i) {
		if (!strcmp(bssid, wpa[i].bssid) && !strcmp(essid, wpa[i].essid)) {
			if (wpa[i].prio > prio) {
				fprintf(stderr, " Bumped BSSID %s ESSID '%s' (%d -> %d) from %s\n", wpa[i].bssid, wpa[i].essid, wpa[i].prio, prio, ctl_subtype[subtype]);
				wpa[i].prio = prio;
			}
			return;
		} else if (!strcmp(bssid, wpa[i].bssid)) {
			if (wpa[i].prio >= prio) {
				fprintf(stderr, "Renamed BSSID %s ESSID '%s' (old '%s' prio %d, new prio %d) from %s\n", wpa[i].bssid, essid, wpa[i].essid, wpa[i].prio, prio, ctl_subtype[subtype]);
				break;
			}
		}
	}

	wpa[nwpa].prio = prio;
	strcpy(wpa[nwpa].essid, essid);
	strcpy(wpa[nwpa].bssid, bssid);

	fprintf(stderr, "Learned BSSID %s ESSID '%s' from %s\n",
	        bssid, essid, ctl_subtype[subtype]);

	if (++nwpa >= max_essids)
		allocate_more_memory();
}

static void Handle4Way(int bIsQOS)
{
	ieee802_1x_frame_hdr_t *pkt = (ieee802_1x_frame_hdr_t*)packet;
	int i, ess=-1;
	uint8 *orig_2 = NULL;
	uint8 *p = (uint8*)&packet[sizeof(ieee802_1x_frame_hdr_t)];
	uint8 *end = packet + pkt_hdr.incl_len;
	ieee802_1x_auth_t *auth;
	int msg = 0;
	char bssid[18];

	// ok, first thing, find the beacon.  If we can NOT find the beacon, then
	// do not proceed.  Also, if we find the becon, we may determine that
	// we already HAVE fully cracked this

	to_bssid(bssid, pkt->addr3);
	for (i = nwpa - 1; i >= 0; --i) {
		if (!strcmp(bssid, wpa[i].bssid)) {
			ess=i;
			break;
		}
	}
	if (ess == -1) {
		fprintf(stderr, "Saw BSSID %s with unknown ESSID. Perhaps -e option needed?\n", bssid);
		goto out;
	}
	if (wpa[ess].fully_cracked)
		goto out;  // no reason to go on.

	safe_malloc(orig_2, pkt_hdr.incl_len);
	memcpy(orig_2, packet, pkt_hdr.incl_len);

	// Ok, after pkt,  uint16 QOS control (should be 00 00)
	if (bIsQOS)
		p += 2;
	// we are now at Logical-Link Control. (8 bytes long).
	// LLC check not needed here any more.  We do it in the packet cracker
	// section, before calling this function.  We just need to skip the 8 byte
	// LLC.
	//if (memcmp(p, "\xaa\xaa\x3\0\0\0\x88\x8e", 8)) return; // not a 4way
	p += 8;
	// p now points to the 802.1X Authentication structure.
	auth = (ieee802_1x_auth_t*)p;
	if (p + sizeof(ieee802_1x_auth_t) > end)
		goto out;
	if ((auth->length = swap16u(auth->length)) == 0)
		goto out;
	//*(uint16*)&(auth->key_info) = swap16u(*(uint16*)&(auth->key_info));
	auth->key_info_u16 = swap16u(auth->key_info_u16);
	auth->key_len  = swap16u(auth->key_len);
	auth->replay_cnt  = swap64u(auth->replay_cnt);
	auth->wpa_keydatlen  = swap16u(auth->wpa_keydatlen);

	if (!auth->key_info.KeyACK) {
		// msg 2 or 4
		if (auth->key_info.Secure) {
			// msg = 4;
			// is this useful?
			goto out;
		}
		else
			msg = 2;
	} else {
		if (auth->key_info.Install)
			msg = 3;
		else
			msg = 1;
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

	if (msg == 1) {
		if (auth->key_info.KeyDescr == 3)
			fprintf(stderr, "Found AES cipher with AES-128-CMAC MIC, 802.11w with WPA2-PSK-SHA256 (PMF) is being used.\n");
		MEM_FREE(wpa[ess].packet1);
		safe_malloc(wpa[ess].packet1, pkt_hdr.incl_len);
		wpa[ess].packet1_len = pkt_hdr.incl_len;
		memcpy(wpa[ess].packet1, packet, pkt_hdr.incl_len);
		MEM_FREE(wpa[ess].packet2);
		MEM_FREE(wpa[ess].orig_2);
		MEM_FREE(wpa[ess].packet3);
	}
	else if (msg == 2) {
		// Some sanitiy checks
		if (pkt_hdr.incl_len < sizeof(ieee802_1x_frame_hdr_t) + (bIsQOS ? 10 : 8)) {
			fprintf(stderr, "%s: header len %u, wanted to subtract "Zu", skipping packet\n",
				filename, pkt_hdr.incl_len, sizeof(ieee802_1x_frame_hdr_t) + (bIsQOS ? 10 : 8));
			goto out;
		}

		// see if we have a msg1 that 'matches'.
		MEM_FREE(wpa[ess].packet3);
		MEM_FREE(wpa[ess].packet2);
		MEM_FREE(wpa[ess].orig_2);
		safe_malloc(wpa[ess].packet2, pkt_hdr.incl_len);
		wpa[ess].packet2_len = pkt_hdr.incl_len;
		wpa[ess].orig_2  = malloc(pkt_hdr.incl_len);
		memcpy(wpa[ess].packet2, packet, pkt_hdr.incl_len);
		memcpy(wpa[ess].orig_2, orig_2, pkt_hdr.incl_len);
		wpa[ess].orig_2_len = pkt_hdr.incl_len;

		// This is canonical for any encapsulations
		wpa[ess].eapol_sz = auth->length + 4;

		if (wpa[ess].eapol_sz > sizeof(((hccap_t*)(NULL))->eapol)) {
			fprintf(stderr, "%s: eapol size %u (too large), skipping packet\n",
			        filename, wpa[ess].eapol_sz);
			wpa[ess].eapol_sz = 0;
			MEM_FREE(wpa[ess].packet2);
			MEM_FREE(wpa[ess].orig_2);
			goto out;
		}

		if (wpa[ess].packet1 && ShowIncomplete) {
			ieee802_1x_auth_t *auth2 = auth, *auth1;
			p = (uint8*)wpa[ess].packet1;
			if (bIsQOS)
				p += 2;
			p += 8;
			p += sizeof(ieee802_1x_frame_hdr_t);
			auth1 = (ieee802_1x_auth_t*)p;
			if (auth1->replay_cnt == auth2->replay_cnt) {
				fprintf (stderr, "\nM1/M2 hit (unverified), for ESSID %s (%s)\n", wpa[ess].essid, filename);
				DumpAuth(ess, 1, bIsQOS);
			}
		}
	}
	else if (msg == 3) {
		// see if we have a msg2 that 'matches',  which is 1 less than our replay count.
		safe_malloc(wpa[ess].packet3, pkt_hdr.incl_len);
		wpa[ess].packet3_len = pkt_hdr.incl_len;
		memcpy(wpa[ess].packet3, packet, pkt_hdr.incl_len);
		if (wpa[ess].packet2) {
			ieee802_1x_auth_t *auth3 = auth, *auth2;
			p = (uint8*)wpa[ess].packet2;
			if (bIsQOS)
				p += 2;
			p += 8;
			p += sizeof(ieee802_1x_frame_hdr_t);
			auth2 = (ieee802_1x_auth_t*)p;
			if (auth2->replay_cnt+1 == auth3->replay_cnt) {
				ieee802_1x_auth_t *auth1;
				if (wpa[ess].packet1) {
					p = (uint8*)wpa[ess].packet1;
					if (bIsQOS)
						p += 2;
					p += 8;
					p += sizeof(ieee802_1x_frame_hdr_t);
					auth1 = (ieee802_1x_auth_t*)p;
				}
				// If we saw the first packet, its nonce must
				// match the third's nonce and we are 100% sure.
				// If we didn't see it, we are only 99% sure.
				if (!wpa[ess].packet1 || !memcmp(auth1->wpa_nonce, auth3->wpa_nonce, 32)) {
					fprintf (stderr, "\nM2/M3 hit (%s verified), for BSSID %s ESSID '%s' (file '%s')\n",
						wpa[ess].packet1 ? "100%" : "99%", wpa[ess].bssid, wpa[ess].essid, filename);
					DumpAuth(ess, 3, bIsQOS);
					wpa[ess].fully_cracked = 1;
				}
			}
		}
		// clear this, so we do not hit the same 3 packet and output exact same 2/3 combo.
		MEM_FREE(wpa[ess].packet1);
		MEM_FREE(wpa[ess].packet3);
		MEM_FREE(wpa[ess].packet2);
		MEM_FREE(wpa[ess].orig_2);
	}

out:
	MEM_FREE(orig_2);
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

static void DumpAuth(int ess, int one_three, int bIsQOS)
{
	ieee802_1x_auth_t *auth13, *auth2;
	uint8 *p = (uint8*)wpa[ess].packet2;
	uint8 *pkt2 = p;
	uint8 *end = (uint8*)wpa[ess].packet2 + wpa[ess].packet2_len;
	uint8 *p13;
	hccap_t	hccap;
	int i;
	uint8 *w;
	char sta_mac[18+1], ap_mac[18+1], gecos[13+1];
	char TmpKey[2048], *cp = TmpKey;
	int search_len;

	fprintf (stderr, "Dumping M%d at time: %d.%d BSSID %s ESSID '%s'\n",
	         one_three, cur_t, cur_u, wpa[ess].bssid, wpa[ess].essid);
	cp += sprintf (cp, "%s:$WPAPSK$%s#", wpa[ess].essid, wpa[ess].essid);
	if (!wpa[ess].packet2) {
		fprintf(stderr, "ERROR, msg2 null\n");
		return;
	}
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ieee802_1x_frame_hdr_t);
	auth2 = (ieee802_1x_auth_t*)p;
	if (one_three==1) {
		if (!wpa[ess].packet1) {
			fprintf(stderr, "ERROR, msg1 null\n");
			return;
		}
		p = wpa[ess].packet1;
		end = (uint8*)wpa[ess].packet1 + wpa[ess].packet1_len;
	} else  {
		if (!wpa[ess].packet3) {
			fprintf(stderr, "ERROR, msg3 null\n");
			return;
		}
		p = wpa[ess].packet3;
		end = (uint8*)wpa[ess].packet3 + wpa[ess].packet3_len;
	}
	p13 = p;
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ieee802_1x_frame_hdr_t);
	auth13 = (ieee802_1x_auth_t*)p;

	memset(&hccap, 0, sizeof(hccap_t));
	hccap.keyver = auth2->key_info.KeyDescr;
	memcpy(hccap.mac1, ((ieee802_1x_frame_hdr_t*)pkt2)->addr1, 6);
	memcpy(hccap.mac2, ((ieee802_1x_frame_hdr_t*)(p13))->addr1, 6);
	memcpy(hccap.nonce1, auth2->wpa_nonce,32);
	memcpy(hccap.nonce2, auth13->wpa_nonce,32);
	memcpy(hccap.keymic, auth2->wpa_keymic, 16);
	p = wpa[ess].orig_2;
	end = p + wpa[ess].orig_2_len;
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ieee802_1x_frame_hdr_t);
	auth2 = (ieee802_1x_auth_t*)p;
	memset(auth2->wpa_keymic, 0, 16);
	hccap.eapol_size = wpa[ess].eapol_sz;
	if (p + hccap.eapol_size > end) {
		// more checks like this should be added to this function
		fprintf(stderr, "%s() malformed data in %s?\n", __FUNCTION__, filename);
		dump_hex("Full packet", pkt2, end - pkt2);
		fprintf(stderr, "\n");
		return;
	}
	memcpy(hccap.eapol, auth2, hccap.eapol_size);

	w = (uint8 *)&hccap;
	for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
		cp += code_block(&w[i], 1, cp);
	cp += code_block(&w[i], 0, cp);
	to_compact(gecos, hccap.mac1);
	to_dashed(ap_mac, hccap.mac1);
	to_dashed(sta_mac, hccap.mac2);
	cp += sprintf(cp, ":%s:%s:%s::WPA", ap_mac, sta_mac, gecos);
	if (hccap.keyver > 1)
		cp += sprintf(cp, "%d", hccap.keyver);
	search_len = cp-TmpKey;
	cp += sprintf(cp, ":%sverified:%s", (one_three == 1) ? "not " : "", filename);
	if (one_three == 1) {
		fprintf (stderr, "unverified auth stored, pending verification\n");
		unVerified[nunVer++] = strdup(TmpKey);
		return;
	} else {
		for (i = 0; i < nunVer; ++i) {
			if (!strncmp(TmpKey, unVerified[i], search_len)) {
				fprintf (stderr, "Auth now verified\n");
				MEM_FREE(unVerified[i]);
				unVerified[i] = unVerified[--nunVer];
				break;
			}
		}
	}
	fprintf(stderr, "\n");
	printf ("%s\n", TmpKey);
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
	unVerified = calloc(max_essids, sizeof(char*));

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
	free(unVerified);

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
	unVerified = calloc(max_essids, sizeof(char*));

	if (!wpa || !unVerified)
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
"Usage: %s [-c] [-e essid:bssid [-e ...]] <file[s]>\n"
"\n-c\tShow only complete auths (incomplete ones might be wrong passwords\n"
"\tbut we can crack what passwords were tried).\n"
"-e\tManually add Name:MAC pair(s) in case the file lacks beacons.\n"
"\teg. -e Networkname:de:ad:ca:fe:ba:be\n\n",
		                 argv[0]);

	for (i = 1; i < argc; i++) {
		int j;

		// Re-init between pcap files
		warn_wpaclean = 0;
		start_t = start_u = 0;
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
