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

#include "wpapcap2john.h"
#include "memdbg.h"

/*
 * Max. number of ESSID's we can collect from all files combined.
 * Just bump this if you need more. We should use a linked list instead
 * and drop this limitation
 */
#define MAX_ESSIDS	10000

static int GetNextPacket(FILE *in);
static int ProcessPacket();
static void HandleBeacon();
static void Handle4Way(int bIsQOS);
static void DumpKey(int idx, int one_three, int bIsQOS);

static uint32 start_t, start_u, cur_t, cur_u;
static pcaprec_hdr_t pkt_hdr;
static uint8 *full_packet;
static uint8 *packet;
static int bROT;
static WPA4way_t wpa[MAX_ESSIDS];
static int nwpa = 0;
static char *unVerified[MAX_ESSIDS];
static int nunVer = 0;
static const char cpItoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const char *filename;
static unsigned int link_type, ShowIncomplete = 1;

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

	if(fread(buffer, 1, 4, f_in) != 4) {
		fprintf(stderr, "%s: fread file header failed\n", filename);
		return(1);
	}

	if(memcmp(buffer, IVSONLY_MAGIC, 4) == 0) {
		fprintf(stderr, "%s: old version .ivs file, no WPA2 handshakes\n", filename);
		return(1);
	}

	if(memcmp(buffer, IVS2_MAGIC, 4) != 0) {
		fprintf(stderr, "%s: not an .%s file\n", filename, IVS2_EXTENSION);
		return(1);
	}

	if(fread(&fivs2, 1, sizeof(struct ivs2_filehdr), f_in) != (size_t) sizeof(struct ivs2_filehdr)) {
		fprintf(stderr, "%s: fread file header failed", filename);
		return(1);
	}

	if(fivs2.version > IVS2_VERSION) {
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

			fprintf(stderr, "%s: bssid: %02x:%02x:%02x:%02x:%02x:%02x\n", filename, p[0], p[1], p[2], p[3], p[4], p[5]);
			bssidFound = 1;
		}
		if (ivs2.flags & IVS2_ESSID) {
			unsigned int ofs = (p - buffer);
			unsigned int len = pktlen - ofs;

			if (len <= 0 || len+1 > sizeof(essid)) {
				printf("Invalid essid length (%d)\n", len);
				return 1;
			}

			memcpy(essid, p, len);
			essid[len] = 0;

			essidFound = 1;

			fprintf(stderr,"essid: '%s' (%d bytes)\n", essid, len);
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
		fprintf(stderr, "Dumping %d unverified keys, which were not verified\n", nunVer);
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
		; //fprintf(stderr, "%s: raw 802.11\n", filename);
	else if (link_type == LINKTYPE_PRISM_HEADER)
		fprintf(stderr, "%s: Prism headers stripped\n", filename);
	else if (link_type == LINKTYPE_RADIOTAP_HDR)
		fprintf(stderr, "%s: Radiotap headers stripped\n", filename);
	else if (link_type == LINKTYPE_PPI_HDR)
		fprintf(stderr, "%s: PPI headers stripped\n", filename);
	else {
		fprintf(stderr, "%s: No 802.11 wireless traffic data (network %d)\n", filename, link_type);
		return 0;
	}

	while (GetNextPacket(in)) {
		if (!ProcessPacket()) {
			dump_any_unver();
			return 1;
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
	full_packet = NULL;
	full_packet = (uint8 *)malloc(pkt_hdr.incl_len);
	if (NULL == full_packet) {
		fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n",
		        __FILE__, __LINE__, sizeof(uint8) * pkt_hdr.orig_len);
		exit(EXIT_FAILURE);
	}
	read_size = fread(full_packet, 1, pkt_hdr.incl_len, in);
	if (read_size < pkt_hdr.incl_len)
		fprintf(stderr, "%s: truncated last packet\n", filename);

	return (read_size == pkt_hdr.incl_len);
}

// Ok, this function is the main packet processor.  NOTE, when we are done
// reading packets (i.e. we have done what we want), we return 0, and
// the program will exit gracefully.  It is not an error, it is just an
// indication we have completed (or that the data we want is not here).
static int ProcessPacket()
{
	ether_frame_hdr_t *pkt;
	ether_frame_ctl_t *ctl;
	unsigned int frame_skip = 0;

	packet = full_packet;

	// Skip Prism frame if present
	if (link_type == LINKTYPE_PRISM_HEADER) {
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
		frame_skip = *(unsigned short*)&packet[2];
#if !ARCH_LITTLE_ENDIAN
		frame_skip = JOHNSWAP(frame_skip);
#endif
		if(frame_skip <= 0 || frame_skip >= pkt_hdr.incl_len)
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

	// our data is in *packet with pkt_hdr being the pcap packet header for this packet.
	pkt = (ether_frame_hdr_t*)packet;
	ctl = (ether_frame_ctl_t *)&pkt->frame_ctl;

	if (ctl->type == 0 && ctl->subtype == 8) { // beacon  Type 0 is management, subtype 8 is beacon
		HandleBeacon();
		return 1;
	}
	// if not beacon, then only look data, looking for EAPOL 'type'
	if (ctl->type == 2) { // type 2 is data
		uint8 *p = packet;
		int bQOS = (ctl->subtype & 8) != 0;
		if ((ctl->toDS ^ ctl->fromDS) != 1)// eapol will ONLY be direct toDS or direct fromDS.
			return 1;
		// Ok, find out if this is a EAPOL packet or not.

		p += sizeof(ether_frame_hdr_t);
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

static void HandleBeacon()
{
	ether_frame_hdr_t *pkt = (ether_frame_hdr_t*)packet;
	int i;

	ether_beacon_data_t *pDat = (ether_beacon_data_t*)&packet[sizeof(ether_frame_hdr_t)];
	ether_beacon_tag_t *tag = pDat->tags;
	uint8 *pFinal = &packet[pkt_hdr.incl_len];
	char essid[36] = { 0 };
	char bssid[18];

	// addr1 should be broadcast
	// addr2 is source addr (should be same as BSSID)
	// addr3 is BSSID (routers MAC)

	// ok, walk the tags

	while (((uint8*)tag) < pFinal) {
		char *x = (char*)tag;
		if (tag->tagtype == 0 && tag->taglen < sizeof(essid))
			memcpy(essid, tag->tag, tag->taglen);
		x += tag->taglen + 2;
		tag = (ether_beacon_tag_t *)x;
	}
	to_bssid(bssid, pkt->addr3);
	for (i = 0; i < nwpa; ++i) {
		if (!strcmp(bssid, wpa[i].bssid) && !strcmp(essid, wpa[i].essid))
			return;
	}
	strcpy(wpa[nwpa].essid, essid);
	strcpy(wpa[nwpa].bssid, bssid);
	if (++nwpa >= MAX_ESSIDS) {
		fprintf(stderr, "ERROR: Too many ESSIDs seen (%d)\n", MAX_ESSIDS);
		exit(EXIT_FAILURE);
	}
}

static void Handle4Way(int bIsQOS)
{
	ether_frame_hdr_t *pkt = (ether_frame_hdr_t*)packet;
	int i, ess=-1;
	uint8 *orig_2 = NULL;
	uint8 *p = (uint8*)&packet[sizeof(ether_frame_hdr_t)];
	ether_auto_802_1x_t *auth;
	int msg = 0;
	char bssid[18];

	// ok, first thing, find the beacon.  If we can NOT find the beacon, then
	// do not proceed.  Also, if we find the becon, we may determine that
	// we already HAVE fully cracked this

	to_bssid(bssid, pkt->addr3);
	for (i = 0; i < nwpa; ++i) {
		if (!strcmp(bssid, wpa[i].bssid)) {
			ess=i;
			break;
		}
	}
	if (ess==-1) goto out;
	if (wpa[ess].fully_cracked)
		goto out;  // no reason to go on.

	orig_2 = (uint8 *)malloc(pkt_hdr.incl_len);
	if (NULL == orig_2) {
		fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n",
		        __FILE__, __LINE__, sizeof(uint8) * pkt_hdr.orig_len);
		exit(EXIT_FAILURE);
	}
	memcpy(orig_2, packet, pkt_hdr.incl_len);

	// Ok, after pkt,  uint16 QOS control (should be 00 00)
	if (bIsQOS)
		p += 2;
	// we are now at Logical-Link Control. (8 bytes long).
	// LLC check not needed here any more.  We do it in the packet cracker section, b4
	// calling this function.  We just need to skip the 8 byte LLC.
	//if (memcmp(p, "\xaa\xaa\x3\0\0\0\x88\x8e", 8)) return; // not a 4way
	p += 8;
	// p now points to the 802.1X Authentication structure.
	auth = (ether_auto_802_1x_t*)p;
	auth->length = swap16u(auth->length);
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

	// Ok, we look for a 1 followed immediately by a 2 which have exact same replay_cnt, we have
	// a 'likely' key. Or we want a 2 followed by a 3 that are 1 replay count apart)  which means
	// we DO have a key.  The 3 is not returned unless the 2 (which came from the client), IS
	// valid. So, we get the anonce from either the 1 or the 3 packet.

	// for our first run, we output ALL valid keys found in the file. That way, I can validate that
	// any keys which were produced by aircrack-ng are 'valid' or not.  aircrack-ng WILL generate some
	// invalid keys.  Also, I want to flag "unknown" keys as just that, unk.  These are 1-2's which
	// do not have valid 3 4's.  They 'may' be valid, but may also be a client with the wrong password.

	if (msg == 1) {
		MEM_FREE(wpa[ess].packet1);
		wpa[ess].packet1 = (uint8 *)malloc(sizeof(uint8) * pkt_hdr.incl_len);
		if (wpa[ess].packet1 == NULL) {
			fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n",
			        __FILE__, __LINE__, sizeof(uint8) * pkt_hdr.orig_len);
			exit(EXIT_FAILURE);
		}
		memcpy(wpa[ess].packet1, packet, pkt_hdr.incl_len);
		MEM_FREE(wpa[ess].packet2);
		MEM_FREE(wpa[ess].orig_2);
		MEM_FREE(wpa[ess].packet3);
	}
	else if (msg == 2) {
		// Some sanitiy checks
		if (pkt_hdr.incl_len < sizeof(ether_frame_hdr_t) + (bIsQOS ? 10 : 8)) {
			fprintf(stderr, "%s: header len %u, wanted to subtract "Zu", skipping packet\n",
				filename, pkt_hdr.incl_len, sizeof(ether_frame_hdr_t) + (bIsQOS ? 10 : 8));
			goto out;
		}

		// see if we have a msg1 that 'matches'.
		MEM_FREE(wpa[ess].packet3);
		wpa[ess].packet2 = (uint8 *)malloc(sizeof(uint8) * pkt_hdr.incl_len);
		if (wpa[ess].packet2 == NULL) {
			fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n",
			        __FILE__, __LINE__, sizeof(uint8) * pkt_hdr.orig_len);
			exit(EXIT_FAILURE);
		}
		wpa[ess].orig_2  = (uint8 *)malloc(sizeof(uint8) * pkt_hdr.incl_len);
		if (wpa[ess].orig_2 == NULL) {
			fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n",
			        __FILE__, __LINE__, sizeof(uint8) * pkt_hdr.orig_len);
			exit(EXIT_FAILURE);
		}
		memcpy(wpa[ess].packet2, packet, pkt_hdr.incl_len);
		memcpy(wpa[ess].orig_2, orig_2, pkt_hdr.incl_len);

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
			ether_auto_802_1x_t *auth2 = auth, *auth1;
			p = (uint8*)wpa[ess].packet1;
			if (bIsQOS)
				p += 2;
			p += 8;
			p += sizeof(ether_frame_hdr_t);
			auth1 = (ether_auto_802_1x_t*)p;
			if (auth1->replay_cnt == auth2->replay_cnt) {
				fprintf (stderr, "\nKey1/Key2 hit (unverified), for ESSID:%s (%s)\n", wpa[ess].essid, filename);
				DumpKey(ess, 1, bIsQOS);
			}
		}
	}
	else if (msg == 3) {
		// see if we have a msg2 that 'matches',  which is 1 less than our replay count.
		wpa[ess].packet3 = (uint8 *)malloc(sizeof(uint8) * pkt_hdr.incl_len);
		if (wpa[ess].packet3 == NULL) {
			fprintf(stderr, "%s:%d: malloc of "Zu" bytes failed\n",
			        __FILE__, __LINE__, sizeof(uint8) * pkt_hdr.orig_len);
			exit(EXIT_FAILURE);
		}
		memcpy(wpa[ess].packet3, packet, pkt_hdr.incl_len);
		if (wpa[ess].packet2) {
			ether_auto_802_1x_t *auth3 = auth, *auth2;
			p = (uint8*)wpa[ess].packet2;
			if (bIsQOS)
				p += 2;
			p += 8;
			p += sizeof(ether_frame_hdr_t);
			auth2 = (ether_auto_802_1x_t*)p;
			if (auth2->replay_cnt+1 == auth3->replay_cnt) {
				ether_auto_802_1x_t *auth1;
				if (wpa[ess].packet1) {
					p = (uint8*)wpa[ess].packet1;
					if (bIsQOS)
						p += 2;
					p += 8;
					p += sizeof(ether_frame_hdr_t);
					auth1 = (ether_auto_802_1x_t*)p;
				}
				// If we saw the first packet, its nonce must
				// match the third's nonce and we are 100% sure.
				// If we didn't see it, we are only 99% sure.
				if (!wpa[ess].packet1 || !memcmp(auth1->wpa_nonce, auth3->wpa_nonce, 32)) {
					fprintf (stderr, "\nKey2/Key3 hit (%s verified), for ESSID:%s (%s)\n",
						wpa[ess].packet1 ? "100%" : "99%", wpa[ess].essid, filename);
					DumpKey(ess, 3, bIsQOS);
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

static void DumpKey(int ess, int one_three, int bIsQOS)
{
	ether_auto_802_1x_t *auth13, *auth2;
	uint8 *p = (uint8*)wpa[ess].packet2;
	uint8 *pkt2 = p;
	uint8 *p13;
	hccap_t	hccap;
	int i;
	uint8 *w;
	char sta_mac[18+1], ap_mac[18+1], gecos[13+1];
	char TmpKey[2048], *cp = TmpKey;
	int search_len;

	fprintf (stderr, "Dumping key %d at time:  %d.%d BSSID %s  ESSID=%s\n", one_three, cur_t, cur_u, wpa[ess].bssid, wpa[ess].essid);
	cp += sprintf (cp, "%s:$WPAPSK$%s#", wpa[ess].essid, wpa[ess].essid);
	if (!wpa[ess].packet2) { printf ("ERROR, msg2 null\n"); return; }
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ether_frame_hdr_t);
	auth2 = (ether_auto_802_1x_t*)p;
	if (one_three==1) {
		if (!wpa[ess].packet1) { printf ("ERROR, msg1 null\n"); return; }
		p = wpa[ess].packet1;
	} else  {
		if (!wpa[ess].packet3) { printf ("ERROR, msg3 null\n"); return; }
		p = wpa[ess].packet3;
	}
	p13 = p;
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ether_frame_hdr_t);
	auth13 = (ether_auto_802_1x_t*)p;

	memset(&hccap, 0, sizeof(hccap_t));
	hccap.keyver = auth2->key_info.KeyDescr;
	memcpy(hccap.mac1, ((ether_frame_hdr_t*)pkt2)->addr1, 6);
	memcpy(hccap.mac2, ((ether_frame_hdr_t*)(p13))->addr1, 6);
	memcpy(hccap.nonce1, auth2->wpa_nonce,32);
	memcpy(hccap.nonce2, auth13->wpa_nonce,32);
	memcpy(hccap.keymic, auth2->wpa_keymic, 16);
	p = wpa[ess].orig_2;
	if (bIsQOS)
		p += 2;
	p += 8;
	p += sizeof(ether_frame_hdr_t);
	auth2 = (ether_auto_802_1x_t*)p;
	memset(auth2->wpa_keymic, 0, 16);
	hccap.eapol_size = wpa[ess].eapol_sz;
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
	cp += sprintf(cp, ":password %sverified:%s", (one_three == 1) ? "not " : "", filename);
	if (one_three == 1) {
		fprintf (stderr, "unVerified key stored, pending verification");
		unVerified[nunVer++] = strdup(TmpKey);
		fprintf(stderr, "\n");
		return;
	} else {
		for (i = 0; i < nunVer; ++i) {
			if (!strncmp(TmpKey, unVerified[i], search_len)) {
				fprintf (stderr, "Key now verified\n");
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

int main(int argc, char **argv)
{
	FILE *in;
	int i;
	char *base;

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

	if (argc < 2)
		return !!fprintf(stderr,
"Converts PCAP or IVS2 files to JtR format\n"
"Usage: %s [-c] <file[s]>\n"
"\n-c\tShow only complete auths (incomplete ones might be wrong passwords\n"
"\tbut we can crack what passwords were tried)\n\n", argv[0]);

	for (i = 1; i < argc; i++) {
		in = fopen(filename = argv[i], "rb");
		if (in) {
			if ((base = strrchr(filename, '/')))
				filename = ++base;
			Process(in);
			fclose(in);
		} else
			fprintf(stderr, "Error, file %s not found\n", argv[i]);
	}
	return 0;
}
