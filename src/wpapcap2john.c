/*
 * This software is Copyright (c) 2013 Jim Fougeron jfoug AT cox dot net,
 * Copyright (c) 2013 Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2014-2018 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 * Kudos to ZeroBeat for misc. help, and code snippets derived from hcxtools!
 *
 * MIC is 32-bit Message Integrity Code of DA, SA and payload.
 * PTK is Pairwise Temporal Key, GTK is Group Temporal Key.
 * IE are Information Elements (eg. supported or selected ciphers).
 *
 *                AP picks random nonce (anonce).
 * 1.  AP -> STA  Send anonce.
 *
 *                STA picks random nonce (snonce) and derives PTK from
 *                PMK + anonce + snonce + AP MAC address + STA MAC address.
 * 2. STA ->  AP  Send snonce, IE and encrypted MIC.
 *
 *                AP derives PTK as above.
 * 3.  AP -> STA  Send anonce, GTK, IE and encrypted MIC.
 *
 * 4  STA -> AP   Send ACK with encrypted MIC (zeroed snonce).
 *
 * EAPOL addr3 is Destination (as opposed to Receiver, which is addr1).
 */

#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>

#include "wpapcap2john.h"
#include "jumbo.h"

//#define WPADEBUG 1
#define IGNORE_MSG1 0
#define IGNORE_MSG2 0
#define IGNORE_MSG3 0

static size_t max_essid = 1024; /* Will grow automagically */
static size_t max_state = 1024; /* This too */

static uint64_t cur_ts64, abs_ts64, start_ts64;
static uint32_t pkt_num;
static uint8_t *full_packet;
static uint8_t *packet;
static uint8_t *packet_TA, *packet_RA, *packet_SA, *packet_DA, *bssid;
static uint8_t *new_p;
static size_t new_p_sz;
static int swap_needed;
static essid_t *essid_db;   /* alloced/realloced to max_essid */
static int n_essid;
static WPA4way_t *apsta_db; /* alloced/realloced to max_state */
static int n_apsta;
static int n_handshakes, n_pmkids;
static int rctime = 2 * 1000000; /* 2 seconds (bumped with -r) */
static const char *filename;
static unsigned int show_unverified = 1, ignore_rc, force_fuzz;
static int warn_wpaclean;
static int warn_snaplen;
static int verbosity;
static char filter_mac[18];
static int filter_hit;
static int output_dupes;
static int opt_e_used;
static uint32_t orig_len, snap_len;

static const char cpItoa64[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t l3mcast[3] = { 0x01, 0x00, 0x5e };

/*
 * Fake 802.11 header. We use this when indata is Ethernet (not monitor mode)
 * in order to fake a packet we can process
 */
static uint8_t fake802_11[] = {
	0x88, 0x02, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x06, 0x00, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00
};

/* Type 0 subtypes, for -vv display */
static const char* const ctl_subtype[16] = {
	"Association request", "Association response", "Reassociation request",
	"Reassociation response", "Probe request", "Probe response",
	"Subtype 6", "Subtype 7", "Beacon", "ATIM", "Disassociation",
	"Authentication", "Deauthentication", "Action", "Action no ack",
	"Subtype 15"
};

#if HAVE___MINGW_ALIGNED_MALLOC
char *strdup_MSVC(const char *str)
{
	char * s;
	s = (char*)__mingw_aligned_malloc(strlen(str)+1, (sizeof(long long)));
	if (s != NULL)
		strcpy(s, str);
	return s;
}
#endif

/*
 * This function output data properly for JtR, in base-64 format.
 * Original taken from hccap2john.c source, modified for this project.
 */
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

static char *to_mac_str(void *ptr)
{
	static int rr;
	static char out[4][18];
	uint8_t *p = ptr;

	if (ptr == NULL)
		return "                 ";

	sprintf(out[rr & 3], "%02X:%02X:%02X:%02X:%02X:%02X",
	        p[0],p[1],p[2],p[3],p[4],p[5]);
	return out[rr++ & 3];
}

static char *to_hex(void *ptr, int len)
{
	static int rr;
	static char out[8][64];
	uint8_t *p = ptr;
	char *o = out[rr & 7];

	while (len--) {
		int ret = sprintf(o, "%02x", *p++);

		if (ret < 0)
			fprintf(stderr, "Error!");
		else
			o += ret;
	}

	return out[rr++ & 7];
}

static int get_essid_num(uint8_t *bssid)
{
	int i;

	for (i = n_essid - 1; i >= 0; --i)
		if (!memcmp(bssid, essid_db[i].bssid, 6))
			return i;
	return -1;
}

static char *get_essid(uint8_t *bssid)
{
	int ess = get_essid_num(bssid);

	if (ess < 0) {
		if (verbosity)
			fprintf(stderr, "ESSID for %s not found\n", to_mac_str(bssid));
		return "[NOTFOUND]";
	}

	if (essid_db[ess].essid_len == 0)
		return to_mac_str(essid_db[ess].bssid);
	else
		return essid_db[ess].essid;
}

/*
 * Dynamically allocate more memory for input data.
 * Make sure newly allocated memory is initialized with zeros.
 */
static void allocate_more_essid(void)
{
	size_t old_max = max_essid;

	max_essid *= 2;
	safe_realloc(essid_db, sizeof(essid_t) * max_essid);
	memset(essid_db + old_max, 0, sizeof(essid_t) * old_max);
}

static void allocate_more_state(void)
{
	size_t old_max = max_state;

	max_state *= 2;
	safe_realloc(apsta_db, sizeof(WPA4way_t) * max_state);
	memset(apsta_db + old_max, 0, sizeof(WPA4way_t) * old_max);
}

/* Convert WPA handshakes from aircrack-ng (airodump-ng) IVS2 to JtR format */
static int convert_ivs2(FILE *f_in)
{
	static char LastKey[2048];
	char NewKey[2048];
	char *cp = NewKey;
	struct ivs2_filehdr fivs2;
	struct ivs2_pkthdr ivs2;
	struct ivs2_WPA_hdsk *wivs2;
	hccap_t hccap;
	uint8_t *ivs_buf;
	int i;
	size_t length, pos;
	unsigned int pktlen;
	unsigned char bssid[6];
	int bssidFound = 0;
	char essid[32 + 1];
	unsigned char *p, *w;
	int ess = -1;

	fseek(f_in, 0, SEEK_END);
	length = ftell(f_in);
	fseek(f_in, 0, SEEK_SET);

	safe_malloc(ivs_buf, length);

	if (fread(ivs_buf, 1, 4, f_in) != 4) {
		fprintf(stderr, "%s: fread file header failed\n", filename);
		MEM_FREE(ivs_buf);
		return 1;
	}

	if (memcmp(ivs_buf, IVSONLY_MAGIC, 4) == 0) {
		fprintf(stderr, "%s: old version .ivs file, only WEP handshakes.\n",
		        filename);
		MEM_FREE(ivs_buf);
		return 1;
	}

	if (memcmp(ivs_buf, IVS2_MAGIC, 4) != 0) {
		MEM_FREE(ivs_buf);
		return 1;
	}

	if (fread(&fivs2, 1, sizeof(struct ivs2_filehdr), f_in) !=
	    (size_t) sizeof(struct ivs2_filehdr)) {
		fprintf(stderr, "%s: fread ivs2 file header failed", filename);
		MEM_FREE(ivs_buf);
		return 1;
	}

	if (fivs2.version > IVS2_VERSION) {
		fprintf(stderr,
		        "%s: wrong %s version: %d. Supported up to version %d.\n",
		        filename, IVS2_EXTENSION, fivs2.version, IVS2_VERSION);
		MEM_FREE(ivs_buf);
		return 1;
	}

	if (verbosity)
		fprintf(stderr, "\n");
	fprintf(stderr, "File %s: airodump-ng 'ivs' file (v2)\n", filename);

	pos = ftell(f_in);

	while (pos < length) {
		if (fread(&ivs2, 1, sizeof(struct ivs2_pkthdr), f_in) !=
		    sizeof(struct ivs2_pkthdr)) {
			fprintf(stderr,
			        "%s: Error reading ivs2 header at pos "Zu" of "Zu"\n",
			        filename, pos, length);
			MEM_FREE(ivs_buf);
			return 1;
		}

		pos +=  sizeof(struct ivs2_pkthdr);

		pktlen = (unsigned int)ivs2.len;
		if (pktlen+pos > length) {
			fprintf(stderr, "%s: Invalid ivs2 packet length %u at "Zu"\n",
			        filename, pktlen, pos-sizeof(struct ivs2_pkthdr));
			MEM_FREE(ivs_buf);
			return 1;
		}

		if (fread(ivs_buf, 1, pktlen, f_in) != pktlen) {
			fprintf(stderr,
			        "%s: Error reading ivs2 data (%u) at pos "Zu" of "Zu"\n",
			        filename, pktlen, pos, length);
			MEM_FREE(ivs_buf);
			return 1;
		}

		p = ivs_buf;
		if (ivs2.flags & IVS2_BSSID) {
			memcpy(bssid, p, 6);
			p += 6;

			if (verbosity >= 2)
				fprintf(stderr, "ivs2 BSSID: %s\n", to_mac_str(bssid));
			bssidFound = 1;
		}
		if (ivs2.flags & IVS2_ESSID) {
			unsigned int ofs = (p - ivs_buf);
			unsigned int len = pktlen - ofs;

			if (len <= 0 || len > 32) {
				fprintf(stderr, "ivs2 Invalid ESSID length (%d)\n", len);
				continue;
			}

			memcpy(essid, p, len);
			essid[len] = 0;

			if (verbosity >= 2)
				fprintf(stderr,"ivs2 ESSID: '%s' (%d bytes)\n", essid, len);
			p += len;

			/* Check if already in ESSID db */
			for (i = n_essid - 1; i >= 0; --i) {
				if (!memcmp(bssid, essid_db[i].bssid, 6) &&
				    !memcmp(essid, essid_db[i].essid, essid_db[i].essid_len)) {
					ess = i;

					break;
				} else if (!memcmp(bssid, essid_db[i].bssid, 6)) {
					if (verbosity >= 2)
						fprintf(stderr, "ivs2 '%s' at %s (renamed, old '%s')\n",
						        essid, to_mac_str(essid_db[i].bssid),
						        essid_db[i].essid);
					memcpy(essid_db[i].essid, essid, len);
					essid_db[i].essid[len] = 0;
					essid_db[i].essid_len = len;
					ess = i;
					break;
				}
			}

			/* New entry in db */
			if (ess < 0) {
				ess = n_essid;
				essid_db[n_essid].prio = 5;
				memcpy(essid_db[n_essid].essid, essid, len);
				essid_db[n_essid].essid[len] = 0;
				memcpy(essid_db[n_essid].bssid, bssid, 6);

				fprintf(stderr, "ivs2 '%s' at %s\n", essid, to_mac_str(bssid));

				if (++n_essid >= max_state)
					allocate_more_state();
			}
		} else if (bssidFound && ess < 0)
			/* Check if already in db */
			ess = get_essid_num(bssid);

		if (ivs2.flags & IVS2_WPA) {
			int ofs = (p - ivs_buf);
			int len = pktlen - ofs;
			char buf[8];
			char anonce[9];
			char snonce[9];

			if (len != sizeof(struct ivs2_WPA_hdsk)) {
				fprintf(stderr, "%s: Invalid WPA handshake length (%d vs %d)\n",
				        filename, len, (int)sizeof(struct ivs2_WPA_hdsk));
				continue;
			}

			if (!bssidFound) {
				fprintf(stderr,
				        "%s: Got WPA handshake but we don't have BSSID\n",
				        filename);
				continue;
			}

			if (ess < 0) {
				fprintf(stderr,
				        "%s: WPA handshake for %s but we don't have ESSID%s\n",
				        filename, to_mac_str(bssid),
				        opt_e_used ? "" : " (perhaps -e option needed?)");
				continue;
			}

			wivs2 = (struct ivs2_WPA_hdsk*)p;

			memset(&hccap, 0, sizeof(hccap_t));
			hccap.keyver = wivs2->keyver;

			memcpy(hccap.mac1, bssid, 6);
			memcpy(hccap.mac2, wivs2->stmac, 6);

			memcpy(hccap.nonce1, wivs2->snonce, 32);
			memcpy(hccap.nonce2, wivs2->anonce, 32);
			memcpy(hccap.keymic, wivs2->keymic, 16);
			hccap.eapol_size = wivs2->eapol_size;

			if (hccap.eapol_size > sizeof(((hccap_t*)(NULL))->eapol)) {
				fprintf(stderr,
				        "%s: eapol size %u (too large), skipping packet\n",
				        filename, hccap.eapol_size);
				continue;
			}
			if (hccap.eapol_size < 91) {
				fprintf(stderr,
				        "%s: eapol size %u (too small), skipping packet\n",
				        filename, hccap.eapol_size);
				continue;
			}
			memcpy(hccap.eapol, wivs2->eapol, wivs2->eapol_size);

			/*
			 * These fields are duplicated in the hccap. We clear one of
			 * them in order to be compatible with hcxtools
			 */
			//memset(hccap.eapol + offsetof(ieee802_1x_eapol_t, wpa_nonce), 0,
			//       sizeof(hccap.nonce1));
			memset(hccap.eapol + offsetof(ieee802_1x_eapol_t, wpa_keymic), 0,
			       sizeof(hccap.keymic));

			sprintf(anonce, "%02x%02x%02x%02x", wivs2->anonce[28],
			        wivs2->anonce[29], wivs2->anonce[30], wivs2->anonce[31]);
			sprintf(snonce, "%02x%02x%02x%02x", wivs2->snonce[28],
			        wivs2->snonce[29], wivs2->snonce[30], wivs2->snonce[31]);

			if (verbosity >= 2) {
				fprintf(stderr,
				        "%s -> %s ivs2 WPA handshake ESSID '%s' anonce %s snonce %s state=%d keyver=%d eapolSize=%d%s%s\n",
				        to_mac_str(hccap.mac2), to_mac_str(hccap.mac1), essid,
				        anonce, snonce, wivs2->state, wivs2->keyver,
				        wivs2->eapol_size, hccap.keyver == 3 ?
				        " [AES-128-CMAC]" : "",
				        (apsta_db[ess].handshake_done) ?
				        " (4-way already seen)" : "");
			}
			if (output_dupes || !apsta_db[ess].handshake_done) {
				cp = NewKey;
				cp += sprintf(cp, "%s:$WPAPSK$%s#", essid, essid);

				/* print struct in base64 format */
				w = (unsigned char*)&hccap;
				for (i=36; i+3 < sizeof(hccap_t); i += 3) {
					code_block(&w[i], 1, buf);
					cp += sprintf(cp, "%s", buf);
				}
				code_block(&w[i], 0, buf);
				cp += sprintf(cp, "%s", buf);
				cp += sprintf(cp, ":%s:%s:%s::WPA", to_hex(hccap.mac2, 6),
				              to_hex(hccap.mac1, 6),
				              to_hex(hccap.mac1, 6));
				if (hccap.keyver > 1)
					cp += sprintf(cp, "2");
				if (hccap.keyver > 2)
					cp += sprintf(cp, " CMAC");
				if (hccap.keyver > 3)
					cp += sprintf(cp, ", ver %d", hccap.keyver);
				cp += sprintf(cp, ":%s", filename);
				if (strcmp(LastKey, NewKey)) {
					puts(NewKey);
					fflush(stdout);
					strcpy(LastKey, NewKey);
					n_handshakes++;
				}
				/* State seems unreliable
				if (wivs2->state == 7)
					apsta_db[ess].handshake_done = 1;
				*/
			}

			p += len;
		}

		if (p < ivs_buf+pktlen) {
			fprintf(stderr,
			        "%s: Unable to parse all data, unsupported flag? (%02x)\n",
			        filename, (int)ivs2.flags);
		}

		pos += pktlen;
	}

	MEM_FREE(ivs_buf);
	return 0;
}

static void remove_handshake(int apsta, int handshake)
{
	MEM_FREE(apsta_db[apsta].M[handshake].eapol);
	apsta_db[apsta].M[handshake].eapol_size = 0;
	apsta_db[apsta].M[handshake].ts64 = 0;
	return;
}

static void print_auth(int apsta, int ap_msg, int sta_msg,
                       hccap_t hccap, int fuzz, int be)
{
	int i;
	char TmpKey[2048], *cp = TmpKey;
	uint8_t *w = (uint8_t *)&hccap;
	int32_t *anonce_lsb = (int32_t*)&hccap.nonce2[28];
	int latest = sta_msg;

	if (fuzz) {
		//fprintf(stderr, "anonce ...%08x -> ", (uint32_t)*anonce_lsb);
		if (be == 1)
			*anonce_lsb =
				swap32u((uint32_t)(
					        (int32_t)swap32u((uint32_t)*anonce_lsb) + fuzz)
					);
		else /* LE */
			*anonce_lsb += fuzz;
		//fprintf(stderr, "%08x\n", (uint32_t)*anonce_lsb);
	}

	cp += sprintf(cp, "%s:$WPAPSK$%s#", get_essid(apsta_db[apsta].bssid),
	              get_essid(apsta_db[apsta].bssid));

	for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
		cp += code_block(&w[i], 1, cp);
	cp += code_block(&w[i], 0, cp);

	cp += sprintf(cp, ":%s:%s:%s::WPA", to_hex(hccap.mac2, 6),
	              to_hex(hccap.mac1, 6), to_hex(hccap.mac1, 6));
	if (hccap.keyver > 1)
		cp += sprintf(cp, "2");
	if (hccap.keyver > 2)
		cp += sprintf(cp, " CMAC");
	if (hccap.keyver > 3)
		cp += sprintf(cp, ", ver %d", hccap.keyver);
	cp += sprintf(cp, ", %sverified",
	              (ap_msg == 1 && sta_msg == 2) ? "not " : "");
	if (fuzz)
		cp += sprintf(cp, ", fuzz %d %s", fuzz, (be == 1) ? "BE" : "LE");
	cp += sprintf(cp, ":%s", filename);

	if (apsta_db[apsta].M[ap_msg].ts64 > apsta_db[apsta].M[sta_msg].ts64)
		latest = ap_msg;
	if (!fuzz)
		fprintf(stderr,
		        "Dumping M%u/M%u at %u.%06u BSSID %s ESSID '%s' STA %s\n",
		        ap_msg, sta_msg,
		        (uint32_t)(apsta_db[apsta].M[latest].ts64 / 1000000),
		        (uint32_t)(apsta_db[apsta].M[latest].ts64 % 1000000),
		        to_mac_str(apsta_db[apsta].bssid),
		        get_essid(apsta_db[apsta].bssid),
		        to_mac_str(apsta_db[apsta].staid));
	printf("%s\n", TmpKey);
	fflush(stdout);
	n_handshakes++;
}

/*
 * We pick anonce from M1 or M3. Everything else should be from M2, or
 * possibly from M4 unless it's zeroed out. In a pinch we can allegedly
 * use EAPOL from M3 but then nonce fuzzing is impossible.
 *
 * hccapx "message pair value"
 * val  msgs   EAPOL  fuzzing possible  rc match  used here
 *   0  M1/M2   M2      yes               yes       yes
 *   1  M1/M4   M4      yes               yes       yes
 *   2  M2/M3   M2      yes               yes       yes
 *   3  M2/M3   M3      no                yes       no
 *   4  M3/M4   M3      no                yes       no
 *   5  M3/M4   M4      yes               yes       yes
 * 128  M1/M2   M2      yes               no        yes*
 * 129  M1/M4   M4      yes               no        yes*
 * 130  M2/M3   M2      yes               no        yes*
 * 131  M2/M3   M3      no                no        no
 * 132  M3/M4   M3      no                no        no
 * 133  M3/M4   M4      yes               no        yes*
 */
static void dump_auth(int apsta, int ap_msg, int sta_msg, int force)
{
	int i, j;
	ieee802_1x_eapol_t *auth13 = apsta_db[apsta].M[ap_msg].eapol;
	ieee802_1x_eapol_t *auth24 = apsta_db[apsta].M[sta_msg].eapol;
	hccap_t	hccap;
	int this_fuzz = 0;
	int endian = apsta_db[apsta].endian;
	int fuzz = apsta_db[apsta].fuzz;
	int have_pmkid = !(ap_msg || sta_msg);

	if (have_pmkid)
		apsta_db[apsta].pmkid_done = 1;

	if (essid_db[get_essid_num(apsta_db[apsta].bssid)].essid_len == 0) {
		if (essid_db[get_essid_num(apsta_db[apsta].bssid)].prio == 6) {
			fprintf(stderr,
			        "%s: %s for %s but we don't have ESSID yet%s\n",
			        filename, have_pmkid ? "RSN IE PMKID" : "WPA handshake",
			        to_mac_str(apsta_db[apsta].bssid),
			        opt_e_used ? "" : " (perhaps -e option needed?)");
			essid_db[get_essid_num(apsta_db[apsta].bssid)].prio = 10;
		}
		return;
	}
	if (ignore_rc && fuzz) {
		if ((ap_msg == 1 && sta_msg == 2) || (ap_msg == 3 && sta_msg == 4))
			this_fuzz = apsta_db[apsta].M[sta_msg].eapol->replay_cnt -
				apsta_db[apsta].M[sta_msg].eapol->replay_cnt;
		else
			this_fuzz = MAX(apsta_db[apsta].M[ap_msg].eapol->replay_cnt, apsta_db[apsta].M[sta_msg].eapol->replay_cnt) - MIN(apsta_db[apsta].M[ap_msg].eapol->replay_cnt, apsta_db[apsta].M[sta_msg].eapol->replay_cnt) - 1;
	}
	this_fuzz = MAX(MAX(ABS(force_fuzz), ABS(this_fuzz)), fuzz);

	if (fuzz < 0)
		this_fuzz = 0 - this_fuzz;

	if (verbosity && this_fuzz)
		fprintf(stderr, "Outputting with fuzz: %d (%d seen) %s\n",
		        this_fuzz, fuzz,
		        endian ? (endian == 1 ? "BE" : "LE") : "LE/BE");

	if (have_pmkid) {
		char *essid = get_essid(apsta_db[apsta].bssid);

		fprintf(stderr,
		        "Dumping RSN IE PMKID at %u.%06u BSSID %s ESSID '%s' STA %s\n",
		        (uint32_t)(apsta_db[apsta].M[0].ts64 / 1000000),
		        (uint32_t)(apsta_db[apsta].M[0].ts64 % 1000000),
		        to_mac_str(apsta_db[apsta].bssid),
		        get_essid(apsta_db[apsta].bssid),
		        to_mac_str(apsta_db[apsta].staid));
		printf("%s:%s*%s*%s*%s:%s:%s:%s::PMKID:%s\n",
		       essid,
		       to_hex(apsta_db[apsta].M[0].eapol, 16),
		       to_hex(apsta_db[apsta].bssid, 6),
		       to_hex(apsta_db[apsta].staid, 6),
		       to_hex(essid, strlen(essid)),
		       to_hex(apsta_db[apsta].staid, 6), // uid
		       to_hex(apsta_db[apsta].bssid, 6), // gid
		       to_hex(apsta_db[apsta].bssid, 6), // gecos
		       filename);
		fflush(stdout);

		n_pmkids++;
		remove_handshake(apsta, 0);
		return;
	}

	if (!auth24) {
		fprintf(stderr, "ERROR, M%u null\n", sta_msg);
		return;
	}

	if (!auth13) {
		fprintf(stderr, "ERROR, M%u null\n", ap_msg);
		return;
	}

	memset(&hccap, 0, sizeof(hccap_t));
	hccap.keyver = auth24->key_info.KeyDescr;
	memcpy(hccap.mac1, apsta_db[apsta].bssid, 6);
	memcpy(hccap.mac2, apsta_db[apsta].staid, 6);
	memcpy(hccap.nonce1, auth24->wpa_nonce, 32);
	memcpy(hccap.nonce2, auth13->wpa_nonce, 32);
	memcpy(hccap.keymic, auth24->wpa_keymic, 16);

#if ARCH_LITTLE_ENDIAN
	/* Endian-swap stuff back before storage */
	auth24->length = swap16u(auth24->length);
	auth24->key_info_u16 = swap16u(auth24->key_info_u16);
	auth24->key_len  = swap16u(auth24->key_len);
	auth24->replay_cnt  = swap64u(auth24->replay_cnt);
	auth24->wpa_keydatlen  = swap16u(auth24->wpa_keydatlen);
#endif

	hccap.eapol_size = apsta_db[apsta].M[sta_msg].eapol_size;
	memcpy(hccap.eapol, auth24, hccap.eapol_size);

	/*
	 * These fields are duplicated in the hccap. We clear one of
	 * them in order to be compatible with hcxtools
	 */
	//memset(hccap.eapol + offsetof(ieee802_1x_eapol_t, wpa_nonce), 0,
	//       sizeof(hccap.nonce1));
	memset(hccap.eapol + offsetof(ieee802_1x_eapol_t, wpa_keymic), 0,
	       sizeof(hccap.keymic));

	/* Non-fuzzed first */
	print_auth(apsta, ap_msg, sta_msg, hccap, 0, 0);

	/* If endianness unknown, we fuzz LE and BE */
	for (j = (endian ? endian : 1); j <= (endian ? endian : 2); j++) {
		/* Fuzz negative */
		if (fuzz < 0 || force_fuzz)
			for (i = -1; i >= (0 - this_fuzz); i--)
				print_auth(apsta, ap_msg, sta_msg, hccap, i, j);

		/* Fuzz positive */
		if (fuzz > 0 || force_fuzz)
			for (i = 1; i <= this_fuzz; i++)
				print_auth(apsta, ap_msg, sta_msg, hccap, i, j);
	}

	if (MAX(ap_msg, sta_msg) > 2 || force) {
		apsta_db[apsta].handshake_done = 1;
		remove_handshake(apsta, 1);
		remove_handshake(apsta, 2);
		remove_handshake(apsta, 3);
		remove_handshake(apsta, 4);
	}
}

static void dump_late() {
	int printed = 0;
	int i;

	for (i = 0; i < n_apsta; i++)
		if (apsta_db[i].M[0].eapol)
			dump_auth(i, 0, 0, 1);

	for (i = 0; i < n_apsta; i++) {
		int ap_msg = 0, sta_msg = 0;

		if (apsta_db[i].M[1].eapol)
			ap_msg = 1;
		if (apsta_db[i].M[2].eapol)
			sta_msg = 2;
		if (apsta_db[i].M[3].eapol)
			ap_msg = 3;
		if (apsta_db[i].M[4].eapol)
			sta_msg = 4;

		if (ap_msg && sta_msg) {
			if (verbosity && !printed++)
				fprintf(stderr, "Dumping unverified and/or post-poned data\n");
			dump_auth(i, ap_msg, sta_msg, show_unverified);
		}
	}
}

static void learn_essid(uint16_t subtype, int has_ht, uint8_t *bssid)
{
	ieee802_1x_frame_hdr_t *pkt = (ieee802_1x_frame_hdr_t*)packet;
	ieee802_1x_beacon_tag_t *tag;
	uint8_t *pFinal = &packet[snap_len];
	char essid[32 + 1];
	int essid_len = 0;
	int prio = 0;
	int i;

	if (subtype == 8 || subtype == 5) { /* beacon or probe response */
		ieee802_1x_beacon_data_t *pDat = (ieee802_1x_beacon_data_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		tag = pDat->tags;
		prio = (subtype == 8 ? 5 : 3);
	} else if (subtype == 4) { /* probe request */
		tag = (ieee802_1x_beacon_tag_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		prio = 4;
	} else if (subtype == 0) { /* association request */
		ieee802_1x_assocreq_t *pDat = (ieee802_1x_assocreq_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		tag = pDat->tags;
		prio = 2;
	} else if (subtype == 2) { /* re-association request */
		ieee802_1x_reassocreq_t *pDat = (ieee802_1x_reassocreq_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		tag = pDat->tags;
		prio = 1;
	} else if (subtype == 11) {
		ieee802_1x_auth_t *p = (ieee802_1x_auth_t*)&packet[sizeof(ieee802_1x_frame_hdr_t) + (has_ht ? 4 : 0)];
		if (verbosity >= 2 && filter_hit) {
			if (p->algo == 0)
				fprintf(stderr, "WPA authentication, status %04x\n", p->status);
			else if (p->algo == 1)
				fprintf(stderr, "WEP authentication, status %04x\n", p->status);
			else
				fprintf(stderr, "Authentication %04x, status %04x\n",
				        p->algo, p->status);
		}
		return;
	} else {
		if (verbosity >= 2 && filter_hit)
			fprintf(stderr, "%s\n", ctl_subtype[subtype]);
		return;
	}

/*
 * addr1 (dst) should be broadcast for beacon, unicast for probe response
 * addr2 (src) is source addr (should be same as BSSID for beacons)
 * addr3 is BSSID (routers MAC)
 *
 * Walk the tags (actually tag 0 allegedly always come first, but WTH)
 */
	while (((uint8_t*)tag) < pFinal) {
		char *x = (char*)tag;
		if (x + 2 > (char*)pFinal || x + 2 + tag->taglen > (char*)pFinal)
			break;
		if (tag->tagtype == 0) {
			if (tag->taglen == 0 || tag->taglen > 32) {
				if (!filter_hit || !verbosity)
					return;
				fprintf(stderr, "%s %s ESSID", ctl_subtype[subtype],
				        tag->taglen ? "with invalid length" : "for any");
				if (memcmp(pkt->addr1, pkt->addr3, 6))
					fprintf(stderr, " (BSSID %s)\n", to_mac_str(bssid));
				else
					fprintf(stderr, "\n");
				return;
			}
			essid_len = tag->taglen;
			memcpy(essid, tag->tag, essid_len + 1);
			essid[essid_len] = 0;
			break;
		}
		x += tag->taglen + 2;
		tag = (ieee802_1x_beacon_tag_t *)x;
	}
	if (strlen(essid) == 0) {
		if (verbosity >= 2 && filter_hit)
			fprintf(stderr, "%s with ESSID length 0\n", ctl_subtype[subtype]);
		return;
	}
	if (pkt->addr3 + 6 > pFinal) {
		if (verbosity >= 2 && filter_hit)
			fprintf(stderr, "%s with malformed data\n", ctl_subtype[subtype]);
		return;
	}

	if (!memcmp(pkt->addr3, bcast, 6)) {
		if (verbosity >= 2 && filter_hit)
			fprintf(stderr, "Broadcast %s '%s'\n",
			        ctl_subtype[subtype], essid);
		return;
	}

	if (verbosity >= 2 && filter_hit && !memcmp(l3mcast, pkt->addr3, 3))
		fprintf(stderr, "[IPv4 mcast BSSID] ");
	else if (verbosity >= 2 && filter_hit && (pkt->addr3[0] & 0x03) == 0x03)
		fprintf(stderr, "[LA mcast BSSID] ");
	else if (verbosity >= 2 && filter_hit && pkt->addr3[0] & 0x01)
		fprintf(stderr, "[mcast BSSID] ");
	else if (verbosity >= 2 && filter_hit && pkt->addr3[0] & 0x02)
		fprintf(stderr, "[LA BSSID] ");

	/* Check if already in db, or older entry has worse prio */
	for (i = n_essid - 1; i >= 0; --i) {
		if (!memcmp(bssid, essid_db[i].bssid, 6) &&
		    essid_db[i].prio > 5) {
			essid_db[i].essid_len = essid_len;
			memcpy(essid_db[i].essid, essid, essid_len);
			essid_db[i].essid[essid_len] = 0;
			if (verbosity && filter_hit)
				fprintf(stderr, "%s '%s' at %s (name found, prio %d -> %d)\n",
				        ctl_subtype[subtype], essid_db[i].essid,
				        to_mac_str(essid_db[i].bssid),
				        essid_db[i].prio, prio);
			essid_db[i].prio = prio;
			return;
		} else if (!memcmp(bssid, essid_db[i].bssid, 6) &&
		    essid_len == essid_db[i].essid_len &&
		    !memcmp(essid, essid_db[i].essid, essid_len)) {
			if (essid_db[i].prio > prio) {
				if (verbosity && filter_hit)
					fprintf(stderr, "%s '%s' at %s (prio %d -> %d)\n",
					        ctl_subtype[subtype], essid_db[i].essid,
					        to_mac_str(essid_db[i].bssid),
					        essid_db[i].prio, prio);
				essid_db[i].prio = prio;
			} else {
				if (verbosity && filter_hit)
					fprintf(stderr, "%s '%s' at %s\n", ctl_subtype[subtype],
					        essid_db[i].essid, to_mac_str(essid_db[i].bssid));
			}
			return;
		} else if (!memcmp(bssid, essid_db[i].bssid, 6)) {
			if (essid_db[i].prio >= prio) {
				if (verbosity && filter_hit)
					fprintf(stderr,
					        "%s '%s' at %s (renamed, old '%s' prio %d, new prio %d)\n",
					        ctl_subtype[subtype], essid,
					        to_mac_str(essid_db[i].bssid), essid_db[i].essid,
					        essid_db[i].prio, prio);
				break;
			}
		}
	}

	essid_db[n_essid].prio = prio;
	essid_db[n_essid].essid_len = essid_len;
	memcpy(essid_db[n_essid].essid, essid, essid_len);
	essid_db[n_essid].essid[essid_len] = 0;
	memcpy(essid_db[n_essid].bssid, bssid, 6);

	if (verbosity && filter_hit)
		fprintf(stderr, "%s '%s' at %s\n",
		        ctl_subtype[subtype], essid, to_mac_str(bssid));

	if (++n_essid >= max_essid)
		allocate_more_essid();
}

static int is_zero(void *ptr, size_t len)
{
	unsigned char *p = ptr;

	while (len--)
		if (*p++)
			return 0;
	return 1;
}

static void handle4way(ieee802_1x_eapol_t *auth, uint8_t *bssid)
{
	uint8_t *end = packet + snap_len;
	int i;
	int apsta = -1, ess = -1;
	int msg = 0;
	uint8_t *staid;
	uint32_t nonce_msb; /* First 32 bits of nonce */
	uint32_t nonce_lsb; /* Last 32 bits of nonce */
	uint64_t rc;
	int eapol_sz;

	if ((uint8_t*)auth + sizeof(ieee802_1x_eapol_t) > end) {
		if (verbosity >= 2)
			fprintf(stderr, "EAPOL truncated?\n");
		return;
	}

	if (auth->length == 0) {
		if (verbosity >= 2)
			fprintf(stderr, "Zero length\n");
		return;
	}

#if ARCH_LITTLE_ENDIAN
	/* Swap things from network order */
	auth->length = swap16u(auth->length);
	auth->key_info_u16 = swap16u(auth->key_info_u16);
	auth->key_len  = swap16u(auth->key_len);
	auth->replay_cnt  = swap64u(auth->replay_cnt);
	auth->wpa_keydatlen  = swap16u(auth->wpa_keydatlen);
#endif

	nonce_msb = (uint32_t)auth->wpa_nonce[0] << 24 |
		(uint32_t)auth->wpa_nonce[1] << 16 |
		(uint32_t)auth->wpa_nonce[2] << 8 |
		auth->wpa_nonce[3];
	nonce_lsb = (uint32_t)auth->wpa_nonce[28] << 24 |
		(uint32_t)auth->wpa_nonce[29] << 16 |
		(uint32_t)auth->wpa_nonce[30] << 8 |
		auth->wpa_nonce[31];
	rc = auth->replay_cnt;

	if (verbosity >= 3) {
		fprintf(stderr,
		        "EAPOL breakdown:\n"
		        "\tver %02x type %02x length %d key_descr %02x",
		        auth->ver, auth->type, auth->length, auth->key_descr);
		fprintf(stderr, " key_info %d %d %d %d %d %d %d %d %d\n",
		        auth->key_info.KeyDescr, auth->key_info.KeyType,
		        auth->key_info.KeyIdx, auth->key_info.Install,
		        auth->key_info.KeyACK,
		        auth->key_info.Secure, auth->key_info.Error,
		        auth->key_info.Reqst, auth->key_info.EncKeyDat);
		fprintf(stderr, "\tkey_len %d replay_cnt %"PRIu64"\n",
		        auth->key_len, auth->replay_cnt);
		dump_hex("\tnonce", auth->wpa_nonce, sizeof(auth->wpa_nonce));
		dump_hex("\tkeyiv", auth->wpa_keyiv, sizeof(auth->wpa_keyiv));
		dump_hex("\tkeyrsc", auth->wpa_keyrsc, sizeof(auth->wpa_keyrsc));
		dump_hex("\tkeyid", auth->wpa_keyid, sizeof(auth->wpa_keyid));
		if (auth->key_info.KeyMIC || !is_zero(auth->wpa_keymic,
		                                      sizeof(auth->wpa_keymic)))
			dump_hex("\tmic", auth->wpa_keymic, sizeof(auth->wpa_keymic));
		fprintf(stderr, "\tkeydatlen %d  ", auth->wpa_keydatlen);
	}

	if (!auth->key_info.KeyACK) {
		staid = packet_TA;
		if (auth->key_info.Secure || auth->wpa_keydatlen == 0) {
			msg = 4;
		} else {
			msg = 2;
		}
	} else {
		staid = packet_RA;
		if (auth->key_info.Install) {
			msg = 3;
		} else {
			msg = 1;
		}
	}


	/* Find the ESSID in our db. */
	ess = get_essid_num(bssid);
	if (ess == -1) {
		ess = n_essid;
		essid_db[ess].prio = 6;
		essid_db[ess].essid_len = 0;
		essid_db[ess].essid[0] = 0;
		memcpy(essid_db[ess].bssid, bssid, 6);

		if (++n_essid >= max_essid)
			allocate_more_essid();
	}

	/* Find the AP/STA pair in our db. */
	for (i = n_apsta - 1; i >= 0; --i) {
		if (!memcmp(bssid, apsta_db[i].bssid, 6) &&
		    !memcmp(staid, apsta_db[i].staid, 6) &&
		    MAX(rc, apsta_db[i].rc) - MIN(rc, apsta_db[i].rc) <= 64) {
			apsta = i;
			break;
		}
	}
	if (apsta == -1) {
		apsta = n_apsta++;
		memcpy(apsta_db[apsta].bssid, bssid, 6);
		memcpy(apsta_db[apsta].staid, staid, 6);
		if (n_apsta >= max_state)
			allocate_more_state();
	}
	apsta_db[apsta].rc = rc;

	if (auth->wpa_keydatlen == 22) {
		keydata_t *keydata = ((eapol_keydata_t*)auth)->tag;

		if ((keydata->tagtype == 0xdd || keydata->tagtype == 0x14) &&
		    !memcmp(keydata->oui, "\x00\x0f\xac", 3) &&
		    keydata->oui_type == 0x04) {
			if (is_zero(keydata->data, 16)) {
				if (verbosity >= 2)
					fprintf(stderr, "RSN IE w/ all-zero PMKID\n");
			} else {
				if (verbosity >= 3)
					dump_hex("RSN IE PMKID", keydata->data, 16);
				if (apsta_db[apsta].pmkid_done) {
					if (verbosity >= 2)
						fprintf(stderr, "RSN IE PMKID (already seen)\n");
				} else if (!apsta_db[apsta].M[0].eapol) {
					/* PMKID is better than a handshake! */
					apsta_db[apsta].M[0].eapol_size = 16;
					apsta_db[apsta].M[0].ts64 = cur_ts64;
					safe_malloc(apsta_db[apsta].M[0].eapol, 16);
					memcpy(apsta_db[apsta].M[0].eapol, keydata->data, 16);
					if (verbosity >= 2)
						fprintf(stderr, "RSN IE PMKID\n");
					dump_auth(apsta, 0, 0, 0);
				}
			}
			return;
		}
	}

	if (msg == 1 || msg == 3) {
		if (nonce_msb == apsta_db[apsta].anonce_msb &&
		    nonce_lsb != apsta_db[apsta].anonce_lsb) {
			int8_t fuzz = apsta_db[apsta].fuzz;
			if ((nonce_lsb & 0x00ffffff) ==
			    (apsta_db[apsta].anonce_lsb & 0x00ffffff)) {
				uint32_t nonce1 = swap32u(apsta_db[apsta].anonce_lsb);
				uint32_t nonce2 = swap32u(nonce_lsb);

				if (nonce2 < nonce1)
					apsta_db[apsta].fuzz = MIN(fuzz, (int8_t)(nonce2 - nonce1));
				else if (nonce2 - nonce1 > 1)
					apsta_db[apsta].fuzz = MAX(fuzz, (int8_t)(nonce2 - nonce1));
				if (apsta_db[apsta].fuzz && verbosity >= 2)
					fprintf(stderr, "anonce LSB inc fuzz %d LE ",
					        apsta_db[apsta].fuzz);
				apsta_db[apsta].endian = 2;
			}
			else if ((nonce_lsb & 0xffffff00) ==
			         (apsta_db[apsta].anonce_lsb & 0xffffff00)) {
				uint32_t nonce1 = apsta_db[apsta].anonce_lsb;
				uint32_t nonce2 = nonce_lsb;

				if (nonce2 < nonce1)
					apsta_db[apsta].fuzz = MIN(fuzz, (int8_t)(nonce2 - nonce1));
				else if (nonce2 - nonce1 > 1)
					apsta_db[apsta].fuzz = MAX(fuzz, (int8_t)(nonce2 - nonce1));
				if (apsta_db[apsta].fuzz && verbosity >= 2)
					fprintf(stderr, "anonce LSB inc fuzz %d BE ",
					        apsta_db[apsta].fuzz);
				apsta_db[apsta].endian = 1;
			}
		}
		apsta_db[apsta].anonce_msb = nonce_msb;
		apsta_db[apsta].anonce_lsb = nonce_lsb;
	}

	if (msg > 1) {
		int i;

		for (i = msg - 1; i > 0; i--) {
			int stp = msg - i;

			if (apsta_db[apsta].M[i].eapol &&
			    cur_ts64 >= apsta_db[apsta].M[i].ts64 &&
			    cur_ts64 - apsta_db[apsta].M[i].ts64 > stp * rctime) {
				if (verbosity >= 3)
					fprintf(stderr, "[discarding stale M%d from %u.%06u] ",
					        i, (uint32_t)(apsta_db[apsta].M[i].ts64 / 1000000),
					        (uint32_t)(apsta_db[apsta].M[i].ts64 % 1000000));
				remove_handshake(apsta, i);
			}
		}
	}

	if (!output_dupes && apsta_db[apsta].handshake_done) {
		if (verbosity >= 2)
			fprintf(stderr,
			        "EAPOL M%u, %cnonce %08x...%08x rc %"PRIu64"%s (4-way already seen)\n",
			        msg, (msg == 1 || msg == 3) ? 'a' : 's',
			        nonce_msb, nonce_lsb, rc,
			        auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		return;  /* no reason to go on. */
	}

	/* This is canonical for any encapsulations */
	eapol_sz = auth->length + 4;

	if (msg == 4 && is_zero(auth->wpa_nonce, 32)) {
		if (verbosity >= 2)
			fprintf(stderr,
			        "Spurious unusable M4 (anonce nulled) rc %"PRIu64"\n", rc);
		return;
	}

/*
 * If we see M1 followed by M2 which have same replay_cnt, we have a likely
 * auth. Or we want a M2 followed by a M3 that are 1 replay count apart
 * which means we DO have an auth.
 * The M3 is not returned unless the M2 (which came from the client), IS
 * valid. So, we get the anonce from either the M1 or the M3 packet.
 *
 * For our first run, we output ALL valid auths found in the file. That way,
 * I can validate that any auths which were produced by aircrack-ng are valid/
 * or not.  aircrack-ng WILL generate some invalid auths.  Also, I want to flag
 * "unknown" auths as just that, unk.  These are M1-M2's which do not have
 * valid M3-M4's.  They may be valid, but may also be a client with the wrong
 * password.
 */
	if (msg == 1 && !IGNORE_MSG1) {
		if (apsta_db[apsta].M[1].eapol) {
			ieee802_1x_eapol_t *auth1 = apsta_db[apsta].M[1].eapol;

			if (auth->replay_cnt == auth1->replay_cnt &&
			    !memcmp(auth->wpa_nonce, auth1->wpa_nonce, 32)) {
				if (verbosity >= 2)
					fprintf(stderr,
					        "dupe M1 anonce %08x...%08x rc %"PRIu64"%s\n",
					        nonce_msb, nonce_lsb, rc,
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "");
				apsta_db[apsta].M[1].ts64 = cur_ts64;
				return;
			}
			if (show_unverified && apsta_db[apsta].M[2].eapol) {
				ieee802_1x_eapol_t *auth2 = apsta_db[apsta].M[2].eapol;

				if (ignore_rc || auth1->replay_cnt == auth2->replay_cnt) {
					if (verbosity >= 2)
						fprintf(stderr, "Dumping older M1/M2 seen%s\n",
						        auth1->replay_cnt == auth2->replay_cnt ?
						        "" : " (rc mismatch)");
					dump_auth(apsta, 1, 2, 0);
				}
			}
		}
		if (verbosity >= 2)
			fprintf(stderr, "EAPOL M1 anonce %08x...%08x rc %"PRIu64"%s\n",
			        nonce_msb, nonce_lsb, rc,
			        auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		remove_handshake(apsta, 1);
		remove_handshake(apsta, 2);
		remove_handshake(apsta, 3);
		remove_handshake(apsta, 4);
		memcpy(apsta_db[apsta].bssid, packet_TA, 6);
		memcpy(apsta_db[apsta].staid, packet_RA, 6);
		apsta_db[apsta].M[1].eapol_size = eapol_sz;
		apsta_db[apsta].M[1].ts64 = cur_ts64;
		safe_malloc(apsta_db[apsta].M[1].eapol, eapol_sz);
		memcpy(apsta_db[apsta].M[1].eapol, auth, eapol_sz);
	}

	else if (msg == 2 && !IGNORE_MSG2) {
		if (apsta_db[apsta].M[2].eapol) {
			/* Check for dupe */
			ieee802_1x_eapol_t *auth2 = apsta_db[apsta].M[2].eapol;

			if (!memcmp(auth->wpa_keymic, auth2->wpa_keymic, 16)) {
				if (verbosity >= 2)
					fprintf(stderr,
					        "dupe M2 snonce %08x...%08x rc %"PRIu64"%s\n",
					        nonce_msb, nonce_lsb, rc,
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "");
				apsta_db[apsta].M[2].ts64 = cur_ts64;
				return;
			}
			if (show_unverified && apsta_db[apsta].M[1].eapol) {
				ieee802_1x_eapol_t *auth1 = apsta_db[apsta].M[1].eapol;

				if (ignore_rc || auth1->replay_cnt == auth2->replay_cnt) {
					if (verbosity >= 2)
						fprintf(stderr,
						        "EAPOL M2, already got one. Dumping old%s\n",
						        auth1->replay_cnt == auth2->replay_cnt ?
						        "" : " (rc mismatch)");
					dump_auth(apsta, 1, 2, 0);
				}
			}
		}

		remove_handshake(apsta, 2);
		remove_handshake(apsta, 3);
		remove_handshake(apsta, 4);
		memcpy(apsta_db[apsta].staid, packet_TA, 6);
		memcpy(apsta_db[apsta].bssid, packet_RA, 6);
		apsta_db[apsta].M[2].eapol_size = eapol_sz;
		apsta_db[apsta].M[2].ts64 = cur_ts64;
		safe_malloc(apsta_db[apsta].M[2].eapol, eapol_sz);
		memcpy(apsta_db[apsta].M[2].eapol, auth, eapol_sz);

		if (eapol_sz > sizeof(((hccap_t*)(NULL))->eapol)) {
			if (verbosity)
				fprintf(stderr,
				        "%s: eapol size %u (too large), skipping packet\n",
				        filename, eapol_sz);
			apsta_db[apsta].M[2].eapol_size = 0;
			remove_handshake(apsta, 2);
			return;
		}
		if (eapol_sz < 91) {
			if (verbosity)
				fprintf(stderr,
				        "%s: eapol size %u (too small), skipping packet\n",
				        filename, eapol_sz);
			apsta_db[apsta].M[2].eapol_size = 0;
			remove_handshake(apsta, 2);
			return;
		}

		/* see if we have a M1 that 'matches'. */
		if (apsta_db[apsta].M[1].eapol) {
			ieee802_1x_eapol_t *auth2 = auth;
			ieee802_1x_eapol_t *auth1 = apsta_db[apsta].M[1].eapol;

			if (ignore_rc || auth1->replay_cnt == auth2->replay_cnt) {
				if (verbosity >= 2)
					fprintf(stderr,
					        "EAPOL M2 snonce %08x...%08x rc %"PRIu64" for '%s'%s (M1 seen%s)\n",
					        nonce_msb, nonce_lsb, rc,
					        get_essid(apsta_db[apsta].bssid),
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "",
					        auth1->replay_cnt == auth2->replay_cnt ?
					        "" : " (rc mismatch)");
			} else {
				if (verbosity >= 2)
					fprintf(stderr,
					        "Spurious M2 snonce %08x...%08x rc %"PRIu64"%s\n",
					        nonce_msb, nonce_lsb, rc,
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "");
				//remove_handshake(apsta, 1);
			}
		} else {
			if (verbosity >= 2)
				fprintf(stderr,
				        "Spurious M2 snonce %08x...%08x rc %"PRIu64"%s\n",
				        nonce_msb, nonce_lsb, rc, auth->key_info.KeyDescr == 3 ?
				        " [AES-128-CMAC]" : "");
		}
		return;
	}

	else if (msg == 3 && !IGNORE_MSG3) {
		/*
		 * Either we have a M2 that 'matches', (1 less than our replay count)
		 * or we get a matching M4 (with non-zeroed data) in the future
		 */
		remove_handshake(apsta, 3);
		remove_handshake(apsta, 4);
		memcpy(apsta_db[apsta].bssid, packet_TA, 6);
		memcpy(apsta_db[apsta].staid, packet_RA, 6);
		apsta_db[apsta].M[3].eapol_size = eapol_sz;
		apsta_db[apsta].M[3].ts64 = cur_ts64;
		safe_malloc(apsta_db[apsta].M[3].eapol, eapol_sz);
		memcpy(apsta_db[apsta].M[3].eapol, auth, eapol_sz);

		if (apsta_db[apsta].M[2].eapol) {
			ieee802_1x_eapol_t *auth3 = auth;
			ieee802_1x_eapol_t *auth2 = apsta_db[apsta].M[2].eapol;

			if (ignore_rc || auth2->replay_cnt + 1 == auth3->replay_cnt) {
				ieee802_1x_eapol_t *auth1 = NULL;

				if (apsta_db[apsta].M[1].eapol)
					auth1 = apsta_db[apsta].M[1].eapol;

				/*
				 * If we saw the M1, its nonce must match the M3 nonce and we
				 * are 100% sure. If we didn't see it, we are only 99% sure.
				 */
				if (!apsta_db[apsta].M[1].eapol ||
				    !memcmp(auth1->wpa_nonce, auth3->wpa_nonce, 32)) {
					if (verbosity)
						fprintf(stderr,
						        "EAPOL M3 anonce %08x...%08x rc %"PRIu64" for '%s'%s (M2 seen%s, M1%s seen)\n",
						        nonce_msb, nonce_lsb, rc,
						        get_essid(apsta_db[apsta].bssid),
						        auth->key_info.KeyDescr == 3 ?
						        " [AES-128-CMAC]" : "",
						        auth2->replay_cnt + 1 == auth3->replay_cnt ?
						        "" : " (rc mismatch)",
						        apsta_db[apsta].M[1].eapol ? "" : " not");
					dump_auth(apsta, 3, 2, 0);
					return;
				}
			}
		}

		if (verbosity >= 2)
			fprintf(stderr,
			        "EAPOL M3 anonce %08x...%08x rc %"PRIu64"%s (no M2 seen)\n",
			        nonce_msb, nonce_lsb, rc, auth->key_info.KeyDescr == 3 ?
			        " [AES-128-CMAC]" : "");
		return;
	}

	else if (msg == 4) {
		if (eapol_sz > sizeof(((hccap_t*)(NULL))->eapol)) {
			if (verbosity)
				fprintf(stderr,
				        "%s: eapol size %u (too large), skipping packet\n",
				        filename, eapol_sz);
			apsta_db[apsta].M[4].eapol_size = 0;
			remove_handshake(apsta, 4);
			return;
		}
		if (eapol_sz < 91) {
			if (verbosity)
				fprintf(stderr,
				        "%s: eapol size %u (too small), skipping packet\n",
				        filename, eapol_sz);
			apsta_db[apsta].M[4].eapol_size = 0;
			remove_handshake(apsta, 4);
			return;
		}

		remove_handshake(apsta, 2);
		remove_handshake(apsta, 4);
		memcpy(apsta_db[apsta].staid, packet_TA, 6);
		memcpy(apsta_db[apsta].bssid, packet_RA, 6);
		apsta_db[apsta].M[4].eapol_size = eapol_sz;
		apsta_db[apsta].M[4].ts64 = cur_ts64;
		safe_malloc(apsta_db[apsta].M[4].eapol, eapol_sz);
		memcpy(apsta_db[apsta].M[4].eapol, auth, eapol_sz);

		/* see if we have a M1 or M3 that 'matches'. */
		if (apsta_db[apsta].M[3].eapol) {
			ieee802_1x_eapol_t *auth4 = auth;
			ieee802_1x_eapol_t *auth3 = apsta_db[apsta].M[3].eapol;

			if (ignore_rc || auth3->replay_cnt == auth4->replay_cnt) {
				if (verbosity)
					fprintf(stderr,
					        "EAPOL M4 snonce %08x...%08x rc %"PRIu64" for '%s'%s (M3 seen%s)\n",
					        nonce_msb, nonce_lsb, rc,
					        get_essid(apsta_db[apsta].bssid),
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "",
					        auth3->replay_cnt == auth4->replay_cnt ?
					        "" : " (rc mismatch)");
				dump_auth(apsta, 3, 4, 0);
				return;
			}
		}
		if (apsta_db[apsta].M[1].eapol) {
			ieee802_1x_eapol_t *auth4 = auth;
			ieee802_1x_eapol_t *auth1 = apsta_db[apsta].M[1].eapol;

			if (ignore_rc || auth1->replay_cnt + 1 == auth4->replay_cnt) {
				if (verbosity)
					fprintf(stderr,
					        "EAPOL M4 snonce %08x...%08x rc %"PRIu64" for '%s'%s (M1 seen%s)\n",
					        nonce_msb, nonce_lsb, rc,
					        get_essid(apsta_db[apsta].bssid),
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "",
					        auth1->replay_cnt + 1 == auth4->replay_cnt ?
					        "" : " (rc mismatch)");
				dump_auth(apsta, 1, 4, 0);
				return;
			} else {
				if (verbosity >= 2)
					fprintf(stderr,
					        "EAPOL M4 snonce %08x...%08x rc %"PRIu64" %s (no M1/M3 seen)\n",
					        nonce_msb, nonce_lsb, rc,
					        auth->key_info.KeyDescr == 3 ?
					        " [AES-128-CMAC]" : "");
			}

		} else {
			if (verbosity >= 2)
				fprintf(stderr,
				        "%sM4 snonce %08x...%08x rc %"PRIu64"%s\n",
				        (apsta_db[apsta].M[1].eapol ||
				         apsta_db[apsta].M[3].eapol) ?
				        "" : "Spurious ",
				        nonce_msb, nonce_lsb, rc,
				        auth->key_info.KeyDescr == 3 ? " [AES-128-CMAC]" : "");
		}
	} else
		if (verbosity >= 2)
			fprintf(stderr, "not EAPOL\n");
}

/*
 * This function is the main packet processor.  When we are done
 * reading packets (i.e. we have done what we want), we return 0, and
 * the program will exit gracefully.  It is not an error, it is just an
 * indication we have completed (or that the data we want is not here).
 */
static int process_packet(uint32_t link_type)
{
	static const char *last_f;
	static uint32_t last_l;
	ieee802_1x_frame_hdr_t *pkt;
	ieee802_1x_frame_ctl_t *ctl;
	unsigned int frame_skip = 0;
	int has_ht;
	unsigned int tzsp_link = 0;

	if (filename != last_f || link_type != last_l) {
		last_f = filename;
		last_l = link_type;

		if (link_type == LINKTYPE_IEEE802_11)
			fprintf(stderr, "File %s: raw 802.11\n", filename);
		else if (link_type == LINKTYPE_PRISM_HEADER)
			fprintf(stderr, "File %s: Prism encapsulation\n", filename);
		else if (link_type == LINKTYPE_RADIOTAP_HDR)
			fprintf(stderr, "File %s: Radiotap encapsulation\n", filename);
		else if (link_type == LINKTYPE_PPI_HDR)
			fprintf(stderr, "File %s: PPI encapsulation\n", filename);
		else if (link_type == LINKTYPE_ETHERNET) {
			unsigned char *packet = full_packet;

			if (snap_len > 47 &&
			    packet[12] == 0x08 && packet[13] == 0x00 && // IPv4
			    packet[23] == 17 && // UDP
			    packet[42] == 0x01 && packet[44] == 0) // TZSP
			{
				if (packet[45] == 18)
					fprintf(stderr, "File %s: 802.11 over TZSP\n", filename);
				else if (packet[45] == 119)
					fprintf(stderr, "File %s: Prism over TZSP\n", filename);
				else
					fprintf(stderr, "File %s: TZSP unknown encapsulation %02x\n",
					        filename, packet[45]);
			} else
				fprintf(stderr, "File %s: Ethernet encapsulation\n", filename);
		} else {
			fprintf(stderr,
			        "File %s: No 802.11 wireless traffic data (network %d)\n",
			        filename, link_type);
			return 0;
		}
	}

	packet = full_packet;
	pkt_num++;

	/*
	 * Handle TZSP over UDP. This is just a hack[tm].
	 */
	if (snap_len > 47 && link_type == LINKTYPE_ETHERNET &&
	    packet[12] == 0x08 && packet[13] == 0x00 && // IPv4
	    packet[23] == 17 && // UDP
	    packet[42] == 0x01 && packet[44] == 0) { // TZSP

		if (packet[45] == 18)
			tzsp_link = LINKTYPE_IEEE802_11;
		else if (packet[45] == 119)
			tzsp_link = LINKTYPE_PRISM_HEADER;
		else
			return 0;

		packet += 46;
		snap_len -= 46;
		orig_len -= 46;

		while (packet[0] != 0x01) {
			int len = packet[1] + 2;

			packet += len;
			snap_len -= len;
			orig_len -= len;
		}
		packet += 1;
		snap_len -= 1;
		orig_len -= 1;
	}

	/* Skip Prism frame if present */
	if (link_type == LINKTYPE_PRISM_HEADER ||
	    tzsp_link == LINKTYPE_PRISM_HEADER) {
		if (snap_len < 8)
			return 0;
		if (packet[7] == 0x40)
			frame_skip = 64;
		else {
			frame_skip = *(unsigned int*)&packet[4];
#if !ARCH_LITTLE_ENDIAN
			frame_skip = swap32u(frame_skip);
#endif
		}
		if (frame_skip < 8 || frame_skip >= snap_len)
			return 0;
		packet += frame_skip;
		snap_len -= frame_skip;
		orig_len -= frame_skip;
	}

	/* Skip Radiotap frame if present */
	if (link_type == LINKTYPE_RADIOTAP_HDR) {
		if (snap_len < 4)
			return 0;
		frame_skip = *(unsigned short*)&packet[2];
#if !ARCH_LITTLE_ENDIAN
		frame_skip = swap32u(frame_skip);
#endif
		if (frame_skip == 0 || frame_skip >= snap_len)
			return 0;
		packet += frame_skip;
		snap_len -= frame_skip;
		orig_len -= frame_skip;
	}

	/* Skip PPI frame if present */
	if (link_type == LINKTYPE_PPI_HDR) {
		if (snap_len < 4)
			return 0;
		frame_skip = *(unsigned short*)&packet[2];
#if !ARCH_LITTLE_ENDIAN
		frame_skip = swap32u(frame_skip);
#endif
		if (frame_skip <= 0 || frame_skip >= snap_len)
			return 0;

		/* Kismet logged broken PPI frames for a period */
		if (frame_skip == 24 && *(unsigned short*)&packet[8] == 2)
			frame_skip = 32;

		if (frame_skip == 0 || frame_skip >= snap_len)
			return 0;
		packet += frame_skip;
		snap_len -= frame_skip;
		orig_len -= frame_skip;
	}

	/*
	 * Handle Ethernet EAPOL data if present. This is typically a pcap
	 * sniffed in non-monitor-mode.
	 * We strip the ethernet header and add a fake 802.11 header instead.
	 */
	if (link_type == LINKTYPE_ETHERNET &&
	    packet[12] == 0x88 && packet[13] == 0x8e) {
		int new_len = snap_len - 12 + sizeof(fake802_11);
		ieee802_1x_eapol_t *auth;

		//dump_hex("Orig packet", packet, snap_len);

		if (new_len > new_p_sz) {
			safe_realloc(new_p, new_len);
			new_p_sz = new_len;
		}
		/* Start with some fake 802.11 header data */
		memcpy(new_p, fake802_11, sizeof(fake802_11));
		/* Put original src and dest in the fake 802.11 header */
		memcpy(new_p + 4, packet, 12);
		/* Add original EAPOL data */
		memcpy(new_p + sizeof(fake802_11), packet + 12, snap_len - 12);

		auth = (ieee802_1x_eapol_t*)&packet[14];
		auth->key_info_u16 = swap16u(auth->key_info_u16);
		/* Add the BSSID to the 802.11 header */
		if (auth->key_info.KeyACK)
			memcpy(new_p + 16, packet + 6, 6);
		else
			memcpy(new_p + 16, packet, 6);

		snap_len += sizeof(fake802_11) - 12;
		orig_len += sizeof(fake802_11) - 12;
		packet = new_p;
		//dump_hex("Fake packet", packet, snap_len);
	}

	/* our data is in *packet  */
	pkt = (ieee802_1x_frame_hdr_t*)packet;

	if (snap_len < 10) {
		if (verbosity >= 2)
			fprintf(stderr, "Truncated data\n");
		return 0;
	}

	packet_RA = pkt->addr1;
	packet_TA = (snap_len >= 16) ? pkt->addr2 : NULL;

	ctl = (ieee802_1x_frame_ctl_t *)&pkt->frame_ctl;

	if (ctl->toDS == 0 && ctl->fromDS == 0) {
		packet_DA = packet_RA;
		packet_SA = packet_TA;
		bssid = (snap_len >= 22) ? pkt->addr3 : NULL;
	} else if (ctl->toDS == 0 && ctl->fromDS == 1) {
		packet_DA = packet_RA;
		packet_SA = (snap_len >= 22) ? pkt->addr3 : NULL;
		bssid = packet_TA;
	} else if (ctl->toDS == 1 && ctl->fromDS == 0) {
		bssid = packet_RA;
		packet_SA = packet_TA;
		packet_DA = (snap_len >= 22) ? pkt->addr3 : NULL;
	} else /*if (ctl->toDS == 1 && ctl->fromDS == 1)*/ {
		packet_DA = (snap_len >= 22) ? pkt->addr3 : NULL;
		packet_SA = (snap_len >= 30) ? &packet[24] : NULL; // addr4
		bssid = packet_TA; /* If anything */
	}

	filter_hit = (!filter_mac[0] ||
	              !strcmp(filter_mac, to_mac_str(packet_RA)) ||
	              (packet_TA && !strcmp(filter_mac, to_mac_str(packet_TA))) ||
	              (packet_SA && !strcmp(filter_mac, to_mac_str(packet_SA))) ||
	              (packet_DA && !strcmp(filter_mac, to_mac_str(packet_DA))));

	if (verbosity >= 2 && filter_hit) {
		if (verbosity >= 4)
			dump_hex("802.11 packet", pkt, snap_len);

		if (verbosity >= 4)
			fprintf(stderr, "%4d %2u.%06u  %s -> %s %-4d ", pkt_num,
			        (uint32_t)(abs_ts64 / 1000000),
			        (uint32_t)(abs_ts64 % 1000000),
			        to_mac_str(packet_TA),
			        to_mac_str(packet_RA), snap_len);
		else
			fprintf(stderr, "%4d %2u.%06u  %s -> %s %-4d ", pkt_num,
			        (uint32_t)(cur_ts64 / 1000000),
			        (uint32_t)(cur_ts64 % 1000000),
			        to_mac_str(packet_TA),
			        to_mac_str(packet_RA), snap_len);

		if (verbosity >= 3)
			fprintf(stderr, "\n\tRA %s TA %s DA %s SA %s BSSID %s",
			        packet_RA ? to_hex(packet_RA, 6) : "null",
			        packet_TA ? to_hex(packet_TA, 6) : "null",
			        packet_DA ? to_hex(packet_DA, 6) : "null",
			        packet_SA ? to_hex(packet_SA, 6) : "null",
			        bssid ? to_hex(bssid, 6) : "null");

		if (verbosity >= 2 && filter_hit && packet_TA) {
			if (!memcmp(l3mcast, packet_TA, 3))
				fprintf(stderr, "[IPv4 mcast src] ");
			else if ((packet_TA[0] & 0x03) == 0x03)
				fprintf(stderr, "[LA mcast src] ");
			else if (packet_TA[0] & 0x01)
				fprintf(stderr, "[mcast src] ");
			else if (packet_TA[0] & 0x02)
				fprintf(stderr, "[LA src] ");
		}
		if (verbosity >= 2 && filter_hit && memcmp(packet_RA, bcast, 6)) {
			if (!memcmp(l3mcast, packet_RA, 3))
				fprintf(stderr, "[IPv4 mcast] ");
			else if ((packet_RA[0] & 0x03) == 0x03)
				fprintf(stderr, "[LA mcast] ");
			else if (packet_RA[0] & 0x01)
				fprintf(stderr, "[mcast] ");
			else if (packet_RA[0] & 0x02)
				fprintf(stderr, "[LA dst] ");
		}
	}

	has_ht = (ctl->order == 1); /* 802.11n, 4 extra bytes MAC header */

	if (has_ht && verbosity >= 2 && filter_hit)
		fprintf(stderr, "[802.11n] ");

	/*
	 * Type 0 is management,
	 * Beacon is subtype 8 and probe response is subtype 5
	 * probe request is 4, assoc request is 0, reassoc is 2
	 */
	if (ctl->type == 0 && bssid) {
		learn_essid(ctl->subtype, has_ht, bssid);
		return 1;
	}

	if (!filter_hit && (memcmp(bcast, packet_RA, 6) || packet_TA != NULL))
		return 1;

	/* if not beacon or probe response, then look only for EAPOL 'type' */
	if (ctl->type == 2) { /* type 2 is data */
		uint8_t *p = packet;
		int has_qos = (ctl->subtype & 8) != 0;
		int has_addr4 = ctl->toDS & ctl->fromDS;

		if (has_qos && verbosity >= 2)
			fprintf(stderr, "[QoS] ");
		if (has_addr4 && verbosity >= 2)
			fprintf(stderr, "[a4] ");

		if (!has_addr4 && ((ctl->toDS ^ ctl->fromDS) != 1)) {
			/* eapol will ONLY be direct toDS or direct fromDS. */
			if (verbosity >= 2)
				fprintf(stderr, "Data\n");
			return 1;
		}
		if (sizeof(ieee802_1x_frame_hdr_t)+6+2+
		    (has_qos?2:0)+(has_ht?4:0)+(has_addr4?6:0) >=
		    snap_len) {
			if (verbosity >= 2)
				fprintf(stderr, "QoS Null or malformed EAPOL\n");
			return 1;
		}
		/* Ok, find out if this is an EAPOL packet or not. */

		p += sizeof(ieee802_1x_frame_hdr_t);
		if (has_addr4)
			p += 6;
		if (has_qos)
			p += 2;
/*
 * p now points to the start of the LLC
 * this is 8 bytes long, and the last 2 bytes are the 'type' field.  What
 * we are looking for is 802.1X authentication packets. These are 0x888e
 * in value.  We are running from an LE point of view, so should look for 0x8e88
 */
		p += 6;
		if (*((uint16_t*)p) == 0x8e88) {
			eapext_t *eap;

			p += 2;
			if (has_ht)
				p += 4;
			eap = (eapext_t*)p;

			if (eap->type == 0) {
				if (snap_len < sizeof(eapext_t) + (has_qos ? 10 : 8)) {
					fprintf(stderr, "%s: truncated packet\n", filename);
					return 1;
				}
				if (eap->eaptype == EAP_TYPE_ID &&
				    eap->eapcode == EAP_CODE_RESP) {
					/* Identity response */
					int len = swap16u(eap->eaplen) - 5;
					char *id;

					p += sizeof(eapext_t);
					safe_malloc(id, len + 1);
					memcpy(id, p, len);
					id[len] = 0;
					if (verbosity >= 2)
						fprintf(stderr, "EAP Identity Response: '%s'\n", id);
					MEM_FREE(id);
					return 1;
				}
			} else if (eap->type == 1) {
				if (verbosity >= 2)
					fprintf(stderr, "EAP Start\n");
				return 1;
			} else if (eap->type == 3) {
				/* EAP key */
				if (snap_len < sizeof(ieee802_1x_frame_hdr_t) +
				    (has_qos ? 10 : 8)) {
					fprintf(stderr, "%s: truncated packet\n", filename);
				} else if (bssid)
					handle4way((ieee802_1x_eapol_t*)p, bssid);
				return 1;
			} else {
				if (verbosity >= 2)
					fprintf(stderr, "EAP type %d\n", eap->type);
				return 1;
			}
		}
	}

	if (verbosity >= 2) {
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

int pcapng_option_print(FILE *in, size_t len, size_t pad_len,
                        char *name, int verb_lvl)
{
	char *string;

	safe_malloc(string, pad_len + 1);

	if (fread(string, 1, pad_len, in) != pad_len) {
		fprintf(stderr, "Malformed %s data in %s\n", name, filename);
		MEM_FREE(string);
		return 1;
	}
	if (verbosity >= verb_lvl) {
		// These strings are NOT null-terminated unless they happen to be padded
		string[len] = 0;
		fprintf(stderr, "File %s %s: %s\n", filename, name, string);
	}

	MEM_FREE(string);
	return 0;
}

void pcapng_option_walk(FILE *in, uint32_t tl)
{
	uint16_t res;
	uint16_t padding;
	option_header_t opthdr;
	uint16_t len, pad_len;

	while (1) {
		res = fread(&opthdr, 1, OH_SIZE, in);
		if (res != OH_SIZE) {
			fprintf(stderr, "Malformed data in %s\n", filename);
			break;
		}
		if (opthdr.option_code == 0) {
			break;
		}
		padding = 0;
		len = opthdr.option_length;
		if ((len % 4))
			padding = 4 - (len % 4);

		pad_len = len + padding;

		if (pad_len > tl) {
			fprintf(stderr, "Malformed data in %s\n", filename);
			break;
		}
		tl -= pad_len;

		if (opthdr.option_code == 1) {
			if (pcapng_option_print(in, len, pad_len, "comment", 0))
				break;
		} else if (opthdr.option_code == 2) {
			if (pcapng_option_print(in, len, pad_len, "hwinfo", 1))
				break;
		} else if (opthdr.option_code == 3) {
			if (pcapng_option_print(in, len, pad_len, "osinfo", 1))
				break;
		} else if (opthdr.option_code == 4) {
			if (pcapng_option_print(in, len, pad_len, "appinfo", 1))
				break;
		} else {
			// Just skip unknown options
			fseek(in, pad_len, SEEK_CUR);
		}
	}
}

static int process_ng(FILE *in)
{
	unsigned int res;
	int aktseek;

	block_header_t pcapngbh;
	section_header_block_t pcapngshb;
	interface_description_block_t pcapngidb;
	packet_block_t pcapngpb;
	enhanced_packet_block_t pcapngepb;

	while (1) {
		res = fread(&pcapngbh, 1, BH_SIZE, in);
		if (res == 0) {
			break;
		}
		if (res != BH_SIZE) {
			printf("failed to read pcapng header block\n");
			break;
		}
		if (pcapngbh.block_type == PCAPNGBLOCKTYPE) {
			res = fread(&pcapngshb, 1, SHB_SIZE, in);
			if (res != SHB_SIZE) {
				printf("failed to read pcapng section header block\n");
				break;
			}
#if !ARCH_LITTLE_ENDIAN
			pcapngbh.total_length = swap32u(pcapngbh.total_length);
			pcapngshb.byte_order_magic	= swap32u(pcapngshb.byte_order_magic);
			pcapngshb.major_version		= swap16u(pcapngshb.major_version);
			pcapngshb.minor_version		= swap16u(pcapngshb.minor_version);
			pcapngshb.section_length	= swap64u(pcapngshb.section_length);
#endif
			if (pcapngshb.byte_order_magic == PCAPNGMAGICNUMBERBE) {
				swap_needed = 1;
				pcapngbh.total_length = swap32u(pcapngbh.total_length);
				pcapngshb.byte_order_magic	= swap32u(pcapngshb.byte_order_magic);
				pcapngshb.major_version		= swap16u(pcapngshb.major_version);
				pcapngshb.minor_version		= swap16u(pcapngshb.minor_version);
				pcapngshb.section_length	= swap64u(pcapngshb.section_length);
			}
			aktseek = ftell(in);
			if (pcapngbh.total_length > (SHB_SIZE + BH_SIZE + 4)) {
				pcapng_option_walk(in, pcapngbh.total_length);
			}
			fseek(in, aktseek + pcapngbh.total_length - BH_SIZE - SHB_SIZE, SEEK_SET);
			continue;
		}
#if !ARCH_LITTLE_ENDIAN
		pcapngbh.block_type = swap32u(pcapngbh.block_type);
		pcapngbh.total_length = swap32u(pcapngbh.total_length);
#endif
		if (swap_needed == 1) {
			pcapngbh.block_type = swap32u(pcapngbh.block_type);
			pcapngbh.total_length = swap32u(pcapngbh.total_length);
		}

		if (pcapngbh.block_type == 1) {
			res = fread(&pcapngidb, 1, IDB_SIZE, in);
			if (res != IDB_SIZE) {
				printf("failed to get pcapng interface description block\n");
				break;
			}
#if !ARCH_LITTLE_ENDIAN
			pcapngidb.linktype	= swap16u(pcapngidb.linktype);
			pcapngidb.snaplen	= swap32u(pcapngidb.snaplen);
#endif
			if (swap_needed == 1) {
				pcapngidb.linktype	= swap16u(pcapngidb.linktype);
				pcapngidb.snaplen	= swap32u(pcapngidb.snaplen);
			}

			fseek(in, pcapngbh.total_length - BH_SIZE - IDB_SIZE, SEEK_CUR);
		}

		else if (pcapngbh.block_type == 2) {
			res = fread(&pcapngpb, 1, PB_SIZE, in);
			if (res != PB_SIZE) {
				printf("failed to get pcapng packet block (obsolete)\n");
				break;
			}
#if !ARCH_LITTLE_ENDIAN
			pcapngpb.interface_id	= swap16u(pcapngpb.interface_id);
			pcapngpb.drops_count	= swap16u(pcapngpb.drops_count);
			pcapngpb.timestamp_high	= swap32u(pcapngpb.timestamp_high);
			pcapngpb.timestamp_low	= swap32u(pcapngpb.timestamp_low);
			pcapngpb.caplen		= swap32u(pcapngpb.caplen);
			pcapngpb.len		= swap32u(pcapngpb.len);
#endif
			if (swap_needed == 1) {
				pcapngpb.interface_id	= swap16u(pcapngpb.interface_id);
				pcapngpb.drops_count	= swap16u(pcapngpb.drops_count);
				pcapngpb.timestamp_high	= swap32u(pcapngpb.timestamp_high);
				pcapngpb.timestamp_low	= swap32u(pcapngpb.timestamp_low);
				pcapngpb.caplen		= swap32u(pcapngpb.caplen);
				pcapngpb.len		= swap32u(pcapngpb.len);
			}

			if ((pcapngepb.timestamp_high == 0) &&
			    (pcapngepb.timestamp_low == 0) && !warn_wpaclean++)
				fprintf(stderr,
"**\n** Warning: %s seems to be processed with some dubious tool like\n"
"** 'wpaclean'. Important information may be lost.\n**\n", filename);

			MEM_FREE(full_packet);
			safe_malloc(full_packet, pcapngepb.caplen);
			res = fread(full_packet, 1, pcapngpb.caplen, in);
			if (res != pcapngpb.caplen) {
				printf("failed to read packet: %s truncated?\n", filename);
				break;
			}
			fseek(in, pcapngbh.total_length - BH_SIZE - PB_SIZE - pcapngepb.caplen, SEEK_CUR);

			MEM_FREE(full_packet);
			safe_malloc(full_packet, pcapngepb.caplen);
			res = fread(full_packet, 1, pcapngpb.caplen, in);
			if (res != pcapngpb.caplen) {
				printf("failed to read packet: %s truncated?\n", filename);
				break;
			}

			fseek(in, pcapngbh.total_length - BH_SIZE - PB_SIZE - pcapngpb.caplen, SEEK_CUR);
		}

		else if (pcapngbh.block_type == 3) {
			fseek(in, pcapngbh.total_length - BH_SIZE, SEEK_CUR);
		}

		else if (pcapngbh.block_type == 4) {
			fseek(in, pcapngbh.total_length - BH_SIZE, SEEK_CUR);
		}

		else if (pcapngbh.block_type == 5) {
			fseek(in, pcapngbh.total_length - BH_SIZE, SEEK_CUR);
		}

		else if (pcapngbh.block_type == 6) {
			res = fread(&pcapngepb, 1, EPB_SIZE, in);
			if (res != EPB_SIZE) {
				printf("failed to get pcapng enhanced packet block\n");
				break;
			}
#if !ARCH_LITTLE_ENDIAN
			pcapngepb.interface_id		= swap32u(pcapngepb.interface_id);
			pcapngepb.timestamp_high	= swap32u(pcapngepb.timestamp_high);
			pcapngepb.timestamp_low		= swap32u(pcapngepb.timestamp_low);
			pcapngepb.caplen		= swap32u(pcapngepb.caplen);
			pcapngepb.len			= swap32u(pcapngepb.len);
#endif
			if (swap_needed == 1) {
				pcapngepb.interface_id		= swap32u(pcapngepb.interface_id);
				pcapngepb.timestamp_high	= swap32u(pcapngepb.timestamp_high);
				pcapngepb.timestamp_low		= swap32u(pcapngepb.timestamp_low);
				pcapngepb.caplen		= swap32u(pcapngepb.caplen);
				pcapngepb.len			= swap32u(pcapngepb.len);
			}

			MEM_FREE(full_packet);
			safe_malloc(full_packet, pcapngepb.caplen);
			res = fread(full_packet, 1, pcapngepb.caplen, in);
			if (res != pcapngepb.caplen) {
				printf("failed to read packet: %s truncated?\n", filename);
				break;
			}
			fseek(in, pcapngbh.total_length - BH_SIZE - EPB_SIZE - pcapngepb.caplen, SEEK_CUR);
		} else {
			fseek(in, pcapngbh.total_length - BH_SIZE, SEEK_CUR);
		}
		if (pcapngepb.caplen > 0) {
			snap_len = pcapngepb.caplen;
			orig_len = pcapngepb.len;
			// FIXME: Honor if_tsresol from Interface Description Block
			abs_ts64 = (((uint64_t)pcapngepb.timestamp_high << 32) +
			              pcapngepb.timestamp_low);
			if (!start_ts64)
				start_ts64 = abs_ts64;
			cur_ts64 = abs_ts64 - start_ts64;
			if (!process_packet(pcapngidb.linktype))
				break;
		}
	}
	if (verbosity >= 2)
		fprintf(stderr, "File %s: End of data\n", filename);
	dump_late();
	return 1;
}

static int get_next_packet(FILE *in)
{
	size_t read_size;
	pcaprec_hdr_t pkt_hdr;

	if (fread(&pkt_hdr, 1, sizeof(pkt_hdr), in) != sizeof(pkt_hdr))
		return 0;

	if (swap_needed) {
		pkt_hdr.ts_sec = swap32u(pkt_hdr.ts_sec);
		pkt_hdr.ts_usec = swap32u(pkt_hdr.ts_usec);
		pkt_hdr.snap_len = swap32u(pkt_hdr.snap_len);
		pkt_hdr.orig_len = swap32u(pkt_hdr.orig_len);
	}

	snap_len = pkt_hdr.snap_len;
	orig_len = pkt_hdr.orig_len;

	if (pkt_hdr.ts_sec == 0 && pkt_hdr.ts_usec == 0 && !warn_wpaclean++)
		fprintf(stderr,
"**\n** Warning: %s seems to be processed with some dubious tool like\n"
"** 'wpaclean'. Important information may be lost.\n**\n", filename);

	if (orig_len > snap_len && !warn_snaplen++)
		fprintf(stderr,
		        "**\n** Warning: %s seems to be recorded with insufficient snaplen, packet was %u bytes but only %u bytes were recorded\n**\n",
		        filename, orig_len, snap_len);

	abs_ts64 = pkt_hdr.ts_sec * 1000000 + pkt_hdr.ts_usec;

	if (!start_ts64)
		start_ts64 = abs_ts64;

	cur_ts64 = abs_ts64 - start_ts64;

	MEM_FREE(full_packet);
	safe_malloc(full_packet, snap_len);
	read_size = fread(full_packet, 1, snap_len, in);
	if (verbosity && read_size < snap_len)
		fprintf(stderr, "%s: truncated last packet\n", filename);

	return (read_size == snap_len);
}

static int process(FILE *in)
{
	pcap_hdr_t main_hdr;

	if (fread(&main_hdr, 1, sizeof(pcap_hdr_t), in) != sizeof(pcap_hdr_t)) {
		fprintf(stderr,
			"%s: Error, could not read enough bytes to get a common 'main' pcap header\n",
			filename);
		return 0;
	}
	if (main_hdr.magic_number == 0xa1b2c3d4)
		swap_needed = 0;
	else if (main_hdr.magic_number == 0xd4c3b2a1)
		swap_needed = 1;
	else if (main_hdr.magic_number == PCAPNGBLOCKTYPE) {
		fseek(in, 0, SEEK_SET);
		return process_ng(in);
	} else {
		if (convert_ivs2(in)) {
			fprintf(stderr, "%s: unknown file. Supported formats are pcap, pcap-ng and ivs2.\n", filename);
			return 0;
		}
		return 1;
	}

	if (swap_needed) {
		main_hdr.magic_number = swap32u(main_hdr.magic_number);
		main_hdr.version_major = swap16u(main_hdr.version_major);
		main_hdr.version_minor = swap16u(main_hdr.version_minor);
		main_hdr.sigfigs = swap32u(main_hdr.sigfigs);
		main_hdr.snaplen = swap32u(main_hdr.snaplen);
		main_hdr.network = swap32u(main_hdr.network);
	}


	while (get_next_packet(in)) {
		if (!process_packet(main_hdr.network)) {
			break;
		}
	}

	if (verbosity >= 2)
		fprintf(stderr, "File %s: End of data\n", filename);
	dump_late();
	return 1;
}

static void e_fail(void)
{
	fprintf(stderr, "Incorrect -e option.\n");
	exit(EXIT_FAILURE);
}

static void manual_beacon(char *essid_bssid)
{
	char *essid = essid_bssid;
	char *bssid = strchr(essid_bssid, ':');
	uint8_t *bssid_bin = essid_db[n_apsta].bssid;
	int l = 0;

	if (!bssid)
		e_fail();

	*bssid++ = 0;
	if (strlen(essid) > 32 || strlen(bssid) < 12)
		e_fail();

	strcpy(essid_db[n_apsta].essid, essid);
	essid_db[n_apsta].essid_len = strlen(essid);

	bssid = strupr(bssid);
	while (*bssid && l < 12) {
		if (*bssid >= '0' && *bssid <= '9')
			*bssid_bin = (*bssid - '0') << 4;
		else if (*bssid >= 'A' && *bssid <= 'F')
			*bssid_bin = (*bssid - 'A' + 10) << 4;
		else {
			bssid++;
			continue;
		}
		l++;
		bssid++;
		if (*bssid >= '0' && *bssid <= '9')
			*bssid_bin |= *bssid - '0';
		else if (*bssid >= 'A' && *bssid <= 'F')
			*bssid_bin |= *bssid - 'A' + 10;
		else {
			bssid++;
			continue;
		}
		bssid_bin++;
		l++;
		bssid++;
	}
	if (*bssid || l != 12)
		e_fail();
	if (++n_essid >= max_state)
		allocate_more_essid();
	fprintf(stderr, "Learned BSSID %s ESSID '%s' from command-line option\n",
	        to_mac_str(essid_db[n_apsta].bssid), essid);
	opt_e_used = 1;
}

static void parse_mac(char *mac)
{
	char *d = filter_mac;
	int l = 0;

	mac = strupr(mac);

	while (*mac && l < 12) {
		if ((*mac >= '0' && *mac <= '9') || (*mac >= 'A' && *mac <= 'F')) {
			*d++ = *mac;
			if (l & 1 && l < 10)
				*d++ = ':';
			l++;
		}
		mac++;
	}
	if (*mac || l != 12) {
		fprintf(stderr, "Incorrect -m option.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Ignoring any packets not involving %s\n", filter_mac);
}

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";
	FILE *in;
	char *base;

	fd = mkstemp(name);
	if (fd < 0) {
		fprintf(stderr,
		        "Problem creating the input file, %s, aborting!\n",
		        strerror(errno));
		exit(EXIT_FAILURE);
	}
	write(fd, data, size);
	close(fd);

	apsta_db = calloc(max_state, sizeof(WPA4way_t));
	essid_db = calloc(max_essid, sizeof(essid_t));

	if (!apsta_db || !essid_db) {
		fprintf(stderr, "%s: Memory allocation error", argv[0]);
		exit(EXIT_FAILURE);
	}

	in = fopen(filename = name, "rb");
	if (in) {
		if ((base = strrchr(filename, '/')))
			filename = ++base;
		process(in);
		fclose(in);
	} else
		fprintf(stderr, "Error, file %s not found\n", name);
	fprintf(stderr, "\n%d AP/STA pairs processed\n", n_apsta);
	fprintf(stderr, "\n%d ESSIDS processed\n", n_essid);
	remove(name);

	free(apsta_db);

	return 0;
}
#endif

void usage(char *name, int ret)
{
	fprintf(stderr,
	"Converts PCAP or IVS2 files to JtR format.\n"
	"Supported encapsulations: 802.11, Prism, Radiotap, PPI and TZSP over UDP.\n"
	"Usage: %s [options] <file[s]>\n"
	"\n-c\t\tShow only complete auths (incomplete ones might be wrong passwords\n"
	"\t\tbut we can crack what passwords were tried).\n"
	"-v\t\tBump verbosity (can be used several times, try -vv)\n"
	"-d\t\tDo not suppress dupe hashes (per AP/STA pair)\n"
	"-r\t\tIgnore replay-count (may output fuzzed-anonce handshakes)\n"
	"-f <n>\t\tForce anonce fuzzing with +/- <n>\n"
	"-e <essid:mac>\tManually add Name:MAC pair(s) in case the file lacks beacons.\n"
	"\t\teg. -e \"Magnum WIFI:6d:61:67:6e:75:6d\"\n"
	"-m <mac>\tIgnore any packets not involving this mac adress\n\n",
	        name);
	exit(ret);
}

#ifdef HAVE_LIBFUZZER
int main_dummy(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
	FILE *in;
	int i;
	char *base;

	apsta_db = calloc(max_state, sizeof(WPA4way_t));
	essid_db = calloc(max_essid, sizeof(essid_t));

	if (!apsta_db || !essid_db) {
		fprintf(stderr, "%s: Memory allocation error", argv[0]);
		return EXIT_FAILURE;
	}

	if (sizeof(struct ivs2_filehdr) != 2  || sizeof(struct ivs2_pkthdr) != 4 ||
	    sizeof(struct ivs2_WPA_hdsk) != 352 || sizeof(hccap_t) != 356+36) {
		fprintf(stderr, "%s: Internal error: struct sizes wrong.\n", argv[0]);
		return EXIT_FAILURE;
	}

	while (argc > 1 && argv[1][0] == '-') {
		if (!strcmp(argv[1], "-h"))
			usage(argv[0], EXIT_SUCCESS);

		if (!strcmp(argv[1], "-c")) {
			show_unverified = 0;
			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (!strncmp(argv[1], "-v", 2)) {
			char *c = argv[1];

			while (*++c == 'v')
				verbosity++;
			if (*c)
				usage(argv[0], EXIT_FAILURE);

			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (!strcmp(argv[1], "-d")) {
			output_dupes = 1;
			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (!strcmp(argv[1], "-r")) {
			ignore_rc = 1;
			rctime = 10 * 1000000;
			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (argc > 2 && !strcmp(argv[1], "-e")) {
			argv[1] = argv[0];
			argv++; argc--;
			manual_beacon(argv[1]);
			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (argc > 2 && !strcmp(argv[1], "-f")) {
			argv[1] = argv[0];
			argv++; argc--;
			force_fuzz = ABS(atoi(argv[1]));
			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (argc > 2 && !strcmp(argv[1], "-m")) {
			argv[1] = argv[0];
			argv++; argc--;
			parse_mac(argv[1]);
			argv[1] = argv[0];
			argv++; argc--;
			continue;
		}

		if (!strcmp(argv[1], "--")) {
			argv[1] = argv[0];
			argv++; argc--;
			break;
		}

		usage(argv[0], EXIT_FAILURE);
	}

	if (argc < 2)
		usage(argv[0], EXIT_FAILURE);

	for (i = 1; i < argc; i++) {
		int j;

		if (verbosity && i > 1)
			fprintf(stderr, "\n");

		/* Re-init between pcap files */
		warn_snaplen = 0;
		warn_wpaclean = 0;
		start_ts64 = 0;
		pkt_num = 0;
		for (j = 0; j < n_essid; j++)
			if (essid_db[j].prio < 5)
				essid_db[j].prio = 5;

		in = fopen(filename = argv[i], "rb");
		if (in) {
			if ((base = strrchr(filename, '/')))
				filename = ++base;
			process(in);
			fclose(in);
		} else
			fprintf(stderr, "Error, file %s not found\n", argv[i]);
	}
	fprintf(stderr, "\n%d ESSIDS processed and %d AP/STA pairs processed\n",
	        n_essid, n_apsta);
	fprintf(stderr, "%d handshakes written, %d RSN IE PMKIDs\n",
	        n_handshakes, n_pmkids);

	MEM_FREE(new_p);

	return 0;
}
