/* vncpcap2john utility (modified VNCcrack) written in March of 2012
 * by Dhiru Kholia. vncpcap2john processes input TightVNC/RealVNC pcap
 * dump files into a format suitable for use with JtR. Works for all
 * versions (3.3, 3.7 and 3.8) of RFB protocol.
 *
 * Output Line Format => src to dst address pair:$vnc$*challenge*response
 *
 * Compilation Command: g++ vncpcap2john.cpp -o vncpcap2john -lpcap
 *
 * VNCcrack
 *
 * (C) 2003, 2004, 2006, 2008 Jack Lloyd <lloyd@randombit.net>
 * Licensed under the GNU GPL v2
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
*/
/*
 * Parts of this software are Copyright (c) 2014 rofl0r,
 * and are hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define __FAVOR_BSD
#include <netinet/ip.h>
#include "tcphdr.h"
#include <pcap.h>
#define u_char unsigned char

#include "memdbg.h"

struct Packet_Reader {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;
	char *payload_str, *dest_addr_str, *src_addr_str;
	size_t payload_len;
};

int Packet_Reader_init(struct Packet_Reader* self, const char* filename)
{
	memset(self, 0, sizeof(*self));
	self->pcap_handle = pcap_open_offline(filename, self->pcap_errbuf);

	if (!self->pcap_handle) return 0;
	return 1;
}

void Packet_Reader_get_error(struct Packet_Reader* self, char* out, size_t len) {
	snprintf(out, len, "Could not read pcap file %s\n", self->pcap_errbuf);
}

void Packet_Reader_close(struct Packet_Reader* self)
{
	if (self->pcap_handle) {
		pcap_close(self->pcap_handle);
		self->pcap_handle = 0;
	}
}

_Bool Packet_Reader_kick(struct Packet_Reader* self)
{
	struct pcap_pkthdr header;
	const u_char * packet;
	const struct ether_header *eptr;
	const struct ip *ip_header;

	free(self->payload_str);
	free(self->src_addr_str);
	free(self->dest_addr_str);

	self->payload_str = self->dest_addr_str = self->src_addr_str = 0;	// reset

	while ((packet = pcap_next(self->pcap_handle, &header))) {
		const struct tcp_hdr *tcp;
		size_t size_ip;
		size_t size_tcp;
		const u_char *payload_buf;
		size_t payload_len;
		char buf[512];

		if (header.len < sizeof(struct ether_header))
			continue;

		eptr = (void*) packet;

		if (ntohs(eptr->ether_type) != ETHERTYPE_IP)
			continue;

		if (header.len < sizeof(struct ether_header) + sizeof(struct ip))
			continue;

		ip_header = (void*)(packet + sizeof(struct ether_header));

		size_ip = 4 * ip_header->ip_hl;
		if (size_ip < 20)
			continue;	// bogus IP header

		if (header.len < sizeof(struct ether_header) + size_ip + sizeof(struct tcp_hdr))
			continue;

		tcp = (void*) (packet + sizeof(struct ether_header) + size_ip);

		size_tcp = tcp->th_off * 4;

		if (size_tcp < 20)
			continue;	// bogus TCP header

		payload_buf =
		    packet + sizeof(struct ether_header) + size_ip + size_tcp;
		payload_len =
		    header.len - (sizeof(struct ether_header) + size_ip + size_tcp);

		self->payload_str = malloc(payload_len);
		self->payload_len = payload_len;
		memcpy(self->payload_str, payload_buf, payload_len);

		snprintf(buf, sizeof buf, "%s-%d", inet_ntoa(ip_header->ip_src), ntohs(tcp->th_sport));
		self->src_addr_str = strdup(buf);

		snprintf(buf, sizeof buf, "%s-%d", inet_ntoa(ip_header->ip_dst), ntohs(tcp->th_dport));
		self->dest_addr_str = strdup(buf);

		return true;	// sucessfully got a TCP packet of some kind (yay)
	}

	return false;		// all out of bits
}

char* obtain(char** src) {
	char *new;

	if(!*src) return 0;
	new = *src;
	*src = 0;
	return new;
}

int contains(const char* haystack, size_t len, const char* needle) {
	size_t l = strlen(needle), i = 0;
	while(i + l <= len) {
		if(!memcmp(haystack + i, needle, l)) return 1;
		i++;
	}
	return 0;
}
_Bool VNC_Auth_Reader_find_next(struct Packet_Reader* reader, char** id_out, char** challenge_out, char** response_out)
{
	while (Packet_Reader_kick(reader)) {
		if(!reader->payload_len) continue;
		// This could be a lot smarter. It would be nice in particular
		// to handle malformed streams and concurrent handshakes.
		if (contains(reader->payload_str, reader->payload_len, "RFB")) {
			char *from = obtain(&reader->src_addr_str);
			char *to = obtain(&reader->dest_addr_str);
			char *challenge = 0, *response = 0;
			while (Packet_Reader_kick(reader))	// find the challenge
			{
				if (reader->payload_len == 16 &&
				    reader->src_addr_str && reader->dest_addr_str &&
				    from && to &&
				    !strcmp(from, reader->src_addr_str) &&
				    !strcmp(to, reader->dest_addr_str) &&
				    !contains(reader->payload_str, reader->payload_len, "VNCAUTH_")) {
					challenge = obtain(&reader->payload_str);
					break;
				}
			}
			while (Packet_Reader_kick(reader))	// now find response
			{
				if (reader->payload_len == 16 &&
				    reader->src_addr_str && reader->dest_addr_str &&
				    from && to &&
				    !strcmp(to, reader->src_addr_str) &&
				    !strcmp(from, reader->dest_addr_str)) {
					response = obtain(&reader->payload_str);
					break;
				}
			}
			if (challenge != 0 && response != 0) {
				char buf[512];

				*challenge_out = challenge;
				*response_out = response;
				snprintf(buf, sizeof buf, "%s to %s", from, to);
				*id_out = strdup(buf);
				free(from); free(to);
				return true;
			} else {
				free(challenge);
				free(response);
			}
			free(from); free(to);
		}
	}
	return false;
}

void makehex(char* in16, char* out33) {
	unsigned char* in = (void*)in16;
	size_t i = 0, j = 0;
	static const char *htab = "0123456789ABCDEF";
	for(;i<16;i++,j+=2) {
		out33[j] = htab[in[i] >> 4];
		out33[j+1] = htab[in[i] & 0xf];
	}
	out33[j] = 0;
}

void attempt_crack(struct Packet_Reader* reader)
{
	char *id, *challenge, *response;
	while (VNC_Auth_Reader_find_next(reader, &id, &challenge, &response)) {
		char hc[33],hr[33];
		makehex(challenge, hc);
		makehex(response, hr);
		printf("%s:$vnc$*%s*%s\n", id, hc, hr);
		free(id); free(challenge); free(response);
	}
}

int main(int argc, char *argv[])
{
	int i = 1;

	if (argc < 2) {
		dprintf(2, "Usage: %s <pcapfiles>\n", argv[0]);
		return 1;
	}
	for(; i < argc; i++) {
		struct Packet_Reader reader;
		if(Packet_Reader_init(&reader, argv[i]))
			attempt_crack(&reader);
		else {
			char buf[512];
			Packet_Reader_get_error(&reader, buf, sizeof buf);
			dprintf(2, "%s", buf);
			Packet_Reader_close(&reader);
			return 1;
		}
		Packet_Reader_close(&reader);
	}
	MEMDBG_PROGRAM_EXIT_CHECKS(stderr);
	return 0;
}
