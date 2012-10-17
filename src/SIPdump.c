/*
 * Copyright (C) 2007  Martin J. Muench <mjm@codito.de>
 *
 * See doc/SIPcrack-LICENSE
 *
 * SIP digest authentication login sniffer
 *
 * gcc -Wall SIPdump.c -o SIPdump -lpcap */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "SIPdump.h"
#include "memory.h"

#define SIP_LINE_LEN   1024	/* Maximum length of SIP protocol lines */
#define SIP_METHOD_LEN   32	/* Maximum length of SIP method string  */
#define MAX_SIP_CON     128	/* Maximum parallel SIP connections     */
#define SNAP_LEN        1518	/* packet length                        */

/* Structure for full connection table */
typedef struct {
	int ipversion;
	int active;
	struct in6_addr client_ip6;
	struct in6_addr server_ip6;
	uint32_t client_ip;
	uint16_t client_port;
	uint32_t server_ip;
	uint16_t server_port;
	char method[SIP_METHOD_LEN];
	char buffer[SIP_LINE_LEN];
} sip_conn_t;

/* Basic connection table */
typedef struct {
	int ipversion;
	struct in6_addr client_ip6;
	struct in6_addr server_ip6;
	uint32_t client_ip;
	uint16_t client_port;
	uint32_t server_ip;
	uint16_t server_port;
} conn_t;


/* Function declarations */
static void sniff_logins(unsigned char *, const struct pcap_pkthdr *,
    const unsigned char *);
static void parse_payload(const conn_t *, unsigned char *, size_t);
static int parse_sip_proto(char *, size_t, unsigned char *, size_t);
static int find_sip_client_proto(unsigned char *, size_t);
static void manual_mode();
static void usage(const char *);
static void parse_n_write_login_data(const char *, const char *, const char *,
    const char *);
static int pcap_dloff(pcap_t *);


/* Globals */
static char *dump_file = NULL;	/* dump file             */
static unsigned int num_logins = 0;	/* sniffed login counter */
//int opterr = 0;			/* shutup getopt()       */
static int offset = 0;		/* packet offset         */

char *addr_to_numeric(const struct in6_addr *addrp)
{
	/* 0000:0000:0000:0000:0000:000.000.000.000
	 * 0000:0000:0000:0000:0000:0000:0000:0000 */
	static char buf[50 + 1];
	return (char *) inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/* Compare two IPv6 addresses */
static int in6addr_cmp(const void *a, const void *b)
{
	const struct in6_addr *ia = (const struct in6_addr *) a;
	const struct in6_addr *ib = (const struct in6_addr *) b;

	return memcmp(ia, ib, sizeof(struct in6_addr));
}

/*
 * SIPdump Main
 */

int main(int argc, char *argv[])
{
	char *dev = NULL, *pcap_file = NULL, *filter = DEFAULT_PCAP_FILTER;
	char errbuf[PCAP_ERRBUF_SIZE];
	int c, manual = 0, retval = 0;
	pcap_t *handle = NULL;
	bpf_u_int32 mask, net;
	struct bpf_program fp;

	memset(&fp, 0, sizeof(struct bpf_program));

	printf("\nSIPdump %s  ( MaJoMu | www.codito.de ) \n"
	    "---------------------------------------\n\n", VERSION);

	/* Parse command line */
	while ((c = getopt(argc, argv, "i:mp:f:")) != -1) {
		switch (c) {
		case 'i':
			dev = (char *) Malloc(strlen(optarg) + 1);
			strcpy(dev, optarg);
			break;
		case 'f':
			filter = (char *) Malloc(strlen(optarg) + 1);
			strcpy(filter, optarg);
			break;
		case 'm':
			manual = 1;
			break;
		case 'p':
			pcap_file = (char *) Malloc(strlen(optarg) + 1);
			strcpy(pcap_file, optarg);
			break;
		default:
			usage("Invalid arguments");
		}
	}

	/* Check if both modes set */
	if (pcap_file != NULL && dev != NULL)
		usage("Specify either interface or pcap file");

	/* Get dump file */
	argv += optind;
	argc -= optind;

	if (argc != 1) {
		MEM_FREE(pcap_file);
		MEM_FREE(dev);
		usage("You need to specify dump file");
	}

	dump_file = (char *) Malloc(strlen(argv[0]) + 1);
	strcpy(dump_file, argv[0]);

	/* Check for manual mode */
	if (manual) {
		manual_mode();
		goto cleanup;
	}

	/* Open pcap stream */
	if (pcap_file != NULL) {

		printf("* Using pcap file '%s' for sniffing\n", pcap_file);

		handle = pcap_open_offline(pcap_file, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "* Cannot open %s: %s\n",
			    pcap_file ? pcap_file : dev, errbuf);
			retval = EXIT_FAILURE;
			goto cleanup;
		}

	} else {

		/* For live capture, euid0 is neeed */
		if (geteuid() != 0) {
			fprintf(stderr,
			    "* You need to have root privileges to run live capture\n");
			retval = EXIT_FAILURE;
			goto cleanup;
		}

		/* Get interface if not specified on command line */
		if (dev == NULL) {
			dev = pcap_lookupdev(errbuf);

			if (dev == NULL) {
				fprintf(stderr,
				    "* Couldn't find default device: %s\n",
				    errbuf);
				retval = EXIT_FAILURE;
				goto cleanup;
			}
		}

		printf("* Using dev '%s' for sniffing\n", dev);

		/* Get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr,
			    "* Couldn't get netmask for device %s: %s\n", dev,
			    errbuf);
			net = 0;
			mask = 0;
		}

		/* Open capture device */
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "* Cannot open device %s: %s\n", dev,
			    errbuf);
			retval = EXIT_FAILURE;
			goto cleanup;
		}

	}			/* else pcap_file == null */

	/* Get offset */
	if ((offset = pcap_dloff(handle)) < 0) {
		fprintf(stderr, "* Cannot get packet offset\n");
		retval = EXIT_FAILURE;
		goto cleanup;
	}
	/* Quick hack to remove vlan from filter in case of raw */
	if (offset == 56)
		filter = "tcp or udp";

	/* Compile the sniffer filter */
	if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
		fprintf(stderr, "* Invalid packet filter: %s\n",
		    pcap_geterr(handle));
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	/* Apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "* Installing packet filter failed: %s\n",
		    pcap_geterr(handle));
		retval = EXIT_FAILURE;
		goto cleanup;
	}

	/* Run main sniffing function */
	printf("* Starting to sniff with packet filter '%s'\n\n", filter);
	pcap_loop(handle, -1, sniff_logins, NULL);
	printf("\n* Exiting, sniffed %u logins\n", num_logins);

	/* Cleanup and exit */
      cleanup:

	pcap_freecode(&fp);

	if (handle)
		pcap_close(handle);

	MEM_FREE(dump_file);
	MEM_FREE(dev);
	MEM_FREE(pcap_file);
	if (strncmp(DEFAULT_PCAP_FILTER, filter, strlen(DEFAULT_PCAP_FILTER))
	    && strncmp("tcp or udp", filter, strlen("tcp or udp")))
		MEM_FREE(filter);

	exit(retval);
}


/*
 * Parse payload and search for SIP connections
 */

static void parse_payload(const conn_t * connection,
    unsigned char *payload, size_t payload_len)
{
	static sip_conn_t conn_table[MAX_SIP_CON];
	static int first = 1, replace_entry = 0;
	int i, ret, recorded = 0;
	char buffer[SIP_LINE_LEN];
	char *payload_buffer = NULL;
	size_t payload_buffer_len = 0;
	char ipstr_server[INET6_ADDRSTRLEN], ipstr_client[INET6_ADDRSTRLEN];

	/* Clear connection table on first call */
	if (first) {
		memset(&conn_table, 0, sizeof(sip_conn_t) * MAX_SIP_CON);
		first = 0;
	}

	/* Return on empty payload */
	if (payload_len <= 0)
		return;

	/* Ignore packet if it contains binary data  */
	if (is_binary(payload, payload_len))
		return;

	/*
	 * Check if this is a recorded connection where Authorization was
	 * not found yet
	 */
	for (i = 0; i < MAX_SIP_CON; i++) {
		if (connection->ipversion == 6) {
			sprintf(ipstr_server, "%s",
			    addr_to_numeric(&connection->server_ip6));
			sprintf(ipstr_client, "%s",
			    addr_to_numeric(&connection->client_ip6));
		} else {
			struct in_addr cli, srv;
			cli.s_addr = connection->client_ip;
			srv.s_addr = connection->server_ip;
			sprintf(ipstr_server, "%s", inet_ntoa(srv));
			sprintf(ipstr_client, "%s", inet_ntoa(cli));
		}

		/* Known connection, check data */
		if ((conn_table[i].active && conn_table[i].ipversion == 4 &&
			connection->server_ip == conn_table[i].server_ip &&
			connection->client_ip == conn_table[i].client_ip &&
			connection->server_port == conn_table[i].server_port &&
			connection->client_port == conn_table[i].client_port)
		    || (conn_table[i].active && conn_table[i].ipversion == 6 &&
			(in6addr_cmp(&connection->server_ip6,
				&conn_table[i].server_ip6) == 0) &&
			(in6addr_cmp(&connection->client_ip6,
				&conn_table[i].client_ip6) == 0) &&
			connection->server_port == conn_table[i].server_port &&
			connection->client_port ==
			conn_table[i].client_port)) {

			debug(("New traffic on monitored connection %d:", i));
			debug(("Client: %s", ipstr_client));
			debug(("Server: %s", ipstr_server));

			/* Set recorded flag to prevent new parsing */
			recorded = 1;

			/* No old data recorded (no unterminated lines in last packet) */
			if (conn_table[i].buffer[0] == 0x00) {
				/* Parse payload and check if we've got digest auth */
				ret =
				    parse_sip_proto(buffer, sizeof(buffer),
				    payload, payload_len);
			}
			/* Already recorded SIP data, append new payload to buffer and recheck */
			else {
				/* Append new payload to existing buffer */
				payload_buffer_len =
				    payload_len +
				    strlen(conn_table[i].buffer) + 1;
				payload_buffer =
				    (char *) Malloc(payload_buffer_len);
				strncpy(payload_buffer, conn_table[i].buffer,
				    payload_buffer_len - 1);
				strncat(payload_buffer, (char *) payload,
				    payload_buffer_len -
				    strlen(payload_buffer) - 1);

				/* Parse buffer (saved buffer + packet payload) */
				ret = parse_sip_proto(buffer,
				    sizeof(buffer),
				    (unsigned char *) payload_buffer,
				    payload_buffer_len);

				/* Free payload buffer */
				MEM_FREE(payload_buffer);
			}

			/* Error or no digets found, removing connection from table */
			if (ret < 0) {
				memset(&conn_table[i], 0, sizeof(sip_conn_t));
				return;
			}

			/* Found challenge response */
			if (ret) {
				/* Extract all needed values and write to dump file */
				parse_n_write_login_data(ipstr_server,
				    ipstr_client, conn_table[i].method,
				    buffer);

				/* Remove entry from connection table */
				memset(&conn_table[i], 0, sizeof(sip_conn_t));

			}

			/* Keep non-line-terminated buffer, new data will be appended */
			else if (!ret) {
				if (buffer[0] != 0x00)
					strncpy(conn_table[i].buffer, buffer,
					    sizeof(conn_table[i].buffer) - 1);
			}

			/* Break lookup in connection table */
			break;
		}

	}			/* for(i=0; i < MAX_SIP_CON; i++) */


	/* Unrecorded connection */
	if (!recorded) {

		/* Check for SIP protocol */
		if (!find_sip_client_proto(payload, payload_len))
			return;

		/* Parse payload and search for digest auth */
		ret =
		    parse_sip_proto(buffer, sizeof(buffer), payload,
		    payload_len);

		/* Ignore packet on error or no digest authentication found */
		if (ret < 0)
			return;

		/* Found challenge response */
		if (ret) {
			/* Get method from payload */
			char method[SIP_METHOD_LEN];
			extract_method(method, (char *) payload,
			    sizeof(method));

			/* Extract all needed values and write to dump file */
			parse_n_write_login_data(ipstr_server, ipstr_client,
			    method, buffer);
		}

		/*
		 * Add to connection table for further checks
		 * (digest authentification line still missing)
		 */

		else if (!ret) {
			debug(("Adding connection to list:"));
			debug(("Client: %s:%d ", ipstr_client,
				connection->client_port));
			debug(("Server: %s:%d ", ipstr_server,
				connection->server_port));

			/* Find free entry in connection table */
			for (i = 0; i < MAX_SIP_CON; i++) {
				if (!conn_table[i].active) {
					recorded = 1;
					break;
				}
			}

			/* If no free entry found, replace another one */
			if (!recorded) {
				debug(("Connection table full, replacing %d",
					replace_entry));
				i = replace_entry;

				if (replace_entry == MAX_SIP_CON - 1)
					replace_entry = 0;
				else
					replace_entry++;
			}

			/* Connection information */
			conn_table[i].ipversion = connection->ipversion;
			conn_table[i].active = 1;
			conn_table[i].client_ip6 = connection->client_ip6;
			conn_table[i].server_ip6 = connection->server_ip6;
			conn_table[i].client_ip = connection->client_ip;
			conn_table[i].server_ip = connection->server_ip;
			conn_table[i].client_port = connection->client_port;
			conn_table[i].server_port = connection->server_port;

			/* Copy method */
			extract_method(conn_table[i].method, (char *) payload,
			    sizeof(conn_table[i].method));
			debug(("Method: %s", conn_table[i].method));

			/* Keep non-line-terminated data (new data will be appended) */
			if (buffer[0] != '\0') {
				strncpy(conn_table[i].buffer, buffer,
				    SIP_LINE_LEN);
				debug(("Saving buffer '%s'", buffer));
			}

		}

	}
	/* if(!recorded) */
	return;
}


/*
 * Initial check for received packets
 */

static void sniff_logins(unsigned char *args,
    const struct pcap_pkthdr *header, const unsigned char *packet)
{
	const struct ip6_hdr *ip6;
	const struct ip *ip_hdr;
	const struct tcphdr *tcp_hdr;
	const struct udphdr *udp_hdr;
	unsigned char *payload;
	int ip_protocol, ip_tot_len;
	conn_t connection;
	size_t size_ip = 0, size_proto = 0, size_payload = 0;

	/* Hack to check if network is vlan if ethernet  */
	if (offset == 18)
		offset = 14;
	if (offset == 14) {
		if (ntohs(packet[12]) == 0x8100)
			offset = 18;
	}

	/* Ignore layer below IP now */
	packet += offset;

	/* Get IP header */
	ip6 = (struct ip6_hdr *) (packet);
	ip_hdr = (struct ip *) (packet);

	switch (ip_hdr->ip_v) {
	case 6:
		size_ip = sizeof(struct ip6_hdr);
		ip_protocol = ip6->ip6_nxt;
		ip_tot_len = ntohs(ip6->ip6_plen);
		connection.server_ip6 = ip6->ip6_dst;
		connection.client_ip6 = ip6->ip6_src;
		connection.ipversion = 6;
		break;
	case 4:
		size_ip = sizeof(struct ip);
		if (size_ip < 20) {
			debug(
			    ("Got packet with invalid IPv4 header length (%d bytes), ignoring...",
				size_ip));
			return;
		}

		connection.server_ip = ip_hdr->ip_src.s_addr;
		connection.client_ip = ip_hdr->ip_dst.s_addr;
		connection.ipversion = 4;
		ip_protocol = ip_hdr->ip_p;
		ip_tot_len = ntohs(ip_hdr->ip_len);
		break;
	default:
		debug(("Got non-IPv4/IPv6 packet, ignoring..."));
		return;
	}

	/* Check proto and get source and destination port */
	switch (ip_protocol) {
	case IPPROTO_TCP:
		tcp_hdr = (struct tcphdr *) (packet + size_ip);
		size_proto = tcp_hdr->th_off * 4;
		if (size_proto < 20) {
			debug(
			    ("Got packet with invalid TCP header length (%d bytes), ignoring...",
				size_proto));
			return;
		}
		connection.server_port = tcp_hdr->th_sport;
		connection.client_port = tcp_hdr->th_dport;
		break;
	case IPPROTO_UDP:
		udp_hdr = (struct udphdr *) (packet + size_ip);
		size_proto = sizeof(struct udphdr);
		connection.server_port = udp_hdr->uh_sport;
		connection.client_port = udp_hdr->uh_dport;
		break;
	default:
		return;
	}

	/* Extract payload from packet */
	payload = (unsigned char *) (packet + size_ip + size_proto);
	size_payload = ip_tot_len - (size_ip + size_proto);
	payload[size_payload] = 0x00;

	/* If we have a payload send to payload and connection information to parser */
	if (size_payload > 0) {
		parse_payload(&connection, payload, size_payload);
	}

	return;
}


/*
 * Extract all needed SIP parameters from buffer
 */

static int parse_sip_proto(char *out,
    size_t out_len, unsigned char *buffer, size_t buffer_len)
{
	char **lines;
	int num_lines, i, found = 0, error = 0;

	/* Clear output buffer */
	memset(out, 0, out_len);

	/* Iterate through sip data (line by line) */
	lines = stringtoarray((char *) buffer, '\n', &num_lines);

	for (i = 0; i < num_lines - 1; i++) {

		/* We are only interested in lines beginning with these strings */
		if ((!strncmp(lines[i], "Proxy-Authorization:",
			    strlen("Proxy-Authorization:")) ||
			!strncmp(lines[i], "WWW-Authenticate:",
			    strlen("WWW-Authenticate:")) ||
			!strncmp(lines[i], "Authorization:",
			    strlen("Authorization:"))) && !found && !error) {
			/* found the digest auth line, copy to output buffer */
			if (out_len - 1 < strlen(lines[i])) {
				debug(
				    ("Buffer too small for line, ignoring..."));
				error = 1;
			}
			strncpy(out, lines[i], out_len - 1);
			found = 1;

		}

		/* free obsolete lines */
		MEM_FREE(lines[i]);
	}

	/* Error or regular end of SIP header and no auth found */
	if (error || (!found && lines[num_lines - 1][0] == 0x00)) {
		MEM_FREE(lines[num_lines - 1]);
		return -1;
	}

	/* Challenge response sniffed */
	if (found) {
		MEM_FREE(lines[num_lines - 1]);
		return 1;
	}

	/* Nothing found so far, recording remaining buffer */
	if (out_len - 1 < strlen(lines[num_lines - 1])) {
		debug(("Buffer too small for line, ignoring..."));
		MEM_FREE(lines[num_lines - 1]);
		return -1;
	}

	strncpy(out, lines[num_lines - 1], out_len - 1);

	/* Free last line */
	MEM_FREE(lines[num_lines - 1]);

	return 0;
}

/*
 * Check if given buffer is a SIP header with methods
 * that might require digest authentication
 */

static int find_sip_client_proto(unsigned char *buffer, size_t len)
{
	int i;
	char c = 0;

	/* Ignore all other SIP requests as they won't be challenged */

	if (strncmp((char *) buffer, "REGISTER ", 9) &&
	    strncmp((char *) buffer, "MESSAGE ", 8) &&
	    strncmp((char *) buffer, "OPTIONS ", 8) &&
	    strncmp((char *) buffer, "INVITE ", 7) &&
	    strncmp((char *) buffer, "BYE ", 4))
		return 0;

	/* Remove replace \r\n with \0 for strstr check */
	for (i = 0; i < len; i++) {
		if (buffer[i] == 0x0a || buffer[i] == 0x0d) {
			c = buffer[i];
			buffer[i] = 0x00;
			break;
		}
	}

	/* Check for valid SIP request and restore buffer */
	if (strstr((char *) buffer, " sip:") &&
	    strstr((char *) buffer, " SIP/")) {
		buffer[i] = c;
		return 1;
	}

	return 0;
}


/*
 * Manual mode to insert a login into dump file
 */

static void manual_mode()
{
	login_t login;

	memset(&login, 0, sizeof(login));

	/* Get user input */
	printf("* Enter login information manually:\n\n");
	get_string_input(login.server, sizeof(login.server),
	    "* Enter server IP  : ");
	get_string_input(login.client, sizeof(login.client),
	    "* Enter client IP  : ");
	get_string_input(login.user, sizeof(login.user),
	    "* Enter username   : ");
	get_string_input(login.realm, sizeof(login.realm),
	    "* Enter realm      : ");
	get_string_input(login.method, sizeof(login.method),
	    "* Enter Method     : ");
	get_string_input(login.uri, sizeof(login.uri),
	    "* Enter URI        : ");
	get_string_input(login.nonce, sizeof(login.nonce),
	    "* Enter nonce      : ");
	get_string_input(login.qop, sizeof(login.qop),
	    "* Enter qop        : ");

	/* Read cnonce and cnonce_count only if qop is set */
	if (strlen(login.qop)) {
		get_string_input(login.cnonce, sizeof(login.cnonce),
		    "* Enter cnonce     : ");
		get_string_input(login.nonce_count, sizeof(login.nonce_count),
		    "* Enter nonce_count: ");
	}

	/* Get algorithm */
	get_string_input(login.algorithm, sizeof(login.algorithm),
	    "* Enter algoritm   : ");
	Toupper(login.algorithm, strlen(login.algorithm));

	/* Get response hash */
	get_string_input(login.hash, sizeof(login.hash),
	    "* Enter response   : ");

	/* Write to file */
	write_login_data(&login, dump_file);

	return;
}


/*
 * Show usage and exit
 */

static void usage(const char *err_msg)
{
	printf
	    ("Usage: sipdump [OPTIONS] <dump file>                           \n\n"
	    "       <dump file>    = file where captured logins will be written to\n\n"
	    "       Options:                                                  \n"
	    "       -i <interface> = interface to listen on                   \n"
	    "       -p <file>      = use pcap data file                       \n"
	    "       -m             = enter login data manually                \n"
	    "       -f \"<filter>\"  = set libpcap filter                       \n"
	    "\n* %s\n", err_msg);
	exit(EXIT_FAILURE);
}


/*
 * Parse all SIP digest auth related values from buffer and write to dump file
 */

static void parse_n_write_login_data(const char *server,
    const char *client, const char *method, const char *buffer)
{
	login_t login_data;

	memset(&login_data, 0, sizeof(login_data));

	/* Copy server and client IP */
	strncpy(login_data.server, server, sizeof(login_data.server) - 1);
	strncpy(login_data.client, client, sizeof(login_data.client) - 1);

	/* Copy method */
	strncpy(login_data.method, method, sizeof(login_data.method) - 1);

	/* Extract Authorization options from buffer */
	if (find_value("username=", buffer, login_data.user,
		sizeof(login_data.user)) ||
	    find_value("realm=", buffer, login_data.realm,
		sizeof(login_data.realm)) ||
	    find_value("uri=", buffer, login_data.uri, sizeof(login_data.uri))
	    || find_value("nonce=", buffer, login_data.nonce,
		sizeof(login_data.nonce)) ||
	    find_value("response=", buffer, login_data.hash,
		sizeof(login_data.hash))) {
		debug(
		    ("Couldn't parse buffer (ignoring data):\n---------\n%s\n---------",
			buffer));
		return;
	}

	/* Check for qop */
	if (!find_value("qop=", buffer, login_data.qop,
		sizeof(login_data.qop))) {
		/* get cnonce and nonce_count */
		if (find_value("cnonce=", buffer, login_data.cnonce,
			sizeof(login_data.cnonce)) ||
		    find_value("nc=", buffer, login_data.nonce_count,
			sizeof(login_data.nonce_count))) {
			debug(
			    ("Couldn't parse cnonce/nonce_count (ignoring data):\n---------\n%s\n---------",
				buffer));
			return;
		}
	}

	/* Get algorithm or set MD5 */
	if (find_value("algorithm=", buffer, login_data.algorithm,
		sizeof(login_data.algorithm)))
		strncpy(login_data.algorithm, "MD5",
		    sizeof(login_data.algorithm));
	else
		Toupper(login_data.algorithm, strlen(login_data.algorithm));

	/* Write to dump file */
	write_login_data(&login_data, dump_file);

	printf("* Dumped login from %s -> %s (User: '%s')\n",
	    login_data.client, login_data.server, login_data.user);

	num_logins++;

	return;
}


/* Get offset, ripped from honeyd */
static int pcap_dloff(pcap_t * pd)
{
	int offset = -1;

	switch (pcap_datalink(pd)) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
	case DLT_IEEE802_11_RADIO:
		offset = 56;	/* 64+32...? */
		break;
	case DLT_IEEE802_11:
		offset = 32;
		break;
	case DLT_FDDI:
		offset = 21;
		break;
#ifdef DLT_PPP
	case DLT_PPP:
		offset = 24;
		break;
#endif
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		offset = 16;
		break;
#endif
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		offset = 4;
		break;
	default:
		break;
	}
	return (offset);
}
