/* vncpcap2john utility (modified VNCcrack) written in March of 2012
 * by Dhiru Kholia. vncpcap2john processes input TightVNC pcap dump
 * files into a format suitable for use with JtR.
 *
 * Output Line Format => src to dst address pair:$vnc$*version*challenge*response
 * Where,
 * 	version = 8, for RFB Protocol Version 3.8 (only version supported currently)
 * 	version = 7, for RFB Protocol Version 3.7
 * 	version = 3, for RFB Protocol Version 3.3
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

#include <cctype>
#include <map>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

using namespace std;

void print_hex(const unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02X", str[i]);
}

class Packet_Reader {
      public:
	Packet_Reader(const std::string & filename);
	~Packet_Reader();

	bool kick();

	 std::string payload() const {
		return payload_str;
	} std::string destination_address() const {
		return dest_addr_str;
	} std::string source_address() const {
		return src_addr_str;
      } private:
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;

	 std::string payload_str, dest_addr_str, src_addr_str;
};

Packet_Reader::Packet_Reader(const std::string & filename)
{
	pcap_handle = pcap_open_offline(filename.c_str(), pcap_errbuf);

	if (!pcap_handle)
		throw std::runtime_error("Could not read pcap file " +
	    std::string(pcap_errbuf));
}

Packet_Reader::~Packet_Reader()
{
	if (pcap_handle) {
		pcap_close(pcap_handle);
		pcap_handle = 0;
	}
}

bool Packet_Reader::kick()
{
	pcap_pkthdr header;

	payload_str = dest_addr_str = src_addr_str = "";	// reset

	while (const u_char * packet = pcap_next(pcap_handle, &header)) {
		if (header.len < sizeof(struct ether_header))
			continue;

		const struct ether_header *eptr =
		    reinterpret_cast < const struct ether_header *>(packet);

		if (ntohs(eptr->ether_type) != ETHERTYPE_IP)
			continue;

		if (header.len <
		    sizeof(struct ether_header) + sizeof(struct ip))
			continue;

		const struct ip *ip_header =
		    reinterpret_cast <
		    const struct ip *>(packet + sizeof(ether_header));

		size_t size_ip = 4 * ip_header->ip_hl;
		if (size_ip < 20)
			continue;	// bogus IP header

		if (header.len <
		    sizeof(struct ether_header) + size_ip + sizeof(tcphdr))
			continue;

		const struct tcphdr *tcp =
		    reinterpret_cast <
		    const struct tcphdr *>(packet + sizeof(ether_header) +
		    size_ip);

		size_t size_tcp = tcp->th_off * 4;

		if (size_tcp < 20)
			continue;	// bongus TCP header

		const u_char *payload_buf =
		    packet + sizeof(ether_header) + size_ip + size_tcp;
		const size_t payload_len =
		    header.len - (sizeof(ether_header) + size_ip + size_tcp);

		payload_str =
		    std::string(reinterpret_cast < const char *>(payload_buf),
		    payload_len);

		std::ostringstream os1;
		os1 << inet_ntoa(ip_header->ip_src) << "-" << ntohs(tcp->th_sport);
		src_addr_str = os1.str();

		std::ostringstream os2;
		os2 << inet_ntoa(ip_header->ip_dst) << "-" << ntohs(tcp->th_dport);
		dest_addr_str = os2.str();

		return true;	// sucessfully got a TCP packet of some kind (yay)
	}

	return false;		// all out of bits
}

class VNC_Auth_Reader {
      public:
	VNC_Auth_Reader(const std::string & filename):reader(filename) {
	} bool find_next(std::string & id_out,
	    std::string & challenge_out, std::string & response_out);

      private:
	Packet_Reader reader;
};

bool VNC_Auth_Reader::find_next(std::string & id_out,
    std::string & challenge_out, std::string & response_out)
{
	while (reader.kick()) {
		const std::string payload = reader.payload();

		// This could be a lot smarter. It would be nice in particular
		// to handle malformed streams and concurrent handshakes.
		if (payload.find("RFB") != std::string::npos) {
			const std::string from = reader.source_address();
			const std::string to = reader.destination_address();
			std::string challenge, response;
			while (reader.kick())	// find the challenge
			{
				if (from == reader.source_address() &&
				    to == reader.destination_address() &&
				    reader.payload().size() == 16 &&
				    reader.payload().find("VNCAUTH_") == std::string::npos) {
					challenge = reader.payload();
					break;
				}
			}
			while (reader.kick())	// now find response
			{
				if (to == reader.source_address() &&
				    from == reader.destination_address() &&
				    reader.payload().size() == 16) {
					response = reader.payload();
					break;
				}
			}
			if (challenge != "" && response != "") {
				challenge_out = challenge;
				response_out = response;
				id_out = from + " to " + to;
				return true;
			}
		}
	}
	return false;
}

void attempt_crack(VNC_Auth_Reader & reader, std::istream & wordlist)
{
	std::map < std::string, std::string > challenge_to_id;
	std::map < std::pair < std::string, std::string >,
	    std::string > solutions;

	std::string id, challenge, response;
	while (reader.find_next(id, challenge, response)) {
		solutions[std::make_pair(challenge, response)] = "";
		challenge_to_id[challenge] = id;
	}

	for (std::map < std::pair < std::string, std::string >,
			std::string >::iterator i = solutions.begin();
			i != solutions.end(); ++i) {
		if (!i->second.empty())
			continue;
		const std::string challenge = i->first.first;
		const std::string response = i->first.second;
		std::cout << challenge_to_id[challenge] << ":$vnc$*8*";
		print_hex((const unsigned char*)challenge.c_str(), 16);
		std::cout<<"*";
		print_hex((const unsigned char*)response.c_str(), 16);
		std::cout<<endl;
	}
}

int main(int argc, char *argv[])
{
	try {
		if (argc < 2) {
			std::cerr << "Usage: " << argv[0] << " <pcapfiles>\n";
			return 1;
		}
		for(int i = 1; i < argc; i++) {
			VNC_Auth_Reader reader(argv[i]);
			attempt_crack(reader, std::cin);
		}
	}
	catch(std::exception & e) {
		std::cout << e.what() << std::endl;
		return 1;
	}
	return 0;
}
