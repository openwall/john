#ifndef _DEVICE_BITSTREAM_H_
#define _DEVICE_BITSTREAM_H_

#include "pkt_comm/pkt_comm.h"


struct device_bitstream {
	// bitstream ID (check is performed by querying operating bitstream)
	unsigned short type;
	char *path;
	// parameters for high-speed packet communication (pkt_comm)
	struct pkt_comm_params pkt_comm_params;
	// device computing performance (in candidates per interval)
	// (keys * mask_num_cand)/crypt_all_interval per jtr_device.
	unsigned int candidates_per_crypt;
	// keys/crypt_all_interval for all devices - link layer performance issue.
	// Also consider 16-bit IDs for template_list/word_list:
	// no more than (64K - 1) keys per crypt_all per jtr_device
	unsigned int abs_max_keys_per_crypt;
	// Max. number of entries in onboard comparator
	int cmp_entries_max;
};


#endif
