
#define PKT_TYPE_CMP_EQUAL			0xd1
#define PKT_TYPE_PROCESSING_DONE 	0xd2
#define PKT_TYPE_RESULT1			0xd3

// ***************************************************************
//
// input packets (received by host from remote device)
//
// ***************************************************************

struct pkt_equal {
	unsigned short word_id;
	unsigned long gen_id;
	unsigned short hash_num;
};

struct pkt_done {
	unsigned long num_processed;
};

struct pkt_result1 {
	unsigned short word_id;
	unsigned long gen_id;
	unsigned char *result;
};

// creates 'struct pkt_equal', fills-in data from 'pkt'
// 'pkt' is deleted
struct pkt_equal *pkt_equal_new(struct pkt *pkt);

// creates 'struct pkt_done', fills-in data from 'pkt'
// 'pkt' is deleted
struct pkt_done *pkt_done_new(struct pkt *pkt);
