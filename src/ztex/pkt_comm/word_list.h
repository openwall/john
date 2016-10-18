
#define PKT_TYPE_WORD_LIST		0x01
#define PKT_TYPE_TEMPLATE_LIST	0x04

// ***************************************************************
//
// Word List, Template List
//
// ***************************************************************

// Reads words from fixed-length records.
// Words are sent \0 - terminated, except ones of max.length
struct pkt *pkt_word_list_new(char *words, int num_words, int max_len);

// Reads words and range_info from fixed-length records
// Words are sent \0 - terminated, except ones of max.length.
// range_info bytes follow, they are \0 - terminated as well
// except for when the number equals to ranges_max.
struct pkt *pkt_template_list_new(char *words,
		int num_words, int max_len,
		unsigned char *range_info, int ranges_max);

