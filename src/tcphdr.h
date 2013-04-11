#ifndef TCPHDR_H
#define TCPHDR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <endian.h>

struct tcp_hdr {
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t th_x2:4;
	uint8_t th_off:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t th_off:4;
	uint8_t th_x2:4;
#else 
#error invalid byte order
#endif
	uint8_t th_flags;
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
};

#ifdef __cplusplus
}
#endif

#endif

