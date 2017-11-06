#ifndef _HCCAP_H
#define _HCCAP_H

#include <stdint.h>

typedef struct {
	char     essid[36];
	uint8_t  mac1[6];    // AP
	uint8_t  mac2[6];    // STA
	uint8_t  nonce1[32]; // snonce
	uint8_t  nonce2[32]; // anonce
	uint8_t  eapol[256];
	uint32_t eapol_size;
	uint32_t keyver;
	uint8_t  keymic[16];
} hccap_t;

#ifdef _MSC_VER
#pragma pack(1)
#endif
typedef struct {
	uint32_t signature;
	uint32_t version;
	uint8_t  message_pair;
	uint8_t  essid_len;
	uint8_t  essid[32];
	uint8_t  keyver;
	uint8_t  keymic[16];
	uint8_t  mac_ap[6];
	uint8_t  nonce_ap[32];  // anonce
	uint8_t  mac_sta[6];
	uint8_t  nonce_sta[32]; // snonce
	uint16_t eapol_len;
	uint8_t  eapol[256];
}
#ifndef _MSC_VER
__attribute__((packed))
#endif
	hccapx_t;
#ifdef _MSC_VER
#pragma pack()
#endif


#define HCCAP_SIZE      sizeof(hccap_t)
#define HCCAPX_SIZE     sizeof(hccapx_t)

#define HCCAPC_MAGIC    0x58504348 /* "HCPX" */

#endif /* _HCCAP_H */
