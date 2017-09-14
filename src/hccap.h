#ifndef _HCCAP_H
#define _HCCAP_H

#include <stdint.h>

typedef struct {
  char          essid[36];
  unsigned char mac1[6];
  unsigned char mac2[6];
  unsigned char nonce1[32];
  unsigned char nonce2[32];
  unsigned char eapol[256];
  int           eapol_size;
  int           keyver;
  unsigned char keymic[16];
} hccap_t;

typedef struct {
	uint32_t signature;
	uint32_t version;
	uint8_t  message_pair;
	uint8_t  essid_len;
	uint8_t  essid[32];
	uint8_t  keyver;
	uint8_t  keymic[16];
	uint8_t  mac_ap[6];
	uint8_t  nonce_ap[32];
	uint8_t  mac_sta[6];
	uint8_t  nonce_sta[32];
	uint16_t eapol_len;
	uint8_t  eapol[256];
} __attribute__((packed)) hccapx_t;

#define HCCAP_SIZE          sizeof(hccap_t)
#define HCCAPX_SIZE          sizeof(hccapx_t)

#endif /* _HCCAP_H */
