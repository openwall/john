/*
 * ASN.1 DER parsing
 *
 * This software is
 * Copyright (c) 2018 magnum
 * Copyright (c) 2006, Jouni Malinen <j@w1.fi>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _OPENCL_ASN1_H
#define _OPENCL_ASN1_H

#define ASN1_TAG_EOC		0x00 /* not used with DER */
#define ASN1_TAG_BOOLEAN	0x01
#define ASN1_TAG_INTEGER	0x02
#define ASN1_TAG_BITSTRING	0x03
#define ASN1_TAG_OCTETSTRING	0x04
#define ASN1_TAG_NULL		0x05
#define ASN1_TAG_OID		0x06
#define ASN1_TAG_OBJECT_DESCRIPTOR	0x07 /* not yet parsed */
#define ASN1_TAG_EXTERNAL	0x08 /* not yet parsed */
#define ASN1_TAG_REAL		0x09 /* not yet parsed */
#define ASN1_TAG_ENUMERATED	0x0A /* not yet parsed */
#define ASN1_TAG_UTF8STRING	0x0C /* not yet parsed */
#define ANS1_TAG_RELATIVE_OID	0x0D
#define ASN1_TAG_SEQUENCE	0x10 /* shall be constructed */
#define ASN1_TAG_SET		0x11
#define ASN1_TAG_NUMERICSTRING	0x12 /* not yet parsed */
#define ASN1_TAG_PRINTABLESTRING	0x13
#define ASN1_TAG_TG1STRING	0x14 /* not yet parsed */
#define ASN1_TAG_VIDEOTEXSTRING	0x15 /* not yet parsed */
#define ASN1_TAG_IA5STRING	0x16
#define ASN1_TAG_UTCTIME	0x17
#define ASN1_TAG_GENERALIZEDTIME	0x18 /* not yet parsed */
#define ASN1_TAG_GRAPHICSTRING	0x19 /* not yet parsed */
#define ASN1_TAG_VISIBLESTRING	0x1A
#define ASN1_TAG_GENERALSTRING	0x1B /* not yet parsed */
#define ASN1_TAG_UNIVERSALSTRING	0x1C /* not yet parsed */
#define ASN1_TAG_BMPSTRING	0x1D /* not yet parsed */

#define ASN1_CLASS_UNIVERSAL		0
#define ASN1_CLASS_APPLICATION		1
#define ASN1_CLASS_CONTEXT_SPECIFIC	2
#define ASN1_CLASS_PRIVATE		3

struct asn1_hdr {
    const uint8_t *payload;
    uint8_t identifier, class, constructed;
    uint tag, length;
};

#define ASN1_MAX_OID_LEN 20

struct asn1_oid {
    ulong oid[ASN1_MAX_OID_LEN];
    size_t len;
};

inline
int asn1_get_next(const uint8_t *buf, size_t len, struct asn1_hdr *hdr)
{
    const uint8_t *pos, *end;
    uint8_t tmp;

    memset_p(hdr, 0, sizeof(*hdr));
    pos = buf;
    end = buf + len;

    hdr->identifier = *pos++;
    hdr->class = hdr->identifier >> 6;
    hdr->constructed = !!(hdr->identifier & (1 << 5));

    if ((hdr->identifier & 0x1f) == 0x1f) {
        hdr->tag = 0;
        do {
            if (pos >= end) {
                return -1;
            }
            tmp = *pos++;
            hdr->tag = (hdr->tag << 7) | (tmp & 0x7f);
        } while (tmp & 0x80);
    } else
        hdr->tag = hdr->identifier & 0x1f;

    tmp = *pos++;
    if (tmp & 0x80) {
        if (tmp == 0xff) {
            return -1;
        }
        tmp &= 0x7f; /* number of subsequent octets */
        hdr->length = 0;
        if (tmp > 4) {
            return -1;
        }
        while (tmp--) {
            if (pos >= end) {
                return -1;
            }
            hdr->length = (hdr->length << 8) | *pos++;
        }
    } else {
        /* Short form - length 0..127 in one octet */
        hdr->length = tmp;
    }

    if (end < pos || hdr->length > (uint) (end - pos)) {
        return -1;
    }

    hdr->payload = pos;
    return 0;
}

#endif /* _OPENCL_ASN1_H */
