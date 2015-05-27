#include "pufferfish_common.h"
#include "pufferfish_itoa64.h"
#include "memdbg.h"

int encode64 (char *dst, unsigned char *src, int size)
{
    char *dptr = dst;
    unsigned char *sptr = src;
    unsigned char *end  = sptr + size;
    unsigned char c1, c2;

    do
    {
        c1 = *sptr++;
        *dptr++ = itoa64[shr(c1, 2)];
        c1 = shl((c1 & 0x03), 4);

        if (sptr >= end)
        {
            *dptr++ = itoa64[c1];
            break;
        }

        c2  = *sptr++;
        c1 |= shr(c2, 4) & 0x0f;

        *dptr++ = itoa64[c1];

        c1 = shl((c2 & 0x0f), 2);

        if (sptr >= end)
        {
            *dptr++ = itoa64[c1];
            break;
        }

        c2  = *sptr++;
        c1 |= shr(c2, 6) & 0x03;

        *dptr++ = itoa64[c1];
        *dptr++ = itoa64[c2 & 0x3f];

    }
    while (sptr < end);

    *dptr = '\0';

    return (dptr - dst);
}

int decode64 (unsigned char *dst, int size, char *src)
{
    unsigned char *sptr = (unsigned char *) src;
    unsigned char *dptr = dst;
    unsigned char *end  = dst + size;
    unsigned char c1, c2, c3, c4;

    do
    {
        c1 = char64(*sptr);
        c2 = char64(*(sptr + 1));

        if (c1 == 255 || c2 == 255) break;

        *dptr++ = shl(c1, 2) | shr((c2 & 0x30), 4);
        if (dptr >= end) break;

        c3 = char64(*(sptr + 2));
        if (c3 == 255) break;

        *dptr++ = shl((c2 & 0x0f), 4) | shr((c3 & 0x3c), 2);
        if (dptr >= end) break;

        c4 = char64(*(sptr + 3));
        if (c4 == 255) break;

        *dptr++ = shl((c3 & 0x03), 6) | c4;
        sptr += 4;
    }
    while (dptr < end);

    return (dptr - dst);
}
