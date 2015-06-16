#pragma once

#define char64(c)((c) > 127 ? 255 : index64[(c)])

const static unsigned char itoa64[] =
        "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const static unsigned char index64[0x80] = {
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,  0,  1,
         54, 55, 56, 57, 58, 59, 60, 61, 62, 63,255,255,255,255,255,255,
        255,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
         17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,255,255,255,255,255,
        255, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
         43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,255,255,255,255,255
};

extern int encode64 (char *dst, unsigned char *src, int size);
extern int decode64 (unsigned char *dst, int size, char *src);
