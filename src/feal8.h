/* Version of 20 September 1989. */

typedef unsigned char ByteType;
typedef unsigned int HalfWord;
typedef unsigned short QuarterWord;

struct JtR_FEAL8_CTX {
        QuarterWord K[16];
        HalfWord K89;
        HalfWord K1011;
        HalfWord K1213;
        HalfWord K1415;
};


void SetKey(ByteType * KP, struct JtR_FEAL8_CTX *ctx);
void Encrypt(ByteType * Plain, ByteType * Cipher, struct JtR_FEAL8_CTX *ctx);

// void Decrypt(ByteType * Cipher, ByteType * Plain);
void Decrypt(ByteType * Cipher, ByteType * Plain, struct JtR_FEAL8_CTX *ctx);
