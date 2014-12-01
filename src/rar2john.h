// rar5 constants

// RAR5 Header flag bits (we do not care about 8, 0x10, 0x20, 0x40, spanning bits, we simply do not handle)
#define HFL_EXTRA         1
#define HFL_DATA          2
#define HFL_SKIPIFUNKNOWN 4

#define CRYPT_VERSION     0
#define CHFL_CRYPT_PSWCHECK     1
#define CRYPT5_KDF_LG2_COUNT 15
#define CRYPT5_KDF_LG2_COUNT_MAX 24
#define SIZE_SALT50 16
#define SIZE_PSWCHECK 8
#define SIZE_PSWCHECK_CSUM 4
#define SIZE_INITV 16


// RAR 5.0 header types.
#define HEAD_MARK    0x00
#define HEAD_MAIN    0x01
#define HEAD_FILE    0x02
#define HEAD_SERVICE 0x03
#define HEAD_CRYPT   0x04
#define HEAD_ENDARC  0x05
#define HEAD_UNKNOWN 0xff

// RAR 5.0 main archive header specific flags.
#define MHFL_VOLUME     0x0001
#define MHFL_VOLNUMBER  0x0002
#define MHFL_SOLID      0x0004
#define MHFL_PROTECT    0x0008
#define MHFL_LOCK       0x0010

// RAR 5.0 file header specific flags.
#define FHFL_DIRECTORY    0x0001
#define FHFL_UTIME        0x0002
#define FHFL_CRC32        0x0004
#define FHFL_UNPUNKNOWN   0x0008

// File and service header extra field values.
#define FHEXTRA_CRYPT    0x01
#define FHEXTRA_HASH     0x02
#define FHEXTRA_HTIME    0x03
#define FHEXTRA_VERSION  0x04
#define FHEXTRA_REDIR    0x05
#define FHEXTRA_UOWNER   0x06
#define FHEXTRA_SUBDATA  0x07

// Flags for FHEXTRA_CRYPT.
#define FHEXTRA_CRYPT_PSWCHECK 0x01
#define FHEXTRA_CRYPT_HASHMAC  0x02
