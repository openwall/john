#ifndef TABLES_H
#define TABLES_H

#include "gost3411-2012-sse41.h"

extern ALIGN(16) const union uint512_u buffer0;
extern ALIGN(16) const union uint512_u buffer512;
extern ALIGN(16) const union uint512_u C[12];
extern ALIGN(16) const uint64_t Ax[8][256];

#endif /* TABLES_H_ */
