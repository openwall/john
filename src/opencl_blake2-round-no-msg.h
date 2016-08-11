/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
   
   modified in 2015 by Agnieszka Bielec <bielecagnieszka8 at gmail.com>
*/

#define G1_V(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
	row1l = row1l + row2l; \
	row1h = row1h + row2h; \
	\
	row4l = row4l ^ row1l; \
	row4h = row4h ^ row1h; \
	\
	row4l = rotate(row4l, -32); \
	row4h = rotate(row4h, -32); \
	\
	row3l = row3l + row4l; \
	row3h = row3h + row4h; \
	\
	row2l = row2l ^ row3l; \
	row2h = row2h ^ row3h; \
	\
	row2l = rotate(row2l, -24); \
	row2h = rotate(row2h, -24); \
 
#define G2_V(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
	row1l = row1l + row2l; \
	row1h = row1h + row2h; \
	\
	row4l = row4l ^ row1l; \
	row4h = row4h ^ row1h; \
	\
	row4l = rotate(row4l, -16); \
	row4h = rotate(row4h, -16); \
	\
	row3l = row3l + row4l; \
	row3h = row3h + row4h; \
	\
	row2l = row2l ^ row3l; \
	row2h = row2h ^ row3h; \
	\
	row2l = rotate(row2l, -63); \
	row2h = rotate(row2h, -63); \


#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = (ulong2) (row2l.y, row2h.x); \
  t1 = (ulong2) (row2h.y, row2l.x); \
  row2l =t0;	\
  row2h =t1;    \
\
  t0 = row3l; \
  row3l = row3h; \
  row3h = t0;    \
  \
  t0 = (ulong2) (row4l.y, row4h.x); \
  t1 = (ulong2) (row4h.y, row4l.x); \
  row4l = t1; \
  row4h = t0;

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
  t0 = (ulong2) (row2h.y, row2l.x); \
  t1 = (ulong2) (row2l.y, row2h.x); \
  row2l = t0; \
  row2h = t1; \
  \
  t0 = row3l; \
  row3l = row3h; \
  row3h = t0; \
  \
  t0 = (ulong2) (row4h.y, row4l.x); \
  t1 = (ulong2) (row4l.y, row4h.x); \
  row4l = t1; \
  row4h = t0;

#define BLAKE2_ROUND_NO_MSG_V(row1l,row1h,row2l,row2h,row3l,row3h,row4l,row4h) \
	G1_V(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	G2_V(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	\
	DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	\
	G1_V(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	G2_V(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
	\
	UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);
