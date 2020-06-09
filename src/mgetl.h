/*
 * Copyright (c) 2020, magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _MGETL_H
#define _MGETL_H

#define _STR_VALUE(arg)         #arg
#define STR_MACRO(n)            _STR_VALUE(n)

#if defined(SIMD_COEF_32)
#define VSCANSZ                 (SIMD_COEF_32 * 4)
#else
#define VSCANSZ                 0
#endif

static char *mem_map, *map_pos, *map_end, *map_scan_end;

#define GET_LINE(line, file)	(mem_map ? mgetl(line) : fgetl(line, LINE_BUFFER_SIZE, file))

/* Like fgetl() but for the memory-mapped file. */
static MAYBE_INLINE char *mgetl(char *res)
{
	char *pos = res;

#if defined(vcmpeq_epi8_mask) && !defined(_MSC_VER) && \
	!VLOADU_EMULATED && !VSTOREU_EMULATED

	/* 16/32/64 chars at a time with known remainder. */
	const vtype vnl = vset1_epi8('\n');

	if (map_pos >= map_end)
		return NULL;

	while (map_pos < map_scan_end &&
	       pos < res + LINE_BUFFER_SIZE - (VSCANSZ + 1)) {
		vtype x = vloadu((vtype const *)map_pos);
		uint64_t v = vcmpeq_epi8_mask(vnl, x);

		vstoreu((vtype*)pos, x);
		if (v) {
#if __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
			unsigned int r = __builtin_ctzl(v);
#else
			unsigned int r = ffs(v) - 1;
#endif
			map_pos += r;
			pos += r;
			break;
		}
		map_pos += VSCANSZ;
		pos += VSCANSZ;
	}

	if (*map_pos != '\n')
	while (map_pos < map_end && pos < res + LINE_BUFFER_SIZE - 1 &&
	       *map_pos != '\n')
		*pos++ = *map_pos++;

	map_pos++;

#elif ARCH_SIZE >= 8 && ARCH_ALLOWS_UNALIGNED /* Eight chars at a time */

	uint64_t *ss = (uint64_t*)map_pos;
	uint64_t *dd = (uint64_t*)pos;
	unsigned int *s = (unsigned int*)map_pos;
	unsigned int *d = (unsigned int*)pos;

	if (map_pos >= map_end)
		return NULL;

	while ((char*)ss < map_scan_end &&
	       (char*)dd < res + LINE_BUFFER_SIZE - 9 &&
	       !((((*ss ^ 0x0a0a0a0a0a0a0a0a) - 0x0101010101010101) &
	          ~(*ss ^ 0x0a0a0a0a0a0a0a0a)) & 0x8080808080808080))
		*dd++ = *ss++;

	s = (unsigned int*)ss;
	d = (unsigned int*)dd;
	if ((char*)s < map_scan_end &&
	    (char*)d < res + LINE_BUFFER_SIZE - 5 &&
	    !((((*s ^ 0x0a0a0a0a) - 0x01010101) &
	       ~(*s ^ 0x0a0a0a0a)) & 0x80808080))
		*d++ = *s++;

	map_pos = (char*)s;
	pos = (char*)d;

	while (map_pos < map_end && pos < res + LINE_BUFFER_SIZE - 1 &&
	       *map_pos != '\n')
		*pos++ = *map_pos++;
	map_pos++;

#elif ARCH_ALLOWS_UNALIGNED /* Four chars at a time */

	unsigned int *s = (unsigned int*)map_pos;
	unsigned int *d = (unsigned int*)pos;

	if (map_pos >= map_end)
		return NULL;

	while ((char*)s < map_scan_end &&
	       (char*)d < res + LINE_BUFFER_SIZE - 5 &&
	       !((((*s ^ 0x0a0a0a0a) - 0x01010101) &
	          ~(*s ^ 0x0a0a0a0a)) & 0x80808080))
		*d++ = *s++;

	map_pos = (char*)s;
	pos = (char*)d;
	while (map_pos < map_end && pos < res + LINE_BUFFER_SIZE - 1 &&
	       *map_pos != '\n')
		*pos++ = *map_pos++;
	map_pos++;

#else /* One char at a time */

	if (map_pos >= map_end)
		return NULL;

	while (map_pos < map_end && pos < res + LINE_BUFFER_SIZE - 1 &&
	       *map_pos != '\n')
		*pos++ = *map_pos++;
	map_pos++;

#endif

	/* Replace LF with NULL */
	*pos = 0;

	/* Handle CRLF too */
	if (pos > res)
	if (*--pos == '\r')
		*pos = 0;

	return res;
}

#endif /* _MGETL_H */
