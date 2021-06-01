/*
 * Copyright (c) 2020-2021, magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef _MGETL_H
#define _MGETL_H

#define _STR_VALUE(arg)         #arg
#define STR_MACRO(n)            _STR_VALUE(n)

#if defined(vcmpeq_epi8_mask) && !defined(_MSC_VER) && !VLOADU_EMULATED
#define MGETL_HAS_SIMD          1
#define VSCANSZ                 sizeof(vtype)
#else
#define VSCANSZ                 0
#endif

typedef union {
	char     c[1];
	uint32_t w[1];
	uint64_t l[1];
#if MGETL_HAS_SIMD
	vtype    v[1];
#endif
} any_type;

static any_type *mem_map, *map_pos, *map_end, *map_scan_end;

#define GET_LINE(line, file)	(mem_map ? mgetl(line) : fgetl(line->c, LINE_BUFFER_SIZE, file))

/* Like fgetl() but for a memory-mapped file. */
static MAYBE_INLINE char *mgetl(any_type *line)
{
	any_type *pos = line;

	if (map_pos >= map_end)
		return NULL;

#if MGETL_HAS_SIMD

	const vtype vnl = vset1_epi8('\n');

	/* 16/32/64 chars at a time with known remainder! */
	while (map_pos < map_scan_end && pos < (any_type*)&line->c[LINE_BUFFER_SIZE - (VSCANSZ + 1)]) {
		vtype x = vloadu(map_pos->v);
		uint64_t v = vcmpeq_epi8_mask(vnl, x);

		vstore(pos->v, x);
		if (v) {
#if __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
			unsigned int r = __builtin_ctzl(v);
#else
			unsigned int r = ffs(v) - 1;
#endif
			map_pos = (any_type*)&map_pos->c[r];
			pos = (any_type*)&pos->c[r];
			break;
		}
		map_pos = (any_type*)&map_pos->v[1];
		pos = (any_type*)&pos->v[1];
	}

#else

#if ARCH_ALLOWS_UNALIGNED && ARCH_SIZE >= 8
	/* Eight chars at a time */
	while (map_pos < map_scan_end && pos < (any_type*)&line->c[LINE_BUFFER_SIZE - 9] &&
	       !((((*map_pos->l ^ 0x0a0a0a0a0a0a0a0a) - 0x0101010101010101) &
	          ~(*map_pos->l ^ 0x0a0a0a0a0a0a0a0a)) & 0x8080808080808080)) {
		*pos->l = *map_pos->l;
		map_pos = (any_type*)&map_pos->l[1];
		pos = (any_type*)&pos->l[1];
	}
#endif

#if ARCH_ALLOWS_UNALIGNED
	/* Four chars at a time */
	while (map_pos < map_scan_end && pos < (any_type*)&line->c[LINE_BUFFER_SIZE - 5] &&
	       !((((*map_pos->w ^ 0x0a0a0a0a) - 0x01010101) & ~(*map_pos->w ^ 0x0a0a0a0a)) & 0x80808080)) {
		*pos->w = *map_pos->w;
		map_pos = (any_type*)&map_pos->w[1];
		pos = (any_type*)&pos->w[1];
	}
#endif

#endif /* MGETL_HAS_SIMD (else) */

	/* One char at a time */
	while (*map_pos->c != '\n' && map_pos < map_end && pos < (any_type*)&line->c[LINE_BUFFER_SIZE - 1]) {
		*pos->c = *map_pos->c;
		map_pos = (any_type*)&map_pos->c[1];
		pos = (any_type*)&pos->c[1];
	}

	map_pos = (any_type*)&map_pos->c[1];

	/* Replace LF with NULL */
	*pos->c = 0;

	/* Handle CRLF too */
	if (pos > line && pos->c[-1] == '\r')
		pos->c[-1] = 0;

	return line->c;
}

#endif /* _MGETL_H */
