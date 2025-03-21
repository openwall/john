/*
 * Copyright (c) 2020-2025, magnum
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
static char *map_scan_end;
#else
#define VSCANSZ                 0
#endif

static char *mem_map, *map_pos, *map_end;

#define GET_LINE(line, file)	(mem_map ? mgetl(line) : fgetl(line, LINE_BUFFER_SIZE, file))

/* Like fgetl() but for the memory-mapped file. */
static MAYBE_INLINE char *mgetl(char *line)
{
	char *pos = line;

	if (map_pos >= map_end)
		return NULL;

#if MGETL_HAS_SIMD

	/* 16/32/64 chars at a time (SIMD width) with known remainder! */
	const vtype vnl = vset1_epi8('\n');

	while (map_pos < map_scan_end && pos < line + LINE_BUFFER_SIZE - (VSCANSZ + 1)) {
		vtype x = vloadu((vtype const *)map_pos);
		uint64_t v = vcmpeq_epi8_mask(vnl, x);

		vstore((vtype*)pos, x);
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

#endif

	/* One char at a time */
	if (map_end - map_pos >= LINE_BUFFER_SIZE - (pos - line)) {
		/* Need only check write */
		while (*map_pos != '\n' && pos < line + LINE_BUFFER_SIZE - 1)
			*pos++ = *map_pos++;

		/* Line may be longer than our buffer, discard extra. */
		if (pos >= line + LINE_BUFFER_SIZE - 1) {
			while (map_pos < map_end && *map_pos != '\n')
				map_pos++;
		}
	} else
		/* Need only check read */
		while (map_pos < map_end && *map_pos != '\n')
			*pos++ = *map_pos++;

	map_pos++;

	/* Replace LF (or missing last line LF) with NULL */
	*pos = 0;

	/* Handle CRLF too */
	if (pos > line && *--pos == '\r')
		*pos = 0;

	return line;
}

#endif /* _MGETL_H */
