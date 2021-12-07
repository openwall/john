#define mul32x32_64(a,b) (((uint64_t)(a))*(b))

#undef ALIGN
#define ALIGN(x) __attribute__((aligned(x)))

/* endian */
inline uint32_t U8TO32_LE(const unsigned char *p) {
	return
	(((uint32_t)(p[0])      ) |
	 ((uint32_t)(p[1]) <<  8) |
	 ((uint32_t)(p[2]) << 16) |
	 ((uint32_t)(p[3]) << 24));
}
