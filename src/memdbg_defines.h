#if !defined (__MEMDBG_DEFINES_H)
#define __MEMDBG_DEFINES_H

#undef MEMDBG_ON
#undef MEMDBG_EXTRA_CHECKS

#if defined MEMDBG_BUILD
/* turn debugging on. */
#define MEMDBG_ON

/*
 * If this is uncommented (and MEMDBG_ON is also uncommented), then the memory
 * checking will be much more through, but memory will not be freed, and
 * runtime will slow, possibly noticeably.  However, it is much more in-depth,
 * finding things like usage of freed pointers.
 */
#if defined MEMDBG_EXTRA
#define MEMDBG_EXTRA_CHECKS
#endif
#endif

#if defined (JTR_RELEASE_BUILD)
#undef MEMDBG_ON
#undef MEMDBG_EXTRA_CHECKS
#endif

#endif /* __MEMDBG_DEFINES_H */
