#if !defined (__MEMDBG_DEFINES_H)
#define __MEMDBG_DEFINES_H

#undef MEMDBG_ON
#undef MEMDBG_EXTRA_CHECKS

/* comment out the next line, to FULLY turn off memory debugging from this module, or uncomment to turn debugging on. */
/*#define MEMDBG_ON*/

/* If this is uncommented (and MEMDBG_ON is also uncommented), then the memory checking will be much more through,
 * but memory will not be freed, and runtime will slow, possibly noticeably.  However, it is much more in-depth,
 * finding things like usage of freed pointers.  Some functions like
 */
/*#define MEMDBG_EXTRA_CHECKS*/

#if defined (JTR_RELEASE_BUILD)
#undef MEMDBG_ON
#undef MEMDBG_EXTRA_CHECKS
#endif

#endif /* __MEMDBG_DEFINES_H */
