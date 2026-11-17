/* Lightweight shim to provide zcalloc/zcfree for infback9 */
#include <stdlib.h>

void *zcalloc(void *opaque, unsigned items, unsigned size) {
    (void)opaque;
    return calloc(items, size);
}

void zcfree(void *opaque, void *ptr) {
    (void)opaque;
    free(ptr);
}
