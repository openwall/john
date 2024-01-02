#ifndef POLY1305_DONNA_H
#define POLY1305_DONNA_H

#include <stddef.h>

/* prevent name clashing with existing implementations */
#define poly1305_init john_poly1305_init
#define poly1305_update john_poly1305_update
#define poly1305_finish john_poly1305_finish
#define poly1305_auth john_poly1305_auth
#define poly1305_verify john_poly1305_verify
#define poly1305_power_on_self_test john_poly1305_power_on_self_test

typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);
void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);
int poly1305_power_on_self_test(void);

#endif /* POLY1305_DONNA_H */
