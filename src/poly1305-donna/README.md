"A state-of-the-art message-authentication code"

# ABOUT

See: [http://cr.yp.to/mac.html](http://cr.yp.to/mac.html) and [http://cr.yp.to/mac/poly1305-20050329.pdf](http://cr.yp.to/mac/poly1305-20050329.pdf)

These are quite portable implementations of increasing efficiency depending on the size of the multiplier available.
Optimized implementations have been moved to [poly1305-opt](https://github.com/floodyberry/poly1305-opt)

# BUILDING

## Default

If compiled with no options, `poly1305-donna.c` will select between the 32 bit and 64 bit implementations based
on what it can tell the compiler supports

    gcc poly1305-donna.c -O3 -o poly1305.o

## Selecting a specific version

    gcc poly1305-donna.c -O3 -o poly1305.o -DPOLY1305_XXBIT

Where `-DPOLY1305_XXBIT` is one of

 * `-DPOLY1305_8BIT`, 8->16 bit multiplies, 32 bit additions
 * `-DPOLY1305_16BIT`, 16->32 bit multiples, 32 bit additions
 * `-DPOLY1305_32BIT`, 32->64 bit multiplies, 64 bit additions
 * `-DPOLY1305_64BIT`, 64->128 bit multiplies, 128 bit additions

8 bit and 16 bit versions were written to keep the code size small, 32 bit and 64 bit versions are mildly optimized due
to needing fewer multiplications. All 4 can be made faster at the expense of increased code size and complexity, which
is not the intention of this project.

# USAGE

See: [http://nacl.cace-project.eu/onetimeauth.html](http://nacl.cace-project.eu/onetimeauth.html), in specific, slightly plagiarized:

The poly1305_auth function, viewed as a function of the message for a uniform random key, is
designed to meet the standard notion of unforgeability after a single message. After the sender
authenticates one message, an attacker cannot find authenticators for any other messages.

The sender **MUST NOT** use poly1305_auth to authenticate more than one message under the same key.
Authenticators for two messages under the same key should be expected to reveal enough information
to allow forgeries of authenticators on other messages.

## Functions

`poly1305_context` is declared in [poly1305.h](poly1305.h) and is an opaque structure large enough to support
every underlying platform specific implementation. It should be size_t aligned, which should be handled already
with the size_t member `aligner`.

`void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);`

where

`key` is the 32 byte key that is **only used for this message and is discarded immediately after**

`void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);`

where `m` is a pointer to the message fragment to be processed, and

`bytes` is the length of the message fragment

`void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);`

where `mac` is the buffer which receives the 16 byte authenticator. After calling finish, the underlying
implementation will zero out `ctx`.

`void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);`

where `mac` is the buffer which receives the 16 byte authenticator,

`m` is a pointer to the message to be processed,

`bytes` is the number of bytes in the message, and

`key` is the 32 byte key that is **only used for this message and is discarded immediately after**.

`int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);`

where `mac1` is compared to `mac2` in constant time and returns `1` if they are equal and `0` if they are not

`int poly1305_power_on_self_test(void);`

tests the underlying implementation to verify it is working correctly. It returns `1` if all tests pass, and `0` if
any tests fail.

## Example

### Simple

    #include "poly1305-donna.h"

    unsigned char key[32] = {...}, mac[16];
    unsigned char msg[] = {...};

    poly1305_auth(mac, msg, msglen, key);

### Full

[example-poly1305.c](example-poly1305.c) is a simple example of how to verify the underlying implementation is producing
the correct results, compute an authenticator, and test it against an expected value.

# LICENSE

[MIT](http://www.opensource.org/licenses/mit-license.php) or PUBLIC DOMAIN


# NAMESAKE

I borrowed the idea for these from Adam Langley's [curve25519-donna](http://github.com/agl/curve25519-donna), hence
the name.