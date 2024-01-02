# blake2_mjosref

29-Jan-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

This is just an another -- somewhat smaller -- implementation of BLAKE2,
written while working on the RFC text. Some stuff regarding parameter
handling has been simplified. The API is little different from the
original Reference implementation (after consultation with BLAKE2 authors).

See [blake2.net](https://blake2.net) for more information.

# OpenCL

This is a trivial port from C to OpenCL by Solar Designer.

The filenames of original blake2_mjosref have been preserved to allow for easy
"diff -ur" against the original.
