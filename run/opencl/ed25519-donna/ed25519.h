#ifndef ED25519_H
#define ED25519_H

typedef unsigned char ed25519_public_key[32];
//typedef unsigned char ed25519_secret_key[32];
typedef unsigned char *ed25519_secret_key;

typedef unsigned char curved25519_key[32];

void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);

#endif // ED25519_H
