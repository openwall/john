/*  Authored by Jeremi Gosney, 2014
    Placed in the public domain.
 */

#pragma once

extern char *pf_gensalt (const unsigned char *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);
extern char *pufferfish_easy (const char *pass, unsigned int t_cost, unsigned int m_cost);
extern int pufferfish_validate (const char *pass, char *correct_hash);
extern unsigned char *pfkdf (unsigned int outlen, const char *pass, unsigned int t_cost, unsigned int m_cost);
extern int PHS (void *out, size_t outlen, const void *in, size_t inlen, const void *salt, size_t saltlen, unsigned int t_cost, unsigned int m_cost);
