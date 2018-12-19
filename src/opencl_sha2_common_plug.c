/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 *
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL


/*
 * Public domain hash function by DJ Bernstein
 * We are hashing almost the entire struct
 */
int common_salt_hash(void * salt, int salt_size, int salt_hash_size)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < salt_size; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (salt_hash_size - 1);
}

#endif /* HAVE_OPENCL */
