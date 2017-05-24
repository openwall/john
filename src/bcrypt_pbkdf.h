int bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt, size_t
		saltlen, uint8_t *key, size_t keylen, unsigned int rounds);
