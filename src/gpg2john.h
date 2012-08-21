/*
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CRYPTUTILS_H_
#define CRYPTUTILS_H_

#include <openssl/sha.h>
#include "stdint.h"

namespace CryptUtils
{

typedef enum {
	PKA_UNKOWN = 0,
	PKA_RSA_ENCSIGN = 1,
	PKA_DSA = 17
} PublicKeyAlgorithm;

typedef enum {
	CIPHER_UNKOWN = -1,
	CIPHER_CAST5 = 3,
	CIPHER_BLOWFISH = 4,
	CIPHER_AES128 = 7,
	CIPHER_AES192 = 8,
	CIPHER_AES256 = 9
} CipherAlgorithm;

typedef enum {
	HASH_UNKOWN = -1,
	HASH_MD5 = 1,
	HASH_SHA1 = 2,
	HASH_RIPEMD160 = 3,
	HASH_SHA256 = 8,
	HASH_SHA384 = 9,
	HASH_SHA512 = 10,
	HASH_SHA224 = 11
} HashAlgorithm;


uint32_t blockSize(CipherAlgorithm algorithm);
uint32_t keySize(CipherAlgorithm algorithm);
uint32_t digestSize(HashAlgorithm algorithm);

} // namespace CryptUtils


#endif // CRYPTUTILS_H_

#ifndef STRING2KEY_H_
#define STRING2KEY_H_

class Memblock;
class PIStream;
class POStream;

class S2KGenerator;


class String2Key
{
	public:
		typedef enum {
			SPEC_SIMPLE = 0,
			SPEC_SALTED = 1,
			SPEC_ITERATED_SALTED = 3
		} Spec;

	public:
		String2Key();
		String2Key(const String2Key &other);
		~String2Key();

		uint8_t usage() const;
		Spec spec() const;

		CryptUtils::HashAlgorithm hashAlgorithm() const;
		const uint8_t *salt() const;
		int32_t count() const;

		CryptUtils::CipherAlgorithm cipherAlgorithm() const;
		const uint8_t *ivec() const;

		void generateKey(const Memblock &string, uint8_t *key, uint32_t length) const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

		String2Key &operator=(const String2Key &other);

		void setupGenerator() const;

		uint8_t m_usage;
		Spec m_spec;
		mutable S2KGenerator *m_keygen;

		CryptUtils::HashAlgorithm m_hashAlgorithm;
		uint8_t m_salt[8];
		int32_t m_count;

		CryptUtils::CipherAlgorithm m_cipherAlgorithm;
		uint8_t *m_iv;
		int bs;


};

// Convenience operators
inline PIStream &operator>>(PIStream &in, String2Key &s2k)
{
	return (s2k << in);
}

inline POStream &operator<<(POStream &out, String2Key &s2k)
{
	return (s2k >> out);
}


#endif // STRING2KEY_H_

#ifndef KEY_H_
#define KEY_H_

#include <openssl/rsa.h>
#include <openssl/dsa.h>

class PIStream;
class POStream;


class Key
{
	public:
		Key();
		Key(const Key &other);
		~Key();

		bool locked() const;
		uint32_t dataLength() const;
		uint32_t bits() const;
		const uint8_t *data() const;
		const String2Key &string2Key() const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

		Key &operator=(const Key &other);

		bool m_locked;
		uint8_t m_version;

		CryptUtils::PublicKeyAlgorithm m_algorithm;
		RSA *m_rsa;
		DSA *m_dsa;

		String2Key m_s2k;
		uint32_t m_datalen;
		uint8_t *m_data;

		uint32_t m_time;
		uint16_t m_expire;
};

// Inlined functions
inline uint32_t Key::bits() const
{
	if (m_rsa) {
		return BN_num_bits(m_rsa->n);
	} else if (m_dsa) {
		return BN_num_bits(m_dsa->p);
	}
	return 0;
}

// Convenience operators
inline PIStream &operator>>(PIStream &in, Key &key)
{
	return (key << in);
}

inline POStream &operator<<(POStream &out, Key &key)
{
	return (key >> out);
}


#endif // KEY_H_

#ifndef PACKETHEADER_H_
#define PACKETHEADER_H_

class PIStream;
class POStream;


class PacketHeader
{
	public:
		typedef enum {
			FORMAT_UNKOWN = -1,
			FORMAT_OLD,
			FORMAT_NEW
		} Format;

		typedef enum {
			TYPE_UNKOWN = -1,
			TYPE_SECRET_KEY = 5,
			TYPE_PUBLIC_KEY = 6
		} Type;

	public:
		PacketHeader();

		bool valid() const;
		Format format() const;
		Type type() const;
		int32_t length() const;

		PIStream &operator<<(PIStream &in);
		POStream &operator>>(POStream &out);

	private:
		Format m_format;
		Type m_type;
		int32_t m_length;
};


// Convenience operators
inline PIStream &operator>>(PIStream &in, PacketHeader &header)
{
	return (header << in);
}

inline POStream &operator<<(POStream &out, PacketHeader &header)
{
	return (header >> out);
}


#endif // PACKETHEADER_H_

#ifndef PISTREAM_H_
#define PISTREAM_H_

#include <istream>
#include <openssl/bn.h>

class PacketHeader;


class PIStream
{
	public:
		PIStream(std::istream &stream);

		uint32_t pos() const;
		bool good() const;
		bool bad() const;
		bool fail() const;

		uint32_t read(char *s, uint32_t n);

		PIStream &operator>>(int8_t &i);
		PIStream &operator>>(uint8_t &i);
		PIStream &operator>>(int16_t &i);
		PIStream &operator>>(uint16_t &i);
		PIStream &operator>>(int32_t &i);
		PIStream &operator>>(uint32_t &i);
		PIStream &operator>>(BIGNUM *&b);

	private:
		void dearmor();

	private:
		std::istream &m_in;
		uint32_t m_read;

		bool m_armored;
		int32_t m_b64count;
		uint32_t m_b64buf;
};

// Inlined functions
inline bool PIStream::good() const
{
	return m_in.good();
}

inline bool PIStream::bad() const
{
	return m_in.bad();
}

inline bool PIStream::fail() const
{
	return m_in.fail();
}

inline PIStream &PIStream::operator>>(uint8_t &i)
{
	return (*this >> reinterpret_cast<int8_t &>(i));
}

inline PIStream &PIStream::operator>>(uint16_t &i)
{
	return (*this >> reinterpret_cast<int16_t &>(i));
}

inline PIStream &PIStream::operator>>(uint32_t &i)
{
	return (*this >> reinterpret_cast<int32_t &>(i));
}


#endif // PISTREAM_H_

#ifndef UTILS_H_
#define UTILS_H_


#include <map>
#include <string>
#include <vector>

namespace Utils
{

bool str2int(const std::string &str, int32_t *i);
bool str2int(const std::string &str, uint32_t *i);
std::string int2str(int32_t i);

void trim(std::string *str);
std::string trim(const std::string &str);
std::vector<std::string> split(const std::string &str, const std::string &token);

std::string strprintf(const char *format, ...);

std::string defaultOption(const std::map<std::string, std::string> &options, const std::string name, const std::string &def);
int32_t defaultOption(const std::map<std::string, std::string> &options, const std::string name, int32_t def);

} // namespace Utils


#endif // UTILS_H_
