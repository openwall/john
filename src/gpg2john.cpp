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

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <cstdio>
#include <cstdlib>
#include "gpg2john.h"

namespace CryptUtils
{

// Returns the block size (in bytes) of a given cipher
uint32_t blockSize(CipherAlgorithm algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_BLOCK;
		case CIPHER_BLOWFISH:
			return BF_BLOCK;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256:
			return AES_BLOCK_SIZE;

		default: break;
	}

	return 0;
}

// Returns the key size (in bytes) of a given cipher
uint32_t keySize(CipherAlgorithm algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_KEY_LENGTH;
		case CIPHER_BLOWFISH:
			return 16;
		case CIPHER_AES128:
			return 16;
		case CIPHER_AES192:
			return 24;
		case CIPHER_AES256:
			return 32;

		default: break;
	}

	return 0;
}

// Returns the digest size (in bytes) of a given hash algorithm
uint32_t digestSize(HashAlgorithm algorithm)
{
	switch (algorithm) {
		case HASH_MD5:
			return 16;
		case HASH_SHA1:
			return 20;
		case HASH_SHA512:
			return 64;
		case HASH_SHA256:
			return 32;
		case HASH_RIPEMD160:
			return 20;
		default: fprintf(stderr, "hash algorithm (%d) is not supported!\n", algorithm);
			 exit(-1);
	}

	return 0;
}

} // namespace CryptUtils

#include <cstring>
#include <ostream>

class Memblock
{
	public:
		Memblock();
		Memblock(const char *string);
		Memblock(const Memblock &other);
		~Memblock();

		void resize(uint32_t n);

		Memblock &operator=(const Memblock &other);
		Memblock &operator+=(const Memblock &other);

	public: // By intention
		uint8_t *data;
		uint32_t length;

	private:
		uint32_t m_alloced;
};


// Inlined functions
inline Memblock::Memblock()
	: data(NULL), length(0), m_alloced(0)
{

}

inline Memblock::Memblock(const char *string)
{
	length = strlen(string);
	data = new uint8_t[length+1];
	data[length] = 0x00;
	memcpy(data, string, length);
	m_alloced = length+1;
}

inline Memblock::Memblock(const Memblock &other)
	: data(NULL), length(0), m_alloced(0)
{
	*this = other;
}

inline Memblock::~Memblock()
{
	delete[] data;
}

inline void Memblock::resize(uint32_t n)
{
	if (data == NULL) {
		data = new uint8_t[n+1];
		data[n] = 0x00;
		m_alloced = n+1;
		length = n;
		return;
	}

	if (m_alloced < n+1) {
		uint8_t *tmp = data;
		data = new uint8_t[n+1];
		data[n] = 0x00;
		m_alloced = n+1;
		memcpy(data, tmp, length+1);
		delete[] tmp;
	}
	length = n;
}

inline Memblock &Memblock::operator=(const Memblock &other)
{
	if (this == &other) {
		return *this;
	}

	if (other.data == NULL) {
		delete[] data;
		data = NULL;
		length = 0;
		m_alloced = 0;
		return *this;
	}

	if (m_alloced < other.length+1) {
		delete[] data;
		data = new uint8_t[other.length+1];
		data[other.length] = 0x00;
		m_alloced = other.length+1;
	}

	memcpy(data, other.data, other.length);
	length = other.length;
	return *this;
}

inline Memblock &Memblock::operator+=(const Memblock &other)
{
	if (this == &other || other.data == NULL || other.length == 0) {
		return *this;
	}

	uint32_t oldlen = length;
	resize(length + other.length);
	memcpy(data + oldlen, other.data, other.length);
	return *this;
}


// Convenience functions
inline std::ostream& operator<<(std::ostream &out, const Memblock &in)
{
	out << in.data;
	return out;
}

#include <iostream>
#include <cstring>


// Constructor
Key::Key()
	: m_version(255), m_algorithm(CryptUtils::PKA_UNKOWN), m_rsa(NULL), m_dsa(NULL),
	  m_datalen(0), m_data(NULL), m_expire(0)
{

}

// Copy constructor
Key::Key(const Key &other)
	: m_rsa(NULL), m_dsa(NULL), m_data(NULL)
{
	*this = other;
}

// Destructor
Key::~Key()
{
	if (m_rsa) {
		RSA_free(m_rsa);
	}
	if (m_dsa) {
		DSA_free(m_dsa);
	}

	delete[] m_data;
}

// Query functions
bool Key::locked() const
{
	return m_locked;
}

uint32_t Key::dataLength() const
{
	return m_datalen;
}

const uint8_t *Key::data() const
{
	return m_data;
}

const String2Key &Key::string2Key() const
{
	return m_s2k;
}

// Reads a key data from a stream
PIStream &Key::operator<<(PIStream &in)
{
	// Read packet header
	PacketHeader header;
	in >> header;
	if (!header.valid()) {
		throw "Invalid packet header";
	}
	if (header.type() != PacketHeader::TYPE_SECRET_KEY) {
		throw Utils::strprintf("Invalid packet type %d (not a secret key)", header.type());
	}
	uint32_t headerOff = in.pos();

	// Read public key
	in >> m_version;
	if (m_version != 3 && m_version != 4) {
		throw Utils::strprintf("Unsupported key version %d", m_version);
	}
	in >> m_time;
	if (m_version == 3) {
		in >> m_expire;
	}
	uint8_t tmp;
	in >> tmp; m_algorithm = (CryptUtils::PublicKeyAlgorithm)tmp;
	if (m_algorithm == CryptUtils::PKA_RSA_ENCSIGN) {
		m_rsa = RSA_new();
		in >> m_rsa->n;
		in >> m_rsa->e;
	} else if (m_algorithm == CryptUtils::PKA_DSA) {
		m_dsa = DSA_new();
		in >> m_dsa->p;
		in >> m_dsa->q;
		in >> m_dsa->g;
		in >> m_dsa->pub_key;
	} else {
		throw Utils::strprintf("Unsupported public-key algorithm %d", m_algorithm);
	}

	// Read private key
	in >> m_s2k;
	if (m_s2k.usage() != 0) {
		// Encrypted
		m_datalen = header.length() - in.pos() + headerOff;
		m_data = new uint8_t[m_datalen];
		if (in.read((char *)m_data, m_datalen) != m_datalen) {
			throw "Premature end of data stream";
		}
	} else {
		// Plaintext
		if (m_algorithm == CryptUtils::PKA_RSA_ENCSIGN) {
			in >> m_rsa->d;
			in >> m_rsa->p;
			in >> m_rsa->q;
			in >> m_rsa->iqmp;
		} else if (m_algorithm == CryptUtils::PKA_DSA) {
			in >> m_dsa->priv_key;
		}
	}

	m_locked = (m_s2k.usage() != 0);

	return in;
}

// Assignment operator
Key &Key::operator=(const Key &other)
{
	m_locked = other.m_locked;
	m_version = other.m_version;

	m_algorithm = other.m_algorithm;

	if (other.m_rsa) {
		m_rsa = RSA_new();
		m_rsa->n = BN_dup(other.m_rsa->n);
		m_rsa->e = BN_dup(other.m_rsa->e);
		if (!other.m_locked) {
			m_rsa->d = BN_dup(other.m_rsa->d);
			m_rsa->p = BN_dup(other.m_rsa->p);
			m_rsa->q = BN_dup(other.m_rsa->q);
			m_rsa->iqmp = BN_dup(other.m_rsa->iqmp);
		}
	} else if (m_rsa) {
		RSA_free(m_rsa);
		m_rsa = NULL;
	}

	if (other.m_dsa) {
		m_dsa = DSA_new();
		m_dsa->p = BN_dup(other.m_dsa->p);
		m_dsa->q = BN_dup(other.m_dsa->q);
		m_dsa->g = BN_dup(other.m_dsa->g);
		m_dsa->pub_key = BN_dup(other.m_dsa->pub_key);
		if (!other.m_locked) {
			m_dsa->priv_key = BN_dup(other.m_dsa->priv_key);
		}
	} else if (m_dsa) {
		DSA_free(m_dsa);
		m_dsa = NULL;
	}

	m_s2k = other.m_s2k;
	m_datalen = other.m_datalen;
	delete[] m_data;
	if (m_s2k.usage() != 0) {
		m_data = new uint8_t[m_datalen];
		memcpy(m_data, other.m_data, m_datalen);
	} else {
		m_data = NULL;
	}

	m_time = other.m_time;
	m_expire = other.m_expire;

	return *this;
}

// Constructor
PacketHeader::PacketHeader()
	: m_format(FORMAT_UNKOWN), m_type(TYPE_UNKOWN), m_length(-1)
{

}

// Query functions
bool PacketHeader::valid() const
{
	return (m_length > 0);
}

PacketHeader::Format PacketHeader::format() const
{
	return m_format;
}

PacketHeader::Type PacketHeader::type() const
{
	return m_type;
}

int32_t PacketHeader::length() const
{
	return m_length;
}

// Reads the header from a stream
PIStream &PacketHeader::operator<<(PIStream &in)
{
	uint8_t byte;
	in >> byte;
	if (byte & 0x40) {
		m_format = FORMAT_NEW;
		m_type = (Type)(byte & 0x3F);

		// TODO: This is currently UNTESTED!
		in >> byte;
		if (byte < 192) {
			m_length = byte;
		} else if (byte < 224) {
			m_length = (byte - 192) << 8;
			in >> byte;
			m_length += (int32_t)byte + 192;
		} else if (byte == 255) {
			in >> m_length;
		} else {
			m_length = -1;
		}
	} else {
		m_format = FORMAT_OLD;
		m_type = (Type)((byte & 0x3C) >> 2);

		switch (byte & 0x03) {
			case 0: {
				uint8_t t;
				in >> t;
				m_length = (int32_t)t;
				break;
			}
			case 1: {
				uint16_t t;
				in >> t;
				m_length = (int32_t)t;
				break;
			}
			case 2: {
				in >> m_length;
				break;
			}
			case 3:
			default: {
				// This is currently unsupported
				m_length = -1;
				break;
			}
		}
	}

	return in;
}

#include <cstring>

// Constructor
PIStream::PIStream(std::istream &stream)
	: m_in(stream), m_read(0), m_armored(false),
	  m_b64count(0), m_b64buf(0)
{
	// Check if the stream is armored. This isn't done
	int32_t b1 = m_in.get();
	int32_t b2 = m_in.peek();
	m_in.unget();
	if (b1 == '-' && b2 == '-') {
		m_armored = true;
		dearmor();
	}
}

// Returns the current stream position
uint32_t PIStream::pos() const
{
	return m_read;
}

// Reads binary data from the (possibly armored) stream
uint32_t PIStream::read(char *s, uint32_t n)
{
	if (!m_armored) {
		m_in.read(s, n);
		m_read += m_in.gcount();
		return m_in.gcount();
	}

	// The Base64 decoding is taken from Qt, again
	uint32_t br = 0;
	while (br < n && m_in.good()) {
		int32_t ch = m_in.get();

		// Decode
		int32_t d;
		if (ch >= 'A' && ch <= 'Z') {
			d = ch - 'A';
		} else if (ch >= 'a' && ch <= 'z') {
			d = ch - 'a' + 26;
		} else if (ch >= '0' && ch <= '9') {
			d = ch - '0' + 52;
		} else if (ch == '+') {
			d = 62;
		} else if (ch == '/') {
			d = 63;
		} else {
			d = -1;
		}

		if (d != -1) {
			m_b64buf = (m_b64buf << 6) | d;
			m_b64count += 6;
			if (m_b64count >= 8) {
				m_b64count -= 8;
				s[br++] = (m_b64buf >> m_b64count);
				m_b64buf &= ((1 << m_b64count) - 1);
			}
		}
	}

	m_read += br;
	return br;
}

// Data extraction operators
PIStream &PIStream::operator>>(int8_t &i)
{
	if (read((char *)&i, 1) != 1) {
		throw "Premature end of data stream";
	}
	return *this;
}

PIStream &PIStream::operator>>(int16_t &i)
{
	// PGP values are big endian
#ifdef WORDS_BIGENDIAN
	if (read((char *)&i, 2) != 2) {
		throw "Premature end of data stream";
	}
#else
	// From Qt
	union {
		int16_t v1;
		char v2[2];
	} t;
	char block[2];
	if (read(block, 2) != 2) {
		throw "Premature end of data stream";
	}
	t.v2[0] = block[1];
	t.v2[1] = block[0];
	i = t.v1;
#endif
	return *this;
}

PIStream &PIStream::operator>>(int32_t &i)
{
	// PGP values are big endian
#ifdef WORDS_BIGENDIAN
	if (read((char *)&i, 4) != 4) {
		throw "Premature end of data stream";
	}
#else
	// From Qt
	union {
		int32_t v1;
		char v2[4];
	} t;
	char block[4];
	if (read(block, 4) != 4) {
		throw "Premature end of data stream";
	}
	t.v2[0] = block[3];
	t.v2[1] = block[2];
	t.v2[2] = block[1];
	t.v2[3] = block[0];
	i = t.v1;
#endif
	return *this;
}

PIStream &PIStream::operator>>(BIGNUM *&b)
{
	uint16_t length;
	*this >> length;
	length = (length + 7) / 8; // Length in bits -> length in bytes

	uint8_t *buffer = new uint8_t[length];
	memset(buffer, 0x00, length);
	if (read((char *)buffer, length) != length) {
		throw "Premature end of data stream";
	}
	b = BN_bin2bn(buffer, length, b);
	delete[] buffer;

	return *this;
}

// Strips the ASCII armor headers from a stream
void PIStream::dearmor()
{
	char buffer[255];
	do {
		m_in.getline(buffer, 254);
	} while (m_in.good() && buffer[0] != 0);
}

#include <cassert>
#include <cstring>
#include <iostream>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define KEYBUFFER_LENGTH 8192


// Key generator base class
class S2KGenerator
{
	public:
		virtual ~S2KGenerator() { }
		virtual void genkey(const Memblock &string, uint8_t *key, uint32_t length) const = 0;
};

// Constructor
String2Key::String2Key()
	: m_spec(SPEC_SIMPLE), m_keygen(NULL), m_hashAlgorithm(CryptUtils::HASH_UNKOWN),
	  m_cipherAlgorithm(CryptUtils::CIPHER_UNKOWN), m_iv(NULL)
{
	memset(m_salt, 0x00, 8);
}

// Copy constructor
String2Key::String2Key(const String2Key &other)
{
	*this = other;
}

// Destructor
String2Key::~String2Key()
{
	delete m_keygen;
	delete[] m_iv;
}

// Query functions
uint8_t String2Key::usage() const
{
	return m_usage;
}

String2Key::Spec String2Key::spec() const
{
	return m_spec;
}

CryptUtils::HashAlgorithm String2Key::hashAlgorithm() const
{
	return m_hashAlgorithm;
}

const uint8_t *String2Key::salt() const
{
	return m_salt;
}

int32_t String2Key::count() const
{
	return m_count;
}

CryptUtils::CipherAlgorithm String2Key::cipherAlgorithm() const
{
	return m_cipherAlgorithm;
}

const uint8_t *String2Key::ivec() const
{
	return m_iv;
}

// Reads S2K data from a stream
PIStream &String2Key::operator<<(PIStream &in)
{
	// Read usage and spec info
	in >> m_usage;
	if (m_usage == 254 || m_usage == 255) {
		uint8_t tmp;
		in >> tmp; m_cipherAlgorithm = (CryptUtils::CipherAlgorithm)tmp;
		in >> tmp; m_spec = (Spec)tmp;
		in >> tmp; m_hashAlgorithm = (CryptUtils::HashAlgorithm)tmp;
		switch (m_spec) {
			case SPEC_SALTED:
				in.read((char *)m_salt, 8);
				break;

			case SPEC_ITERATED_SALTED: {
				in.read((char *)m_salt, 8);
				uint8_t t;
				in >> t;
				m_count = ((int32_t)16 + (t & 15)) << ((t >> 4) + 6);
			}
			break;

			case SPEC_SIMPLE:
				break;

			default:
				throw "Unknown String2Key spec";
		}
	} else if (m_usage != 0) {
		uint8_t tmp;
		in >> tmp; m_cipherAlgorithm = (CryptUtils::CipherAlgorithm)tmp;
		m_spec = SPEC_SIMPLE;
	}

	// Read cipher initialization vector
	if (m_usage != 0) {
		bs = CryptUtils::blockSize(m_cipherAlgorithm);
		m_iv = new uint8_t[bs];
		in.read((char *)m_iv, bs);
	}
	return in;
}

// Assignment operator
String2Key &String2Key::operator=(const String2Key &other)
{
	m_usage = other.m_usage;
	m_spec = other.m_spec;

	m_hashAlgorithm = other.m_hashAlgorithm;
	memcpy(m_salt, other.m_salt, 8);
	m_count = other.m_count;

	m_cipherAlgorithm = other.m_cipherAlgorithm;

	delete[] m_iv;
	uint32_t bs = CryptUtils::blockSize(m_cipherAlgorithm);
	m_iv = new uint8_t[bs];
	memcpy(m_iv, other.m_iv, bs);

	return *this;
}

#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>

namespace Utils
{

// Wrapper for strtol()
template<typename T>
static bool tstr2int(const std::string &str, T *i)
{
	char *end;
	long val = strtol(str.c_str(), &end, 0);

	if (errno == ERANGE || str.c_str() == end
	    || val > std::numeric_limits<int32_t>::max()
	    || val < std::numeric_limits<int32_t>::min()) {
		return false;
	}

	*i = (T)val;
	return true;
}

// Wrapper for strtol()
bool str2int(const std::string &str, int32_t *i)
{
	return tstr2int<int32_t>(str, i);
}

// Wrapper for strtol()
bool str2int(const std::string &str, uint32_t *i)
{
	return tstr2int<uint32_t>(str, i);
}

// Converts an interger to a string
std::string int2str(int32_t i)
{
	std::stringstream out;
	out << i;
	return out.str();
}

// Removes white-space characters at the beginning and end of a string
void trim(std::string *str)
{
	int32_t start = 0;
	int32_t end = str->length()-1;

	while (start < end && isspace(str->at(start))) {
		++start;
	}
	while (end > start && isspace(str->at(end))) {
		--end;
	}

	if (start > 0 || end < (int32_t)str->length()) {
		*str = str->substr(start, (end - start + 1));
	}
}

// Removes white-space characters at the beginning and end of a string
std::string trim(const std::string &str)
{
	std::string copy(str);
	trim(&copy);
	return copy;
}

// Split a string using the given token
std::vector<std::string> split(const std::string &str, const std::string &token)
{
	std::vector<std::string> parts;
	size_t index = 0;

	if (token.length() == 0) {
		for (size_t i = 0; i < str.length(); i++) {
			parts.push_back(str.substr(i, 1));
		}
		return parts;
	}

	while (index < str.length()) {
		size_t pos = str.find(token, index);
		parts.push_back(str.substr(index, pos - index));
		if (pos == std::string::npos) {
			break;
		}
		index = pos + token.length();
		if (index == str.length()) {
			parts.push_back("");
		}
	}

	return parts;
}

// sprintf for std::string
std::string strprintf(const char *format, ...)
{
	va_list vl;
	va_start(vl, format);

	std::ostringstream os;

	const char *ptr = format-1;
	while (*(++ptr) != '\0') {
		if (*ptr != '%') {
			os << *ptr;
			continue;
		}

		++ptr;

		// Only a subset of format specifiers is supported
		switch (*ptr) {
			case 'd':
			case 'i':
				os << va_arg(vl, int);
				break;

			case 'c':
				os << (unsigned char)va_arg(vl, int);
				break;

			case 'e':
			case 'E':
			case 'f':
			case 'F':
			case 'g':
			case 'G':
				os << va_arg(vl, double);
				break;

			case 's':
				os << va_arg(vl, const char *);
				break;

			case '%':
				os << '%';
				break;

			default:
#ifndef NDEBUG
				std::cerr << "Error in strprintf(): unknown format specifier " << *ptr << std::endl;
				exit(1);
#endif
				break;
		}
	}

	va_end(vl);
	return os.str();
}

// Returns an option from the given map or a default value
std::string defaultOption(const std::map<std::string, std::string> &options, const std::string name, const std::string &def)
{
	std::map<std::string, std::string>::const_iterator it = options.find(name);
	if (it != options.end()) {
		return (*it).second;
	} else {
		return def;
	}
}

// Returns an option from the given map or a default value
int32_t defaultOption(const std::map<std::string, std::string> &options, const std::string name, int32_t def)
{
	int32_t i = 0;
	if (str2int(defaultOption(options, name, int2str(def)), &i)) {
		return i;
	} else {
		return def;
	}
}

} // namespace Utils

#include <cstdlib>
#include <fstream>
#include <iostream>

using namespace std;

#define N 128

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

enum {
	SPEC_SIMPLE = 0,
	SPEC_SALTED = 1,
	SPEC_ITERATED_SALTED = 3
};

int main(int argc, char **argv)
{
	if(argc < 2) {
		fprintf(stderr, "Usage: %s <GPG Secret Key File>\n", argv[0]);
		exit(-1);
	}

	ifstream inStream;
	inStream.open(argv[1]);
	Key key;
	try {
		PIStream in(inStream);
		in >> key;
	} catch(const std::string & str) {
		std::cerr << "Exception while parsing key: " << str << std::
		    endl;
		return EXIT_FAILURE;
	}
	catch(const char *cstr) {
		std::cerr << "Exception while parsing key: " << cstr << std::
		    endl;
		return EXIT_FAILURE;
	}

	if (!key.locked()) {
		std::
		    cerr << "Err, this secret key doesn't seem to be encrypted"
		    << std::endl;
		return EXIT_FAILURE;
	}
	const String2Key &s2k = key.string2Key();
	printf("%s:$gpg$*%d*%d*%d*", argv[1], key.m_algorithm, key.m_datalen, key.bits());
	print_hex(key.m_data, key.m_datalen);
	printf("*%d*%d*%d*%d*%d*", s2k.m_spec, s2k.m_usage, s2k.m_hashAlgorithm, s2k.m_cipherAlgorithm, s2k.bs);
	print_hex(s2k.m_iv, s2k.bs);
	switch(s2k.m_spec) {
		case SPEC_SIMPLE:
			break;
		case SPEC_SALTED:
			printf("*0*");
			print_hex((unsigned char*)s2k.m_salt, 8);

		case SPEC_ITERATED_SALTED:
			printf("*%d*", s2k.m_count);
			print_hex((unsigned char*)s2k.m_salt, 8);
			break;
	}
	printf("\n");
	exit(1);
}
