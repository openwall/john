#!/usr/bin/env python

# Copyright (C) 2012, Dhiru Kholia <dhiru@openwall.com>
#
# Modified for JtR
#
# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import traceback
import binascii
import base64
import sys
try:
    from hashlib import md5 as MD5
except ImportError:
    from md5 import md5 as MD5

limited = True  # set to False for "development" mode!

PY3 = sys.version_info[0] == 3
if PY3:
    from io import StringIO
else:
    from StringIO import StringIO

class Object(object):
    pass

try:
    from Crypto.Cipher import DES3, AES
except ImportError:
    AES = Object()
    AES.MODE_CBC = ""
    DES3 = Object()
    DES3.MODE_CBC = ""
    limited = True


class BERException (Exception):
    pass


class BER(object):
    """
    Robey's tiny little attempt at a BER decoder.
    """

    def __init__(self, content=''):
        self.content = content
        self.idx = 0

    def __str__(self):
        return self.content

    def __repr__(self):
        return 'BER(\'' + repr(self.content) + '\')'

    def decode(self):
        return self.decode_next()

    def decode_next(self):
        if self.idx >= len(self.content):
            return None
        ident = ord(self.content[self.idx])
        self.idx += 1
        if (ident & 31) == 31:
            # identifier > 30
            ident = 0
            while self.idx < len(self.content):
                t = ord(self.content[self.idx])
                self.idx += 1
                ident = (ident << 7) | (t & 0x7f)
                if not (t & 0x80):
                    break
        if self.idx >= len(self.content):
            return None
        # now fetch length
        size = ord(self.content[self.idx])
        self.idx += 1
        if size & 0x80:
            # more complimicated...
            # FIXME: theoretically should handle indefinite-length (0x80)
            t = size & 0x7f
            if self.idx + t > len(self.content):
                return None
            size = inflate_long(self.content[self.idx: self.idx + t], True)
            self.idx += t
        if self.idx + size > len(self.content):
            # can't fit
            return None
        data = self.content[self.idx: self.idx + size]
        self.idx += size
        # now switch on id
        if ident == 0x30:
            # sequence
            return self.decode_sequence(data)
        elif ident == 2:
            # int
            return inflate_long(data)
        else:
            # 1: boolean (00 false, otherwise true)
            raise BERException('Unknown ber encoding type %d (robey is lazy)' % ident)

    def decode_sequence(data):
        out = []
        b = BER(data)
        while True:
            x = b.decode_next()
            if x is None:
                break
            out.append(x)
        return out
    decode_sequence = staticmethod(decode_sequence)


class SSHException (Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """
    pass


class AuthenticationException (SSHException):
    """
    Exception raised when authentication failed for some reason.  It may be
    possible to retry with different credentials.  (Other classes specify more
    specific reasons.)

    @since: 1.6
    """
    pass


class PasswordRequiredException (AuthenticationException):
    """
    Exception raised when a password is needed to unlock a private key file.
    """
    pass


class BadAuthenticationType (AuthenticationException):
    """
    Exception raised when an authentication type (like password) is used, but
    the server isn't allowing that type.  (It may only allow public-key, for
    example.)

    @ivar allowed_types: list of allowed authentication types provided by the
        server (possible values are: C{"none"}, C{"password"}, and
        C{"publickey"}).
    @type allowed_types: list

    @since: 1.1
    """
    allowed_types = []

    def __init__(self, explanation, types):
        AuthenticationException.__init__(self, explanation)
        self.allowed_types = types

    def __str__(self):
        return SSHException.__str__(self) + ' (allowed_types=%r)' % self.allowed_types


class PartialAuthentication (AuthenticationException):
    """
    An internal exception thrown in the case of partial authentication.
    """
    allowed_types = []

    def __init__(self, types):
        AuthenticationException.__init__(self, 'partial authentication')
        self.allowed_types = types


class ChannelException (SSHException):
    """
    Exception raised when an attempt to open a new L{Channel} fails.

    @ivar code: the error code returned by the server
    @type code: int

    @since: 1.6
    """
    def __init__(self, code, text):
        SSHException.__init__(self, text)
        self.code = code


class BadHostKeyException (SSHException):
    """
    The host key given by the SSH server did not match what we were expecting.

    @ivar hostname: the hostname of the SSH server
    @type hostname: str
    @ivar key: the host key presented by the server
    @type key: L{PKey}
    @ivar expected_key: the host key expected
    @type expected_key: L{PKey}

    @since: 1.6
    """
    def __init__(self, hostname, got_key, expected_key):
        SSHException.__init__(self, 'Host key for server %s does not match!' % hostname)
        self.hostname = hostname
        self.key = got_key
        self.expected_key = expected_key


from binascii import hexlify, unhexlify
import struct


def inflate_long(s, always_positive=False):
    """turns a normalized byte string into a long-int
    (adapted from Crypto.Util.number)"""
    out = 0
    negative = 0
    if not always_positive and (len(s) > 0) and (ord(s[0]) >= 0x80):
        negative = 1
    if len(s) % 4:
        filler = '\x00'
        if negative:
            filler = '\xff'
        s = filler * (4 - len(s) % 4) + s
    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack('>I', s[i:i + 4])[0]
    if negative:
        out -= (1 << (8 * len(s)))
    return out


def deflate_long(n, add_sign_padding=True):
    "turns a long-int into a normalized byte string (adapted from Crypto.Util.number)"
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    while (n != 0) and (n != -1):
        s = struct.pack('>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros, FFs
    for i in enumerate(s):
        if (n == 0) and (i[1] != '\000'):
            break
        if (n == -1) and (i[1] != '\xff'):
            break
    else:
        # degenerate case, n was either 0 or -1
        i = (0,)
        if n == 0:
            s = '\000'
        else:
            s = '\xff'
    s = s[i[0]:]
    if add_sign_padding:
        if (n == 0) and (ord(s[0]) >= 0x80):
            s = '\x00' + s
        if (n == -1) and (ord(s[0]) < 0x80):
            s = '\xff' + s
    return s


def format_binary_weird(data):
    out = ''
    for i in enumerate(data):
        out += '%02X' % ord(i[1])
        if i[0] % 2:
            out += ' '
        if i[0] % 16 == 15:
            out += '\n'
    return out


def format_binary(data, prefix=''):
    x = 0
    out = []
    while len(data) > x + 16:
        out.append(format_binary_line(data[x:x + 16]))
        x += 16
    if x < len(data):
        out.append(format_binary_line(data[x:]))
    return [prefix + y for y in out]


def format_binary_line(data):
    left = ' '.join(['%02X' % ord(c) for c in data])
    right = ''.join([('.%c..' % c)[(ord(c) + 63) // 95] for c in data])
    return '%-50s %s' % (left, right)


def hexify(s):
    return hexlify(s).upper()


def unhexify(s):
    return unhexlify(s)


def safe_string(s):
    out = ''
    for c in s:
        if (ord(c) >= 32) and (ord(c) <= 127):
            out += c
        else:
            out += '%%%02X' % ord(c)
    return out


def bit_length(n):
    norm = deflate_long(n, 0)
    hbyte = ord(norm[0])
    if hbyte == 0:
        return 1
    bitlen = len(norm) * 8
    while not (hbyte & 0x80):
        hbyte <<= 1
        bitlen -= 1
    return bitlen


def tb_strings():
    return ''.join(traceback.format_exception(*sys.exc_info())).split('\n')


def generate_key_bytes(hashclass, salt, key, nbytes):
    """
    Given a password, passphrase, or other human-source key, scramble it
    through a secure hash into some keyworthy bytes.  This specific algorithm
    is used for encrypting/decrypting private key files.

    @param hashclass: class from L{Crypto.Hash} that can be used as a secure
        hashing function (like C{MD5} or C{SHA}).
    @type hashclass: L{Crypto.Hash}
    @param salt: data to salt the hash with.
    @type salt: string
    @param key: human-entered password or passphrase.
    @type key: string
    @param nbytes: number of bytes to generate.
    @type nbytes: int
    @return: key data
    @rtype: string
    """
    keydata = ''
    digest = ''
    if len(salt) > 8:
        salt = salt[:8]
    while nbytes > 0:
        hash_obj = hashclass()
        if len(digest) > 0:
            hash_obj.update(digest)
        hash_obj.update(key)
        hash_obj.update(salt)
        digest = hash_obj.digest()
        size = min(nbytes, len(digest))
        keydata += digest[:size]
        nbytes -= size
    return keydata

"""
Common API for all public keys.
"""


class PKey (object):
    """
    Base class for public keys.
    """

    # known encryption types for private key files:
    _CIPHER_TABLE = {
        'AES-128-CBC': {'cipher': AES, 'keysize': 16, 'blocksize': 16, 'mode': AES.MODE_CBC},
        'DES-EDE3-CBC': {'cipher': DES3, 'keysize': 24, 'blocksize': 8, 'mode': DES3.MODE_CBC},
        'AES-256-CBC': {'cipher': AES, 'keysize': 32, 'blocksize': 16, 'mode': AES.MODE_CBC},
    }

    def __init__(self, msg=None, data=None):
        """
        Create a new instance of this public key type.  If C{msg} is given,
        the key's public part(s) will be filled in from the message.  If
        C{data} is given, the key's public part(s) will be filled in from
        the string.

        @param msg: an optional SSH L{Message} containing a public key of this
        type.
        @type msg: L{Message}
        @param data: an optional string containing a public key of this type
        @type data: str

        @raise SSHException: if a key cannot be created from the C{data} or
        C{msg} given, or no key was passed in.
        """
        pass

    def __str__(self):
        """
        Return a string of an SSH L{Message} made up of the public part(s) of
        this key.  This string is suitable for passing to L{__init__} to
        re-create the key object later.

        @return: string representation of an SSH key message.
        @rtype: str
        """
        return ''

    def __cmp__(self, other):
        """
        Compare this key to another.  Returns 0 if this key is equivalent to
        the given key, or non-0 if they are different.  Only the public parts
        of the key are compared, so a public key will compare equal to its
        corresponding private key.

        @param other: key to compare to.
        @type other: L{PKey}
        @return: 0 if the two keys are equivalent, non-0 otherwise.
        @rtype: int
        """
        hs = hash(self)
        ho = hash(other)
        if hs != ho:
            return cmp(hs, ho)
        return cmp(str(self), str(other))

    def get_name(self):
        """
        Return the name of this private key implementation.

        @return: name of this private key type, in SSH terminology (for
        example, C{"ssh-rsa"}).
        @rtype: str
        """
        return ''

    def get_bits(self):
        """
        Return the number of significant bits in this key.  This is useful
        for judging the relative security of a key.

        @return: bits in the key.
        @rtype: int
        """
        return 0

    def can_sign(self):
        """
        Return C{True} if this key has the private part necessary for signing
        data.

        @return: C{True} if this is a private key.
        @rtype: bool
        """
        return False

    def get_fingerprint(self):
        """
        Return an MD5 fingerprint of the public part of this key.  Nothing
        secret is revealed.

        @return: a 16-byte string (binary) of the MD5 fingerprint, in SSH
            format.
        @rtype: str
        """
        return MD5.new(str(self)).digest()

    def get_base64(self):
        """
        Return a base64 string containing the public part of this key.  Nothing
        secret is revealed.  This format is compatible with that used to store
        public key files or recognized host keys.

        @return: a base64 string containing the public part of the key.
        @rtype: str
        """
        return base64.encodestring(str(self)).replace('\n', '')

    def sign_ssh_data(self, rng, data):
        """
        Sign a blob of data with this private key, and return a L{Message}
        representing an SSH signature message.

        @param rng: a secure random number generator.
        @type rng: L{Crypto.Util.rng.RandomPool}
        @param data: the data to sign.
        @type data: str
        @return: an SSH signature message.
        @rtype: L{Message}
        """
        return ''

    def verify_ssh_sig(self, data, msg):
        """
        Given a blob of data, and an SSH message representing a signature of
        that data, verify that it was signed with this key.

        @param data: the data that was signed.
        @type data: str
        @param msg: an SSH signature message
        @type msg: L{Message}
        @return: C{True} if the signature verifies correctly; C{False}
            otherwise.
        @rtype: boolean
        """
        return False

    def from_private_key_file(cls, filename, password=None):
        """
        Create a key object by reading a private key file.  If the private
        key is encrypted and C{password} is not C{None}, the given password
        will be used to decrypt the key (otherwise L{PasswordRequiredException}
        is thrown).  Through the magic of python, this factory method will
        exist in all subclasses of PKey (such as L{RSAKey} or L{DSSKey}), but
        is useless on the abstract PKey class.

        @param filename: name of the file to read
        @type filename: str
        @param password: an optional password to use to decrypt the key file,
            if it's encrypted
        @type password: str
        @return: a new key object based on the given private key
        @rtype: L{PKey}

        @raise IOError: if there was an error reading the file
        @raise PasswordRequiredException: if the private key file is
            encrypted, and C{password} is C{None}
        @raise SSHException: if the key file is invalid
        """
        key = cls(filename=filename, password=password)
        return key
    from_private_key_file = classmethod(from_private_key_file)

    def from_private_key(cls, file_obj, password=None):
        """
        Create a key object by reading a private key from a file (or file-like)
        object.  If the private key is encrypted and C{password} is not C{None},
        the given password will be used to decrypt the key (otherwise
        L{PasswordRequiredException} is thrown).

        @param file_obj: the file to read from
        @type file_obj: file
        @param password: an optional password to use to decrypt the key, if it's
            encrypted
        @type password: str
        @return: a new key object based on the given private key
        @rtype: L{PKey}

        @raise IOError: if there was an error reading the key
        @raise PasswordRequiredException: if the private key file is encrypted,
            and C{password} is C{None}
        @raise SSHException: if the key file is invalid
        """
        key = cls(file_obj=file_obj, password=password)
        return key
    from_private_key = classmethod(from_private_key)

    def _read_private_key_file(self, tag, filename, password=None):
        """
        Read an SSH2-format private key file, looking for a string of the type
        C{"BEGIN xxx PRIVATE KEY"} for some C{xxx}, base64-decode the text we
        find, and return it as a string.  If the private key is encrypted and
        C{password} is not C{None}, the given password will be used to decrypt
        the key (otherwise L{PasswordRequiredException} is thrown).

        @param tag: C{"RSA"} or C{"DSA"}, the tag used to mark the data block.
        @type tag: str
        @param filename: name of the file to read.
        @type filename: str
        @param password: an optional password to use to decrypt the key file,
            if it's encrypted.
        @type password: str
        @return: data blob that makes up the private key.
        @rtype: str

        @raise IOError: if there was an error reading the file.
        @raise PasswordRequiredException: if the private key file is
            encrypted, and C{password} is C{None}.
        @raise SSHException: if the key file is invalid.
        """
        try:
            f = open(filename, 'r')
        except IOError:
            e = sys.exc_info()[1]
            sys.stdout.write("%s\n" % str(e))
            return

        data = self._read_private_key(tag, f, password)
        f.close()
        return data

    def _read_private_key(self, tag, f, password=None):
        lines = f.readlines()

        if "BEGIN RSA PRIVATE" in lines[0]:
            tag = "RSA"
            self.type = 0
        elif "-----BEGIN OPENSSH PRIVATE KEY-----" in lines[0]:
            # new private key format for OpenSSH (automatically enabled for
            # keys using ed25519 signatures), ed25519 stuff is not supported
            # yet!
            self.type = 2  # bcrypt pbkdf + aes-256-cbc
        else:
            self.type = 1
            tag = "DSA"

        start = 0
        while (start < len(lines)) and ((lines[start].strip() != '-----BEGIN ' + tag + ' PRIVATE KEY-----') and (lines[start].strip() != '-----BEGIN OPENSSH PRIVATE KEY-----')):
            start += 1
        if start >= len(lines):
            sys.stdout.write("%s is not a valid private key file\n" % f.name)
            return None
        # parse any headers first
        headers = {}
        start += 1
        while start < len(lines):
            l = lines[start].split(': ')
            if len(l) == 1:
                break
            headers[l[0].lower()] = l[1].strip()
            start += 1
        # find end
        end = start
        while ((lines[end].strip() != '-----END OPENSSH PRIVATE KEY-----') and (lines[end].strip() != '-----END ' + tag + ' PRIVATE KEY-----')) and (end < len(lines)):
            end += 1
        # if we trudged to the end of the file, just try to cope.
        try:
            data = ''.join(lines[start:end]).encode()
            data = base64.decodestring(data)
        except base64.binascii.Error:
            e = sys.exc_info()[1]
            raise SSHException('base64 decoding error: ' + str(e))

        if 'proc-type' not in headers and self.type != 2:
            # unencryped: done
            sys.stderr.write("%s has no password!\n" % f.name)
            return None
        # encrypted keyfile: will need a password
        if self.type != 2 and headers['proc-type'] != '4,ENCRYPTED':
            raise SSHException('Unknown private key structure "%s"' % headers['proc-type'])
        try:
            encryption_type, saltstr = headers['dek-info'].split(',')
        except:
            if self.type != 2:
                raise SSHException('Can\'t parse DEK-info in private key file')
            else:
                encryption_type = "AES-256-CBC"
                saltstr = "fefe"
        if encryption_type not in self._CIPHER_TABLE:
            raise SSHException('Unknown private key cipher "%s"' % encryption_type)
        # if no password was passed in, raise an exception pointing out that we need one
        if password is None:
            raise PasswordRequiredException('Private key file is encrypted')
        cipher = self._CIPHER_TABLE[encryption_type]['cipher']
        keysize = self._CIPHER_TABLE[encryption_type]['keysize']
        mode = self._CIPHER_TABLE[encryption_type]['mode']
        salt = unhexlify(saltstr)
        if self.type == 2:
            salt_offset = 47  # XXX is this fixed?
            salt_length = 16
            saltstr = data[salt_offset:salt_offset+salt_length].encode("hex")
        data = binascii.hexlify(data).decode("ascii")
        if keysize == 24:
            self.hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 0,
                len(salt), saltstr, len(data) // 2, data)
        elif keysize == 16:
            self.hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 1, len(saltstr) // 2,
                saltstr, len(data) // 2, data)
        elif keysize == 32 and self.type == 2:  # bcrypt pbkdf + aes-256-cbc
            # round value appears after salt
            rounds = 16
            self.hashline = "%s:$sshng$%s$%s$%s$%s$%s$%d" % (f.name, 2, len(saltstr) // 2,
                saltstr, len(data) // 2, data, rounds)
        else:
            sys.stderr.write("%s uses unsupported cipher, please file a bug!\n" % f.name)
            return None

        if not limited:
            key = generate_key_bytes(MD5, salt, password, keysize)
            data = cipher.new(key, mode, salt).decrypt(data)
            # check encoding
            try:
                d = PKCS7Encoder()
                ddata = d.decode(data)
                return ddata
            except ValueError:  # incorrect password
                return data
        return self.hashline  # dummy value


def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i + n]


class RSADSSKey (PKey):

    def __init__(self, msg=None, data=None, filename=None, password=None, vals=None, file_obj=None):
        self.n = None
        self.e = None
        self.d = None
        self.p = None
        self.q = None
        if file_obj is not None:
            self._from_private_key(file_obj, password)
            return
        if filename is not None:
            self._from_private_key_file(filename, password)
            return
        if vals is not None:
            self.e, self.n = vals
        self.size = bit_length(self.n)

    def __hash__(self):
        h = hash(self.get_name())
        h = h * 37 + hash(self.e)
        h = h * 37 + hash(self.n)
        return hash(h)

    def get_name(self):
        return 'ssh-rsa'

    def get_bits(self):
        return self.size

    ###  internals...

    def _from_private_key_file(self, filename, password):
        data = self._read_private_key_file('RSA', filename, password)

        if not data:
            return
        if limited:
            sys.stdout.write("%s\n" % self.hashline)
            return
        try:
            if self.type == 0:
                self._decode_key(data)
            else:
                self._decode_dss_key(data)
            sys.stderr.write("%s has no password!\n" % filename)
        except SSHException:
            sys.stdout.write("%s\n" % self.hashline)

    def _from_private_key(self, file_obj, password):
        """used for converting older format hashes"""
        data = self._read_private_key('RSA', file_obj, password)
        if limited:
            sys.stdout.write("%s\n" % self.hashline)
            return
        try:
            if self.type == 0:
                self._decode_key(data)
            else:
                self._decode_dss_key(data)
            sys.stderr.write("%s has no password!\n" % file_obj.name)
        except SSHException:
            sys.stdout.write("%s\n" % self.hashline)

    def _decode_key(self, data):
        # private key file contains:
        # RSAPrivateKey = { version = 0, n, e, d, p, q, d mod p-1, d mod q-1, q**-1 mod p }
        try:
            keylist = BER(data).decode()
        except BERException:
            raise SSHException('Unable to parse key file')
        if (type(keylist) is not list) or (len(keylist) < 4) or (keylist[0] != 0):
            raise SSHException('Not a valid RSA private key file (bad ber encoding)')
        self.n = keylist[1]
        self.e = keylist[2]
        self.d = keylist[3]
        # not really needed
        self.p = keylist[4]
        self.q = keylist[5]
        self.size = bit_length(self.n)

    def _decode_dss_key(self, data):
        # private key file contains:
        # DSAPrivateKey = { version = 0, p, q, g, y, x }
        try:
            keylist = BER(data).decode()
        except BERException:
            e = sys.exc_info()[1]
            raise SSHException('Unable to parse key file: ' + str(e))
        if (type(keylist) is not list) or (len(keylist) < 6) or \
                (keylist[0] != 0):
            raise SSHException('not a valid DSA private key file (bad ber encoding)')
        self.p = keylist[1]
        self.q = keylist[2]
        self.g = keylist[3]
        self.y = keylist[4]
        self.x = keylist[5]
        self.size = bit_length(self.p)


# PKCS7Encoder is borrowed from http://japrogbits.blogspot.in/
class PKCS7Encoder(object):
    '''
    RFC 2315: PKCS#7 page 21
    Some content-encryption algorithms assume the
    input length is a multiple of k octets, where k > 1, and
    let the application define a method for handling inputs
    whose lengths are not a multiple of k octets. For such
    algorithms, the method shall be to pad the input at the
    trailing end with k - (l mod k) octets all having value k -
    (l mod k), where l is the length of the input. In other
    words, the input is padded at the trailing end with one of
    the following strings:

             01 -- if l mod k = k-1
            02 02 -- if l mod k = k-2
                        .
                        .
                        .
          k k ... k k -- if l mod k = 0

    The padding can be removed unambiguously since all input is
    padded and no padding string is a suffix of another. This
    padding method is well-defined if and only if k < 256;
    methods for larger k are an open issue for further study.
    '''
    def __init__(self, k=16):
        self.k = k

    ## @param text The padded text for which the padding is to be removed.
    # @exception ValueError Raised when the input padding is missing or corrupt.
    def decode(self, text):
        '''
        Remove the PKCS#7 padding from a text string
        '''
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return text[:l]

    ## @param text The text to encode.
    def encode(self, text):
        '''
        Pad an input string according to PKCS#7
        '''
        l = len(text)
        output = StringIO()
        val = self.k - (l % self.k)
        for _ in xrange(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())


if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s < RSA/DSA private key files >\n" % \
                sys.argv[0])

    for filename in sys.argv[1:]:
        key = RSADSSKey.from_private_key_file(filename, '')
