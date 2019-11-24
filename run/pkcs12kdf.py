__author__ = 'hari'

import math
import hashlib
from binascii import hexlify
from binascii import unhexlify


class PKCS12KDF:
    """This class generates keys and initialization vectors from passwords as specified in RFC 7292"""

    #
    # IDs for Key and IV material as in RFC
    #

    KEY_MATERIAL = 1
    IV_MATERIAL = 2
    PBA_MATERIAL = 3

    def __init__(self, password, salt, iteration_count, hash_algorithm, key_length_bits):
        self._password = password
        self._salt = salt
        self._iteration_count = iteration_count
        self._block_size_bits = None
        self._hash_length_bits = None
        self._key_length_bytes = key_length_bits/8
        self._key = None
        self._iv = None
        self._pba = None
        self._hash_algorithm = hash_algorithm
    #
    # Turns a byte array into a long
    #

    @staticmethod
    def byte_array_to_long(byte_array, nbytes=None):
        #
        # If nbytes is not present
        #
        if nbytes is None:
            #
            # Convert byte -> hex -> int/long
            #
            return int(hexlify(byte_array), 16)
        else:
            #
            # Convert byte -> hex -> int/long
            #
            return int(hexlify(byte_array[-nbytes:]), 16)

    #
    # Turn a long into a byte array
    #

    @staticmethod
    def long_to_byte_array(val, nbytes=None):
        hexval = hex(val)[2:-1] if type(val) is long else hex(val)[2:]
        if nbytes is None:
            return unhexlify('0' * (len(hexval) & 1) + hexval)
        else:
            return unhexlify('0' * (nbytes * 2 - len(hexval)) + hexval[-nbytes * 2:])

    #
    # Run the PKCS12 algorithm for either the key or the IV, specified by id
    #

    def generate_derived_parameters(self, id):

        #
        # Let r be the iteration count
        #

        r = self._iteration_count

        if self._hash_algorithm not in hashlib.algorithms_available:
            raise("Hash function: "+self._hash_algorithm+" not available")

        hash_function = hashlib.new(self._hash_algorithm)

        #
        # Block size, bytes
        #
        #v = self._block_size_bits / 8
        v = hash_function.block_size

        #
        # Hash function output length, bits
        #
        #u = self._hash_length_bits / 8
        u = hash_function.digest_size

        # In this specification however, all passwords are created from BMPStrings with a NULL
        # terminator. This means that each character in the original BMPString is encoded in 2
        # bytes in big-endian format (most-significant byte first). There are no Unicode byte order
        # marks. The 2 bytes produced from the last character in the BMPString are followed by
        # two additional bytes with the value 0x00.

        password = (unicode(self._password) + u'\0').encode('utf-16-be') if self._password is not None else b''

        #
        # Length of password string, p
        #
        p = len(password)

        #
        # Length of salt, s
        #
        s = len(self._salt)

        #
        # Step 1: Construct a string, D (the "diversifier"), by concatenating v copies of ID.
        #

        D = chr(id) * v

        #
        # Step 2: Concatenate copies of the salt, s, together to create a string S of length v * [s/v] bits (the
        # final copy of the salt may be truncated to create S). Note that if the salt is the empty
        # string, then so is S
        #

        S = b''

        if self._salt is not None:
            limit = int(float(v) * math.ceil((float(s)/float(v))))
            for i in range(0, limit):
                S += (self._salt[i % s])
        else:
            S += '0'

        #
        # Step 3: Concatenate copies of the password, p, together to create a string P of length v * [p/v] bits
        # (the final copy of the password may be truncated to create P). Note that if the
        # password is the empty string, then so is P.
        #

        P = b''

        if password is not None:
            limit = int(float(v) * math.ceil((float(p)/float(v))))
            for i in range(0, limit):
                P += password[i % p]
        else:
            P += '0'

        #
        # Step 4: Set I=S||P to be the concatenation of S and P.
        #

        I = bytearray(S) + bytearray(P)

        #
        # 5. Set c=[n/u]. (n = length of key/IV required)
        #

        n = self._key_length_bytes
        c = int(math.ceil(float(n)/float(u)))

        #
        # Step 6 For i=1, 2,..., c, do the following:
        #

        Ai = bytearray()

        for i in range(0, c):
            #
            # Step 6a.Set Ai=Hr(D||I). (i.e. the rth hash of D||I, H(H(H(...H(D||I))))
            #

            hash_function = hashlib.new(self._hash_algorithm)
            hash_function.update(bytearray(D))
            hash_function.update(bytearray(I))

            Ai = hash_function.digest()

            for j in range(1, r):
                hash_function = hashlib.sha256()
                hash_function.update(Ai)
                Ai = hash_function.digest()

            #
            # Step 6b: Concatenate copies of Ai to create a string B of length v bits (the final copy of Ai
            # may be truncated to create B).
            #

            B = b''

            for j in range(0, v):
                B += Ai[j % len(Ai)]

            #
            # Step 6c: Treating I as a concatenation I0, I1,..., Ik-1 of v-bit blocks, where k=[s/v]+[p/v],
            # modify I by setting Ij=(Ij+B+1) mod 2v for each j.
            #

            k = int(math.ceil(float(s)/float(v)) + math.ceil((float(p)/float(v))))

            for j in range(0, k-1):
                I = ''.join([
                    self.long_to_byte_array(
                        self.byte_array_to_long(I[j:j + v]) + self.byte_array_to_long(bytearray(B)), v
                    )
                ])

        return Ai[:self._key_length_bytes]

    #
    # Generate the key and IV
    #

    def generate_key_and_iv(self):
        self._key = self.generate_derived_parameters(self.KEY_MATERIAL)
        self._iv = self.generate_derived_parameters(self.IV_MATERIAL)
        self._pba = self.generate_derived_parameters(self.PBA_MATERIAL)
        return self._pba, self._key, self._iv
