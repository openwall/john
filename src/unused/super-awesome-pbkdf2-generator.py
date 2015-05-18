#!/usr/bin/env python

import getopt
import hashlib
import hmac
import struct
import sys

class prf:
    def __init__(self, digest):
        self.digest      = digest
        self.digest_size = digest().digest_size

    def __call__(self, key, data):
        return hmac.new(key, data, self.digest).digest()

def INT(i):
    assert i > 0
    return struct.pack('>I', i)

def xor(A, B):
    return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(A, B)])


# RFC 2898, section 5.2

def pbkdf2(P, S, c, dkLen, PRF):
    hLen = PRF.digest_size

    if dkLen > (2**32 - 1) * hLen:
        raise Exception('derived key too long')

    l = -(-dkLen // hLen)
    r = dkLen - (l - 1) * hLen

    def F(i):
        def U():
            U = S + INT(i)
            for j in range(c):
                U = PRF(P, U)
                yield U

        return reduce(xor, U())

    T = map(F, range(1, l+1))

    DK = ''.join(T[:-1]) + T[-1][:r]
    return DK


# RFC 6070 format

def print_str(name, s):
    print '  %s = "%s" (%d octets)' % (name, s.replace("\0", "\\0"), len(s))

def print_int(name, i):
    print '  %s = %d' % (name, i)

def print_hex(name, s):
    print '  %s =' % name,
    for i in range(len(s)):
        print '%02x%s' % (ord(s[i]),
            '\n      ' if i % 8 == 7 and i + 1 < len(s) else ''),
    print '%s(%d octets)' % ('   ' * (-len(s) % 8), len(s))

def test(P, S, c, dkLen, PRF):
    print 'Input:'
    print_str("P", P)
    print_str("S", S)
    print_int("c", c)
    print_int("dkLen", dkLen)
    print

    DK = pbkdf2(P, S, c, dkLen, PRF)
    print 'Output:'
    print DK.encode("hex")
    print_hex("DK", DK)
    print
    print


if __name__ == '__main__':
    def usage():
        sys.exit('%s [-b 20] sha1 sha256 ...' % sys.argv[0])

    opts, args = getopt.getopt(sys.argv[1:], 'b:')

    opt_b = None
    for opt, arg in opts:
        if opt == '-b':
            opt_b = int(arg)
        else:
            usage()

    if not args:
        usage()

    for name in args:
        print 'PBKDF2 HMAC-%s Test Vectors' % name.upper()
        print

        PRF = prf(hashlib.new(name).copy)
        block = opt_b or PRF.digest_size

        test("password", "salt", 1,        block, PRF)
        test("password", "salt", 2,        block, PRF)
        # test("password", "salt", 4096,     block, PRF)
        # test("password", "salt", 16777216, block, PRF)
        # test("passwordPASSWORDpassword",
        #     "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, block // 4 * 5, PRF)
        # test("pass\0word", "sa\0lt",                 4096, 16, PRF)
