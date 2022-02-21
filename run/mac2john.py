#!/usr/bin/env python

# NOTE: This script is only tested with Python 3.6, Python 2.7, and Python
# 2.6.9. It cannot work with Python 2.5.x.
#
# This script was previously called "ml2john.py".

# Start of library code

"""
biplist is under BSD license

Copyright (c) 2010, Andrew Wooster
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of biplist nor the names of its contributors may be
      used to endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE"""

"""biplist -- a library for reading and writing binary property list files.

Binary Property List (plist) files provide a faster and smaller serialization
format for property lists on OS X. This is a library for generating binary
plists which can be read by OS X, iOS, or other clients.

The API models the plistlib API, and will call through to plistlib when
XML serialization or deserialization is required.

To generate plists with UID values, wrap the values with the Uid object. The
value must be an int.

To generate plists with NSData/CFData values, wrap the values with the
Data object. The value must be a string.

Date values can only be datetime.datetime objects.

The exceptions InvalidPlistException and NotBinaryPlistException may be
thrown to indicate that the data cannot be serialized or deserialized as
a binary plist.

Plist generation example:

    from biplist import *
    from datetime import datetime
    plist = {'aKey':'aValue',
             '0':1.322,
             'now':datetime.now(),
             'list':[1,2,3],
             'tuple':('a','b','c')
             }
    try:
        writePlist(plist, "example.plist")
    except (InvalidPlistException, NotBinaryPlistException), e:
        print "Something bad happened:", e

Plist parsing example:

    from biplist import *
    try:
        plist = readPlist("example.plist")
        print plist
    except (InvalidPlistException, NotBinaryPlistException), e:
        print "Not a plist:", e
"""

from collections import namedtuple
import datetime
import io
import math
import plistlib
from struct import pack, unpack, unpack_from
import sys
import time

try:
    unicode
    unicodeEmpty = r''
except NameError:
    unicode = str
    unicodeEmpty = ''
try:
    long
except NameError:
    long = int
try:
    {}.iteritems
    iteritems = lambda x: x.iteritems()
except AttributeError:
    iteritems = lambda x: x.items()

__all__ = [
    'Uid', 'Data', 'readPlist', 'writePlist', 'readPlistFromString',
    'writePlistToString', 'InvalidPlistException', 'NotBinaryPlistException'
]

# Apple uses Jan 1, 2001 as a base for all plist date/times.
apple_reference_date = datetime.datetime.utcfromtimestamp(978307200)

class Uid(object):
    """Wrapper around integers for representing UID values. This
       is used in keyed archiving."""
    integer = 0
    def __init__(self, integer):
        self.integer = integer

    def __repr__(self):
        return "Uid(%d)" % self.integer

    def __eq__(self, other):
        if isinstance(self, Uid) and isinstance(other, Uid):
            return self.integer == other.integer
        return False

    def __cmp__(self, other):
        return self.integer - other.integer

    def __lt__(self, other):
        return self.integer < other.integer

    def __hash__(self):
        return self.integer

    def __int__(self):
        return int(self.integer)

class Data(bytes):
    """Wrapper around bytes to distinguish Data values."""

class InvalidPlistException(Exception):
    """Raised when the plist is incorrectly formatted."""

class NotBinaryPlistException(Exception):
    """Raised when a binary plist was expected but not encountered."""

def readPlist(pathOrFile):
    """Raises NotBinaryPlistException, InvalidPlistException"""
    didOpen = False
    result = None
    if isinstance(pathOrFile, (bytes, unicode)):
        pathOrFile = open(pathOrFile, 'rb')
        didOpen = True
    try:
        reader = PlistReader(pathOrFile)
        result = reader.parse()
    except NotBinaryPlistException as e:
        try:
            pathOrFile.seek(0)
            result = None
            if hasattr(plistlib, 'loads'):
                contents = None
                if isinstance(pathOrFile, (bytes, unicode)):
                    with open(pathOrFile, 'rb') as f:
                        contents = f.read()
                else:
                    contents = pathOrFile.read()
                result = plistlib.loads(contents)
            else:
                result = plistlib.readPlist(pathOrFile)
            result = wrapDataObject(result, for_binary=True)
        except Exception as e:
            raise InvalidPlistException(e)
    finally:
        if didOpen:
            pathOrFile.close()
    return result

def wrapDataObject(o, for_binary=False):
    if isinstance(o, Data) and not for_binary:
        v = sys.version_info
        if not (v[0] >= 3 and v[1] >= 4):
            o = plistlib.Data(o)
    elif isinstance(o, (bytes, plistlib.Data)) and for_binary:
        if hasattr(o, 'data'):
            o = Data(o.data)
    elif isinstance(o, tuple):
        o = wrapDataObject(list(o), for_binary)
        o = tuple(o)
    elif isinstance(o, list):
        for i in range(len(o)):
            o[i] = wrapDataObject(o[i], for_binary)
    elif isinstance(o, dict):
        for k in o:
            o[k] = wrapDataObject(o[k], for_binary)
    return o

def readPlistFromString(data):
    return readPlist(io.BytesIO(data))

def is_stream_binary_plist(stream):
    stream.seek(0)
    header = stream.read(7)
    if header == b'bplist0':
        return True
    else:
        return False

PlistTrailer = namedtuple('PlistTrailer', 'offsetSize, objectRefSize, offsetCount, topLevelObjectNumber, offsetTableOffset')
PlistByteCounts = namedtuple('PlistByteCounts', 'nullBytes, boolBytes, intBytes, realBytes, dateBytes, dataBytes, stringBytes, uidBytes, arrayBytes, setBytes, dictBytes')

class PlistReader(object):
    file = None
    contents = ''
    offsets = None
    trailer = None
    currentOffset = 0
    # Used to detect recursive object references.
    offsetsStack = []

    def __init__(self, fileOrStream):
        """Raises NotBinaryPlistException."""
        self.reset()
        self.file = fileOrStream

    def parse(self):
        return self.readRoot()

    def reset(self):
        self.trailer = None
        self.contents = ''
        self.offsets = []
        self.currentOffset = 0
        self.offsetsStack = []

    def readRoot(self):
        result = None
        self.reset()
        # Get the header, make sure it's a valid file.
        if not is_stream_binary_plist(self.file):
            raise NotBinaryPlistException()
        self.file.seek(0)
        self.contents = self.file.read()
        if len(self.contents) < 32:
            raise InvalidPlistException("File is too short.")
        trailerContents = self.contents[-32:]
        try:
            self.trailer = PlistTrailer._make(unpack("!xxxxxxBBQQQ", trailerContents))

            if pow(2, self.trailer.offsetSize*8) < self.trailer.offsetTableOffset:
                raise InvalidPlistException("Offset size insufficient to reference all objects.")

            if pow(2, self.trailer.objectRefSize*8) < self.trailer.offsetCount:
                raise InvalidPlistException("Too many offsets to represent in size of object reference representation.")

            offset_size = self.trailer.offsetSize * self.trailer.offsetCount
            offset = self.trailer.offsetTableOffset

            if offset + offset_size > pow(2, 64):
                raise InvalidPlistException("Offset table is excessively long.")

            if self.trailer.offsetSize > 16:
                raise InvalidPlistException("Offset size is greater than maximum integer size.")

            if self.trailer.objectRefSize == 0:
                raise InvalidPlistException("Object reference size is zero.")

            if offset >= len(self.contents) - 32:
                raise InvalidPlistException("Offset table offset is too large.")

            if offset < len("bplist00x"):
                raise InvalidPlistException("Offset table offset is too small.")

            if self.trailer.topLevelObjectNumber >= self.trailer.offsetCount:
                raise InvalidPlistException("Top level object number is larger than the number of objects.")

            offset_contents = self.contents[offset:offset+offset_size]
            offset_i = 0
            offset_table_length = len(offset_contents)

            while offset_i < self.trailer.offsetCount:
                begin = self.trailer.offsetSize*offset_i
                end = begin+self.trailer.offsetSize
                if end > offset_table_length:
                    raise InvalidPlistException("End of object is at invalid offset %d in offset table of length %d" % (end, offset_table_length))
                tmp_contents = offset_contents[begin:end]
                tmp_sized = self.getSizedInteger(tmp_contents, self.trailer.offsetSize)
                self.offsets.append(tmp_sized)
                offset_i += 1
            self.setCurrentOffsetToObjectNumber(self.trailer.topLevelObjectNumber)
            result = self.readObject()
        except TypeError as e:
            raise InvalidPlistException(e)
        return result

    def setCurrentOffsetToObjectNumber(self, objectNumber):
        if objectNumber > len(self.offsets) - 1:
            raise InvalidPlistException("Invalid offset number: %d" % objectNumber)
        self.currentOffset = self.offsets[objectNumber]
        if self.currentOffset in self.offsetsStack:
            raise InvalidPlistException("Recursive data structure detected in object: %d" % objectNumber)

    def beginOffsetProtection(self):
        self.offsetsStack.append(self.currentOffset)
        return self.currentOffset

    def endOffsetProtection(self, offset):
        try:
            index = self.offsetsStack.index(offset)
            self.offsetsStack = self.offsetsStack[:index]
        except ValueError as e:
            pass

    def readObject(self):
        protection = self.beginOffsetProtection()
        result = None
        tmp_byte = self.contents[self.currentOffset:self.currentOffset+1]
        if len(tmp_byte) != 1:
            raise InvalidPlistException("No object found at offset: %d" % self.currentOffset)
        marker_byte = unpack("!B", tmp_byte)[0]
        format = (marker_byte >> 4) & 0x0f
        extra = marker_byte & 0x0f
        self.currentOffset += 1

        def proc_extra(extra):
            if extra == 0b1111:
                extra = self.readObject()
            return extra

        # bool, null, or fill byte
        if format == 0b0000:
            if extra == 0b0000:
                result = None
            elif extra == 0b1000:
                result = False
            elif extra == 0b1001:
                result = True
            elif extra == 0b1111:
                pass # fill byte
            else:
                raise InvalidPlistException("Invalid object found at offset: %d" % (self.currentOffset - 1))
        # int
        elif format == 0b0001:
            result = self.readInteger(pow(2, extra))
        # real
        elif format == 0b0010:
            result = self.readReal(extra)
        # date
        elif format == 0b0011 and extra == 0b0011:
            result = self.readDate()
        # data
        elif format == 0b0100:
            extra = proc_extra(extra)
            result = self.readData(extra)
        # ascii string
        elif format == 0b0101:
            extra = proc_extra(extra)
            result = self.readAsciiString(extra)
        # Unicode string
        elif format == 0b0110:
            extra = proc_extra(extra)
            result = self.readUnicode(extra)
        # uid
        elif format == 0b1000:
            result = self.readUid(extra)
        # array
        elif format == 0b1010:
            extra = proc_extra(extra)
            result = self.readArray(extra)
        # set
        elif format == 0b1100:
            extra = proc_extra(extra)
            result = set(self.readArray(extra))
        # dict
        elif format == 0b1101:
            extra = proc_extra(extra)
            result = self.readDict(extra)
        else:
            raise InvalidPlistException("Invalid object found: {format: %s, extra: %s}" % (bin(format), bin(extra)))
        self.endOffsetProtection(protection)
        return result

    def readContents(self, length, description="Object contents"):
        end = self.currentOffset + length
        if end >= len(self.contents) - 32:
            raise InvalidPlistException("%s extends into trailer" % description)
        elif length < 0:
            raise InvalidPlistException("%s length is less than zero" % length)
        data = self.contents[self.currentOffset:end]
        return data

    def readInteger(self, byteSize):
        data = self.readContents(byteSize, "Integer")
        self.currentOffset = self.currentOffset + byteSize
        return self.getSizedInteger(data, byteSize, as_number=True)

    def readReal(self, length):
        to_read = pow(2, length)
        data = self.readContents(to_read, "Real")
        if length == 2: # 4 bytes
            result = unpack('>f', data)[0]
        elif length == 3: # 8 bytes
            result = unpack('>d', data)[0]
        else:
            raise InvalidPlistException("Unknown Real of length %d bytes" % to_read)
        return result

    def readRefs(self, count):
        refs = []
        i = 0
        while i < count:
            fragment = self.readContents(self.trailer.objectRefSize, "Object reference")
            ref = self.getSizedInteger(fragment, len(fragment))
            refs.append(ref)
            self.currentOffset += self.trailer.objectRefSize
            i += 1
        return refs

    def readArray(self, count):
        if not isinstance(count, (int, long)):
            raise InvalidPlistException("Count of entries in dict isn't of integer type.")
        result = []
        values = self.readRefs(count)
        i = 0
        while i < len(values):
            self.setCurrentOffsetToObjectNumber(values[i])
            value = self.readObject()
            result.append(value)
            i += 1
        return result

    def readDict(self, count):
        if not isinstance(count, (int, long)):
            raise InvalidPlistException("Count of keys/values in dict isn't of integer type.")
        result = {}
        keys = self.readRefs(count)
        values = self.readRefs(count)
        i = 0
        while i < len(keys):
            self.setCurrentOffsetToObjectNumber(keys[i])
            key = self.readObject()
            self.setCurrentOffsetToObjectNumber(values[i])
            value = self.readObject()
            result[key] = value
            i += 1
        return result

    def readAsciiString(self, length):
        if not isinstance(length, (int, long)):
            raise InvalidPlistException("Length of ASCII string isn't of integer type.")
        data = self.readContents(length, "ASCII string")
        result = unpack("!%ds" % length, data)[0]
        self.currentOffset += length
        return str(result.decode('ascii'))

    def readUnicode(self, length):
        if not isinstance(length, (int, long)):
            raise InvalidPlistException("Length of Unicode string isn't of integer type.")
        actual_length = length*2
        data = self.readContents(actual_length, "Unicode string")
        self.currentOffset += actual_length
        return data.decode('utf_16_be')

    def readDate(self):
        data = self.readContents(8, "Date")
        x = unpack(">d", data)[0]
        if math.isnan(x):
            raise InvalidPlistException("Date is NaN")
        # Use timedelta to workaround time_t size limitation on 32-bit python.
        try:
            result = datetime.timedelta(seconds=x) + apple_reference_date
        except OverflowError:
            if x > 0:
                result = datetime.datetime.max
            else:
                result = datetime.datetime.min
        self.currentOffset += 8
        return result

    def readData(self, length):
        if not isinstance(length, (int, long)):
            raise InvalidPlistException("Length of data isn't of integer type.")
        result = self.readContents(length, "Data")
        self.currentOffset += length
        return Data(result)

    def readUid(self, length):
        if not isinstance(length, (int, long)):
            raise InvalidPlistException("Uid length isn't of integer type.")
        return Uid(self.readInteger(length+1))

    def getSizedInteger(self, data, byteSize, as_number=False):
        """Numbers of 8 bytes are signed integers when they refer to numbers, but unsigned otherwise."""
        result = 0
        if byteSize == 0:
            raise InvalidPlistException("Encountered integer with byte size of 0.")
        # 1, 2, and 4 byte integers are unsigned
        elif byteSize == 1:
            result = unpack('>B', data)[0]
        elif byteSize == 2:
            result = unpack('>H', data)[0]
        elif byteSize == 4:
            result = unpack('>L', data)[0]
        elif byteSize == 8:
            if as_number:
                result = unpack('>q', data)[0]
            else:
                result = unpack('>Q', data)[0]
        elif byteSize <= 16:
            # Handle odd-sized or integers larger than 8 bytes
            # Don't naively go over 16 bytes, in order to prevent infinite loops.
            result = 0
            if hasattr(int, 'from_bytes'):
                result = int.from_bytes(data, 'big')
            else:
                for byte in data:
                    if not isinstance(byte, int): # Python3.0-3.1.x return ints, 2.x return str
                        byte = unpack_from('>B', byte)[0]
                    result = (result << 8) | byte
        else:
            raise InvalidPlistException("Encountered integer longer than 16 bytes.")
        return result

class HashableWrapper(object):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return "<HashableWrapper: %s>" % [self.value]

class BoolWrapper(object):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return "<BoolWrapper: %s>" % self.value

class FloatWrapper(object):
    _instances = {}
    def __new__(klass, value):
        # Ensure FloatWrapper(x) for a given float x is always the same object
        wrapper = klass._instances.get(value)
        if wrapper is None:
            wrapper = object.__new__(klass)
            wrapper.value = value
            klass._instances[value] = wrapper
        return wrapper
    def __repr__(self):
        return "<FloatWrapper: %s>" % self.value

class StringWrapper(object):
    __instances = {}

    encodedValue = None
    encoding = None

    def __new__(cls, value):
        '''Ensure we only have a only one instance for any string,
         and that we encode ascii as 1-byte-per character when possible'''

        encodedValue = None

        for encoding in ('ascii', 'utf_16_be'):
            try:
               encodedValue = value.encode(encoding)
            except: pass
            if encodedValue is not None:
                if encodedValue not in cls.__instances:
                    cls.__instances[encodedValue] = super(StringWrapper, cls).__new__(cls)
                    cls.__instances[encodedValue].encodedValue = encodedValue
                    cls.__instances[encodedValue].encoding = encoding
                return cls.__instances[encodedValue]

        raise ValueError('Unable to get ascii or utf_16_be encoding for %s' % repr(value))

    def __len__(self):
        '''Return roughly the number of characters in this string (half the byte length)'''
        if self.encoding == 'ascii':
            return len(self.encodedValue)
        else:
            return len(self.encodedValue)//2

    def __lt__(self, other):
        return self.encodedValue < other.encodedValue

    @property
    def encodingMarker(self):
        if self.encoding == 'ascii':
            return 0b0101
        else:
            return 0b0110

    def __repr__(self):
        return '<StringWrapper (%s): %s>' % (self.encoding, self.encodedValue)


# Library code ends here, program starts
#
# Written by Dhiru Kholia <dhiru at openwall.com> in September of 2012.
#
# My code is under "Simplified BSD License".
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import base64
import binascii
try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

PY3 = sys.version_info[0] == 3


def process_file(filename):
    try:
        p1 = readPlist(filename)
    except IOError as e:
        print("%s : %s" % (filename, str(e)))
        return False
    except (InvalidPlistException, NotBinaryPlistException):
        print("%s is not a plist file!" % filename)
        return False

    s = p1.get('ShadowHashData', [None])[0]
    if not s:
        # Process the "preprocessed" output XMLs generated by "plutil" command.
        #
        # Example: sudo defaults read /var/db/dslocal/nodes/Default/users/<username>.plist ShadowHashData | tr -dc 0-9a-f | xxd -r -p | plutil -convert xml1 - -o -
        p2 = p1
    else:
        # Handle regular binary plist files and default XML output of "plutil
        # -convert xml1 username.plist".
        s = StringIO(s)
        if not s:
            print("%s: could not find ShadowHashData" % filename)
            return -2
        try:
            p2 = readPlist(s)
        except Exception:
            e = sys.exc_info()[1]
            sys.stderr.write("%s : %s\n" % (filename, str(e)))
            return -3

    d = p2.get('SALTED-SHA512-PBKDF2', None)
    if not d:
        sys.stderr.write("%s does not contain SALTED-SHA512-PBKDF2 hashes\n" % filename)
        return -4

    salt = d.get('salt')
    entropy = d.get('entropy')
    iterations = d.get('iterations')

    salth = binascii.hexlify(salt)
    entropyh = binascii.hexlify(entropy)

    if PY3:
        salth = salth.decode("ascii")
        entropyh = entropyh.decode("ascii")

    hints = ""
    hl = p1.get('realname', []) + p1.get('hint', [])
    hints += ",".join(hl)
    uid = p1.get('uid', ["500"])[0]
    gid = p1.get('gid', ["500"])[0]
    shell = p1.get('shell', ["bash"])[0]
    name = p1.get('name', ["user"])[0]

    sys.stdout.write("%s:$pbkdf2-hmac-sha512$%d.%s.%s:%s:%s:%s:%s:%s\n" % \
            (name, iterations, salth, entropyh[0:128], uid, gid, hints,
             shell, filename))

    # from passlib.hash import grub_pbkdf2_sha512
    # hash = grub_pbkdf2_sha512.encrypt("password", rounds=iterations, salt=salt)
    # print(hash)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("This program helps in extracting password hashes from OS X / macOS systems (>= Mountain Lion -> 10.8+).\n")
        print("Run this program against .plist file(s) obtained from /var/db/dslocal/nodes/Default/users/<username>.plist location.\n")
        print("Usage: %s <OS X / macOS .plist files>" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
