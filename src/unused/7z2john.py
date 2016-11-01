#!/usr/bin/python -u
#
# Copyright (c) 2013 by Dhiru Kholia, <dhiru (at) openwall.com>
#
# Python Bindings for LZMA
#
# Copyright (c) 2004-2010 by Joachim Bauch, mail@joachim-bauch.de
# 7-Zip Copyright (C) 1999-2010 Igor Pavlov
# LZMA SDK Copyright (C) 1999-2010 Igor Pavlov
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# $Id$
#
"""Read from and write to 7zip format archives.
"""

from binascii import unhexlify
from datetime import datetime
try:
    import pylzma
# To install pylzma on Ubuntu:
# apt-get install python-pip python-dev
# pip install pylzma # may do as non-root user in group staff
except ImportError:
    pass
from struct import pack, unpack
from zlib import crc32
import zlib
import bz2
import binascii
import StringIO
import sys
import os

try:
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO as BytesIO
try:
    from functools import reduce
except ImportError:
    # reduce is available in functools starting with Python 2.6
    pass

try:
    from pytz import UTC
except ImportError:
    # pytz is optional, define own "UTC" timestamp
    # reference implementation from Python documentation
    from datetime import timedelta, tzinfo

    ZERO = timedelta(0)

    class UTC(tzinfo):
        """UTC"""

        def utcoffset(self, dt):
            return ZERO

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return ZERO

try:
    unicode
except NameError:
    # Python 3.x
    def unicode(s, encoding):
        return s
else:
    def bytes(s, encoding):
        return s

READ_BLOCKSIZE                   = 16384

MAGIC_7Z                         = unhexlify('377abcaf271c')  # '7z\xbc\xaf\x27\x1c'

PROPERTY_END                     = unhexlify('00')  # '\x00'
PROPERTY_HEADER                  = unhexlify('01')  # '\x01'
PROPERTY_ARCHIVE_PROPERTIES      = unhexlify('02')  # '\x02'
PROPERTY_ADDITIONAL_STREAMS_INFO = unhexlify('03')  # '\x03'
PROPERTY_MAIN_STREAMS_INFO       = unhexlify('04')  # '\x04'
PROPERTY_FILES_INFO              = unhexlify('05')  # '\x05'
PROPERTY_PACK_INFO               = unhexlify('06')  # '\x06'
PROPERTY_UNPACK_INFO             = unhexlify('07')  # '\x07'
PROPERTY_SUBSTREAMS_INFO         = unhexlify('08')  # '\x08'
PROPERTY_SIZE                    = unhexlify('09')  # '\x09'
PROPERTY_CRC                     = unhexlify('0a')  # '\x0a'
PROPERTY_FOLDER                  = unhexlify('0b')  # '\x0b'
PROPERTY_CODERS_UNPACK_SIZE      = unhexlify('0c')  # '\x0c'
PROPERTY_NUM_UNPACK_STREAM       = unhexlify('0d')  # '\x0d'
PROPERTY_EMPTY_STREAM            = unhexlify('0e')  # '\x0e'
PROPERTY_EMPTY_FILE              = unhexlify('0f')  # '\x0f'
PROPERTY_ANTI                    = unhexlify('10')  # '\x10'
PROPERTY_NAME                    = unhexlify('11')  # '\x11'
PROPERTY_CREATION_TIME           = unhexlify('12')  # '\x12'
PROPERTY_LAST_ACCESS_TIME        = unhexlify('13')  # '\x13'
PROPERTY_LAST_WRITE_TIME         = unhexlify('14')  # '\x14'
PROPERTY_ATTRIBUTES              = unhexlify('15')  # '\x15'
PROPERTY_COMMENT                 = unhexlify('16')  # '\x16'
PROPERTY_ENCODED_HEADER          = unhexlify('17')  # '\x17'

COMPRESSION_METHOD_COPY          = unhexlify('00')  # '\x00'
COMPRESSION_METHOD_LZMA          = unhexlify('03')  # '\x03'
COMPRESSION_METHOD_CRYPTO        = unhexlify('06')  # '\x06'
COMPRESSION_METHOD_MISC          = unhexlify('04')  # '\x04'
COMPRESSION_METHOD_MISC_ZIP      = unhexlify('0401')  # '\x04\x01'
COMPRESSION_METHOD_MISC_BZIP     = unhexlify('0402')  # '\x04\x02'
COMPRESSION_METHOD_7Z_AES256_SHA256 = unhexlify('06f10701')  # '\x06\xf1\x07\x01'

# number of seconds between 1601/01/01 and 1970/01/01 (UTC)
# used to adjust 7z FILETIME to Python timestamp
TIMESTAMP_ADJUST                 = -11644473600

def toTimestamp(filetime):
    """Convert 7z FILETIME to Python timestamp."""
    # FILETIME is 100-nanosecond intervals since 1601/01/01 (UTC)
    return (filetime / 10000000.0) + TIMESTAMP_ADJUST

class ArchiveError(Exception):
    pass

class FormatError(ArchiveError):
    pass

class EncryptedArchiveError(ArchiveError):
    pass

class UnsupportedCompressionMethodError(ArchiveError):
    pass

class DecryptionError(ArchiveError):
    pass

class NoPasswordGivenError(DecryptionError):
    pass

class WrongPasswordError(DecryptionError):
    pass

class ArchiveTimestamp(long):
    """Windows FILETIME timestamp."""

    def __repr__(self):
        return '%s(%d)' % (type(self).__name__, self)

    def as_datetime(self):
        """Convert FILETIME to Python datetime object."""
        return datetime.fromtimestamp(toTimestamp(self), UTC)

class Base(object):
    """ base class with support for various basic read/write functions """

    def _readReal64Bit(self, file):
        res = file.read(8)
        a, b = unpack('<LL', res)
        return b << 32 | a, res

    def _read64Bit(self, file):
        b = ord(file.read(1))
        mask = 0x80
        for i in range(8):
            if b & mask == 0:
                bytes = list(unpack('%dB' % i, file.read(i)))
                bytes.reverse()
                value = (bytes and reduce(lambda x, y: x << 8 | y, bytes)) or 0
                highpart = b & (mask - 1)
                return value + (highpart << (i * 8))

            mask >>= 1

    def _readBoolean(self, file, count, checkall=0):
        if checkall:
            alldefined = file.read(1)
            if alldefined != unhexlify('00'):
                return [True] * count

        result = []
        b = 0
        mask = 0
        for i in range(count):
            if mask == 0:
                b = ord(file.read(1))
                mask = 0x80
            result.append(b & mask != 0)
            mask >>= 1

        return result

    def checkcrc(self, crc, data):
        check = crc32(data) & 0xffffffff
        return crc == check


class PackInfo(Base):
    """ informations about packed streams """

    def __init__(self, file):
        self.packpos = self._read64Bit(file)
        self.numstreams = self._read64Bit(file)
        id = file.read(1)
        if id == PROPERTY_SIZE:
            self.packsizes = [self._read64Bit(file) for x in range(self.numstreams)]
            id = file.read(1)

            if id == PROPERTY_CRC:
                self.crcs = [self._read64Bit(file) for x in range(self.numstreams)]
                id = file.read(1)

        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % repr(id))

class Folder(Base):
    """ a "Folder" represents a stream of compressed data """

    def __init__(self, file):
        numcoders = self._read64Bit(file)
        self.numcoders = numcoders
        self.coders = []
        self.digestdefined = False
        totalin = 0
        self.totalout = 0
        for i in range(numcoders):
            while True:
                b = ord(file.read(1))
                methodsize = b & 0xf
                issimple = b & 0x10 == 0
                noattributes = b & 0x20 == 0
                last_alternative = b & 0x80 == 0
                c = {}
                c['method'] = file.read(methodsize)
                if not issimple:
                    c['numinstreams'] = self._read64Bit(file)
                    c['numoutstreams'] = self._read64Bit(file)
                else:
                    c['numinstreams'] = 1
                    c['numoutstreams'] = 1
                totalin += c['numinstreams']
                self.totalout += c['numoutstreams']
                if not noattributes:
                    c['properties'] = file.read(self._read64Bit(file))
                self.coders.append(c)
                if last_alternative:
                    break

        numbindpairs = self.totalout - 1
        self.bindpairs = []
        for i in range(numbindpairs):
            self.bindpairs.append((self._read64Bit(file), self._read64Bit(file), ))

        numpackedstreams = totalin - numbindpairs
        self.numpackedstreams = numpackedstreams
        self.packed_indexes = []
        if numpackedstreams == 1:
            for i in range(totalin):
                if self.findInBindPair(i) < 0:
                    self.packed_indexes.append(i)
        elif numpackedstreams > 1:
            for i in range(numpackedstreams):
                self.packed_indexes.append(self._read64Bit(file))

    def getUnpackSize(self):
        if not self.unpacksizes:
            return 0

        r = list(range(len(self.unpacksizes)))
        r.reverse()
        for i in r:
            if self.findOutBindPair(i):
                return self.unpacksizes[i]

        raise TypeError('not found')

    def findInBindPair(self, index):
        for idx in range(len(self.bindpairs)):
            a, b = self.bindpairs[idx]
            if a == index:
                return idx
        return -1

    def findOutBindPair(self, index):
        for idx in range(len(self.bindpairs)):
            a, b = self.bindpairs[idx]
            if b == index:
                return idx
        return -1

class Digests(Base):
    """ holds a list of checksums """

    def __init__(self, file, count):
        self.defined = self._readBoolean(file, count, checkall=1)
        self.crcs = [unpack('<L', file.read(4))[0] for x in range(count)]

UnpackDigests = Digests

class UnpackInfo(Base):
    """ combines multiple folders """

    def __init__(self, file):
        id = file.read(1)
        if id != PROPERTY_FOLDER:
            raise FormatError('folder id expected but %s found' % repr(id))
        self.numfolders = self._read64Bit(file)
        self.folders = []
        external = file.read(1)
        if external == unhexlify('00'):
            self.folders = [Folder(file) for x in range(self.numfolders)]
        elif external == unhexlify('01'):
            self.datastreamidx = self._read64Bit(file)
        else:
            raise FormatError('0x00 or 0x01 expected but %s found' % repr(external))

        id = file.read(1)
        if id != PROPERTY_CODERS_UNPACK_SIZE:
            raise FormatError('coders unpack size id expected but %s found' % repr(id))

        for folder in self.folders:
            folder.unpacksizes = [self._read64Bit(file) for x in range(folder.totalout)]

        id = file.read(1)
        if id == PROPERTY_CRC:
            digests = UnpackDigests(file, self.numfolders)
            for idx in range(self.numfolders):
                folder = self.folders[idx]
                folder.digestdefined = digests.defined[idx]
                folder.crc = digests.crcs[idx]

            id = file.read(1)

        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % repr(id))

class SubstreamsInfo(Base):
    """ defines the substreams of a folder """

    def __init__(self, file, numfolders, folders):
        self.digests = []
        self.digestsdefined = []
        id = file.read(1)
        if id == PROPERTY_NUM_UNPACK_STREAM:
            self.numunpackstreams = [self._read64Bit(file) for x in range(numfolders)]
            id = file.read(1)
        else:
            self.numunpackstreams = []
            for idx in range(numfolders):
                self.numunpackstreams.append(1)

        if id == PROPERTY_SIZE:
            sum = 0
            self.unpacksizes = []
            for i in range(len(self.numunpackstreams)):
                for j in range(1, self.numunpackstreams[i]):
                    size = self._read64Bit(file)
                    self.unpacksizes.append(size)
                    sum += size
                self.unpacksizes.append(folders[i].getUnpackSize() - sum)

            id = file.read(1)

        numdigests = 0
        numdigeststotal = 0
        for i in range(numfolders):
            numsubstreams = self.numunpackstreams[i]
            if numsubstreams != 1 or not folders[i].digestdefined:
                numdigests += numsubstreams
            numdigeststotal += numsubstreams

        if id == PROPERTY_CRC:
            digests = Digests(file, numdigests)
            didx = 0
            for i in range(numfolders):
                folder = folders[i]
                numsubstreams = self.numunpackstreams[i]
                if numsubstreams == 1 and folder.digestdefined:
                    self.digestsdefined.append(True)
                    self.digests.append(folder.crc)
                else:
                    for j in range(numsubstreams):
                        self.digestsdefined.append(digests.defined[didx])
                        self.digests.append(digests.crcs[didx])
                        didx += 1

            id = file.read(1)

        if id != PROPERTY_END:
            raise FormatError('end id expected but %r found' % id)

        if not self.digestsdefined:
            self.digestsdefined = [False] * numdigeststotal
            self.digests = [0] * numdigeststotal

class StreamsInfo(Base):
    """ informations about compressed streams """

    def __init__(self, file):
        id = file.read(1)
        if id == PROPERTY_PACK_INFO:
            self.packinfo = PackInfo(file)
            id = file.read(1)

        if id == PROPERTY_UNPACK_INFO:
            self.unpackinfo = UnpackInfo(file)
            id = file.read(1)

        if id == PROPERTY_SUBSTREAMS_INFO:
            self.substreamsinfo = SubstreamsInfo(file, self.unpackinfo.numfolders, self.unpackinfo.folders)
            id = file.read(1)

        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % repr(id))

class FilesInfo(Base):
    """ holds file properties """

    def _readTimes(self, file, files, name):
        defined = self._readBoolean(file, len(files), checkall=1)

        # NOTE: the "external" flag is currently ignored, should be 0x00
        external = file.read(1)
        for i in range(len(files)):
            if defined[i]:
                files[i][name] = ArchiveTimestamp(self._readReal64Bit(file)[0])
            else:
                files[i][name] = None

    def __init__(self, file):
        self.numfiles = self._read64Bit(file)
        self.files = [{'emptystream': False} for x in range(self.numfiles)]
        numemptystreams = 0
        while True:
            typ = self._read64Bit(file)
            if typ > 255:
                raise FormatError('invalid type, must be below 256, is %d' % typ)

            typ = pack('B', typ)
            if typ == PROPERTY_END:
                break

            size = self._read64Bit(file)
            buffer = BytesIO(file.read(size))
            if typ == PROPERTY_EMPTY_STREAM:
                isempty = self._readBoolean(buffer, self.numfiles)
                list(map(lambda x, y: x.update({'emptystream': y}), self.files, isempty))
                for x in isempty:
                    if x: numemptystreams += 1
                emptyfiles = [False] * numemptystreams
                antifiles = [False] * numemptystreams
            elif typ == PROPERTY_EMPTY_FILE:
                emptyfiles = self._readBoolean(buffer, numemptystreams)
            elif typ == PROPERTY_ANTI:
                antifiles = self._readBoolean(buffer, numemptystreams)
            elif typ == PROPERTY_NAME:
                external = buffer.read(1)
                if external != unhexlify('00'):
                    self.dataindex = self._read64Bit(buffer)
                    # XXX: evaluate external
                    raise NotImplementedError

                for f in self.files:
                    name = ''
                    while True:
                        ch = buffer.read(2)
                        if ch == unhexlify('0000'):
                            f['filename'] = name
                            break
                        name += ch.decode('utf-16')
            elif typ == PROPERTY_CREATION_TIME:
                self._readTimes(buffer, self.files, 'creationtime')
            elif typ == PROPERTY_LAST_ACCESS_TIME:
                self._readTimes(buffer, self.files, 'lastaccesstime')
            elif typ == PROPERTY_LAST_WRITE_TIME:
                self._readTimes(buffer, self.files, 'lastwritetime')
            elif typ == PROPERTY_ATTRIBUTES:
                defined = self._readBoolean(buffer, self.numfiles, checkall=1)
                for i in range(self.numfiles):
                    f = self.files[i]
                    if defined[i]:
                        f['attributes'] = unpack('<L', buffer.read(4))[0]
                    else:
                        f['attributes'] = None
            else:
                raise FormatError('invalid type %r' % (typ))

class Header(Base):
    """ the archive header """

    def __init__(self, file):
        id = file.read(1)
        if id == PROPERTY_ARCHIVE_PROPERTIES:
            self.properties = ArchiveProperties(file)
            id = file.read(1)

        if id == PROPERTY_ADDITIONAL_STREAMS_INFO:
            self.additional_streams = StreamsInfo(file)
            id = file.read(1)

        if id == PROPERTY_MAIN_STREAMS_INFO:
            self.main_streams = StreamsInfo(file)
            id = file.read(1)

        if id == PROPERTY_FILES_INFO:
            self.files = FilesInfo(file)
            id = file.read(1)

        if id != PROPERTY_END:
            raise FormatError('end id expected but %s found' % (repr(id)))

class ArchiveFile(Base):
    """ wrapper around a file in the archive """

    def __init__(self, info, start, src_start, size, folder, archive, maxsize=None):
        self.digest = None
        self._archive = archive
        self._file = archive._file
        self._start = start
        self._src_start = src_start
        self._folder = folder
        self.size = size
        # maxsize is only valid for solid archives
        self._maxsize = maxsize
        for k, v in info.items():
            setattr(self, k, v)
        self.reset()
        self._decoders = {
            COMPRESSION_METHOD_COPY: '_read_copy',
            COMPRESSION_METHOD_LZMA: '_read_lzma',
            COMPRESSION_METHOD_MISC_ZIP: '_read_zip',
            COMPRESSION_METHOD_MISC_BZIP: '_read_bzip',
            COMPRESSION_METHOD_7Z_AES256_SHA256: '_read_7z_aes256_sha256',
        }

    def _is_encrypted(self):
        return COMPRESSION_METHOD_7Z_AES256_SHA256 in [x['method'] for x in self._folder.coders]

    def reset(self):
        self.pos = 0

    def read(self):
        if not self._folder.coders:
            raise TypeError("file has no coder informations")

        data = None
        for coder in self._folder.coders:
            method = coder['method']
            decoder = None
            while method and decoder is None:
                decoder = self._decoders.get(method, None)
                method = method[:-1]

            if decoder is None:
                raise UnsupportedCompressionMethodError(repr(coder['method']))

            data = getattr(self, decoder)(coder, data)

        return data

    def _read_copy(self, coder, input):
        if not input:
            self._file.seek(self._src_start)
            input = self._file.read(self.uncompressed)
        return input[self._start:self._start+self.size]

    def _read_from_decompressor(self, coder, decompressor, input, checkremaining=False, with_cache=False):
        data = ''
        idx = 0
        cnt = 0
        properties = coder.get('properties', None)
        if properties:
            decompressor.decompress(properties)
        total = self.compressed
        if not input and total is None:
            remaining = self._start+self.size
            out = BytesIO()
            cache = getattr(self._folder, '_decompress_cache', None)
            if cache is not None:
                data, pos, decompressor = cache
                out.write(data)
                remaining -= len(data)
                self._file.seek(pos)
            else:
                self._file.seek(self._src_start)
            checkremaining = checkremaining and not self._folder.solid
            while remaining > 0:
                data = self._file.read(READ_BLOCKSIZE)
                if checkremaining or (with_cache and len(data) < READ_BLOCKSIZE):
                    tmp = decompressor.decompress(data, remaining)
                else:
                    tmp = decompressor.decompress(data)
                assert len(tmp) > 0
                out.write(tmp)
                remaining -= len(tmp)

            data = out.getvalue()
            if with_cache and self._folder.solid:
                # don't decompress start of solid archive for next file
                # TODO: limit size of cached data
                self._folder._decompress_cache = (data, self._file.tell(), decompressor)
        else:
            if not input:
                self._file.seek(self._src_start)
                input = self._file.read(total)
            if checkremaining:
                data = decompressor.decompress(input, self._start+self.size)
            else:
                data = decompressor.decompress(input)
        return data[self._start:self._start+self.size]

    def _read_lzma(self, coder, input):
        dec = pylzma.decompressobj(maxlength=self._start+self.size)
        try:
            return self._read_from_decompressor(coder, dec, input, checkremaining=True, with_cache=True)
        except ValueError:
            if self._is_encrypted():
                raise WrongPasswordError('invalid password')

            raise

    def _read_zip(self, coder, input):
        dec = zlib.decompressobj(-15)
        return self._read_from_decompressor(coder, dec, input, checkremaining=True)

    def _read_bzip(self, coder, input):
        dec = bz2.BZ2Decompressor()
        return self._read_from_decompressor(coder, dec, input)

    def read_7z_aes256_sha256(self, coder, input):
        if not self._archive.password:
            raise NoPasswordGivenError()

        # TODO: this needs some sanity checks
        firstbyte = ord(coder['properties'][0])
        numcyclespower = firstbyte & 0x3f
        if firstbyte & 0xc0 != 0:
            saltsize = (firstbyte >> 7) & 1
            ivsize = (firstbyte >> 6) & 1

            secondbyte = ord(coder['properties'][1])
            saltsize += (secondbyte >> 4)
            ivsize += (secondbyte & 0x0f)

            assert len(coder['properties']) == 2+saltsize+ivsize
            salt = coder['properties'][2:2+saltsize]
            iv = coder['properties'][2+saltsize:2+saltsize+ivsize]
            assert len(salt) == saltsize
            assert len(iv) == ivsize
            assert numcyclespower <= 24
            if ivsize < 16:
                iv += '\x00'*(16-ivsize)
        else:
            salt = iv = ''

        password = self._archive.password.encode('utf-16-le')
        key = pylzma.calculate_key(password, numcyclespower, salt=salt)
        cipher = pylzma.AESDecrypt(key, iv=iv)
        if not input:
            self._file.seek(self._src_start)
            uncompressed_size = self.uncompressed
            if uncompressed_size & 0x0f:
                # we need a multiple of 16 bytes
                uncompressed_size += 16 - (uncompressed_size & 0x0f)
            input = self._file.read(uncompressed_size)
        result = cipher.decrypt(input)
        return result

    def checkcrc(self):
        if self.digest is None:
            return True

        self.reset()
        data = self.read()
        return super(ArchiveFile, self).checkcrc(self.digest, data)

# XXX global state
iv = None
ivSize = None
Salt = None
NumCyclesPower = None
SaltSize = None

def SetDecoderProperties2(data):
    global iv, ivSize, Salt, NumCyclesPower, SaltSize
    pos = 0
    data = bytearray(data)
    firstByte = data[pos]
    pos = pos + 1

    NumCyclesPower = firstByte & 0x3F;
    if NumCyclesPower > 24:
        # print "Bad NumCyclesPower value"
        return None
    if ((firstByte & 0xC0) == 0):
        # XXX
        return "S_OK"
    SaltSize = (firstByte >> 7) & 1;
    ivSize = (firstByte >> 6) & 1;

    secondByte = data[pos]
    pos = pos + 1

    SaltSize += (secondByte >> 4);
    ivSize += (secondByte & 0x0F);

    # get salt
    Salt = data[pos:pos+SaltSize]
    Salt = str(Salt)
    pos = pos + SaltSize
    # get iv
    iv = data[pos:pos+ivSize]
    iv = str(iv)
    if len(iv) < 16:
        iv = iv + "\x00" * (16 - len(iv))
    return "OK"

class Archive7z(Base):
    """ the archive itself """

    def __init__(self, file, password=None):
        self._file = file
        self.password = password
        self.header = file.read(len(MAGIC_7Z))
        if self.header != MAGIC_7Z:
            raise FormatError('not a 7z file')
        self.version = unpack('BB', file.read(2))

        self.startheadercrc = unpack('<L', file.read(4))[0]
        self.nextheaderofs, data = self._readReal64Bit(file)
        crc = crc32(data)
        self.nextheadersize, data = self._readReal64Bit(file)
        crc = crc32(data, crc)
        data = file.read(4)
        self.nextheadercrc = unpack('<L', data)[0]
        crc = crc32(data, crc) & 0xffffffff
        if crc != self.startheadercrc:
            raise FormatError('invalid header data')
        self.afterheader = file.tell()

        file.seek(self.nextheaderofs, 1)
        buffer = BytesIO(file.read(self.nextheadersize))
        if not self.checkcrc(self.nextheadercrc, buffer.getvalue()):
            raise FormatError('invalid header data')

        while True:
            id = buffer.read(1)
            if not id or id == PROPERTY_HEADER:
                break

            if id != PROPERTY_ENCODED_HEADER:
                raise TypeError('Unknown field: %r' % (id))

            # ReadAndDecodePackedStreams (7zIn.cpp)
            streams = StreamsInfo(buffer)
            file.seek(self.afterheader + 0)
            data = bytes('', 'ascii')
            for folder in streams.unpackinfo.folders:
                file.seek(streams.packinfo.packpos, 1)
                props = folder.coders[0]['properties']
                # decode properties
                if SetDecoderProperties2(props):
                    # derive keys
                    # password = "password".encode('utf-16-le')
                    # print NumCyclesPower, Salt, password
                    # key = pylzma.calculate_key(password, NumCyclesPower, salt=Salt)
                    # cipher = pylzma.AESDecrypt(key, iv=str(iv))
                    global Salt
                    if len(Salt) == 0:
                        Salt = "\x11\x22"  # fake salt
                    for idx in range(len(streams.packinfo.packsizes)):
                        tmp = file.read(streams.packinfo.packsizes[idx])
                        fname = os.path.basename(self._file.name)
                        print "%s:$7z$0$%s$%s$%s$%s$%s$%s$%s$%s$%s" % (fname,
                            NumCyclesPower, SaltSize, binascii.hexlify(Salt),
                            ivSize, binascii.hexlify(iv), folder.crc, len(tmp),
                            folder.unpacksizes[idx], binascii.hexlify(tmp))
                        # print binascii.hexlify(tmp)
                        # result = cipher.decrypt(tmp)
                        # print folder.unpacksizes
                        # print folder.coders
                        # XXX we don't now how to handle unpacksizes of size > 1
                        # XXX we need to locate correct data and pass it to correct decompressor
                        # XXX correct decompressor can be located from folder.coders
                        # data = result  # for checksum check
                        size = folder.unpacksizes[idx]  # for checksum check
                        if len(folder.unpacksizes) > 1:
                            sys.stderr.write("%s : multiple unpacksizes found, not supported fully yet!\n" % fname)
                        # print binascii.hexlify(result)
                        # flds = Folder(BytesIO(result))
                        # print flds.coders
                        # print flds.packed_indexes, flds.totalout
                        # XXX return can't be right
                        return
#               else:
#                   for idx in range(len(streams.packinfo.packsizes)):
#                       tmp = file.read(streams.packinfo.packsizes[idx])
#                       data += pylzma.decompress(props+tmp, maxlength=folder.unpacksizes[idx])
#
#               if folder.digestdefined:
#                   if not self.checkcrc(folder.crc, data[0:size]):
#                       raise FormatError('invalid block data')
#                   # XXX return can't be right
#                   return

        # XXX this part is not done yet
        sys.stderr.write("%s : 7-Zip files without header encryption are *not* supported yet!\n" % (file.name))
        return

        buffer = BytesIO(file.read())
        id = buffer.read(1)

        self.files = []
        if not id:
            # empty archive
            self.solid = False
            self.numfiles = 0
            self.filenames = []
            return

        xx  = FilesInfo(buffer)

        self.header = Header(buffer)
        files = self.header.files
        folders = self.header.main_streams.unpackinfo.folders
        packinfo = self.header.main_streams.packinfo
        subinfo = self.header.main_streams.substreamsinfo
        packsizes = packinfo.packsizes
        self.solid = packinfo.numstreams == 1
        if hasattr(subinfo, 'unpacksizes'):
            unpacksizes = subinfo.unpacksizes
        else:
            unpacksizes = [x.unpacksizes[0] for x in folders]

        fidx = 0
        obidx = 0
        src_pos = self.afterheader
        pos = 0
        folder_start = 0
        folder_pos = src_pos
        maxsize = (self.solid and packinfo.packsizes[0]) or None
        for idx in range(files.numfiles):
            info = files.files[idx]
            if info['emptystream']:
                continue

            folder = folders[fidx]
            folder.solid = subinfo.numunpackstreams[fidx] > 1
            maxsize = (folder.solid and packinfo.packsizes[fidx]) or None
            if folder.solid:
                # file is part of solid archive
                info['compressed'] = None
            elif obidx < len(packsizes):
                # file is compressed
                info['compressed'] = packsizes[obidx]
            else:
                # file is not compressed
                info['compressed'] = unpacksizes[obidx]
            info['uncompressed'] = unpacksizes[obidx]
            file = ArchiveFile(info, pos, src_pos, unpacksizes[obidx], folder, self, maxsize=maxsize)
            if subinfo.digestsdefined[obidx]:
                file.digest = subinfo.digests[obidx]
            self.files.append(file)
            if folder.solid:
                pos += unpacksizes[obidx]
            else:
                src_pos += info['compressed']
            obidx += 1
            if idx >= subinfo.numunpackstreams[fidx]+folder_start:
                folder_pos += packinfo.packsizes[fidx]
                src_pos = folder_pos
                folder_start = idx
                fidx += 1

        self.numfiles = len(self.files)
        self.filenames = map(lambda x: x.filename, self.files)

    # interface like TarFile

    def getmember(self, name):
        # XXX: store files in dictionary
        for f in self.files:
            if f.filename == name:
                return f

        return None

    def getmembers(self):
        return self.files

    def getnames(self):
        return self.filenames

    def list(self, verbose=True):
        print ('total %d files in %sarchive' % (self.numfiles, (self.solid and 'solid ') or ''))
        if not verbose:
            print ('\n'.join(self.filenames))
            return

        for f in self.files:
            extra = (f.compressed and '%10d ' % (f.compressed)) or ' '
            print ('%10d%s%.8x %s' % (f.size, extra, f.digest, f.filename))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s < encrypted 7-Zip files >\n" % \
            sys.argv[0])

    for filename in sys.argv[1:]:
        f = Archive7z(open(filename, 'rb'))
