#!/usr/bin/env python

# References:
#
# http://code.activestate.com/recipes/426060/ (r4)
# http://www.rarlab.com/rar/unrarsrc-5.0.13.tar.gz
#
# TODO: Only files using "PSWCHECK" are supported!


import sys
import os
import hashlib
# import binascii


class StringQueue(object):
    def __init__(self, data=""):
        self.l_buffer = []
        self.s_buffer = ""
        self.write(data)
        self.ReadPos = None

    def write(self, data):
        # append data to list, no need to "".join just yet.
        self.l_buffer.append(data)

    def _build_str(self):
        # build a new string out of list
        new_string = "".join(self.l_buffer)
        # join string buffer and new string
        self.s_buffer = "".join((self.s_buffer, new_string))
        # clear list
        self.l_buffer = []

    def __len__(self):
        # calculate length without needing to _build_str
        return sum(len(i) for i in self.l_buffer) + len(self.s_buffer)

    def read(self, count=None):
        # if string doesnt have enough chars to satisfy caller, or caller is
        # requesting all data
        if count > len(self.s_buffer) or not count:
            self._build_str()
        # if i don't have enough bytes to satisfy caller, return nothing.
        if count > len(self.s_buffer):
            return ""
        # get data requested by caller
        result = self.s_buffer[:count]
        # remove requested data from string buffer
        self.s_buffer = self.s_buffer[count:]
        return result

    def GetVSize(self):
        """Return a number of unsigned chars in current variable length integer."""
        size = 0
        data = self.s_buffer
        while size < len(data):
            size = size + 1
            if (ord(data[size]) & 0x80) == 0:
                return size

        assert(0)

    def GetV(self, ReadPos=None):
        self._build_str()
        size = 0
        result = 0
        shift = 0
        data = self.s_buffer
        self.ReadPos = ReadPos
        while size < len(data):
            CurByte = ord(data[size])
            result = result + ((CurByte & 0x7f) << shift)
            shift += 7
            if CurByte & 0x80 == 0:
                self.s_buffer = self.s_buffer[size + 1:]
                if self.ReadPos:
                    self.ReadPos = self.ReadPos + size + 1
                return result
            size = size + 1

        assert(0)

    def Get1(self):
        self._build_str()
        data = ord(self.s_buffer[0])
        self.s_buffer = self.s_buffer[1:]

        return data

    def Get2(self):
        self._build_str()
        b1 = ord(self.s_buffer[0])
        b2 = ord(self.s_buffer[1])

        self.s_buffer = self.s_buffer[2:]

        return b1 + (b2 << 8)

    def Get4(self):
        self._build_str()
        b1 = ord(self.s_buffer[0])
        b2 = ord(self.s_buffer[1])
        b3 = ord(self.s_buffer[2])
        b4 = ord(self.s_buffer[3])

        self.s_buffer = self.s_buffer[4:]

        return b1 + (b2 << 8) + (b3 << 16) + (b4 << 24)


# global constants
SFXSize = 0
FirstReadSize = 7
HFL_SKIPIFUNKNOWN = 0x0004
HFL_EXTRA = 0x0001
HFL_DATA = 0x0002
CRYPT_VERSION = 0
CHFL_CRYPT_PSWCHECK = 0x0001
CRYPT5_KDF_LG2_COUNT = 15
CRYPT5_KDF_LG2_COUNT_MAX = 24
SIZE_SALT50 = 16
SIZE_PSWCHECK = 8
SIZE_PSWCHECK_CSUM = 4
SIZE_INITV = 16

# RAR 5.0 header types.
HEAD_MARK = 0x00
HEAD_MAIN = 0x01
HEAD_FILE = 0x02
HEAD_SERVICE = 0x03
HEAD_CRYPT = 0x04
HEAD_ENDARC = 0x05
HEAD_UNKNOWN = 0xff

HFL_SPLITBEFORE = 0x0008
HFL_SPLITAFTER = 0x0010
HFL_CHILD = 0x0020
HFL_INHERITED = 0x0040

# RAR 5.0 main archive header specific flags.
MHFL_VOLUME = 0x0001
MHFL_VOLNUMBER = 0x0002
MHFL_SOLID = 0x0004
MHFL_PROTECT = 0x0008
MHFL_LOCK = 0x0010

#  RAR 5.0 file compression flags.
FCI_ALGO_BIT0 = 0x0001
FCI_ALGO_BIT1 = 0x0002
FCI_ALGO_BIT2 = 0x0004
FCI_ALGO_BIT3 = 0x0008
FCI_ALGO_BIT4 = 0x0010
FCI_ALGO_BIT5 = 0x0020
FCI_SOLID = 0x0040
FCI_METHOD_BIT0 = 0x0080
FCI_METHOD_BIT1 = 0x0100
FCI_METHOD_BIT2 = 0x0200
FCI_DICT_BIT0 = 0x0400
FCI_DICT_BIT1 = 0x0800
FCI_DICT_BIT2 = 0x1000
FCI_DICT_BIT3 = 0x2000

# RAR 5.0 file header specific flags.
FHFL_DIRECTORY = 0x0001
FHFL_UTIME = 0x0002
FHFL_CRC32 = 0x0004
FHFL_UNPUNKNOWN = 0x0008

# RAR 5.0 end of archive header specific flags.
EHFL_NEXTVOLUME = 0x0001

# RAR 5.0 archive encryption header specific flags.
CHFL_CRYPT_PSWCHECK = 0x0001

# HASH_TYPE
HASH_NONE = 0
HASH_RAR14 = 1
HASH_CRC32 = 0
HASH_BLAKE2 = 2

#  File and service header extra field values.
FHEXTRA_CRYPT = 0x01
FHEXTRA_HASH = 0x02
FHEXTRA_HTIME = 0x03
FHEXTRA_VERSION = 0x04
FHEXTRA_REDIR = 0x05
FHEXTRA_UOWNER = 0x06
FHEXTRA_SUBDATA = 0x07

# Flags for FHEXTRA_CRYPT.
FHEXTRA_CRYPT_PSWCHECK = 0x01
FHEXTRA_CRYPT_HASHMAC = 0x02

CRYPT5_KDF_LG2_COUNT = 15
CRYPT5_KDF_LG2_COUNT_MAX = 24
CRYPT_VERSION = 0

# global variables
Encrypted = False
PswCheck = None
salt = None
iterations = None
UsePswCheck = 0
CurBlockPos = 0


def FullHeaderSize(size):
    """Calculate the block size including encryption fields and padding if any"""
    """
    if Encrypted:
        Size = ALIGN_VALUE(Size, CRYPT_BLOCK_SIZE)
        if Format == RARFMT50:
            pass
            Size += SIZE_INITV
    """
    return size


def ProcessExtra50(f, ExtraSize, RawSize, HeaderType, PrevNextBlockPos):
    ExtraStart = RawSize - ExtraSize
    # print ExtraSize, RawSize, ExtraStart

    f.seek(PrevNextBlockPos, 0)

    buf = StringQueue()
    buf.write(f.read(RawSize))
    buf.read(ExtraStart)

    buf._build_str()

    while True:
        FieldSize = buf.GetV(ExtraStart)
        # print binascii.hexlify(buf.s_buffer)
        # print FieldSize, buf.ReadPos
        NextPos = buf.ReadPos + FieldSize
        FieldType = buf.GetV(buf.ReadPos)
        # print binascii.hexlify(buf.s_buffer)
        # print "FieldType", FieldType

        if HeaderType == HEAD_FILE or HeaderType == HEAD_SERVICE:

            if FieldType == FHEXTRA_CRYPT:
                # print binascii.hexlify(buf.s_buffer)
                EncVersion = buf.GetV()
                # print "EncVersion", EncVersion
                Flags= buf.GetV()

                # print "Flags", Flags
                UsePswCheck = (Flags & FHEXTRA_CRYPT_PSWCHECK) != 0
                if not UsePswCheck:
                    assert 0, "UsePswCheck if OFF. We currently don't support such files"

                UseHashKey = (Flags & FHEXTRA_CRYPT_HASHMAC) != 0
                Lg2Count = buf.Get1()
                # print "Lg2Count", Lg2Count

                assert Lg2Count < CRYPT5_KDF_LG2_COUNT_MAX

                Salt = buf.read( SIZE_SALT50)
                InitV = buf.read(SIZE_INITV)

                PswCheck = buf.read(SIZE_PSWCHECK)
                print "%s:$rar5$%s$%s$%s$%s$%s$%s" % (
                    os.path.basename(f.name),
                    len(Salt), Salt.encode("hex"),
                    len(InitV), InitV.encode("hex"),
                    len(PswCheck), PswCheck.encode("hex"))
                return  # XXX handle other "FieldType" values


def read_rar5_header(f, PrevNextBlockPos=0):

    buf = StringQueue()  # XXX
    global Encrypted
    global PswCheck
    global salt
    global iterations
    # bool Decrypt = Encrypted && CurBlockPos>(int64)SFXSize+SIZEOF_MARKHEAD5
    Decrypt = Encrypted

    if Decrypt:
        buf.write(f.read(SIZE_INITV))
        HeadersInitV = buf.read(SIZE_INITV)
        # cPswCheck = rar5kdf(password, salt, HeadersInitV)
        # cPswCheck = SetCryptKeys(false,CRYPT_RAR50,
        #        &Cmd->Password,CryptHead.Salt,
        #        HeadersInitV,CryptHead.Lg2Count,
        #        NULL,PswCheck)
        # Verify password validity.
        print "%s:$rar5$%s$%s$%s$%s$%s$%s" % (
            sys.argv[1],
            len(salt), salt.encode("hex"),
            len(HeadersInitV), HeadersInitV.encode("hex"),
            len(PswCheck), PswCheck.encode("hex"))
        sys.exit(-1)
    # Header size must not occupy more than 3 variable length integer bytes
    # resulting in 2 MB maximum header size, so here we read 4 byte CRC32
    # followed by 3 bytes or less of header size.
    buf.write(f.read(7))
    HeadCRC = buf.read(4)
    SizeBytes = buf.GetVSize()
    # print "SizeBytes", SizeBytes
    BlockSize = buf.GetV()
    # print "BlockSize", BlockSize
    SizeToRead = BlockSize
    SizeToRead = SizeToRead - (FirstReadSize - SizeBytes - 4)
    # print "SizeToRead", SizeToRead
    HeaderSize = 4 + SizeBytes + BlockSize
    # print "HeaderSize", HeaderSize, f.tell()

    # new stuff
    buf.write(f.read(SizeToRead))
    # GetCRC50()
    HeaderType = buf.GetV()
    # print "HeaderType", HeaderType
    Flags = buf.GetV()
    # print "Flags", Flags
    SkipIfUnknown = (Flags & HFL_SKIPIFUNKNOWN) != 0
    HeadSize = HeaderSize
    CurHeaderType = HeaderType
    ExtraSize = 0
    # handle ExtraSize and other stuff
    if (Flags & HFL_EXTRA) != 0:
        ExtraSize = buf.GetV()
        # print "ExtraSize", ExtraSize
        if ExtraSize >= HeadSize:
            assert 0, "RAR5 (-p mode?) parsing is broken, please report this bug!"
    DataSize = 0
    if (Flags & HFL_DATA) != 0:
        DataSize = buf.GetV()
        # print "DataSize", DataSize

    NextBlockPos = CurBlockPos + FullHeaderSize(HeadSize) + DataSize
    # print ">>>", NextBlockPos, CurBlockPos, DataSize, FullHeaderSize(HeadSize)

    # check header type
    if HeaderType == HEAD_CRYPT:
        CryptVersion = buf.GetV()
        # print "CV", CryptVersion
        if CryptVersion>CRYPT_VERSION:
            print "bad 2"
        EncFlags = buf.GetV()
        UsePswCheck = (EncFlags & CHFL_CRYPT_PSWCHECK) != 0
        Lg2Count = buf.Get1()
        # print "LG2CNT", Lg2Count
        iterations = Lg2Count
        if (Lg2Count>CRYPT5_KDF_LG2_COUNT_MAX):
            print "bad 3"

        # get salt
        salt = buf.read(SIZE_SALT50)
        if (UsePswCheck):
            PswCheck = buf.read(SIZE_PSWCHECK)
            # print len(PswCheck)
            csum = buf.read(SIZE_PSWCHECK_CSUM)
            digest = hashlib.sha256(PswCheck).digest()
            UsePswCheck = csum == digest[0:SIZE_PSWCHECK_CSUM]
            # print "UPC", UsePswCheck
        Encrypted = 1

    elif HeaderType == HEAD_MAIN:
        ArcFlags=buf.GetV();
        # print "HEAD_MAIN ArcFlags", ArcFlags

        Volume = (ArcFlags & MHFL_VOLUME) != 0
        Solid = (ArcFlags & MHFL_SOLID) != 0
        Locked = (ArcFlags & MHFL_LOCK) != 0
        Protected = (ArcFlags & MHFL_PROTECT) != 0
        Signed = False;
        NewNumbering = True;

        if ((ArcFlags & MHFL_VOLNUMBER)!=0):
            VolNumber = buf.GetV();
        else:
          VolNumber=0

        FirstVolume=Volume and VolNumber==0

        if ExtraSize != 0:
            pass
            # print "ExtraSize != 0"
            # ProcessExtra50(...)

    elif HeaderType == HEAD_FILE or HeaderType == HEAD_SERVICE:
        FileBlock = HeaderType == HEAD_FILE
        LargeFile = True
        PackSize = DataSize

        # print "DataSize", DataSize
        FileFlags = buf.GetV()
        # print "FileFlags", FileFlags
        UnpSize = buf.GetV();
        # print "UnpSize", UnpSize
        # UnknownUnpSize = (FileFlags and FHFL_UNPUNKNOWN) != 0

        MaxSize = max(PackSize, UnpSize)

        FileAttr = buf.GetV()
        # print "FileAttr", FileAttr

        if FileFlags & FHFL_UTIME != 0:
            mtime = buf.Get4()

        FileHashType = HASH_NONE
        if FileFlags & FHFL_CRC32 != 0:
            FileHashType = HASH_CRC32
            FileHashCRC32 = buf.Get4()

        # RedirType = FSREDIR_NONE
        CompInfo = buf.GetV()
        Method = (CompInfo>>7) & 7
        UnpVer = CompInfo & 0x3f
        HostOS = buf.GetV()
        NameSize = buf.GetV()

        # print "NameSize", NameSize
        f.read(NameSize)
        # print ">>>", f.tell(), NextBlockPos, PrevNextBlockPos

        # Inherited =(Flags & HFL_INHERITED) != 0
        # SplitBefore = (Flags and HFL_SPLITBEFORE) != 0
        # SplitAfter = (Flags and HFL_SPLITAFTER) != 0
        # SubBlock = (Flags and HFL_CHILD) != 0
        # Solid = FileBlock and (CompInfo & FCI_SOLID) != 0
        # Dir = (FileFlags & FHFL_DIRECTORY) != 0

        # XXX code block
        # hd->WinSize=hd->Dir ? 0:size_t(0x20000)<<((CompInfo>>10)&0xf);
        # hd->CryptMethod=hd->Encrypted ? CRYPT_RAR50:CRYPT_NONE;
        # char FileName[NM*4];
        # size_t ReadNameSize=Min(NameSize,ASIZE(FileName)-1);
        # Raw.GetB((byte *)FileName,ReadNameSize);
        # FileName[ReadNameSize]=0;

        # Should do it before converting names, because extra fields can
        # affect name processing, like in case of NTFS streams.
        if ExtraSize != 0:
            ProcessExtra50(f, ExtraSize, HeadSize, HeaderType, PrevNextBlockPos)

    elif HeaderType == HEAD_ENDARC:
        return None, None

    return HeaderType, NextBlockPos

if __name__ == "__main__":
    f = open(sys.argv[1], "rb")
    # check RAR5 magic
    magic = f.read(8)
    if magic != "\x52\x61\x72\x21\x1a\x07\x01\x00":
        print "%s is not a RAR 5 file!" % sys.argv[1]
        sys.exit(-1)

    NextBlockPos = 0

    while(1):
        CurBlockPos = f.tell()
        HeaderType, NextBlockPos = read_rar5_header(f, NextBlockPos)
        if not NextBlockPos:
            break
        # print "NextBlockPos is", NextBlockPos, HeaderType, CurBlockPos
        f.seek(NextBlockPos, 0)
