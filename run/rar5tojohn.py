#!/usr/bin/env python

# References:
#
# http://code.activestate.com/recipes/426060/ (r4)
# http://www.rarlab.com/rar/unrarsrc-5.0.3.tar.gz
#
# TODO:
#
# 1. Currently, only "hp" mode RAR 5.0 files are handled.
# 2. The parser is incomplete and needs to be extended.

import sys
import os
import hashlib


class StringQueue(object):
    def __init__(self, data=""):
        self.l_buffer = []
        self.s_buffer = ""
        self.write(data)

    def write(self, data):
        # check type here, as wrong data type will cause error on self.read,
        # which may be confusing.
        if type(data) != type(""):
            raise TypeError, "argument 1 must be string, not %s" % type(data).__name__
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
        if count > len(self.s_buffer) or count==None: self._build_str()
        # if i don't have enough bytes to satisfy caller, return nothing.
        if count > len(self.s_buffer): return ""
        # get data requested by caller
        result = self.s_buffer[:count]
        # remove requested data from string buffer
        self.s_buffer = self.s_buffer[len(result):]
        return result

    def GetVSize(self):
        """Return a number of unsigned chars in current variable length
        integer."""
        size = 0
        data = self.s_buffer
        while size < len(data):
            size = size + 1
            if (ord(data[size]) & 0x80) == 0:
                return size

	assert(0)

    def GetV(self):
        self._build_str()
        size = 0
        result = 0
        shift = 0
        data = self.s_buffer
        while size < len(data):
            CurByte = ord(data[size]);
	    result = result + (CurByte & 0x7f) << shift;
            shift += 7
            if ((ord(data[size]) & 0x80)==0):
                self.s_buffer = self.s_buffer[size + 1:]
                return result
            size = size + 1

	assert(0)

    def Get1(self):
        self._build_str()
        data = ord(self.s_buffer[0])
        self.s_buffer = self.s_buffer[1:]

        return data

# global constants
SFXSize = 0;
FirstReadSize = 7
HFL_SKIPIFUNKNOWN = 0x0004
HFL_EXTRA = 0x0001
HFL_DATA = 0x0002
HEAD_CRYPT = 0x04
CRYPT_VERSION = 0
CHFL_CRYPT_PSWCHECK = 0x0001
CRYPT5_KDF_LG2_COUNT = 15
CRYPT5_KDF_LG2_COUNT_MAX = 24
SIZE_SALT50 = 16
SIZE_PSWCHECK = 8
SIZE_PSWCHECK_CSUM = 4
SIZE_INITV = 16

# global variables
Encrypted = False
PswCheck = None
salt = None
iterations = None
UsePswCheck = 0;
CurBlockPos = 0;

def FullHeaderSize(size):
    """Calculate the block size including encryption fields and padding if any"""
    """
    if Encrypted:
        Size = ALIGN_VALUE(Size, CRYPT_BLOCK_SIZE)
        if Format == RARFMT50:
            pass
            Size += SIZE_INITV;
    """
    return size

buf = StringQueue()
f = open(sys.argv[1], "rb")

def read_rar5_header():
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
        #        NULL,PswCheck);
        # Verify password validity.
        print "%s:$rar5$%s$%s$%s$%s$%s$%s" % ( sys.argv[1],
                len(salt), salt.encode("hex"),
                len(HeadersInitV), HeadersInitV.encode("hex"),
                len(PswCheck), PswCheck.encode("hex"))
        sys.exit(-1)
    # some header
    buf.write(f.read(7))
    stuff = buf.read(4)
    SizeBytes = buf.GetVSize()
    # print "SB", SizeBytes
    BlockSize = buf.GetV()
    # print "BS", BlockSize
    SizeToRead = BlockSize
    SizeToRead = SizeToRead - (FirstReadSize - SizeBytes - 4)
    # print "STR", SizeToRead
    HeaderSize = 4 + SizeBytes + BlockSize

    # new stuff
    buf.write(f.read(SizeToRead))
    # GetCRC50();
    HeaderType = buf.GetV()
    # print "HT", HeaderType
    Flags = buf.GetV()
    # print "FLAGS", Flags
    SkipIfUnknown = (Flags & HFL_SKIPIFUNKNOWN) != 0
    HeadSize = HeaderSize;
    CurHeaderType = HeaderType;
    ExtraSize = 0
    if (Flags & HFL_EXTRA) !=0:
        print "!!!!!"
        # ExtraSize = buf.GetV()
        # if ExtraSize>=HeadSize:
        #   print("BAD 3");
    DataSize = 0;
    if (Flags & HFL_DATA)!=0:
        print "!!!!!"
        # DataSize = buf.GetV()

    NextBlockPos = CurBlockPos + FullHeaderSize(HeadSize) + DataSize;

    # check header type
    if HeaderType == HEAD_CRYPT:
        CryptVersion = buf.GetV()
        # print "CV", CryptVersion
        if CryptVersion>CRYPT_VERSION:
            print "bad 2"
        EncFlags = buf.GetV()
        UsePswCheck = (EncFlags & CHFL_CRYPT_PSWCHECK)!=0
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
        Encrypted=1;

if __name__ == "__main__":
    buf.write(f.read(8))
    # check magic
    if buf.read(8) != "\x52\x61\x72\x21\x1a\x07\x01\x00":
        print "bad 1"

    while(1):
        read_rar5_header()
