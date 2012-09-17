#!/usr/bin/env python

"""Utilities for writing code that runs on Python 2 and 3"""

import operator
import sys
import types

__author__ = "Benjamin Peterson <benjamin@python.org>"
__version__ = "1.2.0"

"""
six is under MIT License

Copyright (c) 2010-2011 Benjamin Peterson

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."""


# True if we are running on Python 3.
PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str,
    integer_types = int,
    class_types = type,
    text_type = str
    binary_type = bytes

    MAXSIZE = sys.maxsize
else:
    string_types = basestring,
    integer_types = (int, long)
    class_types = (type, types.ClassType)
    text_type = unicode
    binary_type = str

    if sys.platform == "java":
        # Jython always uses 32 bits.
        MAXSIZE = int((1 << 31) - 1)
    else:
        # It's possible to have sizeof(long) != sizeof(Py_ssize_t).
        class X(object):
            def __len__(self):
                return 1 << 31
        try:
            len(X())
        except OverflowError:
            # 32-bit
            MAXSIZE = int((1 << 31) - 1)
        else:
            # 64-bit
            MAXSIZE = int((1 << 63) - 1)
            del X


def _add_doc(func, doc):
    """Add documentation to a function."""
    func.__doc__ = doc


def _import_module(name):
    """Import module, returning the module after the last dot."""
    __import__(name)
    return sys.modules[name]


class _LazyDescr(object):

    def __init__(self, name):
        self.name = name

    def __get__(self, obj, tp):
        result = self._resolve()
        setattr(obj, self.name, result)
        # This is a bit ugly, but it avoids running this again.
        delattr(tp, self.name)
        return result


class MovedModule(_LazyDescr):

    def __init__(self, name, old, new=None):
        super(MovedModule, self).__init__(name)
        if PY3:
            if new is None:
                new = name
            self.mod = new
        else:
            self.mod = old

    def _resolve(self):
        return _import_module(self.mod)


class MovedAttribute(_LazyDescr):

    def __init__(self, name, old_mod, new_mod, old_attr=None, new_attr=None):
        super(MovedAttribute, self).__init__(name)
        if PY3:
            if new_mod is None:
                new_mod = name
            self.mod = new_mod
            if new_attr is None:
                if old_attr is None:
                    new_attr = name
                else:
                    new_attr = old_attr
            self.attr = new_attr
        else:
            self.mod = old_mod
            if old_attr is None:
                old_attr = name
            self.attr = old_attr

    def _resolve(self):
        module = _import_module(self.mod)
        return getattr(module, self.attr)



class _MovedItems(types.ModuleType):
    """Lazy loading of moved objects"""


_moved_attributes = [
    MovedAttribute("cStringIO", "cStringIO", "io", "StringIO"),
    MovedAttribute("filter", "itertools", "builtins", "ifilter", "filter"),
    MovedAttribute("input", "__builtin__", "builtins", "raw_input", "input"),
    MovedAttribute("map", "itertools", "builtins", "imap", "map"),
    MovedAttribute("reload_module", "__builtin__", "imp", "reload"),
    MovedAttribute("reduce", "__builtin__", "functools"),
    MovedAttribute("StringIO", "StringIO", "io"),
    MovedAttribute("xrange", "__builtin__", "builtins", "xrange", "range"),
    MovedAttribute("zip", "itertools", "builtins", "izip", "zip"),

    MovedModule("builtins", "__builtin__"),
    MovedModule("configparser", "ConfigParser"),
    MovedModule("copyreg", "copy_reg"),
    MovedModule("http_cookiejar", "cookielib", "http.cookiejar"),
    MovedModule("http_cookies", "Cookie", "http.cookies"),
    MovedModule("html_entities", "htmlentitydefs", "html.entities"),
    MovedModule("html_parser", "HTMLParser", "html.parser"),
    MovedModule("http_client", "httplib", "http.client"),
    MovedModule("BaseHTTPServer", "BaseHTTPServer", "http.server"),
    MovedModule("CGIHTTPServer", "CGIHTTPServer", "http.server"),
    MovedModule("SimpleHTTPServer", "SimpleHTTPServer", "http.server"),
    MovedModule("cPickle", "cPickle", "pickle"),
    MovedModule("queue", "Queue"),
    MovedModule("reprlib", "repr"),
    MovedModule("socketserver", "SocketServer"),
    MovedModule("tkinter", "Tkinter"),
    MovedModule("tkinter_dialog", "Dialog", "tkinter.dialog"),
    MovedModule("tkinter_filedialog", "FileDialog", "tkinter.filedialog"),
    MovedModule("tkinter_scrolledtext", "ScrolledText", "tkinter.scrolledtext"),
    MovedModule("tkinter_simpledialog", "SimpleDialog", "tkinter.simpledialog"),
    MovedModule("tkinter_tix", "Tix", "tkinter.tix"),
    MovedModule("tkinter_constants", "Tkconstants", "tkinter.constants"),
    MovedModule("tkinter_dnd", "Tkdnd", "tkinter.dnd"),
    MovedModule("tkinter_colorchooser", "tkColorChooser",
                "tkinter.colorchooser"),
    MovedModule("tkinter_commondialog", "tkCommonDialog",
                "tkinter.commondialog"),
    MovedModule("tkinter_tkfiledialog", "tkFileDialog", "tkinter.filedialog"),
    MovedModule("tkinter_font", "tkFont", "tkinter.font"),
    MovedModule("tkinter_messagebox", "tkMessageBox", "tkinter.messagebox"),
    MovedModule("tkinter_tksimpledialog", "tkSimpleDialog",
                "tkinter.simpledialog"),
    MovedModule("urllib_robotparser", "robotparser", "urllib.robotparser"),
    MovedModule("winreg", "_winreg"),
]
for attr in _moved_attributes:
    setattr(_MovedItems, attr.name, attr)
del attr

moves = sys.modules["six.moves"] = _MovedItems("moves")


def add_move(move):
    """Add an item to six.moves."""
    setattr(_MovedItems, move.name, move)


def remove_move(name):
    """Remove item from six.moves."""
    try:
        delattr(_MovedItems, name)
    except AttributeError:
        try:
            del moves.__dict__[name]
        except KeyError:
            raise AttributeError("no such move, %r" % (name,))


if PY3:
    _meth_func = "__func__"
    _meth_self = "__self__"

    _func_code = "__code__"
    _func_defaults = "__defaults__"

    _iterkeys = "keys"
    _itervalues = "values"
    _iteritems = "items"
else:
    _meth_func = "im_func"
    _meth_self = "im_self"

    _func_code = "func_code"
    _func_defaults = "func_defaults"

    _iterkeys = "iterkeys"
    _itervalues = "itervalues"
    _iteritems = "iteritems"


try:
    advance_iterator = next
except NameError:
    def advance_iterator(it):
        return it.next()
next = advance_iterator


if PY3:
    def get_unbound_function(unbound):
        return unbound

    Iterator = object

    def callable(obj):
        return any("__call__" in klass.__dict__ for klass in type(obj).__mro__)
else:
    def get_unbound_function(unbound):
        return unbound.im_func

    class Iterator(object):

        def next(self):
            return type(self).__next__(self)

    callable = callable
_add_doc(get_unbound_function,
         """Get the function out of a possibly unbound function""")


get_method_function = operator.attrgetter(_meth_func)
get_method_self = operator.attrgetter(_meth_self)
get_function_code = operator.attrgetter(_func_code)
get_function_defaults = operator.attrgetter(_func_defaults)


def iterkeys(d):
    """Return an iterator over the keys of a dictionary."""
    return iter(getattr(d, _iterkeys)())

def itervalues(d):
    """Return an iterator over the values of a dictionary."""
    return iter(getattr(d, _itervalues)())

def iteritems(d):
    """Return an iterator over the (key, value) pairs of a dictionary."""
    return iter(getattr(d, _iteritems)())


if PY3:
    def b(s):
        return s.encode("latin-1")
    def u(s):
        return s
    if sys.version_info[1] <= 1:
        def int2byte(i):
            return bytes((i,))
    else:
        # This is about 2x faster than the implementation above on 3.2+
        int2byte = operator.methodcaller("to_bytes", 1, "big")
    import io
    StringIO = io.StringIO
    BytesIO = io.BytesIO
else:
    def b(s):
        return s
    def u(s):
        return unicode(s, "unicode_escape")
    int2byte = chr
    import StringIO
    StringIO = BytesIO = StringIO.StringIO
_add_doc(b, """Byte literal""")
_add_doc(u, """Text literal""")


if PY3:
    import builtins
    exec_ = getattr(builtins, "exec")


    def reraise(tp, value, tb=None):
        if value.__traceback__ is not tb:
            raise value.with_traceback(tb)
        raise value


    print_ = getattr(builtins, "print")
    del builtins

else:
    def exec_(code, globs=None, locs=None):
        """Execute code in a namespace."""
        if globs is None:
            frame = sys._getframe(1)
            globs = frame.f_globals
            if locs is None:
                locs = frame.f_locals
            del frame
        elif locs is None:
            locs = globs
        exec("""exec code in globs, locs""")


    exec_("""def reraise(tp, value, tb=None):
    raise tp, value, tb
""")


    def print_(*args, **kwargs):
        """The new-style print function."""
        fp = kwargs.pop("file", sys.stdout)
        if fp is None:
            return
        def write(data):
            if not isinstance(data, basestring):
                data = str(data)
            fp.write(data)
        want_unicode = False
        sep = kwargs.pop("sep", None)
        if sep is not None:
            if isinstance(sep, unicode):
                want_unicode = True
            elif not isinstance(sep, str):
                raise TypeError("sep must be None or a string")
        end = kwargs.pop("end", None)
        if end is not None:
            if isinstance(end, unicode):
                want_unicode = True
            elif not isinstance(end, str):
                raise TypeError("end must be None or a string")
        if kwargs:
            raise TypeError("invalid keyword arguments to print()")
        if not want_unicode:
            for arg in args:
                if isinstance(arg, unicode):
                    want_unicode = True
                    break
        if want_unicode:
            newline = unicode("\n")
            space = unicode(" ")
        else:
            newline = "\n"
            space = " "
        if sep is None:
            sep = space
        if end is None:
            end = newline
        for i, arg in enumerate(args):
            if i:
                write(sep)
            write(arg)
        write(end)

_add_doc(reraise, """Reraise an exception.""")


def with_metaclass(meta, base=object):
    """Create a base class with a metaclass."""
    return meta("NewBase", (base,), {})


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

import sys
from collections import namedtuple
import calendar
import datetime
import math
import plistlib
from struct import pack, unpack
import sys
import time

# import six

__all__ = [
    'Uid', 'Data', 'readPlist', 'writePlist', 'readPlistFromString',
    'writePlistToString', 'InvalidPlistException', 'NotBinaryPlistException'
]

apple_reference_date_offset = 978307200

class Uid(int):
    """Wrapper around integers for representing UID values. This
       is used in keyed archiving."""
    def __repr__(self):
        return "Uid(%d)" % self

class Data(binary_type):
    """Wrapper around str types for representing Data values."""
    pass

class InvalidPlistException(Exception):
    """Raised when the plist is incorrectly formatted."""
    pass

class NotBinaryPlistException(Exception):
    """Raised when a binary plist was expected but not encountered."""
    pass

def readPlist(pathOrFile):
    """Raises NotBinaryPlistException, InvalidPlistException"""
    didOpen = False
    result = None
    if isinstance(pathOrFile, (binary_type, text_type)):
        pathOrFile = open(pathOrFile, 'rb')
        didOpen = True
    try:
        reader = PlistReader(pathOrFile)
        result = reader.parse()
    except NotBinaryPlistException as e:
        try:
            pathOrFile.seek(0)
            result = plistlib.readPlist(pathOrFile)
            result = wrapDataObject(result, for_binary=True)
        except Exception as e:
            raise InvalidPlistException(e)
    if didOpen:
        pathOrFile.close()
    return result

def wrapDataObject(o, for_binary=False):
    if isinstance(o, Data) and not for_binary:
        o = plistlib.Data(o)
    elif isinstance(o, plistlib.Data) and for_binary:
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

def writePlist(rootObject, pathOrFile, binary=True):
    if not binary:
        rootObject = wrapDataObject(rootObject, binary)
        return plistlib.writePlist(rootObject, pathOrFile)
    else:
        didOpen = False
        if isinstance(pathOrFile, (six.binary_type, six.text_type)):
            pathOrFile = open(pathOrFile, 'wb')
            didOpen = True
        writer = PlistWriter(pathOrFile)
        result = writer.writeRoot(rootObject)
        if didOpen:
            pathOrFile.close()
        return result

def readPlistFromString(data):
    return readPlist(six.BytesIO(data))

def writePlistToString(rootObject, binary=True):
    if not binary:
        rootObject = wrapDataObject(rootObject, binary)
        if six.PY3:
            return plistlib.writePlistToBytes(rootObject)
        else:
            return plistlib.writePlistToString(rootObject)
    else:
        io = BytesIO()
        writer = PlistWriter(io)
        writer.writeRoot(rootObject)
        return io.getvalue()

def is_stream_binary_plist(stream):
    stream.seek(0)
    header = stream.read(7)
    if header == b('bplist0'):
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
            offset_size = self.trailer.offsetSize * self.trailer.offsetCount
            offset = self.trailer.offsetTableOffset
            offset_contents = self.contents[offset:offset+offset_size]
            offset_i = 0
            while offset_i < self.trailer.offsetCount:
                begin = self.trailer.offsetSize*offset_i
                tmp_contents = offset_contents[begin:begin+self.trailer.offsetSize]
                tmp_sized = self.getSizedInteger(tmp_contents, self.trailer.offsetSize)
                self.offsets.append(tmp_sized)
                offset_i += 1
            self.setCurrentOffsetToObjectNumber(self.trailer.topLevelObjectNumber)
            result = self.readObject()
        except TypeError as e:
            raise InvalidPlistException(e)
        return result

    def setCurrentOffsetToObjectNumber(self, objectNumber):
        self.currentOffset = self.offsets[objectNumber]

    def readObject(self):
        result = None
        tmp_byte = self.contents[self.currentOffset:self.currentOffset+1]
        marker_byte = unpack("!B", tmp_byte)[0]
        format = (marker_byte >> 4) & 0x0f
        extra = marker_byte & 0x0f
        self.currentOffset += 1

        def proc_extra(extra):
            if extra == 0b1111:
                #self.currentOffset += 1
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
            extra = proc_extra(extra)
            result = self.readInteger(pow(2, extra))
        # real
        elif format == 0b0010:
            extra = proc_extra(extra)
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
        return result

    def readInteger(self, bytes):
        result = 0
        original_offset = self.currentOffset
        data = self.contents[self.currentOffset:self.currentOffset+bytes]
        result = self.getSizedInteger(data, bytes)
        self.currentOffset = original_offset + bytes
        return result

    def readReal(self, length):
        result = 0.0
        to_read = pow(2, length)
        data = self.contents[self.currentOffset:self.currentOffset+to_read]
        if length == 2: # 4 bytes
            result = unpack('>f', data)[0]
        elif length == 3: # 8 bytes
            result = unpack('>d', data)[0]
        else:
            raise InvalidPlistException("Unknown real of length %d bytes" % to_read)
        return result

    def readRefs(self, count):
        refs = []
        i = 0
        while i < count:
            fragment = self.contents[self.currentOffset:self.currentOffset+self.trailer.objectRefSize]
            ref = self.getSizedInteger(fragment, len(fragment))
            refs.append(ref)
            self.currentOffset += self.trailer.objectRefSize
            i += 1
        return refs

    def readArray(self, count):
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
        result = unpack("!%ds" % length, self.contents[self.currentOffset:self.currentOffset+length])[0]
        self.currentOffset += length
        return result

    def readUnicode(self, length):
        actual_length = length*2
        data = self.contents[self.currentOffset:self.currentOffset+actual_length]
        # unpack not needed?!! data = unpack(">%ds" % (actual_length), data)[0]
        self.currentOffset += actual_length
        return data.decode('utf_16_be')

    def readDate(self):
        global apple_reference_date_offset
        result = unpack(">d", self.contents[self.currentOffset:self.currentOffset+8])[0]
        result = datetime.datetime.utcfromtimestamp(result + apple_reference_date_offset)
        self.currentOffset += 8
        return result

    def readData(self, length):
        result = self.contents[self.currentOffset:self.currentOffset+length]
        self.currentOffset += length
        return Data(result)

    def readUid(self, length):
        return Uid(self.readInteger(length+1))

    def getSizedInteger(self, data, bytes):
        result = 0
        # 1, 2, and 4 byte integers are unsigned
        if bytes == 1:
            result = unpack('>B', data)[0]
        elif bytes == 2:
            result = unpack('>H', data)[0]
        elif bytes == 4:
            result = unpack('>L', data)[0]
        elif bytes == 8:
            result = unpack('>q', data)[0]
        else:
            raise InvalidPlistException("Encountered integer longer than 8 bytes.")
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

class PlistWriter(object):
    header = b('bplist00bybiplist1.0')
    file = None
    byteCounts = None
    trailer = None
    computedUniques = None
    writtenReferences = None
    referencePositions = None
    wrappedTrue = None
    wrappedFalse = None

    def __init__(self, file):
        self.reset()
        self.file = file
        self.wrappedTrue = BoolWrapper(True)
        self.wrappedFalse = BoolWrapper(False)

    def reset(self):
        self.byteCounts = PlistByteCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.trailer = PlistTrailer(0, 0, 0, 0, 0)

        # A set of all the uniques which have been computed.
        self.computedUniques = set()
        # A list of all the uniques which have been written.
        self.writtenReferences = {}
        # A dict of the positions of the written uniques.
        self.referencePositions = {}

    def positionOfObjectReference(self, obj):
        """If the given object has been written already, return its
           position in the offset table. Otherwise, return None."""
        return self.writtenReferences.get(obj)

    def writeRoot(self, root):
        """
        Strategy is:
        - write header
        - wrap root object so everything is hashable
        - compute size of objects which will be written
          - need to do this in order to know how large the object refs
            will be in the list/dict/set reference lists
        - write objects
          - keep objects in writtenReferences
          - keep positions of object references in referencePositions
          - write object references with the length computed previously
        - computer object reference length
        - write object reference positions
        - write trailer
        """
        output = self.header
        wrapped_root = self.wrapRoot(root)
        should_reference_root = True#not isinstance(wrapped_root, HashableWrapper)
        self.computeOffsets(wrapped_root, asReference=should_reference_root, isRoot=True)
        self.trailer = self.trailer._replace(**{'objectRefSize':self.intSize(len(self.computedUniques))})
        (_, output) = self.writeObjectReference(wrapped_root, output)
        output = self.writeObject(wrapped_root, output, setReferencePosition=True)

        # output size at this point is an upper bound on how big the
        # object reference offsets need to be.
        self.trailer = self.trailer._replace(**{
            'offsetSize':self.intSize(len(output)),
            'offsetCount':len(self.computedUniques),
            'offsetTableOffset':len(output),
            'topLevelObjectNumber':0
            })

        output = self.writeOffsetTable(output)
        output += pack('!xxxxxxBBQQQ', *self.trailer)
        self.file.write(output)

    def wrapRoot(self, root):
        if isinstance(root, bool):
            if root is True:
                return self.wrappedTrue
            else:
                return self.wrappedFalse
        elif isinstance(root, set):
            n = set()
            for value in root:
                n.add(self.wrapRoot(value))
            return HashableWrapper(n)
        elif isinstance(root, dict):
            n = {}
            for key, value in iteritems(root):
                n[self.wrapRoot(key)] = self.wrapRoot(value)
            return HashableWrapper(n)
        elif isinstance(root, list):
            n = []
            for value in root:
                n.append(self.wrapRoot(value))
            return HashableWrapper(n)
        elif isinstance(root, tuple):
            n = tuple([self.wrapRoot(value) for value in root])
            return HashableWrapper(n)
        else:
            return root

    def incrementByteCount(self, field, incr=1):
        self.byteCounts = self.byteCounts._replace(**{field:self.byteCounts.__getattribute__(field) + incr})

    def computeOffsets(self, obj, asReference=False, isRoot=False):
        def check_key(key):
            if key is None:
                raise InvalidPlistException('Dictionary keys cannot be null in plists.')
            elif isinstance(key, Data):
                raise InvalidPlistException('Data cannot be dictionary keys in plists.')
            elif not isinstance(key, (binary_type, text_type)):
                raise InvalidPlistException('Keys must be strings.')

        def proc_size(size):
            if size > 0b1110:
                size += self.intSize(size)
            return size
        # If this should be a reference, then we keep a record of it in the
        # uniques table.
        if asReference:
            if obj in self.computedUniques:
                return
            else:
                self.computedUniques.add(obj)

        if obj is None:
            self.incrementByteCount('nullBytes')
        elif isinstance(obj, BoolWrapper):
            self.incrementByteCount('boolBytes')
        elif isinstance(obj, Uid):
            size = self.intSize(obj)
            self.incrementByteCount('uidBytes', incr=1+size)
        elif isinstance(obj, integer_types):
            size = self.intSize(obj)
            self.incrementByteCount('intBytes', incr=1+size)
        elif isinstance(obj, (float)):
            size = self.realSize(obj)
            self.incrementByteCount('realBytes', incr=1+size)
        elif isinstance(obj, datetime.datetime):
            self.incrementByteCount('dateBytes', incr=2)
        elif isinstance(obj, Data):
            size = proc_size(len(obj))
            self.incrementByteCount('dataBytes', incr=1+size)
        elif isinstance(obj, (text_type, binary_type)):
            size = proc_size(len(obj))
            self.incrementByteCount('stringBytes', incr=1+size)
        elif isinstance(obj, HashableWrapper):
            obj = obj.value
            if isinstance(obj, set):
                size = proc_size(len(obj))
                self.incrementByteCount('setBytes', incr=1+size)
                for value in obj:
                    self.computeOffsets(value, asReference=True)
            elif isinstance(obj, (list, tuple)):
                size = proc_size(len(obj))
                self.incrementByteCount('arrayBytes', incr=1+size)
                for value in obj:
                    asRef = True
                    self.computeOffsets(value, asReference=True)
            elif isinstance(obj, dict):
                size = proc_size(len(obj))
                self.incrementByteCount('dictBytes', incr=1+size)
                for key, value in iteritems(obj):
                    check_key(key)
                    self.computeOffsets(key, asReference=True)
                    self.computeOffsets(value, asReference=True)
        else:
            raise InvalidPlistException("Unknown object type.")

    def writeObjectReference(self, obj, output):
        """Tries to write an object reference, adding it to the references
           table. Does not write the actual object bytes or set the reference
           position. Returns a tuple of whether the object was a new reference
           (True if it was, False if it already was in the reference table)
           and the new output.
        """
        position = self.positionOfObjectReference(obj)
        if position is None:
            self.writtenReferences[obj] = len(self.writtenReferences)
            output += self.binaryInt(len(self.writtenReferences) - 1, bytes=self.trailer.objectRefSize)
            return (True, output)
        else:
            output += self.binaryInt(position, bytes=self.trailer.objectRefSize)
            return (False, output)

    def writeObject(self, obj, output, setReferencePosition=False):
        """Serializes the given object to the output. Returns output.
           If setReferencePosition is True, will set the position the
           object was written.
        """
        def proc_variable_length(format, length):
            result = b('')
            if length > 0b1110:
                result += pack('!B', (format << 4) | 0b1111)
                result = self.writeObject(length, result)
            else:
                result += pack('!B', (format << 4) | length)
            return result

        if isinstance(obj, text_type) and obj == u(''):
            # The Apple Plist decoder can't decode a zero length Unicode string.
            obj = b('')

        if setReferencePosition:
            self.referencePositions[obj] = len(output)

        if obj is None:
            output += pack('!B', 0b00000000)
        elif isinstance(obj, BoolWrapper):
            if obj.value is False:
                output += pack('!B', 0b00001000)
            else:
                output += pack('!B', 0b00001001)
        elif isinstance(obj, Uid):
            size = self.intSize(obj)
            output += pack('!B', (0b1000 << 4) | size - 1)
            output += self.binaryInt(obj)
        elif isinstance(obj, integer_types):
            bytes = self.intSize(obj)
            root = math.log(bytes, 2)
            output += pack('!B', (0b0001 << 4) | int(root))
            output += self.binaryInt(obj)
        elif isinstance(obj, float):
            # just use doubles
            output += pack('!B', (0b0010 << 4) | 3)
            output += self.binaryReal(obj)
        elif isinstance(obj, datetime.datetime):
            timestamp = calendar.timegm(obj.utctimetuple())
            timestamp -= apple_reference_date_offset
            output += pack('!B', 0b00110011)
            output += pack('!d', float(timestamp))
        elif isinstance(obj, Data):
            output += proc_variable_length(0b0100, len(obj))
            output += obj
        elif isinstance(obj, text_type):
            bytes = obj.encode('utf_16_be')
            output += proc_variable_length(0b0110, len(bytes)//2)
            output += bytes
        elif isinstance(obj, binary_type):
            bytes = obj
            output += proc_variable_length(0b0101, len(bytes))
            output += bytes
        elif isinstance(obj, HashableWrapper):
            obj = obj.value
            if isinstance(obj, (set, list, tuple)):
                if isinstance(obj, set):
                    output += proc_variable_length(0b1100, len(obj))
                else:
                    output += proc_variable_length(0b1010, len(obj))

                objectsToWrite = []
                for objRef in obj:
                    (isNew, output) = self.writeObjectReference(objRef, output)
                    if isNew:
                        objectsToWrite.append(objRef)
                for objRef in objectsToWrite:
                    output = self.writeObject(objRef, output, setReferencePosition=True)
            elif isinstance(obj, dict):
                output += proc_variable_length(0b1101, len(obj))
                keys = []
                values = []
                objectsToWrite = []
                for key, value in iteritems(obj):
                    keys.append(key)
                    values.append(value)
                for key in keys:
                    (isNew, output) = self.writeObjectReference(key, output)
                    if isNew:
                        objectsToWrite.append(key)
                for value in values:
                    (isNew, output) = self.writeObjectReference(value, output)
                    if isNew:
                        objectsToWrite.append(value)
                for objRef in objectsToWrite:
                    output = self.writeObject(objRef, output, setReferencePosition=True)
        return output

    def writeOffsetTable(self, output):
        """Writes all of the object reference offsets."""
        all_positions = []
        writtenReferences = list(self.writtenReferences.items())
        writtenReferences.sort(key=lambda x: x[1])
        for obj,order in writtenReferences:
            # Porting note: Elsewhere we deliberately replace empty unicdoe strings
            # with empty binary strings, but the empty unicode string
            # goes into writtenReferences.  This isn't an issue in Py2
            # because u'' and b'' have the same hash; but it is in
            # Py3, where they don't.
            if PY3 and obj == u(''):
                obj = b('')
            position = self.referencePositions.get(obj)
            if position is None:
                raise InvalidPlistException("Error while writing offsets table. Object not found. %s" % obj)
            output += self.binaryInt(position, self.trailer.offsetSize)
            all_positions.append(position)
        return output

    def binaryReal(self, obj):
        # just use doubles
        result = pack('>d', obj)
        return result

    def binaryInt(self, obj, bytes=None):
        result = b('')
        if bytes is None:
            bytes = self.intSize(obj)
        if bytes == 1:
            result += pack('>B', obj)
        elif bytes == 2:
            result += pack('>H', obj)
        elif bytes == 4:
            result += pack('>L', obj)
        elif bytes == 8:
            result += pack('>q', obj)
        else:
            raise InvalidPlistException("Core Foundation can't handle integers with size greater than 8 bytes.")
        return result

    def intSize(self, obj):
        """Returns the number of bytes necessary to store the given integer."""
        # SIGNED
        if obj < 0: # Signed integer, always 8 bytes
            return 8
        # UNSIGNED
        elif obj <= 0xFF: # 1 byte
            return 1
        elif obj <= 0xFFFF: # 2 bytes
            return 2
        elif obj <= 0xFFFFFFFF: # 4 bytes
            return 4
        # SIGNED
        # 0x7FFFFFFFFFFFFFFF is the max.
        elif obj <= 0x7FFFFFFFFFFFFFFF: # 8 bytes
            return 8
        else:
            raise InvalidPlistException("Core Foundation can't handle integers with size greater than 8 bytes.")

    def realSize(self, obj):
        return 8

# Libraries end here, program starts
# Written by Dhiru Kholia <dhiru at openwall.com> in September of 2012
# My code is under "Simplified BSD License"

import StringIO
import binascii


def process_file(filename):
    try:
        p1 = readPlist(filename)
    except IOError, e:
        print >> sys.stderr, "%s : %s" % (filename, str(e))
        return -1
    except InvalidPlistException:
        print >> sys.stderr, "%s is not a plist file!" % filename
        return -1

    s = StringIO.StringIO(p1.get('ShadowHashData', [None])[0])
    if not s:
        print >> sys.stderr, "%s : could not find ShadowHashData" % filename
        return -2

    try:
        p2 = readPlist(s)
    except Exception, e:
        print >> sys.stderr, "%s : %s" % (filename, str(e))
        return -3

    d = p2.get('SALTED-SHA512-PBKDF2', None)
    if not d:
        print >> sys.stderr, "%s does not contain SALTED-SHA512-PBKDF2" % filename
        return -4

    salt = d.get('salt')
    entropy = d.get('entropy')
    iterations = d.get('iterations')
    salth = binascii.hexlify(salt)
    entropyh = binascii.hexlify(entropy)
    print "%s:$pbkdf2-hmac-sha512$%d.%s.%s" % (filename, iterations, salth, entropyh[0:128])

    # from passlib.hash import grub_pbkdf2_sha512
    # hash = grub_pbkdf2_sha512.encrypt("password", rounds=iterations, salt=salt)
    # print hash

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s <Mountain Lion .plist files>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
