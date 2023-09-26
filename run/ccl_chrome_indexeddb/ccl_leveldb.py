"""
Copyright 2020-2021, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import typing
import struct
import re
import os
import io
import pathlib
import dataclasses
import enum
from collections import namedtuple
from types import MappingProxyType

import ccl_chrome_indexeddb.ccl_simplesnappy as ccl_simplesnappy

__version__ = "0.4"
__description__ = "A module for reading LevelDB databases"
__contact__ = "Alex Caithness"


def _read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False) -> typing.Optional[typing.Tuple[int, bytes]]:
    """Read varint from a stream.
    If the read is successful: returns a tuple of the (unsigned) value and the raw bytes making up that varint,
    otherwise returns None.
    Can be switched to limit the varint to 32 bit."""
    # this only outputs unsigned
    i = 0
    result = 0
    underlying_bytes = []
    limit = 5 if is_google_32bit else 10
    while i < limit:
        raw = stream.read(1)
        if len(raw) < 1:
            return None
        tmp, = raw
        underlying_bytes.append(tmp)
        result |= ((tmp & 0x7f) << (i * 7))
        if (tmp & 0x80) == 0:
            break
        i += 1
    return result, bytes(underlying_bytes)


def read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False) -> typing.Optional[int]:
    """Convenience version of _read_le_varint that only returns the value or None"""
    x = _read_le_varint(stream, is_google_32bit=is_google_32bit)
    if x is None:
        return None
    else:
        return x[0]


def read_length_prefixed_blob(stream: typing.BinaryIO):
    length = read_le_varint(stream)
    data = stream.read(length)
    if len(data) != length:
        raise ValueError(f"Could not read all data (expected {length}, got {len(data)}")
    return data


@dataclasses.dataclass(frozen=True)
class BlockHandle:
    """See: https://github.com/google/leveldb/blob/master/doc/table_format.md
    A BlockHandle contains an offset and length of a block in an ldb table file"""
    offset: int
    length: int

    @classmethod
    def from_stream(cls, stream: typing.BinaryIO):
        return cls(read_le_varint(stream), read_le_varint(stream))

    @classmethod
    def from_bytes(cls, data: bytes):
        with io.BytesIO(data) as stream:
            return BlockHandle.from_stream(stream)


@dataclasses.dataclass(frozen=True)
class RawBlockEntry:
    """Raw key, value for a record in a LDB file Block, along with the offset within the block from which it came from
    See: https://github.com/google/leveldb/blob/master/doc/table_format.md"""
    key: bytes
    value: bytes
    block_offset: int


class FileType(enum.Enum):
    Ldb = 1
    Log = 2


class KeyState(enum.Enum):
    Deleted = 0
    Live = 1
    Unknown = 2


@dataclasses.dataclass(frozen=True)
class Record:
    """A record from leveldb; includes details of the origin file, state, etc."""

    key: bytes
    value: bytes
    seq: int
    state: KeyState
    file_type: FileType
    origin_file: os.PathLike
    offset: int
    was_compressed: bool

    @property
    def user_key(self):
        if self.file_type == FileType.Ldb:
            if len(self.key) < 8:
                return self.key
            else:
                return self.key[0:-8]
        else:
            return self.key


    @classmethod
    def ldb_record(cls, key: bytes, value: bytes, origin_file: os.PathLike,
                   offset: int, was_compressed: bool):
        seq = (struct.unpack("<Q", key[-8:])[0]) >> 8
        if len(key) > 8:
            state = KeyState.Deleted if key[-8] == 0 else KeyState.Live
        else:
            state = KeyState.Unknown
        return cls(key, value, seq, state, FileType.Ldb, origin_file, offset, was_compressed)

    @classmethod
    def log_record(cls, key: bytes, value: bytes, seq: int, state: KeyState,
                   origin_file: os.PathLike, offset: int):
        return cls(key, value, seq, state, FileType.Log, origin_file, offset, False)


class Block:
    """Block from an .lldb (table) file. See: https://github.com/google/leveldb/blob/master/doc/table_format.md"""
    def __init__(self, raw: bytes, was_compressed: bool, origin: "LdbFile", offset: int):
        self._raw = raw
        self.was_compressed = was_compressed
        self.origin = origin
        self.offset = offset

        self._restart_array_count, = struct.unpack("<I", self._raw[-4:])
        self._restart_array_offset = len(self._raw) - (self._restart_array_count + 1) * 4

    def get_restart_offset(self, index) -> int:
        offset = self._restart_array_offset + (index * 4)
        return struct.unpack("<i", self._raw[offset: offset + 4])[0]

    def get_first_entry_offset(self) -> int:
        return self.get_restart_offset(0)

    def __iter__(self) -> typing.Iterable[RawBlockEntry]:
        offset = self.get_first_entry_offset()
        with io.BytesIO(self._raw) as buff:
            buff.seek(offset)

            key = b""

            while buff.tell() < self._restart_array_offset:
                start_offset = buff.tell()
                shared_length = read_le_varint(buff, is_google_32bit=True)
                non_shared_length = read_le_varint(buff, is_google_32bit=True)
                value_length = read_le_varint(buff, is_google_32bit=True)

                # sense check
                if offset >= self._restart_array_offset:
                    raise ValueError("Reading start of entry past the start of restart array")
                if shared_length > len(key):
                    raise ValueError("Shared key length is larger than the previous key")

                key = key[:shared_length] + buff.read(non_shared_length)
                value = buff.read(value_length)

                yield RawBlockEntry(key, value, start_offset)


class LdbFile:
    """A leveldb table (.ldb or .sst) file."""
    BLOCK_TRAILER_SIZE = 5
    FOOTER_SIZE = 48
    MAGIC = 0xdb4775248b80fb57

    def __init__(self, file: pathlib.Path):
        if not file.exists():
            raise FileNotFoundError(file)

        self.path = file
        self.file_no = int(file.stem, 16)

        self._f = file.open("rb")
        self._f.seek(-LdbFile.FOOTER_SIZE, os.SEEK_END)

        self._meta_index_handle = BlockHandle.from_stream(self._f)
        self._index_handle = BlockHandle.from_stream(self._f)
        self._f.seek(-8, os.SEEK_END)
        magic, = struct.unpack("<Q", self._f.read(8))
        if magic != LdbFile.MAGIC:
            raise ValueError(f"Invalid magic number in {file}")

        self._index = self._read_index()

    def _read_block(self, handle: BlockHandle):
        # block is the size in the blockhandle plus the trailer
        # the trailer is 5 bytes long.
        # idx  size  meaning
        # 0    1     CompressionType (0 = none, 1 = snappy)
        # 1    4     CRC32

        self._f.seek(handle.offset)
        raw_block = self._f.read(handle.length)
        trailer = self._f.read(LdbFile.BLOCK_TRAILER_SIZE)

        if len(raw_block) != handle.length or len(trailer) != LdbFile.BLOCK_TRAILER_SIZE:
            raise ValueError(f"Could not read all of the block at offset {handle.offset} in file {self.path}")

        is_compressed = trailer[0] != 0
        if is_compressed:
            with io.BytesIO(raw_block) as buff:
                raw_block = ccl_simplesnappy.decompress(buff)

        return Block(raw_block, is_compressed, self, handle.offset)

    def _read_index(self) -> typing.Tuple[typing.Tuple[bytes, BlockHandle], ...]:
        index_block = self._read_block(self._index_handle)
        # key is earliest key, value is BlockHandle to that data block
        return tuple((entry.key, BlockHandle.from_bytes(entry.value))
                     for entry in index_block)

    def __iter__(self) -> typing.Iterable[Record]:
        """Iterate Records in this Table file"""
        for block_key, handle in self._index:
            block = self._read_block(handle)
            for entry in block:
                yield Record.ldb_record(
                    entry.key, entry.value, self.path,
                    block.offset if block.was_compressed else block.offset + entry.block_offset,
                    block.was_compressed)

    def close(self):
        self._f.close()


class LogEntryType(enum.IntEnum):
    Zero = 0
    Full = 1
    First = 2
    Middle = 3
    Last = 4


class LogFile:
    """A levelDb log (.log) file"""
    LOG_ENTRY_HEADER_SIZE = 7
    LOG_BLOCK_SIZE = 32768

    def __init__(self, file: pathlib.Path):
        if not file.exists():
            raise FileNotFoundError(file)

        self.path = file
        self.file_no = int(file.stem, 16)

        self._f = file.open("rb")

    def _get_raw_blocks(self) -> typing.Iterable[bytes]:
        self._f.seek(0)

        while chunk := self._f.read(LogFile.LOG_BLOCK_SIZE):
            yield chunk

    def _get_batches(self) -> typing.Iterable[typing.Tuple[int, bytes]]:
        in_record = False
        start_block_offset = 0
        block = b""
        for idx, chunk_ in enumerate(self._get_raw_blocks()):
            with io.BytesIO(chunk_) as buff:
                while buff.tell() < LogFile.LOG_BLOCK_SIZE - 6:
                    header = buff.read(7)
                    if len(header) < 7:
                        break
                    crc, length, block_type = struct.unpack("<IHB", header)

                    if block_type == LogEntryType.Full:
                        if in_record:
                            raise ValueError(f"Full block whilst still building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        in_record = False
                        yield idx * LogFile.LOG_BLOCK_SIZE + buff.tell(), buff.read(length)
                    elif block_type == LogEntryType.First:
                        if in_record:
                            raise ValueError(f"First block whilst still building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        start_block_offset = idx * LogFile.LOG_BLOCK_SIZE + buff.tell()
                        block = buff.read(length)
                        in_record = True
                    elif block_type == LogEntryType.Middle:
                        if not in_record:
                            raise ValueError(f"Middle block whilst not building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        block += buff.read(length)
                    elif block_type == LogEntryType.Last:
                        if not in_record:
                            raise ValueError(f"Last block whilst not building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        block += buff.read(length)
                        in_record = False
                        yield start_block_offset * LogFile.LOG_BLOCK_SIZE, block
                    else:
                        raise ValueError()  # Cannot happen

    def __iter__(self) -> typing.Iterable[Record]:
        """Iterate Records in this Log file"""
        for batch_offset, batch in self._get_batches():
            # as per write_batch and write_batch_internal
            # offset       length      description
            # 0            8           (u?)int64 Sequence number
            # 8            4           (u?)int32 Count - the log batch can contain multple entries
            #
            #         Then Count * the following:
            #
            # 12           1           ValueType (KeyState as far as this library is concerned)
            # 13           1-4         VarInt32 length of key
            # ...          ...         Key data
            # ...          1-4         VarInt32 length of value
            # ...          ...         Value data

            with io.BytesIO(batch) as buff:  # it's just easier this way
                header = buff.read(12)
                seq, count = struct.unpack("<QI", header)

                for i in range(count):
                    start_offset = batch_offset + buff.tell()
                    state = KeyState(buff.read(1)[0])
                    key_length = read_le_varint(buff, is_google_32bit=True)
                    key = buff.read(key_length)
                    # print(key)
                    if state != KeyState.Deleted:
                        value_length = read_le_varint(buff, is_google_32bit=True)
                        value = buff.read(value_length)
                    else:
                        value = b""

                    yield Record.log_record(key, value, seq + i, state, self.path, start_offset)

    def close(self):
        self._f.close()


class VersionEditTag(enum.IntEnum):
    """
    See: https://github.com/google/leveldb/blob/master/db/version_edit.cc
    """
    Comparator = 1,
    LogNumber = 2,
    NextFileNumber = 3,
    LastSequence = 4,
    CompactPointer = 5,
    DeletedFile = 6,
    NewFile = 7,
    # 8 was used for large value refs
    PrevLogNumber = 9


@dataclasses.dataclass(frozen=True)
class VersionEdit:
    """
    See:
    https://github.com/google/leveldb/blob/master/db/version_edit.h
    https://github.com/google/leveldb/blob/master/db/version_edit.cc
    """
    comparator: str = None
    log_number: int = None
    prev_log_number: int = None
    last_sequence: int = None
    next_file_number: int = None
    compaction_pointers: typing.Tuple[typing.Any] = tuple()
    deleted_files: typing.Tuple[typing.Any] = tuple()
    new_files: typing.Tuple[typing.Any] = tuple()

    @classmethod
    def from_buffer(cls, buffer: bytes):
        comparator = None
        log_number = None
        prev_log_number = None
        last_sequence = None
        next_file_number = None
        compaction_pointers = []
        deleted_files = []
        new_files = []

        compaction_pointer_nt = namedtuple("CompactionPointer", ["level", "pointer"])
        deleted_file_nt = namedtuple("DeletedFile", ["level", "file_no"])
        new_file_nt = namedtuple("NewFile", ["level", "file_no", "file_size", "smallest_key", "largest_key"])

        with io.BytesIO(buffer) as b:
            while b.tell() < len(buffer) - 1:
                tag = read_le_varint(b, is_google_32bit=True)

                if tag == VersionEditTag.Comparator:
                    comparator = read_length_prefixed_blob(b).decode("utf-8")
                elif tag == VersionEditTag.LogNumber:
                    log_number = read_le_varint(b)
                elif tag == VersionEditTag.PrevLogNumber:
                    prev_log_number = read_le_varint(b)
                elif tag == VersionEditTag.NextFileNumber:
                    next_file_number = read_le_varint(b)
                elif tag == VersionEditTag.LastSequence:
                    last_sequence = read_le_varint(b)
                elif tag == VersionEditTag.CompactPointer:
                    level = read_le_varint(b, is_google_32bit=True)
                    compaction_pointer = read_length_prefixed_blob(b)
                    compaction_pointers.append(compaction_pointer_nt(level, compaction_pointer))
                elif tag == VersionEditTag.DeletedFile:
                    level = read_le_varint(b, is_google_32bit=True)
                    file_no = read_le_varint(b)
                    deleted_files.append(deleted_file_nt(level, file_no))
                elif tag == VersionEditTag.NewFile:
                    level = read_le_varint(b, is_google_32bit=True)
                    file_no = read_le_varint(b)
                    file_size = read_le_varint(b)
                    smallest = read_length_prefixed_blob(b)
                    largest = read_length_prefixed_blob(b)
                    new_files.append(new_file_nt(level, file_no, file_size, smallest, largest))

        return cls(comparator, log_number, prev_log_number, last_sequence, next_file_number, tuple(compaction_pointers),
            tuple(deleted_files), tuple(new_files))


class ManifestFile:
    """
    Represents a manifest file which contains database metadata.
    Manifest files are, at a high level, formatted like a log file in terms of the block and batch format,
    but the data within the batches follow their own format.

    Main use is to identify the level of files, use `file_to_level` property to look up levels based on file no.

    See:
    https://github.com/google/leveldb/blob/master/db/version_edit.h
    https://github.com/google/leveldb/blob/master/db/version_edit.cc
    """

    MANIFEST_FILENAME_PATTERN = "MANIFEST-([0-9A-F]{6})"

    def __init__(self, path: pathlib.Path):
        if match := re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, path.name):
            self.file_no = int(match.group(1))
        else:
            raise ValueError("Invalid name for Manifest")

        self._f = path.open("rb")
        self.path = path

        self.file_to_level = {}
        for edit in self:
            if edit.new_files:
                for nf in edit.new_files:
                    self.file_to_level[nf.file_no] = nf.level

        self.file_to_level = MappingProxyType(self.file_to_level)

    def _get_raw_blocks(self) -> typing.Iterable[bytes]:
        self._f.seek(0)

        while chunk := self._f.read(LogFile.LOG_BLOCK_SIZE):
            yield chunk

    def _get_batches(self) -> typing.Iterable[typing.Tuple[int, bytes]]:
        in_record = False
        start_block_offset = 0
        block = b""
        for idx, chunk_ in enumerate(self._get_raw_blocks()):
            with io.BytesIO(chunk_) as buff:
                while buff.tell() < LogFile.LOG_BLOCK_SIZE - 6:
                    header = buff.read(7)
                    if len(header) < 7:
                        break
                    crc, length, block_type = struct.unpack("<IHB", header)

                    if block_type == LogEntryType.Full:
                        if in_record:
                            raise ValueError(f"Full block whilst still building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        in_record = False
                        yield idx * LogFile.LOG_BLOCK_SIZE + buff.tell(), buff.read(length)
                    elif block_type == LogEntryType.First:
                        if in_record:
                            raise ValueError(f"First block whilst still building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        start_block_offset = idx * LogFile.LOG_BLOCK_SIZE + buff.tell()
                        block = buff.read(length)
                        in_record = True
                    elif block_type == LogEntryType.Middle:
                        if not in_record:
                            raise ValueError(f"Middle block whilst not building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        block += buff.read(length)
                    elif block_type == LogEntryType.Last:
                        if not in_record:
                            raise ValueError(f"Last block whilst not building a block at offset "
                                             f"{idx * LogFile.LOG_BLOCK_SIZE + buff.tell()} in {self.path}")
                        block += buff.read(length)
                        in_record = False
                        yield start_block_offset * LogFile.LOG_BLOCK_SIZE, block
                    else:
                        raise ValueError()  # Cannot happen

    def __iter__(self):
        for batch_offset, batch in self._get_batches():
            yield VersionEdit.from_buffer(batch)

    def close(self):
        self._f.close()


class RawLevelDb:
    DATA_FILE_PATTERN = r"[0-9]{6}\.(ldb|log|sst)"

    def __init__(self, in_dir: os.PathLike):

        self._in_dir = pathlib.Path(in_dir)
        if not self._in_dir.is_dir():
            raise ValueError("in_dir is not a directory")

        self._files = []
        latest_manifest = (0, None)
        for file in self._in_dir.iterdir():
            if file.is_file() and re.match(RawLevelDb.DATA_FILE_PATTERN, file.name):
                if file.suffix.lower() == ".log":
                    self._files.append(LogFile(file))
                elif file.suffix.lower() == ".ldb" or file.suffix.lower() == ".sst":
                    self._files.append(LdbFile(file))
            if file.is_file() and re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, file.name):
                manifest_no = int(re.match(ManifestFile.MANIFEST_FILENAME_PATTERN, file.name).group(1), 16)
                if latest_manifest[0] < manifest_no:
                    latest_manifest = (manifest_no, file)

        self.manifest = ManifestFile(latest_manifest[1]) if latest_manifest[1] is not None else None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def in_dir_path(self) -> pathlib.Path:
        return self._in_dir

    def iterate_records_raw(self, *, reverse=False) -> typing.Iterable[Record]:
        for file_containing_records in sorted(self._files, reverse=reverse, key=lambda x: x.file_no):
            yield from file_containing_records

    def close(self):
        for file in self._files:
            file.close()
        if self.manifest:
            self.manifest.close()
