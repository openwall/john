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

import sys
import struct
import os
import pathlib
import io
import enum
import datetime
import dataclasses
import types
import typing

import ccl_leveldb
import ccl_v8_value_deserializer
import ccl_blink_value_deserializer

__version__ = "0.6"
__description__ = "Module for reading Chromium IndexedDB LevelDB databases."
__contact__ = "Alex Caithness"


# TODO: need to go through and ensure that we have endianness right in all cases
#  (it should sit behind a switch for integers, fixed for most other stuff)


def _read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False):
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


def read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False):
    x = _read_le_varint(stream, is_google_32bit=is_google_32bit)
    if x is None:
        return None
    else:
        return x[0]


def _le_varint_from_bytes(data: bytes):
    with io.BytesIO(data) as buff:
        return _read_le_varint(buff)


def le_varint_from_bytes(data: bytes):
    with io.BytesIO(data) as buff:
        return read_le_varint(buff)


class IdbKeyType(enum.IntEnum):
    Null = 0
    String = 1
    Date = 2
    Number = 3
    Array = 4
    MinKey = 5
    Binary = 6


class IdbKey:
    # See: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_leveldb_coding.cc
    def __init__(self, buffer: bytes):
        self.raw_key = buffer
        self.key_type = IdbKeyType(buffer[0])
        raw_key = buffer[1:]

        if self.key_type == IdbKeyType.Null:
            self.value = None
            self._raw_length = 1
        elif self.key_type == IdbKeyType.String:
            str_len, varint_raw = _le_varint_from_bytes(raw_key)
            self.value = raw_key[len(varint_raw):len(varint_raw) + str_len * 2].decode("utf-16-be")
            self._raw_length = 1 + len(varint_raw) + str_len * 2
        elif self.key_type == IdbKeyType.Date:
            ts, = struct.unpack("<d", raw_key[0:8])
            self.value = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ts)
            self._raw_length = 9
        elif self.key_type == IdbKeyType.Number:
            self.value = struct.unpack("<d", raw_key[0:8])[0]
            self._raw_length = 9
        elif self.key_type == IdbKeyType.Array:
            array_count, varint_raw = _le_varint_from_bytes(raw_key)
            raw_key = raw_key[len(varint_raw):]
            self.value = []
            self._raw_length = 1 + len(varint_raw)
            for i in range(array_count):
                key = IdbKey(raw_key)
                raw_key = raw_key[key._raw_length:]
                self._raw_length += key._raw_length
                self.value.append(key)
            self.value = tuple(self.value)
        elif self.key_type == IdbKeyType.MinKey:
            # TODO: not sure what this actually implies, the code doesn't store a value
            self.value = None
            self._raw_length = 1
            raise NotImplementedError()
        elif self.key_type == IdbKeyType.Binary:
            bin_len, varint_raw = _le_varint_from_bytes(raw_key)
            self.value = raw_key[len(varint_raw):len(varint_raw) + bin_len]
            self._raw_length = 1 + len(varint_raw) + bin_len
        else:
            raise ValueError()  # Shouldn't happen

        # trim the raw_key in case this is an inner key:
        self.raw_key = self.raw_key[0: self._raw_length]

    def __repr__(self):
        return f"<IdbKey {self.value}>"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        if not isinstance(other, IdbKey):
            raise NotImplementedError()
        return self.raw_key == other.raw_key

    def __ne__(self, other):
        return not self == other


class IndexedDBExternalObjectType(enum.IntEnum):
    # see: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_external_object.h
    Blob = 0
    File = 1
    NativeFileSystemHandle = 2


class IndexedDBExternalObject:
    # see: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_backing_store.cc
    # for encoding.

    def __init__(self, object_type: IndexedDBExternalObjectType, blob_number: typing.Optional[int],
                 mime_type: typing.Optional[str], size: typing.Optional[int],
                 file_name: typing.Optional[str], last_modified: typing.Optional[datetime.datetime],
                 native_file_token: typing.Optional):
        self.object_type = object_type
        self.blob_number = blob_number
        self.mime_type = mime_type
        self.size = size
        self.file_name = file_name
        self.last_modified = last_modified
        self.native_file_token = native_file_token

    @classmethod
    def from_stream(cls, stream: typing.BinaryIO):
        blob_type = IndexedDBExternalObjectType(stream.read(1)[0])
        if blob_type in (IndexedDBExternalObjectType.Blob, IndexedDBExternalObjectType.File):
            blob_number = read_le_varint(stream)
            mime_type_length = read_le_varint(stream)
            mime_type = stream.read(mime_type_length * 2).decode("utf-16-be")
            data_size = read_le_varint(stream)

            if blob_type == IndexedDBExternalObjectType.File:
                file_name_length = read_le_varint(stream)
                file_name = stream.read(file_name_length * 2).decode("utf-16-be")
                x, x_raw = _read_le_varint(stream)
                last_modified_td = datetime.timedelta(microseconds=x)
                last_modified = datetime.datetime(1601, 1, 1) + last_modified_td
                return cls(blob_type, blob_number, mime_type, data_size, file_name,
                           last_modified, None)
            else:
                return cls(blob_type, blob_number, mime_type, data_size, None, None, None)
        else:
            raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class DatabaseId:
    dbid_no: int
    origin: str
    name: str


class GlobalMetadata:
    def __init__(self, raw_meta_dict: dict):
        # TODO: more of these meta types if required
        self.backing_store_schema_version = None
        if raw_schema_version := raw_meta_dict.get("\x00\x00\x00\x00\x00"):
            self.backing_store_schema_version = le_varint_from_bytes(raw_schema_version)

        self.max_allocated_db_id = None
        if raw_max_db_id := raw_meta_dict.get("\x00\x00\x00\x00\x01"):
            self.max_allocated_db_id = le_varint_from_bytes(raw_max_db_id)

        database_ids_raw = (raw_meta_dict[x] for x in raw_meta_dict
                            if x.startswith(b"\x00\x00\x00\x00\xc9"))

        dbids = []
        for dbid_rec in database_ids_raw:
            with io.BytesIO(dbid_rec.key[5:]) as buff:
                origin_length = read_le_varint(buff)
                origin = buff.read(origin_length * 2).decode("utf-16-be")
                db_name_length = read_le_varint(buff)
                db_name = buff.read(db_name_length * 2).decode("utf-16-be")

            db_id_no = le_varint_from_bytes(dbid_rec.value)

            dbids.append(DatabaseId(db_id_no, origin, db_name))

        self.db_ids = tuple(dbids)


class DatabaseMetadataType(enum.IntEnum):
    OriginName = 0  # String
    DatabaseName = 1  # String
    IdbVersionString = 2  # String (and obsolete)
    MaximumObjectStoreId = 3  # Int
    IdbVersion = 4  # Varint
    BlobNumberGeneratorCurrentNumber = 5  # Varint


class DatabaseMetadata:
    def __init__(self, raw_meta: dict):
        self._metas = types.MappingProxyType(raw_meta)

    def get_meta(self, db_id: int, meta_type: DatabaseMetadataType) -> typing.Optional[typing.Union[str, int]]:
        record = self._metas.get((db_id, meta_type))
        if not record:
            return None

        if meta_type == DatabaseMetadataType.MaximumObjectStoreId:
            return le_varint_from_bytes(record.value)

        # TODO
        raise NotImplementedError()


class ObjectStoreMetadataType(enum.IntEnum):
    StoreName = 0  # String
    KeyPath = 1  # IDBKeyPath
    AutoIncrementFlag = 2  # Bool
    IsEvictable = 3  # Bool (and obsolete apparently)
    LastVersionNumber = 4  # Int
    MaximumAllocatedIndexId = 5  # Int
    HasKeyPathFlag = 6  # Bool (and obsolete apparently)
    KeygeneratorCurrentNumber = 7  # Int


class ObjectStoreMetadata:
    # All metadata fields are prefaced by a 0x00 byte
    def __init__(self, raw_meta: dict):
        self._metas = types.MappingProxyType(raw_meta)

    def get_meta(self, db_id: int, obj_store_id: int, meta_type: ObjectStoreMetadataType):
        record = self._metas.get((db_id, obj_store_id, meta_type))
        if not record:
            return None

        if meta_type == ObjectStoreMetadataType.StoreName:
            return record.value.decode("utf-16-be")

        # TODO
        raise NotImplementedError()


class IndexedDbRecord:
    def __init__(
            self, owner: "IndexedDb", db_id: int, obj_store_id: int, key: IdbKey,
            value: typing.Any, is_live: bool, ldb_seq_no: int):
        self.owner = owner
        self.db_id = db_id
        self.obj_store_id = obj_store_id
        self.key = key
        self.value = value
        self.is_live = is_live
        self.sequence_number = ldb_seq_no

    def resolve_blob_index(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> IndexedDBExternalObject:
        """Resolve a ccl_blink_value_deserializer.BlobIndex to its IndexedDBExternalObject
         to get metadata (file name, timestamps, etc)"""
        return self.owner.get_blob_info(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)

    def get_blob_stream(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> typing.BinaryIO:
        """Resolve a ccl_blink_value_deserializer.BlobIndex to a stream of its content"""
        return self.owner.get_blob(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)


class IndexedDb:
    # This will be informative for a lot of the data below:
    # https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/leveldb_coding_scheme.md

    # Of note, the first byte of the key defines the length of the db_id, obj_store_id and index_id in bytes:
    # 0b xxxyyyzz (x = db_id size - 1, y = obj_store size - 1, z = index_id - 1)
    # Currently I just assume that everything falls between 1 and 127 for simplicity as it makes scanning the keys
    # lots easier.
    def __init__(self, leveldb_dir: os.PathLike, leveldb_blob_dir: os.PathLike = None):
        self._db = ccl_leveldb.RawLevelDb(leveldb_dir)
        self._blob_dir = leveldb_blob_dir
        self.global_metadata = GlobalMetadata(self._get_raw_global_metadata())
        self.database_metadata = DatabaseMetadata(self._get_raw_database_metadata())
        self.object_store_meta = ObjectStoreMetadata(self._get_raw_object_store_metadata())

        self._blob_lookup_cache = {}

    @staticmethod
    def make_prefix(db_id: int, obj_store_id: int, index_id: int) -> bytes:
        def count_bytes(val):
            i = 0
            while val > 0:
                i += 1
                val = val >> 8
            return i

        def yield_le_bytes(val):
            if val < 0:
                raise ValueError
            while val > 0:
                yield val & 0xff
                val >> 8

        db_id_size = count_bytes(db_id)
        obj_store_id_size = count_bytes(obj_store_id)
        index_id_size = count_bytes(index_id)

        if db_id_size > 8 or obj_store_id_size > 8 or index_id_size > 4:
            raise ValueError("id sizes are too big")

        byte_one = ((db_id_size - 1) << 5) | ((obj_store_id_size - 1) << 2) | index_id_size
        return bytes([byte_one, *yield_le_bytes(db_id), *yield_le_bytes(obj_store_id), *yield_le_bytes(index_id)])

    def get_database_metadata(self, db_id: int, meta_type: DatabaseMetadataType):
        return self.database_metadata.get_meta(db_id, meta_type)

    def get_object_store_metadata(self, db_id: int, obj_store_id: int, meta_type: ObjectStoreMetadataType):
        return self.object_store_meta.get_meta(db_id, obj_store_id, meta_type)

    def _get_raw_global_metadata(self, live_only=True) -> typing.Dict[bytes, ccl_leveldb.Record]:
        # Global metadata always has the prefix 0 0 0 0
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")
        meta = {}
        for record in self._db.iterate_records_raw(reverse=True):
            if record.key.startswith(b"\x00\x00\x00\x00") and record.state == ccl_leveldb.KeyState.Live:
                # we only want live keys and the newest version thereof (highest seq)
                if record.key not in meta or meta[record.key].seq < record.seq:
                    meta[record.key] = record

        return meta

    def _get_raw_database_metadata(self, live_only=True):
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")

        db_meta = {}

        for db_id in self.global_metadata.db_ids:
            if db_id.dbid_no > 0x7f:
                raise NotImplementedError("there could be this many dbs, but I don't support it yet")

            prefix = bytes([0, db_id.dbid_no, 0, 0])
            for record in self._db.iterate_records_raw(reverse=True):
                if record.key.startswith(prefix) and record.state == ccl_leveldb.KeyState.Live:
                    # we only want live keys and the newest version thereof (highest seq)
                    meta_type = record.key[len(prefix)]
                    old_version = db_meta.get((db_id.dbid_no, meta_type))
                    if old_version is None or old_version.seq < record.seq:
                        db_meta[(db_id.dbid_no, meta_type)] = record

        return db_meta

    def _get_raw_object_store_metadata(self, live_only=True):
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")

        os_meta = {}

        for db_id in self.global_metadata.db_ids:
            if db_id.dbid_no > 0x7f:
                raise NotImplementedError("there could be this many dbs, but I don't support it yet")

            prefix = bytes([0, db_id.dbid_no, 0, 0, 50])

            for record in self._db.iterate_records_raw(reverse=True):
                if record.key.startswith(prefix) and record.state == ccl_leveldb.KeyState.Live:
                    # we only want live keys and the newest version thereof (highest seq)
                    objstore_id, varint_raw = _le_varint_from_bytes(record.key[len(prefix):])
                    meta_type = record.key[len(prefix) + len(varint_raw)]

                    old_version = os_meta.get((db_id.dbid_no, objstore_id, meta_type))

                    if old_version is None or old_version.seq < record.seq:
                        os_meta[(db_id.dbid_no, objstore_id, meta_type)] = record

        return os_meta

    def iterate_records(
            self, db_id: int, store_id: int, *,
            live_only=False, bad_deserializer_data_handler: typing.Callable[[IdbKey, bytes], typing.Any] = None):
        if db_id > 0x7f or store_id > 0x7f:
            raise NotImplementedError("there could be this many dbs or object stores, but I don't support it yet")

        blink_deserializer = ccl_blink_value_deserializer.BlinkV8Deserializer()

        # goodness me this is a slow way of doing things
        prefix = bytes([0, db_id, store_id, 1])
        for record in self._db.iterate_records_raw():
            if record.key.startswith(prefix):
                key = IdbKey(record.key[len(prefix):])
                if not record.value:
                    # empty values will obviously fail, returning None is probably better than dying.
                    return key, None
                value_version, varint_raw = _le_varint_from_bytes(record.value)
                val_idx = len(varint_raw)
                # read the blink envelope
                blink_type_tag = record.value[val_idx]
                if blink_type_tag != 0xff:
                    # TODO: probably don't want to fail hard here long term...
                    if bad_deserializer_data_handler is not None:
                        bad_deserializer_data_handler(key, record.value)
                        continue
                    else:
                        raise ValueError("Blink type tag not present")
                val_idx += 1

                blink_version, varint_raw = _le_varint_from_bytes(record.value[val_idx:])

                val_idx += len(varint_raw)

                obj_raw = io.BytesIO(record.value[val_idx:])
                deserializer = ccl_v8_value_deserializer.Deserializer(
                    obj_raw, host_object_delegate=blink_deserializer.read)
                try:
                    value = deserializer.read()
                except Exception:
                    if bad_deserializer_data_handler is not None:
                        bad_deserializer_data_handler(key, record.value)
                        continue
                    raise
                yield IndexedDbRecord(self, db_id, store_id, key, value,
                                      record.state == ccl_leveldb.KeyState.Live, record.seq)

    def get_blob_info(self, db_id: int, store_id: int, raw_key: bytes, file_index: int) -> IndexedDBExternalObject:
        if db_id > 0x7f or store_id > 0x7f:
            raise NotImplementedError("there could be this many dbs, but I don't support it yet")

        if result := self._blob_lookup_cache.get((db_id, store_id, raw_key, file_index)):
            return result

        # goodness me this is a slow way of doing things,
        # TODO: we should at least cache along the way to our record
        prefix = bytes([0, db_id, store_id, 3])
        for record in self._db.iterate_records_raw():
            if record.key.startswith(prefix):
                buff = io.BytesIO(record.value)
                idx = 0
                while buff.tell() < len(record.value):
                    blob_info = IndexedDBExternalObject.from_stream(buff)
                    self._blob_lookup_cache[(db_id, store_id, raw_key, idx)] = blob_info
                    idx += 1
                break

        if result := self._blob_lookup_cache.get((db_id, store_id, raw_key, file_index)):
            return result
        else:
            raise KeyError((db_id, store_id, raw_key, file_index))

    def get_blob(self, db_id: int, store_id: int, raw_key: bytes, file_index: int) -> typing.BinaryIO:
        # Some detail here: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/README.md
        if self._blob_dir is None:
            raise ValueError("Can't resolve blob if blob dir is not set")
        info = self.get_blob_info(db_id, store_id, raw_key, file_index)

        # path will be: origin.blob/database id/top 16 bits of blob number with two digits/blob number
        # TODO: check if this is still the case on non-windows systems
        path = pathlib.Path(self._blob_dir, str(db_id), f"{info.blob_number >> 8:02x}", f"{info.blob_number:x}")

        if path.exists():
            return path.open("rb")

        raise FileNotFoundError(path)

    @property
    def database_path(self):
        return self._db.in_dir_path


class WrappedObjectStore:
    def __init__(self, raw_db: IndexedDb,  dbid_no: int, obj_store_id: int):
        self._raw_db = raw_db
        self._dbid_no = dbid_no
        self._obj_store_id = obj_store_id

    @property
    def object_store_id(self):
        return self._obj_store_id

    @property
    def name(self) -> str:
        return self._raw_db.get_object_store_metadata(
            self._dbid_no, self._obj_store_id, ObjectStoreMetadataType.StoreName)

    @staticmethod
    def _log_error(key: IdbKey, data: bytes):
        sys.stderr.write(f"ERROR decoding key: {key}\n")

    def get_blob(self, raw_key: bytes, file_index: int) -> typing.BinaryIO:
        return self._raw_db.get_blob(self._dbid_no, self.object_store_id, raw_key, file_index)

    # def __iter__(self):
    #     yield from self._raw_db.iterate_records(self._dbid_no, self._obj_store_id)

    def iterate_records(
            self, *, live_only=False, errors_to_stdout=False,
            bad_deserializer_data_handler: typing.Callable[[IdbKey, bytes], typing.Any] = None):

        def _handler(key, record):
            if bad_deserializer_data_handler is not None:
                bad_deserializer_data_handler(key, record)
            if errors_to_stdout:
                WrappedObjectStore._log_error(key, record)

        handler = _handler if errors_to_stdout or bad_deserializer_data_handler is not None else None

        yield from self._raw_db.iterate_records(
            self._dbid_no, self._obj_store_id, live_only=live_only,
            bad_deserializer_data_handler=handler)

    def __repr__(self):
        return f"<WrappedObjectStore: object_store_id={self.object_store_id}; name={self.name}>"


class WrappedDatabase:
    def __init__(self, raw_db: IndexedDb,  dbid: DatabaseId):
        self._raw_db = raw_db
        self._dbid = dbid

        names = []
        for obj_store_id in range(1, self.object_store_count + 1):
            names.append(self._raw_db.get_object_store_metadata(
                self.db_number, obj_store_id, ObjectStoreMetadataType.StoreName))
        self._obj_store_names = tuple(names)
        # pre-compile object store wrappers as there's little overhead
        self._obj_stores = tuple(
            WrappedObjectStore(
                self._raw_db, self.db_number, i) for i in range(1, self.object_store_count + 1))

    @property
    def name(self) -> str:
        return self._dbid.name

    @property
    def origin(self) -> str:
        return self._dbid.origin

    @property
    def db_number(self) -> int:
        return self._dbid.dbid_no

    @property
    def object_store_count(self) -> int:
        # NB obj store ids are enumerated from 1.
        return self._raw_db.get_database_metadata(
            self.db_number,
            DatabaseMetadataType.MaximumObjectStoreId) or 0  # returns None if there are none.

    @property
    def object_store_names(self) -> typing.Iterable[str]:
        yield from self._obj_store_names

    def get_object_store_by_id(self, obj_store_id: int) -> WrappedObjectStore:
        if obj_store_id > 0 and obj_store_id <= self.object_store_count:
            return self._obj_stores[obj_store_id - 1]
        raise ValueError("obj_store_id must be greater than zero and less or equal to object_store_count "
                         "NB object stores are enumerated from 1 - there is no store with id 0")

    def get_object_store_by_name(self, name: str) -> WrappedObjectStore:
        if name in self:
            return self.get_object_store_by_id(self._obj_store_names.index(name) + 1)
        raise KeyError(f"{name} is not an object store in this database")

    def __len__(self):
        len(self._obj_stores)

    def __contains__(self, item):
        return item in self._obj_store_names

    def __getitem__(self, item) -> WrappedObjectStore:
        if isinstance(item, int):
            return self.get_object_store_by_id(item)
        elif isinstance(item, str):
            return self.get_object_store_by_name(item)
        raise TypeError("Key can only be str (name) or int (id number)")

    def __repr__(self):
        return f"<WrappedDatabase: id={self.db_number}; name={self.name}; origin={self.origin}>"


class WrappedIndexDB:
    def __init__(self, leveldb_dir: os.PathLike, leveldb_blob_dir: os.PathLike = None):
        self._raw_db = IndexedDb(leveldb_dir, leveldb_blob_dir)
        self._multiple_origins = len(set(x.origin for x in self._raw_db.global_metadata.db_ids)) > 1

        self._db_number_lookup = {
            x.dbid_no: WrappedDatabase(self._raw_db, x)
            for x in self._raw_db.global_metadata.db_ids}
        # set origin to 0 if there's only 1 and we'll ignore it in all lookups
        self._db_name_lookup = {
            (x.name, x.origin if self.has_multiple_origins else 0): x
            for x in self._db_number_lookup.values()}

    @property
    def database_count(self):
        return len(self._db_number_lookup)

    @property
    def database_ids(self):
        yield from self._raw_db.global_metadata.db_ids

    @property
    def has_multiple_origins(self):
        return self._multiple_origins

    def __len__(self):
        len(self._db_number_lookup)

    def __contains__(self, item):
        if isinstance(item, str):
            if self.has_multiple_origins:
                raise ValueError(
                    "Database contains multiple origins, lookups must be provided as a tuple of (name, origin)")
            return (item, 0) in self._db_name_lookup
        elif isinstance(item, tuple) and len(item) == 2:
            name, origin = item
            if not self.has_multiple_origins:
                origin = 0  # origin ignored if not needed
            return (name, origin) in self._db_name_lookup
        elif isinstance(item, int):
            return item in self._db_number_lookup
        else:
            raise TypeError("keys must be provided as a tuple of (name, origin) or a str (if only single origin) or int")

    def __getitem__(self, item: typing.Union[int, str, typing.Tuple[str, str]]) -> WrappedDatabase:
        if isinstance(item, int):
            if item in self._db_number_lookup:
                return self._db_number_lookup[item]
            else:
                raise KeyError(item)
        elif isinstance(item, str):
            if self.has_multiple_origins:
                raise ValueError(
                    "Database contains multiple origins, indexes must be provided as a tuple of (name, origin)")
            if item in self:
                return self._db_name_lookup[item, 0]
            else:
                raise KeyError(item)
        elif isinstance(item, tuple) and len(item) == 2:
            name, origin = item
            if not self.has_multiple_origins:
                origin = 0  # origin ignored if not needed
            if (name, origin) in self:
                return self._db_name_lookup[name, origin]
            else:
                raise KeyError(item)

        raise TypeError("Lookups must be one of int, str or tuple of name and origin")

    def __repr__(self):
        return f"<WrappedIndexDB: {self._raw_db.database_path}>"
