"""
Copyright 2021, CCL Forensics
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

import io
import bisect
import sys
import pathlib
import types
import typing
import dataclasses
import datetime

import ccl_leveldb

__version__ = "0.1"
__description__ = "Module for reading the Chromium leveldb localstorage format"
__contact__ = "Alex Caithness"

"""
See: https://source.chromium.org/chromium/chromium/src/+/main:components/services/storage/dom_storage/local_storage_impl.cc
Meta keys:
    Key = "META:" + storage_key (the host)
    Value = protobuff: 1=timestamp (varint); 2=size in bytes (varint)

Record keys:
    Key = "_" + storage_key + "\\x0" + script_key
    Value = record_value

"""

_META_PREFIX = b"META:"
_RECORD_KEY_PREFIX = b"_"
_CHROME_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0)

EIGHT_BIT_ENCODING = "iso-8859-1"

def from_chrome_timestamp(microseconds: int) -> datetime.datetime:
    return _CHROME_EPOCH + datetime.timedelta(microseconds=microseconds)


def decode_string(raw: bytes) -> str:
    """
    decodes a type-prefixed string - prefix of: 0=utf-16-le; 1=an extended ascii codepage (likely dependant on locale)
    :param raw: raw prefixed-string data
    :return: decoded string
    """
    prefix = raw[0]
    if prefix == 0:
        return raw[1:].decode("utf-16-le")
    elif prefix == 1:
        return raw[1:].decode(EIGHT_BIT_ENCODING)
    else:
        raise ValueError("Unexpected prefix, please contact developer")


@dataclasses.dataclass(frozen=True)
class StorageMetadata:
    storage_key: str
    timestamp: datetime.datetime
    size_in_bytes: int
    leveldb_seq_number: int

    @classmethod
    def from_protobuff(cls, storage_key: str, data: bytes, seq: int):
        with io.BytesIO(data) as stream:
            # This is a simple protobuff, so we'll read it directly, but with checks, rather than add a dependency
            ts_tag = ccl_leveldb.read_le_varint(stream)
            if (ts_tag & 0x07) != 0 or (ts_tag >> 3) != 1:
                raise ValueError("Unexpected tag when reading StorageMetadata from protobuff")
            timestamp = from_chrome_timestamp(ccl_leveldb.read_le_varint(stream))

            size_tag = ccl_leveldb.read_le_varint(stream)
            if (size_tag & 0x07) != 0 or (size_tag >> 3) != 2:
                raise ValueError("Unexpected tag when reading StorageMetadata from protobuff")
            size = ccl_leveldb.read_le_varint(stream)

            return cls(storage_key, timestamp, size, seq)


@dataclasses.dataclass(frozen=True)
class LocalStorageRecord:
    storage_key: str
    script_key: str
    value: str
    leveldb_seq_number: int
    is_live: bool


class LocalStorageBatch:
    def __init__(self, meta: StorageMetadata, end_seq: int):
        self._meta = meta
        self._end = end_seq

    @property
    def storage_key(self) -> str:
        return self._meta.storage_key

    @property
    def timestamp(self) -> datetime.datetime:
        return self._meta.timestamp

    @property
    def start(self):
        return self._meta.leveldb_seq_number

    @property
    def end(self):
        return self._end

    def __repr__(self):
        return f"(storage_key={self.storage_key}, timestamp={self.timestamp}, start={self.start}, end={self.end})"


class LocalStoreDb:
    def __init__(self, in_dir: pathlib.Path):
        if not in_dir.is_dir():
            raise IOError("Input directory is not a directory")

        self._ldb = ccl_leveldb.RawLevelDb(in_dir)

        self._storage_details = {}  # storage_key: {seq_number: StorageMetadata}
        self._flat_items = []       # [StorageMetadata|LocalStorageRecord]   - used to batch items up
        self._records = {}          # storage_key: {script_key: {seq_number: LocalStorageRecord}}

        for record in self._ldb.iterate_records_raw():
            if record.user_key.startswith(_META_PREFIX) and record.state == ccl_leveldb.KeyState.Live:
                # Only live records for metadata - not sure what we can reliably infer from deleted keys
                storage_key = record.user_key.removeprefix(_META_PREFIX).decode(EIGHT_BIT_ENCODING)
                self._storage_details.setdefault(storage_key, {})
                metadata = StorageMetadata.from_protobuff(storage_key, record.value, record.seq)
                self._storage_details[storage_key][record.seq] = metadata
                self._flat_items.append(metadata)
            elif record.user_key.startswith(_RECORD_KEY_PREFIX):
                # We include deleted records here because we need them to build batches
                storage_key_raw, script_key_raw = record.user_key.removeprefix(_RECORD_KEY_PREFIX).split(b"\x00", 1)
                storage_key = storage_key_raw.decode(EIGHT_BIT_ENCODING)
                script_key = decode_string(script_key_raw)

                try:
                    value = decode_string(record.value) if record.state == ccl_leveldb.KeyState.Live else None
                except UnicodeDecodeError as e:
                    # Some sites play games to test the browser's capabilities like encoding half of a surrogate pair
                    print(f"Error decoding record value at seq no {record.seq}; "
                          f"{storage_key} {script_key}:  {record.value}")
                    continue

                self._records.setdefault(storage_key, {})
                self._records[storage_key].setdefault(script_key, {})

                ls_record = LocalStorageRecord(
                    storage_key, script_key, value, record.seq, record.state == ccl_leveldb.KeyState.Live)
                self._records[storage_key][script_key][record.seq] = ls_record
                self._flat_items.append(ls_record)

        self._storage_details = types.MappingProxyType(self._storage_details)
        self._records = types.MappingProxyType(self._records)

        self._all_storage_keys = frozenset(self._storage_details.keys() | self._records.keys())  # because deleted data.
        self._flat_items.sort(key=lambda x: x.leveldb_seq_number)

        # organise batches - this is made complex and slow by having to account for missing/deleted data
        # we're looking for a StorageMetadata followed by sequential (in terms of seq number) LocalStorageRecords
        # with the same storage key. Everything that falls within that chain can safely be considered a batch.
        # Any break in sequence numbers or storage key is a fail and can't be considered part of a batch.
        self._batches = {}
        current_meta: typing.Optional[StorageMetadata] = None
        current_end = 0
        for item in self._flat_items:  # pre-sorted
            if isinstance(item, LocalStorageRecord):
                if current_meta is None:
                    # no currently valid metadata so we can't attribute this record to anything
                    continue
                elif item.leveldb_seq_number - current_end != 1 or item.storage_key != current_meta.storage_key:
                    # this record breaks a chain, so bundle up what we have and clear everything out
                    self._batches[current_meta.leveldb_seq_number] = LocalStorageBatch(current_meta, current_end)
                    current_meta = None
                    current_end = 0
                else:
                    # contiguous and right storage key, include in the current chain
                    current_end = item.leveldb_seq_number
            elif isinstance(item, StorageMetadata):
                if current_meta is not None:
                    # this record breaks a chain, so bundle up what we have, set new start
                    self._batches[current_meta.leveldb_seq_number] = LocalStorageBatch(current_meta, current_end)
                current_meta = item
                current_end = item.leveldb_seq_number
            else:
                raise ValueError

        if current_meta is not None:
            self._batches[current_meta.leveldb_seq_number] = LocalStorageBatch(current_meta, current_end)

        self._batch_starts = tuple(sorted(self._batches.keys()))

    def iter_storage_keys(self) -> typing.Iterable[str]:
        yield from self._storage_details.keys()

    def contains_storage_key(self, storage_key: str) -> bool:
        return storage_key in self._all_storage_keys

    def iter_script_keys(self, storage_key: str) -> typing.Iterable[str]:
        if storage_key not in self._all_storage_keys:
            raise KeyError(storage_key)
        if storage_key not in self._records:
            raise StopIteration
        yield from self._records[storage_key].keys()

    def contains_script_key(self, storage_key: str, script_key: str) -> bool:
        return script_key in self._records.get(storage_key, {})

    def find_batch(self, seq: int):
        """
        Finds the batch that a record with the given sequence number belongs to
        :param seq: leveldb sequence id
        :return: the batch containing the given sequence number or None if no batch contains it
        """

        i = bisect.bisect_left(self._batch_starts, seq) - 1
        if i < 0:
            return None
        start = self._batch_starts[i]
        batch = self._batches[start]
        if batch.start <= seq <= batch.end:
            return batch
        else:
            return None

    def iter_all_records(self) -> typing.Iterable[LocalStorageRecord]:
        """
        :return: iterable of LocalStorageRecords
        """
        for storage_key, script_dict in self._records.items():
            for script_key, values in script_dict.items():
                for seq, value in values.items():
                    if value.is_live:
                        yield value

    def iter_records_for_storage_key(self, storage_key) -> typing.Iterable[LocalStorageRecord]:
        """
        :param storage_key: storage key (host) for the records
        :return: iterable of LocalStorageRecords
        """
        if not self.contains_storage_key(storage_key):
            raise KeyError(storage_key)
        for script_key, values in self._records[storage_key].items():
            for seq, value in values.items():
                if value.is_live:
                    yield value

    def iter_records_for_script_key(self, storage_key, script_key) -> typing.Iterable[LocalStorageRecord]:
        """
        :param storage_key: storage key (host) for the records
        :param script_key: script defined key for the records
        :return: iterable of LocalStorageRecords
        """
        if not self.contains_script_key(storage_key, script_key):
            raise KeyError((storage_key, script_key))
        for seq, value in self._records[storage_key][script_key].items():
            if value.is_live:
                yield value

    def iter_metadata(self) -> typing.Iterable[StorageMetadata]:
        """
        :return: iterable of StorageMetaData
        """
        for meta in self._flat_items:
            if isinstance(meta, StorageMetadata):
                yield meta

    def iter_metadata_for_storage_key(self, storage_key: str) -> typing.Iterable[StorageMetadata]:
        """
        :param storage_key: storage key (host) for the metadata
        :return: iterable of StorageMetadata
        """
        if storage_key not in self._all_storage_keys:
            raise KeyError(storage_key)
        if storage_key not in self._storage_details:
            return None
        for seq, meta in self._storage_details[storage_key].items():
            yield meta

    def iter_batches(self) -> typing.Iterable[LocalStorageBatch]:
        yield from self._batches.values()

    def close(self):
        self._ldb.close()


def main(args):
    in_ldb_path = pathlib.Path(args[0])
    local_store = LocalStoreDb(in_ldb_path)

    for rec in local_store.iter_all_records():
        batch = local_store.find_batch(rec.leveldb_seq_number)
        print(rec, batch)


if __name__ == '__main__':
    main(sys.argv[1:])
