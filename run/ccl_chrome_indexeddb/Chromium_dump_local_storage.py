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

import sys
import pathlib
import datetime
import sqlite3
import ccl_chromium_localstorage

__version__ = "0.1"
__description__ = "Dumps a Chromium localstorage leveldb to sqlite for review"
__contact__ = "Alex Caithness"

DB_SCHEMA = """
CREATE TABLE storage_keys ("_id" INTEGER PRIMARY KEY AUTOINCREMENT, "storage_key" TEXT);
CREATE TABLE batches ("start_ldbseq" INTEGER PRIMARY KEY,
                      "end_ldbseq" INTEGER,
                      "storage_key" INTEGER,
                      "timestamp" INTEGER);
CREATE TABLE records ("_id" INTEGER PRIMARY KEY AUTOINCREMENT,
                      "storage_key" INTEGER,
                      "key" TEXT,
                      "value" TEXT,
                      "batch" INTEGER,
                      "ldbseq" INTEGER);
CREATE INDEX "storage_keys_storage_key" ON "storage_keys" ("storage_key");

CREATE VIEW "records_view" AS
    SELECT
      storage_keys.storage_key AS "storage_key",
      records."key"  AS "key",
      records.value AS "value",
      datetime(batches."timestamp", 'unixepoch') AS "batch_timestamp",
      records.ldbseq AS "ldbseq"
    FROM records
      INNER JOIN storage_keys ON records.storage_key = storage_keys._id
      INNER JOIN batches ON records.batch = batches.start_ldbseq
    ORDER BY records.ldbseq;
"""

INSERT_STORAGE_KEY_SQL = """INSERT INTO "storage_keys" ("storage_key") VALUES (?);"""
INSERT_BATCH_SQL = """INSERT INTO "batches" ("start_ldbseq", "end_ldbseq", "storage_key", "timestamp")
                      VALUES (?, ?, ?, ?);"""
INSERT_RECORD_SQL = """INSERT INTO "records" ("storage_key", "key", "value", "batch", "ldbseq")
                       VALUES (?, ?, ?, ?, ?);"""


def main(args):
    level_db_in_dir = pathlib.Path(args[0])
    db_out_path = pathlib.Path(args[1])

    if db_out_path.exists():
        raise ValueError("output database already exists")

    local_storage = ccl_chromium_localstorage.LocalStoreDb(level_db_in_dir)
    out_db = sqlite3.connect(db_out_path)
    out_db.executescript(DB_SCHEMA)
    cur = out_db.cursor()

    storage_keys_lookup = {}
    for storage_key in local_storage.iter_storage_keys():
        cur.execute(INSERT_STORAGE_KEY_SQL, (storage_key,))
        cur.execute("SELECT last_insert_rowid();")
        storage_key_id = cur.fetchone()[0]
        storage_keys_lookup[storage_key] = storage_key_id

    for batch in local_storage.iter_batches():
        cur.execute(
            INSERT_BATCH_SQL,
            (batch.start, batch.end, storage_keys_lookup[batch.storage_key],
             batch.timestamp.replace(tzinfo=datetime.timezone.utc).timestamp()))

    for record in local_storage.iter_all_records():
        batch = local_storage.find_batch(record.leveldb_seq_number)
        batch_id = batch.start if batch is not None else None
        cur.execute(
            INSERT_RECORD_SQL,
            (
                storage_keys_lookup[record.storage_key], record.script_key, record.value,
                batch_id, record.leveldb_seq_number
            )
        )

    cur.close()
    out_db.commit()
    out_db.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"{pathlib.Path(sys.argv[0]).name} <leveldb dir> <out.db>")
        exit(1)
    main(sys.argv[1:])
