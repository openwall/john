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
import sqlite3
import ccl_chromium_sessionstorage

__version__ = "0.1"
__description__ = "Dumps a Chromium sessionstorage leveldb to sqlite for review"
__contact__ = "Alex Caithness"

DB_SCHEMA = """
CREATE TABLE "hosts" ("_id" INTEGER PRIMARY KEY AUTOINCREMENT, "host" TEXT);
CREATE TABLE "guids" ("_id" INTEGER PRIMARY KEY AUTOINCREMENT, "guid" TEXT);
CREATE TABLE "items" ("_id" INTEGER PRIMARY KEY AUTOINCREMENT,
                      "host" INTEGER,
                      "guid" INTEGER,
                      "ldbseq" INTEGER,
                      "key" TEXT,
                      "value" TEXT);
CREATE INDEX "item_host" ON "items" ("host");
CREATE INDEX "item_ldbseq" ON "items" ("ldbseq");

CREATE VIEW items_view AS
    SELECT "items"."ldbseq",
      "hosts"."host",
      "items"."key",
      "items"."value",
      "guids"."guid"
    FROM "items"
      LEFT JOIN "hosts" ON "items"."host" = "hosts"."_id"
      LEFT JOIN "guids" ON "items"."guid" = "guids"."_id"
    ORDER BY "items"."ldbseq";
"""

INSERT_HOST_SQL = """INSERT INTO "hosts" ("host") VALUES (?);"""
INSERT_ITEM_SQL = """INSERT INTO "items" (host, guid, ldbseq, key, value) VALUES (?, ?, ?, ?, ?);"""


def main(args):
    level_db_in_dir = pathlib.Path(args[0])
    db_out_path = pathlib.Path(args[1])

    if db_out_path.exists():
        raise ValueError("output database already exists")

    session_storage = ccl_chromium_sessionstorage.SessionStoreDb(level_db_in_dir)
    out_db = sqlite3.connect(db_out_path)
    out_db.executescript(DB_SCHEMA)
    cur = out_db.cursor()
    for host in session_storage.iter_hosts():
        cur.execute(INSERT_HOST_SQL, (host,))
        cur.execute("SELECT last_insert_rowid();")
        host_id = cur.fetchone()[0]
        host_kvs = session_storage.get_all_for_host(host)

        for key, values in host_kvs.items():
            for value in values:
                cur.execute(INSERT_ITEM_SQL, (host_id, None, value.leveldb_sequence_number, key, value.value))

    for key, value in session_storage.iter_orphans():
        cur.execute(INSERT_ITEM_SQL, (None, None, value.leveldb_sequence_number, key, value.value))

    cur.close()
    out_db.commit()
    out_db.close()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"{pathlib.Path(sys.argv[0]).name} <leveldb dir> <out.db>")
        exit(1)
    main(sys.argv[1:])
