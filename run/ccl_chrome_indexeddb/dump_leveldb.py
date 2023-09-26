import sys
import csv
import ccl_leveldb
import pathlib

ENCODING = "iso-8859-1"


def main(args):
    input_path = args[0]
    output_path = "leveldb_dump.csv"
    if len(args) > 1:
        output_path = args[1]

    leveldb_records = ccl_leveldb.RawLevelDb(input_path)

    with open(output_path, "w", encoding="utf-8", newline="") as file1:
        writes = csv.writer(file1, quoting=csv.QUOTE_ALL)
        writes.writerow(
            [
                "key-hex", "key-text", "value-hex", "value-text", "origin_file",
                "file_type", "offset", "seq", "state", "was_compressed"
            ])

        for record in leveldb_records.iterate_records_raw():
            writes.writerow([
                record.user_key.hex(" ", 1),
                record.user_key.decode(ENCODING, "replace"),
                record.value.hex(" ", 1),
                record.value.decode(ENCODING, "replace"),
                str(record.origin_file),
                record.file_type.name,
                record.offset,
                record.seq,
                record.state.name,
                record.was_compressed
            ])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {pathlib.Path(sys.argv[0]).name} <indir path> [outpath.csv]")
        exit(1)
    print()
    print("+--------------------------------------------------------+")
    print("|Please note: keys and values in leveldb are binary blobs|")
    print("|so any text seen in the output of this script might not |")
    print("|represent the entire meaning of the data. The output of |")
    print("|this script should be considered as a preview of the    |")
    print("|data only.                                              |")
    print("+--------------------------------------------------------+")
    print()
    main(sys.argv[1:])
