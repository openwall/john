import sys
import pathlib
import ccl_chromium_indexeddb


def main(args):
    ldb_path = pathlib.Path(args[0])
    wrapper = ccl_chromium_indexeddb.WrappedIndexDB(ldb_path)

    for db_info in wrapper.database_ids:
        db = wrapper[db_info.dbid_no]
        print("------Database------")
        print(f"db_number={db.db_number}; name={db.name}; origin={db.origin}")
        print()
        print("\t---Object Stores---")
        for obj_store_name in db.object_store_names:
            obj_store = db[obj_store_name]
            print(f"\tobject_store_id={obj_store.object_store_id}; name={obj_store.name}")
            try:
                one_record = next(obj_store.iterate_records())
            except StopIteration:
                one_record = None
            if one_record is not None:
                print("\tExample record:")
                print(f"\tkey: {one_record.key}")
                print(f"\tvalue: {one_record.value}")
            else:
                print("\tNo records")
            print()
        print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <ldb dir path>")
        exit(1)
    main(sys.argv[1:])
