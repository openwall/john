# ccl_chrome_indexeddb
This repository contains (sometimes partial) re-implementations of the technologies involved in reading IndexedDB data
in Chrome-esque applications.
This includes:
* Snappy decompression
* LevelDB
* V8 object deserialization
* Blink object deserialization
* IndexedDB wrapper

### Blog
Read a blog on the subject here: https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium

### Caveats
There is a fair amount of work yet to be done in terms of documentation, but
the modules should be fine for pulling data out of IndexedDB, with the following
caveats:

#### LevelDB deleted data
The LevelDB module will spit out live and deleted/old versions of records
indiscriminately; it's possible to differentiate between them with some
work, but that hasn't really been baked into the modules as they currently
stand. So you are getting deleted data "for free" currently...whether you
want it or not.

#### Blink data types
I am fairly satisfied that all the possible V8 object types are accounted for
(but I'm happy to be shown otherwise and get that fixed of course!), but it
is likely that the hosted Blink objects aren't all there yet; so if you hit
upon an error coming from inside ccl_blink_value_deserializer and can point
me towards test data, I'd be very thankful!

#### Cyclic references
It is noted in the V8 source that recursive referencing is possible in the
serialization, we're not yet accounting for that so if Python throws a
`RecursionError` that's likely what you're seeing. The plan is to use a
similar approach to ccl_bplist where the collection types are subclassed and
do Just In Time resolution of the items, but that isn't done yet.

## Using the modules
There are two methods for accessing records - a more pythonic API using a set of
wrapper objects and a raw API which doesn't mask the underlying workings. There is
unlikely to be much benefit to using the raw API in most cases, so the wrapper objects
are recommended in most cases.

### Wrapper API
```python
import sys
import ccl_chromium_indexeddb

# assuming command line arguments are paths to the .leveldb and .blob folders
leveldb_folder_path = sys.argv[1]
blob_folder_path = sys.argv[2]

# open the indexedDB:
wrapper = ccl_chromium_indexeddb.WrappedIndexDB(leveldb_folder_path, blob_folder_path)

# You can check the databases present using `wrapper.database_ids`

# Databases can be accessed from the wrapper in a number of ways:
db = wrapper[2]  # accessing database using id number
db = wrapper["MyTestDatabase"]  # accessing database using name (only valid for single origin indexedDB instances)
db = wrapper["MyTestDatabase", "file__0@1"]  # accessing the database using name and origin
# NB using name and origin is likely the preferred option in most cases

# The wrapper object also supports checking for databases using `in`

# You can check for object store names using `db.object_store_names`

# Object stores can be accessed from the database in a number of ways:
obj_store = db[1]  # accessing object store using id number
obj_store = db["store"]  # accessing object store using name

# Records can then be accessed by iterating the object store in a for-loop
for record in obj_store.iterate_records():
    print(record.user_key)
    print(record.value)

    # if this record contained a FileInfo object somewhere linking
    # to data stored in the blob dir, we could access that data like
    # so (assume the "file" key in the record value is our FileInfo):
    with record.get_blob_stream(record.value["file"]) as f:
        file_data = f.read()

# By default, any errors in decoding records will bubble an exception
# which might be painful when iterating records in a for-loop, so either
# passing True into the errors_to_stdout argument and/or by passing in an
# error handler function to bad_deserialization_data_handler, you can
# perform logging rather than crashing:

for record in obj_store.iterate_records(
        errors_to_stdout=True,
        bad_deserializer_data_handler= lambda k,v: print(f"error: {k}, {v}")):
    print(record.user_key)
    print(record.value)
```

### Raw access API
```python
import sys
import ccl_chromium_indexeddb

# assuming command line arguments are paths to the .leveldb and .blob folders
leveldb_folder_path = sys.argv[1]
blob_folder_path = sys.argv[2]

# open the database:
db = ccl_chromium_indexeddb.IndexedDb(leveldb_folder_path, blob_folder_path)

# there can be multiple databases, so we need to iterate through them (NB
# DatabaseID objects contain additional metadata, they aren't just ints):
for db_id_meta in db.global_metadata.db_ids:
    # and within each database, there will be multiple object stores so we
    # will need to know the maximum object store number (this process will be
    # cleaned up in future releases):
    max_objstore_id = db.get_database_metadata(
            db_id_meta.dbid_no,
            ccl_chromium_indexeddb.DatabaseMetadataType.MaximumObjectStoreId)

    # if the above returns None, then there are no stores in this db
    if max_objstore_id is None:
        continue

    # there may be multiple object stores, so again, we iterate through them
    # this time based on the id number. Object stores start at id 1 and the
    # max_objstore_id is inclusive:
    for obj_store_id in range(1, max_objstore_id + 1):
        # now we can ask the indexeddb wrapper for all records for this db
        # and object store:
        for record in db.iterate_records(db_id_meta.dbid_no, obj_store_id):
            print(f"key: {record.user_key}")
            print(f"key: {record.value}")

            # if this record contained a FileInfo object somewhere linking
            # to data stored in the blob dir, we could access that data like
            # so (assume the "file" key in the record value is our FileInfo):
            with record.get_blob_stream(record.value["file"]) as f:
                file_data = f.read()
```
