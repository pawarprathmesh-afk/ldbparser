# leveldb_parser.py

A Windows/macOS-native, read-only forensic parser for Chromium/Comet LevelDB
data:

- Raw LevelDB tables (`.ldb`/`.sst`) and write-ahead logs (`.log`)
- **Local Storage** LevelDB (`.../Local Storage/leveldb`)
- **IndexedDB** LevelDB (`.../IndexedDB/....indexeddb.leveldb`) -- these use
  a custom `idb_cmp1` comparator that plyvel/leveldb C++ bindings can't
  open, so this tool parses the on-disk table/log format directly instead
  of going through any LevelDB library
- Comet Browser / Perplexity AI conversation, prompt/response, and
  web-citation artifacts embedded in LevelDB values

The parsing engine is pure standard-library Python -- **no plyvel, no
python-leveldb, no leveldb-tools, no python-snappy, no WSL required.**
Snappy decompression is implemented in pure Python.

## Usage

Run with no arguments to launch the PyQt5 GUI (`pip install PyQt5` if you
want it -- the engine itself has no dependency on it):

```
python leveldb_parser.py
```

Or run a headless scan and write a CSV report:

```
python leveldb_parser.py --cli "path/to/Local Storage/leveldb" "path/to/IndexedDB/leveldb" -o report.csv --hashes
```

Local Storage and IndexedDB directories can be freely mixed in one
invocation; pass a parent folder and it's searched recursively for every
LevelDB/IndexedDB database underneath it.

`--hashes` additionally writes a SHA-256 evidence manifest (chain of
custody) for every `.ldb`/`.sst`/`.log`/`CURRENT`/`MANIFEST*` file found.

Run `python leveldb_parser.py --help` for the full option list.
