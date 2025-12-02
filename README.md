# ldbparser
This script parses a single LevelDB .ldb file and extracts key-value records without requiring the full database. It manually decodes LevelDB structures like varints, index/data blocks, restart points, and prefix-compressed keys, and supports Snappy decompression for readable forensic data recovery.
to run this you have to install some libraries.
1. plyvel
2. python-snappy.
