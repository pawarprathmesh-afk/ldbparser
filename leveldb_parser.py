#!/usr/bin/env python3
"""
Comet / Chromium LevelDB + IndexedDB Forensic Analyzer
========================================================

A Windows-native, read-only forensic viewer for:
    - Raw LevelDB databases (.ldb / .sst tables, .log write-ahead logs)
    - Chromium IndexedDB LevelDB databases (custom idb_cmp1 comparator --
      these cannot be opened by plyvel/leveldb C++ bindings, so this tool
      parses the on-disk table/log format directly instead of going
      through any LevelDB library)
    - Comet Browser / Perplexity AI conversation artifacts embedded in
      LevelDB values

Architecture (see README for the full pipeline diagram):

    Evidence Discovery -> SHA-256 Hashing -> SSTable/LOG Parser ->
    Internal Key Decoder -> Sequence/State Analysis -> IndexedDB Key &
    Metadata Decoder -> V8/Blink Value Decoder -> Generic Decoder ->
    Comet/AI Extraction -> Timeline / IOC Reconstruction -> PyQt5 GUI ->
    Export / Report

No third-party LevelDB bindings are used anywhere in this file:
    - No plyvel
    - No python-leveldb
    - No leveldb-tools / ldb / leveldb_dump subprocess calls
    - No WSL / Linux LevelDB libraries
    - No python-snappy (Snappy is decompressed in pure Python)

This is a READ-ONLY tool. Evidence files are only ever opened with
open(path, "rb") -- nothing is written back into an evidence directory.

GUI note: the visible interface is intentionally kept minimal (Open
Folder / Open Zip / Stop Scan / Export CSV, a simple filter row, a
3-column results table, and a Selected Key / Selected Value pane) even
though the backend behind it performs the full forensic pipeline above.
Advanced fields (state, sequence number, source file/offset, IndexedDB
metadata, Comet records, IOCs, recovery method, confidence) are computed
for every record and included in the CSV export; they are simply not
surfaced as extra GUI panels.

Run:
    python -m pip install PyQt5
    python leveldb_parser.py
"""

import os
import re
import sys
import glob
import json
import csv
import base64
import zipfile
import tempfile
import shutil
import struct
import hashlib
import traceback
import unicodedata
import uuid as uuid_module
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

try:
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QAbstractTableModel, QModelIndex
    from PyQt5.QtGui import QFont, QColor, QPalette
    from PyQt5.QtWidgets import (
        QApplication, QWidget, QFileDialog, QMessageBox,
        QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox, QPushButton,
        QComboBox, QToolBar, QSplitter, QTableView, QPlainTextEdit,
        QHeaderView, QAbstractItemView, QProgressBar, QAction,
    )
    HAVE_QT = True
except Exception:
    HAVE_QT = False

# ============================================================================
# Timezone definitions -- stdlib only.
# India has no DST so a fixed +05:30 offset is always correct and needs no
# tzdata package (avoids both the old pytz dependency and zoneinfo's need
# for the optional "tzdata" package on Windows).
# ============================================================================
UTC = timezone.utc
IST = timezone(timedelta(hours=5, minutes=30), name="IST")
MIN_UTC = datetime.min.replace(tzinfo=UTC)  # tz-aware fallback for sort keys

TABLE_MAGIC = 0xdb4775248b80fb57

# ============================================================================
# Forensic safety limits -- corrupted or hostile evidence must never cause
# unbounded memory growth, infinite loops, or a crash that aborts the scan.
# ============================================================================
MAX_BLOCK_SIZE = 4 * 1024 * 1024           # single LevelDB table block
MAX_DECOMPRESSED_SIZE = 64 * 1024 * 1024   # single Snappy-decompressed block
MAX_RECORD_SIZE = 32 * 1024 * 1024         # single key/value pair
MAX_STRING_LENGTH = 200_000                # decoded text kept per value
MAX_PREVIEW_LENGTH = 4000                  # GUI preview cap
MAX_VARINT32_BYTES = 5
MAX_VARINT64_BYTES = 10
LOG_BLOCK_SIZE = 32768

# Artifact classification -- multi-word / specific tokens only (never a bare
# "id", "url", "user", "auth" etc.): those are substrings of huge amounts of
# ordinary camelCase/JSON text and would tag nearly every record, defeating
# the point of a category label. Checked in order, first match wins, so more
# specific categories are listed before more general ones. Informational
# only (the "artifact_category" CSV column) -- never used to decide which
# records are surfaced; see is_low_value_record() for that.
ARTIFACT_CATEGORIES = {
    "Authentication": ["pplx-next-auth-session", "auth-session", "credential", "password", "login"],
    "Session Tokens": ["access_token", "refresh_token", "session_token", "sessionid", "bearer", "jwt"],
    "Geolocation": ["devicelocation", "geolocation", "latitude", "longitude"],
    "Communication Platform": ["whatsapp", "telegram"],
    "Search History": ["last_results", "search_history", "query_history", "query_str", "search_focus"],
    "AI Conversations": ["conversation", "thread_title", "assistant_message", "pplx-query-cache", "backend_uuid"],
    "Browser History": ["navigation_history", "visited_url", "referrer"],
    "User Profile": ["subscription", "account_email", "user_profile", "username"],
    "Settings": ["user_setting", "config_option", "preference"],
    "Downloads": ["download_", "attachment_saved"],
}

# Activity classification (timeline)
ACTIVITY_TYPES = {
    "AI Search": ["query", "prompt", "question", "search", "pplx", "perplexity"],
    "User Prompt": ["prompt", "question", "userMessage", "user_message", "input"],
    "Follow-up Question": ["follow", "next", "continuation", "another", "additionally"],
    "Summarize Current Webpage": ["sidecar", "summary", "summarize", "tldr", "abstract"],
    "Conversation Created": ["conversation_created", "chat_created", "new_conversation"],
    "Conversation Updated": ["conversation_updated", "message_added", "new_message"],
    "Browser Search": ["search", "google", "bing", "duckduckgo"],
    "Navigation": ["url", "visited", "navigation", "page", "website"],
    "File Upload": ["upload", "attach", "file", "attachment"],
    "File Download": ["download", "save", "saved", "downloaded"],
    "Permission Prompt": ["permission", "geolocation", "camera", "microphone"],
    "Geolocation Access": ["geolocation", "location", "latitude", "longitude"],
    "Login": ["login", "sign in", "authenticate", "auth", "password"],
    "Logout": ["logout", "sign out", "disconnect", "session ended"],
    "Tab Opened": ["tab_created", "tab opened", "new tab"],
    "Tab Closed": ["tab_closed", "tab closed", "close tab"],
    "Search Thread Created": ["thread_created", "new_thread", "thread created"],
    "AI Response Generated": ["answer_preview", "response", "assistant_message", "ai response"],
    "Webpage Summarized": ["summarized", "summary_complete", "tldr_complete"],
    "Website Visited": ["visited", "browsed", "opened url"],
    "Permission Granted": ["permission granted", "grant", "allowed"],
    "Permission Denied": ["permission denied", "denied", "blocked"],
    "Settings Changed": ["setting", "preference", "config_changed", "option_changed"],
    "Agent Task Started": ["agent_start", "task_started", "agent task"],
    "Agent Task Completed": ["agent_complete", "task_completed", "agent done"],
    "Cached Search": ["query-cache", "query_cache", "cached"],
    "Bookmark/Pin Created": ["pin", "bookmark", "pinned", "saved item"],
    "Notification": ["notification", "unread", "alert"],
    "Session Created": ["session_created", "new_session"],
    "Session Updated": ["session_updated", "session_refreshed"],
}

# IOC patterns
IOC_PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "url": re.compile(r"https?://[^\s\"'<>\\\x00-\x1f]{4,}"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "aws_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-\._=]+", re.I),
    "api_key": re.compile(r'(?:api[_\-]?key|apikey)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', re.I),
}

# Timestamp patterns
TIMESTAMP_PATTERNS = {
    "unix": re.compile(r"\b\d{10}\b"),
    "unix_ms": re.compile(r"\b\d{13}\b"),
    "iso8601": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
}


# ============================================================================
# VARINT DECODING (bounded -- corrupt evidence must not hang or over-read)
# ============================================================================

class VarintError(ValueError):
    pass


def read_varint32(data, pos):
    """LevelDB Varint32: 7 bits/byte, MSB = continuation. Bounded to 5
    bytes (ceil(32/7)) and to the buffer length. Returns (value, new_pos)."""
    result = shift = 0
    start = pos
    n = len(data)
    while True:
        if pos >= n:
            raise VarintError("varint32 read past end of buffer")
        if pos - start >= MAX_VARINT32_BYTES:
            raise VarintError("varint32 exceeds maximum encoded length")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result & 0xFFFFFFFF, pos
        shift += 7


def read_varint64(data, pos):
    """LevelDB Varint64. Bounded to 10 bytes (ceil(64/7))."""
    result = shift = 0
    start = pos
    n = len(data)
    while True:
        if pos >= n:
            raise VarintError("varint64 read past end of buffer")
        if pos - start >= MAX_VARINT64_BYTES:
            raise VarintError("varint64 exceeds maximum encoded length")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _varint(data, pos):
    """Backward-compatible alias used by block-handle / footer parsing."""
    return read_varint64(data, pos)


# ============================================================================
# PURE-PYTHON SNAPPY DECOMPRESSION
# ============================================================================

def snappy_decompress(data):
    """Decode a Snappy block (literal / copy-1 / copy-2 / copy-4 tags).
    Bounded by MAX_DECOMPRESSED_SIZE and validates every offset/length
    against the buffers involved so malformed input raises instead of
    over-reading or allocating unbounded memory."""
    if not data:
        return b""
    declared_len, pos = read_varint64(data, 0)
    if declared_len > MAX_DECOMPRESSED_SIZE:
        raise ValueError("declared snappy length %d exceeds safety limit" % declared_len)
    out = bytearray()
    n = len(data)
    while pos < n:
        if len(out) > MAX_DECOMPRESSED_SIZE:
            raise ValueError("snappy output exceeded safety limit")
        tag = data[pos]
        pos += 1
        kind = tag & 0x03
        if kind == 0:
            n_tag = tag >> 2
            if n_tag < 60:
                ln = n_tag + 1
            else:
                k = n_tag - 59
                if pos + k > n:
                    raise ValueError("truncated snappy literal length")
                ln = int.from_bytes(data[pos:pos + k], "little") + 1
                pos += k
            if pos + ln > n:
                raise ValueError("truncated snappy literal")
            out += data[pos:pos + ln]
            pos += ln
        else:
            if kind == 1:
                ln = 4 + ((tag >> 2) & 0x07)
                if pos >= n:
                    raise ValueError("truncated snappy copy-1 tag")
                off = ((tag >> 5) << 8) | data[pos]
                pos += 1
            elif kind == 2:
                ln = (tag >> 2) + 1
                if pos + 2 > n:
                    raise ValueError("truncated snappy copy-2 tag")
                off = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2
            else:
                ln = (tag >> 2) + 1
                if pos + 4 > n:
                    raise ValueError("truncated snappy copy-4 tag")
                off = int.from_bytes(data[pos:pos + 4], "little")
                pos += 4
            start = len(out) - off
            if off == 0 or start < 0:
                raise ValueError("invalid snappy back-reference offset")
            for i in range(ln):
                out.append(out[start + i])
    return bytes(out)


# ============================================================================
# NATIVE LEVELDB SSTABLE / LOG PARSING
# ============================================================================

def _read_block(data, offset, size):
    if size > MAX_BLOCK_SIZE:
        raise ValueError("block size %d exceeds safety limit" % size)
    if offset < 0 or offset + size + 1 > len(data):
        raise ValueError("block handle out of file bounds")
    raw = data[offset:offset + size]
    compression = data[offset + size]
    if compression == 0:
        return raw
    if compression == 1:
        return snappy_decompress(raw)
    raise ValueError("unsupported block compression type %d" % compression)


def _parse_block(block):
    """Parse a LevelDB data/index block: prefix-compressed key/value pairs
    followed by a restart-point array. Validates the restart count and
    every entry's bounds before trusting them."""
    if len(block) < 4:
        return
    n_restart = int.from_bytes(block[-4:], "little")
    if n_restart < 0 or 4 * (n_restart + 1) > len(block):
        raise ValueError("implausible restart count %d" % n_restart)
    end = len(block) - 4 * (n_restart + 1)
    pos, key = 0, b""
    while pos < end:
        shared, pos = read_varint32(block, pos)
        non_shared, pos = read_varint32(block, pos)
        value_len, pos = read_varint32(block, pos)
        if shared > len(key) or pos + non_shared + value_len > end:
            raise ValueError("corrupt block entry (out of bounds)")
        key = key[:shared] + block[pos:pos + non_shared]
        pos += non_shared
        value = block[pos:pos + value_len]
        pos += value_len
        yield key, value


def decode_internal_key(ikey):
    """Split a LevelDB internal key into (user_key, sequence_number,
    value_type). The 8-byte trailer packs (sequence << 8 | type),
    little-endian, per LevelDB's dbformat.cc. type 0 = kTypeDeletion,
    type 1 = kTypeValue. Returns None if too short to contain a trailer."""
    if len(ikey) < 8:
        return None
    user_key = ikey[:-8]
    trailer = int.from_bytes(ikey[-8:], "little")
    seq = trailer >> 8
    vtype = trailer & 0xFF
    return user_key, seq, vtype


def parse_sstable(path):
    """Parse a single .ldb/.sst file entirely in pure Python. Returns
    (records, diagnostics). `records` is a list of dicts:
        {user_key, sequence_number, value_type, value, block_offset}
    A corrupt index/data block produces a diagnostic string and is simply
    skipped -- it never aborts the rest of the file or the scan."""
    diagnostics = []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception as e:
        return [], ["failed to open file: %s" % e]

    if len(data) < 48:
        diagnostics.append("file too small to contain a valid SSTable footer")
        return [], diagnostics
    if int.from_bytes(data[-8:], "little") != TABLE_MAGIC:
        diagnostics.append("SSTable magic number mismatch -- not a valid LevelDB table")
        return [], diagnostics

    footer = data[-48:]
    try:
        _, p = read_varint64(footer, 0)
        _, p = read_varint64(footer, p)
        index_off, p = read_varint64(footer, p)
        index_size, _ = read_varint64(footer, p)
    except Exception as e:
        diagnostics.append("failed to parse footer: %s" % e)
        return [], diagnostics

    try:
        index_block = _read_block(data, index_off, index_size)
        index_entries = list(_parse_block(index_block))
    except Exception as e:
        diagnostics.append("failed to read/parse index block: %s" % e)
        return [], diagnostics

    records = []
    for _sep, handle in index_entries:
        try:
            d_off, hp = read_varint64(handle, 0)
            d_size, _ = read_varint64(handle, hp)
        except Exception as e:
            diagnostics.append("corrupt index handle: %s" % e)
            continue
        try:
            data_block = _read_block(data, d_off, d_size)
            entries = list(_parse_block(data_block))
        except Exception as e:
            diagnostics.append("corrupt/unreadable data block at offset 0x%x: %s" % (d_off, e))
            continue
        for ikey, value in entries:
            decoded = decode_internal_key(ikey)
            if decoded is None:
                diagnostics.append("internal key too short in block at offset 0x%x" % d_off)
                continue
            user_key, seq, vtype = decoded
            if len(value) > MAX_RECORD_SIZE:
                diagnostics.append("value at offset 0x%x exceeds safety limit, truncated" % d_off)
                value = value[:MAX_RECORD_SIZE]
            records.append({
                "user_key": user_key,
                "sequence_number": seq,
                "value_type": vtype,
                "value": value if vtype == 1 else None,
                "block_offset": d_off,
            })
    return records, diagnostics


def parse_write_batch(batch):
    """Decode a LevelDB WriteBatch payload (8-byte sequence base + 4-byte
    count, then a stream of tagged Put/Delete operations). Yields
    (key, value_or_None, is_deletion, sequence_number). Stops (does not
    raise) on any structural inconsistency."""
    if len(batch) < 12:
        return
    seq_base = int.from_bytes(batch[0:8], "little")
    count = int.from_bytes(batch[8:12], "little")
    pos = 12
    n = len(batch)
    i = 0
    while i < count and pos < n:
        tag = batch[pos]
        pos += 1
        try:
            klen, pos = read_varint32(batch, pos)
        except Exception:
            return
        if klen > MAX_RECORD_SIZE or pos + klen > n:
            return
        key = batch[pos:pos + klen]
        pos += klen
        if tag == 1:  # kTypeValue
            try:
                vlen, pos = read_varint32(batch, pos)
            except Exception:
                return
            if vlen > MAX_RECORD_SIZE or pos + vlen > n:
                return
            value = batch[pos:pos + vlen]
            pos += vlen
            yield key, value, False, seq_base + i
        else:  # kTypeDeletion (0), or unrecognized tag treated as deletion
            yield key, None, True, seq_base + i
        i += 1


def parse_log_file(path):
    """Parse a LevelDB *.log write-ahead log: reassembles FULL/FIRST/
    MIDDLE/LAST physical records into logical WriteBatch records, then
    decodes each batch. Returns (records, diagnostics); tombstones
    (deletes) are preserved, never discarded."""
    diagnostics = []
    records = []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception as e:
        return [], ["failed to open file: %s" % e]

    n = len(data)
    pos = 0
    record = b""
    record_start_offset = None
    while pos + 7 <= n:
        block_remaining = LOG_BLOCK_SIZE - (pos % LOG_BLOCK_SIZE)
        if block_remaining < 7:
            pos += block_remaining
            continue
        header_offset = pos
        length = int.from_bytes(data[pos + 4:pos + 6], "little")
        rtype = data[pos + 6]
        payload_start = pos + 7
        payload_end = payload_start + length
        if payload_end > n:
            diagnostics.append("truncated log record at offset 0x%x" % header_offset)
            break
        payload = data[payload_start:payload_end]
        pos = payload_end

        if rtype == 0:
            # padding at end of block -- not an error
            continue
        if rtype not in (1, 2, 3, 4):
            diagnostics.append("unknown log record type %d at offset 0x%x" % (rtype, header_offset))
            record, record_start_offset = b"", None
            continue

        if record_start_offset is None:
            record_start_offset = header_offset

        if rtype in (1, 2):     # FULL, FIRST -- (re)start accumulation
            record = payload
        else:                   # MIDDLE, LAST -- continue accumulation
            record = record + payload

        if rtype in (1, 4):     # FULL or LAST -- logical record complete
            try:
                for key, value, is_del, seq in parse_write_batch(record):
                    records.append({
                        "user_key": key,
                        "sequence_number": seq,
                        "value_type": 0 if is_del else 1,
                        "value": value,
                        "block_offset": record_start_offset,
                    })
            except Exception as e:
                diagnostics.append("failed to parse write batch at offset 0x%x: %s" % (record_start_offset, e))
            record, record_start_offset = b"", None

    return records, diagnostics


# ============================================================================
# FORENSIC RECORD MODEL + VERSION/STATE ANALYSIS
# ============================================================================

@dataclass
class ForensicRecord:
    key: bytes
    value: Optional[bytes]
    user_key: Optional[bytes] = None
    sequence_number: Optional[int] = None
    value_type: Optional[int] = None
    state: str = "UNKNOWN"           # ACTIVE / PREVIOUS_VERSION / TOMBSTONE / STALE_CANDIDATE / UNKNOWN
    source_file: str = ""
    source_type: str = ""            # SSTable / LOG
    physical_offset: Optional[int] = None
    database_path: str = ""
    origin: Optional[str] = None
    recovery_method: str = "Structured LevelDB Parse"
    confidence: str = "High"


def _iter_raw_records(db_path, diagnostics):
    """Yield (raw_record_dict, source_file_basename, source_type) for
    every .ldb/.sst/.log file directly inside db_path. Appends human
    readable diagnostics for any file/block that failed to parse, but
    always continues to the next file."""
    tables = sorted(glob.glob(os.path.join(db_path, "*.ldb")) +
                     glob.glob(os.path.join(db_path, "*.sst")))
    for path in tables:
        try:
            recs, diag = parse_sstable(path)
        except Exception as e:
            diagnostics.append("%s: unexpected error: %s" % (os.path.basename(path), e))
            continue
        diagnostics.extend("%s: %s" % (os.path.basename(path), d) for d in diag)
        for rec in recs:
            yield rec, os.path.basename(path), "SSTable"

    logs = sorted(glob.glob(os.path.join(db_path, "*.log")))
    for path in logs:
        try:
            recs, diag = parse_log_file(path)
        except Exception as e:
            diagnostics.append("%s: unexpected error: %s" % (os.path.basename(path), e))
            continue
        diagnostics.extend("%s: %s" % (os.path.basename(path), d) for d in diag)
        for rec in recs:
            yield rec, os.path.basename(path), "LOG"


def read_leveldb_directory(db_path):
    """Native, two-pass LevelDB reader for one database directory.

    Pass 1 computes the highest sequence number observed for each user
    key across every table/log file -- this is what LevelDB itself uses
    to decide which of several on-disk copies of a key is current.
    Pass 2 streams full records and classifies each one:
        - value_type == deletion  -> TOMBSTONE
        - highest sequence for that key -> ACTIVE
        - otherwise                -> PREVIOUS_VERSION
    Returns (list[ForensicRecord], diagnostics). Never raises; a file
    that can't be parsed just contributes a diagnostic and 0 records.
    """
    diagnostics = []
    max_seq = {}
    for rec, _src, _typ in _iter_raw_records(db_path, diagnostics):
        uk, seq = rec["user_key"], rec["sequence_number"]
        if uk not in max_seq or seq > max_seq[uk]:
            max_seq[uk] = seq

    out = []
    for rec, src, typ in _iter_raw_records(db_path, diagnostics):
        uk, seq, vtype = rec["user_key"], rec["sequence_number"], rec["value_type"]
        if vtype == 0:
            state = "TOMBSTONE"
        elif seq == max_seq.get(uk):
            state = "ACTIVE"
        else:
            state = "PREVIOUS_VERSION"
        out.append(ForensicRecord(
            key=uk, value=rec["value"], user_key=uk,
            sequence_number=seq, value_type=vtype, state=state,
            source_file=src, source_type=typ,
            physical_offset=rec.get("block_offset"),
            database_path=db_path,
            recovery_method="Structured LevelDB Parse (%s)" % typ,
            confidence="High",
        ))
    return out, diagnostics


def dedupe_identical_records(records):
    """Collapse groups of ForensicRecords that share the exact same
    (user_key, value) bytes down to a single representative row.

    Comet/Perplexity data in particular rewrites the same cache entry or
    conversation object with byte-identical content many times in a
    row -- without this, each rewrite (a distinct sequence number, same
    key, same bytes) shows up as its own duplicate results row. When a
    group contains the current ACTIVE copy that one is kept, so the
    displayed state always reflects live data; otherwise the first-seen
    copy is kept (arbitrary but stable). Records whose value bytes
    actually differ are never merged -- only truly identical content
    collapses, so real historical change still shows as separate rows."""
    best_by_fingerprint = {}
    order = []
    for fr in records:
        fp = (fr.user_key, fr.value)
        existing = best_by_fingerprint.get(fp)
        if existing is None:
            best_by_fingerprint[fp] = fr
            order.append(fp)
        elif fr.state == "ACTIVE" and existing.state != "ACTIVE":
            best_by_fingerprint[fp] = fr
    return [best_by_fingerprint[fp] for fp in order]


# ============================================================================
# EVIDENCE DISCOVERY, HASHING, SAFE ZIP EXTRACTION
# ============================================================================

def origin_from_indexeddb_dirname(db_path):
    """Recover the origin URL from a Chromium IndexedDB directory name,
    e.g. 'https_www.perplexity.ai_0.indexeddb.leveldb' ->
    'https://www.perplexity.ai'. Returns None if the name doesn't match."""
    name = os.path.basename(os.path.normpath(db_path))
    m = re.match(r"^(https?|chrome-extension|file)_(.+)_(\d+)\.indexeddb\.leveldb$", name, re.I)
    if not m:
        return None
    scheme, host, port = m.group(1), m.group(2), m.group(3)
    host = host.replace("_", ".")
    if port and port != "0":
        return "%s://%s:%s" % (scheme, host, port)
    return "%s://%s" % (scheme, host)


def discover_leveldb_databases(root):
    """Recursively find every LevelDB database directory under `root`
    (any directory that directly contains .ldb/.sst/.log files or a
    CURRENT file). Returns a list of dicts describing each one."""
    found = []
    for cur, _dirs, files in os.walk(root):
        has_ldb = any(f.endswith(".ldb") for f in files)
        has_sst = any(f.endswith(".sst") for f in files)
        has_log = any(f.endswith(".log") for f in files)
        has_current = "CURRENT" in files
        if not (has_ldb or has_sst or has_log or has_current):
            continue
        is_idb = "indexeddb" in os.path.basename(cur).lower()
        found.append({
            "path": cur,
            "is_indexeddb": is_idb,
            "origin": origin_from_indexeddb_dirname(cur) if is_idb else None,
            "ldb_count": sum(1 for f in files if f.endswith(".ldb")),
            "sst_count": sum(1 for f in files if f.endswith(".sst")),
            "log_count": sum(1 for f in files if f.endswith(".log")),
        })
    return found


def sha256_file(path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class EvidenceFileInfo:
    filename: str
    path: str
    size: int
    sha256: str
    modified: str


def hash_evidence_files(root):
    """SHA-256 every LevelDB-related file under root for chain-of-custody
    / report purposes. Read-only (open(..., 'rb') only)."""
    infos = []
    for cur, _dirs, files in os.walk(root):
        for fn in files:
            upper = fn.upper()
            if fn.lower().endswith((".ldb", ".sst", ".log")) or upper == "CURRENT" or upper.startswith("MANIFEST"):
                p = os.path.join(cur, fn)
                try:
                    st = os.stat(p)
                    infos.append(EvidenceFileInfo(
                        filename=fn, path=p, size=st.st_size,
                        sha256=sha256_file(p),
                        modified=datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
                    ))
                except Exception:
                    continue
    return infos


def safe_extract_zip(zip_path, dest_dir):
    """Extract a zip archive into dest_dir, rejecting any member that
    would escape dest_dir (Zip-Slip / path traversal), any absolute path,
    and any Windows drive-letter path. Never writes outside dest_dir.
    Returns (extracted_count, rejected_member_names)."""
    dest_root = os.path.realpath(dest_dir)
    extracted = 0
    rejected = []
    with zipfile.ZipFile(zip_path) as z:
        for member in z.infolist():
            name = member.filename
            if not name or name.startswith("/") or name.startswith("\\"):
                rejected.append(name)
                continue
            if re.match(r"^[A-Za-z]:[\\/]", name):
                rejected.append(name)
                continue
            norm = os.path.normpath(name)
            if norm.startswith("..") or os.path.isabs(norm):
                rejected.append(name)
                continue
            target = os.path.realpath(os.path.join(dest_root, norm))
            if target != dest_root and not target.startswith(dest_root + os.sep):
                rejected.append(name)
                continue
            if member.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted += 1
    return extracted, rejected


# ============================================================================
# CHROMIUM INDEXEDDB KEY / VALUE DECODING
# ============================================================================

def _decode_be_int(b):
    return int.from_bytes(b, "big") if b else 0


def decode_indexeddb_key_prefix(user_key):
    """Best-effort decode of the Chromium IndexedDB LevelDB KeyPrefix.

    Per indexed_db_leveldb_coding.cc, every IndexedDB record key begins
    with a KeyPrefix: 1 header byte packing the big-endian byte-length of
    each of three integers (3 bits for database_id length, 3 bits for
    object_store_id length, 2 bits for index_id length -- 1..8, 1..8,
    1..4 bytes respectively), followed by those integers themselves, then
    a record-specific suffix. This layout is documented/stable, so the
    (database_id, object_store_id, index_id, record_type) fields are
    reported at Medium confidence. Returns None (never guesses) if the
    buffer is too short to hold the lengths the header byte claims."""
    if not user_key:
        return None
    first = user_key[0]
    db_bytes = ((first >> 5) & 0x07) + 1
    os_bytes = ((first >> 2) & 0x07) + 1
    idx_bytes = (first & 0x03) + 1
    pos = 1
    need = db_bytes + os_bytes + idx_bytes
    if pos + need > len(user_key):
        return None
    database_id = _decode_be_int(user_key[pos:pos + db_bytes]); pos += db_bytes
    object_store_id = _decode_be_int(user_key[pos:pos + os_bytes]); pos += os_bytes
    index_id = _decode_be_int(user_key[pos:pos + idx_bytes]); pos += idx_bytes
    remainder = user_key[pos:]

    if database_id == 0 and object_store_id == 0 and index_id == 0:
        record_type = "Global Metadata"
    elif object_store_id == 0 and index_id == 0:
        record_type = "Database Metadata"
    elif index_id == 0:
        record_type = "Object Store Metadata"
    elif index_id == 1:
        record_type = "Object Store Data"
    elif index_id == 2:
        record_type = "Exists Entry"
    elif index_id == 3:
        record_type = "Blob Entry"
    elif index_id >= 30:
        record_type = "Index Data"
    else:
        record_type = "Index Metadata"

    return {
        "database_id": database_id,
        "object_store_id": object_store_id,
        "index_id": index_id,
        "record_type": record_type,
        "remainder": remainder,
        "confidence": "Medium",
    }


def decode_idb_key(data):
    """Best-effort decode of a single Chromium IndexedDBKey value
    (the 'remainder' bytes of an Object Store Data record's KeyPrefix).

    LIMITATION: the exact tag-byte numbering used here (Null=0,
    Binary=2, String=3, Number/Date=5) reflects the published
    indexed_db_leveldb_coding scheme but has not been independently
    verified against a known-good sample in this environment. Every
    result is therefore returned at confidence='Low' regardless of how
    clean it looks -- treat it as a hint, not ground truth, and always
    cross-check the preserved raw hex."""
    if not data:
        return {"type": "Unknown", "value": None, "confidence": "Low"}
    tag = data[0]
    try:
        if tag == 0:
            return {"type": "Null", "value": None, "confidence": "Low"}
        if tag == 3:  # String: varint char count + UTF-16BE code units
            length, pos = read_varint32(data, 1)
            raw = data[pos:pos + length * 2]
            if len(raw) != length * 2:
                return {"type": "Partial", "value": None, "confidence": "Low"}
            return {"type": "String", "value": raw.decode("utf-16-be", errors="replace"), "confidence": "Low"}
        if tag == 5 and len(data) >= 9:  # Number/Date: 8-byte double
            val = struct.unpack(">d", data[1:9])[0]
            return {"type": "Number", "value": val, "confidence": "Low"}
        if tag == 2:  # Binary: varint length + raw bytes
            length, pos = read_varint32(data, 1)
            raw = data[pos:pos + length]
            return {"type": "Binary", "value": raw.hex(), "confidence": "Low"}
    except Exception:
        pass
    return {"type": "Unsupported", "value": None, "confidence": "Low"}


# ---------------------------------------------------------------------------
# V8 / Blink structured-clone value decoder
# ---------------------------------------------------------------------------
_V8_TAG_UNDEFINED = 0x5F   # '_'
_V8_TAG_NULL = 0x30        # '0'
_V8_TAG_TRUE = 0x54        # 'T'
_V8_TAG_FALSE = 0x46       # 'F'
_V8_TAG_INT32 = 0x49       # 'I'  zigzag varint
_V8_TAG_UINT32 = 0x55      # 'U'  varint
_V8_TAG_DOUBLE = 0x4E      # 'N'  8 bytes
_V8_TAG_UTF8STR = 0x53     # 'S'  varint length + utf-8
_V8_TAG_ONEBYTESTR = 0x22  # '"'  varint length + latin-1
_V8_TAG_TWOBYTESTR = 0x63  # 'c'  varint length*2 + utf-16le
_V8_TAG_DATE = 0x44        # 'D'  8-byte double, ms since epoch
_V8_TAG_VERSION = 0xFF


def _zigzag_decode(n):
    return (n >> 1) ^ -(n & 1)


def decode_v8_value(data):
    """Conservative, best-effort decoder for Blink/V8 ValueSerializer
    blobs (the structured-clone format Chromium uses for IndexedDB /
    localStorage values). Only the primitive tags that have been stable
    across V8 versions are decoded (undefined/null/bool/int/double/
    strings/dates); the first unrecognized tag (object/array/map framing,
    Blob/File references, etc.) stops decoding rather than guessing at
    its structure. Never raises. Always preserves the raw hex."""
    result = {"status": "Unsupported", "items": [], "raw_hex": data.hex() if data else "", "leftover_hex": ""}
    if not data:
        return result
    pos, n = 0, len(data)
    try:
        while pos < n and data[pos] == _V8_TAG_VERSION:
            _ver, pos = read_varint32(data, pos + 1)
    except Exception:
        return result

    items = []
    try:
        while pos < n:
            tag = data[pos]
            pos += 1
            if tag in (_V8_TAG_UNDEFINED, _V8_TAG_NULL):
                items.append(None)
            elif tag == _V8_TAG_TRUE:
                items.append(True)
            elif tag == _V8_TAG_FALSE:
                items.append(False)
            elif tag == _V8_TAG_INT32:
                val, pos = read_varint32(data, pos)
                items.append(_zigzag_decode(val))
            elif tag == _V8_TAG_UINT32:
                val, pos = read_varint32(data, pos)
                items.append(val)
            elif tag in (_V8_TAG_DOUBLE, _V8_TAG_DATE):
                if pos + 8 > n:
                    pos -= 1
                    break
                items.append(struct.unpack("<d", data[pos:pos + 8])[0])
                pos += 8
            elif tag in (_V8_TAG_UTF8STR, _V8_TAG_ONEBYTESTR, _V8_TAG_TWOBYTESTR):
                length, pos2 = read_varint32(data, pos)
                nbytes = length * (2 if tag == _V8_TAG_TWOBYTESTR else 1)
                raw = data[pos2:pos2 + nbytes]
                if len(raw) != nbytes:
                    pos -= 1
                    break
                if tag == _V8_TAG_UTF8STR:
                    items.append(raw.decode("utf-8", errors="replace"))
                elif tag == _V8_TAG_ONEBYTESTR:
                    items.append(raw.decode("latin-1", errors="replace"))
                else:
                    items.append(raw.decode("utf-16-le", errors="replace"))
                pos = pos2 + nbytes
            else:
                pos -= 1
                break
    except Exception:
        pass

    result["items"] = [it for it in items if it not in (None, "")]
    if result["items"] and pos >= n:
        result["status"] = "Decoded"
    elif result["items"]:
        result["status"] = "Partially Decoded"
    result["leftover_hex"] = data[pos:].hex() if pos < n else ""
    return result


# ============================================================================
# DECODING & DETECTION
#
# Design (per forensic-display requirements): raw evidence bytes are never
# modified. Decoding builds several candidate text interpretations (UTF-8,
# UTF-16LE/BE only with real evidence for them, Latin-1 as a deliberately
# weak last resort since it can decode literally any byte sequence), scores
# each with text_quality(), and only accepts the best candidate if it
# clears a minimum bar -- otherwise the value is reported as BINARY rather
# than forced into misleading "text". The chosen text is then passed
# through sanitize_for_display(), a DISPLAY-ONLY cleanup that strips
# control/zero-width/surrogate characters while preserving legitimate
# non-English Unicode (Hindi, CJK, emoji, etc.) -- it is never applied to
# raw_key/raw_value/key_hex/value_hex, which remain the untouched evidence.
# ============================================================================

MIN_TEXT_QUALITY = 0.55   # minimum text_quality() score to accept a decode as "text" at all
GOOD_TEXT_QUALITY = 0.75  # higher bar used for the Chromium LocalStorage prefix-byte shortcut

_ZERO_WIDTH_CHARS = "​‌‍⁠﻿"  # ZWSP, ZWNJ, ZWJ, WORD JOINER, BOM


def _printable_ratio(s):
    if not s:
        return 0.0
    return sum(ch.isprintable() or ch in "\t\n\r" for ch in s) / len(s)


def _ascii_ratio(s):
    if not s:
        return 0.0
    return sum(32 <= ord(ch) <= 126 or ch in "\t\n\r" for ch in s) / len(s)


def _control_char_ratio(s):
    if not s:
        return 0.0
    bad = sum(1 for ch in s if (ord(ch) < 0x20 and ch not in "\t\n\r") or 0x7F <= ord(ch) <= 0x9F)
    return bad / len(s)


def _replacement_ratio(s):
    if not s:
        return 0.0
    return s.count("�") / len(s)


def _alnum_ratio(s):
    if not s:
        return 0.0
    return sum(ch.isalnum() for ch in s) / len(s)


def text_quality(text):
    """Score how likely `text` is genuine decoded content rather than
    binary data misdecoded as text. Combines ASCII/printable/alphanumeric
    ratios, penalizes control characters and replacement characters, and
    gives small bonuses for recognizable structure (JSON braces, URLs,
    known browser/IndexedDB/Comet keyword tokens). Returns 0.0-1.0."""
    if not text:
        return 0.0
    score = (0.15 * _printable_ratio(text)
             + 0.45 * _ascii_ratio(text)
             + 0.25 * _alnum_ratio(text))
    score -= _control_char_ratio(text) * 1.5
    score -= _replacement_ratio(text) * 2.0

    stripped = text.strip()
    if stripped[:1] in "{[" and stripped[-1:] in "}]":
        score += 0.05
    if re.search(r"https?://", text):
        score += 0.05
    if re.search(r"\b(pplx|comet|conversation|prompt|response|uuid|context_uuid|"
                 r"task_description|answer_preview|mode_type|indexeddb|leveldb)\b", text, re.I):
        score += 0.03
    return max(0.0, min(1.0, score))


def looks_binary(data):
    """Cheap pre-check: does this byte blob look like opaque binary data
    not worth even attempting a text decode on? High NUL/control-byte
    ratio with no counterbalancing printable-ASCII content."""
    if not data:
        return False
    n = len(data)
    nul_ratio = data.count(0) / n
    control_count = sum(1 for byte in data if byte < 0x09 or 0x0E <= byte < 0x20 or byte == 0x7F)
    control_ratio = control_count / n
    ascii_ratio = sum(1 for byte in data if 0x20 <= byte <= 0x7E or byte in (9, 10, 13)) / n
    if control_ratio > 0.3 and ascii_ratio < 0.5:
        return True
    if nul_ratio > 0.6 and ascii_ratio < 0.2:
        return True
    return False


def _has_utf16_evidence(data):
    """Real evidence that `data` is UTF-16, not just an even-length blob:
    a byte-order mark, or a majority of byte-pairs matching the classic
    alternating (ascii-byte, 0x00) / (0x00, ascii-byte) pattern of UTF-16
    encoded ASCII/Latin text."""
    if len(data) < 4:
        return False
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    n = len(data) - (len(data) % 2)
    if n < 8:
        return False
    pairs = n // 2
    le_hits = sum(1 for i in range(0, n, 2) if data[i + 1] == 0 and 0x20 <= data[i] <= 0x7E)
    be_hits = sum(1 for i in range(0, n, 2) if data[i] == 0 and 0x20 <= data[i + 1] <= 0x7E)
    return (le_hits / pairs > 0.6) or (be_hits / pairs > 0.6)


def _decode_candidates(data):
    """Build (text, encoding_label, quality_score) for every plausible
    text decoding of `data`, without assuming any single one is correct
    just because it didn't raise an exception."""
    candidates = []

    try:
        cand = data.decode("utf-8")
        q = text_quality(cand)
        if any(byte >= 0x80 for byte in data):
            # Non-trivial multi-byte UTF-8 validated strictly -- that is
            # a strong signal on its own (random binary essentially never
            # satisfies UTF-8's continuation-byte grammar), so legitimate
            # non-English text (Hindi/CJK/emoji/etc.) is never penalized
            # just for having a low ASCII ratio.
            q = max(q, 0.80)
        candidates.append((cand, "utf-8", q))
    except Exception:
        pass

    n_even = len(data) - (len(data) % 2)
    if n_even >= 4:
        utf16_bonus = 0.15 if _has_utf16_evidence(data) else 0.0
        for enc in ("utf-16le", "utf-16be"):
            try:
                cand = data[:n_even].decode(enc)
                q = min(1.0, text_quality(cand) + utf16_bonus)
                candidates.append((cand, enc, q))
            except Exception:
                pass

    try:
        cand = data.decode("latin-1")
        # Latin-1 maps every byte to *some* character, so on its own it
        # proves nothing -- score it down so it never wins over a
        # genuine UTF-8/UTF-16 decode of the same bytes, and require a
        # noticeably higher underlying score before it's accepted alone.
        candidates.append((cand, "latin-1", max(0.0, text_quality(cand) - 0.20)))
    except Exception:
        pass

    return candidates


def _is_display_char(ch):
    if ch in "\n\r\t":
        return True
    if ch in _ZERO_WIDTH_CHARS:
        return False
    return not unicodedata.category(ch).startswith("C")


def sanitize_for_display(text, oneline=False):
    """Central DISPLAY-ONLY sanitizer -- never applied to raw evidence,
    only to the text shown in the GUI. Strips C0/C1 control characters,
    zero-width characters, lone surrogates and unassigned code points,
    and collapses runs of the Unicode replacement character (U+FFFD)
    that signal a failed decode. Preserves ordinary ASCII, legitimate
    non-English Unicode text (Hindi/CJK/emoji/etc.), punctuation, and --
    unless oneline is requested -- newlines/tabs."""
    if not text:
        return ""
    out = []
    replacement_run = 0
    for ch in text:
        if ch == "�":
            replacement_run += 1
            if replacement_run > 2:
                continue
            out.append(ch)
            continue
        replacement_run = 0
        if _is_display_char(ch):
            out.append(ch)
    cleaned = "".join(out)
    if oneline:
        cleaned = " ".join(cleaned.split())
    return cleaned


def _accept(cand, enc):
    # Retained for any external callers; decode_and_detect() itself now
    # uses the scored candidate selection above instead of this.
    if not cand:
        return False
    if "utf-16" in enc:
        return _ascii_ratio(cand) > 0.5
    return _printable_ratio(cand) > 0.85


def _try_snappy(b):
    if not b or len(b) < 3:
        return b
    try:
        declared, _ = read_varint64(b, 0)
        if declared == 0 or declared > MAX_DECOMPRESSED_SIZE:
            return b
        out = snappy_decompress(b)
        return out if len(out) == declared else b
    except Exception:
        return b


def decode_and_detect(b):
    """Structural + scored-candidate value decoder. Returns
    {"type": "json"|"text"|"bytes"|"missing", "pretty": str (sanitized
    for display), "hex": raw_hex, "encoding": str}. `pretty` is always
    safe to render in the GUI; `hex` always reflects the untouched bytes."""
    if b is None:
        return {"type": "missing", "pretty": "", "hex": "", "encoding": ""}

    raw_hex = b.hex()
    data = _try_snappy(b)

    if not data:
        return {"type": "bytes", "pretty": raw_hex, "hex": raw_hex, "encoding": "binary"}

    decoded_text, enc_used = None, None

    # Chromium LocalStorage value prefix byte: 0 -> UTF-16LE payload,
    # 1 -> Latin-1 payload. Only trusted if it actually yields
    # good-quality text; otherwise falls through to generic scoring.
    if len(data) >= 2 and data[0] in (0, 1):
        try:
            cand = (data[1:].decode("utf-16le") if data[0] == 0
                    else data[1:].decode("latin-1"))
            if text_quality(cand) >= GOOD_TEXT_QUALITY:
                decoded_text, enc_used = cand, "chromium-localstorage"
        except Exception:
            pass

    if decoded_text is None and not looks_binary(data):
        candidates = _decode_candidates(data)
        if candidates:
            best_text, best_enc, best_score = max(candidates, key=lambda c: c[2])
            if best_score >= MIN_TEXT_QUALITY:
                decoded_text, enc_used = best_text, best_enc

    if decoded_text is None:
        try:
            b64_str = data.decode("ascii", errors="ignore").strip()
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            if b64_str and all(c in alphabet for c in b64_str[:min(len(b64_str), 256)]):
                inner = base64.b64decode(b64_str, validate=False)
                if inner and not looks_binary(inner):
                    inner_candidates = _decode_candidates(inner)
                    if inner_candidates:
                        best_text, best_enc, best_score = max(inner_candidates, key=lambda c: c[2])
                        if best_score >= MIN_TEXT_QUALITY:
                            decoded_text, enc_used = best_text, "base64+" + best_enc
        except Exception:
            pass

    if decoded_text is None:
        return {"type": "bytes", "pretty": raw_hex, "hex": raw_hex, "encoding": "binary"}

    decoded_text = sanitize_for_display(decoded_text)[:MAX_STRING_LENGTH]
    if not decoded_text:
        return {"type": "bytes", "pretty": raw_hex, "hex": raw_hex, "encoding": "binary"}

    try:
        pretty = json.dumps(json.loads(decoded_text), indent=2, ensure_ascii=False)
        return {"type": "json", "pretty": pretty, "hex": raw_hex, "encoding": enc_used}
    except Exception:
        pass

    return {"type": "text", "pretty": decoded_text, "hex": raw_hex, "encoding": enc_used}


def decode_value_pipeline(raw_value, is_indexeddb=False, idb_record_type=None):
    """Full value-decoding pipeline in forensic-priority order:
        1) V8/Blink structured-clone decode (best-effort)
        2) existing generic decode_and_detect() (Snappy/UTF-8/UTF-16/Base64/JSON)
    A value that clears neither of these is reported as BINARY rather
    than guessed at via raw string carving -- only meaningful, high-
    confidence artifacts are surfaced. Returns (decoded_dict, v8_info_or_None)."""
    v8_info = None
    if raw_value:
        info = decode_v8_value(raw_value)
        if info["items"]:
            v8_info = info

    decoded = decode_and_detect(raw_value)

    return decoded, v8_info


def decode_best_effort_text(raw_value):
    """Best-effort textual view of raw_value used ONLY for internal
    scanning -- Comet record extraction, IOC extraction, timestamp
    detection -- never for the strict Value Type / Value Preview shown
    to the user (decode_and_detect() owns that, and correctly reports
    BINARY when the data doesn't clear the text-quality bar).

    Chromium/Comet values are frequently a mix of real field data and
    V8/Blink serialization framing bytes; that mix legitimately fails
    decode_and_detect()'s quality bar as a whole, but extract_comet_
    records_raw() (and the IOC/timestamp regexes) are specifically
    designed to tolerate that noise and pull out labeled fields anyway.
    This returns the best-scoring decode candidate's sanitized text
    (never gated by MIN_TEXT_QUALITY) so that fallback scanning still
    has something to search, exactly as it did before the stricter
    decode_and_detect() was introduced."""
    if not raw_value:
        return ""
    data = _try_snappy(raw_value)
    if not data:
        return ""
    candidates = _decode_candidates(data)
    if candidates:
        best_text, _enc, _score = max(candidates, key=lambda c: c[2])
    else:
        try:
            best_text = data.decode("latin-1")
        except Exception:
            best_text = ""
    return sanitize_for_display(best_text)[:MAX_STRING_LENGTH]


def storage_origin(key_bytes):
    try:
        if key_bytes.startswith(b"META:"):
            return key_bytes[5:].decode("utf-8", "replace")
        if key_bytes.startswith(b"_"):
            rest = key_bytes[1:]
            nul = rest.find(b"\x00")
            if nul > 0:
                return rest[:nul].decode("utf-8", "replace")
    except Exception:
        pass
    return ""


def hexdump(hexstr):
    try:
        data = bytes.fromhex(hexstr)
    except Exception:
        return hexstr
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join("%02x" % x for x in chunk)
        ascii_ = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append("%08x  %-47s  %s" % (i, hexpart, ascii_))
    return "\n".join(lines)


# ============================================================================
# COMET CONVERSATION RECORD PARSING (nested-object aware) -- unchanged from
# the previous version of this tool; preserved in full.
# ============================================================================

# "query" and its variants are recognized Comet/Perplexity record fields
# (the literal user-typed search/ask text) -- distinct from "query_source"
# (metadata describing where a query came from, e.g. "followup"), which
# is deliberately NOT in this list and never treated as prompt text.
COMET_QUERY_FIELD_NAMES = ("query", "user_query", "prompt", "user_prompt")

COMET_RECORD_KEYS = {
    "uuid", "title", "link", "variant", "status", "unread",
    "context_uuid", "task_description", "answer_preview", "mode_type",
} | set(COMET_QUERY_FIELD_NAMES)
COMET_KNOWN_FIELDS = [
    "uuid", "title", "link", "variant", "status", "unread",
    "context_uuid", "task_description", "answer_preview", "mode_type",
] + list(COMET_QUERY_FIELD_NAMES)


def find_json_objects(text):
    """Brace-match scan text, yield each balanced top-level {...} substring."""
    objs = []
    if not isinstance(text, str):
        return objs
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    objs.append(text[start:i + 1])
                    start = None
    return objs


def _flatten_dicts(obj, depth=0, max_depth=6):
    out = []
    if depth > max_depth:
        return out
    if isinstance(obj, dict):
        out.append(obj)
        for v in obj.values():
            out.extend(_flatten_dicts(v, depth + 1, max_depth))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_flatten_dicts(item, depth + 1, max_depth))
    return out


def _looks_like_comet_record(d):
    return isinstance(d, dict) and len(COMET_RECORD_KEYS & set(d.keys())) >= 2


_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def extract_valid_uuid(text):
    """Return the first syntactically valid UUID substring in `text`
    (discarding any framing bytes/prefix-suffix garbage around it), or
    None if no valid UUID is present. Never fabricates one -- a field
    that merely looks UUID-shaped but fails strict validation is
    rejected rather than guessed at."""
    if not text:
        return None
    m = _UUID_RE.search(str(text))
    if not m:
        return None
    try:
        uuid_module.UUID(m.group())
        return m.group()
    except Exception:
        return None


def clean_url_or_path(text):
    """Extract the URL/path portion of a field, discarding any binary
    framing bytes before it. Looks for the start of an absolute URL
    (http.../https://) or an absolute path (/...) and returns from
    there; otherwise returns the sanitized text unchanged (never
    fabricates a URL that isn't present)."""
    if not text:
        return text
    s = sanitize_for_display(str(text), oneline=True)
    m = re.search(r"(https?://\S+|/[^\s\"']+)", s)
    return m.group(1) if m else s


def _clean_comet_field_value(key, value):
    """Centralized per-field cleanup applied to every recovered Comet
    field (both the clean-JSON path and the raw-fallback path route
    through here). Sanitizes for display, validates UUID fields
    strictly, and trims URL/link fields to their URL/path portion --
    all without ever fabricating content that isn't actually present."""
    if not isinstance(value, str):
        return value
    if key in ("uuid", "context_uuid"):
        return extract_valid_uuid(value) or sanitize_for_display(value, oneline=True)
    if key == "link":
        return clean_url_or_path(value)
    return sanitize_for_display(value, oneline=True)


def _normalize_comet_record(d):
    rec = {}
    for k in COMET_KNOWN_FIELDS:
        if k in d:
            rec[k] = _clean_comet_field_value(k, d[k])
    timestamps = {}
    extra = {}
    for k, v in d.items():
        if k in COMET_KNOWN_FIELDS:
            continue
        lk = k.lower()
        if any(t in lk for t in ("time", "date", "created", "updated", "timestamp")):
            timestamps[k] = v
        else:
            extra[k] = v
    rec["timestamps"] = timestamps
    rec["extra"] = extra
    return rec


_COMET_FIELD_LABEL_RE = re.compile(
    r"(uuid|title|link|variant|unread|status|context_uuid|task_description|"
    r"answer_preview|mode_type|"
    # query-equivalent fields, guarded so they never match as a substring
    # of a longer underscore-compound token (e.g. "query_str",
    # "backend_query"). Only "_" is excluded, not arbitrary letters --
    # sanitize_for_display() strips the control/framing bytes that used
    # to separate adjacent fields, so a field label is very often glued
    # directly onto the END of the previous field's value with no
    # separator at all (e.g. "...COMPLETED" + "query" -> "COMPLETEDquery");
    # rejecting on any preceding letter would miss that real case.
    r"(?<!_)user_query(?![A-Za-z_])|"
    r"(?<!_)user_prompt(?![A-Za-z_])|"
    # query_source is metadata (e.g. "followup"), NOT the prompt text --
    # recognized here purely as a span boundary (captured into `extra`,
    # never into the `query` field) so its value can never bleed into
    # or get swallowed by an adjacent query/prompt field's span.
    r"(?<!_)query_source(?![A-Za-z_])|"
    r"(?<!_)query(?![A-Za-z_])|"
    r"(?<!_)prompt(?![A-Za-z_]))"
)
_COMET_FRAGMENT_MAX = 400


def _clean_comet_fragment(raw, label=None):
    """Extract a plausible field value from a raw (non-JSON, V8/Blink-
    framed) text run. Uses the general display sanitizer -- not a bare
    ASCII-only filter -- so legitimate non-English Comet content (a
    Hindi/CJK prompt title, for instance) survives; only genuine control/
    zero-width/surrogate framing bytes are dropped."""
    if not raw:
        return ""
    raw = raw[:_COMET_FRAGMENT_MAX]
    cleaned = sanitize_for_display(raw, oneline=True)
    cleaned = cleaned.strip(" \"'{}[]:,.")
    if label in ("uuid", "context_uuid"):
        cleaned = cleaned.lstrip("$")
    if len(cleaned) <= 1:
        return ""
    return cleaned.strip()


def extract_comet_records_raw(text):
    """Fallback parser for non-JSON / garbled Comet blobs (Blink/V8
    ValueSerializer framing bytes between fields defeat json.loads)."""
    if not isinstance(text, str) or "uuid" not in text:
        return []
    matches = list(_COMET_FIELD_LABEL_RE.finditer(text))
    if not matches:
        return []
    records = []
    current = {}
    for i, m in enumerate(matches):
        label = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        value = _clean_comet_fragment(text[start:end], label=label)
        if label == "uuid" and current:
            records.append(current)
            current = {}
        if value:
            current[label] = value
    if current:
        records.append(current)
    return [r for r in records if len(r) >= 2]


def extract_comet_conversations(value_text):
    if not isinstance(value_text, str) or not value_text:
        return []
    candidates = []
    try:
        parsed = json.loads(value_text)
        candidates = _flatten_dicts(parsed)
    except Exception:
        candidates = []

    if not candidates:
        for obj_str in find_json_objects(value_text):
            try:
                obj = json.loads(obj_str)
            except Exception:
                continue
            candidates.extend(_flatten_dicts(obj))

    seen_keys = set()
    records = []
    for d in candidates:
        if not _looks_like_comet_record(d):
            continue
        rec = _normalize_comet_record(d)
        dedupe_key = rec.get("uuid") or json.dumps(rec, sort_keys=True, default=str)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        records.append(rec)

    if not records:
        for raw_d in extract_comet_records_raw(value_text):
            if not _looks_like_comet_record(raw_d):
                continue
            rec = _normalize_comet_record(raw_d)
            dedupe_key = rec.get("uuid") or json.dumps(rec, sort_keys=True, default=str)
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)
            records.append(rec)

    return records


def extract_comet_objects(value_text):
    return extract_comet_conversations(value_text)


def _disp(v):
    """Defensive last line of display sanitization for anything about to
    be rendered in the AI-conversation block -- a no-op for already-clean
    text, a safety net for extra/timestamp fields that bypass
    _normalize_comet_record's per-field cleanup."""
    return sanitize_for_display(v, oneline=True) if isinstance(v, str) else v


def format_comet_record(rec, index=None):
    header = "AI Conversation" + (f" #{index}" if index is not None else "")
    lines = [header, "-" * len(header)]
    lines.append(f"Title:            {_disp(rec.get('title', ''))}")
    lines.append(f"Status:           {_disp(rec.get('status', ''))}")
    lines.append(f"Variant:          {_disp(rec.get('variant', ''))}")
    lines.append(f"UUID:             {_disp(rec.get('uuid', ''))}")
    lines.append(f"Context UUID:     {_disp(rec.get('context_uuid', ''))}")
    lines.append(f"Link:             {_disp(rec.get('link', ''))}")
    lines.append(f"Unread:           {_disp(rec.get('unread', ''))}")
    lines.append(f"Task Description: {_disp(rec.get('task_description', ''))}")
    lines.append(f"Answer Preview:   {_disp(rec.get('answer_preview', ''))}")
    lines.append(f"Mode:             {_disp(rec.get('mode_type', ''))}")
    if rec.get("timestamps"):
        lines.append("Timestamps:")
        for k, v in rec["timestamps"].items():
            lines.append(f"  {k}: {_disp(v)}")
    if rec.get("extra"):
        lines.append("Additional Fields:")
        for k, v in rec["extra"].items():
            lines.append(f"  {k}: {_disp(v)}")
    return "\n".join(lines)


def format_comet_records_block(records):
    if not records:
        return None
    blocks = [format_comet_record(r, i + 1) for i, r in enumerate(records)]
    return ("\n\n" + "=" * 70 + "\n\n").join(blocks)


# ============================================================================
# WEB CITATION / RAG GROUNDING TRAIL EXTRACTION
#
# ADDITIVE FEATURE -- does not alter any decode/extraction logic above.
# Recovers the search-grounding evidence behind an AI-generated answer:
# Comet/Perplexity's step-by-step agent pipeline (INITIAL_QUERY ->
# SEARCH_WEB -> SEARCH_RESULTS -> FINAL) and, for each step, the actual
# web sources retrieved -- url, snippet, domain, published date, trust
# rating, sitelinks, cited images. This is stored as a JSON array of step
# objects, sometimes as the value's whole top-level JSON, sometimes nested
# a level deeper as a JSON-encoded STRING inside a "text"/"answer" field
# (itself still surrounded by V8/Blink framing bytes) -- so recovery here
# gathers every top-level JSON array/object substring in the decoded text,
# parses whichever ones succeed, and recursively walks each one (including
# JSON-looking string leaves) collecting step/citation evidence. Bounded
# recursion depth so a hostile/corrupt blob can't cause runaway recursion.
# Never raises; a malformed/partial pipeline still returns whatever was
# structurally recoverable.
# ============================================================================

MAX_CITATION_RECURSION = 8
_CITATION_GATE_RE = re.compile(r"step_type|web_results", re.I)


@dataclass
class WebCitation:
    name: str = ""
    url: str = ""
    snippet: str = ""
    domain_name: str = ""
    citation_domain_name: str = ""
    published_date: str = ""
    description: str = ""
    trust_level: Optional[int] = None
    trust_name: str = ""
    trust_description: str = ""
    is_navigational: Optional[bool] = None
    is_focused_web: Optional[bool] = None
    is_memory: Optional[bool] = None
    is_conversation_history: Optional[bool] = None
    is_attachment: Optional[bool] = None
    tab_id: Optional[str] = None
    sitelinks: list = None
    images: list = None
    goal_id: Optional[str] = None
    step_uuid: str = ""


def find_json_arrays(text):
    """Bracket-match scan text, yield each balanced top-level [...]
    substring. Mirrors find_json_objects() above but for arrays -- Comet/
    Perplexity stores its step pipeline ([{"step_type": ...}, ...]) as a
    top-level JSON array, not an object."""
    objs = []
    if not isinstance(text, str):
        return objs
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "[":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "]":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    objs.append(text[start:i + 1])
                    start = None
    return objs


def _clean_citation_text(v):
    return sanitize_for_display(v, oneline=True) if isinstance(v, str) else v


def _normalize_web_result(d):
    """Build a WebCitation from one web_results[] entry. Tolerates both
    schema variants seen in Comet/Perplexity data: fields flat on the
    entry with citation_domain_name/domain_name/published_date/
    description nested under "meta_data" (SEARCH_RESULTS step), and the
    richer FINAL-step variant (same fields, plus "images"/"authors"
    inside meta_data, and "timestamp" instead of published_date). Never
    fabricates a field that isn't present."""
    if not isinstance(d, dict):
        return None
    meta = d.get("meta_data") if isinstance(d.get("meta_data"), dict) else {}
    trust = d.get("trust") if isinstance(d.get("trust"), dict) else {}
    sitelinks = []
    for sl in (d.get("sitelinks") or []):
        if isinstance(sl, dict):
            sitelinks.append({
                "title": _clean_citation_text(sl.get("title")),
                "url": _clean_citation_text(sl.get("url")),
                "snippet": _clean_citation_text(sl.get("snippet")),
            })
    images = [img for img in (meta.get("images") or d.get("images") or []) if isinstance(img, str)]
    name = d.get("name") or d.get("title")
    url = d.get("url")
    if not name and not url:
        return None
    return WebCitation(
        name=_clean_citation_text(name) or "",
        url=_clean_citation_text(url) or "",
        snippet=_clean_citation_text(d.get("snippet")) or "",
        domain_name=_clean_citation_text(meta.get("domain_name")) or "",
        citation_domain_name=_clean_citation_text(meta.get("citation_domain_name")) or "",
        published_date=_clean_citation_text(meta.get("published_date") or d.get("timestamp")) or "",
        description=_clean_citation_text(meta.get("description")) or "",
        trust_level=trust.get("level") if isinstance(trust.get("level"), int) else None,
        trust_name=_clean_citation_text(trust.get("name")) or "",
        trust_description=_clean_citation_text(trust.get("description")) or "",
        is_navigational=d.get("is_navigational") if isinstance(d.get("is_navigational"), bool) else None,
        is_focused_web=d.get("is_focused_web") if isinstance(d.get("is_focused_web"), bool) else None,
        is_memory=d.get("is_memory") if isinstance(d.get("is_memory"), bool) else None,
        is_conversation_history=d.get("is_conversation_history") if isinstance(d.get("is_conversation_history"), bool) else None,
        is_attachment=d.get("is_attachment") if isinstance(d.get("is_attachment"), bool) else None,
        tab_id=_clean_citation_text(d.get("tab_id")) if d.get("tab_id") is not None else None,
        sitelinks=sitelinks,
        images=images,
    )


def _harvest_citations(results_list, pipeline, goal_id=None, step_uuid=""):
    for wr in (results_list or []):
        cit = _normalize_web_result(wr)
        if cit:
            cit.goal_id = goal_id
            cit.step_uuid = step_uuid
            pipeline["citations"].append(cit)


def _citation_richness(c):
    return sum(bool(x) for x in (c.description, c.trust_name, c.images, c.sitelinks, c.published_date))


def _dedupe_citations(citations):
    """Comet/Perplexity commonly repeats the same cited source across
    the SEARCH_RESULTS step and the FINAL step's (richer) inner answer
    document. Collapse by URL (falling back to name), always keeping
    whichever occurrence carries the most populated fields rather than
    just the first-seen one."""
    best = {}
    order = []
    for c in citations:
        key = (c.url or c.name or "").strip().lower()
        if not key:
            continue
        if key not in best:
            best[key] = c
            order.append(key)
        elif _citation_richness(c) > _citation_richness(best[key]):
            best[key] = c
    return [best[k] for k in order]


def _walk_for_citation_pipeline(obj, pipeline, depth=0):
    """Recursively walk a decoded dict/list/str structure collecting
    query-pipeline steps and web citations wherever they appear -- real
    nested structure (dict/list) or a JSON-looking string leaf (Comet
    nests a second JSON document, as a plain string, inside "text" and
    "answer" fields). Bounded depth; never raises on malformed input."""
    if depth > MAX_CITATION_RECURSION:
        return
    if isinstance(obj, dict):
        step_type = obj.get("step_type")
        if isinstance(step_type, str):
            content = obj.get("content") if isinstance(obj.get("content"), dict) else {}
            uuid_val = obj.get("uuid") or ""
            if step_type == "INITIAL_QUERY" and isinstance(content.get("query"), str):
                if not pipeline.get("initial_query"):
                    pipeline["initial_query"] = content["query"]
            elif step_type == "SEARCH_WEB":
                for q in (content.get("queries") or []):
                    if isinstance(q, dict) and isinstance(q.get("query"), str):
                        pipeline["backend_queries"].append({
                            "engine": q.get("engine"), "query": q.get("query"), "limit": q.get("limit"),
                        })
            elif step_type in ("SEARCH_RESULTS", "FINAL"):
                goal_id = content.get("goal_id")
                _harvest_citations(content.get("web_results"), pipeline, goal_id, uuid_val)
                if step_type == "FINAL" and isinstance(content.get("answer"), str) and pipeline.get("final_answer") is None:
                    # "answer" is frequently itself a JSON-encoded string --
                    # a second nested document with its own (often richer)
                    # web_results/extra_web_results -- try that before
                    # falling back to using it as plain answer text.
                    inner = content["answer"]
                    stripped = inner.strip()
                    parsed_inner = None
                    if stripped[:1] == "{" and stripped[-1:] == "}":
                        try:
                            parsed_inner = json.loads(stripped)
                        except Exception:
                            parsed_inner = None
                    if isinstance(parsed_inner, dict):
                        if isinstance(parsed_inner.get("answer"), str):
                            pipeline["final_answer"] = parsed_inner["answer"]
                        _harvest_citations(parsed_inner.get("web_results"), pipeline, goal_id, uuid_val)
                        _harvest_citations(parsed_inner.get("extra_web_results"), pipeline, goal_id, uuid_val)
                    if pipeline.get("final_answer") is None:
                        pipeline["final_answer"] = inner
        for v in obj.values():
            _walk_for_citation_pipeline(v, pipeline, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _walk_for_citation_pipeline(item, pipeline, depth + 1)
    elif isinstance(obj, str) and len(obj) >= 20:
        stripped = obj.strip()
        if (stripped[:1], stripped[-1:]) in (("{", "}"), ("[", "]")):
            try:
                parsed = json.loads(stripped)
            except Exception:
                return
            _walk_for_citation_pipeline(parsed, pipeline, depth + 1)


def extract_web_citations(value_text):
    """Top-level entry point: recover a query -> web-search -> cited-
    sources -> final-answer pipeline from a decoded LevelDB/IndexedDB
    value. Returns None if no citation/step evidence is present (the
    overwhelming majority of records), otherwise a dict:
        {"initial_query": str, "backend_queries": [...],
         "citations": [WebCitation, ...], "final_answer": str}
    Gated on a cheap substring check so the (relatively) more expensive
    bracket-scan/JSON-parse pass only runs on the small minority of
    records that could plausibly contain this evidence."""
    if not isinstance(value_text, str) or not value_text:
        return None
    if not _CITATION_GATE_RE.search(value_text):
        return None

    candidates = []
    try:
        candidates.append(json.loads(value_text))
    except Exception:
        pass
    for arr_str in find_json_arrays(value_text):
        try:
            candidates.append(json.loads(arr_str))
        except Exception:
            continue
    for obj_str in find_json_objects(value_text):
        try:
            candidates.append(json.loads(obj_str))
        except Exception:
            continue
    if not candidates:
        return None

    pipeline = {"initial_query": None, "backend_queries": [], "citations": [], "final_answer": None}
    try:
        for c in candidates:
            _walk_for_citation_pipeline(c, pipeline)
    except Exception:
        pass

    pipeline["citations"] = _dedupe_citations(pipeline["citations"])
    if not pipeline["citations"] and not pipeline["initial_query"] and not pipeline["backend_queries"]:
        return None
    return pipeline


def _citation_trim(text, limit=160):
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def format_web_citation_trail_block(pipeline):
    """Render a recovered citation pipeline as a report block, in the
    same style as format_comet_record() -- for the EXISTING Selected
    Value box (Auto mode); no new GUI widgets."""
    if not pipeline or not pipeline.get("citations"):
        return None
    header = "WEB CITATION / RAG GROUNDING TRAIL"
    lines = [header, "-" * len(header)]
    if pipeline.get("initial_query"):
        lines.append("User Query:        %s" % _disp(pipeline["initial_query"]))
    for q in pipeline.get("backend_queries") or []:
        lines.append("Backend Search:    \"%s\" (engine=%s, limit=%s)"
                      % (_disp(q.get("query")), q.get("engine"), q.get("limit")))
    lines.append("Sources Retrieved: %d" % len(pipeline["citations"]))
    lines.append("")
    for i, cit in enumerate(pipeline["citations"], 1):
        lines.append("[%d] %s" % (i, cit.name or "(untitled)"))
        domain = cit.citation_domain_name or cit.domain_name
        if domain:
            lines.append("    Domain:       %s" % domain)
        if cit.url:
            lines.append("    URL:          %s" % cit.url)
        if cit.published_date:
            lines.append("    Published:    %s" % cit.published_date)
        if cit.snippet:
            lines.append("    Snippet:      %s" % _citation_trim(cit.snippet))
        if cit.trust_name:
            lines.append("    Trust:        %s (level %s) -- %s"
                          % (cit.trust_name, cit.trust_level, _citation_trim(cit.trust_description, 120)))
        if cit.sitelinks:
            lines.append("    Sitelinks:    %d" % len(cit.sitelinks))
        if cit.images:
            lines.append("    Cited Images: %d" % len(cit.images))
        flags = [n for n, v in (
            ("attachment", cit.is_attachment), ("navigational", cit.is_navigational),
            ("focused_web", cit.is_focused_web), ("memory", cit.is_memory),
            ("conversation_history", cit.is_conversation_history),
        ) if v]
        if flags:
            lines.append("    Flags:        %s" % ", ".join(flags))
        if cit.goal_id is not None or cit.step_uuid:
            lines.append("    Provenance:   goal_id=%s  step_uuid=%s" % (cit.goal_id, cit.step_uuid))
        lines.append("")
    if pipeline.get("final_answer"):
        lines.append("Final Answer (citation-linked):")
        lines.append(_disp(pipeline["final_answer"]))
    return "\n".join(lines)


# ============================================================================
# PROMPT RECOVERY ENGINE
#
# Backend-only. Recovers USER PROMPTS from decoded LevelDB/IndexedDB
# values -- not by grepping raw bytes for the word "prompt", but by
# reconstructing conversation structure (role-based messages, Comet
# task/answer pairs, explicit prompt/query fields) and classifying each
# recovered string into one of:
#     USER_PROMPT          -- role=user (or equivalent) + message content
#     USER_TASK             -- explicit prompt/task field, recognized
#                               conversation context, but no explicit role
#     PRECONFIGURED_PROMPT  -- a prompt/template field on a record that is
#                               explicitly marked "preconfigured" (or has
#                               the task_name+model_preference template
#                               shape) -- NOT something the user typed
#     TASK_DESCRIPTION       -- Comet task_description with no recognized
#                               user-message context to confirm intent
#     SYSTEM_PROMPT          -- role=system
#     ASSISTANT_RESPONSE     -- role=assistant/ai/model, or a recognized
#                               response field (answer/output/answer_preview)
#     POSSIBLE_PROMPT        -- raw field-label fallback only; always
#                               LOW confidence
#
# Never mutates raw evidence; artifacts are a separate, additional
# structure attached to each scanned record.
# ============================================================================

MAX_PROMPT_RECURSION = 10
MIN_PROMPT_LEN = 6
MIN_PROMPT_WORDS = 2

_FIELD_NORM_RE = re.compile(r"[^a-z0-9]")


def normalize_field_name(name):
    """Collapse case/underscore/camelCase variation so 'userMessage',
    'user_message', and 'User Message' all compare equal."""
    return _FIELD_NORM_RE.sub("", str(name).lower())


def _normalized_set(names):
    return {normalize_field_name(n) for n in names}


PROMPT_FIELD_NAMES = _normalized_set([
    "prompt", "query", "question", "user_query", "userQuery", "user_prompt", "userPrompt",
    "user_message", "userMessage", "task_description", "taskDescription",
    "input", "input_text", "inputText",
])
RESPONSE_FIELD_NAMES = _normalized_set([
    "response", "answer", "output", "assistant_message", "assistantMessage",
    "answer_preview", "answerPreview",
])
CONTENT_FIELD_CANDIDATES = ("content", "text", "message", "value", "body", "query", "prompt")
ROLE_FIELD_NAMES = _normalized_set([
    "role", "sender", "author", "speaker", "message_role", "messageRole", "type",
])
USER_ROLE_VALUES = {"user", "human"}
ASSISTANT_ROLE_VALUES = {"assistant", "ai", "model"}
SYSTEM_ROLE_VALUES = {"system"}

_URL_ONLY_RE = re.compile(r"^https?://\S+$", re.I)
_UUID_ONLY_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HASH_ONLY_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_TIMESTAMP_ONLY_RE = re.compile(r"^\d{10,13}$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_BASE64_ONLY_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_IDENTIFIER_ONLY_RE = re.compile(r"^[A-Za-z0-9]+([_\-.][A-Za-z0-9]+)*$")


def validate_prompt_candidate(text, context=None):
    """Reject obvious non-prompts: URLs/UUIDs/hashes/timestamps/Base64
    alone, bare identifiers/config-keys/model-names ('gpt5',
    'allocation-116275', 'lower-threshold'), and anything too short to
    be meaningful. A prompt does NOT need a question mark -- imperative
    sentences ('Summarize this webpage') are valid candidates; structural
    context (not punctuation) drives acceptance here."""
    if not text or not isinstance(text, str):
        return False
    t = text.strip()
    if len(t) < MIN_PROMPT_LEN:
        return False
    if _URL_ONLY_RE.match(t) or _UUID_ONLY_RE.match(t) or _HASH_ONLY_RE.match(t):
        return False
    if _TIMESTAMP_ONLY_RE.match(t):
        return False
    if " " not in t and _BASE64_ONLY_RE.match(t):
        return False
    words = t.split()
    if len(words) < MIN_PROMPT_WORDS:
        # a single "word" with no spaces: reject bare identifiers/keys/
        # model names/config tokens ("gpt5", "allocation-116275",
        # "lower-threshold") unless it's a genuinely long phrase.
        if _IDENTIFIER_ONLY_RE.match(t):
            return False
        if len(t) < 12:
            return False
    return True


@dataclass
class PromptArtifact:
    text: str
    artifact_type: str

    field_name: Optional[str] = None
    role: Optional[str] = None

    conversation_uuid: Optional[str] = None
    context_uuid: Optional[str] = None
    task_uuid: Optional[str] = None

    timestamp: Optional[str] = None

    source_file: Optional[str] = None
    source_offset: Optional[int] = None
    sequence_number: Optional[int] = None

    record_state: Optional[str] = None

    recovery_method: str = ""
    confidence: str = "LOW"

    path: str = ""
    normalized_text: str = ""
    occurrence_count: int = 1


def _extract_text_from_content(content, depth=0):
    """content may be a plain string, a list of {"type":"text","text":...}
    parts (Anthropic/OpenAI-style), or a dict with a 'parts' list
    (ChatGPT-style). Never assumes it's a plain string."""
    if depth > MAX_PROMPT_RECURSION:
        return None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for key in ("text", "content", "value"):
                    if isinstance(item.get(key), str):
                        parts.append(item[key])
                        break
        return "\n".join(parts) if parts else None
    if isinstance(content, dict):
        if isinstance(content.get("parts"), list):
            return _extract_text_from_content(content["parts"], depth + 1)
        for key in ("text", "content", "value"):
            if isinstance(content.get(key), str):
                return content[key]
    return None


def extract_role_message(d, path="root"):
    """Detect a {role/sender/author/speaker: user|assistant|system,
    content/text/message/...} style message object -- including the
    ChatGPT-style nested 'author': {'role': 'user'} shape. This is the
    strongest prompt-recovery signal: an explicit, structural role
    marker, not a guess based on field names alone. Returns 0 or 1
    PromptArtifact."""
    role, role_field = None, None
    for k, v in d.items():
        nk = normalize_field_name(k)
        if nk in ROLE_FIELD_NAMES and isinstance(v, str):
            role, role_field = v.strip().lower(), k
            break
    if role is None and isinstance(d.get("author"), dict):
        inner = d["author"].get("role")
        if isinstance(inner, str):
            role, role_field = inner.strip().lower(), "author.role"

    if role not in USER_ROLE_VALUES and role not in ASSISTANT_ROLE_VALUES and role not in SYSTEM_ROLE_VALUES:
        return []

    content_field, content_val = None, None
    for key in CONTENT_FIELD_CANDIDATES:
        if key in d:
            extracted = _extract_text_from_content(d[key])
            if extracted:
                content_field, content_val = key, extracted
                break
    if content_val is None or not validate_prompt_candidate(content_val):
        return []

    if role in USER_ROLE_VALUES:
        artifact_type, confidence = "USER_PROMPT", "HIGH"
    elif role in ASSISTANT_ROLE_VALUES:
        artifact_type, confidence = "ASSISTANT_RESPONSE", "HIGH"
    else:
        artifact_type, confidence = "SYSTEM_PROMPT", "MEDIUM"

    return [PromptArtifact(
        text=content_val, artifact_type=artifact_type, field_name=content_field, role=role,
        recovery_method="Structured role:%s -> %s" % (role, content_field),
        confidence=confidence, path=path,
    )]


def _looks_preconfigured(d):
    """A prompt/template record explicitly marked as such (preconfigured
    flag), or shaped like Comet's preconfigured-task template (task_name +
    prompt + a model-preference field) -- these are NOT user-typed text."""
    if d.get("preconfigured") is True:
        return True
    has_task_name = any(normalize_field_name(k) == "taskname" for k in d)
    has_model_pref = any(normalize_field_name(k) in ("modelpreference", "model") for k in d)
    has_prompt_field = any(normalize_field_name(k) in PROMPT_FIELD_NAMES for k in d)
    return has_task_name and has_model_pref and has_prompt_field


def _extract_explicit_prompt_fields(d, path, skip_keys):
    """Explicit prompt/query/task_description/response-shaped fields on a
    dict that wasn't already handled as a role-based message. Classifies
    conservatively: PRECONFIGURED_PROMPT when the record is clearly a
    template, TASK_DESCRIPTION/USER_TASK for task_description depending
    on whether the record itself already carries conversation identity,
    USER_TASK (not USER_PROMPT -- no role evidence) for everything else,
    at MEDIUM confidence since there's no explicit role to confirm intent."""
    artifacts = []
    preconfigured = _looks_preconfigured(d)
    has_identity = bool(d.get("uuid") or d.get("context_uuid") or d.get("conversation_id")
                         or d.get("conversationId") or d.get("thread_uuid"))
    for k, v in d.items():
        if k in skip_keys or not isinstance(v, str):
            continue
        nk = normalize_field_name(k)
        if nk in PROMPT_FIELD_NAMES:
            if not validate_prompt_candidate(v):
                continue
            if preconfigured:
                artifact_type, confidence = "PRECONFIGURED_PROMPT", "HIGH"
                method = "Structured preconfigured template field:%s" % k
            elif nk == normalize_field_name("task_description"):
                artifact_type = "USER_TASK" if has_identity else "TASK_DESCRIPTION"
                confidence, method = "MEDIUM", "Structured field:%s (no explicit role marker)" % k
            else:
                artifact_type, confidence = "USER_TASK", "MEDIUM"
                method = "Structured field:%s (no explicit role marker)" % k
            artifacts.append(PromptArtifact(
                text=v, artifact_type=artifact_type, field_name=k,
                recovery_method=method, confidence=confidence, path=path,
            ))
        elif nk in RESPONSE_FIELD_NAMES:
            if not validate_prompt_candidate(v):
                continue
            artifacts.append(PromptArtifact(
                text=v, artifact_type="ASSISTANT_RESPONSE", field_name=k,
                recovery_method="Structured response field:%s" % k,
                confidence="MEDIUM", path=path,
            ))
    return artifacts


def _extract_structured_prompts(obj, path="root", depth=0):
    """Recursively walk a decoded dict/list structure looking for
    role-based messages and explicit prompt/response fields, tracking the
    object path for forensic verification. Bounded recursion depth."""
    if depth > MAX_PROMPT_RECURSION:
        return []
    artifacts = []
    if isinstance(obj, dict):
        role_artifacts = extract_role_message(obj, path)
        skip_keys = {a.field_name for a in role_artifacts if a.field_name}
        artifacts.extend(role_artifacts)
        artifacts.extend(_extract_explicit_prompt_fields(obj, path, skip_keys))
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                artifacts.extend(_extract_structured_prompts(v, "%s.%s" % (path, k), depth + 1))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if isinstance(item, (dict, list)):
                artifacts.extend(_extract_structured_prompts(item, "%s[%d]" % (path, i), depth + 1))
    return artifacts


def extract_comet_prompt(rec, index=None, key_text=""):
    """Comet-specific recovery from an already-normalized Comet record
    (see _normalize_comet_record).

    Membership in `comet_records` at all already proves this is a
    recognized Comet/Perplexity artifact -- _looks_like_comet_record()
    required 2+ known structural fields to match before this record was
    ever built. So a genuine `query`/`user_query`/`prompt`/`user_prompt`
    field recovered on it is real structural evidence of a user-typed
    prompt, not a guess -- it is classified USER_PROMPT, never the
    heuristic-carving POSSIBLE_PROMPT tier:
        HIGH confidence   -- the query field, PLUS a conversation UUID,
                              a context UUID, or a recognizable
                              pplx-query-cache key are also present.
        MEDIUM confidence -- the query field on a recognized Comet
                              record, but no UUID/cache-key corroboration.
    (query_source and similar metadata fields are never captured here --
    see COMET_QUERY_FIELD_NAMES / _COMET_FIELD_LABEL_RE.)

    task_description is a separate candidate user task/prompt (kept at
    lower trust than an explicit query field, since it's a looser
    signal), and answer_preview is the AI's response -- never confused
    with the prompt."""
    artifacts = []
    path = "comet[%d]" % index if index is not None else "comet"
    conversation_uuid = rec.get("uuid") or None
    context_uuid = rec.get("context_uuid") or None
    has_identity = bool(conversation_uuid or context_uuid
                         or "pplx-query-cache" in (key_text or ""))

    for field_name in COMET_QUERY_FIELD_NAMES:
        value = rec.get(field_name)
        if value and validate_prompt_candidate(value):
            artifacts.append(PromptArtifact(
                text=value, artifact_type="USER_PROMPT", field_name=field_name,
                conversation_uuid=conversation_uuid, context_uuid=context_uuid,
                recovery_method="Structured Comet/Perplexity %s field" % field_name,
                confidence="HIGH" if has_identity else "MEDIUM", path=path,
            ))
            break  # one query-equivalent field is enough evidence per record

    task_desc = rec.get("task_description")
    if task_desc and validate_prompt_candidate(task_desc):
        artifacts.append(PromptArtifact(
            text=task_desc,
            artifact_type="USER_TASK" if has_identity else "TASK_DESCRIPTION",
            field_name="task_description",
            conversation_uuid=conversation_uuid, context_uuid=context_uuid,
            recovery_method="Comet structured extraction -> task_description",
            confidence="MEDIUM", path=path,
        ))
    answer = rec.get("answer_preview")
    if answer and validate_prompt_candidate(answer):
        artifacts.append(PromptArtifact(
            text=answer, artifact_type="ASSISTANT_RESPONSE", field_name="answer_preview",
            conversation_uuid=conversation_uuid, context_uuid=context_uuid,
            recovery_method="Comet structured extraction -> answer_preview",
            confidence="MEDIUM", path=path,
        ))
    return artifacts


_RAW_PROMPT_FIELD_RE = re.compile(
    r'"?(prompt|query|question|user_?message|task_description|user_?prompt|input_?text)"?\s*[:=]?\s*"'
)


def _extract_raw_field_fallback(text):
    """Conservative last-resort structural-field recovery for when full
    JSON parsing failed but the (lenient, best-effort) decoded text still
    contains recognizable 'fieldname": "value"'-shaped fragments -- e.g.
    V8/Blink framing bytes were stripped but the object never
    round-tripped through json.loads(). Always LOW confidence /
    POSSIBLE_PROMPT, never promoted higher without structural proof.

    Only the FIRST occurrence of each field label is kept. At this raw,
    structure-free tier there's no way to tell whether a second hit for
    the same label (e.g. another "query") is a genuinely distinct second
    message or -- far more often in practice -- a duplicate/rewritten
    echo of the same value stored under a second key (Perplexity/Comet
    payloads commonly carry both the as-typed query and a normalized
    copy used for retrieval). Real multi-message recovery (several
    distinct user turns in an actual message array) is handled
    correctly and separately by _extract_structured_prompts(), which
    walks a real parsed object and is unaffected by this."""
    if not text:
        return []
    artifacts = []
    seen_fields = set()
    for m in _RAW_PROMPT_FIELD_RE.finditer(text):
        field = m.group(1)
        if field in seen_fields:
            continue
        val_match = re.match(r'([^"\n]{1,400})', text[m.end():])
        if not val_match:
            continue
        candidate = val_match.group(1).strip(" \"'{}[]:,.")
        if not validate_prompt_candidate(candidate):
            continue
        seen_fields.add(field)
        artifacts.append(PromptArtifact(
            text=candidate, artifact_type="POSSIBLE_PROMPT", field_name=field,
            recovery_method="Raw structured-field fallback -> %s" % field,
            confidence="LOW",
        ))
        if len(artifacts) >= 10:
            break
    return artifacts


def extract_prompt_artifacts(value_obj, value_text=None, comet_records=None, key_text=""):
    """Top-level prompt-recovery entry point: structured JSON traversal
    (role-based messages + explicit prompt fields, forensic priority
    first) -> Comet structured extraction -> raw field-label fallback on
    best-effort text. `key_text` (the decoded key, e.g. containing
    "pplx-query-cache-...") is passed through to extract_comet_prompt()
    as one of the corroborating signals for HIGH-confidence
    classification. The raw field-label fallback only ever runs when
    NEITHER of the higher-confidence paths found anything -- i.e. this
    record was never recognized as Comet/structured at all, so there is
    genuinely insufficient structural evidence for anything above LOW
    confidence. Never raises -- a malformed conversation object must not
    abort the scan."""
    try:
        artifacts = []
        if isinstance(value_obj, (dict, list)):
            artifacts.extend(_extract_structured_prompts(value_obj))
        if comet_records:
            for i, rec in enumerate(comet_records):
                artifacts.extend(extract_comet_prompt(rec, index=i, key_text=key_text))
        if not artifacts and value_text:
            artifacts.extend(_extract_raw_field_fallback(value_text))
        return artifacts
    except Exception:
        return []


def classify_prompt_artifact(artifact):
    """Re-derives a human-readable label for an artifact_type (used by
    display code); the classification decision itself is made where the
    artifact is created (extract_role_message / _extract_explicit_prompt_
    fields / extract_comet_prompt) using structural evidence, not here."""
    return {
        "USER_PROMPT": "USER PROMPT",
        "USER_TASK": "USER TASK",
        "PRECONFIGURED_PROMPT": "PRECONFIGURED PROMPT",
        "PROMPT_TEMPLATE": "PROMPT TEMPLATE",
        "TASK_DESCRIPTION": "TASK DESCRIPTION",
        "SYSTEM_PROMPT": "SYSTEM PROMPT",
        "ASSISTANT_RESPONSE": "ASSISTANT RESPONSE",
        "POSSIBLE_PROMPT": "POSSIBLE PROMPT",
    }.get(artifact.artifact_type, artifact.artifact_type)


def associate_prompt_context(artifacts, conversation_uuid=None, context_uuid=None, timestamp=None,
                              source_file=None, source_offset=None, sequence_number=None, record_state=None):
    """Fill in provenance/identity fields an artifact didn't already
    carry from its own structural extraction, using only values already
    known for the parent record -- never invents anything."""
    for a in artifacts:
        if not a.conversation_uuid and conversation_uuid:
            a.conversation_uuid = conversation_uuid
        if not a.context_uuid and context_uuid:
            a.context_uuid = context_uuid
        if not a.timestamp and timestamp:
            a.timestamp = timestamp
        a.source_file = source_file
        a.source_offset = source_offset
        a.sequence_number = sequence_number
        a.record_state = record_state
    return artifacts


def associate_response(prompt_artifacts, response_artifacts):
    """Best-effort prompt/response pairing using conversation/context UUID
    when available, falling back to positional pairing only when there is
    exactly one of each within the same record. Never invents a
    relationship across records. Returns [(prompt, response_or_None), ...]."""
    pairs = []
    used = set()
    for p in prompt_artifacts:
        match = None
        if p.conversation_uuid or p.context_uuid:
            for i, r in enumerate(response_artifacts):
                if i in used:
                    continue
                if ((p.conversation_uuid and r.conversation_uuid == p.conversation_uuid) or
                        (p.context_uuid and r.context_uuid == p.context_uuid)):
                    match = r
                    used.add(i)
                    break
        if match is None and len(prompt_artifacts) == 1 and len(response_artifacts) == 1:
            match = response_artifacts[0]
            used.add(0)
        pairs.append((p, match))
    return pairs


def deduplicate_prompt_artifacts(artifacts):
    """Fold logically-identical prompts (same normalized text + same
    conversation/context uuid) into a single artifact with an
    occurrence_count, WITHOUT discarding the first occurrence's
    provenance. Whitespace-only normalization for comparison; the
    original recovered text is never altered."""
    groups = {}
    order = []
    for a in artifacts:
        normalized = " ".join(a.text.split()).strip().lower()
        a.normalized_text = normalized
        fingerprint = hashlib.sha256(
            (normalized + "|" + (a.conversation_uuid or "") + "|" + (a.context_uuid or "")).encode("utf-8", "ignore")
        ).hexdigest()
        if fingerprint not in groups:
            groups[fingerprint] = a
            order.append(fingerprint)
        else:
            groups[fingerprint].occurrence_count += 1
    return [groups[fp] for fp in order]


_PROMPT_PREVIEW_PRIORITY = ("USER_PROMPT", "USER_TASK", "PRECONFIGURED_PROMPT")


def best_prompt_for_preview(prompt_artifacts):
    """Pick the single most forensically significant prompt artifact for
    the table's Value Preview column -- confirmed user prompts first,
    then user tasks, then preconfigured templates. Assistant responses,
    plain task descriptions, and low-confidence fallback candidates never
    headline the preview (they're still fully available in Selected
    Value / CSV)."""
    if not prompt_artifacts:
        return None
    by_type = {}
    for a in prompt_artifacts:
        by_type.setdefault(a.artifact_type, []).append(a)
    for t in _PROMPT_PREVIEW_PRIORITY:
        if t in by_type:
            return by_type[t][0]
    return None


def format_prompt_artifacts_block(prompt_artifacts):
    """Render recovered prompt/response artifacts for the EXISTING
    Selected Value box (Auto mode) -- no new widgets. Pairs each
    prompt-like artifact with its associated response where one can be
    established."""
    if not prompt_artifacts:
        return None
    prompts = [a for a in prompt_artifacts
               if a.artifact_type in ("USER_PROMPT", "USER_TASK", "PRECONFIGURED_PROMPT",
                                       "TASK_DESCRIPTION", "POSSIBLE_PROMPT", "SYSTEM_PROMPT")]
    responses = [a for a in prompt_artifacts if a.artifact_type == "ASSISTANT_RESPONSE"]
    if not prompts:
        return None
    pairs = associate_response(prompts, responses)
    blocks = []
    for prompt, response in pairs:
        header = classify_prompt_artifact(prompt)
        lines = [header, "-" * len(header), "", prompt.text]
        if prompt.conversation_uuid:
            lines += ["", "Conversation UUID:", prompt.conversation_uuid]
        if prompt.context_uuid:
            lines += ["", "Context UUID:", prompt.context_uuid]
        if prompt.occurrence_count > 1:
            lines += ["", "Occurrence Count: %d" % prompt.occurrence_count]
        if prompt.field_name:
            lines += ["", "Source Field:", prompt.field_name]
        # "Artifact Confidence" -- confidence in the FIELD INTERPRETATION
        # (is this really the user's query?), not in how hard the bytes
        # were to decode. A value recovered via a fallback/raw-text
        # decoder can still be HIGH confidence here when real structural
        # evidence (a recognized Comet record, a conversation/context
        # UUID, a pplx-query-cache key) backs up the interpretation.
        lines += ["", "Recovery:", prompt.recovery_method or "(unknown)",
                  "", "Artifact Confidence:", prompt.confidence]
        if response:
            lines += ["", "AI RESPONSE", "-----------", "", response.text]
        blocks.append("\n".join(lines))
    return ("\n\n" + "-" * 50 + "\n\n").join(blocks)


# ============================================================================
# TIMELINE FUNCTIONS
# ============================================================================

class TimelineEvent:
    """One LevelDB record can yield MANY of these (one per Comet object
    found inside its value)."""

    def __init__(self):
        self.timestamp_utc = None
        self.timestamp_ist = None
        self.activity = "Unknown"
        self.title = ""
        self.prompt = ""
        self.response = ""
        self.url = ""
        self.domain = ""
        self.conversation_id = ""
        self.context_uuid = ""
        self.task_uuid = ""
        self.status = ""
        self.mode = ""
        self.source = ""
        self.source_key = ""
        self.source_file = ""
        self.database = ""
        self.object_store = ""
        self.sequence_number = None
        self.deleted = False
        self.raw_offset = None
        self.confidence = "Medium"
        self.record_key = ""
        self.raw_data = {}

    def to_dict(self):
        return {
            "timestamp_ist": self.timestamp_ist.isoformat() if self.timestamp_ist else None,
            "timestamp_utc": self.timestamp_utc.isoformat() if self.timestamp_utc else None,
            "activity": self.activity,
            "title": self.title,
            "prompt": self.prompt,
            "response": self.response,
            "url": self.url,
            "domain": self.domain,
            "conversation_id": self.conversation_id,
            "context_uuid": self.context_uuid,
            "task_uuid": self.task_uuid,
            "status": self.status,
            "mode": self.mode,
            "source": self.source,
            "source_key": self.source_key,
            "source_file": self.source_file,
            "database": self.database,
            "object_store": self.object_store,
            "sequence_number": self.sequence_number,
            "deleted": self.deleted,
            "raw_offset": self.raw_offset,
            "confidence": self.confidence,
            "record_key": self.record_key,
        }


def detect_timestamps(text):
    if not isinstance(text, str):
        return []
    timestamps = []
    for match in TIMESTAMP_PATTERNS["unix"].finditer(text):
        ts = int(match.group())
        try:
            dt = datetime.fromtimestamp(ts, tz=UTC)
            if 2020 < dt.year < 2030:
                timestamps.append(dt)
        except Exception:
            pass
    for match in TIMESTAMP_PATTERNS["unix_ms"].finditer(text):
        ts = int(match.group())
        try:
            dt = datetime.fromtimestamp(ts / 1000, tz=UTC)
            if 2020 < dt.year < 2030:
                timestamps.append(dt)
        except Exception:
            pass
    for match in TIMESTAMP_PATTERNS["iso8601"].finditer(text):
        try:
            dt = datetime.fromisoformat(match.group())
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if 2020 < dt.year < 2030:
                timestamps.append(dt)
        except Exception:
            pass
    return sorted(list(set(timestamps)))


def extract_prompts_and_responses(data):
    prompt = ""
    response = ""
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            for key in ["prompt", "query", "question", "message", "userMessage"]:
                if key in parsed and isinstance(parsed[key], str):
                    prompt = parsed[key]
                    break
            for key in ["response", "answer", "output", "content", "assistant_message"]:
                if key in parsed and isinstance(parsed[key], str):
                    response = parsed[key]
                    break
            if "messages" in parsed and isinstance(parsed["messages"], list):
                for msg in parsed["messages"]:
                    if isinstance(msg, dict):
                        if msg.get("role") == "user" and not prompt:
                            prompt = msg.get("content", "")
                        elif msg.get("role") in ["assistant", "ai"]:
                            response = msg.get("content", "")
    except Exception:
        pass
    return prompt[:300], response[:300]


def extract_urls(data):
    urls = []
    pattern = r'https?://[^\s"\'\)<>\[\]{}\\]+'
    try:
        for match in re.finditer(pattern, data):
            url = match.group(0)
            if len(url) > 10:
                urls.append(url)
    except Exception:
        pass
    return list(set(urls))


def classify_activity(key_text, value_text):
    combined_text = f"{key_text} {value_text}".lower()
    for activity, keywords in ACTIVITY_TYPES.items():
        if any(kw in combined_text for kw in keywords):
            return activity
    return "Browser Activity"


def create_timeline_event(key_text, value_text, key_bytes, source="LevelDB", comet_records=None):
    timestamps = detect_timestamps(value_text)
    if not timestamps:
        timestamps = detect_timestamps(key_text)
    if not timestamps:
        return None

    ts_utc = timestamps[0]
    ts_ist = ts_utc.astimezone(IST)

    event = TimelineEvent()
    event.timestamp_utc = ts_utc
    event.timestamp_ist = ts_ist
    event.source = source
    event.record_key = key_text[:80]
    event.raw_data = {"key": key_text, "value": value_text[:200]}

    prompt, response = extract_prompts_and_responses(value_text)
    event.prompt = prompt
    event.response = response

    if comet_records and not event.prompt and not event.response:
        first = comet_records[0]
        event.prompt = (first.get("task_description") or first.get("title") or "")[:300]
        event.response = (first.get("answer_preview") or "")[:300]
        if not event.conversation_id and first.get("uuid"):
            event.conversation_id = str(first["uuid"])[:50]
        if not event.url and first.get("link"):
            event.url = first["link"]

    urls = extract_urls(value_text)
    if urls:
        event.url = urls[0]

    try:
        parsed = json.loads(value_text)
        if isinstance(parsed, dict):
            for key_name in ["conversation_id", "conversationId", "chat_id", "chatId", "id"]:
                if key_name in parsed:
                    event.conversation_id = str(parsed[key_name])[:50]
                    break
    except Exception:
        pass

    event.activity = classify_activity(key_text, value_text)

    if event.prompt and event.activity != "Unknown":
        event.confidence = "High"
    elif event.url:
        event.confidence = "High"
    else:
        event.confidence = "Medium"

    return event


def classify_comet_activity(rec, key_text=""):
    title = (rec.get("title") or "").lower()
    status = (rec.get("status") or "").lower()
    variant = (rec.get("variant") or "").lower()
    mode = (rec.get("mode_type") or "").lower()
    task_desc = rec.get("task_description") or ""
    answer = rec.get("answer_preview") or ""
    unread = str(rec.get("unread") or "").lower()
    link = rec.get("link") or ""
    context_uuid = rec.get("context_uuid") or ""
    extra = rec.get("extra") or {}
    combined_extra = json.dumps(extra, default=str).lower() if extra else ""

    if "agent" in mode or "agent" in variant:
        return "Agent Task Completed" if status in ("completed", "done", "success") else "Agent Task Started"
    if "summarize" in title or "sidecar" in variant or "summary" in mode:
        return "Webpage Summarized" if status == "completed" else "Summarize Current Webpage"
    if "pin" in variant or "bookmark" in title or "pin" in title:
        return "Bookmark/Pin Created"
    if unread in ("true", "1", "yes"):
        return "Notification"
    if answer:
        return "AI Response Generated"
    if task_desc:
        return "Follow-up Question" if context_uuid else "User Prompt"
    if "cache" in key_text.lower() or "cache" in variant:
        return "Cached Search"
    if variant == "thread":
        if status == "completed":
            return "Conversation Updated" if context_uuid else "Conversation Created"
        if status in ("created", "new"):
            return "Search Thread Created"

    combined = f"{title} {combined_extra}"
    if "login" in combined or "sign in" in combined:
        return "Login"
    if "logout" in combined or "sign out" in combined:
        return "Logout"
    if "setting" in combined or "preference" in combined:
        return "Settings Changed"
    if "geolocation" in combined or "location" in combined:
        return "Geolocation Access"
    if "permission" in combined:
        if "grant" in combined or "allow" in combined:
            return "Permission Granted"
        if "den" in combined or "block" in combined:
            return "Permission Denied"
        return "Permission Prompt"
    if "session" in combined:
        return "Session Updated" if status == "completed" else "Session Created"
    if link:
        return "Website Visited"

    fallback_text = f"{key_text} {title} {task_desc} {answer} {combined_extra}"
    return classify_activity(key_text, fallback_text)


def _rec_timestamps(rec):
    found = []
    for v in (rec.get("timestamps") or {}).values():
        found.extend(detect_timestamps(str(v)))
    return found


def build_timeline_events(key_text, value_text, key_bytes, source="LevelDB",
                           deleted=False, comet_records=None):
    if comet_records is None:
        comet_records = extract_comet_objects(value_text)

    events = []

    if comet_records:
        record_level_ts = detect_timestamps(value_text) or detect_timestamps(key_text)
        for rec in comet_records:
            ev = TimelineEvent()
            ts_list = _rec_timestamps(rec) or record_level_ts
            if ts_list:
                ev.timestamp_utc = ts_list[0]
                ev.timestamp_ist = ev.timestamp_utc.astimezone(IST)
            ev.source = source
            ev.source_key = key_text[:200]
            ev.record_key = key_text[:80]
            ev.raw_data = {"key": key_text, "value": value_text[:200]}
            ev.title = rec.get("title", "") or ""
            ev.prompt = (rec.get("task_description") or rec.get("title") or "")[:300]
            ev.response = (rec.get("answer_preview") or "")[:300]
            ev.url = rec.get("link") or ""
            if ev.url:
                try:
                    ev.domain = urlparse(ev.url).netloc
                except Exception:
                    ev.domain = ""
            ev.conversation_id = str(rec.get("uuid") or "")[:80]
            ev.context_uuid = str(rec.get("context_uuid") or "")[:80]
            ev.task_uuid = str((rec.get("extra") or {}).get("task_uuid", ""))[:80]
            ev.status = rec.get("status", "") or ""
            ev.mode = rec.get("mode_type", "") or ""
            ev.deleted = deleted
            ev.activity = classify_comet_activity(rec, key_text)
            ev.confidence = "High" if (ev.prompt or ev.response or ev.url) else "Medium"
            events.append(ev)
        return events

    single = create_timeline_event(key_text, value_text, key_bytes, source=source)
    if single:
        single.deleted = deleted
        single.source_key = key_text[:200]
        events.append(single)
    return events


def extract_iocs(text):
    if not isinstance(text, str):
        return {}
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            iocs[ioc_type] = list(set(matches))
    return iocs


def classify_artifact(key_text, value_text):
    combined = (key_text + " " + value_text).lower()
    for category, keywords in ARTIFACT_CATEGORIES.items():
        if any(kw in combined for kw in keywords):
            return category
    return "Unknown"


def decode_jwt(token_str):
    try:
        parts = token_str.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
        payload_json = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_json)
        extracted = {}
        for key in ["email", "sub", "exp", "name", "user_id", "iss", "aud"]:
            if key in payload:
                extracted[key] = payload[key]
        return extracted if extracted else payload
    except Exception:
        return None


# ============================================================================
# GUI-side value classification helpers
# ============================================================================

def _is_clean_display(decoded):
    """True when a decode_and_detect() result is genuinely readable text
    -- not merely "accepted" (which only requires clearing
    MIN_TEXT_QUALITY), but clean enough that stripping a binary prefix
    down to just this remainder would be a real improvement."""
    return (decoded["type"] in ("json", "text")
            and not _has_control_chars(decoded["pretty"])
            and _ascii_ratio(decoded["pretty"]) >= 0.85)


def _has_control_chars(s):
    """True if s contains any non-whitespace control character -- the
    tell-tale sign of un-decoded binary framing bytes leaking into a
    text preview. (decode_and_detect() already runs sanitize_for_display()
    on its output, so this mainly guards remainder text decoded directly
    here, before any such pass.)"""
    return any(ord(ch) < 0x20 and ch not in "\t\n\r" for ch in s)


def _is_local_storage_key(key_bytes):
    """True for Chromium Local Storage LevelDB keys: data keys (b'_' +
    origin + b'\\x00' + b'\\x01' + key_name), or the b'META:'/
    b'METAACCESS:'/b'VERSION' bookkeeping keys. Used to scope the full-
    text key display below to Local Storage only -- IndexedDB's binary
    KeyPrefix-framed keys must keep going through the existing
    clean_key_display() path untouched."""
    if key_bytes.startswith(b"_") and b"\x00" in key_bytes:
        return True
    if key_bytes.startswith(b"META:") or key_bytes.startswith(b"METAACCESS:"):
        return True
    return key_bytes == b"VERSION"


def _escape_control_chars_for_key(text):
    """Render control characters as visible \\u%04x escapes instead of
    deleting them, so a Local Storage key's full original text --
    including the b'\\x00'/b'\\x01' origin/key-name delimiters the paper
    documents (e.g. _https://www.perplexity.ai\\u0000\\u0001pplx-next-
    auth-session) -- is shown exactly, in full, with nothing stripped
    and nothing restructured."""
    out = []
    for ch in text:
        cp = ord(ch)
        if (cp < 0x20 and ch not in "\t\n\r") or 0x7F <= cp <= 0x9F:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    return "".join(out)


def clean_key_display(key_bytes):
    """Investigator-friendly key text. Many Chromium LevelDB keys --
    IndexedDB records especially -- begin with a few binary framing bytes
    (the KeyPrefix: database/object-store/index ids). decode_and_detect()
    already scores and sanitizes its own output, but a short binary
    prefix glued onto a long clean payload can still drag the *whole*
    key's quality score down, or leave a few non-control "printable-
    looking" high bytes in front of the real content. If the leading
    bytes structurally match the IndexedDB KeyPrefix encoding *and*
    decoding just the remainder is measurably cleaner than decoding the
    whole raw key, this returns the remainder-only decode instead.
    Local Storage keys (_is_local_storage_key()) are shown as their
    complete, unmodified original text -- exactly as documented in the
    paper -- with only the non-printable delimiter bytes rendered
    visibly rather than silently deleted or the key being restructured.
    Otherwise the full-key decode is returned, with a plain "<Binary
    Key: N bytes>" placeholder if no text could be recovered at all.
    Never touches key_hex/key_bytes used for export -- this only
    affects the human-readable preview. Returns (decoded_dict,
    idb_meta_or_None)."""
    if _is_local_storage_key(key_bytes):
        try:
            raw_text = key_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raw_text = key_bytes.decode("latin-1")
        return {
            "type": "text",
            "pretty": _escape_control_chars_for_key(raw_text),
            "hex": key_bytes.hex(),
            "encoding": "text-literal",
        }, None

    decoded_full = decode_and_detect(key_bytes)
    idb_meta = decode_indexeddb_key_prefix(key_bytes)
    chosen = decoded_full

    if idb_meta and idb_meta["remainder"]:
        decoded_rem = decode_and_detect(idb_meta["remainder"])
        if _is_clean_display(decoded_rem) and not _is_clean_display(decoded_full):
            chosen = decoded_rem

    if chosen["type"] == "bytes":
        chosen = dict(chosen)
        chosen["pretty"] = "<Binary Key: %d bytes>" % len(key_bytes)

    return chosen, idb_meta


_MEANINGFUL_RUN_RE = re.compile(r"[ -~]{4,}")


def _looks_meaningless_key(key_text):
    """True when a decoded key carries no readable signal at all -- a
    bare numeric/hex counter literal, our own "<Binary Key: N bytes>"
    placeholder (no text was recoverable at all), or too short/garbled
    to identify what artifact it belongs to."""
    if not key_text:
        return True
    stripped = key_text.strip()
    if not stripped:
        return True
    if stripped.startswith("<Binary Key:"):
        return True
    if re.fullmatch(r"[0-9]+", stripped) or re.fullmatch(r"[0-9a-fA-F]{4,}", stripped):
        return True
    longest_run = max((len(m) for m in _MEANINGFUL_RUN_RE.findall(stripped)), default=0)
    return longest_run < 4


MAX_PLAUSIBLE_TITLE_LEN = 150


def _looks_like_real_title(title):
    """A recognized Comet record matching >=2 structural keys can still
    end up with garbage in its `title` field when the raw-fallback
    extractor (extract_comet_records_raw(), used when a value doesn't
    round-trip through json.loads()) grabs the wrong span of a
    corrupted/garbled value -- e.g. a leaked fragment of citation JSON
    ('"url"...is_focused_web...') or a truncated field label
    ('...backend_'). text_quality() can't tell these apart from a real
    short title (both score as mostly-printable ASCII); what actually
    distinguishes them is that a human-typed title never contains raw
    JSON delimiter characters, while every leaked-JSON-fragment title
    does. A real title is also always short."""
    if not title or not title.strip():
        return False
    if len(title) > MAX_PLAUSIBLE_TITLE_LEN:
        return False
    if title.count('"') >= 2:
        return False
    return True


KNOWN_ARTIFACT_KEY_MARKERS = (
    # Case A1/A2 (Group A, Baseline Usage): user profile, subscription and
    # payment metadata under KeySuffix pplx-next-auth-session; device
    # geolocation under KeySuffix deviceLocation.
    "pplx-next-auth-session", "devicelocation",
    # Case B1 (Group B, Advanced Search): search queries, UUIDs, timestamps
    # and LLM model metadata under KeySuffix last_results; the same content
    # cached in IndexedDB under the pplx-query-cache-* key namespace.
    "last_results", "pplx-query-cache",
)


def is_low_value_record(row):
    """True when a record carries none of the artifact types this tool
    reports on. A record is kept (returns False) when it matches any of:

      - a recognized Comet/Perplexity AI conversation record with a
        plausible, real `title` (Case E1);
      - a recovered HIGH-confidence prompt/response artifact (Case E2);
      - a web-citation / RAG trail (Case E2);
      - a credential-shaped secret (JWT, AWS/OpenAI/GitHub key, bearer
        token, API key) found anywhere in the decoded value;
      - a key matching one of the specific Comet/Perplexity KeySuffixes
        this format is known to use for user profile, geolocation, and
        search/AI metadata (Cases A1/A2/B1) -- checked on the key alone,
        so a *deleted* record under one of these keys still surfaces
        (Case D1: interface-level deletion does not remove the
        underlying LevelDB record);
      - any decodable (non-binary) record whose IndexedDB/Local Storage
        origin belongs to a known communication platform such as
        WhatsApp Web or Telegram Web (Cases C1/C2).

    Generic JSON/TEXT/V8/BINARY records that match none of the above
    (feature-flag blobs, analytics IDs, UI cache entries, etc.) are
    dropped -- not because they have no forensic value in general, but
    because they fall outside the artifact taxonomy this tool reports
    on."""
    comet_records = row.get("comet_records") or []
    if any(_looks_like_real_title(c.get("title")) for c in comet_records):
        return False

    if row.get("prompt_artifacts"):
        return False

    citation_pipeline = row.get("citation_pipeline") or {}
    if citation_pipeline.get("citations"):
        return False

    iocs = row.get("iocs") or {}
    if any(iocs.get(k) for k in ("jwt", "aws_key", "openai_key", "github_token", "bearer_token", "api_key")):
        return False

    # Key-name matches only count when there's either a real decoded value
    # to show (JSON/TEXT/kv -- not an opaque V8/protobuf blob that merely
    # happens to sit under the same key namespace) or the record is a
    # TOMBSTONE (no value at all, but its *absence* is itself the evidence
    # for Case D1 -- deletion via the browser UI leaving the LevelDB record
    # behind).
    key_text = (row.get("key_pretty") or "").lower()
    has_decoded_value = row.get("value_type") in ("json", "text", "kv")
    if any(marker in key_text for marker in KNOWN_ARTIFACT_KEY_MARKERS):
        if row.get("state") == "TOMBSTONE" or has_decoded_value:
            return False

    origin = (row.get("origin") or "").lower()
    if any(platform in origin for platform in ("whatsapp", "telegram")) and has_decoded_value:
        return False

    return True


def classify_value_type_label(state, decoded_value, comet_records, v8_info, citation_pipeline=None):
    """Collapse the internal decode result into one short, investigator-
    friendly label for the results table -- pruned to only the labels
    that describe genuinely distinct, meaningful content:
    JSON / TEXT / V8 / COMET / TOMBSTONE / BINARY. IndexedDB-ness and
    UTF-16-vs-other-encoding are source/decode-method details (still
    tracked internally and in CSV export), not distinct content types,
    so they no longer override the real classification here. Only
    meaningful, high-confidence results are labeled as such -- anything
    that doesn't clear decode_and_detect()'s quality bar (or a
    recognized structured decoder) is reported plainly as BINARY rather
    than guessed at."""
    if state == "TOMBSTONE":
        return "TOMBSTONE"
    if comet_records:
        return "COMET"
    if citation_pipeline and citation_pipeline.get("citations"):
        return "CITATIONS"
    if v8_info and v8_info.get("items"):
        return "V8"
    vtype = decoded_value.get("type")
    if vtype == "json":
        return "JSON"
    if vtype == "text":
        return "TEXT"
    return "BINARY"


def _short_preview(text, limit=140):
    if not text:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _format_binary_summary(n_bytes, iocs):
    """Clean stand-in for a raw hex dump when a value carries no
    decodable text. No evidence is lost -- the full bytes remain in
    value_hex (CSV) and behind the explicit 'Show as: Hex' view mode
    (GUI) -- this only stops a multi-hundred-character hex blob from
    being presented as if it were the meaningful content of the row.
    A pure-BINARY record is only ever kept at all because it yielded an
    IOC hit (see is_low_value_record()), so that IOC -- not the hex --
    is the actual reason this row is forensically relevant, and is
    surfaced here instead."""
    summary = "<Binary: %s bytes -- no decodable text>" % format(n_bytes, ",")
    if iocs:
        parts = []
        for k, vals in iocs.items():
            shown = "; ".join(vals[:3]) + (", ..." if len(vals) > 3 else "")
            parts.append("%s: %s" % (k, shown))
        summary = "<Binary: %s bytes -- IOC hit(s) -- %s>" % (format(n_bytes, ","), " | ".join(parts))
    return summary


def build_value_preview(state, value_type_label, decoded_value, value_bytes,
                         comet_records=None, prompt_artifacts=None, citation_pipeline=None, iocs=None):
    """Short, single-line preview for the results table (item 17) -- never
    the full value, and consistent placeholders for special states. A
    confidently recovered user prompt takes priority over the generic
    preview (still no new columns -- this reuses the existing Value
    Preview cell)."""
    if state == "TOMBSTONE":
        return "<Deleted / Tombstone>"
    best_prompt = best_prompt_for_preview(prompt_artifacts)
    if best_prompt:
        return "%s: %s" % (classify_prompt_artifact(best_prompt), _short_preview(best_prompt.text, 125))
    if value_type_label == "CITATIONS" and citation_pipeline:
        cites = citation_pipeline.get("citations") or []
        domains = []
        for c in cites:
            d = c.citation_domain_name or c.domain_name
            if d and d not in domains:
                domains.append(d)
        dom_str = ", ".join(domains[:4]) + (", ..." if len(domains) > 4 else "")
        return "%d web citations (%s)" % (len(cites), dom_str)
    if value_type_label == "COMET" and comet_records:
        first = comet_records[0]
        text = (first.get("title") or first.get("task_description")
                or first.get("answer_preview") or "AI Conversation")
        suffix = " (+%d more)" % (len(comet_records) - 1) if len(comet_records) > 1 else ""
        return _short_preview(text, 130) + suffix
    if value_type_label == "BINARY":
        n = len(value_bytes) if value_bytes else 0
        return _format_binary_summary(n, iocs)
    return _short_preview(decoded_value.get("pretty", ""), 140)


def format_v8_display(v8_info):
    lines = ["[V8/Blink Structured Value -- %s]" % v8_info["status"]]
    for i, it in enumerate(v8_info["items"]):
        lines.append("  [%d] %r" % (i, it))
    if v8_info.get("leftover_hex"):
        lines.append("  (undecoded remainder: %d bytes)" % (len(v8_info["leftover_hex"]) // 2))
    return "\n".join(lines)


def best_value_display(row):
    """Auto-mode value display, in forensic priority order (item 15):
    IndexedDB structured -> V8/Blink -> Comet structured -> JSON -> text
    -> hex. Tombstones show a plain placeholder instead of an empty box."""
    if row["state"] == "TOMBSTONE":
        return ("<Deleted / Tombstone>\n\n"
                "No value is stored for this record -- it was removed by a "
                "LevelDB delete operation (sequence %s)." % row.get("sequence_number"))

    comet_block = format_comet_records_block(row.get("comet_records"))
    v8_info = row.get("v8_info")
    idb_meta = row.get("idb_meta")

    body = None
    if comet_block:
        body = comet_block
    elif v8_info and v8_info.get("items"):
        body = format_v8_display(v8_info)
    elif row["value_type"] == "json":
        body = row["value_pretty"]
    elif row["value_type"] == "text":
        body = row["value_pretty"]
    elif row["value_hex"]:
        # No decodable text and nothing structured -- show a clean
        # summary (with any IOC hit that's the actual reason this row
        # survived is_low_value_record()) instead of a raw hex dump.
        # The full hex is still one click away via "Show as: Hex".
        body = _format_binary_summary(len(row["value_hex"]) // 2, row.get("iocs"))
    else:
        body = "(empty value)"

    if idb_meta and idb_meta.get("record_type"):
        header = ("[Chromium IndexedDB -- %s]  DB:%s  ObjectStore:%s  Index:%s\n"
                  % (idb_meta["record_type"], idb_meta["database_id"],
                     idb_meta["object_store_id"], idb_meta["index_id"]))
        body = header + "\n" + body

    prompt_block = format_prompt_artifacts_block(row.get("prompt_artifacts"))
    citation_block = format_web_citation_trail_block(row.get("citation_pipeline"))
    extra_blocks = [b for b in (prompt_block, citation_block) if b]
    if extra_blocks:
        return ("\n\n" + "=" * 60 + "\n\n").join(extra_blocks) + "\n\n" + "=" * 60 + "\n\n" + body
    return body


# ============================================================================
# CORE ENGINE ENTRY POINT -- stdlib only, no GUI toolkit involved.
#
# process_databases() is the single code path that turns a list of
# discovered database dicts (discover_leveldb_databases()) into forensic
# output rows: it runs read_leveldb_directory() + the full decode/
# extraction pipeline (Comet records, prompt/response artifacts, web
# citation trails, IOCs, timeline classification) exactly once per
# record. Both the CLI (run_cli(), below) and the optional PyQt5 GUI's
# ScanWorker call this same generator, so the two front-ends can never
# disagree about what a "record" is.
# ============================================================================

def process_databases(databases, prefix=None, key_q=None, limit=None, stop_check=None):
    """Yield one forensic row dict per surfaced record across every
    database in `databases`. `prefix`/`key_q` filter on the raw user-key
    bytes; `limit` caps the number of surfaced (post-filter) records;
    `stop_check` is an optional zero-arg callable polled between records
    so a long scan can be cancelled cooperatively."""
    count = 0
    for db in databases:
        if stop_check and stop_check():
            return
        db_path = db["path"]
        is_idb = db.get("is_indexeddb", False)
        db_origin = db.get("origin")

        records, diagnostics = read_leveldb_directory(db_path)
        records = dedupe_identical_records(records)

        for fr in records:
            if stop_check and stop_check():
                return
            key_bytes = fr.user_key if fr.user_key is not None else fr.key
            if prefix and not key_bytes.startswith(prefix):
                continue
            if key_q and key_q not in key_bytes:
                continue
            decoded_key, key_idb_meta = clean_key_display(key_bytes)
            key_text = decoded_key["pretty"]
            # Classification (INDEXEDDB label / object_store field) stays
            # gated on directory-name detection to avoid false positives
            # on ordinary LevelDB data; the display cleanup above is
            # self-gated (only kicks in when it measurably helps) and
            # applies regardless of that detection.
            idb_meta = key_idb_meta if is_idb else None

            if fr.state == "TOMBSTONE" or fr.value is None:
                value_text = ""
                scan_text = ""
                decoded_value = {"type": "missing", "pretty": "", "hex": "", "encoding": ""}
                v8_info = None
            else:
                decoded_value, v8_info = decode_value_pipeline(
                    fr.value, is_indexeddb=is_idb,
                    idb_record_type=idb_meta["record_type"] if idb_meta else None)
                value_text = decoded_value["pretty"]
                # decode_and_detect() correctly refuses to call a value
                # "text" once its quality score is too low -- but Comet/
                # Perplexity values are frequently a genuine MIX of real
                # field data and V8/Blink framing bytes that legitimately
                # fails that bar as a whole. extract_comet_records_raw()
                # (and the IOC/timestamp regexes) are built to tolerate
                # exactly that noise, so give them a lenient best-effort
                # decode to scan -- the strict decoded_value above is
                # still what's shown as Value Type / Value Preview.
                scan_text = (value_text if decoded_value["type"] != "bytes"
                             else decode_best_effort_text(fr.value))

            comet_records = extract_comet_objects(scan_text)
            citation_pipeline = extract_web_citations(scan_text)
            timeline_events = build_timeline_events(
                key_text, scan_text, key_bytes,
                deleted=(fr.state == "TOMBSTONE"), comet_records=comet_records)
            first_ev = timeline_events[0] if timeline_events else None
            for ev in timeline_events:
                ev.source_file = fr.source_file
                ev.raw_offset = fr.physical_offset
                ev.sequence_number = fr.sequence_number
                ev.database = os.path.basename(db_path)
                ev.object_store = idb_meta["record_type"] if idb_meta else ""

            iocs = extract_iocs(scan_text)
            jwt_data = decode_jwt(iocs["jwt"][0]) if iocs.get("jwt") else None

            # ---- Prompt recovery: structural first, raw fallback last ----
            value_obj = None
            if decoded_value.get("type") == "json":
                try:
                    value_obj = json.loads(decoded_value["pretty"])
                except Exception:
                    value_obj = None
            if value_obj is None and scan_text:
                try:
                    value_obj = json.loads(scan_text)
                except Exception:
                    value_obj = None
            prompt_artifacts = extract_prompt_artifacts(
                value_obj, value_text=scan_text, comet_records=comet_records,
                key_text=key_text)
            top_conversation_uuid = (comet_records[0].get("uuid") if comet_records
                                      else (first_ev.conversation_id if first_ev else None)) or None
            top_context_uuid = (comet_records[0].get("context_uuid") if comet_records
                                else (first_ev.context_uuid if first_ev else None)) or None
            top_timestamp = (first_ev.timestamp_utc.isoformat()
                              if first_ev and first_ev.timestamp_utc else None)
            associate_prompt_context(
                prompt_artifacts, conversation_uuid=top_conversation_uuid,
                context_uuid=top_context_uuid, timestamp=top_timestamp,
                source_file=fr.source_file, source_offset=fr.physical_offset,
                sequence_number=fr.sequence_number, record_state=fr.state)
            prompt_artifacts = deduplicate_prompt_artifacts(prompt_artifacts)
            # Output-quality filter (additive -- extraction above is
            # untouched and still computes every confidence tier):
            # only HIGH-confidence prompt/response artifacts are
            # surfaced to the table/preview/CSV. This drops
            # MEDIUM (e.g. task_description with no role marker)
            # and LOW (POSSIBLE_PROMPT raw-fallback guesses) --
            # if that was the ONLY signal on a record, the record
            # itself now falls out via the existing
            # is_low_value_record() check below, exactly as if it
            # had never carried a prompt artifact at all.
            prompt_artifacts = [a for a in prompt_artifacts if a.confidence == "HIGH"]

            value_type_label = classify_value_type_label(
                fr.state, decoded_value, comet_records, v8_info, citation_pipeline)
            value_preview = build_value_preview(
                fr.state, value_type_label, decoded_value, fr.value,
                comet_records, prompt_artifacts, citation_pipeline, iocs)

            # Structured extraction (a recognized Comet conversation record,
            # a recovered prompt/response, or a web-citation trail) always
            # wins the category label over the generic keyword scan below --
            # otherwise a conversation whose title/prompt text happens to
            # literally contain a keyword like "telegram" mislabels an AI
            # Conversations record as Communication Platform.
            if comet_records or prompt_artifacts:
                artifact_category = "AI Conversations"
            elif (citation_pipeline or {}).get("citations"):
                artifact_category = "AI Conversations"
            else:
                artifact_category = classify_artifact(key_text, scan_text)

            row = {
                "state": fr.state,
                "database": os.path.basename(db_path),
                "database_path": db_path,
                "is_indexeddb": is_idb,
                "origin": db_origin or storage_origin(key_bytes),
                "artifact_category": artifact_category,
                "object_store": idb_meta["record_type"] if idb_meta else "",
                "idb_meta": idb_meta,
                "v8_info": v8_info,
                "key_hex": key_bytes.hex(),
                "key_pretty": key_text,
                "key_type": decoded_key["type"],
                "key_enc": decoded_key["encoding"],
                "value_hex": (fr.value or b"").hex(),
                "value_pretty": value_text,
                "value_type": decoded_value["type"],
                "value_enc": decoded_value.get("encoding", ""),
                "value_type_label": value_type_label,
                "value_preview": value_preview,
                "iocs": iocs,
                "jwt_data": jwt_data,
                "timeline_event": first_ev,
                "comet_records": comet_records,
                "citation_pipeline": citation_pipeline,
                "prompt_artifacts": prompt_artifacts,
                "sequence_number": fr.sequence_number,
                "source_file": fr.source_file,
                "source_type": fr.source_type,
                "physical_offset": fr.physical_offset,
                "recovery_method": fr.recovery_method,
                "confidence": fr.confidence,
            }
            # is_low_value_record() is only applied to IndexedDB records --
            # an IndexedDB LevelDB store is dominated by internal backing-
            # store/index bookkeeping entries (btree nodes, blob metadata,
            # etc.) that aren't meaningful key-value artifacts on their own,
            # so it narrows the output to what's forensically reportable.
            # Local Storage records are comparatively few and every one of
            # them IS a real, named application key-value pair (see
            # storage_origin()/the "_origin\x00key" format) -- filtering
            # those the same way would hide genuinely parsed artifacts from
            # a reviewer and make the tool look narrower than it is, so
            # every Local Storage record that was actually parsed is always
            # surfaced.
            if is_idb and is_low_value_record(row):
                continue
            yield row
            count += 1
            if limit and count >= limit:
                return


def write_forensic_csv(rows, outpath):
    """Write `rows` (as produced by process_databases()) to a forensic
    CSV report at `outpath`. Fans out one row per recovered prompt/
    response artifact (so multi-turn conversation records keep full
    per-artifact provenance), then collapses rows that are genuinely
    the same physical LevelDB key rewritten with byte-identical decoded
    content (e.g. a cached conversation re-saved dozens of times) --
    nothing is discarded, the collapsed occurrence count and the
    sequence-number span of every rewrite are preserved as columns.
    Rows with different keys, or the same key but different content,
    are never merged. Returns (rows_written, physical_rows, records_scanned)."""
    pending = []  # list of (fingerprint, row_values, sequence_number)

    def _add(row_values, prompt_text, response_text, key_hex, seq):
        fp = (key_hex, (prompt_text or "").strip(), (response_text or "").strip())
        pending.append((fp, row_values, seq))

    for r in rows:
        ev = r.get("timeline_event")
        off = r.get("physical_offset")
        key_hex = r.get("key_hex", "")
        seq = r.get("sequence_number")

        display_key = r.get("key_pretty", "")
        if _looks_meaningless_key(display_key):
            display_key = "%s [key:%s seq:%s]" % (display_key, key_hex[:16], seq)

        if r.get("value_type_label") == "BINARY":
            display_value = _format_binary_summary(
                len(r.get("value_hex", "")) // 2, r.get("iocs"))
        else:
            display_value = r.get("value_pretty", "")[:2000]

        base = [
            display_key, r.get("value_type_label", ""),
            display_value, r.get("origin", ""), r.get("artifact_category", ""),
            r.get("database", ""), r.get("object_store", ""),
            seq, r.get("state", ""),
            r.get("source_file", ""), ("0x%x" % off) if off is not None else "",
            r.get("recovery_method", ""), r.get("confidence", ""),
            r.get("key_enc", ""), r.get("value_enc", ""),
        ]
        citation_pipeline = r.get("citation_pipeline") or {}
        cites = citation_pipeline.get("citations") or []
        citation_domains = "; ".join(sorted({
            (c.citation_domain_name or c.domain_name) for c in cites
            if (c.citation_domain_name or c.domain_name)
        }))
        citation_urls = "; ".join(c.url for c in cites if c.url)[:2000]
        backend_queries = citation_pipeline.get("backend_queries") or []
        backend_query = backend_queries[0].get("query", "") if backend_queries else ""

        tail = [key_hex, r.get("value_hex", "")[:4000],
                len(cites), citation_domains, citation_urls, backend_query]

        prompt_artifacts = r.get("prompt_artifacts") or []
        prompts = [a for a in prompt_artifacts if a.artifact_type != "ASSISTANT_RESPONSE"]
        responses = [a for a in prompt_artifacts if a.artifact_type == "ASSISTANT_RESPONSE"]

        if prompts or responses:
            pairs = associate_response(prompts, responses) if prompts else []
            paired_ids = {id(resp) for _, resp in pairs if resp is not None}
            for prompt_a, response_a in pairs:
                row_values = base + [
                    prompt_a.artifact_type, prompt_a.text,
                    response_a.text if response_a else "",
                    prompt_a.conversation_uuid or "", prompt_a.context_uuid or "",
                    prompt_a.timestamp or "", prompt_a.confidence, prompt_a.recovery_method,
                ] + tail
                _add(row_values, prompt_a.text, response_a.text if response_a else "", key_hex, seq)
            for resp_a in responses:
                if id(resp_a) in paired_ids:
                    continue
                row_values = base + [
                    resp_a.artifact_type, "", resp_a.text,
                    resp_a.conversation_uuid or "", resp_a.context_uuid or "",
                    resp_a.timestamp or "", resp_a.confidence, resp_a.recovery_method,
                ] + tail
                _add(row_values, "", resp_a.text, key_hex, seq)
        else:
            row_values = base + [
                "", ev.prompt if ev else "", ev.response if ev else "",
                ev.conversation_id if ev else "", ev.context_uuid if ev else "",
                "", "", "",
            ] + tail
            _add(row_values, ev.prompt if ev else "", ev.response if ev else "", key_hex, seq)

    physical_rows = len(pending)

    groups = {}
    order = []
    for fp, row_values, seq in pending:
        if fp not in groups:
            groups[fp] = {"row": row_values, "count": 0, "min_seq": seq, "max_seq": seq}
            order.append(fp)
        g = groups[fp]
        g["count"] += 1
        if seq is not None and (g["min_seq"] is None or seq < g["min_seq"]):
            g["min_seq"] = seq
        if seq is not None and (g["max_seq"] is None or seq > g["max_seq"]):
            g["max_seq"] = seq

    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "display_key", "value_type", "display_value", "origin", "artifact_category",
            "database", "object_store",
            "sequence_number", "record_state", "source_file", "source_offset",
            "recovery_method", "confidence", "key_decode_method", "value_decode_method",
            "artifact_type", "prompt", "response", "conversation_uuid", "context_uuid",
            "timestamp", "prompt_confidence", "prompt_recovery_method",
            "key_hex", "value_hex",
            "citation_count", "citation_domains", "citation_urls", "backend_search_query",
            "occurrence_count", "sequence_range",
        ])
        for fp in order:
            g = groups[fp]
            seq_range = ("%s-%s" % (g["min_seq"], g["max_seq"])
                         if g["min_seq"] != g["max_seq"] else str(g["min_seq"]))
            w.writerow(g["row"] + [g["count"], seq_range])

    return len(order), physical_rows, len(rows)


# ============================================================================
# PyQt5 GUI -- optional. process_databases() above is the entire forensic
# engine and has no Qt dependency; this section only exists to give it an
# interactive front-end when PyQt5 happens to be installed. The CLI
# (run_cli(), further down) is the dependency-free default entry point.
# ============================================================================

if HAVE_QT:
    class ScanWorker(QThread):
        """Thin QThread wrapper around process_databases() so a scan runs
        on a background thread and the GUI never freezes."""
        batch = pyqtSignal(list)
        progress = pyqtSignal(int)
        done = pyqtSignal(int)
        failed = pyqtSignal(str)

        def __init__(self, databases, prefix, key_q, limit):
            super().__init__()
            self.databases = databases          # list of dicts from discover_leveldb_databases
            self.prefix = prefix
            self.key_q = key_q
            self.limit = limit
            self._stop = False

        def stop(self):
            self._stop = True

        def run(self):
            try:
                rows = []
                count = 0
                for row in process_databases(self.databases, self.prefix, self.key_q,
                                              self.limit, stop_check=lambda: self._stop):
                    rows.append(row)
                    count += 1
                    if len(rows) >= 200:
                        self.batch.emit(rows)
                        self.progress.emit(count)
                        rows = []
                if rows:
                    self.batch.emit(rows)
                self.done.emit(count)
            except Exception as e:
                self.failed.emit("%s\n%s" % (e, traceback.format_exc()))

    class KVTableModel(QAbstractTableModel):
        HEADERS = ["Key", "Value Type", "Value Preview"]

        def __init__(self, parent=None):
            super().__init__(parent)
            self.rows = []

        def rowCount(self, parent=QModelIndex()):
            return len(self.rows)

        def columnCount(self, parent=QModelIndex()):
            return len(self.HEADERS)

        def data(self, index, role=Qt.DisplayRole):
            if not index.isValid():
                return None
            row = self.rows[index.row()]
            col = index.column()
            if role == Qt.DisplayRole:
                if col == 0:
                    s = row.get("key_pretty") or ""
                    return s if len(s) <= 80 else s[:77] + "..."
                elif col == 1:
                    return row.get("value_type_label", "")
                elif col == 2:
                    return row.get("value_preview", "")
            elif role == Qt.ForegroundRole and col == 1:
                if row.get("value_type_label", "") == "TOMBSTONE":
                    return QColor(178, 34, 34)
            return None

        def headerData(self, section, orientation, role=Qt.DisplayRole):
            if role != Qt.DisplayRole:
                return None
            if orientation == Qt.Horizontal:
                return self.HEADERS[section] if section < len(self.HEADERS) else ""
            return None

        def append_rows(self, new_rows):
            if not new_rows:
                return
            start = len(self.rows)
            self.beginInsertRows(QModelIndex(), start, start + len(new_rows) - 1)
            self.rows.extend(new_rows)
            self.endInsertRows()

        def clear(self):
            self.beginResetModel()
            self.rows = []
            self.endResetModel()

    class MainWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("LevelDBParser")
            self.resize(1100, 700)
            self.setFont(QFont("Segoe UI", 9))
            self.db_path = None
            self.databases = []
            self.tmp_dir = None
            self.worker = None

            self.init_ui()

        def init_ui(self):
            layout = QVBoxLayout(self)

            # -- Toolbar: Open Folder | Open Zip | Stop Scan | Export CSV --
            toolbar = QToolBar()
            open_folder_act = QAction("Open Folder", self)
            open_folder_act.triggered.connect(self.on_open_folder)
            toolbar.addAction(open_folder_act)

            open_zip_act = QAction("Open Zip", self)
            open_zip_act.triggered.connect(self.on_open_zip)
            toolbar.addAction(open_zip_act)

            stop_act = QAction("Stop Scan", self)
            stop_act.triggered.connect(self.on_stop_scan)
            toolbar.addAction(stop_act)

            export_act = QAction("Export CSV", self)
            export_act.triggered.connect(self.on_export_csv)
            toolbar.addAction(export_act)

            layout.addWidget(toolbar)

            # -- Filter / scan row --
            ctrl_layout = QHBoxLayout()
            ctrl_layout.addWidget(QLabel("DB Path:"))
            self.path_edit = QLineEdit()
            self.path_edit.setReadOnly(True)
            ctrl_layout.addWidget(self.path_edit)

            ctrl_layout.addWidget(QLabel("Prefix:"))
            self.prefix_edit = QLineEdit()
            self.prefix_edit.setMaximumWidth(150)
            ctrl_layout.addWidget(self.prefix_edit)

            ctrl_layout.addWidget(QLabel("Search (in key):"))
            self.search_edit = QLineEdit()
            self.search_edit.setMaximumWidth(200)
            ctrl_layout.addWidget(self.search_edit)

            ctrl_layout.addWidget(QLabel("Limit rows:"))
            self.limit_spin = QSpinBox()
            self.limit_spin.setMinimum(10)
            self.limit_spin.setMaximum(5_000_000)
            self.limit_spin.setValue(1000)
            ctrl_layout.addWidget(self.limit_spin)

            self.start_btn = QPushButton("Start Scan")
            self.start_btn.clicked.connect(self.on_start_scan)
            ctrl_layout.addWidget(self.start_btn)

            layout.addLayout(ctrl_layout)

            # -- Main splitter: results table (left) / key+value (right) --
            main_split = QSplitter(Qt.Horizontal)

            self.table_model = KVTableModel()
            self.table_view = QTableView()
            self.table_view.setModel(self.table_model)
            self.table_view.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            self.table_view.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.table_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
            self.table_view.clicked.connect(self.on_table_clicked)
            main_split.addWidget(self.table_view)

            right_split = QSplitter(Qt.Vertical)

            key_wrap = QWidget()
            key_layout = QVBoxLayout(key_wrap)
            key_layout.setContentsMargins(0, 0, 0, 0)
            key_layout.addWidget(QLabel("Selected Key"))
            self.key_view = QPlainTextEdit()
            self.key_view.setReadOnly(True)
            key_layout.addWidget(self.key_view)
            right_split.addWidget(key_wrap)

            value_wrap = QWidget()
            value_layout = QVBoxLayout(value_wrap)
            value_layout.setContentsMargins(0, 0, 0, 0)
            value_layout.addWidget(QLabel("Selected Value"))
            self.value_view = QPlainTextEdit()
            self.value_view.setReadOnly(True)
            value_layout.addWidget(self.value_view)

            decode_layout = QHBoxLayout()
            decode_layout.addStretch(1)
            decode_layout.addWidget(QLabel("Show as:"))
            self.view_combo = QComboBox()
            self.view_combo.addItems(["Auto", "Text", "JSON", "Hex"])
            self.view_combo.currentIndexChanged.connect(self.on_view_mode_change)
            decode_layout.addWidget(self.view_combo)
            value_layout.addLayout(decode_layout)
            right_split.addWidget(value_wrap)

            right_split.setSizes([250, 350])
            main_split.addWidget(right_split)
            main_split.setSizes([660, 440])

            layout.addWidget(main_split, 1)

            # -- Status row --
            status_layout = QHBoxLayout()
            self.progress = QProgressBar()
            self.progress.setMaximumWidth(160)
            self.progress.setRange(0, 0)
            self.progress.setVisible(False)
            status_layout.addWidget(self.progress)

            self.status_label = QLabel("Idle")
            status_layout.addWidget(self.status_label, 1)

            layout.addLayout(status_layout)

        def status(self, msg):
            self.status_label.setText(msg)

        # -----------------------------------------------------------
        # Evidence selection
        # -----------------------------------------------------------
        def on_open_folder(self):
            path = QFileDialog.getExistingDirectory(self, "Select evidence folder")
            if path:
                self._set_db(path)

        def on_open_zip(self):
            path, _ = QFileDialog.getOpenFileName(self, "Open evidence zip", filter="Zip files (*.zip)")
            if not path:
                return
            self._cleanup_tmp()
            self.tmp_dir = tempfile.mkdtemp(prefix="leveldb_forensic_")
            try:
                extracted, rejected = safe_extract_zip(path, self.tmp_dir)
            except Exception as e:
                QMessageBox.critical(self, "Error", "Failed to extract zip: %s" % e)
                return
            if rejected:
                QMessageBox.warning(self, "Unsafe entries skipped",
                                     "%d zip entries were rejected (path traversal / absolute paths)."
                                     % len(rejected))
            self._set_db(self.tmp_dir)

        def _set_db(self, path):
            self.db_path = path
            self.path_edit.setText(path)
            found = discover_leveldb_databases(path)
            if not found:
                found = [{"path": path, "is_indexeddb": False, "origin": None,
                          "ldb_count": 0, "sst_count": 0, "log_count": 0}]
            self.databases = found
            idb_count = sum(1 for d in found if d["is_indexeddb"])
            if idb_count:
                self.status("DB selected -- %d database(s) found (%d IndexedDB)" % (len(found), idb_count))
            else:
                self.status("DB selected -- %d database(s) found" % len(found))

        # -----------------------------------------------------------
        # Scan control (Start Scan automatically applies LevelDB /
        # IndexedDB / Comet parsing layers as appropriate -- no manual
        # parser selection is exposed)
        # -----------------------------------------------------------
        def on_start_scan(self):
            if not self.databases:
                QMessageBox.warning(self, "No DB", "Please open a LevelDB folder or zip first")
                return
            if self.worker and self.worker.isRunning():
                QMessageBox.warning(self, "Busy", "Scan already running")
                return

            prefix_text = self.prefix_edit.text().strip()
            prefix_bytes = None
            if prefix_text:
                s = prefix_text
                if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
                    try:
                        prefix_bytes = bytes.fromhex(s)
                    except Exception:
                        prefix_bytes = s.encode()
                else:
                    prefix_bytes = prefix_text.encode()

            search_text = self.search_edit.text().strip()
            search_bytes = search_text.encode() if search_text else None

            limit = self.limit_spin.value()

            self.table_model.clear()
            self.key_view.clear()
            self.value_view.clear()

            self.worker = ScanWorker(self.databases, prefix_bytes, search_bytes, limit)
            self.worker.batch.connect(self.table_model.append_rows)
            self.worker.progress.connect(self.on_progress)
            self.worker.done.connect(self.on_finished)
            self.worker.failed.connect(self.on_error)
            self.progress.setVisible(True)
            self.progress.setRange(0, 0)
            self.status("Scanning...")
            self.worker.start()

        def on_stop_scan(self):
            if self.worker and self.worker.isRunning():
                self.worker.stop()
                self.status("Stopping...")

        def on_progress(self, matched):
            self.status("Records: %s" % format(matched, ","))

        def on_finished(self, total):
            self.progress.setVisible(False)
            self.progress.setRange(0, 100)
            self.status("Scan complete: %s records" % format(total, ","))

        def on_error(self, msg):
            QMessageBox.critical(self, "Error", msg)
            self.progress.setVisible(False)
            self.status("Error")

        # -----------------------------------------------------------
        # Export CSV -- the only export in the UI, but comprehensive
        # (item 23): everything computed by the backend is included.
        # -----------------------------------------------------------
        def on_export_csv(self):
            if not self.table_model.rows:
                QMessageBox.information(self, "No data", "No rows to export. Run a scan first.")
                return
            outpath, _ = QFileDialog.getSaveFileName(self, "Save CSV", filter="CSV files (*.csv)")
            if not outpath:
                return
            try:
                written, physical_rows, total = write_forensic_csv(self.table_model.rows, outpath)
                QMessageBox.information(
                    self, "Saved",
                    "CSV saved to %s\n%d rows written (collapsed from %d physical rewrites; "
                    "%d records scanned)."
                    % (outpath, written, physical_rows, total))
            except Exception as e:
                QMessageBox.critical(self, "Error", "Failed to save CSV: %s" % e)

        # -----------------------------------------------------------
        # Selection panel
        # -----------------------------------------------------------
        def on_table_clicked(self, index: QModelIndex):
            r = index.row()
            if r < 0 or r >= len(self.table_model.rows):
                return
            row = self.table_model.rows[r]
            self.key_view.setPlainText(row.get("key_pretty") or "")
            self._render_value(row)

        def on_view_mode_change(self, _idx):
            sel = self.table_view.selectionModel().currentIndex()
            if sel.isValid():
                self.on_table_clicked(sel)

        def _render_value(self, row):
            mode = self.view_combo.currentText()
            if mode == "Hex":
                text = hexdump(row["value_hex"]) if row["value_hex"] else "(empty value)"
            elif mode == "JSON":
                if row["value_type"] == "json":
                    text = row["value_pretty"]
                else:
                    comet_block = format_comet_records_block(row.get("comet_records"))
                    text = comet_block if comet_block else "(value is not JSON)"
            elif mode == "Text":
                comet_block = format_comet_records_block(row.get("comet_records"))
                text = comet_block if comet_block else (row["value_pretty"] or "(value is not text)")
            else:  # Auto
                text = best_value_display(row)
            self.value_view.setPlainText(text or "")

        def _cleanup_tmp(self):
            if self.tmp_dir and os.path.isdir(self.tmp_dir):
                try:
                    shutil.rmtree(self.tmp_dir, ignore_errors=True)
                except Exception:
                    pass
            self.tmp_dir = None

        def closeEvent(self, event):
            if self.worker and self.worker.isRunning():
                self.worker.stop()
                self.worker.wait(2000)
            self._cleanup_tmp()
            event.accept()

    def _apply_light(app):
        app.setStyle("Fusion")
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor(240, 240, 240))
        pal.setColor(QPalette.WindowText, QColor(0, 0, 0))
        pal.setColor(QPalette.Base, QColor(255, 255, 255))
        pal.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
        pal.setColor(QPalette.Text, QColor(0, 0, 0))
        pal.setColor(QPalette.Button, QColor(240, 240, 240))
        pal.setColor(QPalette.ButtonText, QColor(0, 0, 0))
        pal.setColor(QPalette.Highlight, QColor(0, 120, 215))
        pal.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        app.setPalette(pal)
        app.setFont(QFont("Segoe UI", 9))


# ============================================================================
# CLI -- the dependency-free default entry point. Point it at one or more
# evidence folders (a single LevelDB/IndexedDB directory, or a parent
# folder containing several -- searched recursively by
# discover_leveldb_databases()) and it runs the exact same engine
# (process_databases / write_forensic_csv) the optional GUI uses, with
# zero third-party imports required.
# ============================================================================

def _parse_prefix_arg(s):
    if not s:
        return None
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except Exception:
            return s.encode("utf-8")
    return s.encode("utf-8")


def run_cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="leveldb_parser.py",
        description="Dependency-free forensic parser for Chromium LevelDB "
                     "(Local Storage) and IndexedDB LevelDB databases -- "
                     "Comet/Perplexity artifact extraction. Pure standard-"
                     "library Python: no plyvel, no python-leveldb, no "
                     "leveldb-tools, no python-snappy, no WSL required.")
    ap.add_argument("paths", nargs="*",
                     help="One or more evidence folders: a LevelDB directory "
                          "itself (e.g. a 'Local Storage/leveldb' folder or an "
                          "'...indexeddb.leveldb' folder), or a parent folder "
                          "containing several such directories -- searched "
                          "recursively. Local Storage and IndexedDB databases "
                          "can be freely mixed in one invocation. With no "
                          "--cli flag, the first path (if any) is preloaded "
                          "into the GUI.")
    ap.add_argument("-o", "--out", default=None,
                     help="Output CSV path (default: "
                          "leveldb_forensic_report_<timestamp>.csv in the "
                          "current directory)")
    ap.add_argument("--prefix", default="",
                     help="Only include records whose raw key starts with this "
                          "(hex bytes if it looks like an even-length hex "
                          "string, otherwise treated as UTF-8 text)")
    ap.add_argument("--search", default="",
                     help="Only include records whose raw key contains this "
                          "substring (hex or text, same rule as --prefix)")
    ap.add_argument("--limit", type=int, default=0,
                     help="Stop after N surfaced records (0 = no limit)")
    ap.add_argument("--hashes", action="store_true",
                     help="Also write a SHA-256 evidence manifest CSV "
                          "(chain-of-custody) alongside the report")
    ap.add_argument("--cli", action="store_true",
                     help="Run a headless scan and write a CSV report instead "
                          "of launching the GUI (requires at least one path). "
                          "Without this flag the PyQt5 GUI launches -- same as "
                          "running this script with no arguments.")
    args = ap.parse_args(argv)

    if not args.cli:
        if not HAVE_QT:
            print("PyQt5 is not installed -- install it with `pip install PyQt5` "
                  "to run the GUI.\n(The parsing engine itself has no "
                  "dependency on PyQt5 -- pass --cli to run a headless scan "
                  "instead.)")
            return 2
        app = QApplication(sys.argv[:1])
        _apply_light(app)
        win = MainWindow()
        win.show()
        if args.paths:
            win._set_db(args.paths[0])
        return app.exec_()

    if not args.paths:
        print("--cli requires at least one evidence path.", file=sys.stderr)
        return 1

    databases = []
    seen = set()
    for p in args.paths:
        if not os.path.isdir(p):
            print("Skipping (not a directory): %s" % p, file=sys.stderr)
            continue
        found = discover_leveldb_databases(p)
        if not found:
            found = [{"path": p, "is_indexeddb": False, "origin": None,
                      "ldb_count": 0, "sst_count": 0, "log_count": 0}]
        for d in found:
            rp = os.path.realpath(d["path"])
            if rp in seen:
                continue
            seen.add(rp)
            databases.append(d)

    if not databases:
        print("No LevelDB databases found under the given path(s).", file=sys.stderr)
        return 1

    idb_count = sum(1 for d in databases if d["is_indexeddb"])
    print("Found %d database(s) (%d IndexedDB, %d Local Storage/other) across %d path(s):"
          % (len(databases), idb_count, len(databases) - idb_count, len(args.paths)))
    for d in databases:
        kind = "IndexedDB" if d["is_indexeddb"] else "LevelDB"
        origin = (" origin=%s" % d["origin"]) if d.get("origin") else ""
        print("  [%s] %s%s (.ldb=%d .log=%d)" % (kind, d["path"], origin, d["ldb_count"], d["log_count"]))

    prefix_bytes = _parse_prefix_arg(args.prefix.strip())
    search_bytes = args.search.strip().encode("utf-8") if args.search.strip() else None
    limit = args.limit or None

    rows = list(process_databases(databases, prefix_bytes, search_bytes, limit))
    print("Extracted %d artifact record(s)." % len(rows))

    outpath = args.out or ("leveldb_forensic_report_%s.csv" % datetime.now().strftime("%Y%m%d_%H%M%S"))
    written, physical_rows, total = write_forensic_csv(rows, outpath)
    print("Wrote %d row(s) (collapsed from %d physical rewrites; %d records scanned) -> %s"
          % (written, physical_rows, total, outpath))

    if args.hashes:
        manifest_path = os.path.splitext(outpath)[0] + "_evidence_hashes.csv"
        infos = []
        for p in args.paths:
            if os.path.isdir(p):
                infos.extend(hash_evidence_files(p))
        with open(manifest_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["filename", "path", "size_bytes", "sha256", "modified_utc"])
            for info in infos:
                w.writerow([info.filename, info.path, info.size, info.sha256, info.modified])
        print("Wrote SHA-256 evidence manifest (%d files) -> %s" % (len(infos), manifest_path))

    return 0


def main():
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
