import struct
import snappy
import sys

# -------------------------------
# VARINT DECODER
# -------------------------------
def decode_varint(buf, pos):
    val = 0
    shift = 0
    start = pos
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7
    raise ValueError("Incomplete varint at position %d" % start)

# -------------------------------
# DECODE A LEVELDB BLOCK (data or index)
# -------------------------------
def decode_block(block_bytes):
    """
    Returns:
        entries = list of (key, value_bytes)
    """
    entries = []
    block_size = len(block_bytes)
    print(block_size)

    # Restart count = last 4 bytes
    restart_count = struct.unpack("<I", block_bytes[-4:])[0]
    

    # Restart array
    restart_array_offset = block_size - 4 - restart_count * 4

    restart_offsets = [
        struct.unpack("<I", block_bytes[restart_array_offset + i*4 : restart_array_offset + (i+1)*4])[0]
        for i in range(restart_count)
    ]

    # Now decode entries
    prev_key = ""
    pos = 0
    restart_index = 0

    def at_restart(p):
        nonlocal restart_index
        if restart_index < len(restart_offsets) and p == restart_offsets[restart_index]:
            prev_key = ""
            restart_index += 1
            return True
        return False

    entries = []

    prev_key = ""
    restart_idx = 0

    while pos < restart_array_offset:
        # Check for restart
        if restart_idx < len(restart_offsets) and pos == restart_offsets[restart_idx]:
            prev_key = ""
            restart_idx += 1

        # Decode varint fields
        shared, pos = decode_varint(block_bytes, pos)
        non_shared, pos = decode_varint(block_bytes, pos)
        val_len, pos = decode_varint(block_bytes, pos)

        # Key suffix
        key_suffix = block_bytes[pos:pos+non_shared]
        pos += non_shared

        try:
            key_suffix_dec = key_suffix.decode("utf-8")
        except:
            key_suffix_dec = key_suffix.hex()

        full_key = prev_key[:shared] + key_suffix_dec

        # Value
        val = block_bytes[pos:pos+val_len]
        pos += val_len

        entries.append((full_key, val))
        prev_key = full_key

    return entries


# -------------------------------
# MAIN SST PARSER
# -------------------------------
def parse_sst(path):
    with open(path, "rb") as f:
        data = f.read()

    file_size = len(data)
    print(f"[+] File loaded: {path}")
    print(f"[+] Size: {file_size} bytes")

    # ----- FOOTER -----
    footer = data[-48:]
    handles = footer[:40]
    magic = footer[40:]
    magic_val = struct.unpack("<Q", magic)[0]

    EXPECTED_MAGIC = 0xDB4775248B80FB57
    if magic_val != EXPECTED_MAGIC:
        print("[!] ERROR: Invalid SST magic number.")
        sys.exit(1)

    print("[+] Footer magic correct.")

    # Decode block handles (metaindex, index)
    pos = 0
    meta_off, pos = decode_varint(handles, pos)
    meta_sz, pos = decode_varint(handles, pos)
    idx_off, pos = decode_varint(handles, pos)
    idx_sz, pos = decode_varint(handles, pos)

    print(f"[+] Metaindex block @ {meta_off}, size {meta_sz}")
    print(f"[+] Index block     @ {idx_off}, size {idx_sz}")

    # ----- METAINDEX BLOCK -----
    meta_block_raw = data[meta_off : meta_off + meta_sz]
    # Trailer is AFTER the block
    meta_trailer = data[meta_off + meta_sz : meta_off + meta_sz + 5]

    compression = meta_trailer[0]

    if compression == 0:
        meta_block = meta_block_raw
    elif compression == 1:
        meta_block = snappy.decompress(meta_block_raw)
        
    else:
        raise Exception("Unknown metaindex compression type.")

    print("[+] Metaindex block decoded.")

    # ----- INDEX BLOCK -----
    idx_block_raw = data[idx_off : idx_off + idx_sz]
    idx_trailer = data[idx_off + idx_sz : idx_off + idx_sz + 5]

    idx_compression = idx_trailer[0]

    if idx_compression == 0:
        idx_block = idx_block_raw
    elif idx_compression == 1:
        idx_block = snappy.decompress(idx_block_raw)
    else:
        raise Exception("Unknown index compression type.")

    print("[+] Index block decoded (after snappy).")

    # Decode index entries
    index_entries = decode_block(idx_block)

    print(f"[+] Index entries found: {len(index_entries)}")

    # ----- DATA BLOCKS -----
    print("\n============================")
    print("       DATA BLOCKS")
    print("============================\n")

    for key, val in index_entries:
        # Value here = BlockHandle(offset,size)
        vpos = 0
        block_off, vpos = decode_varint(val, vpos)
        block_sz, vpos = decode_varint(val, vpos)

        print(f"[+] Data block for key '{key}': offset={block_off}, size={block_sz}")

        # Extract raw block
        raw_block = data[block_off : block_off + block_sz]

        # Get trailer
        trailer = data[block_off + block_sz : block_off + block_sz + 5]
        comp_type = trailer[0]

        # Handle compression
        if comp_type == 0:
            block = raw_block
        elif comp_type == 1:
            block = snappy.decompress(raw_block)
        else:
            print("    [!] Unknown compression, skipping block.")
            continue

        # Decode data block
        kv_pairs = decode_block(block)

        print(f"    -> {len(kv_pairs)} KV pairs")
        for k, v in kv_pairs:
            print(f"       KEY: {k}")
            try:
                print(f"       VAL: {v.decode('utf-8')}")
            except:
                print(f"       VAL(hex): {v.hex()}")
            print()


# -------------------------------
# RUN SCRIPT
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_sst.py <file.ldb>")
        sys.exit(1)

    parse_sst(sys.argv[1])
