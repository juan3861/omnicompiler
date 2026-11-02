"""
LMDB-Inspired Zero-Copy Memory-Mapped Store & Fast Snapshot Engine (v2 Binary Index)
Transplanted from LMDB/lmdb & designed for O(1) zero-allocation compiler artifact caching.
Features:
  - Direct in-mmap binary open-addressing hash index table (Header Magic: OMMMAP02)
  - Eliminates O(N) JSON metadata serialization on writes (true O(1) slot writes in RAM pages)
  - Zero-copy reads via direct OS-mapped memoryview slicing
  - Content-addressed deduplication by dual BLAKE3/SHA-256 digest
"""

import os
import mmap
import struct
import hashlib
from typing import Dict, Any, Optional, Union
from crypto.blake3_engine import blake3_digest, dual_content_digest


MMAP_MAGIC = b"OMMMAP02"
HEADER_SIZE = 64
SLOT_COUNT = 2048  # Power-of-two open-addressing hash table in mmap header
SLOT_SIZE = 192
INDEX_REGION_SIZE = HEADER_SIZE + (SLOT_COUNT * SLOT_SIZE)  # ~384 KB binary index region

# Slot binary layout (192 bytes):
#   occupied: uint8 (1 = occupied, 0 = empty)
#   reserved: 7 bytes
#   key_hash64: uint64
#   data_offset: uint64
#   data_length: uint64
#   blake3_hex: 64 bytes ASCII
#   sha256_hex: 64 bytes ASCII
#   key_bytes:  32 bytes UTF-8 prefix/tag (full key verified via key_hash64 + payload header)
SLOT_STRUCT = struct.Struct("<B7xQQQ64s64s32s")


def _hash64(key_str: str) -> int:
    digest = hashlib.blake2b(key_str.encode("utf-8"), digest_size=8).digest()
    val = struct.unpack("<Q", digest)[0]
    return val if val != 0 else 1


class MMapArtifactStore:
    """Zero-copy memory-mapped key-value store with O(1) binary hash index inside mmap."""

    def __init__(self, storage_dir: str, file_name: str = "artifacts.mmap", initial_size_mb: int = 16):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        self.db_path = os.path.join(storage_dir, file_name)
        self.size = max(initial_size_mb * 1024 * 1024, INDEX_REGION_SIZE + 1024 * 1024)
        self._mmap: Optional[mmap.mmap] = None
        self._fd: Optional[int] = None
        self.index: Dict[str, Dict[str, Any]] = {}
        self._cursor = INDEX_REGION_SIZE
        self._init_mmap()

    def _init_mmap(self) -> None:
        file_exists = os.path.exists(self.db_path) and os.path.getsize(self.db_path) >= INDEX_REGION_SIZE
        self._fd = os.open(self.db_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0))
        curr_file_size = os.path.getsize(self.db_path)
        if curr_file_size < self.size:
            os.ftruncate(self._fd, self.size)
        else:
            self.size = curr_file_size

        self._mmap = mmap.mmap(self._fd, self.size, access=mmap.ACCESS_WRITE)

        # Read or initialize binary header: <8sQQ (magic, cursor, entry_count)
        magic, saved_cursor, _ = struct.unpack_from("<8sQQ", self._mmap, 0)
        if file_exists and magic == MMAP_MAGIC and saved_cursor >= INDEX_REGION_SIZE:
            self._cursor = saved_cursor
            self._load_binary_index()
        else:
            self._cursor = INDEX_REGION_SIZE
            self._mmap[0:INDEX_REGION_SIZE] = b"\x00" * INDEX_REGION_SIZE
            struct.pack_into("<8sQQ", self._mmap, 0, MMAP_MAGIC, self._cursor, 0)

    def _load_binary_index(self) -> None:
        """Reconstructs in-memory O(1) lookup cache from binary mmap hash slots."""
        self.index.clear()
        for slot_idx in range(SLOT_COUNT):
            pos = HEADER_SIZE + slot_idx * SLOT_SIZE
            occupied, kh64, offset, length, b3_raw, s256_raw, _ = SLOT_STRUCT.unpack_from(self._mmap, pos)
            if occupied != 1:
                continue
            # Read stored full alias key from payload record header
            # Record header at (offset - 12): <4sII (b'LMDB', key_len, payload_len)
            rec_hdr_pos = offset - 12
            if rec_hdr_pos >= INDEX_REGION_SIZE:
                rmagic, key_len, _ = struct.unpack_from("<4sII", self._mmap, rec_hdr_pos)
                if rmagic == b"LMDB":
                    key_pos = rec_hdr_pos - ((key_len + 7) & ~7)
                    alias_key = bytes(self._mmap[key_pos:key_pos + key_len]).decode("utf-8", errors="ignore")
                    b3_hex = b3_raw.decode("ascii", errors="ignore").rstrip("\x00")
                    s256_hex = s256_raw.decode("ascii", errors="ignore").rstrip("\x00")
                    tenant_id = alias_key.split("::", 1)[0] if "::" in alias_key else "global"
                    entry = {
                        "offset": offset,
                        "length": length,
                        "digests": {
                            "blake3": b3_hex,
                            "sha256": s256_hex,
                            "composite_id": f"b3_{b3_hex[:16]}_s256_{s256_hex[:16]}"
                        },
                        "tenant_id": tenant_id,
                        "key_hash64": kh64
                    }
                    self.index[alias_key] = entry
                    if b3_hex:
                        self.index[b3_hex] = entry

    def _write_binary_slot(self, alias_key: str, entry: Dict[str, Any]) -> None:
        """Inserts or updates a single 192-byte slot in the binary mmap hash table in O(1)."""
        kh64 = _hash64(alias_key)
        mask = SLOT_COUNT - 1
        idx = kh64 & mask
        b3_bytes = entry["digests"]["blake3"].encode("ascii")[:64].ljust(64, b"\x00")
        s256_bytes = entry["digests"]["sha256"].encode("ascii")[:64].ljust(64, b"\x00")
        key_tag = alias_key.encode("utf-8")[:32].ljust(32, b"\x00")

        for _ in range(SLOT_COUNT):
            pos = HEADER_SIZE + idx * SLOT_SIZE
            occupied, existing_kh64 = struct.unpack_from("<B7xQ", self._mmap, pos)
            if occupied in (0, 2) or existing_kh64 == kh64:
                SLOT_STRUCT.pack_into(
                    self._mmap,
                    pos,
                    1,
                    kh64,
                    entry["offset"],
                    entry["length"],
                    b3_bytes,
                    s256_bytes,
                    key_tag
                )
                return
            idx = (idx + 1) & mask

    def _ensure_capacity(self, needed_bytes: int) -> None:
        if self._cursor + needed_bytes <= self.size:
            return
        new_size = self.size
        while self._cursor + needed_bytes > new_size:
            new_size *= 2
        self._mmap.close()
        os.ftruncate(self._fd, new_size)
        self.size = new_size
        self._mmap = mmap.mmap(self._fd, self.size, access=mmap.ACCESS_WRITE)

    def put_artifact(self, key: str, data: Union[str, bytes, memoryview], tenant_id: str = "global") -> Dict[str, Any]:
        """Stores artifact into memory-mapped page buffer in O(1) without JSON re-serialization."""
        if isinstance(data, str):
            raw = data.encode("utf-8")
        elif isinstance(data, memoryview):
            raw = bytes(data)
        else:
            raw = bytes(data)

        digests = dual_content_digest(raw)
        length = len(raw)
        alias_key = f"{tenant_id}::{key}"
        content_hash = digests["blake3"]

        if content_hash in self.index:
            existing = self.index[content_hash]
            entry = {
                "offset": existing["offset"],
                "length": existing["length"],
                "digests": digests,
                "tenant_id": tenant_id
            }
            self.index[alias_key] = entry
            self._write_binary_slot(alias_key, entry)
            return {
                "key": key,
                "tenant_id": tenant_id,
                "digests": digests,
                "offset": entry["offset"],
                "length": entry["length"],
                "deduplicated": True,
                "zero_copy": True
            }

        key_bytes = alias_key.encode("utf-8")
        aligned_key_len = (len(key_bytes) + 7) & ~7
        total_rec_bytes = aligned_key_len + 12 + length + 8
        self._ensure_capacity(total_rec_bytes)

        key_pos = self._cursor
        self._mmap[key_pos:key_pos + len(key_bytes)] = key_bytes
        hdr_pos = key_pos + aligned_key_len
        struct.pack_into("<4sII", self._mmap, hdr_pos, b"LMDB", len(key_bytes), length)
        payload_offset = hdr_pos + 12
        self._mmap[payload_offset:payload_offset + length] = raw

        entry = {
            "offset": payload_offset,
            "length": length,
            "digests": digests,
            "tenant_id": tenant_id
        }
        self.index[content_hash] = entry
        self.index[alias_key] = entry
        self._cursor = (payload_offset + length + 7) & ~7

        # Update header cursor and binary slot in O(1)
        struct.pack_into("<Q", self._mmap, 8, self._cursor)
        self._write_binary_slot(alias_key, entry)

        return {
            "key": key,
            "tenant_id": tenant_id,
            "digests": digests,
            "offset": payload_offset,
            "length": length,
            "deduplicated": False,
            "zero_copy": True
        }

    def get_artifact_view(self, key: str, tenant_id: str = "global") -> Optional[memoryview]:
        """Retrieves direct zero-copy memoryview into the OS-mapped pages."""
        alias_key = f"{tenant_id}::{key}"
        entry = self.index.get(alias_key) or self.index.get(key)
        if not entry or self._mmap is None:
            return None
        offset = entry["offset"]
        length = entry["length"]
        return memoryview(self._mmap)[offset:offset + length]

    def get_artifact_bytes(self, key: str, tenant_id: str = "global") -> Optional[bytes]:
        view = self.get_artifact_view(key, tenant_id)
        try:
            return bytes(view) if view is not None else None
        finally:
            if view is not None:
                view.release()

    def get_artifact_text(self, key: str, tenant_id: str = "global") -> Optional[str]:
        b = self.get_artifact_bytes(key, tenant_id)
        return b.decode("utf-8") if b is not None else None

    def delete_artifact(self, key: str, tenant_id: str = "global") -> bool:
        """Marks an artifact slot as deleted (tombstone=2) in O(1) inside the binary mmap index."""
        alias_key = f"{tenant_id}::{key}"
        if alias_key not in self.index or self._mmap is None:
            return False
        self.index.pop(alias_key, None)
        kh64 = _hash64(alias_key)
        mask = SLOT_COUNT - 1
        idx = kh64 & mask
        for _ in range(SLOT_COUNT):
            pos = HEADER_SIZE + idx * SLOT_SIZE
            occupied, existing_kh64 = struct.unpack_from("<B7xQ", self._mmap, pos)
            if occupied == 0:
                break
            if occupied == 1 and existing_kh64 == kh64:
                struct.pack_into("<B", self._mmap, pos, 2)
                return True
            idx = (idx + 1) & mask
        return False

    def count(self) -> int:
        """Returns number of live alias entries in the store."""
        return sum(1 for k in self.index if "::" in k)

    store_artifact = put_artifact
    read_zero_copy = get_artifact_view

    def flush(self) -> None:
        if self._mmap is not None:
            self._mmap.flush()

    def close(self) -> None:
        if self._mmap is not None:
            try:
                self._mmap.flush()
                self._mmap.close()
            except BufferError:
                pass
            self._mmap = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


MmapArtifactStore = MMapArtifactStore
