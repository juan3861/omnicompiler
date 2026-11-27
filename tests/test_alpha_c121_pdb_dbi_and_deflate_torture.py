"""Alpha-C121 verification: 6-stream PDB DBI+S_PUB32, ELF .symtab & RFC-1951 DEFLATE Torture."""

import io
import os
import struct
import unittest

from elftools.elf.elffile import ELFFile

from benchmarks.oss_torture_suite import run_deflate_torture_benchmark
from compiler.binary_emitter import StandaloneBinaryEmitter


def _read_pdb_stream(pdb_bytes: bytes, stream_idx: int) -> bytes:
    block_size, _fpm, _num_blks, dir_sz = struct.unpack_from("<IIII", pdb_bytes, 32)
    dir_map_blk = struct.unpack_from("<I", pdb_bytes, 52)[0]
    n_dir_blks = (dir_sz + block_size - 1) // block_size
    dir_blks = struct.unpack_from(f"<{n_dir_blks}I", pdb_bytes, dir_map_blk * block_size)
    dir_buf = bytearray()
    for blk in dir_blks:
        dir_buf.extend(pdb_bytes[blk * block_size:(blk + 1) * block_size])
    dir_buf = dir_buf[:dir_sz]
    n_streams = struct.unpack_from("<I", dir_buf, 0)[0]
    sizes = struct.unpack_from(f"<{n_streams}I", dir_buf, 4)
    off = 4 + 4 * n_streams
    blks_by_stream = []
    for s_sz in sizes:
        nb = (s_sz + block_size - 1) // block_size if s_sz else 0
        blks_by_stream.append(struct.unpack_from(f"<{nb}I", dir_buf, off) if nb else ())
        off += 4 * nb
    target = bytearray()
    for blk in blks_by_stream[stream_idx]:
        target.extend(pdb_bytes[blk * block_size:(blk + 1) * block_size])
    return bytes(target[:sizes[stream_idx]])


class TestAlphaC121PdbDbiAndDeflateTorture(unittest.TestCase):
    def test_01_pdb_msf7_dbi_header_symrecord_stream_and_elf_symtab(self) -> None:
        emitter = StandaloneBinaryEmitter()
        exports = {"alpha_fn": 0, "beta_fn": 32, "gamma_fn": 96}
        rsds, pdb_bytes, guid = emitter.build_pdb_msf_rsds("c121_sym.dll", exports, base_fn_rva=0x1010)
        self.assertTrue(rsds.startswith(b"RSDS"))
        self.assertEqual(len(guid), 16)

        # Verify Stream 3 is exact 64B DBI header pointing SymRecordStreamIndex -> 5
        s3 = _read_pdb_stream(pdb_bytes, 3)
        self.assertEqual(len(s3), 64)
        ver_sig, ver_hdr, _age, _g, _b, _p, _pv, sym_rec_stream = struct.unpack_from("<iIIHHHHH", s3, 0)
        self.assertEqual(ver_sig, -1)
        self.assertEqual(ver_hdr, 19990903)
        self.assertEqual(sym_rec_stream, 5)
        machine = struct.unpack_from("<H", s3, 58)[0]
        self.assertEqual(machine, 0x8664)

        # Verify Stream 5 contains S_PUB32 (0x110E) records for every exported symbol
        s5 = _read_pdb_stream(pdb_bytes, 5)
        pos = 0
        found_syms = {}
        while pos + 4 <= len(s5):
            reclen, rectyp = struct.unpack_from("<HH", s5, pos)
            self.assertEqual(rectyp, 0x110E)
            _flags, sec_off, seg = struct.unpack_from("<IIH", s5, pos + 4)
            name_raw = s5[pos + 14:pos + 2 + reclen].split(b"\x00", 1)[0].decode("utf-8")
            found_syms[name_raw] = (seg, sec_off)
            pos += 2 + reclen
        self.assertEqual(found_syms, {
            "alpha_fn": (1, 0x10),
            "beta_fn": (1, 0x30),
            "gamma_fn": (1, 0x70),
        })

        # Verify ELF64 .so emits static .symtab + .strtab + .text alongside .gnu.hash
        so_bytes = emitter.build_elf64_so(
            func_code=(b"\x90" * 128),
            export_name="alpha_fn",
            extra_exports=exports,
            soname="libc121.so",
        )
        elf = ELFFile(io.BytesIO(so_bytes))
        symtab = elf.get_section_by_name(".symtab")
        self.assertIsNotNone(symtab)
        static_names = {sym.name for sym in symtab.iter_symbols() if sym.name}
        self.assertTrue({"alpha_fn", "beta_fn", "gamma_fn"}.issubset(static_names))

    def test_02_rfc1951_deflate_bazel_monorepo_comdat_torture_vs_gxx_o3(self) -> None:
        rep = run_deflate_torture_benchmark(iterations=20)
        self.assertTrue(rep["all_passed"], f"Deflate Bazel torture suite failed: {rep}")
        self.assertTrue(rep["bit_exact_parity"])
        self.assertEqual(rep["bazel_units"], 5)


if __name__ == "__main__":
    unittest.main()
