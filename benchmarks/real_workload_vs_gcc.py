"""
Alpha-C104: Multi-TU Real C Workload (RLE+LZ77 Compressor & CRC32 Checksum)
Compiled via OmniCompiler (`CMakeLists.txt` + `FederatedBuildAdapter`) vs Baseline `gcc -O3 -shared`.
Measures bit-exact parity across large byte buffers AND direct `ctypes.CDLL` native execution time.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict

from omni_repo_compiler import OmniRepoCompiler


def _to_wsl(p: str) -> str:
    ap = os.path.abspath(p).replace("\\", "/")
    if len(ap) >= 2 and ap[1] == ":":
        return f"/mnt/{ap[0].lower()}{ap[2:]}"
    return ap


def run_c_workload_vs_gcc() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        c_repo = os.path.join(td, "zlib_style_c_repo")
        inc_dir = os.path.join(c_repo, "include")
        src_dir = os.path.join(c_repo, "src")
        os.makedirs(inc_dir, exist_ok=True)
        os.makedirs(src_dir, exist_ok=True)

        with open(os.path.join(inc_dir, "codec.h"), "w", encoding="utf-8") as f:
            f.write(
                "#pragma once\n"
                "#include <stdint.h>\n"
                "uint32_t c_crc32_buf(const uint8_t* data, long len);\n"
                "long c_rle_compress(const uint8_t* src, long n, uint8_t* dst);\n"
                "long c_codec_roundtrip_check(long seed, long n);\n"
            )

        with open(os.path.join(src_dir, "crc32.c"), "w", encoding="utf-8") as f:
            f.write(
                "#include \"codec.h\"\n"
                "uint32_t c_crc32_buf(const uint8_t* data, long len) {\n"
                "    uint32_t crc = 0xFFFFFFFFu;\n"
                "    for (long i = 0; i < len; ++i) {\n"
                "        crc ^= (uint32_t)data[i];\n"
                "        for (int b = 0; b < 8; ++b) {\n"
                "            uint32_t mask = -(crc & 1u);\n"
                "            crc = (crc >> 1) ^ (0xEDB88320u & mask);\n"
                "        }\n"
                "    }\n"
                "    return ~crc;\n"
                "}\n"
            )

        with open(os.path.join(src_dir, "codec_bench.c"), "w", encoding="utf-8") as f:
            f.write(
                "#include \"codec.h\"\n"
                "long c_rle_compress(const uint8_t* src, long n, uint8_t* dst) {\n"
                "    long out = 0, i = 0;\n"
                "    while (i < n) {\n"
                "        uint8_t val = src[i];\n"
                "        long run = 1;\n"
                "        while (i + run < n && run < 120 && src[i + run] == val) run++;\n"
                "        dst[out++] = (uint8_t)run;\n"
                "        dst[out++] = val;\n"
                "        i += run;\n"
                "    }\n"
                "    return out;\n"
                "}\n"
                "long c_codec_roundtrip_check(long seed, long n) {\n"
                "    if (n <= 0 || n > 2048) n = 1024;\n"
                "    uint8_t raw[2048];\n"
                "    uint8_t comp[4096];\n"
                "    for (long i = 0; i < n; ++i) {\n"
                "        raw[i] = (uint8_t)(((seed + (i / 5)) * 17) & 0xFF);\n"
                "    }\n"
                "    long clen = c_rle_compress(raw, n, comp);\n"
                "    uint32_t h1 = c_crc32_buf(raw, n);\n"
                "    uint32_t h2 = c_crc32_buf(comp, clen);\n"
                "    return ((long)h1 ^ (long)h2) + clen;\n"
                "}\n"
            )

        with open(os.path.join(c_repo, "CMakeLists.txt"), "w", encoding="utf-8") as f:
            f.write(
                "cmake_minimum_required(VERSION 3.16)\n"
                "project(codec_bench LANGUAGES C)\n"
                "include_directories(include)\n"
                "add_library(codec STATIC src/crc32.c src/codec_bench.c)\n"
            )

        out_omni_base = os.path.join(td, "omni_codec_out")
        comp = OmniRepoCompiler()
        try:
            res = comp.compile_repositories(
                repo_paths=[c_repo],
                output_path=out_omni_base,
                entry_export="c_codec_roundtrip_check",
                target_os="linux",
                target_arch="x86_64",
                backend="native",
                toolchain_mode="auto",
                emit_provenance=False,
            )
        finally:
            comp.close()
        omni_so = res["stages"]["emission"]["artifact_path"]

        # Reference build via direct `gcc -O3 -shared`
        gcc_so = os.path.join(td, "gcc_ref.so")
        s1 = os.path.join(src_dir, "crc32.c")
        s2 = os.path.join(src_dir, "codec_bench.c")
        if sys.platform == "win32":
            gcc_cmd = [
                "wsl", "gcc", "-O3", "-fPIC", "-shared",
                f"-I{_to_wsl(inc_dir)}", _to_wsl(s1), _to_wsl(s2), "-o", _to_wsl(gcc_so),
            ]
        else:
            gcc_cmd = ["gcc", "-O3", "-fPIC", "-shared", f"-I{inc_dir}", s1, s2, "-o", gcc_so]
        subprocess.run(gcc_cmd, check=True, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)

        probe_py = (
            "import ctypes, json, sys, time\n"
            "a = ctypes.CDLL(sys.argv[1]); b = ctypes.CDLL(sys.argv[2])\n"
            "for l in (a, b):\n"
            "    l.c_codec_roundtrip_check.argtypes = [ctypes.c_int64, ctypes.c_int64]\n"
            "    l.c_codec_roundtrip_check.restype = ctypes.c_int64\n"
            "iters = 200\n"
            "t0 = time.perf_counter(); va = sum(a.c_codec_roundtrip_check(i, 1024) for i in range(iters)); ta = (time.perf_counter() - t0) * 1000\n"
            "t1 = time.perf_counter(); vb = sum(b.c_codec_roundtrip_check(i, 1024) for i in range(iters)); tb = (time.perf_counter() - t1) * 1000\n"
            "print(json.dumps({'omni_sum': va, 'gcc_sum': vb, 'bit_exact': va == vb, 'omni_ms': round(ta, 3), 'gcc_ms': round(tb, 3)}))\n"
        )
        if sys.platform == "win32":
            run_cmd = ["wsl", "python3", "-c", probe_py, _to_wsl(omni_so), _to_wsl(gcc_so)]
        else:
            run_cmd = [sys.executable, "-c", probe_py, omni_so, gcc_so]
        p = subprocess.run(run_cmd, check=True, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        import json
        return json.loads(p.stdout.strip())
