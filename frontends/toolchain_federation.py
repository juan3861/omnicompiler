"""
Alpha-C96: Federated Bitcode / IR & Native Toolchain Ingestion Engine
(`frontends/toolchain_federation.py`)

Bridges external industrial compiler frontends (`clang`, `clang++`, `gcc`, `g++`,
`rustc`, `cargo`, `go`, `tsc`, plus WSL2 cross-Linux ELF64 fallback on Windows)
and build databases (`compile_commands.json`, C/C++ sources, prebuilt `.bc`/`.ll`/`.o`/`.obj`)
into OmniRepoCompiler's LTO Bitcode Fusion (`LLVMBackend.link_bitcode_modules`)
and `NativeObjectLinker`, while preserving automatic offline AOT fallback.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple


def _to_wsl_path(win_path: str) -> str:
    p = os.path.abspath(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


@dataclass
class FederatedUnitArtifact:
    source_path: str
    repo_name: str
    language: str
    artifact_kind: str  # "bitcode" | "ir" | "object"
    payload: bytes
    defined_symbols: List[str] = field(default_factory=list)
    toolchain_used: str = "builtin"
    compile_ms: float = 0.0
    object_format: str = "auto"  # "coff" | "elf" | "macho" | "llvm_bc"


class ToolchainRegistry:
    """Discovers and caches native and WSL2 compiler frontends available on host."""

    _CACHE: Optional[Dict[str, Optional[str]]] = None
    _WSL_CACHE: Optional[Dict[str, Optional[str]]] = None

    @classmethod
    def discover(cls) -> Dict[str, Optional[str]]:
        if cls._CACHE is None:
            names = ("clang", "clang++", "gcc", "g++", "rustc", "cargo", "go", "tsc", "node", "cmake", "ninja")
            cls._CACHE = {name: shutil.which(name) for name in names}
        return dict(cls._CACHE)

    @classmethod
    def discover_wsl(cls) -> Dict[str, Optional[str]]:
        if cls._WSL_CACHE is not None:
            return dict(cls._WSL_CACHE)
        res: Dict[str, Optional[str]] = {"wsl": shutil.which("wsl")}
        if sys.platform != "win32" or not res["wsl"]:
            cls._WSL_CACHE = res
            return dict(res)
        try:
            probe = subprocess.run(
                [
                    "wsl", "python3", "-c",
                    "import json, shutil; print(json.dumps({k: shutil.which(k) for k in ('clang','clang++','gcc','g++','rustc','go')}))",
                ],
                capture_output=True, text=True, timeout=12, stdin=subprocess.DEVNULL,
            )
            if probe.returncode == 0 and probe.stdout.strip():
                parsed = json.loads(probe.stdout.strip().splitlines()[-1])
                if isinstance(parsed, dict):
                    res.update({str(k): (str(v) if v else None) for k, v in parsed.items()})
        except Exception:
            pass
        cls._WSL_CACHE = res
        return dict(res)


class FederatedBuildAdapter:
    """
    Compiles external full-spec C/C++/Rust/Bitcode units into `.bc` or `.o`/`.obj`
    so `OmniRepoCompiler` can fuse them via LLVM O3 Bitcode LTO and native relocation linking.
    """

    def __init__(self, target_os: str = "linux", target_arch: str = "x86_64"):
        self.target_os = target_os.lower()
        self.target_arch = target_arch.lower()
        self.native_tools = ToolchainRegistry.discover()
        self.wsl_tools = ToolchainRegistry.discover_wsl() if sys.platform == "win32" else {}

    def available_summary(self) -> Dict[str, Any]:
        return {
            "native": {k: bool(v) for k, v in self.native_tools.items()},
            "wsl": {k: bool(v) for k, v in self.wsl_tools.items()} if self.wsl_tools else {},
        }

    @staticmethod
    def _inspect_bitcode_exports(payload: bytes) -> List[str]:
        try:
            import llvmlite.binding as llvm
            if payload.startswith((b"BC\xc0\xde", b"\xde\xc0\x17\x0b")):
                mod = llvm.parse_bitcode(payload)
            else:
                mod = llvm.parse_assembly(payload.decode("utf-8", errors="replace"))
            syms = [
                fn.name for fn in mod.functions
                if not fn.is_declaration and not fn.name.startswith("llvm.")
            ]
            for gv in mod.global_variables:
                if not gv.is_declaration and not gv.name.startswith((".", "__")):
                    syms.append(gv.name)
            return sorted(set(syms))
        except Exception:
            return []

    @staticmethod
    def _inspect_object_exports(payload: bytes, obj_fmt: str) -> List[str]:
        from compiler.object_linker import load_coff_object, load_elf_object, load_macho_object
        try:
            if obj_fmt == "coff":
                m = load_coff_object(payload, repo_name="probe")
            elif obj_fmt == "macho":
                m = load_macho_object(payload, repo_name="probe")
            else:
                m = load_elf_object(payload, repo_name="probe")
            return sorted(k for k, sd in m.symbols.items() if sd.is_exported)
        except Exception:
            return []

    @staticmethod
    def _inspect_archive_exports(payload: bytes, target_os: str, repo_name: str = "probe") -> Tuple[List[str], str]:
        from compiler.object_linker import load_static_archive
        fmt = "coff" if target_os == "windows" else ("macho" if target_os == "macos" else "elf")
        try:
            mods = load_static_archive(payload, repo_name=repo_name)
            syms = sorted({k for m in mods for k, sd in m.symbols.items() if sd.is_exported})
            return syms, fmt
        except Exception:
            return [], fmt

    def _compile_c_cpp_to_bitcode(
        self, src_path: str, repo_name: str, extra_flags: Sequence[str] = ()
    ) -> Optional[FederatedUnitArtifact]:
        ext = os.path.splitext(src_path)[1].lower()
        lang = "cpp" if ext in (".cc", ".cpp", ".cxx") else "c"
        compiler_key = "clang++" if lang == "cpp" else "clang"
        cc = self.native_tools.get(compiler_key) or self.native_tools.get("clang")
        use_wsl = False
        if not cc and self.target_os == "linux" and self.wsl_tools.get(compiler_key):
            cc = self.wsl_tools[compiler_key]
            use_wsl = True
        if not cc:
            return None

        t0 = time.perf_counter()
        src_txt = ""
        try:
            with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
                src_txt = f.read()
        except OSError:
            pass
        with tempfile.TemporaryDirectory() as td:
            out_bc = os.path.join(td, "unit.bc")
            flags = self._normalize_flags(extra_flags, src_path)
            if "-O" not in " ".join(flags):
                flags.append("-O3")
            if lang == "cpp" and "throw " not in src_txt and "-fexceptions" not in flags:
                flags.extend(["-fno-exceptions", "-fno-rtti"])
            cmd: List[str]
            if use_wsl:
                wsl_flags = [
                    (f"-I{_to_wsl_path(f[2:])}" if f.startswith("-I") and len(f) > 2 else f)
                    for f in flags
                ]
                cmd = ["wsl", cc, *wsl_flags, "-emit-llvm", "-c", _to_wsl_path(src_path), "-o", _to_wsl_path(out_bc)]
            else:
                cmd = [cc, *flags, "-emit-llvm", "-c", src_path, "-o", out_bc]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            if proc.returncode != 0 or not os.path.exists(out_bc):
                return None
            with open(out_bc, "rb") as f:
                payload = f.read()
            syms = self._inspect_bitcode_exports(payload)
            return FederatedUnitArtifact(
                source_path=src_path,
                repo_name=repo_name,
                language=lang,
                artifact_kind="bitcode",
                payload=payload,
                defined_symbols=syms,
                toolchain_used=f"{'wsl:' if use_wsl else ''}{os.path.basename(cc)}",
                compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                object_format="llvm_bc",
            )

    def _compile_c_cpp_to_object(
        self, src_path: str, repo_name: str, extra_flags: Sequence[str] = ()
    ) -> Optional[FederatedUnitArtifact]:
        ext = os.path.splitext(src_path)[1].lower()
        lang = "cpp" if ext in (".cc", ".cpp", ".cxx") else "c"
        use_wsl = False
        cc: Optional[str] = None
        obj_fmt = "coff" if self.target_os == "windows" else ("macho" if self.target_os == "macos" else "elf")

        if self.target_os == "windows":
            cands = ("clang++", "g++") if lang == "cpp" else ("clang", "gcc")
            for k in cands:
                if self.native_tools.get(k):
                    cc = self.native_tools[k]
                    break
        elif self.target_os == "linux" and self.target_arch == "x86_64":
            cands = ("clang++", "g++") if lang == "cpp" else ("clang", "gcc")
            if sys.platform != "win32":
                for k in cands:
                    if self.native_tools.get(k):
                        cc = self.native_tools[k]
                        break
            else:
                for k in cands:
                    if self.wsl_tools.get(k):
                        cc = self.wsl_tools[k]
                        use_wsl = True
                        break
        elif self.target_os == "macos":
            for k in (("clang++", "g++") if lang == "cpp" else ("clang", "gcc")):
                if self.native_tools.get(k) and sys.platform == "darwin":
                    cc = self.native_tools[k]
                    break
        if not cc:
            return None

        t0 = time.perf_counter()
        src_txt = ""
        try:
            with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
                src_txt = f.read()
        except OSError:
            pass
        with tempfile.TemporaryDirectory() as td:
            out_obj = os.path.join(td, "unit.o")
            flags = self._normalize_flags(extra_flags, src_path)
            if "-O" not in " ".join(flags):
                flags.append("-O2")
            if lang == "cpp" and "throw " not in src_txt and "-fexceptions" not in flags:
                flags.extend(["-fno-exceptions", "-fno-rtti"])
            pic_flags = ["-fPIC", "-fno-asynchronous-unwind-tables"] if obj_fmt in ("elf", "macho") else ["-fno-asynchronous-unwind-tables"]
            cmd: List[str]
            if use_wsl:
                wsl_flags = [
                    (f"-I{_to_wsl_path(f[2:])}" if f.startswith("-I") and len(f) > 2 else f)
                    for f in flags
                ]
                cmd = ["wsl", cc, *wsl_flags, *pic_flags, "-c", _to_wsl_path(src_path), "-o", _to_wsl_path(out_obj)]
            else:
                cmd = [cc, *flags, *pic_flags, "-c", src_path, "-o", out_obj]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            if proc.returncode != 0 or not os.path.exists(out_obj):
                return None
            with open(out_obj, "rb") as f:
                payload = f.read()
            syms = self._inspect_object_exports(payload, obj_fmt)
            return FederatedUnitArtifact(
                source_path=src_path,
                repo_name=repo_name,
                language=lang,
                artifact_kind="object",
                payload=payload,
                defined_symbols=syms,
                toolchain_used=f"{'wsl:' if use_wsl else ''}{os.path.basename(cc)}",
                compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                object_format=obj_fmt,
            )

    def _compile_rust_to_bitcode(self, src_path: str, repo_name: str) -> Optional[FederatedUnitArtifact]:
        rustc = self.native_tools.get("rustc")
        if not rustc:
            return None
        t0 = time.perf_counter()
        with tempfile.TemporaryDirectory() as td:
            out_bc = os.path.join(td, "rust_unit.bc")
            cmd = [rustc, "--crate-type", "lib", "--emit=llvm-bc", "-C", "opt-level=3", src_path, "-o", out_bc]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
            if proc.returncode != 0 or not os.path.exists(out_bc):
                return None
            with open(out_bc, "rb") as f:
                payload = f.read()
            syms = self._inspect_bitcode_exports(payload)
            return FederatedUnitArtifact(
                source_path=src_path,
                repo_name=repo_name,
                language="rust",
                artifact_kind="bitcode",
                payload=payload,
                defined_symbols=syms,
                toolchain_used="rustc",
                compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                object_format="llvm_bc",
            )

    @staticmethod
    def _normalize_flags(extra_flags: Sequence[str], src_path: str, repo_dir: str = "") -> List[str]:
        prefixes = ("-I", "-D", "-std=", "-O", "-fexceptions", "-frtti", "-fno-", "-isystem")
        flags = [str(f) for f in extra_flags if isinstance(f, str) and f.startswith(prefixes)]
        src_dir = os.path.dirname(os.path.abspath(src_path))
        inc_candidates = [src_dir]
        if repo_dir:
            inc_candidates.append(os.path.abspath(repo_dir))
            inc_sub = os.path.join(repo_dir, "include")
            if os.path.isdir(inc_sub):
                inc_candidates.append(os.path.abspath(inc_sub))
        for inc_d in inc_candidates:
            flag_i = f"-I{inc_d}"
            if flag_i not in flags:
                flags.append(flag_i)
        return flags

    @staticmethod
    def _parse_compile_commands_file(cc_json: str, repo_path: str) -> List[Tuple[str, List[str]]]:
        if not os.path.isfile(cc_json):
            return []
        try:
            with open(cc_json, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []
        units: List[Tuple[str, List[str]]] = []
        for entry in data if isinstance(data, list) else []:
            raw_file = entry.get("file", "")
            base_dir = entry.get("directory") or repo_path
            fpath = raw_file if os.path.isabs(raw_file) else os.path.abspath(os.path.join(base_dir, raw_file))
            if not os.path.isfile(fpath):
                continue
            args = entry.get("arguments")
            if not args and isinstance(entry.get("command"), str):
                args = shlex.split(entry["command"])
            flags = [
                str(a)
                for a in (args or [])
                if isinstance(a, str) and a.startswith(("-I", "-D", "-std=", "-O", "-fexceptions", "-frtti"))
            ]
            units.append((fpath, flags))
        return units

    @classmethod
    def _parse_compile_commands(cls, repo_path: str) -> List[Tuple[str, List[str]]]:
        return cls._parse_compile_commands_file(os.path.join(repo_path, "compile_commands.json"), repo_path)

    def _collect_cmake_units(self, repo_path: str) -> Tuple[bool, List[Tuple[str, List[str]]]]:
        """
        Configures real CMakeLists.txt projects (`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`)
        when a compatible native C/C++ compiler exists, and extracts CMake targets/includes/defines
        for cross-WSL2 C/C++ builds on Windows.
        """
        import re
        cmake_file = os.path.join(repo_path, "CMakeLists.txt")
        if not os.path.isfile(cmake_file):
            return False, []

        # 1. Try real CMake configure when matching compiler is natively callable
        cmake_bin = self.native_tools.get("cmake")
        can_native_cmake = bool(cmake_bin) and (
            (sys.platform != "win32" and (self.native_tools.get("gcc") or self.native_tools.get("clang")))
            or (sys.platform == "win32" and self.target_os == "windows" and (self.native_tools.get("clang") or self.native_tools.get("gcc")))
        )
        if can_native_cmake and cmake_bin:
            with tempfile.TemporaryDirectory() as bdir:
                cmd = [cmake_bin, "-S", repo_path, "-B", bdir, "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
                if self.native_tools.get("ninja"):
                    cmd.extend(["-G", "Ninja"])
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45, stdin=subprocess.DEVNULL)
                cc_out = os.path.join(bdir, "compile_commands.json")
                if proc.returncode == 0 and os.path.isfile(cc_out):
                    parsed = self._parse_compile_commands_file(cc_out, repo_path)
                    if parsed:
                        return True, parsed

        # 2. Structured CMakeLists.txt directive extraction (for cross-Linux WSL2 builds or missing local CMake compiler)
        try:
            with open(cmake_file, "r", encoding="utf-8", errors="ignore") as f:
                cm_txt = f.read()
        except OSError:
            return False, []

        clean_txt = re.sub(r"#.*", "", cm_txt)
        inc_flags: List[str] = [f"-I{os.path.abspath(repo_path)}"]
        def_flags: List[str] = []
        extra_flags: List[str] = []

        std_m = re.search(r"CMAKE_CXX_STANDARD\s+(\d+)", clean_txt)
        if std_m:
            extra_flags.append(f"-std=c++{std_m.group(1)}")

        for m_inc in re.finditer(r"(?:target_include_directories|include_directories)\s*\(([^)]+)\)", clean_txt, re.IGNORECASE):
            for tok in m_inc.group(1).split():
                t = tok.strip("\"'")
                if t.upper() in ("PUBLIC", "PRIVATE", "INTERFACE") or tok == m_inc.group(1).split()[0]:
                    continue
                t = t.replace("${CMAKE_CURRENT_SOURCE_DIR}", repo_path).replace("${PROJECT_SOURCE_DIR}", repo_path)
                cand = t if os.path.isabs(t) else os.path.abspath(os.path.join(repo_path, t))
                if os.path.isdir(cand):
                    fi = f"-I{cand}"
                    if fi not in inc_flags:
                        inc_flags.append(fi)

        for m_def in re.finditer(r"(?:target_compile_definitions|add_definitions)\s*\(([^)]+)\)", clean_txt, re.IGNORECASE):
            for tok in m_def.group(1).split():
                t = tok.strip("\"'")
                if t.upper() in ("PUBLIC", "PRIVATE", "INTERFACE"):
                    continue
                if t.startswith("-D"):
                    def_flags.append(t)
                elif "=" in t or t.isupper():
                    def_flags.append(f"-D{t}")

        src_units: List[Tuple[str, List[str]]] = []
        seen_src: set = set()
        shared_flags = inc_flags + def_flags + extra_flags
        for m_src in re.finditer(r"([A-Za-z0-9_./\\-]+\.(?:cpp|cxx|cc|c))(?![A-Za-z0-9_])", clean_txt):
            rel_s = m_src.group(1)
            full_s = os.path.abspath(os.path.join(repo_path, rel_s))
            if os.path.isfile(full_s) and full_s not in seen_src:
                seen_src.add(full_s)
                src_units.append((full_s, list(shared_flags)))

        return bool(src_units), src_units

    def _compile_go_module(self, repo_path: str, repo_name: str) -> Optional[FederatedUnitArtifact]:
        """
        Invokes official `go build` on `go.mod` / `*.go` repositories:
        - Uses `go build -buildmode=c-archive` when matching host C toolchain exists (producing linkable `.a`).
        - Otherwise compiles pure Go directly with `GOOS=wasip1 GOARCH=wasm go build` (produces standard `.wasm`).
        """
        go_bin = self.native_tools.get("go")
        use_wsl_go = False
        if not go_bin and self.target_os == "linux" and self.wsl_tools.get("go"):
            go_bin = self.wsl_tools["go"]
            use_wsl_go = True
        if not go_bin:
            return None

        has_gomod = os.path.isfile(os.path.join(repo_path, "go.mod"))
        go_files = [
            os.path.join(repo_path, fn)
            for fn in os.listdir(repo_path)
            if fn.endswith(".go") and not fn.endswith("_test.go")
        ]
        if not (has_gomod or go_files):
            return None

        has_export_comment = False
        for gf in go_files:
            try:
                with open(gf, "r", encoding="utf-8", errors="ignore") as f:
                    if "//export " in f.read():
                        has_export_comment = True
                        break
            except OSError:
                pass

        t0 = time.perf_counter()
        can_cgo_archive = has_export_comment and (
            (self.target_os == "linux" and (sys.platform != "win32" or use_wsl_go) and (self.native_tools.get("gcc") or self.wsl_tools.get("gcc")))
            or (self.target_os == "windows" and bool(self.native_tools.get("gcc")))
        )
        with tempfile.TemporaryDirectory() as td:
            if can_cgo_archive:
                out_a = os.path.join(td, f"lib{repo_name}_go.a")
                env = dict(os.environ)
                env["CGO_ENABLED"] = "1"
                cmd = (
                    ["wsl", go_bin, "build", "-buildmode=c-archive", "-o", _to_wsl_path(out_a), "."]
                    if use_wsl_go
                    else [go_bin, "build", "-buildmode=c-archive", "-o", out_a, "."]
                )
                proc = subprocess.run(cmd, cwd=repo_path, env=env, capture_output=True, text=True, timeout=45, stdin=subprocess.DEVNULL)
                if proc.returncode == 0 and os.path.isfile(out_a):
                    with open(out_a, "rb") as af:
                        ar_bytes = af.read()
                    syms, ar_fmt = self._inspect_archive_exports(ar_bytes, self.target_os, repo_name)
                    return FederatedUnitArtifact(
                        source_path=repo_path,
                        repo_name=repo_name,
                        language="go",
                        artifact_kind="static_archive",
                        payload=ar_bytes,
                        defined_symbols=syms,
                        toolchain_used="go:c-archive",
                        compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                        object_format=ar_fmt,
                    )

            # Portable native Go WASI build (`GOOS=wasip1 GOARCH=wasm`) requiring zero Cgo C compiler
            out_wasm = os.path.join(td, f"{repo_name}_go.wasm")
            env_w = dict(os.environ)
            env_w["GOOS"] = "wasip1"
            env_w["GOARCH"] = "wasm"
            cmd_w = [go_bin, "build", "-o", out_wasm, "."]
            proc_w = subprocess.run(cmd_w, cwd=repo_path, env=env_w, capture_output=True, text=True, timeout=45, stdin=subprocess.DEVNULL)
            if proc_w.returncode == 0 and os.path.isfile(out_wasm):
                with open(out_wasm, "rb") as wf:
                    w_bytes = wf.read()
                return FederatedUnitArtifact(
                    source_path=repo_path,
                    repo_name=repo_name,
                    language="go",
                    artifact_kind="wasm_module",
                    payload=w_bytes,
                    defined_symbols=[],
                    toolchain_used="go:wasip1",
                    compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                    object_format="wasm",
                )
        return None

    def collect_federated_artifacts(
        self,
        manifests: Sequence[Any],
        parsed_symbols: Optional[set] = None,
        toolchain_mode: str = "auto",
    ) -> List[FederatedUnitArtifact]:
        """
        Discovers prebuilt `.bc`/`.ll`/`.o`/`.obj` files, `compile_commands.json` units,
        and (in `federated_lto` mode or for unparsed C/C++/Rust files) invokes native/WSL
        compilers to emit LLVM Bitcode or relocatable object files.
        """
        if toolchain_mode == "aot_only":
            return []

        already_lowered = set(parsed_symbols or ())
        artifacts: List[FederatedUnitArtifact] = []
        seen_paths: set = set()

        for m in manifests:
            repo_dir = getattr(m, "repo_path", "")
            repo_name = getattr(m, "repo_name", "repo")
            if not repo_dir or not os.path.isdir(repo_dir):
                continue

            # 1. Explicit compile_commands.json database entries
            for fpath, flags in self._parse_compile_commands(repo_dir):
                norm_p = os.path.abspath(fpath)
                if norm_p in seen_paths:
                    continue
                seen_paths.add(norm_p)
                eff_flags = self._normalize_flags(flags, norm_p, repo_dir=repo_dir)
                art = self._compile_c_cpp_to_bitcode(norm_p, repo_name, extra_flags=eff_flags)
                if art is None:
                    art = self._compile_c_cpp_to_object(norm_p, repo_name, extra_flags=eff_flags)
                if art is not None:
                    artifacts.append(art)

            # 1b. CMakeLists.txt build system integration
            if os.path.isfile(os.path.join(repo_dir, "CMakeLists.txt")):
                _cm_ok, cm_units = self._collect_cmake_units(repo_dir)
                for fpath, flags in cm_units:
                    norm_p = os.path.abspath(fpath)
                    if norm_p in seen_paths:
                        continue
                    seen_paths.add(norm_p)
                    eff_flags = self._normalize_flags(flags, norm_p, repo_dir=repo_dir)
                    art = self._compile_c_cpp_to_bitcode(norm_p, repo_name, extra_flags=eff_flags)
                    if art is None:
                        art = self._compile_c_cpp_to_object(norm_p, repo_name, extra_flags=eff_flags)
                    if art is not None:
                        artifacts.append(art)

            # 1c. Real Go module compilation (`go build -buildmode=c-archive` / `GOOS=wasip1`)
            if toolchain_mode == "federated_lto":
                go_art = self._compile_go_module(repo_dir, repo_name)
                if go_art is not None:
                    artifacts.append(go_art)

            # 2. Walk repo for prebuilt bitcode/IR/objects or complex C/C++/Rust units
            for root, _, files in os.walk(repo_dir):
                if any(p in root for p in (".git", "__pycache__", ".venv", "node_modules", "target", "build")):
                    continue
                for fn in sorted(files):
                    fpath = os.path.abspath(os.path.join(root, fn))
                    if fpath in seen_paths:
                        continue
                    ext = os.path.splitext(fn)[1].lower()
                    if ext in (".bc", ".ll"):
                        seen_paths.add(fpath)
                        with open(fpath, "rb") as f:
                            payload = f.read()
                        artifacts.append(
                            FederatedUnitArtifact(
                                source_path=fpath,
                                repo_name=repo_name,
                                language="llvm_ir",
                                artifact_kind="bitcode" if ext == ".bc" else "ir",
                                payload=payload,
                                defined_symbols=self._inspect_bitcode_exports(payload),
                                toolchain_used="prebuilt_llvm",
                                object_format="llvm_bc",
                            )
                        )
                    elif ext in (".a", ".lib"):
                        seen_paths.add(fpath)
                        with open(fpath, "rb") as f:
                            payload = f.read()
                        if payload.startswith(b"!<arch>\n"):
                            ar_syms, ar_fmt = self._inspect_archive_exports(payload, self.target_os, repo_name)
                            artifacts.append(
                                FederatedUnitArtifact(
                                    source_path=fpath,
                                    repo_name=repo_name,
                                    language="static_archive",
                                    artifact_kind="static_archive",
                                    payload=payload,
                                    defined_symbols=ar_syms,
                                    toolchain_used="prebuilt_archive",
                                    object_format=ar_fmt,
                                )
                            )
                    elif ext in (".o", ".obj"):
                        seen_paths.add(fpath)
                        with open(fpath, "rb") as f:
                            payload = f.read()
                        if payload[:4] == b"\x7fELF":
                            ofmt = "elf"
                        elif payload[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
                            ofmt = "macho"
                        else:
                            ofmt = "coff"
                        artifacts.append(
                            FederatedUnitArtifact(
                                source_path=fpath,
                                repo_name=repo_name,
                                language="native_obj",
                                artifact_kind="object",
                                payload=payload,
                                defined_symbols=self._inspect_object_exports(payload, ofmt),
                                toolchain_used="prebuilt_obj",
                                object_format=ofmt,
                            )
                        )
                    elif ext in (".c", ".cc", ".cpp", ".cxx"):
                        needs_fed = toolchain_mode == "federated_lto"
                        if not needs_fed:
                            try:
                                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                    src_txt = f.read()
                                if any(tok in src_txt for tok in ("template<", "template <", "std::", "namespace ", "virtual ", "#include <")):
                                    needs_fed = True
                            except OSError:
                                needs_fed = False
                        if needs_fed:
                            seen_paths.add(fpath)
                            repo_flags = self._normalize_flags([], fpath, repo_dir=repo_dir)
                            art = self._compile_c_cpp_to_bitcode(fpath, repo_name, extra_flags=repo_flags)
                            if art is None:
                                art = self._compile_c_cpp_to_object(fpath, repo_name, extra_flags=repo_flags)
                            if art is not None and (toolchain_mode == "federated_lto" or not set(art.defined_symbols).issubset(already_lowered)):
                                artifacts.append(art)
                    elif ext == ".rs" and toolchain_mode == "federated_lto":
                        seen_paths.add(fpath)
                        art = self._compile_rust_to_bitcode(fpath, repo_name)
                        if art is not None:
                            artifacts.append(art)

        return artifacts
