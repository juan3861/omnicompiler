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

import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]
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
            names = (
                "clang", "clang++", "gcc", "g++", "rustc", "cargo",
                "go", "tsc", "node", "cmake", "ninja", "meson", "make", "pkg-config",
            )
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
                    "import json, shutil; print(json.dumps({k: shutil.which(k) for k in ('clang','clang++','gcc','g++','rustc','cargo','go')}))",
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
        self._last_cargo_workspaces: Dict[str, Dict[str, Any]] = {}
        self.discovered_external_libs: List[str] = []

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
            uses_cpp_eh = any(tok in src_txt for tok in ("throw ", "catch", "try", "typeid", "dynamic_cast"))
            if lang == "cpp" and uses_cpp_eh:
                if "-fexceptions" not in flags:
                    flags.append("-fexceptions")
            elif lang == "cpp" and "-fexceptions" not in flags:
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
            uses_cpp_eh = any(tok in src_txt for tok in ("throw ", "catch", "try", "typeid", "dynamic_cast"))
            if lang == "cpp" and uses_cpp_eh:
                if "-fexceptions" not in flags:
                    flags.append("-fexceptions")
                pic_flags = ["-fPIC"] if obj_fmt in ("elf", "macho") else []
            else:
                if lang == "cpp" and "-fexceptions" not in flags:
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

    @staticmethod
    def _extract_cmake_calls(clean_txt: str) -> List[Tuple[str, List[str]]]:
        """Extracts balanced `command(args...)` directives from stripped CMakeLists text."""
        calls: List[Tuple[str, List[str]]] = []
        n = len(clean_txt)
        i = 0
        cmd_pat = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        while i < n:
            m = cmd_pat.search(clean_txt, i)
            if not m:
                break
            cmd_name = m.group(1).lower()
            pos = m.end()
            depth = 1
            in_q = False
            start_args = pos
            while pos < n and depth > 0:
                ch = clean_txt[pos]
                if ch == '"' and (pos == 0 or clean_txt[pos - 1] != "\\"):
                    in_q = not in_q
                elif not in_q:
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                pos += 1
            raw_args = clean_txt[start_args : pos - 1 if depth == 0 else pos]
            tokens = [t.strip("\"'") for t in re.findall(r'"[^"]*"|[^\s;]+', raw_args) if t.strip("\"'")]
            calls.append((cmd_name, tokens))
            i = pos
        return calls

    @staticmethod
    def _expand_cmake_vars(token: str, cmake_vars: Dict[str, str]) -> List[str]:
        """Substitutes `${VAR}` (including space-separated list variables) in CMake tokens."""
        m_full = re.fullmatch(r"\$\{([A-Za-z0-9_]+)\}", token.strip())
        if m_full:
            val = cmake_vars.get(m_full.group(1), "")
            return [x for x in val.split() if x] if val else []
        expanded = re.sub(
            r"\$\{([A-Za-z0-9_]+)\}",
            lambda mm: cmake_vars.get(mm.group(1), mm.group(0)),
            token,
        )
        return [expanded] if expanded else []

    def _walk_cmake_tree(
        self,
        cur_dir: str,
        root_dir: str,
        parent_vars: Dict[str, str],
        inherited_inc: List[str],
        inherited_def: List[str],
        inherited_extra: List[str],
        visited_dirs: set,
        out_units: List[Tuple[str, List[str]]],
        seen_src: set,
    ) -> None:
        norm_dir = os.path.abspath(cur_dir)
        if norm_dir in visited_dirs:
            return
        visited_dirs.add(norm_dir)
        cm_path = os.path.join(norm_dir, "CMakeLists.txt")
        if not os.path.isfile(cm_path):
            return
        try:
            with open(cm_path, "r", encoding="utf-8", errors="ignore") as f:
                cm_txt = f.read()
        except OSError:
            return

        clean_txt = re.sub(r"#.*", "", cm_txt)
        local_vars = dict(parent_vars)
        local_vars["CMAKE_CURRENT_SOURCE_DIR"] = norm_dir
        local_vars["CMAKE_CURRENT_LIST_DIR"] = norm_dir
        local_vars.setdefault("PROJECT_SOURCE_DIR", root_dir)
        local_vars.setdefault("CMAKE_SOURCE_DIR", root_dir)

        inc_flags = list(inherited_inc)
        cur_inc_flag = f"-I{norm_dir}"
        if cur_inc_flag not in inc_flags:
            inc_flags.append(cur_inc_flag)
        def_flags = list(inherited_def)
        extra_flags = list(inherited_extra)
        local_src_candidates: List[str] = []
        subdirs_to_visit: List[str] = []

        src_exts = (".c", ".cc", ".cpp", ".cxx")
        calls = self._extract_cmake_calls(clean_txt)
        for cmd_name, tokens in calls:
            if not tokens:
                continue
            if cmd_name == "set":
                var_name = tokens[0]
                exp_vals: List[str] = []
                for tk in tokens[1:]:
                    if tk in ("PARENT_SCOPE", "CACHE", "STRING", "PATH", "FILEPATH", "BOOL", "FORCE"):
                        continue
                    exp_vals.extend(self._expand_cmake_vars(tk, local_vars))
                local_vars[var_name] = " ".join(exp_vals)
                if var_name == "CMAKE_CXX_STANDARD" and exp_vals and exp_vals[0].isdigit():
                    std_flag = f"-std=c++{exp_vals[0]}"
                    if std_flag not in extra_flags:
                        extra_flags.append(std_flag)
            elif cmd_name == "file" and len(tokens) >= 3 and tokens[0].upper() in ("GLOB", "GLOB_RECURSE"):
                recursive = tokens[0].upper() == "GLOB_RECURSE"
                var_name = tokens[1]
                matched_files: List[str] = []
                for raw_pat in tokens[2:]:
                    if raw_pat.upper() in ("CONFIGURE_DEPENDS", "LIST_DIRECTORIES", "RELATIVE", "TRUE", "FALSE"):
                        continue
                    for pat in self._expand_cmake_vars(raw_pat, local_vars):
                        full_pat = pat if os.path.isabs(pat) else os.path.join(norm_dir, pat)
                        if recursive and "**" not in full_pat:
                            dir_part, base_part = os.path.split(full_pat)
                            full_pat = os.path.join(dir_part, "**", base_part)
                        for hit in sorted(glob.glob(full_pat, recursive=recursive)):
                            if os.path.isfile(hit):
                                matched_files.append(os.path.abspath(hit))
                local_vars[var_name] = " ".join(matched_files)
            elif cmd_name in ("target_include_directories", "include_directories"):
                arg_start = 1 if cmd_name == "target_include_directories" else 0
                for tk in tokens[arg_start:]:
                    if tk.upper() in ("PUBLIC", "PRIVATE", "INTERFACE", "SYSTEM", "BEFORE", "AFTER"):
                        continue
                    for path_tok in self._expand_cmake_vars(tk, local_vars):
                        cand = path_tok if os.path.isabs(path_tok) else os.path.abspath(os.path.join(norm_dir, path_tok))
                        if os.path.isdir(cand):
                            fi = f"-I{cand}"
                            if fi not in inc_flags:
                                inc_flags.append(fi)
            elif cmd_name in ("target_compile_definitions", "add_definitions"):
                arg_start = 1 if cmd_name == "target_compile_definitions" else 0
                for tk in tokens[arg_start:]:
                    if tk.upper() in ("PUBLIC", "PRIVATE", "INTERFACE"):
                        continue
                    for d_tok in self._expand_cmake_vars(tk, local_vars):
                        if d_tok.startswith("-D"):
                            if d_tok not in def_flags:
                                def_flags.append(d_tok)
                        elif "=" in d_tok or d_tok.isupper():
                            df = f"-D{d_tok}"
                            if df not in def_flags:
                                def_flags.append(df)
            elif cmd_name == "target_compile_features":
                for tk in tokens[1:]:
                    m_std = re.fullmatch(r"cxx_std_(\d+)", tk)
                    if m_std:
                        sf = f"-std=c++{m_std.group(1)}"
                        if sf not in extra_flags:
                            extra_flags.append(sf)
            elif cmd_name in ("add_library", "add_executable", "target_sources"):
                for tk in tokens[1:]:
                    if tk.upper() in ("STATIC", "SHARED", "OBJECT", "INTERFACE", "MODULE", "PUBLIC", "PRIVATE", "EXCLUDE_FROM_ALL"):
                        continue
                    for exp_s in self._expand_cmake_vars(tk, local_vars):
                        if os.path.splitext(exp_s)[1].lower() in src_exts:
                            local_src_candidates.append(exp_s)
            elif cmd_name == "add_subdirectory":
                for sub_tok in self._expand_cmake_vars(tokens[0], local_vars):
                    subdirs_to_visit.append(os.path.abspath(os.path.join(norm_dir, sub_tok)))

        shared_flags = inc_flags + def_flags + extra_flags
        for raw_s in local_src_candidates:
            full_s = raw_s if os.path.isabs(raw_s) else os.path.abspath(os.path.join(norm_dir, raw_s))
            if os.path.isfile(full_s) and full_s not in seen_src:
                seen_src.add(full_s)
                out_units.append((full_s, list(shared_flags)))

        for m_src in re.finditer(r"([A-Za-z0-9_./\\-]+\.(?:cpp|cxx|cc|c))(?![A-Za-z0-9_])", clean_txt):
            full_s = os.path.abspath(os.path.join(norm_dir, m_src.group(1)))
            if os.path.isfile(full_s) and full_s not in seen_src:
                seen_src.add(full_s)
                out_units.append((full_s, list(shared_flags)))

        for sub_dir in subdirs_to_visit:
            self._walk_cmake_tree(
                sub_dir,
                root_dir,
                local_vars,
                inc_flags,
                def_flags,
                extra_flags,
                visited_dirs,
                out_units,
                seen_src,
            )

    def _collect_cmake_units(self, repo_path: str) -> Tuple[bool, List[Tuple[str, List[str]]]]:
        """
        Configures real CMakeLists.txt projects (`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`)
        when a compatible native C/C++ compiler exists, and otherwise executes recursive
        CMake AST resolution (`add_subdirectory`, `file(GLOB)`, `${VAR}`, includes, defines).
        """
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

        # 2. Hierarchical CMakeLists.txt recursive tree parser (supports cross-WSL2 & no-local-compiler hosts)
        root_abs = os.path.abspath(repo_path)
        src_units: List[Tuple[str, List[str]]] = []
        self._walk_cmake_tree(
            cur_dir=root_abs,
            root_dir=root_abs,
            parent_vars={"PROJECT_SOURCE_DIR": root_abs, "CMAKE_SOURCE_DIR": root_abs},
            inherited_inc=[f"-I{root_abs}"],
            inherited_def=[],
            inherited_extra=[],
            visited_dirs=set(),
            out_units=src_units,
            seen_src=set(),
        )
        return bool(src_units), src_units

    def inspect_cargo_lock(self, repo_path: str) -> Dict[str, Any]:
        """
        Parses `Cargo.lock` (v3/v4 TOML) and optional `cargo metadata --format-version 1`
        to recover locked external crates, versions, SHA-256 checksums, `build.rs`, and vendor config.
        """
        lock_path = os.path.join(repo_path, "Cargo.lock")
        packages: List[Dict[str, Any]] = []
        if tomllib is not None and os.path.isfile(lock_path):
            try:
                with open(lock_path, "rb") as lf:
                    ldata = tomllib.load(lf)
                for p in ldata.get("package", []) or []:
                    if not isinstance(p, dict) or not p.get("name"):
                        continue
                    packages.append({
                        "name": str(p["name"]),
                        "version": str(p.get("version", "0.0.0")),
                        "source": str(p.get("source", "")),
                        "checksum": str(p.get("checksum", "")),
                        "dependencies": [str(d) for d in (p.get("dependencies") or [])],
                    })
            except Exception:
                pass

        has_vendor = os.path.isdir(os.path.join(repo_path, "vendor")) or os.path.isfile(
            os.path.join(repo_path, ".cargo", "config.toml")
        )
        has_build_rs = False
        for root, _dirs, files in os.walk(repo_path):
            if any(skip in root for skip in (".git", "target")):
                continue
            if "build.rs" in files:
                has_build_rs = True
                break

        cargo_bin = self.native_tools.get("cargo") or (self.wsl_tools.get("cargo") if self.target_os == "linux" else None)
        cargo_meta_ok = False
        if cargo_bin and os.path.isfile(os.path.join(repo_path, "Cargo.toml")):
            use_wsl = bool(not self.native_tools.get("cargo") and self.target_os == "linux" and self.wsl_tools.get("cargo"))
            offline_flag = ["--offline"] if (has_vendor or os.path.isfile(lock_path)) else []
            try:
                if use_wsl:
                    off_s = " --offline" if offline_flag else ""
                    cmd = ["wsl", "bash", "-lc", f"cd '{_to_wsl_path(repo_path)}' && '{cargo_bin}' metadata --format-version 1{off_s}"]
                else:
                    cmd = [cargo_bin, "metadata", "--format-version", "1", *offline_flag, "--manifest-path", os.path.join(repo_path, "Cargo.toml")]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
                if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
                    meta_json = json.loads(proc.stdout)
                    if not packages:
                        for mp in meta_json.get("packages", []) or []:
                            packages.append({
                                "name": str(mp.get("name", "")),
                                "version": str(mp.get("version", "0.0.0")),
                                "source": str(mp.get("source") or ""),
                                "checksum": "",
                                "dependencies": [str(d.get("name", "")) for d in (mp.get("dependencies") or [])],
                            })
                    cargo_meta_ok = True
            except Exception:
                pass

        return {
            "has_cargo_lock": os.path.isfile(lock_path),
            "packages": packages,
            "has_vendor": has_vendor,
            "has_build_rs": has_build_rs,
            "cargo_metadata_resolved": cargo_meta_ok,
        }

    def inspect_cargo_workspace(self, repo_path: str) -> Dict[str, Any]:
        """
        Parses `Cargo.toml` (single crate or multi-crate `[workspace]`) using `tomllib`,
        expands workspace member globs, resolves local `path` dependencies, and computes
        dependency-first topological build order.
        """
        root_toml = os.path.join(repo_path, "Cargo.toml")
        if tomllib is None or not os.path.isfile(root_toml):
            return {"has_cargo": False, "is_workspace": False, "ordered_crates": [], "path_edges": []}

        def _load_toml(p: str) -> Dict[str, Any]:
            with open(p, "rb") as tf:
                return tomllib.load(tf)

        root_data = _load_toml(root_toml)
        ws_tbl = root_data.get("workspace")
        is_workspace = isinstance(ws_tbl, dict)
        crate_dirs: List[str] = []
        if is_workspace:
            excludes = {
                os.path.abspath(os.path.join(repo_path, ex))
                for ex in ws_tbl.get("exclude", [])
                if isinstance(ex, str)
            }
            for pat in ws_tbl.get("members", []) or []:
                if not isinstance(pat, str):
                    continue
                for hit in sorted(glob.glob(os.path.join(repo_path, pat))):
                    abs_h = os.path.abspath(hit)
                    if abs_h not in excludes and os.path.isfile(os.path.join(abs_h, "Cargo.toml")):
                        if abs_h not in crate_dirs:
                            crate_dirs.append(abs_h)
        if isinstance(root_data.get("package"), dict):
            abs_r = os.path.abspath(repo_path)
            if abs_r not in crate_dirs:
                crate_dirs.insert(0, abs_r)

        ws_deps = (ws_tbl.get("dependencies") or {}) if is_workspace else {}
        crates_by_name: Dict[str, Dict[str, Any]] = {}
        external_deps_all: List[str] = []
        for cdir in crate_dirs:
            cdata = _load_toml(os.path.join(cdir, "Cargo.toml"))
            pkg = cdata.get("package") or {}
            raw_name = str(pkg.get("name") or os.path.basename(cdir))
            crate_ident = raw_name.replace("-", "_")
            lib_tbl = cdata.get("lib") or {}
            if isinstance(lib_tbl, dict) and lib_tbl.get("path"):
                entry_rs = os.path.abspath(os.path.join(cdir, str(lib_tbl["path"])))
            elif os.path.isfile(os.path.join(cdir, "src", "lib.rs")):
                entry_rs = os.path.abspath(os.path.join(cdir, "src", "lib.rs"))
            else:
                entry_rs = os.path.abspath(os.path.join(cdir, "src", "main.rs"))
            crate_types = list(lib_tbl.get("crate-type") or ["rlib"]) if isinstance(lib_tbl, dict) else ["rlib"]
            is_proc_macro = bool(lib_tbl.get("proc-macro", False)) if isinstance(lib_tbl, dict) else False
            deps = cdata.get("dependencies") or {}
            local_deps: List[Tuple[str, str]] = []
            ext_deps: List[str] = []
            for dep_name, dep_spec in deps.items():
                eff_spec = ws_deps.get(dep_name, dep_spec) if (isinstance(dep_spec, dict) and dep_spec.get("workspace")) else dep_spec
                if isinstance(eff_spec, dict) and isinstance(eff_spec.get("path"), str):
                    dep_base = os.path.abspath(repo_path) if (isinstance(dep_spec, dict) and dep_spec.get("workspace")) else cdir
                    dep_dir = os.path.abspath(os.path.join(dep_base, eff_spec["path"]))
                    dep_ident = dep_name.replace("-", "_")
                    if os.path.isfile(os.path.join(dep_dir, "Cargo.toml")):
                        d_toml = _load_toml(os.path.join(dep_dir, "Cargo.toml"))
                        dp_name = str((d_toml.get("package") or {}).get("name") or dep_name)
                        dep_ident = dp_name.replace("-", "_")
                    local_deps.append((dep_ident, dep_dir))
                else:
                    ext_deps.append(dep_name)
                    if dep_name not in external_deps_all:
                        external_deps_all.append(dep_name)
            crates_by_name[crate_ident] = {
                "crate_name": crate_ident,
                "package_name": raw_name,
                "crate_dir": cdir,
                "entry_rs": entry_rs,
                "crate_types": crate_types,
                "proc_macro": is_proc_macro,
                "has_build_rs": os.path.isfile(os.path.join(cdir, "build.rs")),
                "local_deps": local_deps,
                "external_deps": ext_deps,
            }

        # Topological sort (dependencies compiled before consumers)
        ordered: List[Dict[str, Any]] = []
        visiting: set = set()
        visited: set = set()
        edges: List[Tuple[str, str]] = []

        def _visit(cname: str) -> None:
            if cname in visited or cname in visiting or cname not in crates_by_name:
                return
            visiting.add(cname)
            meta = crates_by_name[cname]
            for dep_ident, _ in meta["local_deps"]:
                edges.append((cname, dep_ident))
                if dep_ident in crates_by_name:
                    _visit(dep_ident)
            visiting.discard(cname)
            visited.add(cname)
            ordered.append(meta)

        for cname in sorted(crates_by_name.keys()):
            _visit(cname)

        lock_info = self.inspect_cargo_lock(repo_path)
        return {
            "has_cargo": True,
            "is_workspace": is_workspace,
            "workspace_root": os.path.abspath(repo_path),
            "ordered_crates": ordered,
            "path_edges": edges,
            "external_deps": external_deps_all,
            "has_build_rs": bool(lock_info["has_build_rs"] or any(c["has_build_rs"] for c in ordered)),
            "has_vendor": lock_info["has_vendor"],
            "has_cargo_lock": lock_info["has_cargo_lock"],
            "lock_packages": lock_info["packages"],
        }

    def _compile_cargo_workspace(self, repo_path: str, repo_name: str) -> List[FederatedUnitArtifact]:
        """Resolves `Cargo.toml` / `Cargo.lock` workspaces and compiles via `cargo` or `rustc`."""
        info = self.inspect_cargo_workspace(repo_path)
        self._last_cargo_workspaces[repo_name] = info
        if not info.get("has_cargo") or not info.get("ordered_crates"):
            return []

        rustc_bin = self.native_tools.get("rustc")
        use_wsl_rust = False
        if not rustc_bin and self.target_os == "linux" and self.wsl_tools.get("rustc"):
            rustc_bin = self.wsl_tools["rustc"]
            use_wsl_rust = True
        if not rustc_bin:
            return []

        cargo_bin = self.native_tools.get("cargo") if not use_wsl_rust else self.wsl_tools.get("cargo")
        needs_cargo_driver = bool(info.get("external_deps") or info.get("has_build_rs") or info.get("has_vendor"))
        artifacts: List[FederatedUnitArtifact] = []
        if cargo_bin and needs_cargo_driver:
            with tempfile.TemporaryDirectory() as c_td:
                offline_args = ["--offline"] if (info.get("has_vendor") or info.get("has_cargo_lock")) else []
                t0 = time.perf_counter()
                if use_wsl_rust:
                    off_s = " --offline" if offline_args else ""
                    cmd_c = [
                        "wsl", "bash", "-lc",
                        f"cd '{_to_wsl_path(repo_path)}' && CARGO_TARGET_DIR='{_to_wsl_path(c_td)}' '{cargo_bin}' build --release{off_s}",
                    ]
                else:
                    env_c = dict(os.environ)
                    env_c["CARGO_TARGET_DIR"] = c_td
                    cmd_c = [cargo_bin, "build", "--release", *offline_args, "--manifest-path", os.path.join(repo_path, "Cargo.toml")]
                    proc_c = subprocess.run(cmd_c, env=env_c, cwd=repo_path, capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL)
                if use_wsl_rust:
                    proc_c = subprocess.run(cmd_c, capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL)
                if proc_c.returncode != 0:
                    info["cargo_build_stderr"] = (proc_c.stderr or proc_c.stdout or "").strip()
                if proc_c.returncode == 0:
                    rel_dir = os.path.join(c_td, "release")
                    for fn in sorted(os.listdir(rel_dir)) if os.path.isdir(rel_dir) else []:
                        fp = os.path.join(rel_dir, fn)
                        if fn.endswith((".a", ".lib")) and os.path.isfile(fp):
                            with open(fp, "rb") as af:
                                ar_bytes = af.read()
                            if ar_bytes.startswith(b"!<arch>\n"):
                                syms, ar_fmt = self._inspect_archive_exports(ar_bytes, self.target_os, repo_name)
                                artifacts.append(
                                    FederatedUnitArtifact(
                                        source_path=fp,
                                        repo_name=repo_name,
                                        language="rust",
                                        artifact_kind="static_archive",
                                        payload=ar_bytes,
                                        defined_symbols=syms,
                                        toolchain_used="cargo:build",
                                        compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                                        object_format=ar_fmt,
                                    )
                                )
                    if artifacts:
                        return artifacts
        with tempfile.TemporaryDirectory() as td:
            built_rlibs: Dict[str, str] = {}
            for meta in info["ordered_crates"]:
                entry_rs = meta["entry_rs"]
                if not os.path.isfile(entry_rs):
                    continue
                t0 = time.perf_counter()
                cname = meta["crate_name"]
                out_bc = os.path.join(td, f"{cname}.bc")
                out_rlib = os.path.join(td, f"lib{cname}.rlib")
                # Build rlib (plus LLVM bitcode) in topological order using --extern for local path deps
                extern_flags: List[str] = []
                for dep_ident, _ in meta["local_deps"]:
                    if dep_ident in built_rlibs:
                        extern_flags.extend(["--extern", f"{dep_ident}={_to_wsl_path(built_rlibs[dep_ident]) if use_wsl_rust else built_rlibs[dep_ident]}"])
                if use_wsl_rust:
                    ext_str = " ".join(shlex.quote(x) for x in extern_flags)
                    wsl_td = _to_wsl_path(td)
                    wsl_src = _to_wsl_path(entry_rs)
                    cmd = [
                        "wsl", "bash", "-lc",
                        f"'{rustc_bin}' --crate-name {cname} --crate-type rlib --emit=link,llvm-bc -C opt-level=3 {ext_str} -L dependency='{wsl_td}' '{wsl_src}' --out-dir '{wsl_td}'",
                    ]
                else:
                    cmd = [
                        rustc_bin, "--crate-name", cname, "--crate-type", "rlib",
                        "--emit=link,llvm-bc", "-C", "opt-level=3",
                        *extern_flags, "-L", f"dependency={td}", entry_rs, "--out-dir", td,
                    ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45, stdin=subprocess.DEVNULL)
                if proc.returncode == 0 and os.path.isfile(out_bc):
                    if os.path.isfile(out_rlib):
                        built_rlibs[cname] = out_rlib
                    with open(out_bc, "rb") as bf:
                        payload = bf.read()
                    syms = self._inspect_bitcode_exports(payload)
                    artifacts.append(
                        FederatedUnitArtifact(
                            source_path=entry_rs,
                            repo_name=repo_name,
                            language="rust",
                            artifact_kind="bitcode",
                            payload=payload,
                            defined_symbols=syms,
                            toolchain_used="cargo+rustc" if cargo_bin else "rustc",
                            compile_ms=round((time.perf_counter() - t0) * 1000.0, 2),
                            object_format="llvm_bc",
                        )
                    )
        return artifacts

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
        go_files: List[str] = []
        for root, _, files in os.walk(repo_path):
            if any(skip in root for skip in (".git", "vendor", "target", "build")):
                continue
            for fn in files:
                if fn.endswith(".go") and not fn.endswith("_test.go"):
                    go_files.append(os.path.join(root, fn))
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
                if use_wsl_go:
                    cmd = [
                        "wsl", "bash", "-lc",
                        f"cd '{_to_wsl_path(repo_path)}' && CGO_ENABLED=1 '{go_bin}' build -buildmode=c-archive -o '{_to_wsl_path(out_a)}' .",
                    ]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
                else:
                    cmd = [go_bin, "build", "-buildmode=c-archive", "-o", out_a, "."]
                    proc = subprocess.run(cmd, cwd=repo_path, env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
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
            if use_wsl_go:
                cmd_w = [
                    "wsl", "bash", "-lc",
                    f"cd '{_to_wsl_path(repo_path)}' && GOOS=wasip1 GOARCH=wasm '{go_bin}' build -o '{_to_wsl_path(out_wasm)}' .",
                ]
                proc_w = subprocess.run(cmd_w, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            else:
                env_w = dict(os.environ)
                env_w["GOOS"] = "wasip1"
                env_w["GOARCH"] = "wasm"
                cmd_w = [go_bin, "build", "-o", out_wasm, "."]
                proc_w = subprocess.run(cmd_w, cwd=repo_path, env=env_w, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
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

    def _resolve_pkg_config(self, packages: Sequence[str], pkg_config_path: str = "") -> Tuple[List[str], List[str]]:
        """Resolves `--cflags` and `--libs` via native or WSL2 `pkg-config`."""
        cflags: List[str] = []
        libs: List[str] = []
        pkgs = [str(p).strip() for p in packages if str(p).strip()]
        if not pkgs:
            return cflags, libs
        pk_bin = self.native_tools.get("pkg-config")
        use_wsl_pk = False
        if not pk_bin and self.target_os == "linux" and sys.platform == "win32" and self.wsl_tools.get("wsl"):
            chk = subprocess.run(["wsl", "which", "pkg-config"], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
            if chk.returncode == 0 and chk.stdout.strip():
                pk_bin = chk.stdout.strip()
                use_wsl_pk = True
        if not pk_bin:
            return cflags, libs
        try:
            if use_wsl_pk:
                env_pfx = f"PKG_CONFIG_PATH='{_to_wsl_path(pkg_config_path)}' " if pkg_config_path else ""
                p_str = " ".join(shlex.quote(p) for p in pkgs)
                proc = subprocess.run(
                    ["wsl", "bash", "-lc", f"{env_pfx}'{pk_bin}' --cflags --libs {p_str}"],
                    capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL,
                )
            else:
                env_pk = dict(os.environ)
                if pkg_config_path:
                    env_pk["PKG_CONFIG_PATH"] = pkg_config_path
                proc = subprocess.run(
                    [pk_bin, "--cflags", "--libs", *pkgs],
                    env=env_pk, capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL,
                )
            if proc.returncode == 0:
                for tok in shlex.split(proc.stdout):
                    if tok.startswith("-l"):
                        lib_name = tok[2:]
                        if lib_name and lib_name not in libs:
                            libs.append(lib_name)
                        if lib_name and lib_name not in self.discovered_external_libs:
                            self.discovered_external_libs.append(lib_name)
                    elif tok.startswith(("-I", "-D", "-std=")):
                        if tok not in cflags:
                            cflags.append(tok)
        except Exception:
            pass
        return cflags, libs

    def _collect_meson_units(self, repo_path: str) -> Tuple[bool, List[Tuple[str, List[str]]]]:
        """
        Detects and parses `meson.build` trees (running `meson setup` when available,
        otherwise recursively parsing `include_directories`, `dependency`, `files`,
        `library`/`shared_library`/`executable`, and `subdir`).
        """
        meson_file = os.path.join(repo_path, "meson.build")
        if not os.path.isfile(meson_file):
            return False, []

        meson_bin = self.native_tools.get("meson")
        can_native_meson = bool(meson_bin and self.native_tools.get("ninja")) and (
            (sys.platform != "win32" and (self.native_tools.get("gcc") or self.native_tools.get("clang")))
            or (sys.platform == "win32" and self.target_os == "windows" and (self.native_tools.get("clang") or self.native_tools.get("gcc")))
        )
        if can_native_meson and meson_bin:
            with tempfile.TemporaryDirectory() as bdir:
                proc = subprocess.run([meson_bin, "setup", bdir, repo_path], capture_output=True, text=True, timeout=45, stdin=subprocess.DEVNULL)
                cc_p = os.path.join(bdir, "compile_commands.json")
                if proc.returncode == 0 and os.path.isfile(cc_p):
                    parsed = self._parse_compile_commands_file(cc_p, repo_path)
                    if parsed:
                        return True, parsed

        units: List[Tuple[str, List[str]]] = []
        seen_src: set = set()
        visited_dirs: set = set()

        def _walk_meson(cur_dir: str, inh_flags: List[str]) -> None:
            norm_d = os.path.abspath(cur_dir)
            if norm_d in visited_dirs:
                return
            visited_dirs.add(norm_d)
            mpath = os.path.join(norm_d, "meson.build")
            if not os.path.isfile(mpath):
                return
            try:
                with open(mpath, "r", encoding="utf-8", errors="ignore") as mf:
                    mtxt = mf.read()
            except OSError:
                return
            clean = re.sub(r"#.*", "", mtxt)
            cur_flags = list(inh_flags)
            inc_f = f"-I{norm_d}"
            if inc_f not in cur_flags:
                cur_flags.append(inc_f)
            for m_inc in re.finditer(r"include_directories\s*\(([^)]+)\)", clean):
                for raw_d in re.findall(r"['\"]([^'\"]+)['\"]", m_inc.group(1)):
                    cand = os.path.abspath(os.path.join(norm_d, raw_d))
                    if os.path.isdir(cand) and f"-I{cand}" not in cur_flags:
                        cur_flags.append(f"-I{cand}")
            for m_std in re.finditer(r"cpp_std\s*=\s*(c\+\+\d+)", clean):
                if f"-std={m_std.group(1)}" not in cur_flags:
                    cur_flags.append(f"-std={m_std.group(1)}")
            for m_arg in re.finditer(r"(?:add_project_arguments|c_args|cpp_args)\s*[\(:]([^\n\)]+)", clean):
                for arg in re.findall(r"['\"]([^'\"]+)['\"]", m_arg.group(1)):
                    if arg.startswith(("-D", "-I", "-std=")) and arg not in cur_flags:
                        cur_flags.append(arg)
            dep_pkgs = re.findall(r"dependency\s*\(\s*['\"]([^'\"]+)['\"]", clean)
            if dep_pkgs:
                pc_flags, _ = self._resolve_pkg_config(dep_pkgs, pkg_config_path=norm_d)
                for pf in pc_flags:
                    if pf not in cur_flags:
                        cur_flags.append(pf)
            for m_src in re.finditer(r"['\"]([A-Za-z0-9_./\\-]+\.(?:cpp|cxx|cc|c))['\"]", clean):
                full_s = os.path.abspath(os.path.join(norm_d, m_src.group(1)))
                if os.path.isfile(full_s) and full_s not in seen_src:
                    seen_src.add(full_s)
                    units.append((full_s, list(cur_flags)))
            for m_sub in re.finditer(r"subdir\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", clean):
                _walk_meson(os.path.join(norm_d, m_sub.group(1)), cur_flags)

        _walk_meson(repo_path, [])
        return bool(units), units

    def _collect_makefile_units(self, repo_path: str) -> Tuple[bool, List[Tuple[str, List[str]]]]:
        """Parses standard `Makefile` / `GNUmakefile` variables (`CFLAGS`, `CPPFLAGS`, `SRCS`, `wildcard`)."""
        mk_path = next(
            (os.path.join(repo_path, fn) for fn in ("GNUmakefile", "Makefile", "makefile") if os.path.isfile(os.path.join(repo_path, fn))),
            None,
        )
        if not mk_path:
            return False, []
        try:
            with open(mk_path, "r", encoding="utf-8", errors="ignore") as mf:
                raw = mf.read()
        except OSError:
            return False, []

        joined = re.sub(r"\\\r?\n", " ", raw)
        clean = re.sub(r"#.*", "", joined)
        mk_vars: Dict[str, str] = {}
        for line in clean.splitlines():
            m_asg = re.match(r"^\s*([A-Za-z0-9_]+)\s*(\+?=|:=)\s*(.+)$", line)
            if not m_asg:
                continue
            k, op, val = m_asg.group(1), m_asg.group(2), m_asg.group(3).strip()
            val = re.sub(
                r"\$\(wildcard\s+([^)]+)\)",
                lambda wm: " ".join(sorted(glob.glob(os.path.join(repo_path, wm.group(1).strip())))),
                val,
            )
            val = re.sub(r"\$\(([A-Za-z0-9_]+)\)", lambda vm: mk_vars.get(vm.group(1), ""), val)
            if op == "+=" and k in mk_vars:
                mk_vars[k] = mk_vars[k] + " " + val
            else:
                mk_vars[k] = val

        flags: List[str] = [f"-I{os.path.abspath(repo_path)}"]
        for vname in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "INCLUDES"):
            for tok in mk_vars.get(vname, "").split():
                if tok.startswith("-I"):
                    inc_p = tok[2:]
                    cand = inc_p if os.path.isabs(inc_p) else os.path.abspath(os.path.join(repo_path, inc_p))
                    fi = f"-I{cand}"
                    if os.path.isdir(cand) and fi not in flags:
                        flags.append(fi)
                elif tok.startswith(("-D", "-std=")) and tok not in flags:
                    flags.append(tok)

        for vname in ("LDFLAGS", "LDLIBS", "LIBS"):
            for tok in mk_vars.get(vname, "").split():
                if tok.startswith("-l") and len(tok) > 2:
                    lname = tok[2:]
                    if lname not in self.discovered_external_libs:
                        self.discovered_external_libs.append(lname)

        src_units: List[Tuple[str, List[str]]] = []
        seen_src: set = set()
        cand_blobs = " ".join(mk_vars.values()) + "\n" + clean
        src_exts = (".c", ".cc", ".cpp", ".cxx")
        for tok in cand_blobs.replace("=", " ").split():
            raw_s = tok.strip("\"'();,:")
            if os.path.splitext(raw_s)[1].lower() not in src_exts:
                continue
            full_s = raw_s if os.path.isabs(raw_s) else os.path.abspath(os.path.join(repo_path, raw_s))
            if os.path.isfile(full_s) and full_s not in seen_src:
                seen_src.add(full_s)
                src_units.append((full_s, list(flags)))
        return bool(src_units), src_units

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

            # 1b-2. Meson (`meson.build`) & Makefile (`Makefile`/`GNUmakefile`) build system integration
            if os.path.isfile(os.path.join(repo_dir, "meson.build")):
                _ms_ok, ms_units = self._collect_meson_units(repo_dir)
                for fpath, flags in ms_units:
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

            if any(os.path.isfile(os.path.join(repo_dir, fn)) for fn in ("GNUmakefile", "Makefile", "makefile")):
                _mk_ok, mk_units = self._collect_makefile_units(repo_dir)
                for fpath, flags in mk_units:
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

            # 1d. Cargo.toml multi-crate workspace topological resolution & compilation
            if os.path.isfile(os.path.join(repo_dir, "Cargo.toml")):
                cargo_arts = self._compile_cargo_workspace(repo_dir, repo_name)
                for cart in cargo_arts:
                    seen_paths.add(os.path.abspath(cart.source_path))
                    artifacts.append(cart)

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
