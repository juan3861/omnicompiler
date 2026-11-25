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
            flags = [f for f in extra_flags if f.startswith(("-I", "-D", "-std=", "-O"))]
            if "-O" not in " ".join(flags):
                flags.append("-O3")
            if lang == "cpp" and "throw " not in src_txt and "-fexceptions" not in flags:
                flags.extend(["-fno-exceptions", "-fno-rtti"])
            cmd: List[str]
            if use_wsl:
                cmd = ["wsl", cc, *flags, "-emit-llvm", "-c", _to_wsl_path(src_path), "-o", _to_wsl_path(out_bc)]
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
            flags = [f for f in extra_flags if f.startswith(("-I", "-D", "-std=", "-O"))]
            if "-O" not in " ".join(flags):
                flags.append("-O2")
            if lang == "cpp" and "throw " not in src_txt and "-fexceptions" not in flags:
                flags.extend(["-fno-exceptions", "-fno-rtti"])
            pic_flags = ["-fPIC", "-fno-asynchronous-unwind-tables"] if obj_fmt in ("elf", "macho") else ["-fno-asynchronous-unwind-tables"]
            cmd: List[str]
            if use_wsl:
                cmd = ["wsl", cc, *flags, *pic_flags, "-c", _to_wsl_path(src_path), "-o", _to_wsl_path(out_obj)]
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
    def _parse_compile_commands(repo_path: str) -> List[Tuple[str, List[str]]]:
        cc_json = os.path.join(repo_path, "compile_commands.json")
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
            flags = [str(a) for a in (args or []) if isinstance(a, str) and a.startswith(("-I", "-D", "-std=", "-O"))]
            units.append((fpath, flags))
        return units

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
                art = self._compile_c_cpp_to_bitcode(norm_p, repo_name, extra_flags=flags)
                if art is None:
                    art = self._compile_c_cpp_to_object(norm_p, repo_name, extra_flags=flags)
                if art is not None:
                    artifacts.append(art)

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
                            art = self._compile_c_cpp_to_bitcode(fpath, repo_name)
                            if art is None:
                                art = self._compile_c_cpp_to_object(fpath, repo_name)
                            if art is not None and (toolchain_mode == "federated_lto" or not set(art.defined_symbols).issubset(already_lowered)):
                                artifacts.append(art)
                    elif ext == ".rs" and toolchain_mode == "federated_lto":
                        seen_paths.add(fpath)
                        art = self._compile_rust_to_bitcode(fpath, repo_name)
                        if art is not None:
                            artifacts.append(art)

        return artifacts
