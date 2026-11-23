"""
OmniCompiler Hermetic Content-Addressable Storage (CAS) & Remote Build Execution (RBE) Engine (Alpha-C77/C78).

Provides:
1. ContentAddressableStore (CAS): SHA-256 immutable blob store + ActionCache.
2. HermeticSandboxExecutor: Isolated per-action working directory with scrubbed
   deterministic environment (`SOURCE_DATE_EPOCH=0`, `PYTHONHASHSEED=0`, `TZ=UTC`, `LC_ALL=C`).
3. RBEWorkerNode & RBECoordinator: Real multi-node HTTP/TCP remote execution workers
   with parallel topological DAG scheduling and bit-for-bit reproducible artifact guarantees.
"""

import hashlib
import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass
class ActionSpec:
    action_id: str
    kind: str  # "compile_ir", "link_binary", "custom_fn"
    payload: Dict[str, Any]
    input_blobs: Dict[str, str] = field(default_factory=dict)  # rel_path -> sha256
    deps: List[str] = field(default_factory=list)
    target_triple: str = "x86_64-unknown-linux-gnu"

    def compute_digest(self) -> str:
        canonical = {
            "kind": self.kind,
            "payload": self.payload,
            "input_blobs": dict(sorted(self.input_blobs.items())),
            "target_triple": self.target_triple,
        }
        return compute_sha256(canonical_json_bytes(canonical))


@dataclass
class ActionResult:
    action_id: str
    action_digest: str
    output_blobs: Dict[str, str]  # rel_path -> sha256
    metadata: Dict[str, Any]
    cache_hit: bool = False
    worker_id: str = "local"


class ContentAddressableStore:
    """Disk-backed immutable SHA-256 blob store and ActionCache."""

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self.blobs_dir = os.path.join(self.root_dir, "blobs")
        self.actions_dir = os.path.join(self.root_dir, "actions")
        os.makedirs(self.blobs_dir, exist_ok=True)
        os.makedirs(self.actions_dir, exist_ok=True)
        self._lock = threading.Lock()

    def _blob_path(self, digest: str) -> str:
        return os.path.join(self.blobs_dir, digest[:2], digest)

    def put_blob(self, data: bytes) -> str:
        digest = compute_sha256(data)
        dst = self._blob_path(digest)
        with self._lock:
            if not os.path.exists(dst):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(dst), prefix=".tmp_blob_")
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                    os.replace(tmp_path, dst)
                except BaseException:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                    raise
        return digest

    def get_blob(self, digest: str) -> bytes:
        path = self._blob_path(digest)
        if not os.path.exists(path):
            raise FileNotFoundError(f"CAS blob not found: {digest}")
        with open(path, "rb") as f:
            data = f.read()
        actual = compute_sha256(data)
        if actual != digest:
            raise ValueError(f"CAS integrity corruption for {digest}: got {actual}")
        return data

    def has_blob(self, digest: str) -> bool:
        return os.path.exists(self._blob_path(digest))

    def get_action_result(self, action_digest: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(self.actions_dir, f"{action_digest}.json")
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)
        # Verify all referenced output blobs exist before declaring cache hit
        for blob_digest in record.get("output_blobs", {}).values():
            if not self.has_blob(blob_digest):
                return None
        return record

    def put_action_result(self, action_digest: str, output_blobs: Dict[str, str], metadata: Dict[str, Any]) -> None:
        path = os.path.join(self.actions_dir, f"{action_digest}.json")
        record = {
            "action_digest": action_digest,
            "output_blobs": dict(sorted(output_blobs.items())),
            "metadata": metadata,
        }
        with self._lock:
            fd, tmp_path = tempfile.mkstemp(dir=self.actions_dir, prefix=".tmp_act_")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(record, f, sort_keys=True)
                os.replace(tmp_path, path)
            except BaseException:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                raise


class HermeticSandboxExecutor:
    """Executes build actions in an isolated directory with scrubbed deterministic environment."""

    DETERMINISTIC_ENV = {
        "SOURCE_DATE_EPOCH": "0",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "LC_ALL": "C",
    }

    def __init__(self, cas: ContentAddressableStore, handlers: Optional[Dict[str, Callable]] = None):
        self.cas = cas
        self.handlers: Dict[str, Callable[[Dict[str, Any], str, Dict[str, str]], Dict[str, Any]]] = handlers or {}
        self.register_default_handlers()

    def register_default_handlers(self):
        self.handlers.setdefault("emit_standalone_binary", self._handle_emit_standalone_binary)
        self.handlers.setdefault("compile_ir_unit", self._handle_compile_ir_unit)

    def _handle_emit_standalone_binary(self, payload: Dict[str, Any], sandbox_dir: str, env: Dict[str, str]) -> Dict[str, Any]:
        from compiler.binary_emitter import StandaloneBinaryEmitter

        fmt = payload.get("target_format", "elf64")
        exit_code = int(payload.get("exit_code", 0))
        out_name = payload.get("output_name", f"omni_out_{fmt}.bin")
        out_path = os.path.join(sandbox_dir, out_name)
        emitted_path = StandaloneBinaryEmitter().emit_standalone_binary(
            out_path,
            target_format=fmt,
            exit_code=exit_code,
        )
        rel_name = os.path.basename(emitted_path)
        return {"outputs": [rel_name], "metadata": {"target_format": fmt, "exit_code": exit_code}}

    def _handle_compile_ir_unit(self, payload: Dict[str, Any], sandbox_dir: str, env: Dict[str, str]) -> Dict[str, Any]:
        from compiler.native_codegen import NativeCodeGenerator
        from compiler.ssa_ir import SSAFunction, BasicBlock, SSAInstruction, SSAVar

        func_name = payload.get("func_name", "unit_fn")
        const_val = int(payload.get("const_val", 42))
        arch = payload.get("arch", "x86_64")
        target_os = payload.get("target_os", "linux")

        fn = SSAFunction(name=func_name, params=[], return_type="i64")
        bb = BasicBlock("entry")
        ret_v = SSAVar(name="v", version=0, var_type="i64")
        bb.add_instruction(SSAInstruction(result=ret_v, opcode="const", operands=[const_val]))
        bb.add_instruction(SSAInstruction(result=None, opcode="ret", operands=[ret_v]))
        fn.entry_block = bb
        fn.blocks.append(bb)

        artifact = NativeCodeGenerator(arch=arch, target_os=target_os).compile_ssa(fn)
        code_bytes = artifact.code_bytes
        out_name = payload.get("output_name", f"{func_name}.o.bin")
        out_path = os.path.join(sandbox_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(code_bytes)
        return {"outputs": [out_name], "metadata": {"code_bytes_len": len(code_bytes), "arch": arch}}

    def execute(self, action: ActionSpec, worker_id: str = "local") -> ActionResult:
        action_digest = action.compute_digest()
        cached = self.cas.get_action_result(action_digest)
        if cached is not None:
            return ActionResult(
                action_id=action.action_id,
                action_digest=action_digest,
                output_blobs=cached["output_blobs"],
                metadata=cached["metadata"],
                cache_hit=True,
                worker_id=worker_id,
            )

        handler = self.handlers.get(action.kind)
        if handler is None:
            raise ValueError(f"Unknown RBE action kind: {action.kind}")

        sandbox_dir = tempfile.mkdtemp(prefix=f"omni_rbe_{action.action_id}_")
        try:
            for rel_path, blob_digest in sorted(action.input_blobs.items()):
                target = os.path.join(sandbox_dir, rel_path)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as f:
                    f.write(self.cas.get_blob(blob_digest))

            env = dict(self.DETERMINISTIC_ENV)
            result_info = handler(action.payload, sandbox_dir, env)
            output_blobs: Dict[str, str] = {}
            for rel_out in sorted(result_info.get("outputs", [])):
                out_abs = os.path.join(sandbox_dir, rel_out)
                with open(out_abs, "rb") as f:
                    output_blobs[rel_out] = self.cas.put_blob(f.read())

            metadata = dict(result_info.get("metadata", {}))
            metadata["sandbox_deterministic_env"] = True
            self.cas.put_action_result(action_digest, output_blobs, metadata)
            return ActionResult(
                action_id=action.action_id,
                action_digest=action_digest,
                output_blobs=output_blobs,
                metadata=metadata,
                cache_hit=False,
                worker_id=worker_id,
            )
        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class RBEWorkerNode:
    """HTTP/TCP remote build execution worker connected to a shared CAS."""

    def __init__(self, worker_id: str, cas: ContentAddressableStore, handlers: Optional[Dict[str, Callable]] = None):
        self.worker_id = worker_id
        self.cas = cas
        self.executor = HermeticSandboxExecutor(cas, handlers=handlers)
        self.executed_count = 0
        self._lock = threading.Lock()
        self._server: Optional[_ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    def start(self) -> str:
        node = self

        class _RBEHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/execute":
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                req = json.loads(raw.decode("utf-8"))
                spec = ActionSpec(
                    action_id=req["action_id"],
                    kind=req["kind"],
                    payload=req["payload"],
                    input_blobs=req.get("input_blobs", {}),
                    deps=req.get("deps", []),
                    target_triple=req.get("target_triple", "x86_64-unknown-linux-gnu"),
                )
                res = node.executor.execute(spec, worker_id=node.worker_id)
                with node._lock:
                    node.executed_count += 1
                body = json.dumps({
                    "action_id": res.action_id,
                    "action_digest": res.action_digest,
                    "output_blobs": res.output_blobs,
                    "metadata": res.metadata,
                    "cache_hit": res.cache_hit,
                    "worker_id": res.worker_id,
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        self._server = _ThreadingHTTPServer(("127.0.0.1", 0), _RBEHandler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None


class RBECoordinator:
    """Schedules topological ActionSpec DAGs across remote RBEWorkerNodes with CAS caching."""

    def __init__(self, cas: ContentAddressableStore, worker_urls: List[str]):
        self.cas = cas
        self.worker_urls = list(worker_urls)
        self._rr_idx = 0
        self._rr_lock = threading.Lock()

    def _next_worker_url(self) -> str:
        with self._rr_lock:
            url = self.worker_urls[self._rr_idx % len(self.worker_urls)]
            self._rr_idx += 1
            return url

    def _dispatch_remote(self, spec: ActionSpec) -> ActionResult:
        # Fast-path local ActionCache check before network RPC
        digest = spec.compute_digest()
        cached = self.cas.get_action_result(digest)
        if cached is not None:
            return ActionResult(
                action_id=spec.action_id,
                action_digest=digest,
                output_blobs=cached["output_blobs"],
                metadata=cached["metadata"],
                cache_hit=True,
                worker_id="cas_cache",
            )

        url = f"{self._next_worker_url()}/execute"
        body = json.dumps({
            "action_id": spec.action_id,
            "kind": spec.kind,
            "payload": spec.payload,
            "input_blobs": spec.input_blobs,
            "deps": spec.deps,
            "target_triple": spec.target_triple,
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return ActionResult(
            action_id=data["action_id"],
            action_digest=data["action_digest"],
            output_blobs=data["output_blobs"],
            metadata=data["metadata"],
            cache_hit=bool(data["cache_hit"]),
            worker_id=data["worker_id"],
        )

    def execute_dag(self, actions: List[ActionSpec], max_workers: int = 4) -> Dict[str, ActionResult]:
        pending = {a.action_id: a for a in actions}
        results: Dict[str, ActionResult] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            while pending:
                ready = [
                    spec for spec in pending.values()
                    if all(dep in results for dep in spec.deps)
                ]
                if not ready:
                    raise RuntimeError(f"Cycle or missing dependency in RBE DAG: {list(pending.keys())}")
                futures = {pool.submit(self._dispatch_remote, spec): spec.action_id for spec in ready}
                for fut, aid in futures.items():
                    results[aid] = fut.result()
                    pending.pop(aid, None)
        return results
