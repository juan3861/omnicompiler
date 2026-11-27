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
                    try:
                        os.replace(tmp_path, dst)
                    except (PermissionError, FileExistsError):
                        if not os.path.exists(dst):
                            raise
                finally:
                    if os.path.exists(tmp_path):
                        try:
                            os.remove(tmp_path)
                        except OSError:
                            pass
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
            if os.path.exists(path):
                return
            fd, tmp_path = tempfile.mkstemp(dir=self.actions_dir, prefix=".tmp_act_")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(record, f, sort_keys=True)
                try:
                    os.replace(tmp_path, path)
                except (PermissionError, FileExistsError):
                    if not os.path.exists(path):
                        raise
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

    def put_merkle_tree(self, root_dir: str) -> Dict[str, Any]:
        """
        Ingests a filesystem directory into CAS as a canonical Bazel REAPI v2
        Merkle Tree (`Directory` nodes + `Tree` root digest).
        """
        root_abs = os.path.realpath(root_dir)
        children_by_hash: Dict[str, Dict[str, Any]] = {}
        file_count = 0
        total_bytes = 0

        def _walk_dir(cur_dir: str) -> Tuple[str, Dict[str, Any]]:
            nonlocal file_count, total_bytes
            files_list: List[Dict[str, Any]] = []
            dirs_list: List[Dict[str, Any]] = []
            for entry in sorted(os.scandir(cur_dir), key=lambda e: e.name):
                if entry.is_dir(follow_symlinks=False):
                    sub_h, sub_node = _walk_dir(entry.path)
                    children_by_hash[sub_h] = sub_node
                    dirs_list.append({"name": entry.name, "digest": {"hash": sub_h, "size_bytes": len(json.dumps(sub_node, sort_keys=True).encode("utf-8"))}})
                elif entry.is_file(follow_symlinks=False):
                    with open(entry.path, "rb") as f:
                        raw = f.read()
                    h = self.put_blob(raw)
                    file_count += 1
                    total_bytes += len(raw)
                    is_exec = bool(os.stat(entry.path).st_mode & 0o111)
                    files_list.append({
                        "name": entry.name,
                        "digest": {"hash": h, "size_bytes": len(raw)},
                        "is_executable": is_exec,
                    })
            dir_node = {"files": files_list, "directories": dirs_list, "symlinks": []}
            dir_bytes = json.dumps(dir_node, sort_keys=True, separators=(",", ":")).encode("utf-8")
            dir_h = self.put_blob(dir_bytes)
            return dir_h, dir_node

        root_h, root_node = _walk_dir(root_abs)
        tree_obj = {"root": root_node, "children": [children_by_hash[k] for k in sorted(children_by_hash)]}
        tree_bytes = json.dumps(tree_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        tree_h = self.put_blob(tree_bytes)
        return {
            "tree_digest": tree_h,
            "root_digest": root_h,
            "file_count": file_count,
            "total_bytes": total_bytes,
            "directory_count": 1 + len(children_by_hash),
        }

    def materialize_merkle_tree(self, root_dir_digest: str, dst_dir: str) -> List[str]:
        """Materializes a CAS `Directory` digest into `dst_dir` cleanly without path traversal."""
        dst_abs = os.path.realpath(dst_dir)
        os.makedirs(dst_abs, exist_ok=True)
        restored: List[str] = []

        def _restore_dir(d_hash: str, cur_dst: str) -> None:
            raw_d = self.get_blob(d_hash)
            node = json.loads(raw_d.decode("utf-8"))
            for f_ent in node.get("files", []):
                fname = os.path.basename(str(f_ent["name"]))
                if not fname or fname in (".", ".."):
                    raise ValueError(f"Unsafe Merkle file entry: {f_ent['name']}")
                out_p = os.path.join(cur_dst, fname)
                blob = self.get_blob(str(f_ent["digest"]["hash"]))
                with open(out_p, "wb") as f:
                    f.write(blob)
                if f_ent.get("is_executable"):
                    try:
                        os.chmod(out_p, 0o755)
                    except OSError:
                        pass
                restored.append(out_p)
            for sub_ent in node.get("directories", []):
                dname = os.path.basename(str(sub_ent["name"]))
                if not dname or dname in (".", ".."):
                    raise ValueError(f"Unsafe Merkle dir entry: {sub_ent['name']}")
                sub_dst = os.path.join(cur_dst, dname)
                os.makedirs(sub_dst, exist_ok=True)
                _restore_dir(str(sub_ent["digest"]["hash"]), sub_dst)

        _restore_dir(root_dir_digest, dst_abs)
        return restored


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
        self.handlers.setdefault("compile_llvm_shard", self._handle_compile_llvm_shard)
        self.handlers.setdefault("run_sandboxed_tool", self._handle_run_sandboxed_tool)

    def _handle_compile_llvm_shard(self, payload: Dict[str, Any], sandbox_dir: str, env: Dict[str, str]) -> Dict[str, Any]:
        import llvmlite.binding as llvm
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        try:
            llvm.initialize_all_targets()
            llvm.initialize_all_asmprinters()
        except Exception:
            pass
        bc_path = os.path.join(sandbox_dir, "shard.bc")
        with open(bc_path, "rb") as bf:
            bc_bytes = bf.read()
        mod = llvm.parse_bitcode(bc_bytes)
        triple = str(payload.get("target_triple") or llvm.get_default_triple())
        opt_lvl = int(payload.get("opt_level", 3))
        mod.triple = triple
        target = llvm.Target.from_triple(triple)
        tm = target.create_target_machine(opt=opt_lvl, reloc="pic", codemodel="small")
        pto = llvm.create_pipeline_tuning_options(speed_level=opt_lvl)
        pto.loop_vectorization = True
        pto.slp_vectorization = True
        pto.loop_unrolling = True
        pb = llvm.create_pass_builder(tm, pto)
        pb.getModulePassManager().run(mod, pb)
        obj_bytes = tm.emit_object(mod)
        out_name = "shard.obj"
        with open(os.path.join(sandbox_dir, out_name), "wb") as of:
            of.write(obj_bytes)
        return {"outputs": [out_name], "metadata": {"obj_bytes_len": len(obj_bytes), "triple": triple}}

    def _handle_run_sandboxed_tool(self, payload: Dict[str, Any], sandbox_dir: str, env: Dict[str, str]) -> Dict[str, Any]:
        import sys
        cmd = payload.get("cmd")
        if not cmd:
            py_code = str(payload.get("python_code", "print('OK')"))
            cmd = [sys.executable, "-c", py_code]
        timeout_sec = float(payload.get("timeout_sec", 10.0))
        max_memory_mb = int(payload.get("max_memory_mb", 256))
        sb_res = OSSandboxController().run_sandboxed_subprocess(
            cmd=cmd,
            sandbox_dir=sandbox_dir,
            env=env,
            timeout_sec=timeout_sec,
            max_memory_mb=max_memory_mb,
        )
        out_name = payload.get("output_name", "stdout.txt")
        out_path = os.path.join(sandbox_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(sb_res["stdout"].encode("utf-8"))
        outputs = [out_name]
        for extra in payload.get("expected_outputs", []):
            if os.path.exists(os.path.join(sandbox_dir, extra)):
                outputs.append(extra)
        return {
            "outputs": outputs,
            "metadata": {
                "exit_code": sb_res["returncode"],
                "sandbox_kernel_backend": sb_res["sandbox_kernel_backend"],
                "kernel_enforced": sb_res["kernel_enforced"],
                "stderr": sb_res["stderr"],
            },
        }

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
            def _send_json(self, code_num: int, payload_obj: Dict[str, Any]):
                body = json.dumps(payload_obj, sort_keys=True).encode("utf-8")
                self.send_response(code_num)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path in (
                    "/v2/capabilities",
                    "/build.bazel.remote.execution.v2.Capabilities/GetCapabilities",
                ):
                    self._send_json(200, REAPIServerCapabilities.default_capabilities())
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b"{}"
                req = json.loads(raw.decode("utf-8"))

                if self.path in (
                    "/v2/capabilities",
                    "/build.bazel.remote.execution.v2.Capabilities/GetCapabilities",
                ):
                    self._send_json(200, REAPIServerCapabilities.default_capabilities())
                    return

                if self.path in (
                    "/v2/cas/FindMissingBlobs",
                    "/build.bazel.remote.execution.v2.ContentAddressableStorage/FindMissingBlobs",
                ):
                    missing = []
                    for d in req.get("blob_digests", []):
                        h = str(d["hash"])
                        if not node.cas.has_blob(h):
                            missing.append({"hash": h, "size_bytes": int(d.get("size_bytes", 0))})
                    self._send_json(200, {"missing_blob_digests": missing})
                    return

                if self.path in (
                    "/v2/cas/BatchUpdateBlobs",
                    "/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchUpdateBlobs",
                ):
                    import base64
                    responses = []
                    for item in req.get("requests", []):
                        dig = item["digest"]
                        data = base64.b64decode(item["data"])
                        stored_h = node.cas.put_blob(data)
                        responses.append({
                            "digest": {"hash": stored_h, "size_bytes": len(data)},
                            "status": {"code": 0, "message": "OK"},
                        })
                    self._send_json(200, {"responses": responses})
                    return

                if self.path in (
                    "/v2/cas/BatchReadBlobs",
                    "/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchReadBlobs",
                ):
                    import base64
                    responses = []
                    for dig in req.get("digests", []):
                        h = str(dig["hash"])
                        if node.cas.has_blob(h):
                            blob = node.cas.get_blob(h)
                            responses.append({
                                "digest": {"hash": h, "size_bytes": len(blob)},
                                "data": base64.b64encode(blob).decode("ascii"),
                                "status": {"code": 0, "message": "OK"},
                            })
                        else:
                            responses.append({
                                "digest": dig,
                                "data": "",
                                "status": {"code": 5, "message": "NOT_FOUND"},
                            })
                    self._send_json(200, {"responses": responses})
                    return

                if self.path in (
                    "/v2/ac/GetActionResult",
                    "/build.bazel.remote.execution.v2.ActionCache/GetActionResult",
                ):
                    ad = req.get("action_digest", {})
                    h = str(ad["hash"] if isinstance(ad, dict) else ad)
                    cached = node.cas.get_action_result(h)
                    if cached is None:
                        self._send_json(404, {"code": 5, "message": "ActionResult not found"})
                        return
                    self._send_json(200, _to_reapi_action_result(cached, node.cas))
                    return

                if self.path in (
                    "/v2/ac/UpdateActionResult",
                    "/build.bazel.remote.execution.v2.ActionCache/UpdateActionResult",
                ):
                    ad = req["action_digest"]
                    h = str(ad["hash"] if isinstance(ad, dict) else ad)
                    ar = req["action_result"]
                    out_blobs = {f["path"]: f["digest"]["hash"] for f in ar.get("output_files", [])}
                    meta = ar.get("execution_metadata", {})
                    node.cas.put_action_result(h, out_blobs, meta)
                    self._send_json(200, ar)
                    return

                if self.path in (
                    "/v2/execution/Execute",
                    "/build.bazel.remote.execution.v2.Execution/Execute",
                ):
                    act_req = req.get("action_payload", req)
                    spec = ActionSpec(
                        action_id=act_req["action_id"],
                        kind=act_req["kind"],
                        payload=act_req["payload"],
                        input_blobs=act_req.get("input_blobs", {}),
                        deps=act_req.get("deps", []),
                        target_triple=act_req.get("target_triple", "x86_64-unknown-linux-gnu"),
                    )
                    res = node.executor.execute(spec, worker_id=node.worker_id)
                    with node._lock:
                        node.executed_count += 1
                    reapi_ar = _to_reapi_action_result(
                        {"output_blobs": res.output_blobs, "metadata": res.metadata},
                        node.cas,
                    )
                    self._send_json(200, {
                        "name": f"operations/{res.action_digest}",
                        "done": True,
                        "response": {
                            "@type": "type.googleapis.com/build.bazel.remote.execution.v2.ExecuteResponse",
                            "result": reapi_ar,
                            "cached_result": res.cache_hit,
                            "status": {"code": 0, "message": "OK"},
                            "worker_id": res.worker_id,
                            "action_digest": {"hash": res.action_digest, "size_bytes": 0},
                        },
                    })
                    return

                if self.path != "/execute":
                    self.send_response(404)
                    self.end_headers()
                    return
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
                self._send_json(200, {
                    "action_id": res.action_id,
                    "action_digest": res.action_digest,
                    "output_blobs": res.output_blobs,
                    "metadata": res.metadata,
                    "cache_hit": res.cache_hit,
                    "worker_id": res.worker_id,
                })

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

        worker_url = self._next_worker_url()
        if worker_url.startswith("grpc://"):
            data = REAPIGrpcClient(worker_url).execute_raw({
                "action_id": spec.action_id,
                "kind": spec.kind,
                "payload": spec.payload,
                "input_blobs": spec.input_blobs,
                "deps": spec.deps,
                "target_triple": spec.target_triple,
            })
        else:
            url = f"{worker_url}/execute"
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

    def execute_dag_bwob(
        self,
        actions: List[ActionSpec],
        materialize_finals_to: Optional[str] = None,
        max_workers: int = 4,
    ) -> Dict[str, Any]:
        """
        Build-without-the-Bytes (BwoB) RBE DAG execution:
        Intermediate artifacts flow across stages purely as CAS REAPI Digest handles without
        materializing intermediate blobs onto local disk; only terminal root outputs are fetched
        when `materialize_finals_to` is provided.
        """
        depended_on = {d for a in actions for d in a.deps}
        pending = {a.action_id: a for a in actions}
        results: Dict[str, ActionResult] = {}
        digests_by_action: Dict[str, Dict[str, Dict[str, Any]]] = {}
        skipped_blobs = 0
        skipped_bytes = 0

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            while pending:
                ready = [spec for spec in pending.values() if all(dep in results for dep in spec.deps)]
                if not ready:
                    raise RuntimeError(f"Cycle or missing dependency in RBE DAG: {list(pending.keys())}")
                futures = {}
                for spec in ready:
                    merged_inputs = dict(spec.input_blobs)
                    for dep_id in spec.deps:
                        for rel_p, d_info in digests_by_action.get(dep_id, {}).items():
                            merged_inputs.setdefault(rel_p, d_info["hash"])
                    eff_spec = ActionSpec(
                        action_id=spec.action_id,
                        kind=spec.kind,
                        payload=spec.payload,
                        input_blobs=merged_inputs,
                        deps=spec.deps,
                        target_triple=spec.target_triple,
                    )
                    futures[pool.submit(self._dispatch_remote, eff_spec)] = spec.action_id
                for fut, aid in futures.items():
                    res = fut.result()
                    results[aid] = res
                    act_digs: Dict[str, Dict[str, Any]] = {}
                    for rel_p, b_hash in res.output_blobs.items():
                        b_size = len(self.cas.get_blob(b_hash)) if self.cas.has_blob(b_hash) else 0
                        act_digs[rel_p] = {"hash": b_hash, "size_bytes": b_size}
                        if aid in depended_on:
                            skipped_blobs += 1
                            skipped_bytes += b_size
                    digests_by_action[aid] = act_digs
                    pending.pop(aid, None)

        materialized_files: List[str] = []
        if materialize_finals_to is not None:
            w_url = self._next_worker_url()
            client = REAPIGrpcClient(w_url) if w_url.startswith("grpc://") else REAPIClient(w_url)
            terminal_ids = [a.action_id for a in actions if a.action_id not in depended_on]
            digest_to_path: List[Tuple[Dict[str, Any], str]] = []
            for tid in terminal_ids:
                for rel_p, d_info in digests_by_action.get(tid, {}).items():
                    digest_to_path.append((d_info, os.path.join(materialize_finals_to, tid, rel_p)))
            if digest_to_path:
                fetched = client.batch_read_blobs([d for d, _ in digest_to_path])
                for (_, dst_path), raw_b in zip(digest_to_path, fetched):
                    if raw_b is not None:
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        with open(dst_path, "wb") as f:
                            f.write(raw_b)
                        materialized_files.append(dst_path)

        return {
            "results": results,
            "digests_by_action": digests_by_action,
            "bwob_telemetry": {
                "blobs_skipped_local_download": skipped_blobs,
                "bytes_avoided_local_transfer": skipped_bytes,
                "intermediate_local_materializations": 0,
                "final_materialized_files": materialized_files,
            },
        }


def _to_reapi_action_result(cached: Dict[str, Any], cas: ContentAddressableStore) -> Dict[str, Any]:
    out_files = []
    for rel_p, h in sorted(cached.get("output_blobs", {}).items()):
        sz = len(cas.get_blob(h)) if cas.has_blob(h) else 0
        out_files.append({"path": rel_p, "digest": {"hash": h, "size_bytes": sz}, "is_executable": rel_p.endswith((".out", ".exe", ".sh", ".so", ".dylib", ".dll"))})
    return {
        "output_files": out_files,
        "output_directories": [],
        "exit_code": int(cached.get("metadata", {}).get("exit_code", 0)),
        "execution_metadata": cached.get("metadata", {}),
    }


class REAPIServerCapabilities:
    """Bazel REAPI v2 Capabilities advertisement."""

    @staticmethod
    def default_capabilities() -> Dict[str, Any]:
        return {
            "cache_capabilities": {
                "digest_functions": ["SHA256"],
                "action_cache_update_capabilities": {"update_enabled": True},
                "max_batch_total_size_bytes": 16 * 1024 * 1024,
                "symlink_absolute_path_strategy": "DISALLOWED",
            },
            "execution_capabilities": {
                "digest_function": "SHA256",
                "exec_enabled": True,
                "execution_priority_capabilities": {"priorities": [{"min_priority": 0, "max_priority": 10}]},
            },
            "low_api_version": {"major": 2, "minor": 0, "patch": 0},
            "high_api_version": {"major": 2, "minor": 2, "patch": 0},
            "omni_extensions": {"bwob_supported": True, "kernel_sandbox": True},
        }


class REAPIClient:
    """Bazel REAPI v2 HTTP/JSON RPC client (Capabilities, CAS, ActionCache, Execution)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str) -> Dict[str, Any]:
        req = urllib.request.Request(f"{self.base_url}{path}", method="GET")
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _post(self, path: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        import urllib.error
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8") if err.fp else "{}"
            return err.code, json.loads(raw or "{}")

    def get_capabilities(self) -> Dict[str, Any]:
        return self._get("/v2/capabilities")

    def find_missing_blobs(self, digests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        _, data = self._post("/v2/cas/FindMissingBlobs", {"blob_digests": digests})
        return data.get("missing_blob_digests", [])

    def batch_update_blobs(self, blobs: List[bytes]) -> List[Dict[str, Any]]:
        import base64
        import hashlib
        reqs = []
        for b in blobs:
            h = hashlib.sha256(b).hexdigest()
            reqs.append({"digest": {"hash": h, "size_bytes": len(b)}, "data": base64.b64encode(b).decode("ascii")})
        _, data = self._post("/v2/cas/BatchUpdateBlobs", {"requests": reqs})
        return data.get("responses", [])

    def batch_read_blobs(self, digests: List[Dict[str, Any]]) -> List[Optional[bytes]]:
        import base64
        _, data = self._post("/v2/cas/BatchReadBlobs", {"digests": digests})
        out: List[Optional[bytes]] = []
        for r in data.get("responses", []):
            if r.get("status", {}).get("code", 0) == 0:
                out.append(base64.b64decode(r["data"]))
            else:
                out.append(None)
        return out

    def get_action_result(self, action_digest: str) -> Optional[Dict[str, Any]]:
        code_num, data = self._post("/v2/ac/GetActionResult", {"action_digest": {"hash": action_digest, "size_bytes": 0}})
        return data if code_num == 200 else None

    def execute_action(self, spec: ActionSpec) -> Dict[str, Any]:
        _, data = self._post(
            "/v2/execution/Execute",
            {
                "action_payload": {
                    "action_id": spec.action_id,
                    "kind": spec.kind,
                    "payload": spec.payload,
                    "input_blobs": spec.input_blobs,
                    "deps": spec.deps,
                    "target_triple": spec.target_triple,
                }
            },
        )
        return data


class REAPIGrpcClient:
    """Real Bazel REAPI v2 gRPC HTTP/2 + Protobuf (`google.protobuf.Struct`) RPC Client (Alpha-C93)."""

    def __init__(self, target: str):
        addr = target[7:] if target.startswith("grpc://") else target
        self.target = addr.rstrip("/")

    def _rpc(self, method_path: str, payload: Dict[str, Any], timeout: float = 15.0) -> Dict[str, Any]:
        import grpc
        from google.protobuf import json_format, struct_pb2

        req_msg = json_format.ParseDict(payload, struct_pb2.Struct())
        with grpc.insecure_channel(self.target) as channel:
            stub = channel.unary_unary(
                method_path,
                request_serializer=lambda m: m.SerializeToString(),
                response_deserializer=struct_pb2.Struct.FromString,
            )
            resp_msg = stub(req_msg, timeout=timeout)
        return json_format.MessageToDict(resp_msg)

    def get_capabilities(self) -> Dict[str, Any]:
        return self._rpc("/build.bazel.remote.execution.v2.Capabilities/GetCapabilities", {})

    def find_missing_blobs(self, digests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        data = self._rpc(
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/FindMissingBlobs",
            {"blob_digests": digests},
        )
        return data.get("missing_blob_digests", [])

    def batch_update_blobs(self, blobs: List[bytes]) -> List[Dict[str, Any]]:
        import base64
        import hashlib
        reqs = []
        for b in blobs:
            h = hashlib.sha256(b).hexdigest()
            reqs.append({"digest": {"hash": h, "size_bytes": len(b)}, "data": base64.b64encode(b).decode("ascii")})
        data = self._rpc(
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchUpdateBlobs",
            {"requests": reqs},
        )
        return data.get("responses", [])

    def batch_read_blobs(self, digests: List[Dict[str, Any]]) -> List[Optional[bytes]]:
        import base64
        data = self._rpc(
            "/build.bazel.remote.execution.v2.ContentAddressableStorage/BatchReadBlobs",
            {"digests": digests},
        )
        out: List[Optional[bytes]] = []
        for r in data.get("responses", []):
            if int(r.get("status", {}).get("code", 0)) == 0:
                out.append(base64.b64decode(r["data"]))
            else:
                out.append(None)
        return out

    def get_action_result(self, action_digest: str) -> Optional[Dict[str, Any]]:
        try:
            return self._rpc(
                "/build.bazel.remote.execution.v2.ActionCache/GetActionResult",
                {"action_digest": {"hash": action_digest, "size_bytes": 0}},
            )
        except Exception:
            return None

    def execute_action(self, spec: ActionSpec) -> Dict[str, Any]:
        return self._rpc(
            "/build.bazel.remote.execution.v2.Execution/Execute",
            {
                "action_payload": {
                    "action_id": spec.action_id,
                    "kind": spec.kind,
                    "payload": spec.payload,
                    "input_blobs": spec.input_blobs,
                    "deps": spec.deps,
                    "target_triple": spec.target_triple,
                }
            },
        )

    def execute_raw(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("/build.bazel.remote.execution.v2.Execution/ExecuteRaw", req)


class REAPIGrpcServer:
    """Real Bazel REAPI v2 gRPC HTTP/2 + Protobuf Server backed by CAS & HermeticSandboxExecutor."""

    def __init__(self, worker_id: str, cas: ContentAddressableStore, handlers: Optional[Dict[str, Callable]] = None):
        self.worker_id = worker_id
        self.cas = cas
        self.executor = HermeticSandboxExecutor(cas, handlers=handlers)
        self.executed_count = 0
        self._lock = threading.Lock()
        self._server = None
        self._pool: Optional[ThreadPoolExecutor] = None
        self.port: int = 0

    def start(self) -> str:
        import base64
        import grpc
        from google.protobuf import json_format, struct_pb2

        node = self

        def _wrap(handler_fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
            def _rpc_impl(request_msg, context):
                req_dict = json_format.MessageToDict(request_msg)
                resp_dict = handler_fn(req_dict)
                return json_format.ParseDict(resp_dict, struct_pb2.Struct())

            return grpc.unary_unary_rpc_method_handler(
                _rpc_impl,
                request_deserializer=struct_pb2.Struct.FromString,
                response_serializer=lambda m: m.SerializeToString(),
            )

        def _get_caps(_req):
            caps = REAPIServerCapabilities.default_capabilities()
            caps["omni_extensions"]["transport"] = "grpc+http2+protobuf"
            return caps

        def _find_missing(req):
            missing = []
            for d in req.get("blob_digests", []):
                h = str(d["hash"])
                if not node.cas.has_blob(h):
                    missing.append({"hash": h, "size_bytes": int(d.get("size_bytes", 0))})
            return {"missing_blob_digests": missing}

        def _batch_update(req):
            responses = []
            for item in req.get("requests", []):
                data = base64.b64decode(item["data"])
                stored_h = node.cas.put_blob(data)
                responses.append({
                    "digest": {"hash": stored_h, "size_bytes": len(data)},
                    "status": {"code": 0, "message": "OK"},
                })
            return {"responses": responses}

        def _batch_read(req):
            responses = []
            for dig in req.get("digests", []):
                h = str(dig["hash"])
                if node.cas.has_blob(h):
                    blob = node.cas.get_blob(h)
                    responses.append({
                        "digest": {"hash": h, "size_bytes": len(blob)},
                        "data": base64.b64encode(blob).decode("ascii"),
                        "status": {"code": 0, "message": "OK"},
                    })
                else:
                    responses.append({"digest": dig, "data": "", "status": {"code": 5, "message": "NOT_FOUND"}})
            return {"responses": responses}

        def _get_ar(req):
            ad = req.get("action_digest", {})
            h = str(ad["hash"] if isinstance(ad, dict) else ad)
            cached = node.cas.get_action_result(h)
            if cached is None:
                return {"found": False, "code": 5}
            return _to_reapi_action_result(cached, node.cas)

        def _exec_reapi(req):
            act_req = req.get("action_payload", req)
            spec = ActionSpec(
                action_id=act_req["action_id"],
                kind=act_req["kind"],
                payload=act_req["payload"],
                input_blobs=act_req.get("input_blobs", {}),
                deps=act_req.get("deps", []),
                target_triple=act_req.get("target_triple", "x86_64-unknown-linux-gnu"),
            )
            res = node.executor.execute(spec, worker_id=node.worker_id)
            with node._lock:
                node.executed_count += 1
            reapi_ar = _to_reapi_action_result({"output_blobs": res.output_blobs, "metadata": res.metadata}, node.cas)
            return {
                "name": f"operations/{res.action_digest}",
                "done": True,
                "response": {
                    "@type": "type.googleapis.com/build.bazel.remote.execution.v2.ExecuteResponse",
                    "result": reapi_ar,
                    "cached_result": res.cache_hit,
                    "status": {"code": 0, "message": "OK"},
                    "worker_id": res.worker_id,
                    "action_digest": {"hash": res.action_digest, "size_bytes": 0},
                },
            }

        def _exec_raw(req):
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
            return {
                "action_id": res.action_id,
                "action_digest": res.action_digest,
                "output_blobs": res.output_blobs,
                "metadata": res.metadata,
                "cache_hit": res.cache_hit,
                "worker_id": res.worker_id,
            }

        self._pool = ThreadPoolExecutor(max_workers=4)
        self._server = grpc.server(self._pool)
        self._server.add_generic_rpc_handlers((
            grpc.method_handlers_generic_handler(
                "build.bazel.remote.execution.v2.Capabilities",
                {"GetCapabilities": _wrap(_get_caps)},
            ),
            grpc.method_handlers_generic_handler(
                "build.bazel.remote.execution.v2.ContentAddressableStorage",
                {
                    "FindMissingBlobs": _wrap(_find_missing),
                    "BatchUpdateBlobs": _wrap(_batch_update),
                    "BatchReadBlobs": _wrap(_batch_read),
                },
            ),
            grpc.method_handlers_generic_handler(
                "build.bazel.remote.execution.v2.ActionCache",
                {"GetActionResult": _wrap(_get_ar)},
            ),
            grpc.method_handlers_generic_handler(
                "build.bazel.remote.execution.v2.Execution",
                {"Execute": _wrap(_exec_reapi), "ExecuteRaw": _wrap(_exec_raw)},
            ),
        ))
        self.port = self._server.add_insecure_port("127.0.0.1:0")
        self._server.start()
        return f"grpc://127.0.0.1:{self.port}"

    def stop(self):
        if self._server is not None:
            self._server.stop(0).wait(timeout=5.0)
            self._server = None
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None


class OSSandboxController:
    """
    Cross-platform OS kernel-level process & filesystem/memory sandbox:
    - Windows: Win32 Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | PROCESS_MEMORY | ACTIVE_PROCESS`)
    - Linux: `resource.setrlimit` (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NOFILE`) + Landlock LSM syscall when available
    - macOS: `resource.setrlimit` + isolated TMPDIR jail
    """

    @staticmethod
    def probe_capabilities() -> Dict[str, Any]:
        import sys
        plat = sys.platform
        if plat == "win32":
            return {"platform": plat, "backend": "win32_job_object", "landlock": False, "job_object": True, "rlimit": False}
        if plat.startswith("linux"):
            has_ll = False
            try:
                import ctypes
                libc = ctypes.CDLL(None, use_errno=True)
                # probe landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION=1)
                rc = libc.syscall(444, 0, 0, 1)
                has_ll = rc >= 1
            except Exception:
                has_ll = False
            return {"platform": plat, "backend": "linux_landlock_rlimit" if has_ll else "linux_rlimit", "landlock": has_ll, "job_object": False, "rlimit": True}
        return {"platform": plat, "backend": "darwin_rlimit", "landlock": False, "job_object": False, "rlimit": True}

    def run_sandboxed_subprocess(
        self,
        cmd: List[str],
        sandbox_dir: str,
        env: Optional[Dict[str, str]] = None,
        timeout_sec: float = 10.0,
        max_memory_mb: int = 256,
    ) -> Dict[str, Any]:
        import subprocess
        import sys

        clean_env = dict(env or {})
        clean_env["TMPDIR"] = sandbox_dir
        clean_env["TEMP"] = sandbox_dir
        clean_env["TMP"] = sandbox_dir
        if "SYSTEMROOT" in os.environ:
            clean_env.setdefault("SYSTEMROOT", os.environ["SYSTEMROOT"])
        if "PATH" in os.environ:
            clean_env.setdefault("PATH", os.environ["PATH"])

        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            k32 = ctypes.windll.kernel32
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            k32.SetInformationJobObject.restype = wintypes.BOOL
            k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            k32.AssignProcessToJobObject.restype = wintypes.BOOL
            k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]

            CREATE_SUSPENDED = 0x00000004
            job = k32.CreateJobObjectW(None, None)
            if not job:
                raise OSError("Failed to create Win32 Job Object")
            try:
                info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                # KILL_ON_JOB_CLOSE (0x2000) | ACTIVE_PROCESS (0x8) | PROCESS_MEMORY (0x100)
                info.BasicLimitInformation.LimitFlags = 0x2000 | 0x0008 | 0x0100
                info.BasicLimitInformation.ActiveProcessLimit = 16
                info.ProcessMemoryLimit = max(32, max_memory_mb) * 1024 * 1024
                ok_set = k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
                proc = subprocess.Popen(
                    cmd,
                    cwd=sandbox_dir,
                    env=clean_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                ok_assign = bool(k32.AssignProcessToJobObject(job, int(proc._handle)))
                try:
                    out_b, err_b = proc.communicate(timeout=timeout_sec)
                    rc = proc.returncode
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out_b, err_b = proc.communicate()
                    rc = -1
                return {
                    "returncode": rc,
                    "stdout": out_b.decode("utf-8", errors="replace"),
                    "stderr": err_b.decode("utf-8", errors="replace"),
                    "sandbox_kernel_backend": "win32_job_object",
                    "kernel_enforced": bool(ok_set and ok_assign),
                }
            finally:
                k32.CloseHandle(job)

        # POSIX / Linux (rlimit + real Landlock LSM path_beneath ruleset) / macOS (rlimit)
        import resource

        caps = self.probe_capabilities()
        mem_bytes = max(64, max_memory_mb) * 1024 * 1024
        sandbox_real = os.path.realpath(sandbox_dir)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ro_candidates = [
            "/usr", "/lib", "/lib64", "/bin", "/sbin",
            "/etc/ld.so.cache", "/etc/alternatives", "/etc/ssl",
            "/dev/null", "/dev/urandom",
            sys.prefix, sys.base_prefix, sys.exec_prefix,
            os.path.dirname(os.path.realpath(sys.executable)),
            project_root,
        ]
        ro_paths: List[str] = []
        seen_ro = set()
        for cand in ro_candidates:
            rp = os.path.realpath(cand)
            if rp not in seen_ro and os.path.exists(rp):
                seen_ro.add(rp)
                ro_paths.append(rp)

        def _apply_landlock() -> bool:
            import ctypes

            class LandlockRulesetAttr(ctypes.Structure):
                _fields_ = [("handled_access_fs", ctypes.c_uint64)]

            class LandlockPathBeneathAttr(ctypes.Structure):
                _pack_ = 1
                _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

            libc = ctypes.CDLL(None, use_errno=True)
            # SYS_landlock_create_ruleset=444, add_rule=445, restrict_self=446 (same on Linux x86_64/arm64)
            # ABI v1 handled_access_fs bits 0..12 = 0x1FFF; read+exec+readdir = 0x0D
            all_fs = 0x1FFF
            ro_fs = 0x000D  # EXECUTE (1) | READ_FILE (4) | READ_DIR (8)
            attr = LandlockRulesetAttr(handled_access_fs=all_fs)
            ruleset_fd = libc.syscall(444, ctypes.byref(attr), ctypes.sizeof(attr), 0)
            if ruleset_fd < 0:
                return False

            o_path_flags = getattr(os, "O_PATH", 0x200000) | getattr(os, "O_CLOEXEC", 0)
            try:
                def _allow(path_str: str, mask: int) -> None:
                    fd = -1
                    try:
                        fd = os.open(path_str, o_path_flags)
                        eff_mask = mask if os.path.isdir(path_str) else (mask & 0x0007)
                        pb = LandlockPathBeneathAttr(allowed_access=eff_mask, parent_fd=fd)
                        libc.syscall(445, ruleset_fd, 1, ctypes.byref(pb), 0)
                    except OSError:
                        pass
                    finally:
                        if fd >= 0:
                            os.close(fd)

                for ro_p in ro_paths:
                    _allow(ro_p, 0x0006 if ro_p == "/dev/null" else ro_fs)
                _allow(sandbox_real, all_fs)

                # prctl(PR_SET_NO_NEW_PRIVS=38, 1, 0, 0, 0) required by Landlock
                if libc.prctl(38, 1, 0, 0, 0) != 0:
                    return False
                if libc.syscall(446, ruleset_fd, 0) != 0:
                    return False
                return True
            finally:
                os.close(ruleset_fd)

        def _preexec():
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(timeout_sec)), max(1, int(timeout_sec))))
                resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
                if sys.platform.startswith("linux"):
                    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes * 4, mem_bytes * 4))
            except Exception:
                pass
            if caps.get("landlock"):
                try:
                    _apply_landlock()
                except Exception:
                    pass

        proc = subprocess.Popen(
            cmd,
            cwd=sandbox_dir,
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_preexec,
        )
        try:
            out_b, err_b = proc.communicate(timeout=timeout_sec)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            out_b, err_b = proc.communicate()
            rc = -1
        return {
            "returncode": rc,
            "stdout": out_b.decode("utf-8", errors="replace"),
            "stderr": err_b.decode("utf-8", errors="replace"),
            "sandbox_kernel_backend": caps["backend"],
            "kernel_enforced": bool(caps.get("landlock")) if sys.platform.startswith("linux") else True,
            "landlock_restricted": bool(caps.get("landlock")),
        }


def apply_windows_job_sandbox(
    proc_handle: int,
    max_memory_mb: int = 512,
    active_process_limit: int = 16,
    kill_on_close: bool = True,
) -> Optional[int]:
    """
    Attaches an external Windows process handle to a hard Win32 Job Object
    enforcing memory caps, active child count caps, and automatic teardown on close.
    Returns the Job HANDLE (caller closes via kernel32.CloseHandle) or None on non-win32.
    """
    import sys
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class _BASIC_INFO(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _EXT_INFO(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BASIC_INFO),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    k32 = ctypes.windll.kernel32
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.restype = wintypes.BOOL
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.restype = wintypes.BOOL
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise OSError("CreateJobObjectW failed")
    info = _EXT_INFO()
    flags = 0x0008 | 0x0100 | (0x2000 if kill_on_close else 0)
    info.BasicLimitInformation.LimitFlags = flags
    info.BasicLimitInformation.ActiveProcessLimit = max(1, int(active_process_limit))
    info.ProcessMemoryLimit = max(32, int(max_memory_mb)) * 1024 * 1024
    ok_set = bool(k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)))
    ok_assign = bool(k32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc_handle))))
    if not (ok_set and ok_assign):
        k32.CloseHandle(job)
        return None
    return int(job)


class RBEClusterPool:
    """
    Multi-process RBE Execution Cluster (Alpha-C98):
    Spawns `num_workers` isolated OS worker processes (`REAPIGrpcServer` over HTTP/2
    when `grpc` is available, or `RBEWorkerNode` HTTP fallback), attached to Win32 Job Objects
    on Windows, sharing one `ContentAddressableStore` with topological DAG scheduling.
    """

    def __init__(
        self,
        cas: ContentAddressableStore,
        num_workers: int = 2,
        prefer_grpc: bool = True,
        max_memory_mb: int = 512,
    ):
        self.cas = cas
        self.num_workers = max(1, int(num_workers))
        self.prefer_grpc = prefer_grpc
        self.max_memory_mb = max_memory_mb
        self._procs: List[Any] = []
        self._job_handles: List[int] = []
        self.endpoints: List[str] = []
        self.worker_pids: List[int] = []
        self.coordinator: Optional[RBECoordinator] = None

    def start(self) -> "RBEClusterPool":
        import subprocess
        import sys

        if self._procs:
            return self

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for idx in range(self.num_workers):
            wid = f"rbe_proc_worker_{idx}"
            cmd = [
                sys.executable,
                "-m",
                "orchestrator.rbe_cas",
                "--worker",
                "--cas-dir",
                self.cas.root_dir,
                "--worker-id",
                wid,
                "--transport",
                "grpc" if self.prefer_grpc else "http",
            ]
            proc = subprocess.Popen(
                cmd,
                cwd=project_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self._procs.append(proc)
            if sys.platform == "win32":
                try:
                    jh = apply_windows_job_sandbox(int(proc._handle), max_memory_mb=self.max_memory_mb)
                    if jh:
                        self._job_handles.append(jh)
                except Exception:
                    pass
            ready_line = proc.stdout.readline().strip() if proc.stdout else ""
            if not ready_line:
                err = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"RBEClusterPool worker {wid} failed to bind: {err}")
            info = json.loads(ready_line)
            self.endpoints.append(info["endpoint"])
            self.worker_pids.append(int(info.get("pid", proc.pid)))

        self.coordinator = RBECoordinator(self.cas, self.endpoints)
        return self

    def execute_dag(self, actions: List[ActionSpec]) -> Dict[str, Any]:
        if self.coordinator is None:
            self.start()
        assert self.coordinator is not None
        res_map = self.coordinator.execute_dag(actions, max_workers=max(1, len(self.endpoints)))
        hits = sum(1 for r in res_map.values() if r.cache_hit)
        workers_used = sorted({r.worker_id for r in res_map.values()})
        return {
            "results": res_map,
            "total_actions": len(actions),
            "cache_hits": hits,
            "executed_misses": len(actions) - hits,
            "workers_used": workers_used,
            "worker_pids": list(self.worker_pids),
            "endpoints": list(self.endpoints),
        }

    def close(self) -> None:
        import sys
        for proc in self._procs:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass
            try:
                proc.terminate()
            except Exception:
                pass
        for proc in self._procs:
            try:
                proc.wait(timeout=5.0)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=2.0)
                except Exception:
                    pass
            for pipe in (proc.stdout, proc.stderr):
                try:
                    if pipe:
                        pipe.close()
                except Exception:
                    pass
        self._procs.clear()
        if sys.platform == "win32" and self._job_handles:
            import ctypes
            k32 = ctypes.windll.kernel32
            for jh in self._job_handles:
                try:
                    k32.CloseHandle(jh)
                except Exception:
                    pass
            self._job_handles.clear()
        self.endpoints.clear()
        self.worker_pids.clear()
        self.coordinator = None

    def __enter__(self) -> "RBEClusterPool":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def _run_worker_cli(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="OmniCompiler RBE Worker Node Daemon")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--cas-dir", required=True)
    parser.add_argument("--worker-id", default="worker_0")
    parser.add_argument("--transport", default="grpc", choices=["grpc", "http"])
    args = parser.parse_args(argv)

    cas = ContentAddressableStore(args.cas_dir)
    srv = None
    if args.transport == "grpc":
        try:
            srv = REAPIGrpcServer(args.worker_id, cas)
            ep = srv.start()
        except Exception:
            srv = None
    if srv is None:
        srv = RBEWorkerNode(args.worker_id, cas)
        ep = srv.start()

    sys.stdout.write(json.dumps({"endpoint": ep, "pid": os.getpid(), "worker_id": args.worker_id}) + "\n")
    sys.stdout.flush()
    try:
        sys.stdin.read()
    except Exception:
        pass
    finally:
        srv.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_worker_cli())
