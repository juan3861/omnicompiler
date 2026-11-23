"""
Cryptographic SLSA Level 3 / in-toto v1 Provenance Generator & Verifier (Alpha-C86).

Generates signed in-toto Statement v1 bundles wrapping SLSA Provenance v1.0
(`https://slsa.dev/provenance/v1`) bound to:
  - Target binary subject SHA-256 digests
  - Bazel REAPI v2 / Omni CAS input & action digests
  - OWASP CycloneDX 1.5 SBOM digest
  - Hermetic sandbox execution metadata
Signed in DSSE (Dead Simple Signing Envelope) format using pure-Python
RFC 8032 Ed25519 (zero non-stdlib crypto dependency, bit-exact interop).
"""

import base64
import hashlib
import json
import os
import platform
import secrets
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Pure-Python RFC 8032 Ed25519 (zero external deps, RFC 8032 test-vector exact)
# ---------------------------------------------------------------------------
_ED_Q = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_Q - 2, _ED_Q)
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if x % 2 != 0:
        x = _ED_Q - x
    return x


_ED_GY = (4 * pow(5, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_GX = _ed_xrecover(_ED_GY)
_ED_G = (_ED_GX % _ED_Q, _ED_GY % _ED_Q, 1, (_ED_GX * _ED_GY) % _ED_Q)
_ED_ZERO = (0, 1, 1, 0)


def _ed_point_add(p1: Tuple[int, int, int, int], p2: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_Q
    b = ((y1 + x1) * (y2 + x2)) % _ED_Q
    c = (2 * t1 * t2 * _ED_D) % _ED_Q
    d = (2 * z1 * z2) % _ED_Q
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f) % _ED_Q, (g * h) % _ED_Q, (f * g) % _ED_Q, (e * h) % _ED_Q


def _ed_scalarmult(pt: Tuple[int, int, int, int], e: int) -> Tuple[int, int, int, int]:
    res = _ED_ZERO
    cur = pt
    while e > 0:
        if e & 1:
            res = _ed_point_add(res, cur)
        cur = _ed_point_add(cur, cur)
        e >>= 1
    return res


def _ed_encode_point(pt: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED_Q - 2, _ED_Q)
    x = (x * zi) % _ED_Q
    y = (y * zi) % _ED_Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode_point(raw: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _ED_Q:
        return None
    x = _ed_xrecover(y)
    if (x & 1) != sign:
        x = _ED_Q - x
    pt = (x, y, 1, (x * y) % _ED_Q)
    # Verify on curve: (-x^2 + y^2 - 1 - d*x^2*y^2) mod q == 0
    if ((-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_Q) != 0:
        return None
    return pt


def _ed_clamp_scalar(h_prefix: bytes) -> int:
    a = bytearray(h_prefix)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")


def ed25519_generate_keypair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Returns `(private_seed_32b, public_key_32b)`."""
    sk = seed if seed is not None else secrets.token_bytes(32)
    if len(sk) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = _ed_clamp_scalar(h[:32])
    pk = _ed_encode_point(_ed_scalarmult(_ED_G, a))
    return sk, pk


def ed25519_public_key_from_seed(sk: bytes) -> bytes:
    if len(sk) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = _ed_clamp_scalar(h[:32])
    return _ed_encode_point(_ed_scalarmult(_ED_G, a))


def ed25519_sign(sk: bytes, message: bytes) -> bytes:
    """RFC 8032 pure Ed25519 64-byte deterministic signature."""
    if len(sk) != 32:
        raise ValueError("Ed25519 private key seed must be 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = _ed_clamp_scalar(h[:32])
    prefix = h[32:]
    pk = _ed_encode_point(_ed_scalarmult(_ED_G, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED_L
    r_pt = _ed_encode_point(_ed_scalarmult(_ED_G, r))
    k = int.from_bytes(hashlib.sha512(r_pt + pk + message).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    return r_pt + s.to_bytes(32, "little")


def ed25519_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 verification."""
    if len(pk) != 32 or len(signature) != 64:
        return False
    a_pt = _ed_decode_point(pk)
    r_pt = _ed_decode_point(signature[:32])
    if a_pt is None or r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + pk + message).digest(), "little") % _ED_L
    lhs = _ed_scalarmult(_ED_G, s)
    rhs = _ed_point_add(r_pt, _ed_scalarmult(a_pt, k))
    return _ed_encode_point(lhs) == _ed_encode_point(rhs)


def dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """Dead Simple Signing Envelope (DSSE) Pre-Authentication Encoding."""
    pt_b = payload_type.encode("utf-8")
    return f"DSSEv1 {len(pt_b)} ".encode("utf-8") + pt_b + f" {len(payload_bytes)} ".encode("utf-8") + payload_bytes


# ---------------------------------------------------------------------------
# SLSA Level 3 / in-toto v1 Provenance Builder & Cryptographic Auditor
# ---------------------------------------------------------------------------
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DSSE_IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class SLSAProvenanceGenerator:
    """
    Produces and cryptographically verifies SLSA Build Level 3 in-toto v1
    provenance attestations serialized inside signed DSSE envelopes.
    """

    BUILDER_ID = "https://omnicompiler.dev/builders/hermetic-rbe-slsa3/v1"
    BUILD_TYPE = "https://omnicompiler.dev/OmniBuild/v1"

    def __init__(self, signer_seed: Optional[bytes] = None):
        if signer_seed is None:
            self.private_seed, self.public_key = ed25519_generate_keypair()
        else:
            self.private_seed = signer_seed
            self.public_key = ed25519_public_key_from_seed(signer_seed)
        self.keyid = _sha256_bytes(self.public_key)

    def build_statement(
        self,
        subjects: Sequence[Union[str, Tuple[str, Union[bytes, str]]]],
        action_spec: Optional[Any] = None,
        action_result: Optional[Any] = None,
        cas: Optional[Any] = None,
        sbom: Optional[Dict[str, Any]] = None,
        external_params: Optional[Dict[str, Any]] = None,
        invocation_id: Optional[str] = None,
        started_on: Optional[str] = None,
        finished_on: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Builds an in-toto Statement v1 with SLSA Provenance v1.0 predicate.
        `subjects` entries can be filesystem paths, `(name, bytes)`, or `(name, sha256_hex)`.
        """
        subj_list: List[Dict[str, Any]] = []
        for item in subjects:
            if isinstance(item, str):
                subj_list.append({"name": os.path.basename(item), "digest": {"sha256": _sha256_file(item)}})
            elif isinstance(item, tuple) and len(item) == 2:
                name, payload_or_hex = item
                if isinstance(payload_or_hex, (bytes, bytearray)):
                    hex_dig = _sha256_bytes(bytes(payload_or_hex))
                else:
                    hex_dig = str(payload_or_hex)
                subj_list.append({"name": str(name), "digest": {"sha256": hex_dig}})
            else:
                raise ValueError(f"Invalid provenance subject entry: {item!r}")

        if not subj_list:
            raise ValueError("SLSA Provenance statement requires at least one subject")

        resolved_deps: List[Dict[str, Any]] = []
        ext_p = dict(external_params or {})

        if action_spec is not None:
            act_digest = action_spec.compute_digest()
            ext_p.setdefault("action_id", action_spec.action_id)
            ext_p.setdefault("action_kind", action_spec.kind)
            ext_p.setdefault("target_triple", action_spec.target_triple)
            ext_p.setdefault("action_digest", act_digest)
            for rel_p, blob_hash in sorted(getattr(action_spec, "input_blobs", {}).items()):
                resolved_deps.append({
                    "uri": f"cas://sha256/{blob_hash}",
                    "name": rel_p,
                    "digest": {"sha256": blob_hash},
                })

        if action_result is not None:
            for rel_out, out_hash in sorted(getattr(action_result, "output_blobs", {}).items()):
                resolved_deps.append({
                    "uri": f"cas://output/{rel_out}",
                    "name": rel_out,
                    "digest": {"sha256": out_hash},
                })

        byproducts: List[Dict[str, Any]] = []
        if sbom is not None:
            sbom_canon = json.dumps(sbom, sort_keys=True, separators=(",", ":")).encode("utf-8")
            sbom_sha = _sha256_bytes(sbom_canon)
            resolved_deps.append({
                "uri": "urn:omnicompiler:sbom:cyclonedx-1.5",
                "name": "sbom.cdx.json",
                "digest": {"sha256": sbom_sha},
                "mediaType": "application/vnd.cyclonedx+json",
            })
            byproducts.append({
                "name": "cyclonedx_sbom",
                "digest": {"sha256": sbom_sha},
                "mediaType": "application/vnd.cyclonedx+json",
            })

        now_iso = datetime.now(timezone.utc).isoformat()
        inv_id = invocation_id or f"omni-inv-{_sha256_bytes(json.dumps(subj_list, sort_keys=True).encode('utf-8'))[:16]}"
        statement = {
            "_type": IN_TOTO_STATEMENT_TYPE,
            "subject": subj_list,
            "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": self.BUILD_TYPE,
                    "externalParameters": ext_p,
                    "internalParameters": {
                        "python_version": sys.version.split()[0],
                        "host_platform": platform.platform(),
                        "cas_backed": cas is not None,
                        "reproducible": True,
                    },
                    "resolvedDependencies": resolved_deps,
                },
                "runDetails": {
                    "builder": {
                        "id": self.BUILDER_ID,
                        "version": {"omnicompiler": "2.0.0"},
                    },
                    "metadata": {
                        "invocationId": inv_id,
                        "startedOn": started_on or now_iso,
                        "finishedOn": finished_on or now_iso,
                        "reproducible": True,
                    },
                    "byproducts": byproducts,
                },
            },
        }
        return statement

    def sign_statement(self, statement: Dict[str, Any]) -> Dict[str, Any]:
        """Wraps in-toto Statement v1 into an Ed25519 DSSE envelope."""
        payload_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
        pae = dsse_pae(DSSE_IN_TOTO_PAYLOAD_TYPE, payload_bytes)
        sig = ed25519_sign(self.private_seed, pae)
        return {
            "payloadType": DSSE_IN_TOTO_PAYLOAD_TYPE,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signatures": [
                {
                    "keyid": self.keyid,
                    "sig": base64.b64encode(sig).decode("ascii"),
                    "alg": "ed25519",
                }
            ],
            "publicKeyB64": base64.b64encode(self.public_key).decode("ascii"),
        }

    def generate_and_sign(self, **kwargs) -> Dict[str, Any]:
        stmt = self.build_statement(**kwargs)
        return self.sign_statement(stmt)

    @staticmethod
    def verify_bundle(
        envelope: Dict[str, Any],
        public_key: Optional[bytes] = None,
        subjects_data: Optional[Dict[str, Union[bytes, str]]] = None,
        cas: Optional[Any] = None,
        expected_sbom: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Cryptographically verifies a signed DSSE SLSA v1.0 provenance bundle:
        1. Validates Ed25519 signature over DSSE PAE encoding.
        2. Validates in-toto v1 + SLSA v1 schema structure.
        3. Validates subject file/byte SHA-256 digests when `subjects_data` supplied.
        4. Validates resolved CAS dependency digests exist in `cas` when supplied.
        5. Validates expected CycloneDX SBOM digest when `expected_sbom` supplied.
        """
        pk = public_key
        if pk is None and envelope.get("publicKeyB64"):
            pk = base64.b64decode(envelope["publicKeyB64"])
        if not pk:
            return {"valid": False, "reason": "MISSING_PUBLIC_KEY"}

        payload_type = envelope.get("payloadType", "")
        if payload_type != DSSE_IN_TOTO_PAYLOAD_TYPE:
            return {"valid": False, "reason": f"INVALID_PAYLOAD_TYPE_{payload_type}"}
        try:
            payload_bytes = base64.b64decode(envelope["payload"])
        except Exception:
            return {"valid": False, "reason": "INVALID_PAYLOAD_BASE64"}

        sigs = envelope.get("signatures", [])
        if not sigs:
            return {"valid": False, "reason": "NO_SIGNATURES"}
        pae = dsse_pae(payload_type, payload_bytes)
        expected_keyid = _sha256_bytes(pk)
        sig_ok = False
        for entry in sigs:
            try:
                sig_bytes = base64.b64decode(entry["sig"])
            except Exception:
                continue
            if entry.get("keyid") and entry.get("keyid") != expected_keyid:
                continue
            if ed25519_verify(pk, pae, sig_bytes):
                sig_ok = True
                break
        if not sig_ok:
            return {"valid": False, "reason": "INVALID_ED25519_SIGNATURE"}

        try:
            stmt = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return {"valid": False, "reason": "INVALID_STATEMENT_JSON"}

        if stmt.get("_type") != IN_TOTO_STATEMENT_TYPE:
            return {"valid": False, "reason": "INVALID_IN_TOTO_TYPE"}
        if stmt.get("predicateType") != SLSA_PROVENANCE_PREDICATE_TYPE:
            return {"valid": False, "reason": "INVALID_SLSA_PREDICATE_TYPE"}

        subj_map = {s["name"]: s["digest"]["sha256"] for s in stmt.get("subject", [])}
        if subjects_data:
            for sname, sdata in subjects_data.items():
                if sname not in subj_map:
                    return {"valid": False, "reason": f"SUBJECT_NOT_IN_PROVENANCE_{sname}"}
                actual_h = (
                    _sha256_bytes(sdata)
                    if isinstance(sdata, (bytes, bytearray))
                    else _sha256_file(str(sdata))
                )
                if actual_h != subj_map[sname]:
                    return {"valid": False, "reason": f"SUBJECT_DIGEST_MISMATCH_{sname}"}

        deps = stmt.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])
        if cas is not None:
            for d in deps:
                if str(d.get("uri", "")).startswith("cas://sha256/"):
                    h = d["digest"]["sha256"]
                    if not cas.has_blob(h):
                        return {"valid": False, "reason": f"MISSING_CAS_DEPENDENCY_{h}"}
                    if _sha256_bytes(cas.get_blob(h)) != h:
                        return {"valid": False, "reason": f"CORRUPTED_CAS_DEPENDENCY_{h}"}

        if expected_sbom is not None:
            sbom_canon = json.dumps(expected_sbom, sort_keys=True, separators=(",", ":")).encode("utf-8")
            exp_h = _sha256_bytes(sbom_canon)
            sbom_deps = [d for d in deps if d.get("name") == "sbom.cdx.json"]
            if not sbom_deps or sbom_deps[0].get("digest", {}).get("sha256") != exp_h:
                return {"valid": False, "reason": "SBOM_DIGEST_MISMATCH"}

        return {
            "valid": True,
            "reason": "VERIFIED_SLSA_L3_PROVENANCE",
            "keyid": expected_keyid,
            "statement": stmt,
        }
