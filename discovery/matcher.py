"""
RC-05 Capability Discovery Engine: Identifies capabilities from FactBundle
matching the requirements of the IntegrationSpec.
Prioritizes exact matching over substring matching.
Explicitly records unknowns, side effects, and protocol constraints.
"""

import math
from typing import List, Dict, Any
from contracts.models import FactBundle, IntegrationSpec, CapabilityContract


class MftBitmap64:
    """
    64-Bit Word Bitmap Block Filter (from github.com/juan3861/fastmft/bitmap.go).
    Packs boolean candidate flags into 64-bit unsigned integer words so 64 capability
    candidates can be skipped in a single CPU register check (word == 0).
    """
    def __init__(self, flags: List[bool]):
        self.record_count = len(flags)
        self.words: List[int] = []
        word = 0
        for idx, flag in enumerate(flags):
            if flag:
                word |= (1 << (idx & 63))
            if (idx & 63) == 63 or idx == len(flags) - 1:
                self.words.append(word)
                word = 0

    def is_record_in_use(self, idx: int) -> bool:
        if idx < 0 or idx >= self.record_count:
            return False
        return bool((self.words[idx >> 6] >> (idx & 63)) & 1)

    def chunk_has_in_use(self, start_idx: int, count: int = 64) -> bool:
        if count <= 0 or start_idx >= self.record_count:
            return False
        w_idx = start_idx >> 6
        return w_idx < len(self.words) and self.words[w_idx] != 0


def grover_quantum_amplify(scores: List[float], target_idx: int) -> Dict[str, Any]:
    """
    Quantum Hilbert-Space State Vector & Grover O(sqrt(N)) Amplitude Amplification
    (from github.com/juan3861/fastmft §5):
      |psi_0> = (1/sqrt(N)) sum_{i=0}^{N-1} |i>
      U_omega |i> = (-1)^{omega(i)} |i>
      U_s = 2|psi_0><psi_0| - I
    Amplifies the target capability state probability amplitude in floor((pi/4)*sqrt(N)) steps.
    """
    n = len(scores)
    if n <= 1 or target_idx < 0 or target_idx >= n:
        return {"hilbert_dim": max(1, n), "grover_iterations": 0, "target_probability": 1.0}

    inv_sqrt_n = 1.0 / math.sqrt(n)
    amplitudes = [inv_sqrt_n] * n
    k_opt = max(1, int(math.floor((math.pi / 4.0) * math.sqrt(n))))

    for _ in range(k_opt):
        # 1. Phase Oracle U_omega: flip phase of marked state
        amplitudes[target_idx] = -amplitudes[target_idx]
        # 2. Grover Diffusion Operator U_s = 2|s><s| - I (inversion about the mean)
        mean_amp = sum(amplitudes) / n
        amplitudes = [2.0 * mean_amp - a for a in amplitudes]

    norm_sq = sum(a * a for a in amplitudes) or 1.0
    target_prob = (amplitudes[target_idx] * amplitudes[target_idx]) / norm_sq
    return {
        "hilbert_dim": n,
        "grover_iterations": k_opt,
        "target_probability": round(target_prob, 6)
    }


class CapabilityDiscoveryEngine:
    def __init__(self, schema_version: str = "0.1"):
        self.schema_version = schema_version

    def discover_capabilities(
        self,
        spec: IntegrationSpec,
        fact_bundle: FactBundle
    ) -> List[CapabilityContract]:
        discovered: List[CapabilityContract] = []
        symbols = fact_bundle.symbols
        n_syms = len(symbols)

        for req in spec.required_capabilities:
            req_clean = req.strip()
            req_lower = req_clean.lower().replace("-", "_").replace(" ", "_")
            best_symbol = None
            best_idx = -1
            max_score = -1.0

            # Pre-filter active candidates into a 64-bit MftBitmap64 (juan3861/fastmft)
            cand_flags = [
                (req_lower in s["name"].lower() or req_lower in s["qualified_name"].lower() or req_lower in s["docstring"].lower())
                for s in symbols
            ]
            bitmap = MftBitmap64(cand_flags)
            scores = [0.0] * n_syms

            for block_start in range(0, n_syms, 64):
                if not bitmap.chunk_has_in_use(block_start, 64):
                    continue
                block_end = min(n_syms, block_start + 64)
                for idx in range(block_start, block_end):
                    if not bitmap.is_record_in_use(idx):
                        continue
                    sym = symbols[idx]
                    sym_name = sym["name"].lower()
                    qual_name = sym["qualified_name"].lower()
                    doc = sym["docstring"].lower()

                    score = 0.0
                    if req_lower == sym_name:
                        score = 100.0
                    elif sym_name.endswith(f".{req_lower}") or sym_name == req_lower:
                        score = 90.0
                    elif f".{req_lower}." in qual_name:
                        score = 80.0
                    elif req_lower in sym_name:
                        score = 20.0
                    elif req_lower in doc:
                        score = 5.0

                    scores[idx] = score
                    if score > max_score:
                        max_score = score
                        best_symbol = sym
                        best_idx = idx

            if best_symbol and max_score >= 5.0:
                input_schema = {}
                for p in best_symbol["parameters"]:
                    input_schema[p["name"]] = {
                        "type": p["type"],
                        "meaning": p["name"],
                        "required": p.get("required", True),
                        "kind": p.get("kind", "regular"),
                        "default": None
                    }

                output_schema = {
                    "type": best_symbol["return_type"],
                    "structure": "return_value"
                }

                # Infer effects from docstring and operation name
                effects = []
                doc = best_symbol["docstring"].lower()
                sym_low = best_symbol["name"].lower()
                if any(w in doc or w in sym_low for w in ("write", "save", "insert", "store", "ingest", "index", "persist", "record", "audit_sink")):
                    effects.append("write:storage")
                elif any(w in doc or w in sym_low for w in ("read", "search", "query", "get", "fetch", "parse", "sanitize", "render", "format", "calculate", "compute", "score", "tokenize", "verify", "encode", "decode", "clean", "normalize", "encrypt")):
                    effects.append("read:storage")
                if ("network" in doc and "networkx" not in doc) or "http" in doc:
                    effects.append("network:io")

                protocol = {
                    "initial": "uninitialized" if ("init" in doc or "connect" in doc or "requires_init" in doc) else "ready",
                    "states": ["ready", "executing", "closed"]
                }

                unknowns = []
                if best_symbol["return_type"] == "Any":
                    unknowns.append("untyped_return_value")
                if any(p["type"] == "Any" for p in best_symbol["parameters"]):
                    unknowns.append("untyped_parameters")
                if not best_symbol["docstring"]:
                    unknowns.append("undocumented_behavior")

                lang = best_symbol.get("language", "python")
                ep_kind = "node_callable" if lang in ("javascript", "typescript") else "python_callable"

                grover_meta = grover_quantum_amplify(scores, best_idx)
                contract = CapabilityContract(
                    schema_version=self.schema_version,
                    capability_id=f"cap:{fact_bundle.repo_id}:{req}",
                    source_repo_id=fact_bundle.repo_id,
                    entrypoint={
                        "kind": ep_kind,
                        "language": lang,
                        "operation": best_symbol["name"],
                        "symbol_ref": best_symbol["qualified_name"],
                        "file_path": best_symbol["file_path"],
                        "is_async": best_symbol.get("is_async", False),
                        "class_name": best_symbol.get("class_name")
                    },
                    input_schema=input_schema,
                    output_schema=output_schema,
                    effects=effects,
                    requires=[],
                    protocol=protocol,
                    evidence=[
                        {"kind": "ast_inspection", "source_ref": best_symbol["qualified_name"]},
                        {"kind": "confidence", "level": fact_bundle.confidence_map.get(best_symbol["qualified_name"], "unknown")},
                        {"kind": "fastmft_quantum_grover", **grover_meta}
                    ],
                    unknowns=unknowns
                )
                discovered.append(contract)

        return discovered
