# ACCEPTANCE CONTRACT — Alpha-C29: Generalized N-Level Recursive Loop-Tree Inductive TV + Polyglot Arrow/Match/Do-While/Tuple + Pipe Handle Cleanliness

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C29 (`F:\repository-compiler`)  
**Baseline:** Alpha-C28 (`bd550de`, CI `43770228128`, 192 discovery PASS)

## 1. Deliverables & Architecture Contracts

1. **Generalized N-Level Recursive Loop-Tree Inductive Verification (`validation/ssa_translation_validator.py`):**
   - Replace the 2-level specialized multi-loop handler with a unified recursive loop-tree verifier (`_verify_loop_tree_node`) supporting arbitrary nesting depth (`1, 2, 3+` nested levels) and hybrid sequential + nested loop regions.
   - At each level of the loop tree:
     - Prove entry lockstep, bypass equivalence, and base relational invariant from the enclosing region state.
     - Recursively verify any sequence of child sub-loops inside the loop body under the enclosing inductive invariant assumption, substituting proven-equal Skolemized post-sub-loop states & memory downstream.
     - Verify loop step lockstep preservation, early returns, and exit equivalence (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`).
   - Catch regressions at ANY depth (`depth=1, 2, 3`) or sibling index with `REFUTED_COUNTEREXAMPLE`.

2. **Polyglot Extensions (`frontends/polyglot_ssa_lowering.py`):**
   - **JS/TS Arrow Functions:** Top-level `(export )?(const|let|var) name = (params)(: Type)? => ( { block } | expr );` and `exports.name = (params) => ...`.
   - **Rust `match` Statements/Tails:** `match scrutinee { pat1 => block_or_expr, ..., _ => default_block_or_expr }` lowered cleanly into structured `ast.If` chains (including implicit tail return propagation in Rust).
   - **JS/TS `do { ... } while (cond);`:** Lowered cleanly into structured `while 1:` + trailing guarded `break`.
   - **Multi-Variable / Tuple Swap & Comma Decls:** Go `a, b := expr1, expr2` / `a, b = b, a + b` (`ast.Assign([Tuple], Tuple)`) and JS/TS comma declarations `let a = 1, b = 2;`.

3. **Runtime Resource Cleanliness (`adapters/synthesizer.py`):**
   - Close `proc.stdin`, `proc.stdout`, and `proc.stderr` pipes safely inside `FastNodeBridge.close()` regardless of worker exit state so full test runs emit zero leaked-pipe `ResourceWarning`s.

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c29_recursive_loops_and_polyglot_ext.py` + `run_c29_tests.py`:
  1. Unbounded 3-level triple nested loop (`depth=3`) inductive proof (`PROVEN_INDUCTIVE_EQUIVALENT`, `bounded=False`) + concrete counterexample refutation (`REFUTED_COUNTEREXAMPLE`) on mutations at depth 1, depth 2, and depth 3.
  2. Hybrid nested + sequential loop CFG (`outer loop` containing 2 sequential inner loops + trailing sequential loop) proven unbounded + mutation catch.
  3. Polyglot JS/TS arrow functions, Rust `match`, JS `do { ... } while`, and Go tuple swap lowered to Omni-SSA, verified across LLVM/WAT TV, and differentially executed across Native x86-64 JIT, LLVM O3, and Wasmtime.
  4. End-to-end multi-repo compilation (`OmniRepoCompiler`) fusing arrow TS + Rust `match` + Go tuple swap into `.dll`/`.so` (`ctypes.CDLL`) and `.wasm`.
  5. Clean zero-`ResourceWarning` execution of `FastNodeBridge` in `test_ceiling_engineering_complete.py`.
- Full regression `run_full_regression.py` + `unittest discover`, `AetherMind_Strict_Auditor.py` `APROVADO`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
