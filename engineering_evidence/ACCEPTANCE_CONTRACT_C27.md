# ACCEPTANCE CONTRACT — Alpha-C27: True Polyglot AOT Frontend + Intra-Module Call Congruence & Backend TV + VLASimdEngine Telemetry

**Status:** FROZEN BEFORE IMPLEMENTATION  
**Milestone:** Alpha-C27 (`F:\repository-compiler`)  
**Baseline:** Alpha-C26 (`a593980`, CI run `43765360184`, 96/96 local suites / 182 CI tests PASS)

## 1. Deliverables & Architecture Contracts

1. **True Polyglot AOT Lowering (`frontends/polyglot_ssa_lowering.py`):**
   - Clean tokenizer/recursive parser (with fail-closed diagnostics) lowering real **JavaScript (`.js`)**, **TypeScript (`.ts`)**, **Rust (`.rs`)**, and **Go (`.go`)** functions into canonical Python `ast.Module` + `ast.FunctionDef` units so every downstream compiler engine (CPG, Omni-SSA, Z3 SMT Refinement, ThinLTO, SSATranslationValidator, Native x86-64/ARM64, LLVM O3, WebAssembly `.wasm`) compiles non-Python repositories identically to Python.
   - Supported constructs across all 4 languages:
     - Top-level function declarations (`function f(...)`, `export function f(...)`, `pub fn f(...) -> T`, `fn f(...) -> T`, `func f(...) T`).
     - Typed and untyped parameters (`a: number`, `a: i64`, `a int`).
     - Local declarations & mutations (`let`, `const`, `var`, `let mut`, `:=`, `=`, `+=`, `-=`, `*=`, `&=`, `|=`, `^=`, `<<=`, `>>=`, `x++`, `x--`).
     - Expressions: 64-bit integer literals (decimal, hex), unary `-`/`~`/`!`, binary arithmetic (`+`, `-`, `*`, `/`, `%`), bitwise (`&`, `|`, `^`, `<<`, `>>`, `>>>`), comparisons (`==`, `===`, `!=`, `!==`, `<`, `<=`, `>`, `>=`), boolean (`&&`, `||`), ternary `cond ? a : b`, parenthesized expressions, and pure/cross-repo function calls `callee(arg0, ...)`.
     - Control flow: `if / else if / else`, `while`, C-style `for (init; cond; step)`, Go `for cond` / `for init; cond; step`, Rust `for i in a..b` / `for i in a..=b`, `return expr;`, and Rust implicit tail expression.
   - Fail-closed behavior: unsupported syntax raises `PolyglotLoweringError` instead of silently miscompiling; file scanner records diagnostic metadata without crashing valid functions.

2. **Polyglot Manifest & Compiler Pipeline Wiring (`orchestrator/repo_manifest_ingestor.py`, `omni_repo_compiler.py`):**
   - `RepoManifestIngestor.ingest_repository()` extracts exports and requirements from `.js`, `.ts`, and `.go` files alongside `.py`, `.c/.h/.cpp`, and `.rs`.
   - `OmniRepoCompiler._scan_repo_asts()` parses `.js`, `.ts`, `.rs`, and `.go` sources via `polyglot_ssa_lowering.parse_polyglot_file_to_ast()` into `parsed_modules` and `funcs`, enabling multi-repo JS/TS/Rust/Go/Python fusion, native JIT/LLVM/WASM AOT emission, and ThinLTO.

3. **Intra-Module Call Congruence & Lifting in Translation Validators (`validation/ssa_translation_validator.py`, `validation/backend_translation_validator.py`):**
   - `SSATranslationValidator(..., enable_call_congruence: bool = False)` models deterministic `call` instructions over pure callees via shared Z3 uninterpreted function symbols (`z3.Function(f"uf_call_{callee}_{arity}", *([bv64]*arity), bv64)`), preserving C24–C26 default strictness while proving equivalence across transformations/lowerings that preserve callee identity and arguments.
   - `LLVMIRToSSALifter` and `WATToSSALifter` lift intra-module `call` (`%lhs = call i64 @callee(...)` / `call $callee` using parsed WAT signature arities) so recursive and cross-function modules pass `BackendTranslationValidator` with SMT proof (`PROVEN_EQUIVALENT` / `PROVEN_BOUNDED_EQUIVALENT`) rather than `UNSUPPORTED_OPCODE_call`.

4. **VLASimdEngine Telemetry Wiring (`omni_repo_compiler.py`):**
   - When `LoopVectorizerPass` vectorizes loops (`vectorized_loops > 0`), `OmniRepoCompiler` populates `results["stages"]["codegen"]["vla_simd_metadata"]` using `compiler.vla_simd_engine.VLASimdEngine` (`emit_x86_vmaskmov_metadata` and `emit_arm64_sve_metadata`).

## 2. Empirical Acceptance Gates

- `tests/test_alpha_c27_polyglot_aot_and_call_tv.py` + `run_c27_tests.py`:
  1. Multi-language lowering & native x86-64 JIT execution parity across real `.js`, `.ts`, `.rs`, and `.go` sources (loops, shifts, conditionals, intra-module calls).
  2. Multi-repo polyglot fusion (`repo_go` + `repo_rs` + `repo_ts` + `repo_py`) through `OmniRepoCompiler.compile_repositories()` verifying `RepoManifestIngestor` exports, native ELF/PE/Mach-O/DLL artifacts, `.wasm` module output, and non-zero native execution.
  3. Fail-closed verification on unsupported polyglot syntax (`PolyglotLoweringError`).
  4. `BackendTranslationValidator` SMT proof (`PROVEN_EQUIVALENT`) + real `wasmtime`/`llvm` differential execution for `call`-containing and recursive/multi-function SSA <-> LLVM IR <-> WAT modules.
  5. `VLASimdEngine` metadata population (`vla_simd_metadata`) on vectorized loop compilation.
- Full regression `run_full_regression.py` (`101/101` local suites PASS), `AetherMind_Strict_Auditor.py` `APROVADO` (exit 0) on both `run_c27_tests.py` and `run_full_regression.py`, and GitHub Actions CI green on `ubuntu-latest` and `windows-latest`.
