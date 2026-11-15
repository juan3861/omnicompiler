# ACCEPTANCE CONTRACT — ALPHA-C18 (GEORGE-APPEL ITERATED REGISTER COALESCING & ABI PARTITIONING)

- **Contract Version:** `ALPHA-C18-CONTRACT-v1.0`
- **Repository:** `F:\repository-compiler` (`https://github.com/juan3861/omnicompiler.git`)
- **Mode:** `SINGLE_AGENT_WITH_EXECUTION` (Builder + Hostile Empirical Auditor via `AetherMind_Strict_Auditor.py`)

---

## 1. Frozen Requirements & Invariants

| Requirement ID | Specification | Gate Type | Verification Oracle |
| :--- | :--- | :--- | :--- |
| `REQ-C18-01` | George & Appel (1996) Iterated Register Coalescing (`IteratedRegisterCoalescingAllocator`) worklist engine (`Build`, `Simplify`, `Coalesce`, `Freeze`, `SelectSpill`, `AssignColors`) in `compiler/regalloc_graph_coloring.py`. | `REQUIRED` | `test_01_briggs_and_george_conservative_coalescing` |
| `REQ-C18-02` | Briggs (`significant_neighbors < K`) and George (`for all t in adj[v]: interferes(t, u) or deg(t) < K`) conservative coalescing criteria eliminating non-interfering `mov` and `phi` copies without introducing spills. | `REQUIRED` | `test_01_briggs_and_george_conservative_coalescing` |
| `REQ-C18-03` | Exact call-site liveness tracking (`live_across_call`) in backward CFG liveness sweep, identifying every SSA variable live across any `call` instruction boundary. | `REQUIRED` | `test_02_call_site_liveness_and_abi_callee_saved_partitioning` |
| `REQ-C18-04` | ABI-aware caller-saved vs. callee-saved register partitioning across Windows x64 (`WIN64_CALLER_SAVED` / `WIN64_CALLEE_SAVED`), System V AMD64 (`SYSV64_CALLER_SAVED` / `SYSV64_CALLEE_SAVED`), and ARM64 AAPCS64 (`ARM64_CALLER_SAVED` / `ARM64_CALLEE_SAVED`). | `REQUIRED` | `test_02`, `test_03` |
| `REQ-C18-05` | Loop-depth-weighted spill selection (`10^loop_depth / degree`) and `Freeze` transition under high chromatic pressure ($> K$ simultaneously live variables). | `REQUIRED` | `test_04_freeze_and_loop_weighted_spill_under_chromatic_pressure` |
| `REQ-C18-06` | Integration into `NativeCodeGenerator` and `OmniRepoCompiler` AOT compilation pipeline, prioritizing volatile caller-saved registers in leaf functions (`prologue_size == 0` when $\le 3$ caller-saved registers suffice) and recording `irc_coalesced_moves`. | `REQUIRED` | `test_05`, `test_06` |
| `INV-C18-01` | Zero regressions across all 137 tests in full repository discovery (`tests/`). | `REQUIRED` | `run_full_regression.py` + `unittest discover` |
