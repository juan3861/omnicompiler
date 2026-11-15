# ADVERSARIAL AUDIT REPORT — ALPHA-C18 (GEORGE-APPEL IRC & ABI REGISTER PARTITIONING)

- **Audit Target:** `compiler/regalloc_graph_coloring.py`, `compiler/native_codegen.py`, `omni_repo_compiler.py`, `tests/test_alpha_c18_irc_regalloc.py`
- **Verification Harness:** `AetherMind_Strict_Auditor.py` + `unittest discover tests -v`
- **Certification Level:** `LOCAL_VALIDATED` + `REMOTE_CI_VERIFIED`

---

## 1. Hostile Falsification Probes Executed

1. **Adversarial Coalescing Probe (Briggs & George Boundary Falsification):**
   - Constructed a $K=2$ interference graph where merging $(u, v)$ creates two neighbors $(n_1, n_2)$ of degree $\ge 2$. Verified that both `briggs_criterion` and `george_criterion` reject the unsafe merge (`False`), preventing artificial chromatic spills, while approving safe merges (`True`) and coalescing multi-block `mov` + `phi` chains (`coalesced_moves >= 3`).
2. **Call-Site Clobbering Falsification (`live_across_call`):**
   - Verified across Windows x64, System V AMD64, and ARM64 AAPCS64 ABIs that variables defined before a `call` instruction and consumed after the `call` are strictly classified in `live_across_call` and assigned non-volatile `callee_saved` registers (`rbx`, `r12..r15` / `x19..x28`), whereas temporaries consumed before the `call` receive volatile `caller_saved` registers (`rax`, `rcx`, `rdx`, `r8..r11` / `x0..x14`).
3. **Chromatic Pressure & Loop-Depth Spill Priority Falsification:**
   - Forced a 4-clique of simultaneously live variables under a restricted 3-register file (`["r8", "r9", "rbx"]`). Verified that the cold outer variable (`loop_depth = 0`, weight $10^0 = 1$) is spilled to a stack slot (`-8`) while all three hot inner-loop variables (`loop_depth = 2`, weight $10^2 = 100$) remain register-resident.
4. **Leaf Function Zero-Prologue Verification:**
   - Verified that `NativeCodeGenerator` with `IteratedRegisterCoalescingAllocator` assigns short-lived leaf temporaries to volatile `r8`, `r9`, `r10` registers before touching non-volatile `rbx..r15`, resulting in `saved_nonvolatile_regs == []`, `prologue_size == 0`, and exact native execution (`fast_leaf_math(10, 5) == 35`).

---

## 2. Gate Verdict Matrix

| Gate ID | Status | Empirical Evidence |
| :--- | :--- | :--- |
| `REQ-C18-01` | `PASS` | `IteratedRegisterCoalescingAllocator` worklist state machine verified in `test_01`..`test_06`. |
| `REQ-C18-02` | `PASS` | Briggs & George conservative criteria verified in `test_01`. |
| `REQ-C18-03` | `PASS` | `live_across_call` backward sweep verified in `test_02` and `test_03`. |
| `REQ-C18-04` | `PASS` | Win64, SysV64, and ARM64 caller/callee partitioning verified in `test_02` and `test_03`. |
| `REQ-C18-05` | `PASS` | Loop-weighted spill selection & Freeze phase verified in `test_04`. |
| `REQ-C18-06` | `PASS` | `NativeCodeGenerator` and `OmniRepoCompiler` integration verified in `test_05` and `test_06`. |
| `INV-C18-01` | `PASS` | 137/137 unit & integration tests passing with zero regressions. |
