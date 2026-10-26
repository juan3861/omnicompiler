# SEARCH QUERIES AND LIMITS — DISCOVERY-100 (ALPHA-C7)
**Protocol:** MASTER PROMPT ALPHA-C7 DISCOVERY-100  
**Data:** 2026-10-26  
**Status:** CONCLUÍDO (100 Repositórios Canônicos Únicos Catalogados)  

---

### 1. Resumo Quantitativo das Métricas de Descoberta
- **`FOUND_UNIQUE`:** 100 / 100
- **`PREVIEWED`:** 100
- **`DEEP_REVIEWED`:** 20 (candidatos com relevância $\ge 80/100$)
- **`STAGED`:** 20 (encaminhados para avaliação em staging)
- **`INTEGRATED`:** 1 (integração autorizada de maior impacto imediato: Emissão Mach-O 64-bit multi-target)
- **`VERIFIED`:** 1 (comprovado por testes e oráculos formais)
- **`UNVERIFIED`:** 0

---

### 2. Famílias de Consulta e Cadeias de Sinônimos

| Família de Busca | Termos e Consultas Utilizadas | Domínio Alvo |
| :--- | :--- | :--- |
| **Família 1: Emissão Mach-O & Linkers** | `mach-o 64 bit emitter`, `pure binary linker`, `LC_SEGMENT_64`, `object file generation`, `faerie rust`, `goblin macho`, `mold macho linker` | GAP-01 (Emissão macOS/Apple Silicon) |
| **Família 2: DWARF Debug Line Encoding** | `dwarf line table serializer`, `leb128 line number state machine`, `gimli dwarf`, `debug_line encoder` | GAP-02 (Tabela de Linhas de Debug) |
| **Família 3: SIMD Auto-Vectorization** | `highway simd runtime dispatch`, `ispc spmd vectorizer`, `sleef elementary functions`, `simd loop unrolling` | GAP-03 (Auto-Vetorização Numérica) |
| **Família 4: Alocação de Registradores** | `regalloc2 backtracking`, `chaitin-briggs graph coloring zero spill`, `linear scan register allocator` | Core Hardening (Alocação de Registradores) |
| **Família 5: SMT & Translation Validation** | `alive2 translation validation`, `z3 bitvector qf_bv`, `cvc5 bitvector`, `formal equivalence proof` | Core SMT Refinement |
| **Família 6: E-Graphs & Term Rewriting** | `egg equality saturation`, `egglog datalog rewriting`, `e-graph extraction heuristic` | Core E-Graph Optimizer |
| **Família 7: Superotimização Assembly** | `alphadev mcts assembly`, `souper smt synthesis`, `stoke stochastic superoptimizer` | Core MCTS Superoptimizer |
| **Família 8: Lógica de Separação & Heap** | `meta infer bi-abduction`, `pulse separation logic`, `memory frame axiom array theory` | Core Memory Safety |
| **Família 9: Code Property Graph** | `cpg taint tracking`, `joern code property graph`, `interprocedural dataflow reachability` | Core Tenant Isolation |
| **Família 10: Sandboxing & Emulação** | `unicorn cpu emulation`, `wasmtime wasi component model`, `capstone disassembly` | Core Silicon Safety |

---

### 3. Critérios de Deduplicação e Regras Anti-Gaming
1. **Deduplicação Canônica:** Espelhos (*mirrors*), forks secundários sem alteração de arquitetura e forks puramente cosméticos foram descartados em favor do repositório canônico upstream.
2. **Separação de Peça vs Repositório:** A pontuação no catálogo foi atribuída à engrenagem técnica específica de interesse, e não à popularidade estelar do repositório.
3. **Limiares de Triagem:**
   - $\text{Relevância} \ge 80/100 \implies$ Elegível para staging em `external_component_candidates/selected/`.
   - $\text{Relevância} \in [60, 79] \implies$ Mantido em reserva técnica (`RESERVE`).
   - $\text{Relevância} < 60 \implies$ Arquivado com justificativa (`ARCHIVED`).
