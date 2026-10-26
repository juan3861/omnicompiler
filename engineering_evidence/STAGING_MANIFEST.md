# STAGING MANIFEST — DISCOVERY-100 (ALPHA-C7)
**Protocol:** MASTER PROMPT ALPHA-C7 DISCOVERY-100  
**Staging Directory:** `external_component_candidates/selected/`  
**Data:** 2026-10-26  

---

### 1. Engrenagens Qualificadas para Staging ($\text{Relevância} \ge 80/100$)

| ID | Repositório de Origem | Engrenagem Selecionada | Relevância | Prontidão | Decisão |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `GEAR-001` | `gimli-rs/object` | Arquitetura unificada de cabeçalhos e seções Mach-O 64-bit | 95 | 88 | **SELECIONADA P/ INTEGRAÇÃO** |
| `GEAR-002` | `m4b/goblin` | Especificação de Load Commands (`LC_SEGMENT_64`, `LC_MAIN`) | 92 | 85 | **SELECIONADA P/ INTEGRAÇÃO** |
| `GEAR-003` | `gimli-rs/gimli` | State Machine de linhas DWARF v4/v5 (LEB128) | 90 | 82 | Reserva p/ Próximo Ciclo |
| `GEAR-004` | `rui314/mold` | Otimização de concorrência em relocação de símbolos | 89 | 75 | Reserva Técnica |
| `GEAR-005` | `bytecodealliance/regalloc2` | Algoritmo backtracking SSA para alocação de registradores | 88 | 84 | Reserva Técnica |
| `GEAR-006` | `google/highway` | Runtime dispatch para seleção de instruções AVX2/NEON | 86 | 70 | Reserva Técnica |
| `GEAR-007` | `angr/cle` | Carregador e oráculo estrutural de binários Mach-O | 87 | 89 | **SELECIONADA P/ VALIDAÇÃO** |
| `GEAR-008` | `al45tair/faerie` | Padrões de emissão direta de Mach-O em código freestanding | 85 | 80 | Referência de Staging |
| `GEAR-009` | `trailofbits/maco` | Validador de invariantes de segmentos Mach-O em Python | 88 | 90 | **SELECIONADA P/ VALIDAÇÃO** |
| `GEAR-010` | `bytecodealliance/cranelift` | Lowering de IR retargetável para x86_64 e ARM64 | 89 | 78 | Reserva Técnica |
| `GEAR-011` | `egraphs-good/egg` | Heurísticas de extração de custo mínimo em E-Graphs | 85 | 76 | Reserva Técnica |
| `GEAR-012` | `egraphs-good/egglog` | Fusão de igualdade saturada com regras relacionais | 82 | 72 | Reserva Técnica |
| `GEAR-013` | `AliveToolkit/alive2` | Formalização de semântica de refinamento bit-exact | 86 | 75 | Reserva Técnica |
| `GEAR-014` | `slp/wild` | Padrões de layout de tabela de símbolos em memória | 84 | 74 | Reserva Técnica |
| `GEAR-015` | `google/souper` | Síntese de transformações por contra-exemplos SMT | 83 | 72 | Reserva Técnica |
| `GEAR-016` | `StanfordPL/stoke` | Formulação de custo para superotimização estocástica | 81 | 70 | Reserva Técnica |
| `GEAR-017` | `asmjit/asmjit` | Tabelas de codificação de opcodes x86-64 e AArch64 | 84 | 80 | Reserva Técnica |
| `GEAR-018` | `facebook/infer` | Teoremas de enquadramento de memória (bi-abduction) | 82 | 71 | Reserva Técnica |
| `GEAR-019` | `joernio/joern` | Rastreamento interprocedural de taint em CPG | 83 | 75 | Reserva Técnica |
| `GEAR-020` | `jart/cosmopolitan` | Truques de cabeçalhos binários universais portáveis | 85 | 81 | Referência de Staging |

---

### 2. Justificativa da Escolha para Implementação Imediata
A integração escolhida para esta iteração do Protocolo ALPHA-C7 ataca diretamente a lacuna prioritária **GAP-01**:
**Implementação da Emissão Direta e Validação Estrutural de Binários Mach-O 64-bit (macOS x86-64 e Apple Silicon ARM64)**.
- **Benefício Líquido Demonstrável:** Eleva o OmniCompiler para suporte universal aos **três grandes sistemas operacionais do planeta** (Windows PE32+, Linux ELF64 e macOS Mach-O 64), cobrindo tanto executáveis standalone quanto bibliotecas compartilhadas (`.dylib`), sem nenhuma dependência de GCC/Clang/MSVC ou de Xcode local.
- **Princípio da Menor Alteração:** Extensão modular e limpa nos módulos canônicos `compiler/binary_emitter.py`, `compiler/object_linker.py`, `omni_repo_compiler.py`, `omnicompiler_cli.py` e `validation/binary_structure_auditor.py`.
- **Risco & Reversibilidade:** Risco baixo; as emissões existentes (PE e ELF) mantêm-se 100% inalteradas e preservadas.
