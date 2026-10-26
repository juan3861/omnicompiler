# EXISTING CAPABILITY MAP — OMNICOMPILER (ALPHA-C7)
**Version:** 7.0.0  
**Data:** 2026-10-26  

---

### Mapeamento Factual das Capacidades Existentes

| Módulo / Subdomínio | Componente Existente | Função Implementada | Status Verificado |
| :--- | :--- | :--- | :---: |
| **Ingestão Multi-Repo** | `orchestrator/repo_manifest_ingestor.py` | Leitura de manifestos JSON/YAML, ordenação topológica Kahn, detecção de ciclos. | PROVADO |
| **Poda de Código Morto** | `slicer/inter_repo_slicer.py` | ThinLTO reachability slicing; invariante de conservação de símbolos. | PROVADO |
| **Grafo de Propriedades (CPG)** | `slicer/persistent_cpg.py` | Armazenamento SQLite com AST + CFG + DDG; isolamento de taint multitenant. | PROVADO |
| **Síntese e Pontes ABI** | `adapters/universal_abi_bridge.py` | Adaptação Windows x64 $\leftrightarrow$ System V AMD64; sintetizador CEGIS via Z3. | PROVADO |
| **Emissão Binária PE32+** | `compiler/binary_emitter.py` | Emissão direta x86-64 / ARM64 para DLL (com `.edata`) e EXE sem dependências. | PROVADO |
| **Emissão Binária ELF64** | `compiler/binary_emitter.py` | Emissão direta x86-64 / ARM64 para Shared Objects (`.dynsym`/`.dynstr`) e binários via `sys_exit`. | PROVADO |
| **Linker de Objetos** | `compiler/object_linker.py` | Resolução de símbolos, relocação `REL32`/`ADDR64` e oráculo `RelocationOutOfBoundsError`. | PROVADO |
| **Auditoria Estrutural** | `validation/binary_structure_auditor.py` | Validação de conformidade formal PE/ELF via `pefile` e `pyelftools` com checagem de alinhamento de página. | PROVADO |
| **Sandbox de CPU Virtual** | `validation/silicon_safety_sandbox.py` | Emulação prévia de CPU x86-64 em Unicorn (captura de null pointers e loops infinitos). | PROVADO |
| **Verificação SMT** | `smt_refinement_validator/` | Validação estilo Alive2 via Z3 bitvectors ($\text{QF\_BV}$). | PROVADO |
| **Otimização E-Graph** | `egraph_optimizer/` | Saturação de igualdade e extração de kernel ótimo. | PROVADO |
| **Superotimizador Assembly** | `mcts_assembly_superoptimizer/` | Busca de sequências de instruções assembly via AlphaDev MCTS. | PROVADO |
| **Alocador de Registradores** | `compiler/regalloc_graph_coloring.py` | Coloração Chaitin-Briggs com 0 spills na arquitetura AMD64. | PROVADO |
| **Ledger Criptográfico** | `compiler/audit_ledger.py` | Assinatura HMAC-SHA256, árvore Merkle de fontes e CLI `audit-attest`. | PROVADO |
