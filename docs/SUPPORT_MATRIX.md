# Repository Compiler v2.0 — Matriz Oficial de Capacidades e Suporte Comprovado

**Data:** 19/10/2026  
**Versão:** `2.0.0-self-hosted`  
**Regra de Publicação (P5):** Nenhuma linguagem ou fronteira é listada como suportada para execução apenas porque seu parser aceita arquivos; cada linha distingue explicitamente **Indexação AST** vs. **Execução E2E Verificada**.

---

## 1. Matriz de Linguagens, Runtimes e Fronteiras

| Linguagem / Runtime | Extração Estrutural (AST / CST) | Fatiamento Cirúrgico (Slicing) | Síntese de Adapter & Execução E2E | Fronteira de Comunicação | Status Empírico |
|---|---|---|---|---|---|
| **Python 3.11+ (`cpython`)** | `ast` + `Instagram/LibCST` + `ast-grep-py` + `networkx` | **Sim** (Remoção de código morto, imports quebrados e arquivos órfãos via `CapsuleExtractor`) | **Sim (L0–L2)** (`python_callable`, classes, `async` coroutines, auto-init de protocolo e isolamento `sys.modules`) | In-Process Scoped Namespace (`spec_from_file_location` + `sys.modules` context switch) | **PROVADO** (`T01`–`T09`, `T13`–`T19`, Self-Hosting v2.0) |
| **JavaScript (`Node.js v22`)** | `ast-grep-py` + `tree-sitter-javascript` | Preservação integral de módulo | **Sim (L0–L2)** (`node_callable` via IPC Bridge + tradução semântica `_ALIAS_MAP`) | Subprocesso IPC Isolado (`node -e` JSON Bridge) | **PROVADO** (`T10_dev_polyglot_python_nodejs`) |
| **TypeScript (`Node.js v22 --experimental-strip-types`)** | `ast-grep-py` + `tree-sitter-typescript` | Preservação integral de módulo | **Sim (L0–L2)** (`node_callable` com execução nativa `.ts` via strip-types) | Subprocesso IPC Isolado (`node --experimental-strip-types`) | **PROVADO** (`T20_holdout_polyglot_python_typescript`) |
| **Rust (`.rs`) & Go (`.go`)** | `ast-grep-py` + `tree-sitter-rust` / `tree-sitter-go` | Somente Indexação | Não (Requer compilação para Wasm/WIT via `cargo-component` / `wac`) | Contrato `manifests/component_world.wit` emitido | **INDEXAÇÃO PROVADA / EXECUÇÃO VIA WIT** |

---

## 2. Matriz das 8 Categorias do Corpus P4 (20 Tarefas: 12 Dev + 8 Holdout)

| Categoria (`PLANO_DE_EXECUCAO.md` Seção 8) | Tarefas Dev (`T01`–`T12`) | Tarefas Holdout (`T13`–`T20`) | Mecanismo Técnico Comprovado |
|---|---|---|---|
| `same_lang_lib_app` | `T01`, `T02`, `T11` (Negativo) | `T13` | Costura automática de fluxo de dados $A \to B$ via Z3 SMT + isolamento por tenant |
| `frontend_to_api` | `T03` | `T14` | Tradução semântica L2 (`event_id -> id`, `payload -> body`, `subtotal -> price`) |
| `data_pipeline` | `T04`, `T05`, `T12` (Negativo/Trap) | `T15` | Propagação automática de saída transformada em $A$ para indexação/agregação em $B$ |
| `plugin_extension` | `T06` | `T16` | Acoplamento de Host a Plugins de Criptografia Envelope e Assinatura HMAC |
| `stateful_init_component` | `T07` | `T17` | Transição automática de protocolo `uninitialized -> ready` (`connect()`, `initialize()`) |
| `persistent_state_component` | `T08` | `T18` | Persistência real em disco (JSON e SQLite) sobrevivendo entre subprocessos isolados |
| `dependency_conflict` | `T09` (`shared_codec` v1 vs v2) | `T19` (`crypto_core` ABI 1 vs 2) | Context-switching escopado de `sys.modules` e `sys.path` por componente no mesmo processo |
| `polyglot_bridge` | `T10` (Python $\to$ JS) | `T20` (Python $\to$ TypeScript `.ts`) | Execução poliglota real entre Python 3.11 e Node.js v22 com dataflow sintetizado por Z3 |

---

## 3. Taxonomia Estável de Diagnóstico de Falhas (Seção 5)

| Código Estável (`error_code`) | Gatilho Determinístico |
|---|---|
| `intent_ambiguous` | `IntegrationSpec` sem capacidades requeridas ou sem cenários de aceitação |
| `baseline_failed` | Erro de sintaxe/AST ou falha de baseline nos repositórios doadores |
| `unsupported_language` | Nenhum símbolo extraído pelos frontends |
| `no_plan_in_model` | Solver ASP (`potassco/clingo`) retorna `UNSAT` (ex: efeito colateral proibido `write:storage`) |
| `unresolved_dependency` | Falha na resolução do módulo provedor durante `global:health_check` |
| `protocol_mismatch` | Violação de ciclo de vida de inicialização |
| `synthesis_timeout` | Subprocesso excede o orçamento de tempo |
| `verification_failed` | Divergência de saída no oráculo independente ou violação de invariante (ex: vazamento de tenant) |
