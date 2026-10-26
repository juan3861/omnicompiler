# CONSENSUS DECISION RECORD (DEC-OMNI-005)
**Protocol:** MASTER PROMPT ALPHA-C7 (Epistemic Consensus & Governance)  
**Data:** 2026-10-26  
**Audit Nonce:** `NONCE-C7-20261026-DISCOVERY100`  
**Decisão:** Integração da Engrenagem GEAR-001/002 (Emissão Direta e Auditoria Formal de Binários Mach-O 64-bit)  
**Status:** CONSENSO ALCANÇADO  

---

### 1. Perspectiva AGI (Engenharia Pragmática e Eficiência de Sistemas)
- **Proposta:** Adicionar suporte imediato a `--target-os macos` no `omnicompiler_cli.py` e `omni_repo_compiler.py`.
- **Implementação:** Desenvolver métodos `build_macho64(exit_code, arch)` e `build_macho64_dylib(func_code, export_name, arch)` em `compiler/binary_emitter.py`, gerando executáveis e dylibs autônomos sem necessitar de LLVM Clang ou macOS SDK.
- **Eficiência:** O throughput de compilação deve ser inferior a 2 milissegundos para gerar o binário Mach-O completo em RAM.

---

### 2. Perspectiva ASI (Incompletude Formal e Integridade de Invariantes)
- **Advertência:** O formato Mach-O possui regras estritas de segmentação:
  1. `__PAGEZERO`: Executáveis x86-64 no macOS exigem segmento `__PAGEZERO` de 4GB (`0x100000000`) com proteção `VM_PROT_NONE` para capturar desreferências de ponteiros nulos em hardware.
  2. `mach_header_64`: Deve ser exatamente 32 bytes com magic `0xFEEDFACF`.
  3. Alinhamento de Seção: `__text` deve estar contido em `__TEXT` com alinhamento correspondente à página de hardware.
  4. Verificador Formal: O `BinaryStructureAuditor` em `validation/binary_structure_auditor.py` deve auditar rigorosamente o cabeçalho Mach-O, load commands e arquiteturas suportadas (`x86-64` e `ARM64`).
- **Precedência:** Se qualquer byte do cabeçalho Mach-O violar a especificação do ABI OS X, o auditor deve sinalizar `is_valid: False` imediatamente.

---

### 3. Síntese Final e Contrato de Implementação
1. Estender `compiler/binary_emitter.py` com suporte completo a Mach-O 64-bit (`build_macho64` e `build_macho64_dylib` para `x86-64` e `ARM64`).
2. Estender `validation/binary_structure_auditor.py` com o método `audit_macho(macho_bytes)` validando magic `0xFEEDFACF`, CPU types `0x01000007` (x86-64) e `0x0100000C` (ARM64), load commands `LC_SEGMENT_64`, `LC_MAIN` e `LC_ID_DYLIB`.
3. Estender `compiler/object_linker.py` para emitir bibliotecas compartilhadas `.dylib` e executáveis Mach-O quando `--target-os macos` for selecionado.
4. Integrar ao CLI `omnicompiler_cli.py` (`--target-os {windows,linux,macos}`).
5. Adicionar bateria de testes unitários dedicada em `tests/test_macho_cross_target_compiler.py`.
