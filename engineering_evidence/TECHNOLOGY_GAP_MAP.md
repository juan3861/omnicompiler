# TECHNOLOGY GAP MAP — OMNICOMPILER (ALPHA-C7)
**Version:** 7.0.0  
**Data:** 2026-10-26  

---

### Mapeamento das Lacunas Tecnológicas Concretas

| ID da Lacuna | Descrição Técnica da Lacuna | Impacto no Projeto | Complexidade / Risco |
| :--- | :--- | :--- | :--- |
| **GAP-01: Suporte Mach-O (macOS / Apple Silicon)** | O emissor binário suporta Windows PE32+ e Linux ELF64, mas não suporta o formato Mach-O 64-bit de executáveis (`MH_EXECUTE`) e dylibs (`MH_DYLIB`) para x86-64 e ARM64 (Apple Silicon). | **Alto**: Impede que o compilador seja verdadeiramente "trio universal" de sistemas operacionais (Windows, Linux, macOS). | Moderado: Exige estruturas de cabeçalho `mach_header_64`, load commands (`LC_SEGMENT_64`, `LC_MAIN`, `LC_ID_DYLIB`) e alinhamento de 16KB. |
| **GAP-02: Tabela de Linhas de Depuração DWARF / PDB** | Os binários emitidos não possuem metadados de debug DWARF (`.debug_line` / `.debug_info`), impedindo que ferramentas de diagnóstico (`lldb`, `gdb`, `perf`) mapeiem instruções para linhas de código fonte. | **Médio**: Afeta observabilidade e debugging em ambientes de produção. | Moderado: Exige codificação DWARF v4/v5 com State Machine de números de linha (LEB128). |
| **GAP-03: Auto-Vetorização SIMD (AVX2 / NEON)** | O pipeline gera apenas código escalar; laços computacionais intensivos não são vetorizados em registradores YMM (AVX2) ou Q-registers (ARM NEON). | **Alto**: Limita throughput em kernels numéricos de alta densidade. | Alto: Exige análise de dependência de dados poliédrica e seleção de instruções vetorizadas. |
| **GAP-04: Hot-Patching Incremental no Linker** | O linker recompila e reloca a imagem inteira contiguamente a cada invocação, sem suporte a remendo atômico de funções via *thunks* de salto indireto. | **Médio**: Impacta tempo de recarga rápida em compilação contínua. | Baixo-Médio: Exige geração de jump tables relocáveis. |
| **GAP-05: WASI Preview 2 / Component Model** | O backend WebAssembly emite WAT/Wasm básico de módulo único, sem suporte aos tipos canônicos de interfaces do WASI Preview 2 (wit). | **Médio**: Limita interoperabilidade com runtimes modernos de borda (edge computing). | Alto: Exige parser de schemas WIT e lowering da ABI canônica. |
