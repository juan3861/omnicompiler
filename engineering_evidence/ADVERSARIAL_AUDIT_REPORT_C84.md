# Adversarial Audit Report - Alpha-C84

## Counter-Corruption Proofs
1. Real `X64CodeGenerator` SysV and Win64 native machine bytes are decoded directly from bytes (no IR caching or shortcuts) and proven Z3 equivalent to the input `SSAFunction`.
2. Real `Arm64CodeGenerator` AAPCS64 native bytes including spilled frame slots `[sp, #imm]` and shift division lowering are decoded from 32-bit words and proven Z3 equivalent.
3. Multi-block `while` loops compiled for both `x86_64` and `arm64` lift with back-edge header PHIs and pass Z3 equivalence.
4. Flipping a single immediate byte in either emitted `x86_64` or `arm64` machine code is immediately caught with `REFUTED_COUNTEREXAMPLE`.
