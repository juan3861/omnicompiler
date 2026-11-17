import sys
import unittest

sys.path.insert(0, r"F:\repository-compiler")

test_modules = [
    "tests.test_alpha_c13_stateful_selection",
    "tests.test_alpha_c14_multiblock_lto_simd",
    "tests.test_alpha_c15_stack_promotion",
    "tests.test_alpha_c16_autovec_and_ffi",
    "tests.test_alpha_c17_aot_compiler",
    "tests.test_alpha_c18_irc_regalloc",
    "tests.test_alpha_c19_vla_polyhedral",
    "tests.test_alpha_c20_ipsccp_gvn",
    "tests.test_alpha_c21_licm_dse",
    "tests.test_alpha_c22_tco_layout",
    "tests.test_alpha_c23_sroa_devirt",
    "tests.test_alpha_c24_smt_translation_validation",
    "tests.test_alpha_c25_unified_smt_aot",
    "tests.test_alpha_c26_inductive_and_backend_tv",
    "tests.test_alpha_c27_polyglot_aot_and_call_tv",
    "tests.test_alpha_c28_nested_loops_and_mem_tv",
    "tests.test_alpha_c29_recursive_loops_and_polyglot_ext",
    "tests.test_alpha_c30_ieee754_float_stack",
    "tests.test_alpha_c31_f64_memory_and_inductive_qfabvfp",
    "tests.test_alpha_c32_f64_autovec_thinlto_and_omnirepo",
    "tests.test_alpha_c33_cabi_structs_narrow_widths_and_f64_ffi",
    "tests.test_alpha_c34_sub32_widths_and_nested_structs",
    "tests.test_alpha_c35_embedded_arrays_and_cabi_strides",
    "tests.test_alpha_c36_match_switch_and_rodata_luts",
    "tests.test_alpha_c37_z3_bounds_salsa_and_os_cdll",
    "tests.test_alpha_c38_cli_and_top100_ceiling_audit",
    "tests.test_alpha_c40_stress_metacognition",
    "tests.test_alpha_c42_c43_disk_salsa_and_cpp",
    "tests.test_alpha_c44_c45_os_imports_and_11langs",
    "tests.test_native_composite_collections",
    "tests.test_ceiling_engineering_complete",
]

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for mod in test_modules:
        suite.addTests(loader.loadTestsFromName(mod))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
