import unittest
from slicer.tree_sitter_polyglot import TreeSitterPolyglotEngine


class TestTreeSitterPolyglot(unittest.TestCase):
    def setUp(self):
        self.engine = TreeSitterPolyglotEngine()

    def test_c_prototype_parsing(self):
        c_code = b"""
        int64_t matrix_multiply(const double* a, const double* b, int64_t n);
        void reset_state();
        static int helper(int x) { return x + 1; }
        """
        symbols = self.engine.parse_c_symbols(c_code, "include/math_core.h")
        self.assertGreater(len(symbols), 0)
        names = [s.name for s in symbols]
        self.assertIn("matrix_multiply", names)
        self.assertIn("reset_state", names)

        # Check parameter extraction for matrix_multiply
        mm_sym = next(s for s in symbols if s.name == "matrix_multiply")
        self.assertEqual(mm_sym.params, ["a", "b", "n"])
        self.assertEqual(mm_sym.return_type, "int64_t")

    def test_rust_function_parsing(self):
        rust_code = b"""
        pub fn compute_hash(seed: u64, rounds: u32) -> u64 {
            seed ^ (rounds as u64)
        }

        fn internal_scramble(val: u64) -> u64 {
            val.rotate_left(3)
        }

        pub fn execute_transaction(account_id: i64) {
        }
        """
        symbols = self.engine.parse_rust_symbols(rust_code, "src/crypto.rs")
        self.assertGreater(len(symbols), 0)
        names = [s.name for s in symbols]
        self.assertIn("compute_hash", names)
        self.assertIn("execute_transaction", names)
        self.assertNotIn("internal_scramble", names)  # private fn should not be exported

        hash_sym = next(s for s in symbols if s.name == "compute_hash")
        self.assertEqual(hash_sym.params, ["seed", "rounds"])
        self.assertEqual(hash_sym.return_type, "u64")

    def test_python_symbol_parsing(self):
        py_code = b"""
        def calculate_velocity(distance: float, time: float) -> float:
            return distance / time

        def _hidden_routine():
            pass
        """
        symbols = self.engine.parse_python_symbols(py_code, "physics.py")
        names = [s.name for s in symbols]
        self.assertIn("calculate_velocity", names)
        self.assertNotIn("_hidden_routine", names)

        vel_sym = next(s for s in symbols if s.name == "calculate_velocity")
        self.assertEqual(vel_sym.params, ["distance", "time"])


if __name__ == "__main__":
    unittest.main()
