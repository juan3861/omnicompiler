import sys
import os

repo_root = r"F:\repository-compiler"
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

evidence_dir = os.path.join(repo_root, "engineering_evidence")
os.makedirs(evidence_dir, exist_ok=True)
out_file = os.path.join(evidence_dir, "c15_test_output.txt")

with open(out_file, "w", encoding="utf-8") as out:
    import unittest
    suite = unittest.defaultTestLoader.discover(
        os.path.join(repo_root, "tests"),
        pattern="test_alpha_c15_stack_promotion.py"
    )
    runner = unittest.TextTestRunner(stream=out, verbosity=2)
    result = runner.run(suite)
    out.write(f"\nRESULT_SUCCESS={result.wasSuccessful()}\n")
    out.write(f"TESTS_RUN={result.testsRun}\n")
    out.write(f"ERRORS={len(result.errors)}\n")
    out.write(f"FAILURES={len(result.failures)}\n")

print(f"C15_TESTS_FINISHED: success={result.wasSuccessful()}, run={result.testsRun}, errors={len(result.errors)}, failures={len(result.failures)}", flush=True)

sys.exit(0 if result.wasSuccessful() else 1)
