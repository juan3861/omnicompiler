import sys
import subprocess
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

target_script = sys.argv[1] if len(sys.argv) > 1 else r"F:\repository-compiler\run_c14_tests.py"

cmd = [
    r"C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe",
    r"F:\AetherMind_Apotheosis_Final\aethermind_apotheosis\AetherMind_Strict_Auditor.py",
    target_script,
]
result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

evidence_file = r"F:\repository-compiler\engineering_evidence\strict_auditor_output.txt"
with open(evidence_file, "w", encoding="utf-8") as f:
    f.write(result.stdout + "\n" + result.stderr)

# Clean print to stdout
print("STRICT_AUDITOR_RESULT: returncode=" + str(result.returncode), flush=True)
for line in result.stdout.splitlines():
    ascii_line = line.encode("ascii", errors="replace").decode("ascii")
    print("   " + ascii_line, flush=True)

sys.exit(result.returncode)
