"""Run every demo in order (the full live-presentation script).

    python run_all.py           # non-stop
    python run_all.py --pause   # stop after each step (use this when presenting)
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
DEMOS = [
    "demo1_correct_use.py",
    "demo2_nonce_reuse_attack.py",
    "demo3_defense_rfc6979.py",
    "demo4_rsa_textbook_vs_pss.py",
]

if __name__ == "__main__":
    extra = sys.argv[1:]
    results = []
    for demo in DEMOS:
        code = subprocess.call([sys.executable, str(HERE / demo), *extra], cwd=HERE)
        results.append((demo, code))
    print("\nSUMMARY")
    for demo, code in results:
        print(f"   {'PASS' if code == 0 else 'FAIL'}  {demo}")
    sys.exit(max(code for _, code in results))
