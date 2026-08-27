"""
AegisGuard-ULPF SIH Final Validation Runner

Runs all judge-facing validation flows:
- Core pipeline
- Unknown log handling
- Semantic packs
- Parser drift
- Air-gap readiness
- Traceability verification
"""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent


def run_step(name, command):
    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        print("FAILED")
        print(result.stderr)
        return False

    print(result.stdout)
    print("PASS")
    return True


def main():

    print("""
============================================
 AegisGuard-ULPF SIH FINAL VALIDATION
============================================
""")

    checks = []


    # 1. Core pipeline
    checks.append(
        run_step(
            "1. Core ULPF Pipeline",
            "python demo/run_final_demo.py"
        )
    )


    # 2. Tier-0 unknown handling
    checks.append(
        run_step(
            "2. Tier-0 Unknown Log Handling",
            "python demo/run_unknown_log_demo.py"
        )
    )


    # 3. Semantic packs
    checks.append(
        run_step(
            "3. Semantic Pack Architecture",
            "python demo/run_semantic_pack_demo.py"
        )
    )


    # 4. Parser drift
    checks.append(
        run_step(
            "4. Parser Drift Detection",
            "python demo/run_parser_drift_demo.py"
        )
    )


    # 5. Air gap
    checks.append(
        run_step(
            "5. Air Gap Deployment",
            "python demo/run_airgap_demo.py"
        )
    )


    # 6. Traceability
    checks.append(
        run_step(
            "6. Hash Chain Traceability",
            "python demo/run_traceability_demo.py"
        )
    )


    print("\n" + "=" * 60)
    print("FINAL RESULT")
    print("=" * 60)


    if all(checks):
        print("""
[PASS] Core pipeline operational
[PASS] Multi-vendor normalization
[PASS] Tier-0 fallback
[PASS] Semantic pack onboarding
[PASS] Parser drift detection
[PASS] Air-gap execution
[PASS] Hash-chain verification

AegisGuard-ULPF SIH READY
""")
        return 0

    else:
        print("""
FAILED

One or more validation stages failed.
""")
        return 1



if __name__ == "__main__":
    sys.exit(main())