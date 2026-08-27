"""Generate a measured parser-onboarding comparison from repository files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "src" / "aegisguard_ulpf" / "parsing" / "vendors" / "palaalto" / "panos" / "traffic.py"
PACK = ROOT / "examples" / "semantic_packs" / "demo_vendor" / "semantic_pack.json"

def main():
    legacy_lines = len(LEGACY.read_text(encoding="utf-8").splitlines())
    pack_lines = len(PACK.read_text(encoding="utf-8").splitlines())
    report = ROOT / "docs" / "parser_effort_benchmark.md"
    report.write_text(f"# Parser Effort Benchmark\n\nMeasured on this checkout.\n\n| Approach | Files inspected | Lines |\n|---|---:|---:|\n| Existing PAN-OS Traffic parser | 1 | {legacy_lines} |\n| DemoVendor declarative Semantic Pack | 1 | {pack_lines} |\n\nNo development-time claim is made: repository history does not contain comparable timed onboarding measurements. Run `python scripts/measure_parser_effort.py` to refresh these file measurements.\n", encoding="utf-8")
    print(report)
if __name__ == "__main__": main()
