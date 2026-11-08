"""Print every case of test_sdk_path_filter.py with expected and actual.

Usage: python3 cases.py <repo-root>   (sdk.yml and the test read from there)
"""
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location(
    "f", root / ".github/scripts/test_sdk_path_filter.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
bad = 0
for label, changed, runs in mod.CASES:
    got = mod.run_for(changed) == "run=true"
    ok = got == runs
    bad += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {label:45} expect={'run ' if runs else 'skip'} got={'run ' if got else 'skip'} {changed}")
print(f"{len(mod.CASES)} cases, {bad} wrong")
sys.exit(1 if bad else 0)
