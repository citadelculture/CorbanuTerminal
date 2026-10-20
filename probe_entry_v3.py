"""Proposed synthetic child only; no sandbox invocation or default execution."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise RuntimeError("Proposed method is macOS-only; no cross-platform qualification")
    manifest = json.loads(args.manifest.read_text())
    if manifest.get("schema") != "network-address-fixture-instance-v3":
        raise RuntimeError("Wrong fixture manifest")
    markers = {key: os.environ.get(key)
               for key in ("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")}
    marker_hash = hashlib.sha256(
        json.dumps(markers, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if marker_hash != manifest["inheritedMarkersSha256"]:
        raise RuntimeError("Inherited controls differ from the parent observation")
    module_path = Path(__file__).resolve().with_name("address_boundary_fixtures_v3.py")
    if module_path.is_symlink():
        raise RuntimeError("Unexpected fixture symlink")
    if hashlib.sha256(module_path.read_bytes()).hexdigest() != manifest["fixtureSha256"]:
        raise RuntimeError("Fixture source changed")
    spec = importlib.util.spec_from_file_location("fixed_boundary_fixtures", module_path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    cases = [case for case in fixture.CASES if case["id"] == args.case]
    if len(cases) != 1 or manifest["fixedCaseIds"] != [case["id"] for case in fixture.CASES]:
        raise RuntimeError("Unknown or changed fixed case set")
    result = fixture.probe(cases[0], manifest, args.token)
    result["inheritedMarkersMatched"] = True
    result["fixtureSha256"] = manifest["fixtureSha256"]
    print(json.dumps(result, sort_keys=True))
    # Zero means a complete observation, not acceptance of a denial or policy.
    return 0 if result["status"] in ("connected", "permission_denied") else 1


if __name__ == "__main__":
    raise SystemExit(main())
