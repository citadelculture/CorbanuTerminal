"""Freeze/check exact underlying tool binaries inside the prepared image."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from hosted_controls import digest, write_json

TOOLS = ('rustc', 'cargo', 'rustup', 'python3', 'just', 'cargo-nextest', 'cmake', 'rg',
         'cc', 'c++', 'clang', 'clang++', 'ar', 'ld', 'pkg-config', 'ninja', 'protoc')


def observe_tools():
    records = {}
    for tool in TOOLS:
        if tool in ('rustc', 'cargo'):
            path = Path(subprocess.check_output(['rustup', 'which', '--toolchain', '1.99.1', tool], text=True).strip()).resolve(strict=True)
        else:
            found = shutil.which(tool)
            if not found:
                raise RuntimeError('Required public tool absent: ' + tool)
            path = Path(found).resolve(strict=True)
        argv = [str(path), 'nextest', '--version'] if tool == 'cargo-nextest' else [str(path), '--version']
        version = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15)
        records[tool] = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest(path),
                         'version': (version.stdout + version.stderr).strip()}
    assert records['rustc']['version'].startswith('rustc 1.99.1 ')
    assert records['just']['version'] == 'just 1.58.0'
    assert '0.9.146' in records['cargo-nextest']['version']
    return records


def compare_tools(expected, observed):
    if expected != observed:
        differences = sorted(name for name in set(expected) | set(observed) if expected.get(name) != observed.get(name))
        raise RuntimeError('Frozen real-tool manifest mismatch: ' + ', '.join(differences))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    write_json(args.destination, observe_tools())
    print('Frozen actual-tool manifest SHA256:', digest(args.destination))
