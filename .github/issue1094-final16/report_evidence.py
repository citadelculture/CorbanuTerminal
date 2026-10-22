"""Capture the observed Nextest report and pending snapshots before source checks."""
from pathlib import Path
import shutil

from hosted_controls import digest, write_json

# Frozen wrapper selects profile.local. Actual 0.9.146 run 39715280360 wrote
# /src/codex-rs/target/nextest/local/junit.xml despite CARGO_TARGET_DIR=/scratch/target.
# Mount only that report-store directory; do not change wrapper/config/CLI flags.
REPORT_MOUNT = Path('/src/codex-rs/target/nextest')
REPORT_RELATIVE = Path('local/junit.xml')


def capture_report_evidence(report_root, source, evidence, label, snapshot_paths,
                            available, reserve):
    """Try every exact evidence file; record failures without hiding other files."""
    record = {'reportRoot': str(report_root), 'expectedJUnit': str(REPORT_RELATIVE),
              'copiedJUnit': [], 'copiedSnapshots': [], 'missing': [], 'errors': [],
              'sourceInvariantNotEvaluatedHere': True}

    def copy_exact(path, root, destination, limit, field):
        try:
            if path.is_symlink():
                raise RuntimeError('Expected evidence file is a symlink')
            if not path.exists():
                record['missing'].append(str(path))
                return
            if not path.is_file() or path.resolve() != root.resolve() / path.relative_to(root):
                raise RuntimeError('Expected evidence path is not a contained regular file')
            size = path.stat().st_size
            if size > limit or available() - size < reserve:
                raise RuntimeError('Evidence capture size/reserve bound refused')
            expected = digest(path)
            with path.open('rb') as input_stream, destination.open('xb') as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            if destination.stat().st_size != size or digest(destination) != expected or digest(path) != expected:
                raise RuntimeError('Evidence bytes changed during preservation')
            record[field].append({'sourcePath': str(path), 'path': destination.name,
                                  'bytes': size, 'sha256': expected})
        except BaseException as error:
            record['errors'].append({'path': str(path), 'error': type(error).__name__ + ': ' + str(error)})

    try:
        copy_exact(report_root / REPORT_RELATIVE, report_root,
                   evidence / (label + '-junit-0.xml'), 16 * 1024**2, 'copiedJUnit')
        for name in sorted(snapshot_paths):
            path = source / name
            copy_exact(path, source, evidence / path.name, 1024**2, 'copiedSnapshots')
        # This is a narrow report namespace, not a source-drift allowance.
        # Preserve the expected files first even when an unexpected report exists.
        record['reportFiles'] = sorted(str(path.relative_to(report_root))
                                       for path in report_root.rglob('*')
                                       if path.is_file() or path.is_symlink())
        unexpected = sorted(set(record['reportFiles']) - {str(REPORT_RELATIVE)})
        if unexpected:
            record['errors'].append({'path': str(report_root),
                                     'error': 'Unexpected report-store paths: ' + repr(unexpected)})
    except BaseException as error:
        record['errors'].append({'path': str(report_root), 'error': type(error).__name__ + ': ' + str(error)})
    finally:
        write_json(evidence / (label + '-report-snapshot-preservation.json'), record)
    if record['errors']:
        raise RuntimeError('Expected report/snapshot capture incomplete; see preservation receipt')
    return record
