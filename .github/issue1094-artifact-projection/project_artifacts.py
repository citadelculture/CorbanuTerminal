#!/usr/bin/env python3
"""Project already-produced public evidence; never import or execute its contents."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MIB = 1024 ** 2
GIB = 1024 ** 3
MAX_ARCHIVE = 300 * MIB
MAX_EXPANDED = 2 * GIB
MAX_MEMBER = GIB
MAX_TEXT_MEMBER = 32 * MIB
MAX_TEXT_TOTAL = 96 * MIB
MAX_MEMBERS = 512
CHUNK = MIB
PUBLIC_SUFFIXES = ('.json', '.jsonl', '.log', '.xml', '.txt', '.diff', '.snap.new')
BINARY = re.compile(r'(?:generate|regression)-(?:codex-tui-lib-test|interrupted-codex_tui-[a-f0-9]+)\Z')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Bounds:
    def __init__(self, root, seconds=1200):
        self.root = root
        self.deadline = time.monotonic() + seconds
        self.text_bytes = 0
        self.check(4 * GIB)

    def check(self, reserve=2 * GIB):
        if time.monotonic() > self.deadline:
            raise RuntimeError('Projection wall-clock bound exceeded')
        if shutil.disk_usage(self.root).free < reserve:
            raise RuntimeError('Projection disk reserve refused')


def verify_run(value, pins):
    expected = {'id': pins['runId'], 'head_sha': pins['headSha'],
                'status': 'completed', 'conclusion': 'failure', 'run_attempt': 1}
    if any(value.get(key) != wanted for key, wanted in expected.items()):
        raise RuntimeError('Original run identity/state mismatch')
    if value.get('repository', {}).get('full_name') != pins['repository']:
        raise RuntimeError('Original run repository mismatch')
    return {**expected, 'repository': pins['repository']}


def verify_artifact(value, expected, pins):
    checks = {'id': expected['id'], 'name': expected['name'],
              'size_in_bytes': expected['bytes'], 'digest': 'sha256:' + expected['sha256'],
              'expired': False}
    if any(value.get(key) != wanted for key, wanted in checks.items()):
        raise RuntimeError('Original artifact identity/digest mismatch')
    run = value.get('workflow_run', {})
    if run.get('id') != pins['runId'] or run.get('head_sha') != pins['headSha']:
        raise RuntimeError('Original artifact run/head mismatch')
    return {**checks, 'workflow_run': {'id': run['id'], 'head_sha': run['head_sha']}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicEvidenceAPI:
    def __init__(self, token, repository):
        self.token = token
        self.base = 'https://api.github.com/repos/' + repository
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, suffix):
        return urllib.request.Request(self.base + suffix, headers={
            'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'issue1094-evidence-projection'})

    def metadata(self, suffix):
        with self.opener.open(self.request(suffix), timeout=30) as response:
            body = response.read(2 * MIB + 1)
        if len(body) > 2 * MIB:
            raise RuntimeError('API metadata size bound exceeded')
        return json.loads(body)

    def archive_location(self, artifact_id):
        try:
            with self.opener.open(self.request('/actions/artifacts/' + str(artifact_id) + '/zip'), timeout=30):
                raise RuntimeError('Expected GitHub artifact redirect')
        except urllib.error.HTTPError as error:
            try:
                if error.code != 302:
                    raise RuntimeError('GitHub artifact redirect refused') from None
                location = error.headers.get('Location', '')
            finally:
                error.close()
        parsed = urllib.parse.urlsplit(location)
        if (parsed.scheme != 'https' or not parsed.hostname
                or not parsed.hostname.endswith('.blob.core.windows.net')
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise RuntimeError('Unexpected GitHub artifact storage origin')
        return location

    def download(self, expected, destination, bounds):
        # Authorization is attached ONLY to the initial api.github.com request.
        # The signed storage URL is never written to logs, errors, or receipts.
        location = self.archive_location(expected['id'])
        digest = hashlib.sha256()
        count = 0
        deadline = time.monotonic() + 300
        with self.opener.open(urllib.request.Request(location), timeout=30) as response:
            with destination.open('xb') as output:
                while True:
                    bounds.check()
                    if time.monotonic() > deadline:
                        raise RuntimeError('Archive download deadline exceeded')
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > min(expected['bytes'], MAX_ARCHIVE):
                        raise RuntimeError('Archive download size bound exceeded')
                    output.write(chunk)
                    digest.update(chunk)
        actual = digest.hexdigest()
        if count != expected['bytes'] or actual != expected['sha256']:
            raise RuntimeError('Original archive size/SHA-256 verification failed')
        return {'bytes': count, 'sha256': actual, 'originalArchiveVerified': True}


def inspect_members(archive):
    members = archive.infolist()
    if not members or len(members) > MAX_MEMBERS:
        raise RuntimeError('Archive member-count bound refused')
    seen = set()
    total = 0
    for member in members:
        name = member.filename
        # The original controller emits only flat evidence files. No extraction
        # API that interprets ZIP paths, permissions, links, or code is used.
        if (not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', name)
                or name != member.orig_filename or name in seen):
            raise RuntimeError('Unsafe/duplicate original member name')
        seen.add(name)
        mode = member.external_attr >> 16
        if (member.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                or member.flag_bits & 1
                or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            raise RuntimeError('Unsupported original member type/encryption/compression')
        binary = bool(BINARY.fullmatch(name))
        if not binary and not name.endswith(PUBLIC_SUFFIXES):
            raise RuntimeError('Unrecognized original evidence member')
        if member.file_size > (MAX_MEMBER if binary else MAX_TEXT_MEMBER):
            raise RuntimeError('Original member expansion bound refused')
        total += member.file_size
        if total > MAX_EXPANDED:
            raise RuntimeError('Original archive expansion bound refused')
    return members


def project_zip(archive_path, output, expected, bounds):
    if archive_path.stat().st_size != expected['bytes'] or sha256(archive_path) != expected['sha256']:
        raise RuntimeError('Archive changed before projection')
    output.mkdir(exist_ok=False)
    manifest = []
    with zipfile.ZipFile(archive_path) as archive:
        members = inspect_members(archive)
        for member in members:
            bounds.check()
            binary = bool(BINARY.fullmatch(member.filename))
            digest = hashlib.sha256()
            count = 0
            magic = b''
            destination = None if binary else output / member.filename
            writer = None
            try:
                if destination:
                    writer = destination.open('xb')
                    os.chmod(destination, 0o600)
                with archive.open(member, 'r') as reader:
                    while True:
                        bounds.check()
                        chunk = reader.read(CHUNK)
                        if not chunk:
                            break
                        if not magic:
                            magic = chunk[:4]
                        count += len(chunk)
                        if count > member.file_size:
                            raise RuntimeError('Member exceeds declared size')
                        digest.update(chunk)
                        if writer:
                            bounds.text_bytes += len(chunk)
                            if bounds.text_bytes > MAX_TEXT_TOTAL:
                                raise RuntimeError('Projection text-total bound refused')
                            writer.write(chunk)
                if count != member.file_size or (binary and magic != b'\x7fELF'):
                    raise RuntimeError('Member bytes/type mismatch')
            finally:
                if writer:
                    writer.close()
            member_hash = digest.hexdigest()
            if destination and sha256(destination) != member_hash:
                raise RuntimeError('Copied original member changed')
            manifest.append({'name': member.filename, 'bytes': count,
                             'sha256': member_hash, 'zipCrc32': f'{member.CRC:08x}',
                             'projectedOriginalBytes': not binary,
                             'omissionReason': 'ELF test-binary bytes omitted; original archive retained by GitHub' if binary else None})
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    method = Path(__file__).resolve().parent
    pins = json.loads((method / 'projection-pins.json').read_text())
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_REPOSITORY') != pins['repository']):
        raise RuntimeError('Projection requires the exact own-fork fresh hosted runner')
    work, output = args.work.resolve(), args.output.resolve()
    if work == output or work in output.parents or output in work.parents:
        raise RuntimeError('Projection work/output must be separate fresh directories')
    work.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    terminal = {'startedAt': now(), 'outcome': 'INCOMPLETE', 'productExecuted': False,
                'behaviorQualified': False, 'snapshotsAccepted': False,
                'originalRun': pins['runId'], 'originalHead': pins['headSha'],
                'projectionWorkflowSha': os.environ.get('GITHUB_SHA'),
                'projectionRunId': os.environ.get('GITHUB_RUN_ID'),
                'methodHashes': {p.name: sha256(p) for p in method.iterdir() if p.is_file()},
                'artifacts': [], 'workCleanup': 'retained until hosted runner teardown'}
    stage = 'admission'
    try:
        bounds = Bounds(work)
        token = os.environ.pop('GITHUB_TOKEN', None)
        if not token:
            raise RuntimeError('Read-only GitHub workflow token is absent')
        api = PublicEvidenceAPI(token, pins['repository'])
        stage = 'verify-original-run'
        run = verify_run(api.metadata('/actions/runs/' + str(pins['runId'])), pins)
        write_json(output / 'verified-original-run.json', run)
        for expected in pins['artifacts']:
            lane = expected['lane']
            stage = lane + ':verify-original-artifact'
            metadata = verify_artifact(api.metadata('/actions/artifacts/' + str(expected['id'])), expected, pins)
            write_json(output / (lane + '-verified-original-artifact.json'), metadata)
            stage = lane + ':download-original-archive'
            path = work / (lane + '.zip')
            record = {'lane': lane, 'artifactId': expected['id'], 'originalName': expected['name']}
            terminal['artifacts'].append(record)
            record.update(api.download(expected, path, bounds))
            stage = lane + ':project-original-members'
            record['members'] = project_zip(path, output / lane, expected, bounds)
            write_json(output / (lane + '-original-member-manifest.json'), record)
        stage = 'projection-complete'
        terminal['outcome'] = 'VERIFIED_ORIGINAL_EVIDENCE_PROJECTION'
        # Only owned downloaded copies are removed after both full archive and
        # all member hashes are retained. GitHub originals are never changed.
        shutil.rmtree(work)
        terminal['workCleanup'] = 'owned archive copies absent' if not work.exists() else 'unknown'
        if work.exists():
            raise RuntimeError('Owned archive cleanup was not proven')
    except BaseException as error:
        terminal['outcome'] = 'PROJECTION_FAILED_OR_INCOMPLETE'
        # Deliberately exclude exception text: HTTP errors can contain signed URLs.
        terminal['failure'] = {'stage': stage, 'type': type(error).__name__,
                               'httpStatus': error.code if isinstance(error, urllib.error.HTTPError) else None}
        raise RuntimeError('Projection failed at ' + stage + ' (' + type(error).__name__ + ')') from None
    finally:
        terminal['endedAt'] = now()
        write_json(output / 'projection-terminal.json', terminal)


if __name__ == '__main__':
    main()
