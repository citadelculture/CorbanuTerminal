"""Inert until admitted controller calls prepare; only the verified ELF is installed."""
import datetime
import email.utils
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat

ORIGIN = "https://security.ubuntu.com/ubuntu/"
SUITE = "noble-security"
INDEX = "main/binary-amd64/Packages.xz"
KEYRING = "/usr/share/keyrings/issue943-authenticated-ubuntu-archive-v1.gpg"
TARGET = "/usr/bin/bwrap"
MAX_RELEASE = 1024 * 1024
MAX_INDEX = 8 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024


class SetupHold(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise SetupHold(reason)


def read_bounded(path, limit):
    p = Path(path)
    st = p.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_size <= limit, "setup_regular_file_bound")
    with p.open("rb") as f:
        data = f.read(limit + 1)
    require(len(data) == st.st_size and len(data) <= limit, "setup_file_changed_or_bound")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_fields(text):
    fields, current = {}, None
    for line in text.splitlines():
        if line.startswith((" ", "\t")):
            require(current is not None, "metadata_orphan_continuation")
            fields[current] += "\n" + line[1:]
        else:
            require(": " in line or line.endswith(":"), "metadata_field_syntax")
            key, value = line.split(":", 1)
            require(re.fullmatch(r"[A-Za-z0-9-]+", key) and key not in fields,
                    "metadata_duplicate_or_invalid_field")
            fields[key], current = value.lstrip(), key
    return fields


def release_index(data, now):
    require(len(data) <= MAX_RELEASE, "release_bound")
    fields = parse_fields(data.decode("utf-8", "strict"))
    require(all(fields.get(k) == v for k, v in
                {"Origin": "Ubuntu", "Label": "Ubuntu", "Suite": SUITE,
                 "Codename": "noble", "Version": "24.04"}.items()), "release_identity")
    date = email.utils.parsedate_to_datetime(fields["Date"])
    require(date.tzinfo is not None and -86400 <= (now - date).total_seconds() <= 7 * 86400,
            "release_not_current")
    if fields.get("Valid-Until"):
        until = email.utils.parsedate_to_datetime(fields["Valid-Until"])
        require(until.tzinfo is not None and now <= until, "release_expired")
    matches = []
    for line in fields["SHA256"].splitlines():
        if not line.strip():
            continue
        parts = line.split()
        require(len(parts) == 3, "release_hash_syntax")
        digest, size, path = parts
        if path == INDEX:
            require(re.fullmatch(r"[0-9a-f]{64}", digest) and size.isdecimal()
                    and 0 < int(size) <= MAX_INDEX, "release_index_bound")
            matches.append({"path": path, "sha256": digest, "bytes": int(size)})
    require(len(matches) == 1, "release_index_missing_or_duplicate")
    return fields["Date"], matches[0]


def expand_index(data, limit=MAX_EXPANDED):
    require(len(data) <= MAX_INDEX, "compressed_index_bound")
    decompressor = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
    out = decompressor.decompress(data, max_length=limit + 1)
    require(len(out) <= limit and decompressor.eof and not decompressor.unused_data,
            "index_expansion_bound_or_trailing_data")
    return out


def package_record(data, pins):
    require(len(data) <= MAX_EXPANDED, "package_index_bound")
    matches = []
    for paragraph in data.decode("utf-8", "strict").strip().split("\n\n"):
        fields = parse_fields(paragraph)
        if fields.get("Package") == pins["package"]:
            matches.append((fields, paragraph + "\n"))
    require(len(matches) == 1, "package_missing_or_duplicate")
    fields, paragraph = matches[0]
    expected = {"Package": pins["package"], "Version": pins["version"],
                "Architecture": pins["architecture"], "Filename": pins["filename"],
                "Size": str(pins["debBytes"]), "SHA256": pins["debSha256"]}
    require(all(fields.get(k) == v for k, v in expected.items()), "package_pin_mismatch")
    return fields, paragraph


def signature_fingerprints(text):
    require(not re.search(r"\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY)\b",
                          text), "signature_rejected")
    matches = re.findall(r"(?m)^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ", text)
    require(bool(matches), "signature_status_missing")
    return sorted(set(matches))


def fetch_argv(destination, url, maximum):
    require(url.startswith(ORIGIN), "non_official_download")
    return ["/usr/bin/curl", "-q", "--fail", "--silent", "--show-error",
            "--proto", "=https", "--retry", "0", "--connect-timeout", "20",
            "--max-time", "120", "--max-filesize", str(maximum),
            "--output", str(destination), url]


def provision_keyring_argv():
    helper = Path(__file__).resolve().with_name("provision_authenticated_keyring.py")
    asset = helper.with_name("ubuntu-archive-keyring.gpg")
    require(sha(read_bounded(helper, 16384)) == "89636c931e7abc35f0bb6fdf62c8ce832ebf2d91f18425d09c42e43869161551",
            "authenticated_keyring_helper_pin")
    require(sha(read_bounded(asset, 3607)) ==
            "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
            "authenticated_keyring_asset_pin")
    return ["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", "-B",
            str(helper), "--dispatch"]


def install_argv(executable):
    installer = Path(__file__).resolve().with_name("install_elf_exclusive.py")
    return ["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", "-B",
            str(installer), "--dispatch", "--source", str(executable)]


def verify_extracted(unpack, members):
    wanted = {}
    for row in members:
        # tar lists directory names with a trailing slash; pathlib does not.
        path = row["path"].removesuffix("/") if row["directory"] else row["path"]
        require(path not in wanted, "duplicate_canonical_inventory_path")
        wanted[path] = {**row, "path": path}
    require(wanted.pop("", None) == {"path": "", "directory": True, "bytes": 0},
            "extracted_root_inventory")
    seen = {}
    for path in unpack.rglob("*"):
        require(len(seen) < len(wanted), "extracted_member_bound")
        st = path.lstat()
        require(stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode), "extracted_special_file")
        row = {"path": str(path.relative_to(unpack)), "directory": stat.S_ISDIR(st.st_mode),
               "bytes": 0 if stat.S_ISDIR(st.st_mode) else st.st_size}
        seen[row["path"]] = row
    require(seen == wanted, "extracted_inventory_mismatch")
    return {"entriesIncludingRoot": len(seen)+1, "regularBytes": sum(r["bytes"] for r in seen.values())}


def root_owned_regular(path, limit, executable=False, *, observation=None):
    p = Path(path)
    if observation is not None:
        # Only the fixed public keyring call opts in. No file contents, resolved
        # path, exception text or environment are added to this observation.
        observation.update({"schema": "system-file-identity-observation-v1",
                            "path": str(p), "limitBytes": limit,
                            "executableRequired": bool(executable),
                            "statFollowsSymlinks": True, "state": "stat_pending"})
    try:
        st = p.stat()
    except OSError as exc:
        if observation is not None:
            observation.update({"state": "stat_error", "errno": exc.errno,
                                "exceptionType": type(exc).__name__})
        raise
    if observation is not None:
        predicates = {
            "rootOwned": st.st_uid == 0,
            "regularFile": stat.S_ISREG(st.st_mode),
            "notGroupOrOtherWritable": not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
            "withinSizeBound": st.st_size <= limit,
            "ownerExecutableWhenRequired": bool(not executable or st.st_mode & stat.S_IXUSR),
        }
        observation.update({"state": "identity_accepted" if all(predicates.values())
                            else "identity_rejected",
                            "metadata": {"uid": st.st_uid, "gid": st.st_gid,
                                         "mode": st.st_mode, "modeOctal": oct(st.st_mode),
                                         "fileType": stat.S_IFMT(st.st_mode), "bytes": st.st_size},
                            "predicates": predicates})
    require(st.st_uid == 0 and stat.S_ISREG(st.st_mode)
            and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            and st.st_size <= limit and (not executable or st.st_mode & stat.S_IXUSR),
            "setup_system_file_identity")
    return {"path": str(p), "resolvedPath": str(p.resolve(strict=True)),
            "sha256": sha(read_bounded(p.resolve(strict=True), limit)), "bytes": st.st_size}


def prepare(c, pins, result):
    """Called only after hosted admission, source pins and inherited-control guard."""
    evidence = {"status": "INCOMPLETE", "method": "documented-fingerprint-bootstrap-and-signed-archive-binary-only",
                "package": pins, "maintainerScriptsExecuted": False,
                "packageManagerInstallExecuted": False, "packageRegistered": False,
                "systemFilesWritten": [], "securityControlsModified": False,
                "namespaceCapabilityClaimed": False}
    result["bubblewrapSetup"] = evidence
    try:
        require(not os.path.lexists(TARGET), "bwrap_already_present_no_replacement")
        os_release = read_bounded(Path("/etc/os-release").resolve(strict=True), 16384).decode()
        require(all(re.search(r"(?m)^" + key + r'="?'+re.escape(value)+r'"?$', os_release)
                    for key, value in {"ID": "ubuntu", "VERSION_ID": "24.04",
                                       "VERSION_CODENAME": "noble"}.items()), "ubuntu_noble_required")
        work = c.root / "bubblewrap-setup"
        work.mkdir(mode=0o700)
        public = c.output / "bubblewrap-provenance"
        public.mkdir()
        # Independent documented-fingerprint bootstrap; the unsafe original
        # system keyring is neither read, modified nor admitted by this method.
        evidence["systemTools"] = [root_owned_regular(p, 32 * 1024 * 1024, True) for p in
                                  ("/usr/bin/curl", "/usr/bin/gpgv", "/usr/bin/dpkg-deb",
                                   "/usr/bin/sudo", "/usr/bin/python3")]
        require(not os.path.lexists(KEYRING), "authenticated_keyring_exists_no_replacement")
        evidence["keyringBootstrap"] = {
            "method": "ubuntu_documented_full_fingerprints_and_frozen_public_bytes",
            "originalSystemKeyringAccepted": False,
            "originalSystemKeyringModified": False,
            "exclusiveCreationAttempted": True, "exclusiveCreationCompleted": False,
            "path": KEYRING}
        c.run("bwrap-provision-authenticated-keyring", provision_keyring_argv(), 15)
        evidence["keyringBootstrap"]["exclusiveCreationCompleted"] = True
        evidence["systemFilesWritten"].append(KEYRING)
        evidence["keyringIdentityObservation"] = {}
        evidence["keyring"] = root_owned_regular(
            KEYRING, MAX_RELEASE, observation=evidence["keyringIdentityObservation"])
        require(evidence["keyring"]["sha256"] ==
                "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
                and evidence["keyring"]["bytes"] == 3607, "authenticated_keyring_installed_pin")
        inrelease, release = work / "InRelease", work / "Release.verified"
        c.run("bwrap-fetch-inrelease", fetch_argv(inrelease, ORIGIN+"dists/"+SUITE+"/InRelease",
                                                 MAX_RELEASE), 130)
        signed = read_bounded(inrelease, MAX_RELEASE)
        (public / "InRelease").write_bytes(signed)
        evidence["inRelease"] = {"url": ORIGIN+"dists/"+SUITE+"/InRelease",
                                "sha256": sha(signed), "bytes": len(signed)}
        raw, _ = c.run("bwrap-verify-inrelease",
                       ["/usr/bin/gpgv", "--keyring", KEYRING, "--status-fd", "1",
                        "--output", str(release), str(inrelease)], 30)
        evidence["validSignatureFingerprints"] = signature_fingerprints(
            read_bounded(raw / "stdout", MAX_RELEASE).decode("utf-8", "strict"))
        verified = read_bounded(release, MAX_RELEASE)
        date, index = release_index(verified, datetime.datetime.now(datetime.timezone.utc))
        (public / "Release.verified").write_bytes(verified)
        evidence["verifiedRelease"] = {"sha256": sha(verified), "bytes": len(verified), "date": date}
        archive = work / "Packages.xz"
        url = ORIGIN+"dists/"+SUITE+"/"+INDEX
        c.run("bwrap-fetch-package-index", fetch_argv(archive, url, index["bytes"]), 130)
        compressed = read_bounded(archive, index["bytes"])
        require(len(compressed) == index["bytes"] and sha(compressed) == index["sha256"],
                "signed_index_hash_mismatch")
        expanded = expand_index(compressed)
        fields, paragraph = package_record(expanded, pins)
        (public / "bubblewrap.Package").write_text(paragraph)
        evidence["packageIndex"] = {**index, "url": url, "expandedBytes": len(expanded),
                                    "expandedSha256": sha(expanded)}
        evidence["resolvedPackage"] = {k: fields[k] for k in
                                       ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")}
        deb = work / "bubblewrap.deb"
        c.run("bwrap-fetch-deb", fetch_argv(deb, ORIGIN+pins["filename"], pins["debBytes"]), 130)
        package = read_bounded(deb, pins["debBytes"])
        require(len(package) == pins["debBytes"] and sha(package) == pins["debSha256"],
                "deb_hash_mismatch")
        evidence["verifiedDeb"] = {"sha256": sha(package), "bytes": len(package),
                                   "url": ORIGIN+pins["filename"]}
        unpack = work / "extracted"
        # Exact hash-bound archive; dpkg-deb extracts data only, never runs scripts.
        c.run("bwrap-extract-deb", ["/usr/bin/dpkg-deb", "--extract", str(deb), str(unpack)], 30)
        evidence["extractedDataInventory"] = verify_extracted(unpack, pins["dataMembers"])
        executable = unpack / "usr/bin/bwrap"
        elf = read_bounded(executable, pins["elfBytes"])
        require(elf.startswith(b"\x7fELF") and len(elf) == pins["elfBytes"]
                and sha(elf) == pins["elfSha256"], "extracted_elf_mismatch")
        evidence["extractedElf"] = {"sha256": sha(elf), "bytes": len(elf)}
        require(not os.path.lexists(TARGET), "bwrap_appeared_no_replacement")
        # Hash-admitted helper creates target with O_EXCL, even if it appears now.
        # No package installation, hooks, policy or sysctl changes.
        evidence["binaryInstallAttempted"] = True
        evidence["binaryInstallCompleted"] = False
        c.run("bwrap-install-elf-only", install_argv(executable), 15)
        evidence["binaryInstallCompleted"] = True
        evidence["systemFilesWritten"].append(TARGET)
        installed = root_owned_regular(TARGET, pins["elfBytes"], True)
        st = Path(TARGET).lstat()
        require(installed["sha256"] == pins["elfSha256"] and installed["bytes"] == pins["elfBytes"]
                and stat.S_IMODE(st.st_mode) == 0o755 and st.st_gid == 0
                and not Path(TARGET).is_symlink(), "installed_elf_mismatch")
        evidence["installedElf"], evidence["status"] = installed, "VERIFIED_ELF_INSTALLED"
    except Exception as exc:
        evidence["failureCode"] = str(exc) if isinstance(exc, SetupHold) else "setup_"+type(exc).__name__
        raise
    finally:
        (c.output / "bubblewrap-setup.json").write_text(json.dumps(evidence, indent=2, sort_keys=True)+"\n")
