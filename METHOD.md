# Issue943: supply the missing Bubblewrap executable (v2)

This package is prepared for independent review and one fresh GitHub-hosted Ubuntu 24.04 runner. Admission is false until the publication owner approves the exact frozen files. No hosted result or product qualification is claimed.

The completed metadata-only diagnostic [39435768845](https://github.com/citadelculture/CorbanuTerminal/actions/runs/39435768845), control commit `550cbfe766278612ed66f34eaf07111ee656cd2d`, established that `/usr/bin/bwrap` was absent on that runner. Its 26 source inputs and both original product files matched. This does not establish the filename missing in earlier run 39423100324.

## Narrow change

The original paired Issue943 campaign retains its exact public source `bfa6f7da57b55803be09ccd3613cdcdedd1c7e25`, two-file fixture, baseline assertion, 14 orchestrator and 6 integration cases per variant, ordinary `just test`, source/tool pins, cleanup, captures and bounds. The workflow changes only its name and branch route.

After the original source and inherited-control gates, a hash-admitted helper supplies the absent executable:

1. Require Ubuntu 24.04 Noble, an absent `/usr/bin/bwrap`, and root-owned, non-writable system verification tools and Ubuntu archive keyring.
2. Download the official `noble-security/InRelease` over HTTPS, once. Verify its signature with `/usr/bin/gpgv` and only `/usr/share/keyrings/ubuntu-archive-keyring.gpg`; no configuration or default keyring is used. Record actual keyring hash, signature fingerprints, signed metadata hash and date. Require exact Ubuntu/Noble/security identity, a date within the previous seven days (at most one day ahead), and any declared validity deadline.
3. Download only `main/binary-amd64/Packages.xz` and verify its size and SHA256 against the verified Release. Extract the unique `bubblewrap` package record. Require every frozen package/version/architecture/path/size/SHA256 binding. Source changes or metadata races hold; there is no automatic retry.
4. Download only the bound `bubblewrap_0.9.0-1ubuntu0.3_amd64.deb`, 50,436 bytes, SHA256 `2461f1beee9cb04c8942739fe1a2b37e7b7c2a3d518f0779dc75f9245baa3094`. `dpkg-deb --extract` unpacks its data into the private task directory without running maintainer scripts. The reviewed archive contains 30 entries and 106,214 regular-file bytes; the exact extracted inventory is checked. Expected directory paths lose their single trailing slash before comparison; canonical duplicates are rejected, and regular-file paths, types and sizes remain exact.
5. Verify the extracted ELF: 72,160 bytes, SHA256 `e318903862396f96de3df57264e0158682b952fd3fb53ac23d876413e7b30f71`. Check absence again, then invoke the hash-admitted exclusive creation helper as the sole privileged command:

   `sudo -n -- /usr/bin/python3 -I -B <CONTROL>/install_elf_exclusive.py --dispatch --source <TASK_ROOT>/bubblewrap-setup/extracted/usr/bin/bwrap`

   The helper requires root Linux, a fixed task-owned source path, and the exact ELF hash and size before creating any target. Its only destination is `/usr/bin/bwrap`. `O_CREAT|O_EXCL|O_NOFOLLOW` makes target absence an atomic condition: even a file or symlink appearing after the last preflight check causes failure without replacement or metadata changes. The new file starts at mode 0600, is fully written and synchronized, then becomes root:root 0755. An interrupted partial creation is retained non-executable; the helper never removes or overwrites a target.

6. Verify installed bytes, root:root ownership, regular-file identity and exact 0755 mode. Resume the original root-owned ELF check, `bwrap --version`, and unchanged `--unshare-user --unshare-net --ro-bind / / -- /bin/true` gate. The original util-linux/libcap checks also precede any product source change, tool acquisition, build or test.

Only the executable is installed. No APT/dpkg installation, dependency installation, package registration, upgrades, maintainer scripts, AppArmor files, sysctl configuration or enforcement changes occur. The package's `postinst` runs `sysctl --system` for `kernel.unprivileged_userns_clone`; that script is deliberately never invoked. Its bundled sysctl data remains inert inside the private extraction tree.

Namespace rejection is a setup hold. It must be preserved, never bypassed or followed by a product build. Other missing prerequisites remain unknown until the unchanged gates observe them.

## Bounds and retained evidence

Each HTTPS fetch has zero retries, a 20-second connect timeout, a 120-second total timeout and an exact or maximum byte cap. InRelease and verified Release are capped at 1 MiB; compressed index at 8 MiB; expanded index at 64 MiB with 128 MiB decoder memory cap. GPG verification/extraction are each limited to 30 seconds; installation to 15 seconds. The original 6,900-second campaign deadline, 120-minute job deadline, 16 MiB command stream bounds, owned-child cleanup and disk floors remain unchanged.

The setup adds complete normalized command records and `bubblewrap-setup.json`, plus the fetched InRelease, verified Release and selected package paragraph under `bubblewrap-provenance/`. These record actual package, index, ELF, system-tool and trust-anchor digests. The full compressed index and package remain in the disposable task directory; no home files, environments, private receipts or complete system inventories are exported.

HOME, CODEX_HOME and inherited sandbox markers retain their original handling. The unresolved local native incident and prior host-override denial remain binding.

## Exact runtime mapping

The publication owner copies only the entries of `publication-manifest-v2.json`. The workflow source `issue943-held-note.yml` maps to `.github/workflows/issue943-held-note.yml`; other public files retain their relative names. The control checkout contains `controller.py`, `bubblewrap_setup.py`, `install_elf_exclusive.py`, `bubblewrap-pins.json`, `source-manifest.json`, `tools-pins.json`, `admission.json`, this method and `payload/`. The independent source checkout uses the pinned public base.

The workflow invokes:

```sh
python3 -I -B control/controller.py --dispatch \
  --source "$GITHUB_WORKSPACE/source" \
  --control "$GITHUB_WORKSPACE/control" \
  --output "$GITHUB_WORKSPACE/public-evidence" \
  --binaries "$GITHUB_WORKSPACE/qualification-binaries"
```

The controller accepts only a first-attempt push on `citadelculture/CorbanuTerminal` branch `codex/issue943-bubblewrap-recovery-v2-20261020`, with exact approved controller/helper/exclusive-installer/pins/source/tools/workflow hashes, nonroot Linux x86_64 and GitHub-hosted runner identity. Local execution is not authorized by this document.

Primary package provenance: [Ubuntu package checksum page](https://packages.ubuntu.com/noble-updates/amd64/bubblewrap/download), [official archive](https://security.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.3_amd64.deb), [signed archive metadata](https://security.ubuntu.com/ubuntu/dists/noble-security/InRelease), and [GnuPG verification documentation](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html). Local preparation checked the package/index bytes and parsed metadata but did not perform signature verification, installation or native execution. Fresh hosted signature verification is mandatory.

V2 addresses only the independent review findings about directory trailing slashes and the final copy race. Frozen v1 and its HOLD receipt remain preserved. All 74 pure tests pass: 29 setup tests (20 existing controls and 9 new regressions) plus all 45 original-controller tests. These include actual-pin-shaped inventory and intervening file/symlink controls. No local privileged helper main, package, namespace or product execution occurred.
