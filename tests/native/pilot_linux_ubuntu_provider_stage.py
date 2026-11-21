"""Pre-CI archive provenance rehearsal; never run a downloaded executable."""
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time

PINS = (
    ("gnome-keyring", "46.1-2ubuntu0.2", "gnome-keyring"),
    ("libgck-1-0", "3.41.2-1build3", "gcr"),
    ("libgcr-base-3-1", "3.41.2-1build3", "gcr"),
)

PROMPT_ARCHIVES = {
    "gcr": "5c239a7ec1a732c649ab4c043cd55a5c7a2c673df4e486a8317e42a25cc9f928",
    "libgcr-ui-3-1": "e48fd6e74dddbb1a522abd4b9f2a40b10bc73c93c7279809817dd71377a6d090",
}
PROMPT_MEMBERS = {
    "gcr": ("./usr/libexec/gcr-prompter", "gcr-prompter",
            ("libgcr-ui-3.so.1", "libgcr-base-3.so.1", "libglib-2.0.so.0", "libgobject-2.0.so.0",
             "libgio-2.0.so.0", "libgtk-3.so.0", "libc.so.6")),
    "libgcr-ui-3-1": ("./usr/lib/x86_64-linux-gnu/libgcr-ui-3.so.1.0.0", "libgcr-ui-3.so.1",
                     ("libgck-1.so.0", "libgcr-base-3.so.1", "libglib-2.0.so.0", "libgobject-2.0.so.0",
                      "libgio-2.0.so.0", "libgtk-3.so.0", "libgdk-3.so.0", "libpango-1.0.so.0",
                      "libcairo.so.2", "libgdk_pixbuf-2.0.so.0", "libc.so.6")),
}

PEER_ARCHIVES = {
    "gnome-keyring": "86629a081c91dd8004655f5f48d8a5bfb75dde8c4e69ef7401b15568c2eacafb",
    "libgck-1-0": "bceace92f5cbbf55ab2c963a426f73335c887f0c1c45c7b0b7d7610b36d9afde",
    "libgcr-base-3-1": "b702e0ef02517caf5a3e35b9b663dfc22935315dc2e7dc507e78435963ff2e24",
}
LIBRARIES = {
    "libgck-1-0": ("libgck-1.so.0.0.0", "libgck-1.so.0"),
    "libgcr-base-3-1": ("libgcr-base-3.so.1.0.0", "libgcr-base-3.so.1"),
}
EXPECTED_PROVIDER_NEEDED = [
    "libgcr-base-3.so.1", "libgck-1.so.0", "libgio-2.0.so.0", "libgobject-2.0.so.0",
    "libglib-2.0.so.0", "libgcrypt.so.20", "libsystemd.so.0", "libc.so.6",
]


def extract_member(cmd, archive_path, member_path, candidate):
    # Read exact regular member into a fresh private path. Do not materialize archive
    # symlinks/scripts/hooks/config files, and do not preserve archive modes/ownership.
    archive = cmd("dpkg-deb", "--fsys-tarfile", str(archive_path))
    need(len(archive) <= 16 * 1024 * 1024)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as payload:
        matches = [entry for entry in payload if entry.name == member_path]
        need(len(matches) == 1 and matches[0].isfile() and 0 < matches[0].size <= 4 * 1024 * 1024)
        file = payload.extractfile(matches[0])
        need(file is not None)
        data = file.read()
        need(len(data) == matches[0].size and data.startswith(b"\x7fELF"))
        with candidate.open("xb") as dest:
            dest.write(data)
    candidate.chmod(0o400)
    return candidate.lstat()


phase = "runner"

def need(value):
    if not value:
        raise ValueError("stage denied")


# Canonical's published Noble archive trust anchor. The keyserver is the
# transport, not the source of authority for its identity:
# https://documentation.ubuntu.com/security/software-integrity/image-verification/
ARCHIVE_KEY = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
ARCHIVE_KEY_URL = "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x" + ARCHIVE_KEY


def archive_key(work, cmd):
    global phase
    phase = "archive-key-fetch"
    armored = work / "archive-key.asc"
    cmd("curl", "--disable", "--fail", "--silent", "--show-error", "--proto", "=https",
        "--max-time", "20", "--max-filesize", "65536", "--output", str(armored), ARCHIVE_KEY_URL)
    phase = "archive-key-armor"
    need(0 < armored.stat().st_size <= 65536)
    lines = armored.read_text(encoding="ascii").strip().splitlines()
    need(len(lines) >= 4 and lines[0] == "-----BEGIN PGP PUBLIC KEY BLOCK-----" and
         lines[-1] == "-----END PGP PUBLIC KEY BLOCK-----" and
         all(not line.startswith("-----") for line in lines[1:-1]))

    home = work / "gnupg"
    home.mkdir(mode=0o700)
    gpg = ("--no-options", "--homedir", str(home), "--batch", "--no-tty",
           "--no-auto-key-retrieve", "--no-auto-key-import")
    phase = "archive-key-inspect"
    data = cmd("gpg", *gpg, "--with-colons", "--with-fingerprint", "--show-keys", str(armored))
    records = [line.split(":") for line in data.decode("utf-8").splitlines()]
    public = [i for i, row in enumerate(records) if row[0] == "pub"]
    phase = "archive-key-primary"
    need(len(public) == 1 and not any(row[0] in ("sec", "ssb") for row in records))
    public = public[0]
    need(len(records[public]) > 6 and public + 1 < len(records))
    validity, expiry = records[public][1], records[public][6]
    need(validity not in ("r", "e", "d", "i") and (expiry == "" or int(expiry) > time.time()))
    phase = "archive-key-fingerprint"
    fingerprint = records[public + 1]
    need(len(fingerprint) > 9 and fingerprint[0] == "fpr" and fingerprint[9] == ARCHIVE_KEY)
    phase = "archive-key-stage"
    key = work / "ubuntu-archive-2018.gpg"
    cmd("gpg", *gpg, "--output", str(key), "--dearmor", str(armored))
    need(0 < key.stat().st_size <= 65536)
    key.chmod(0o400)
    return key


def run():
    global phase
    need(sys.platform == "linux" and os.uname().machine == "x86_64" and os.getuid() == os.geteuid() != 0)
    os_release = Path("/etc/os-release").read_text()
    need("ID=ubuntu" in os_release.splitlines() and "VERSION_CODENAME=noble" in os_release.splitlines())
    need(len(sys.argv) == 1 and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("AKC_UBUNTU_PROVIDER_STAGE") in ("archive-only-v1", "private-peer-v1", "encrypted-session-v1", "collection-offer-v1", "private-display-v1", "prompt-cancel-v1"))
    mode = os.environ["AKC_UBUNTU_PROVIDER_STAGE"]
    display_smoke = mode == "private-display-v1"
    prompt_cancel = mode == "prompt-cancel-v1"
    verify_peer = mode not in ("archive-only-v1", "private-display-v1")
    prompt_pins = tuple((name, "3.41.2-1build3", "gcr") for name in PROMPT_ARCHIVES)
    pins = prompt_pins if display_smoke else PINS + prompt_pins if prompt_cancel else PINS
    collection_offer = mode == "collection-offer-v1" or prompt_cancel
    encrypted = mode == "encrypted-session-v1" or collection_offer
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="akc-noble-stage-", dir="/tmp") as location:
        work = Path(location)
        library_dir = work / "private-libraries"
        library_dir.mkdir(mode=0o700)
        staged_libraries = {}
        candidate = work / "gnome-keyring-daemon"
        for dest in ("lists/partial", "archives/partial", "empty"):
            (work / dest).mkdir(parents=True)
        for dest in ("status", "local.conf"):
            (work / dest).touch()
        config = work / "apt.conf"
        config.write_text(f"""
Dir::Etc "{work}";
Dir::Etc::main "local.conf";
Dir::Etc::parts "empty";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "empty";
Dir::Etc::trusted "empty/trusted.gpg";
Dir::Etc::trustedparts "empty";
Dir::State "{work}";
Dir::State::status "{work}/status";
Dir::State::lists "{work}/lists";
Dir::Cache "{work}";
Dir::Cache::archives "{work}/archives";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
APT::Architecture "amd64";
Acquire::Languages "none";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::Check-Valid-Until "true";
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";
Acquire::Retries "0";
APT::Get::AllowUnauthenticated "false";
""")
        env = {"HOME": str(work), "PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": str(config)}

        def cmd(exe, *args, timeout=40):
            return subprocess.run(["/usr/bin/" + exe, *args], cwd=work, env=env, check=True,
                                  timeout=timeout, capture_output=True).stdout

        key = archive_key(work, cmd)
        phase = "archive-sources"
        (work / "sources.list").write_text("\n".join(
            f"deb [arch=amd64 signed-by={key},{ARCHIVE_KEY}] https://archive.ubuntu.com/ubuntu/ {suite} main"
            for suite in ("noble", "noble-updates")
        ) + "\n")

        phase = "signed-index"
        cmd("apt-get", "-o", "APT::Update::Error-Mode=any", "update", timeout=120)
        for name, version, source in pins:
            phase = "metadata-" + name
            target = f"{name}:amd64={version}"
            records = []
            for block in cmd("apt-cache", "show", target).decode("utf-8").split("\n\n"):
                fields = dict(line.split(": ", 1) for line in block.splitlines()
                              if line and not line[0].isspace() and ": " in line)
                if (fields.get("Package"), fields.get("Version"), fields.get("Architecture")) == (name, version, "amd64"):
                    records.append(fields)
            need(len(records) == 1)
            record = records[0]
            digest = record.get("SHA256", "")
            filename = f"{name}_{version}_amd64.deb"
            need(re.fullmatch(r"[a-f0-9]{64}", digest) and
                 record.get("Filename") == f"pool/main/{source[0]}/{source}/{filename}")
            if name in PROMPT_ARCHIVES:
                need(digest == PROMPT_ARCHIVES[name])
            elif verify_peer:
                need(digest == PEER_ARCHIVES[name])
            size = int(record["Size"])
            need(0 < size <= 4 * 1024 * 1024)
            # Fetch exact bytes using the fixed official archive URL from the validated index path.
            phase = "archive-" + name
            output = work / filename
            cmd("curl", "--disable", "--fail", "--silent", "--show-error", "--proto", "=https",
                "--max-time", "30", "--max-filesize", str(size), "--output", str(output),
                "https://archive.ubuntu.com/ubuntu/" + record["Filename"])
            need(output.stat().st_size == size and hashlib.sha256(output.read_bytes()).hexdigest() == digest)
            if name in PROMPT_ARCHIVES:
                phase = "prompt-asset-" + name
                member, leaf, dependencies = PROMPT_MEMBERS[name]
                path = (library_dir if name == "libgcr-ui-3-1" and prompt_cancel else work) / leaf
                asset = extract_member(cmd, output, member, path)
                dynamic = cmd("readelf", "--dynamic", str(path)).decode("ascii")
                need(tuple(re.findall(r"Shared library: \[([a-zA-Z0-9._+-]+)\]", dynamic)) == dependencies and
                     not re.search(r"\((?:RPATH|RUNPATH)\)", dynamic))
                if name == "libgcr-ui-3-1":
                    need(re.findall(r"Library soname: \[([a-zA-Z0-9._+-]+)\]", dynamic) == [leaf])
                    if prompt_cancel:
                        staged_libraries[path] = asset
                else:
                    prompter_image, prompter_stat = path, asset
            elif name == "gnome-keyring":
                phase = "member"
                provider = extract_member(cmd, output, "./usr/bin/gnome-keyring-daemon", candidate)
                phase = "elf"
                dynamic = cmd("readelf", "--dynamic", str(candidate)).decode("ascii")
                needed = re.findall(r"Shared library: \[([a-zA-Z0-9._+-]+)\]", dynamic)
                need(bool(needed))
                if verify_peer:
                    need(needed == EXPECTED_PROVIDER_NEEDED and not re.search(r"\((?:RPATH|RUNPATH)\)", dynamic))
                    phase = "provider-elf-interpreter"
                    headers = cmd("readelf", "--file-header", "--program-headers", str(candidate)).decode("ascii")
                    need(re.search(r"(?m)^\s*Class:\s*ELF64\s*$", headers) and
                         re.search(r"(?m)^\s*Type:\s*DYN\b", headers) and
                         re.search(r"(?m)^\s*Machine:\s*Advanced Micro Devices X86-64\s*$", headers) and
                         re.findall(r"Requesting program interpreter: ([^\]]+)\]", headers) ==
                         ["/lib64/ld-linux-x86-64.so.2"])
                for library in needed:
                    print("ubuntu_provider_needed_library " + library)
            elif verify_peer:
                phase = "member-" + name
                member, soname = LIBRARIES[name]
                path = library_dir / soname
                staged_libraries[path] = extract_member(cmd, output, "./usr/lib/x86_64-linux-gnu/" + member, path)
                dynamic = cmd("readelf", "--dynamic", str(path)).decode("ascii")
                need(re.findall(r"Library soname: \[([a-zA-Z0-9._+-]+)\]", dynamic) == [soname] and
                     not re.search(r"\((?:RPATH|RUNPATH)\)", dynamic))
            print("ubuntu_provider_archive_verified " + name + " " + version + " sha256=" + digest)
        if display_smoke:
            phase = "display-prerequisites"
            import runpy
            smoke = runpy.run_path(str(Path(__file__).with_name("pilot_linux_private_display.py")))["verify_private_display"]
            try:
                smoke()
            except Exception:
                phase = smoke.__globals__["phase"]
                raise ValueError("isolated display denied") from None
            print("linux_private_xvfb_peer_and_authentication_verified_gcr_asset_not_executed")
            return
        if not verify_peer:
            print("ubuntu_provider_stage_archive_only_not_executed")
            return

        phase = "private-peer-prerequisites"
        # Execute only in the separate, explicitly requested hosted peer lane.
        # Python -I excludes script siblings; load only this fixed reviewed file.
        import runpy
        lane = runpy.run_path(str(Path(__file__).with_name("pilot_linux_private_secret_bus.py")))
        need(len(staged_libraries) == (3 if prompt_cancel else 2))
        candidate.chmod(0o500)
        def verify_provider(prompt=None):
            global phase
            try:
                lane["verify_private_provider"](candidate, provider, library_dir, staged_libraries,
                                               encrypted=encrypted, collection_offer=collection_offer, prompt=prompt)
            except Exception:
                phase = "private-peer-" + lane["verify_private_provider"].__globals__["phase"]
                raise ValueError("private provider peer denied") from None
        if prompt_cancel:
            display = runpy.run_path(str(Path(__file__).with_name("pilot_linux_private_display.py")))
            phase = "prompt-display-prerequisites"
            prompter_image.chmod(0o500)
            try:
                with display["owned_private_display"](prompt=True) as (display_env, secret_display):
                    verify_provider((prompter_image, prompter_stat, display_env,
                                     lambda mark: display["screen_windows"](secret_display, mark)))
            except Exception:
                if not phase.startswith("private-peer-"):
                    phase = display["owned_private_display"].__wrapped__.__globals__["phase"]
                raise ValueError("private prompt denied") from None
            print("linux_private_gcr_prompt_visible_and_cancelled_not_storage")
            return
        verify_provider()
        if collection_offer:
            print("linux_private_secret_bus_collection_offer_verified_not_prompted_or_created")
            return
        print("linux_private_secret_bus_encrypted_negotiation_verified_not_storage" if encrypted else
              "linux_private_secret_bus_peer_identity_verified_not_storage")



if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("ubuntu_provider_archive_stage_denied phase=" + phase, file=sys.stderr)
        sys.exit(1)
