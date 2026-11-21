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

PINS = (
    ("gnome-keyring", "46.1-2ubuntu0.2", "gnome-keyring"),
    ("libgck-1-0", "3.41.2-1build3", "gcr"),
    ("libgcr-base-3-1", "3.41.2-1build3", "gcr"),
)


phase = "runner"

def need(value):
    if not value:
        raise ValueError("stage denied")


def run():
    global phase
    need(sys.platform == "linux" and os.uname().machine == "x86_64" and os.getuid() == os.geteuid() != 0)
    os_release = Path("/etc/os-release").read_text()
    need("ID=ubuntu" in os_release.splitlines() and "VERSION_CODENAME=noble" in os_release.splitlines())
    need(len(sys.argv) == 1 and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("AKC_UBUNTU_PROVIDER_STAGE") == "archive-only-v1")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="akc-noble-stage-", dir="/tmp") as location:
        work = Path(location)
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
        phase = "archive-key"
        key = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
        need(key.is_file() and key.stat().st_uid == 0 and not key.stat().st_mode & 0o022)
        (work / "sources.list").write_text("\n".join(
            f"deb [arch=amd64 signed-by={key}] https://archive.ubuntu.com/ubuntu/ {suite} main"
            for suite in ("noble", "noble-updates")
        ) + "\n")
        env = {"HOME": str(work), "PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_CONFIG": str(config)}

        def cmd(exe, *args, timeout=40):
            return subprocess.run(["/usr/bin/" + exe, *args], cwd=work, env=env, check=True,
                                  timeout=timeout, capture_output=True).stdout

        phase = "signed-index"
        cmd("apt-get", "-o", "APT::Update::Error-Mode=any", "update", timeout=120)
        for name, version, source in PINS:
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
            size = int(record["Size"])
            need(0 < size <= 4 * 1024 * 1024)
            # Fetch exact bytes using the fixed official archive URL from the validated index path.
            phase = "archive-" + name
            output = work / filename
            cmd("curl", "--disable", "--fail", "--silent", "--show-error", "--proto", "=https",
                "--max-time", "30", "--max-filesize", str(size), "--output", str(output),
                "https://archive.ubuntu.com/ubuntu/" + record["Filename"])
            need(output.stat().st_size == size and hashlib.sha256(output.read_bytes()).hexdigest() == digest)
            # Select one regular member from authenticated bytes; do not unpack arbitrary paths,
            # create links, preserve credentials/modes, install schemas/hooks, or execute it.
            if name == "gnome-keyring":
                phase = "member"
                candidate = work / "gnome-keyring-daemon"
                member_path = "./usr/bin/gnome-keyring-daemon"
                archive = cmd("dpkg-deb", "--fsys-tarfile", str(output))
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
                phase = "elf"
                dynamic = cmd("readelf", "--dynamic", str(candidate)).decode("ascii")
                needed = re.findall(r"Shared library: \[([a-zA-Z0-9._+-]+)\]", dynamic)
                need(bool(needed))
                for library in needed:
                    print("ubuntu_provider_needed_library " + library)
            print("ubuntu_provider_archive_verified " + name + " " + version + " sha256=" + digest)
        print("ubuntu_provider_stage_archive_only_not_executed")


if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("ubuntu_provider_archive_stage_denied phase=" + phase, file=sys.stderr)
        sys.exit(1)
