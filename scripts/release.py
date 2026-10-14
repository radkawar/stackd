#!/usr/bin/env python3
"""Build and exercise release archives without creating tags or GitHub releases."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64")
SEMVER = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")


def run(*command, env=None, capture=False):
    return subprocess.run(command, cwd=ROOT, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def version(value):
    match = SEMVER.fullmatch(value)
    if not match or any(part.isdigit() and len(part) > 1 and part[0] == "0"
                        for part in (match[4] or "").split(".")):
        raise ValueError("Version must be a v-prefixed SemVer tag (numeric prerelease identifiers cannot have leading zeros)")
    return bool(match[4])


def go_environment(target):
    goos, goarch = target.split("/")
    return dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0", GOFLAGS="-mod=readonly", GOWORK="off")


def json_objects(text):
    decoder = json.JSONDecoder()
    position = 0
    while position < len(text):
        if text[position].isspace():
            position += 1
            continue
        item, position = decoder.raw_decode(text, position)
        yield item


def modules_for(target, package):
    modules = {}
    for item in json_objects(run("go", "list", "-deps", "-json", package,
                                 env=go_environment(target), capture=True)):
        module = item.get("Module")
        if module and not module.get("Main"):
            modules[module["Path"]] = module
    return modules


def license_files(directory):
    names = {"license", "licence", "copying", "notice", "copyright", "patents", "attrib", "attribution"}
    return sorted(path for path in directory.iterdir() if path.is_file()
                  and path.name.lower().split(".")[0] in names)


def notices(modules):
    chunks = ["Third-party software compiled into stackd and its Linux Lambda telemetry helpers.\n"
              "Generated AWS declarations additionally retain the AWS SDK attribution below.\n"]
    goroot = Path(run("go", "env", "GOROOT", capture=True).strip())
    for path in license_files(goroot):
        chunks.append(f"\n=== Go toolchain: {path.name} ===\n{path.read_text()}\n")
    for name, module in sorted(modules.items()):
        effective = module.get("Replace", module)
        directory = Path(effective["Dir"])
        files = license_files(directory)
        # Some nested modules retain the notice at the enclosing module root.
        while not files and directory.parent != directory and directory != ROOT:
            directory = directory.parent
            files = license_files(directory)
        if not files:
            raise RuntimeError(f"No upstream license found for {name}; release packaging cannot omit attribution")
        label = f"{name} {module.get('Version', '')}"
        if "Replace" in module:
            label += f" (replacement {effective['Path']} {effective.get('Version', '')})"
        for path in files:
            chunks.append(f"\n=== {label}: {path.name} ===\n{path.read_text()}\n")
    for path in sorted((ROOT / "third_party" / "aws-sdk-go-v2").iterdir()):
        if path.is_file():
            chunks.append(f"\n=== Generated AWS declarations: {path.name} ===\n{path.read_text()}\n")
    return "".join(chunks)


def elf_helper(path, architecture):
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != {"amd64": 62, "arm64": 183}[architecture]:
            raise RuntimeError(f"{path.name} is not the required Linux/{architecture} ELF")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        for index in range(count):
            stream.seek(offset + index * size)
            if struct.unpack("<I", stream.read(4))[0] == 3:
                raise RuntimeError(f"{path.name} requires a dynamic loader; telemetry helpers must be static")


def checksums(directory):
    archives = sorted(directory.glob("stackd_*.tar.gz"))
    if not archives:
        raise RuntimeError("No release archives found")
    lines = []
    for path in archives:
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        lines.append(f"{digest}  {path.name}\n")
    (directory / "SHA256SUMS").write_text("".join(lines))


def build(args):
    version(args.version)
    goversion = run("go", "env", "GOVERSION", capture=True).strip()
    match = re.fullmatch(r"go(\d+)\.(\d+)\.(\d+)", goversion)
    if not match or tuple(map(int, match.groups())) < (1, 26, 5):
        raise RuntimeError("Release builds require Go 1.26.5 or newer (stable toolchain)")
    commit = run("git", "rev-parse", "HEAD", capture=True).strip()
    epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD", capture=True).strip())
    changed = bool(run("git", "diff", "--name-only", "HEAD", capture=True).strip()
                   or run("git", "ls-files", "--others", "--exclude-standard", capture=True).strip())
    if args.require_tag:
        tagged = run("git", "rev-parse", "--verify", f"refs/tags/{args.version}^{{commit}}", capture=True).strip()
        if tagged != commit or changed:
            raise RuntimeError("Tagged release requires a clean checkout of the exact tag commit")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("Use a new or empty release output directory; artifacts are never overwritten")
    targets = args.platform or list(PLATFORMS)
    with tempfile.TemporaryDirectory(prefix="stackd-release-") as temporary:
        work = Path(temporary)
        helpers = {}
        helper_modules = {}
        for architecture in ("amd64", "arm64"):
            target = "linux/" + architecture
            helper = work / ("lambda-telemetry-" + architecture)
            package = "./compute/lambda/cmd/telemetry-buffer"
            run("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", str(helper), package, env=go_environment(target))
            elf_helper(helper, architecture)
            helpers[architecture] = helper
            helper_modules.update(modules_for(target, package))
        for target in targets:
            name = "stackd_" + args.version + "_" + target.replace("/", "_")
            bundle = work / name
            bundle.mkdir()
            run("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", str(bundle / "stackd"), "./cmd/stackd", env=go_environment(target))
            for helper in helpers.values():
                shutil.copyfile(helper, bundle / helper.name)
            shutil.copyfile(ROOT / "LICENSE", bundle / "LICENSE")
            modules = dict(helper_modules)
            modules.update(modules_for(target, "./cmd/stackd"))
            (bundle / "THIRD_PARTY_NOTICES.txt").write_text(notices(modules))
            manifest = {"version": args.version, "commit": commit, "source_modified": changed,
                        "go": goversion, "platform": target,
                        "telemetry_helpers": ["linux/amd64", "linux/arm64"],
                        "modules": {name: module.get("Version", "") for name, module in sorted(modules.items())}}
            (bundle / "RELEASE.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            archive = output / (name + ".tar.gz")
            with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path in [bundle, *sorted(bundle.iterdir())]:
                    info = tar.gettarinfo(str(path), arcname=str(path.relative_to(work)))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    info.mode = 0o755 if path.is_dir() or path.name in ("stackd", "lambda-telemetry-amd64", "lambda-telemetry-arm64") else 0o644
                    if path.is_file():
                        with path.open("rb") as source:
                            tar.addfile(info, source)
                    else:
                        tar.addfile(info)
            print(archive)
    checksums(output)


def smoke(args):
    # Reuse the local executable probes' strict process/shutdown contract.
    sys.path.insert(0, str(ROOT / "scripts" / "aws"))
    from stackd_process import StackdProcess
    architecture = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    native = platform.system().lower() + "/" + str(architecture)
    archive = args.archive.resolve()
    sums = archive.parent / "SHA256SUMS"
    expected = dict(line.split("  ", 1)[::-1] for line in sums.read_text().splitlines())
    with archive.open("rb") as source:
        if expected.get(archive.name) != hashlib.file_digest(source, "sha256").hexdigest():
            raise RuntimeError("Archive checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="stackd-package-smoke-") as temporary:
        work = Path(temporary)
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            for member in members:
                parts = Path(member.name).parts
                if member.name.startswith("/") or ".." in parts or not (member.isfile() or member.isdir()):
                    raise RuntimeError("Unsafe release archive member")
            tar.extractall(work, filter="data")
        bundles = list(work.glob("stackd_*"))
        if len(bundles) != 1:
            raise RuntimeError("Release archive must contain exactly one bundle")
        bundle = bundles[0]
        manifest = json.loads((bundle / "RELEASE.json").read_text())
        if manifest["platform"] != native:
            raise RuntimeError(f"Smoke requires a native archive ({native}), not {manifest['platform']}")
        for architecture in ("amd64", "arm64"):
            elf_helper(bundle / ("lambda-telemetry-" + architecture), architecture)
        for name in ("LICENSE", "THIRD_PARTY_NOTICES.txt"):
            if not (bundle / name).read_text().strip():
                raise RuntimeError(f"Empty {name}")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        endpoint = f"http://127.0.0.1:{port}"
        account = "583194762048"
        environment = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1",
                           AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="", AWS_CONFIG_FILE=str(work / "empty-config"),
                           AWS_SHARED_CREDENTIALS_FILE=str(work / "empty-credentials"), AWS_CLI_AUTO_PROMPT="off")
        # Suppress inherited proxies so all smoke traffic stays on the loopback listener.
        for key in list(environment):
            if key.lower().endswith("_proxy"):
                del environment[key]
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        controller = StackdProcess(work)
        command = [str(bundle / "stackd"), "-listen", f"127.0.0.1:{port}", "-account-id", account,
                   "-database", str(work / "state.sqlite")]
        def aws(*arguments):
            result = run("aws", "--endpoint-url", endpoint, "--region", "us-east-1", "--no-cli-pager",
                         "--output", "json", *arguments, env=environment, capture=True)
            return json.loads(result) if result.strip() else None
        try:
            controller.start(command, endpoint, environment=environment)
            identity = aws("sts", "get-caller-identity")
            if identity["Account"] != account or identity["Arn"] != f"arn:aws:iam::{account}:root":
                raise RuntimeError(f"Unexpected STS identity: {identity}")
            bucket = "stackd-release-smoke"
            payload = b"packaged stackd actual S3 object round-trip\n"
            (work / "input").write_bytes(payload)
            aws("s3api", "create-bucket", "--bucket", bucket)
            aws("s3api", "put-object", "--bucket", bucket, "--key", "proof.txt", "--body", str(work / "input"))
            for restart in (False, True):
                if restart:
                    controller.stop()
                    controller.start(command, endpoint, environment=environment)
                destination = work / ("output-restarted" if restart else "output")
                aws("s3api", "get-object", "--bucket", bucket, "--key", "proof.txt", str(destination))
                if destination.read_bytes() != payload:
                    raise RuntimeError("Packaged S3 object bytes did not survive the round-trip/restart")
            aws("s3api", "delete-object", "--bucket", bucket, "--key", "proof.txt")
            aws("s3api", "delete-bucket", "--bucket", bucket)
        finally:
            failed = sys.exc_info()[0] is not None
            try:
                controller.stop(kill_on_timeout=True)
            except BaseException:
                failed = True
                raise
            finally:
                if failed:
                    for log in sorted(work.glob("controller-*.log")):
                        print(f"=== {log.name} ===\n{log.read_text(errors='replace')}", file=sys.stderr)
        print(json.dumps({"archive": archive.name, "commit": manifest["commit"], "platform": native,
                          "observations": ["native packaged CLI", "static amd64/arm64 Linux helpers", "STS account/root identity",
                                           "S3 byte round-trip", "SQLite restart persistence", "resource deletion", "clean shutdown"]}, indent=2))


def verify(args):
    version(args.version)
    expected = {f"stackd_{args.version}_{target.replace('/', '_')}.tar.gz": target for target in PLATFORMS}
    if {path.name for path in args.directory.glob("*.tar.gz")} != set(expected):
        raise RuntimeError("Release must contain exactly the four requested platform archives")
    for filename, target in expected.items():
        with tarfile.open(args.directory / filename) as tar:
            root = filename.removesuffix(".tar.gz")
            members = tar.getmembers()
            required = {"stackd", "lambda-telemetry-amd64", "lambda-telemetry-arm64",
                        "LICENSE", "THIRD_PARTY_NOTICES.txt", "RELEASE.json"}
            if {member.name for member in members} != {root, *(root + "/" + name for name in required)}:
                raise RuntimeError(f"Unexpected archive layout: {filename}")
            if any(not (member.isfile() or member.isdir()) for member in members):
                raise RuntimeError(f"Nonregular release archive member: {filename}")
            for name in required:
                member = tar.getmember(root + "/" + name)
                if not member.isfile() or member.size == 0:
                    raise RuntimeError(f"Missing or empty release member: {filename}/{name}")
                if name in ("stackd", "lambda-telemetry-amd64", "lambda-telemetry-arm64") and member.mode != 0o755:
                    raise RuntimeError(f"Nonexecutable release binary: {filename}/{name}")
            manifest = json.load(tar.extractfile(root + "/RELEASE.json"))
            if (manifest["version"], manifest["platform"], manifest["commit"], manifest["source_modified"]) != (args.version, target, args.commit, False):
                raise RuntimeError(f"Archive did not originate from the clean tagged commit: {filename}")
    checksums(args.directory)
    print(f"Verified four platform archives from {args.commit}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("build")
    package.add_argument("version")
    package.add_argument("--output", type=Path, default=ROOT / "bin" / "releases")
    package.add_argument("--platform", action="append", choices=PLATFORMS)
    package.add_argument("--require-tag", action="store_true")
    package.set_defaults(function=build)
    check = commands.add_parser("smoke")
    check.add_argument("archive", type=Path)
    check.set_defaults(function=smoke)
    sums = commands.add_parser("checksums")
    sums.add_argument("directory", type=Path)
    sums.set_defaults(function=lambda args: checksums(args.directory))
    verification = commands.add_parser("verify")
    verification.add_argument("version")
    verification.add_argument("commit")
    verification.add_argument("directory", type=Path)
    verification.set_defaults(function=verify)
    validate = commands.add_parser("validate-version")
    validate.add_argument("version")
    def validate_version(args):
        prerelease = version(args.version)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write(f"version={args.version}\nprerelease={str(prerelease).lower()}\n")
        print(json.dumps({"version": args.version, "prerelease": prerelease}))
    validate.set_defaults(function=validate_version)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
