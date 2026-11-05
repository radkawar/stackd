# Tagged CLI releases

## Install a published release

Download packages from [GitHub Releases](https://github.com/radkawar/stackd/releases).
The current release is `v0.1.1`. Run stackd only on trusted networks.

Packages support Linux and macOS (Darwin), on amd64 and arm64. Choose the
platform of the host running stackd, not a future Lambda container:

```sh
set -eu
VERSION=v0.1.1
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) platform=linux_amd64 ;;
  Linux/aarch64|Linux/arm64) platform=linux_arm64 ;;
  Darwin/x86_64) platform=darwin_amd64 ;;
  Darwin/arm64) platform=darwin_arm64 ;;
  *) echo "Unsupported controller platform" >&2; exit 1 ;;
esac
archive="stackd_${VERSION}_${platform}.tar.gz"
base="https://github.com/radkawar/stackd/releases/download/$VERSION"
curl --fail --location --remote-name "$base/$archive"
curl --fail --location --remote-name "$base/SHA256SUMS"
# shasum is available on macOS and typical Linux installations.
grep -F "  $archive" SHA256SUMS | shasum -a 256 --check -
tar -xzf "$archive"
export PATH="$PWD/stackd_${VERSION}_${platform}:$PATH"
mkdir -p data
stackd -listen 127.0.0.1:4566 -database "$PWD/data/stackd.sqlite"
```

Require the checksum command to report `OK` before extraction. Checksums detect
corruption; they are not detached signatures.

From another terminal, use explicit local credentials and endpoint:

```sh
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true \
  aws --region us-east-1 --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
```

The basic API needs no Docker. For application setup, see the
[Terraform, CloudFormation and Docker reload examples](../examples/README.md).

## Package contents

Each archive contains a directory named `stackd_<version>_<os>_<arch>`:

```text
stackd
lambda-telemetry-amd64
lambda-telemetry-arm64
LICENSE
THIRD_PARTY_NOTICES.txt
RELEASE.json
```

Keep all three executables together. Both telemetry helpers are static Linux
executables, including in macOS archives, because Lambda containers run Linux.
stackd looks for them alongside its own executable by default. If you install
them elsewhere, set `-lambda-telemetry-directory` when enabling Lambda execution.

`RELEASE.json` records the version, source commit, controller platform, Go
toolchain, module versions and whether the source was modified. It replaces Go
build VCS metadata, which packaging disables. `THIRD_PARTY_NOTICES.txt` contains
the compiled dependencies' license and notice texts, Go toolchain attribution
and retained AWS SDK notices for generated declarations. Missing attribution
fails packaging. `SHA256SUMS` lists checksums for all four archives.

Packages do not include Docker, container images, QEMU/guest images, k3d, Trivy,
or optional ALB/ORC helpers. Prepare optional backends using
[runtime-containers.md](runtime-containers.md) and [runtime-vms.md](runtime-vms.md).
QEMU guest and native disk execution require a Linux controller. Neither
packaging nor the package smoke test pulls runtime images or contacts AWS.

## Build and exercise locally

Prerequisites:

- Go **1.26.5 or newer**, stable release; the hosted workflow pins **1.26.5**.
- Python **3.11 or newer**, including `hashlib.file_digest` and safe tar extraction.
- Git, a source checkout and writable Go module/build caches.
- AWS CLI v2 for the package smoke test; hosted jobs install **2.36.28**.

The first build may download Go modules. The basic API smoke test needs no
Docker, AWS account, cloud credentials or additional Python packages.

From the repository root, choose a **new or empty** output directory:

```sh
python3 -B -P -m unittest discover -s scripts -p release_test.py
python3 -B -P scripts/release.py build v0.0.0-local --output bin/releases-local
```

This builds all four controller targets and both Linux helpers. Packaging uses
`CGO_ENABLED=0`, `GOWORK=off`, `-mod=readonly`, `-trimpath` and `-buildvcs=false`.
It validates helper architecture and static linking, and normalizes archive
metadata to the source commit's timestamp. Reproducible builds require the same
source, dependency contents and Go toolchain. Modified local source is recorded
in the manifest.

Smoke-test the archive matching the **current host** (choose exactly one):

```sh
# Linux x86-64:
python3 -B -P scripts/release.py smoke bin/releases-local/stackd_v0.0.0-local_linux_amd64.tar.gz
# Linux ARM64:
python3 -B -P scripts/release.py smoke bin/releases-local/stackd_v0.0.0-local_linux_arm64.tar.gz
# macOS Intel:
python3 -B -P scripts/release.py smoke bin/releases-local/stackd_v0.0.0-local_darwin_amd64.tar.gz
# macOS Apple Silicon:
python3 -B -P scripts/release.py smoke bin/releases-local/stackd_v0.0.0-local_darwin_arm64.tar.gz
```

For a faster single-platform build, append `--platform linux/amd64` (or another
listed platform) to `build`. Both telemetry helpers are still included; other
controller platforms are not built or tested.

The smoke test checks the archive checksum and helpers, then runs the packaged
CLI on loopback with an isolated SQLite database and local credentials. It
checks STS identity, an S3 byte round-trip, persistence after restart, deletion
and clean shutdown. It removes temporary files and does not use inherited AWS
credentials or proxy settings. Optional execution engines are not covered.

To validate an existing clean tagged checkout without publishing:

```sh
python3 -B -P scripts/release.py build v1.2.3 --require-tag --output bin/releases-v1.2.3
python3 -B -P scripts/release.py verify v1.2.3 "$(git rev-parse HEAD)" bin/releases-v1.2.3
```

`verify` requires all four archives, their executable and notice files, and
manifests from the same clean tagged commit. It generates `SHA256SUMS`. To check
all downloaded archives, use `sha256sum --check SHA256SUMS` on Linux or
`shasum --algorithm 256 --check SHA256SUMS` on macOS.

## GitHub publishing

Release tags are immutable. Use the local build commands above to test packaging
before tagging a version.

1. Complete the local build and matching-host smoke test above, then run the
   maintainer checks below.
2. Push the approved release tag. Only pushed tags matching `v*` trigger the
   [release workflow](../.github/workflows/release.yml). The tag must be a
   `v`-prefixed SemVer version without leading zeros in numeric version or
   prerelease identifiers, such as `v1.2.3`, `v1.2.3-rc.1` or `v1.2.3+build.4`.
3. Check the workflow result and published assets. Prerelease tags produce
   GitHub prereleases and do not replace the latest stable release.

The workflow runs the shared CI checks before packaging. Native runners build
and smoke-test each platform from the same tagged commit. Publication verifies
all four artifacts from that workflow run, generates checksums, uploads a draft
and then publishes it. A failed check, package job or artifact verification
prevents publication. Interrupted uploads can leave a draft; inspect and remove
it before retrying. The workflow does not overwrite an existing release or
create or move tags.

Action dependencies are pinned to full commit SHAs, and checkout does not
persist credentials. Permissions are read-only except for `contents: write` in
the publication job, which uses GitHub's short-lived job token rather than a
stored repository secret. Attempts for the same tag are serialized without
canceling an active release. Protect release tags with repository rulesets so
only authorized maintainers can create them. Branch and pull-request checks
cannot publish releases.

The published [`v0.1.1`](https://github.com/radkawar/stackd/releases/tag/v0.1.1)
was built from `956a81162d8722c2497b08f8b3253d451a918dcb` by the
[tagged workflow](https://github.com/radkawar/stackd/actions/runs/41822332991).
Newer branch features, including analytics changes, are not part of that tag.

## Maintainer checks

See [the shared CI workflow](../.github/workflows/checks.yml) for the current
checks and pinned tools, and [the release script](../scripts/release.py) for
packaging and smoke-test details. The release workflow runs the checks defined
at the tagged commit.

Run these maintainer checks after integrating changes:

```sh
actionlint .github/workflows/checks.yml .github/workflows/release.yml
python3 -B -P -m unittest discover -s scripts -p release_test.py
make generate-iam-check generate-oidc-check generate-simulation-check \
  generate-lambda-runtime-check generate-sql-check generate-mq-schema-check \
  generate-cloudformation-check generate-guardduty-findings-check \
  generate-terraform-apis-check
# The GuardDuty/provider targets require the recorded clones, as prepared by CI.
```

`actionlint` must be installed separately. Some generation checks require
ignored upstream source checkouts; consult the workflow for their preparation.
The local commands exercise only the host platform. The release workflow must
also pass its native package smoke tests on the other three platforms.
