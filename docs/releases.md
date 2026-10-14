# Tagged CLI releases

The tag workflow in `.github/workflows/release.yml` builds CLI archives for:

- Linux amd64 and arm64;
- macOS (Darwin) amd64 and arm64.

Every archive contains one directory named `stackd_<version>_<os>_<arch>` with:

```text
stackd
lambda-telemetry-amd64
lambda-telemetry-arm64
LICENSE
THIRD_PARTY_NOTICES.txt
RELEASE.json
```

Both telemetry helpers are **static Linux executables**, including in macOS
archives: Lambda containers run Linux. They remain alongside `stackd`, matching
its default executable-directory helper lookup. Keep the three executables
together when installing, or explicitly configure `-lambda-telemetry-directory`
when enabling Lambda execution. `RELEASE.json` records the version, source
commit, controller platform, Go toolchain, module versions, and whether local
source was modified. Go build VCS metadata is disabled; that explicit manifest
is the provenance record.

`THIRD_PARTY_NOTICES.txt` includes upstream license/notice texts for the actual
compiled module dependencies, the Go toolchain, and the retained AWS SDK notices
for generated declarations. Missing upstream attribution fails packaging rather
than silently omitting it. The release also publishes `SHA256SUMS` for all four
archives. Checksums detect corruption; they are not a detached signature.

These packages do **not** include Docker, container images, QEMU/guest images,
k3d, Trivy, or optional ALB/ORC helpers. The packaging command and package smoke
neither pull runtime images nor contact AWS. Prepare optional execution backends
explicitly using [runtime-containers.md](runtime-containers.md) and
[runtime-vms.md](runtime-vms.md). A Darwin controller does not enable the
Linux-only QEMU guest/native disk execution boundary.

## Install a published release

The public assets are on [GitHub Releases](https://github.com/radkawar/stackd/releases).
The first release is `v0.1.0`: an experimental local sandbox, not complete AWS
parity or a production security boundary. Choose the archive for the controller
host, not the architecture of a future Lambda container.

```sh
set -eu
VERSION=v0.1.0
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

Require the checksum command to report `OK` before extraction. Keep all three
executables together; the two Linux helpers are intentionally included even on
macOS. From another terminal, use explicit local credentials and endpoint:

```sh
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_EC2_METADATA_DISABLED=true \
  aws --region us-east-1 --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
```

The basic API needs no Docker. Install optional runtime prerequisites separately;
see [executable Terraform/CloudFormation and Docker reload examples](../examples/README.md).

## Build and exercise locally

Prerequisites:

- Go **1.26.5 or newer**, stable release; the hosted workflow pins **1.26.5**;
- Python **3.11 or newer** (including `hashlib.file_digest` and safe tar extraction);
- Git, a source checkout, and a writable Go module/build cache;
- AWS CLI v2 for the actual packaged API smoke (hosted jobs install **2.36.28**).

Go dependencies may need downloading during the first build. This is build-time
module resolution, not a runtime image pull. The basic API smoke needs no Docker,
AWS account, cloud credentials, or separately installed Python packages.

From the repository root, choose a **new or empty** output directory:

```sh
python3 -B -P -m unittest discover -s scripts -p release_test.py
python3 -B -P scripts/release.py build v0.0.0-local --output bin/releases-local
```

This cross-compiles all four CLI targets and both Linux helpers. The packaging
entrypoint explicitly sets `CGO_ENABLED=0`, `GOWORK=off`, `-mod=readonly`,
`-trimpath`, and `-buildvcs=false`. It checks helper ELF architecture and absence
of a dynamic interpreter. Archive members have fixed modes, UID/GID, ordering,
and the source commit's timestamp; gzip headers have no filename or current
wall-clock time. Reproducibility still depends on identical source, dependency
contents, and Go toolchain; local modified source is honestly marked in the
manifest, not treated as a tagged release.

Smoke the archive matching the **current host** (choose exactly one):

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

For a faster native-only iteration, append `--platform linux/amd64` (or another
listed platform) to `build`. Both telemetry helpers are still included. This is
not equivalent to building or exercising all four releases.

The smoke verifies the archive checksum, extracts the actual archive, validates
both helpers, and launches the extracted CLI on an ephemeral loopback port with
an isolated SQLite database. It uses explicit local `test` fixture credentials,
a nonsequential account ID, blank AWS config/credential paths, and no inherited
AWS environment or proxy settings. It verifies STS account/root identity,
creates an S3 bucket, writes and reads exact object bytes, restarts the controller
against the same database, verifies persisted object bytes, removes the object
and bucket, and requires clean process shutdown. Temporary files are removed.
This is a concrete package/control-plane/storage smoke, **not** proof that
optional native engines or complete AWS behavior work.

To validate an **existing** clean tagged checkout without publishing anything:

```sh
python3 -B -P scripts/release.py build v1.2.3 --require-tag --output bin/releases-v1.2.3
python3 -B -P scripts/release.py verify v1.2.3 "$(git rev-parse HEAD)" bin/releases-v1.2.3
```

`verify` requires exactly the four platform archives, their complete executable
and notice layout, and manifests from the same clean tagged source commit. It
then generates the combined `SHA256SUMS`. On Linux, consumers can check downloaded
files with `sha256sum --check SHA256SUMS`; on macOS use
`shasum --algorithm 256 --check SHA256SUMS`.

## GitHub publishing

Only a **pushed tag** matching `v*` triggers the release workflow. The workflow
then rejects anything other than a `v`-prefixed SemVer version, including leading
zeros in numeric version/prerelease identifiers. Valid examples are `v1.2.3`,
`v1.2.3-rc.1`, and `v1.2.3+build.4`. A prerelease identifier marks the GitHub
release as a prerelease and does not replace the latest stable release.

The tag workflow first runs the reusable focused CI workflow, including retained
generation checks, identity/deployment/encryption regressions and actual
Terraform/CloudFormation application lifecycles. Packaging cannot start if those
checks fail.

Each native runner checks out the same exact tag, verifies its peeled commit,
builds its own archive with the pinned toolchain, and runs the packaged API
smoke on that platform. A separate publication job downloads only artifacts
from that workflow run, checks every archive manifest against the validated
commit, creates combined checksums, creates a draft containing all assets, then
publishes it. If any native job or artifact verification fails, no published
release is created. An interrupted upload/publication can leave a draft;
maintainers must inspect and remove that draft before retrying. The automation
does not overwrite an existing release.

Action dependencies are pinned to full commit SHAs. Checkout does not persist
credentials. Workflow permissions are read-only except the final publication
job's `contents: write`; publication uses GitHub's short-lived job token, not a
stored repository secret. Concurrency serializes attempts for the same tag
without canceling an in-progress release. Configure repository tag/ruleset
protection so only authorized maintainers can create release tags. The workflow
never creates or moves a tag, and ordinary branch/PR checks cannot publish.

The hosted workflow cannot be exercised end-to-end until an authorized
maintainer pushes a real release tag. Local builds/smokes and workflow syntax
checks are not evidence that GitHub runners or publication succeeded. Do not
create a tag/release merely to test the tooling without the maintainer's release
decision.

## Focused CI, not a full integration claim

`.github/workflows/checks.yml` runs on pull requests, branch pushes and release
workflow calls. It checks Go formatting, release-tool contracts, targeted
controller/identity/time/policy vet and staticcheck, focused race tests,
deployment/encryption SDK regressions, `make build`, executable IaC examples and
retained-source generators. Terraform is pinned to 1.15.9 for these CI examples.
Docker reload is a separately exercised prerequisite-heavy example, not an
unexecuted hosted claim. GuardDuty's catalog check additionally fetches
the exact upstream Git revision recorded in `docs/guardduty-findings.json` and
verifies its source SHA-256 before generation; it never follows upstream HEAD.
The generator records GitHub HTTPS repository URLs with a `.git` suffix.
This gives the same provenance for GitHub Actions checkout and ordinary clones.
The provider API check fetches the exact Terraform AWS revision recorded in
`docs/terraform-provider-apis.json`. It checks the generated source map, not
all provider resource behavior. The hosted EIP example uses AWS provider 6.68.0.
Focused regressions also cover secure CloudFormation references, Athena result
manifests, RDS requested capacity and Glue statistics. Native RDS/Trino acceptance
remains separately exercised local engine evidence.
These match repository Makefile/hook conventions without invoking the full
integration suite.

AWS operation/coverage regeneration and SSM-agent regeneration require ignored
upstream source checkouts; hosted CI does not pretend to verify them without
those inputs. Online vocabulary refresh is also intentionally excluded. SQL
checks use the Makefile-pinned SQLC version. The repository's known behavioral
integration failures remain tracked separately; a green focused CI run is not
`make check`, full integration success, or AWS parity.

Maintainer syntax/check commands (run after changes are integrated):

```sh
actionlint .github/workflows/checks.yml .github/workflows/release.yml
python3 -B -P -m unittest discover -s scripts -p release_test.py
make generate-iam-check generate-oidc-check generate-simulation-check \
  generate-lambda-runtime-check generate-sql-check generate-mq-schema-check \
  generate-cloudformation-check generate-guardduty-findings-check \
  generate-terraform-apis-check
# The GuardDuty/provider targets require the recorded clones, as prepared by CI.
```

`actionlint` is an additional maintainer prerequisite, not vendored by stackd.
The four local builds plus the matching-host API smoke above are the package
acceptance commands; hosted native smoke on the other platforms remains gated
on actual runner execution.
