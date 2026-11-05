# Lambda live reload

## Purpose

Run a Python 3.12 Lambda function in Docker, edit its mounted source and invoke
it again without redeploying. The example checks that the runtime restarts with
the edited code while the function identity and `/tmp` contents remain unchanged.

## Prerequisites

Complete [shared preparation](../README.md#prepare-once). `make build` produces
the Linux telemetry helpers required by Lambda; a controller-only build does
not. For an installed release, keep the helpers beside `stackd`.

Use a trusted local rootful Linux Docker Engine or a prepared Docker Desktop
Linux VM. Docker access and privileged Lambda storage helpers grant host/VM-root
access. The storage backend requires loop devices, ext4, `fallocate`, direct I/O
and a daemon `/dev` bind. This function does not need the VPC networking toolkit.

Select the daemon and install the images before running:

```sh
export DOCKER_HOST="${DOCKER_HOST:-$(docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}')}"
docker info --format 'OS={{.OSType}} Architecture={{.Architecture}} Security={{json .SecurityOptions}}'

# Storage helper.
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
# Python 3.12 on x86_64.
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3

docker image inspect ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
docker image inspect public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
```

For ARM64, install this runtime instead and pass `--architecture arm64`:

```sh
docker pull --platform linux/arm64 public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
docker image inspect public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
```

The runner checks installed images and helpers; it does not download them.
Match the runtime architecture to the host unless CPU emulation is configured.
See [container setup](../../docs/runtime-containers.md) for storage requirements
and offline image preparation.

## Run

### Linux

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/lambda-hot-reload/run.py --port 14663 \
  --docker-host "$DOCKER_HOST" --architecture x86_64
```

Use `--stackd PATH` for an installed server. The runner binds the API to
`0.0.0.0` and creates callback listeners on ephemeral ports so containers can
connect. Restrict inbound access to trusted clients. The SDK driver uses
loopback; the function uses `host.docker.internal` for the AWS endpoint and the
Linux host gateway for Runtime API callbacks.

The runner enables `-lambda-runtime`, selects the telemetry directory beside
the executable and maps the function ARN to its temporary source directory with
`-lambda-hot-reload-code`. The complete server command is printed at startup.

### Docker Desktop

Use the Desktop Unix socket, not a remote daemon. The server and Docker daemon
must both access the resolved source path. On macOS, allow the path in Desktop
file sharing. A path inside an unrelated server container is not automatically
a daemon-host path.

The runtime runs as UID 993. The runner creates traversable directories (0755)
and readable source files (0644), without changing an existing parent's
permissions. If your home directory is private, use a dedicated shared parent.
For Desktop installations sharing `/Users/Shared`:

```sh
RELOAD_PARENT="$(mktemp -d /Users/Shared/stackd-reload-parent.XXXXXX)"
chmod 755 "$RELOAD_PARENT"
"$EXAMPLE_PYTHON" examples/lambda-hot-reload/run.py --port 14663 \
  --docker-host "$DOCKER_HOST" --desktop --architecture arm64 \
  --work-parent "$RELOAD_PARENT"
```

`--desktop` advertises Runtime API callbacks through `host.docker.internal`,
resolved inside the VM. Permit the VM to reach the callback ports. The shared
filesystem must deliver change notifications; unsupported mounts fail the
bounded reload check.

## Expected results

The uploaded ZIP contains `MESSAGE = "uploaded"`, while the mounted source
starts with `MESSAGE = "first"`. Initial invocation returns `first`, the input
message, the function ARN and `$LATEST`. Another invocation retains the same
module `boot_id` and file-backed `/tmp` marker.

The runner edits only its temporary source copy, changing the message to
`second-edited`. It invokes the function for up to 30 seconds until it observes:

- The new message and a different `boot_id`.
- The same `/tmp` marker.
- Unchanged `FunctionArn`, `CodeSha256`, `RevisionId` and `LastModified`.

`evidence.json` records the before/after responses and deployment identity.
Function or Runtime API errors fail the example.

## Cleanup

The runner deletes its function and IAM role, checks their absence and stops the
server. Source files, SQLite state, logs and `evidence.json` remain in the
printed directory. Follow [shared cleanup](../README.md#cleanup-and-evidence).
On Desktop, also remove the temporary `RELOAD_PARENT` once empty. Keep runtime
images installed for subsequent runs; do not prune unrelated Docker resources.

## Limitations

Live reload applies only to `$LATEST`. Published versions use uploaded artifacts;
use `UpdateFunctionCode` to deploy changes. This example does not modify host
DNS or firewall settings, configure CPU emulation or support arbitrary remote
Docker daemons. See [local development directories](../../docs/lambda.md#local-development-directories).
