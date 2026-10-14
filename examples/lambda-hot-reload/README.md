# Real Docker-backed Python Lambda live reload

This executes the official Python 3.12 Lambda runtime/RIC in Docker through
stackd's Runtime API. The driver never imports the handler or synthesizes its
result. It submits a real ZIP, creates an IAM execution role/function, observes
warm invocations, atomically edits a host-mounted file, and invokes again. No
`UpdateFunctionCode`, function deletion/recreation or redeployment occurs between
the before/after invocations.

## Explicit prerequisites and preparation

Complete [shared Python/build preparation](../README.md). Run `make build`, not
just a controller-only `go build`: Lambda requires the static Linux telemetry
helper matching the function CPU, beside the controller. Use a trusted local
rootful Linux Docker Engine or a separately prepared Docker Desktop Linux VM.
Docker access and Lambda's privileged setup helpers grant host/VM-root authority.

Prepare these **exact installed pins** on the selected Engine while connected:

```sh
# Select the actual daemon; this respects an explicit operator override.
export DOCKER_HOST="${DOCKER_HOST:-$(docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}')}"
docker info --format 'OS={{.OSType}} Architecture={{.Architecture}} Security={{json .SecurityOptions}}'

# Disk-backed /tmp storage helper, required even for this simple function.
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
# Python 3.12 x86_64: the concrete linux/amd64 child manifest, not a mutable tag.
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3

# Both references must inspect successfully on this SAME Engine before execution.
docker image inspect ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
docker image inspect public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
```

For native arm64 instead, install the corresponding runtime and pass
`--architecture arm64`:

```sh
docker pull --platform linux/arm64 public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
docker image inspect public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
```

The runner **only inspects** images; it never pulls/builds one on demand. A
missing/wrong-architecture image or missing telemetry helper fails immediately.
CPU emulation is a separate prerequisite, not something `--platform` installs.
The storage helper needs privileged helpers, real loop devices/ext4, `fallocate`,
direct I/O and a daemon `/dev` bind. On Desktop those facilities must work inside
the Linux VM. This function does not use VPC networking, so it does not require
the separate networking toolkit image. Full setup and offline image identity
preservation are documented in [runtime containers](../../docs/runtime-containers.md).

## Linux run

Choose unused port 14663 or another `--port`. Restrict host inbound access before
running: unlike the IaC examples, this controller binds `0.0.0.0` so its real
containers can reach it. Runtime callback listeners also bind non-loopback on
per-environment ephemeral ports. The SDK driver still uses only loopback.

```sh
"$EXAMPLE_PYTHON" examples/lambda-hot-reload/run.py --port 14663 \
  --docker-host "$DOCKER_HOST" --architecture x86_64
```

The actual printed controller command includes all of:

```text
-lambda-runtime
-docker-host unix:///your/actual/docker.sock
-lambda-telemetry-directory /absolute/path/to/bin
-compute-endpoint http://host.docker.internal:14663
-lambda-hot-reload-code arn:aws:lambda:us-east-1:738492615083:function:<unique-name>=/absolute/owned/run/code
```

`-docker-host` alone does **not** enable Lambda; `-lambda-runtime` is required.
The full unqualified ARN uses the explicit realistic local fixture account,
verified with signed STS before provisioning. Linux's default callback uses the
Docker host gateway. No host resolver or firewall settings are changed.

## Docker Desktop host-path boundary

Use the real Desktop Unix socket selected above, **not** an arbitrary remote
Docker daemon. The controller and Docker daemon must see the same resolved
absolute source path. On Linux this is normally a host path. On macOS the
controller sees the macOS path but Docker bind mounts are served through the
Desktop Linux VM; the path must be allowed by Desktop file sharing. A path inside
an unrelated controller container is not automatically a daemon-host path.

Place runs under a shareable parent and make it traversable/readable by runtime
UID 993. The script creates its own directories with mode 0755 and source files
0644; it never changes permissions on an existing parent/home directory. If your
home is private, select a different dedicated shared parent rather than making
your entire home world-readable. For example, on a Desktop installation already
sharing `/Users/Shared`, prepare one **new** example directory there:

```sh
RELOAD_PARENT="$(mktemp -d /Users/Shared/stackd-reload-parent.XXXXXX)"
chmod 755 "$RELOAD_PARENT"
"$EXAMPLE_PYTHON" examples/lambda-hot-reload/run.py --port 14663 \
  --docker-host "$DOCKER_HOST" --desktop --architecture arm64 \
  --work-parent "$RELOAD_PARENT"
```

`--desktop` adds `-lambda-callback-host host.docker.internal`; that name is
resolved by the container's Desktop DNS, not by the native controller. Callback
ports must be reachable from the VM. If the handler filesystem notifications do
not traverse the chosen share, the bounded real-invocation check fails; this
example does not replace missing notifications with a synthetic output or claim
all NFS/SMB/FUSE paths work. Use a local supported share/filesystem.

## What must actually be observed

The uploaded ZIP has `MESSAGE = "uploaded"`, but the live source initially has
`MESSAGE = "first"`. After Active readiness, signed SDK invocation must return
`first`, the caller's exact input, the expected function ARN and `$LATEST`.
A second unchanged invocation must retain the module-level `boot_id` and the
file-backed `/tmp` marker.

The driver edits **only its owned source copy**, atomically changing the message
to `second-edited`. After the watcher's 500 ms settle interval, it repeatedly
invokes (bounded to 30 seconds) until the runtime actually returns that new
message. It then requires:

- A different module-level `boot_id`, proving customer process reinitialization.
- The same `/tmp` marker, proving the keeper's storage survived reload.
- Unchanged `FunctionArn`, `CodeSha256`, `RevisionId`, and `LastModified`, proving
  no AWS deployment mutation was used to pretend that a live reload occurred.

`evidence.json` retains the actual before/after payloads and deployment identity.
No timer, file edit or container-create response alone is treated as proof.
Actual Runtime API/function errors fail the runner. The development override
applies only to `$LATEST`; immutable published versions still use uploaded
artifacts. A deployable change must go through `UpdateFunctionCode` normally.
See [local development directories](../../docs/lambda.md#local-development-directories).

## Teardown

A `finally` block deletes only this unique function and role and checks their
absence with signed APIs. The owned controller receives SIGTERM and is awaited
for graceful runtime cleanup. The new source copy, database, logs and evidence
remain in the printed run directory for inspection. Follow [shared cleanup](../README.md#cleanup-and-evidence)
to remove that exact directory; on Desktop also remove the exact newly created
`RELOAD_PARENT` when empty. Do not prune Docker or remove existing images,
volumes, databases, or user-owned resources. Keep prerequisites installed for the
next run. A failed cleanup remains an error, never a reported passing run.
