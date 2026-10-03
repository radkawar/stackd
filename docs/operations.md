# Operations, persistence and shutdown

[Documentation index](README.md) · [Getting started](getting-started.md) · [Configuration](configuration.md)

## Keep the deployment boundary explicit

Record the controller command, database path, account, API origin and any native
runtime/state directories when starting an instance. Use a separate directory
for each instance. The documented `data/` directory is ignored by Git because it
can contain local credentials, keys, application data and captured email; that
is not a substitute for filesystem access controls or secure backups.

The basic control-plane deployment is one foreground process. Optional Docker,
Kubernetes, database and guest execution adds independently owned processes and
storage. There is no single global `stackd down` command or automatic infrastructure
sweep. Do not infer ownership from a container's name alone.

## Share source or a build, not live state

Share a clean checkout and these setup instructions, or a controller build with
the helper artifacts required by its selected runtimes. Do not bundle `data/`,
private keys, local databases, captured email, native volumes, probe workspaces
or your AWS credential files. Supply example fixture credentials, not credentials
from an existing instance. A pre-populated state bundle needs its own explicit
sanitization and ownership/recovery plan.

After a sanitizing history rewrite, use a fresh clone of the rewritten repository.
Do not merge old branches or push legacy refs back into it: that restores removed
history. Keep old worktrees attached only to the private history backup. A force
push changes published refs; it cannot erase other clones or guarantee removal of
GitHub's cached/unreachable objects. See
[GitHub's removal limitations](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository#about-sensitive-data-exposure).

There is currently no top-level project `LICENSE` file. Establish the project's
license before public redistribution; third-party licenses do not implicitly
license the repository. Native images and bundled third-party code retain their
own terms, including the restricted Glue image described in the
[runtime guide](runtimes.md#execution-selection-and-prerequisites).

## Inspect a running instance

These local administration endpoints are useful during development. Keep them
on a trusted listener; they are not a public monitoring/authentication boundary.

```sh
curl --fail http://127.0.0.1:4566/_stackd/health
curl --fail 'http://127.0.0.1:4566/_stackd/events?after=0&limit=20'
curl --fail http://127.0.0.1:4566/_stackd/clock
```

Health reports the controller and its registered capabilities, not complete
service behavior or native-engine readiness. Read the relevant resource's API
status before using an asynchronous database, cluster or other engine. Event
records are local application diagnostics; protect exported logs and journals as
potentially sensitive data.

To drain currently due service work in a deterministic scenario:

```sh
curl --fail -X POST 'http://127.0.0.1:4566/_stackd/jobs/drain?limit=256'
```

A drain does not advance time. Its `processed` count may be zero if an automatic
worker already completed the due work. `more` indicates additional due work
within the captured service instant, not a guarantee that every external effect
has finished. See [service-time configuration](configuration.md#manual-service-time)
and the [event journal](event-journal.md).

## Stop the controller

For a foreground instance, press **Ctrl-C** and wait for exit. For a process you
started under a supervisor, request its normal SIGTERM shutdown and wait for its
reported result. Target the exact process/service; do not use a blanket
`pkill stackd` on a host with multiple instances.

A clean exit is preferable to SIGKILL: shutdown closes listeners, cancels and
joins owned work, and lets runtime owners perform their required cleanup. If it
reports an ownership or cleanup error, preserve the logs and state and inspect
that specific resource. Do not bypass ownership checks by deleting everything
whose name starts with `stackd`.

| Deployment | What controller exit means |
| --- | --- |
| Control plane without `-database` or native runtimes | In-memory resource state is lost. |
| Control plane with `-database`, no native runtimes | Supported control state remains in SQLite for restart. |
| Native runtimes with in-memory state | CLI owners attempt their documented cleanup; verify the result rather than assuming every resource disappeared. |
| Native runtimes with SQLite | Service-specific engines, workloads, volumes or guests may remain for reattachment. Controller exit is not an infrastructure shutdown. |
| Embedded Go instance | Close the stack and separately dispose caller-owned runtimes/backends according to their contracts. |

## Stop all infrastructure belonging to one instance

1. Stop submitting work and quiesce applications. Scale down or disable producers
   and schedules before stopping their consumers, or reconciliation may create
   new work.
2. While the controller is available, use the service's stop/scale controls where
   supported. Examples include reducing ECS service desired count, stopping
   active CodeBuild builds and stopping EC2 instances. A service **delete** API
   may destroy native data; do not use it as a synonym for suspend.
3. Stop the controller normally and record its exit result.
4. Inspect native processes, containers, listeners and service-specific ownership
   metadata. Stop only resources whose IDs, labels and retained state establish
   that they belong to this instance. Check whether an external supervisor or
   restart policy will start them again.
5. Verify that the intended processes and listeners are no longer active.
   Preserve SQLite, engine volumes, guest disks, cluster state and snapshots
   unless permanent deletion was explicitly intended.

Useful read-only host inventory commands, when those tools are installed:

```sh
docker context show
docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Labels}}'
docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Status}}'
ps -eo pid,ppid,comm,args
ss -ltnp
```

Confirm the Docker context/endpoint before acting. Different daemons have
independent resource inventories. Service guides describe their ownership
labels and lifecycle contracts: [ECS](ecs.md#runtime-ownership-dependencies-and-recovery),
[Lambda](lambda.md#temporary-storage-and-crash-recovery), [EC2](ec2.md),
[EKS](eks.md), [RDS](rds.md), [OpenSearch](behavior-references.md#opensearch-engines-evidence-and-boundaries)
and [other runtimes](runtimes.md).

**Do not use `docker system prune`, `docker volume prune`, blanket container
removal, or state-directory deletion as a shutdown procedure.** Stopped containers
and retained volumes are not running compute. They can be intentionally retained
for recovery; storage cleanup is a separate, potentially destructive decision.

## Restart, back up and reset

Restart a persistent instance with its original command, database path, native
state paths and compatible installed images. Keep one active controller for a
storage bundle. Reusing the same path helps preserve the native ownership
namespace; copying a database is not a safe way to clone a live native deployment.

For backups:

1. Quiesce clients and native workloads so their data can be captured coherently.
2. Stop the controller and verify shutdown.
3. Use a consistent SQLite backup rather than copying a live main database file
   while ignoring its WAL. For example, with the optional `sqlite3` CLI installed:

   ```sh
   umask 077
   mkdir -p backups
   sqlite3 ./data/stackd.sqlite ".backup './backups/stackd.sqlite'"
   ```

4. Back up the corresponding engine volumes, guest disks, cluster directories,
   keys and local MIME capture as required by those owners. A SQLite backup alone
   does not include them.
5. Protect the backup and test recovery using the same service/runtime contracts.

The backend applies ordered schema migrations when opening state. Preserve a
backup before changing binaries; do not assume an older binary can read a newer
schema. See [SQLite state and recovery limits](sqlite-state.md).

For a fresh **control-plane-only** workspace, stop the old instance and choose a
new database filename, such as `./data/fresh.sqlite`. Leave the old files intact
until you deliberately decide to delete them. Native deployments also need
separate matching state/ownership resources, not just a different SQL filename.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `address already in use` | Identify the listener owner or choose a different `-listen` port; update client and advertised endpoints too. |
| CLI reaches AWS or reports real-account errors | Check every explicit endpoint override; use a dedicated shell with local credentials and no stale session token. |
| `AccessDenied` with an IAM-created user | New users have no permissions. Inspect current policies, resource policy, role trust and organization controls; do not disable IAM to hide the failure. |
| Wrong account or no resources after restart | Check credentials/account, signing region, database path and the actual server process receiving requests. |
| TLS trust or hostname error | Trust the correct CA and use a hostname/IP in the certificate. Do not make verification bypass the standard setup. |
| Function/task cannot reach the API | Container loopback is not host loopback. Check `-listen`, compute/public origins, DNS and returned resource URLs; see [runtime networking](runtimes.md#networking-before-execution). |
| Runtime/image prerequisite error | Install the documented runtime, immutable image and helper artifacts; the emulator does not silently pull or simulate them. |
| `NotImplemented` / unsupported configuration | Check the service guide and inventory. Registration is not a promise of complete AWS behavior. |
| Jobs appear stalled | Check the resource state, current IAM, runtime readiness, logs and whether a manual clock is paused. Advancing service time does not advance guest/container clocks. |
| Shutdown refuses to clean up an ownership mismatch | Preserve state and diagnose the exact current owner. Do not sweep a successor's resources. |

## Real AWS probes are a separate operational boundary

Ordinary local usage does not need an AWS account. Scripts under `scripts/aws/`
include both local smokes and native AWS probes; read each script before running
it. Native probes can create billable resources and require explicit real-account
credentials, ownership fences and cleanup. Their resources do not disappear when
the local emulator stops.

For native cleanup, establish the account, region and exact owned resource IDs
from retained capture/cleanup records. Confirm live state and stop/delete only
those resources. A pending KMS deletion window or failed service-linked-role
deletion is not completed cleanup. Retain such blockers explicitly rather than
altering unrelated account settings or claiming everything was deleted.
