# Current-provider API controls

## Purpose

This companion to `../terraform-api` declares 24 managed Terraform types,
55 managed instances, and 11 data-source types across API Gateway REST/V2,
AppSync, and Route53. The exact per-type boundaries and unimplemented families
are retained in `coverage.json`; registration alone is not implementation.

## Prerequisites

### Preparation and command

Use official Terraform **1.16.6** and AWS provider **6.68.0**. The runner rejects
another Terraform version and the configuration pins both versions exactly.
Complete the shared [Python environment and controller build](../README.md#prepare-once),
then install the extra client packages from the repository root:

```sh
"$EXAMPLE_PYTHON" -m pip install -r examples/terraform-api-controls/requirements.txt
```

Prepare the Linux amd64 Lambda telemetry helper beside `stackd`, Docker
CLI/Engine, OpenSSL, BIND `dig`, and PostgreSQL `psql`. Prepare the
[Docker host and Lambda storage prerequisites](../../docs/runtime-containers.md).
Preinstall the five exact digests from `run.py`:

```sh
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
docker pull amazon/dynamodb-local@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab
docker pull postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
docker pull mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d
```

Nothing pulls images implicitly. The fixture uses the amd64 runtime/helper;
other host architectures need separately prepared execution support.

## Run

From the repository root, with Terraform 1.16.6 selected on `PATH`:

```sh
"$EXAMPLE_PYTHON" examples/terraform-api-controls/run.py \
  --port 14803 --dns-port 15803 --http-port 16803
```

`--provider-mirror /absolute/path/to/mirror` selects AWS 6.68.0 from an existing
filesystem mirror without registry fallback. Omitting it permits registry
installation. `--stackd /absolute/path/to/stackd` selects a prepared controller;
`--work-parent /existing/directory` changes the new workspace's parent.
`--docker-host` selects an existing local Unix-socket daemon (default:
`DOCKER_HOST`, otherwise `unix:///var/run/docker.sock`).

All three ports must be unused and distinct. The owned controller binds
`0.0.0.0` so runtime containers can make callbacks; only run on a trusted host
with appropriate firewall isolation. SDK, Terraform, WebSocket, SQL, and DNS
consumers target the actual owned endpoints. Each execution generates a unique
12-digit local account and resource-name prefix, uses fresh retained SQLite
state, and discovers the account with a signed STS request. Reopen preserves
that exact account and database. There is no native AWS provisioning, host DNS
change, insecure TLS option, broad Docker cleanup, or production credential
fallback.

The real HTTP data source and OIDC discovery/JWKS issuer share a private owned
TLS listener. The runner explicitly enables `-oidc-discovery`, advertises the
RS256 algorithm, signs genuine RS256 OIDC tokens, and trusts the exact owned CA
via ordinary certificate verification. The listener processes actual
GraphQL source requests; it is not a fabricated AWS endpoint or a response
header that bypasses deployed state.

## Assertion-bearing workflow

* Create all managed resources with the pinned provider. Consume data-source
  outputs and deployed REST and HTTP authorizers using actual Python Lambda
  invocation, rejection cases, 60-second cache identity, and REST cache flush.
  Exercise Cognito/JWT tokens and reject tampering. Cognito's nullable TTL
  control behavior has separate captured evidence; it is not credited as a
  Lambda cache.
* Consume the Swagger-imported deployed response; HTTP and direct-Lambda
  GraphQL sources; verified OIDC and Cognito GraphQL authentication; a real
  DynamoDB resolver write and independent native item read; an RDS Data write
  and independent `psql` row read; GraphQL subscription delivery; and a real
  WebSocket Lambda reply.
* Assert UDP **and** TCP DNS answers for A, AAAA, TXT, CNAME, PTR, MX, SRV, CAA,
  SOA, weighted and multivalue records, and NS referral/glue. Add a rogue record
  and prove `records_exclusive` reconciliation removes its actual DNS answer.
* Check current IAM grant/revocation, live-stage throttling, request-correlated
  access/execution Logs, current logging-role denial, and current AppSync-role
  denial with no DynamoDB side effect. Preserve a live socket while proving a
  draft route-response deletion changes nothing until deployment, then
  suppresses delivery without suppressing the actual backend invocation.
  Verify signed management callbacks deliver the exact frame and deny an
  ungranted caller.
* Import eight managed instances across seven types and require a normal
  detailed-exitcode plan to return **0** without ignoring drift. Change the
  revision, assert stable owner IDs and changed deployment IDs, and consume all
  changed real effects through retained sockets. Clear and restore the
  account's logging role without rewriting the actual client response.
* Require an updated no-op plan, stop the owned controller gracefully, reopen
  the same database/account, establish new actual sockets, reconsume the
  changed effects, recheck revoked IAM authority, and require another no-op
  plan. Finally require a refresh-only detailed-exitcode plan to return **0**.
* In success and failure paths, destroy owned Terraform resources; verify API,
  account and zone absence, empty Terraform state, and DNS refusal; delete the
  exact SDK prerequisites; and gracefully stop the owned controller.

The final refresh-only gate is deliberately last so an upstream no-diff exit2
cannot hide unexercised update/reopen consumers. **Exit2 remains terminal
failure**, including when the plan text says “No changes.” It is neither
applied nor normalized to success. Real provider or owner drift is also a
failure; the runner does not use `ignore_changes`, fake authority, or downgrades.

## Expected results

A successful run finishes all consumers, eight imports, update, actual database
reopen, strict refresh/normal plan gates and destroy. It prints
`Current-provider API control lifecycle complete`. A strict-plan failure remains
a nonzero result even if consumer and cleanup stages succeeded.

## Cleanup

The runner attempts Terraform destroy and exact SDK prerequisite cleanup on
failure as well as success, checks absence/empty state, and stops its owned
controller and TLS listener. The retained private directory contains sensitive
keys, tokens, database credentials, `stackd.sqlite`, Terraform state/plans,
`stackd.log` and numbered Terraform logs. Remove only that exact printed directory
after owned processes have stopped and evidence is no longer needed.

## Limitations

### Evidence and limitations

The printed private workspace is retained with mode0700 because state, tokens,
keys and database credentials are sensitive. `evidence.json` records the exact
controller path and SHA256, Terraform fixture SHA256 values, account, completed
assertion stages, every Terraform argv/exit status, per-command output logs, and
terminal error/success. `refresh.tfplan` and its `terraform show -json` command
log retain the final gate's actual result. A cleanup stage does not imply the
lifecycle succeeded. Inspect both the terminal error and completed stages.

The provider unconditionally replays the read cache TTL when updating method
settings. With no allocated/enabled stage cache, only the identical default
`300` replay is accepted. A changed TTL or cache enable still fails explicitly,
and a failed later patch rolls back earlier throttle changes. This does not
claim response caching. See the
[official method settings contract](https://docs.aws.amazon.com/apigateway/latest/api/API_MethodSetting.html).
Exclusive DNS record names use canonical absolute trailing-dot names so import
and refresh agree with actual Route53 API output; no normalization drift is
ignored. Zone `force_destroy` remains enabled and uses the owner-backed
unsigned `GetDNSSEC` read, not a fabricated successful signing state.

The real PostgreSQL engine is exposed as an Aurora-shaped cluster/writer for
this local Data API consumer. This fixture does not certify Aurora replication,
SQL TLS, all AppSync languages, every routing mode, or sibling service Terraform
lifecycle coverage. SDK-created IAM/Lambda/Logs/DynamoDB/RDS/Cognito prerequisites
are consumed dependencies, not extra managed-type claims. Unsupported provider
families remain explicitly listed in `coverage.json`. Delete only the exact
printed workspace after reviewing its evidence.

## Exercised result

Historical official Terraform **1.16.6** / AWS provider **6.68.0** evidence completed
both revision consumers, eight imports, current IAM checks, database reopen,
normal no-op plans and destruction of all 55 instances, but **failed** the final
refresh-only gate with exit 2 despite no semantic changes. `coverage.json`
preserves that bounded evidence; it is not a passing full lifecycle.

A separate run with the explicit local
[Terraform Core correction](../README.md#terraform-core-refresh-only-correction-opt-in)
passed the complete API-controls lifecycle. That binary is a **locally patched
consumer**, not an official release or upstream-merged fix. Preserve its source,
patch and binary checksums and keep official and patched results distinct.
Do not downgrade a binary or weaken the strict gate to obtain a pass.
