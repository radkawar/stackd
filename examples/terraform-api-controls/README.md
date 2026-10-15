# Current-provider API controls

This companion to `../terraform-api` declares 24 managed Terraform types,
55 managed instances, and 11 data-source types across API Gateway REST/V2,
AppSync, and Route53. The exact per-type boundaries and unimplemented families
are retained in `coverage.json`; registration alone is not implementation.

## Preparation and command

Use official Terraform **1.16.6** and AWS provider **6.68.0**. The runner rejects
another Terraform version and the configuration pins both versions exactly.
Install Python dependencies from this directory's `requirements.txt` in a
private virtual environment. Prepare a controller and its Linux amd64 Lambda
telemetry helper side by side, plus Docker, OpenSSL, `dig`, and `psql`.
Preinstall the five exact image digests named in `run.py`; image inspection must
succeed before any resource is created. Nothing pulls images implicitly.

```sh
python -m pip install -r examples/terraform-api-controls/requirements.txt
PATH="/absolute/path/to/terraform-1.16.6/bin:$PATH" \
  python examples/terraform-api-controls/run.py \
  --stackd /absolute/path/to/prepared/stackd \
  --provider-mirror /absolute/path/to/provider/mirror \
  --port 14803 --dns-port 15803 --http-port 16803
```

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

## Evidence and limitations

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

The retained run `/tmp/stackd-terraform-api-controls-2q1wxd1l` used account
`392406071851`, official Terraform1.16.6/provider6.68.0, and the coherent private
source manifest `.stackd/api-controls420-source-93qz5kr_/manifest.json`.
All declared first/second-revision consumers, eight imports, current IAM and
role effects, graceful database reopen and fresh socket consumers completed.
Normal strict import/update/reopen plans each exited0. Terraform destroyed all
55 instances; signed API/account/zone absence, empty state and actual DNS
refusal passed; exact SDK prerequisites were cleaned up.

The lifecycle **did not pass**: the final refresh-only plan exited2.
`terraform-039.log` says “No changes”; `terraform-040.log` has no resource drift
or resource changes and an identical before/after no-op `proof` output.
The runner retained this as terminal failure and did not apply the plan.
`coverage.json` records the exact evidence and earlier fixture/owner defects;
its per-type aggregate lifecycle statuses are deliberately not promoted to a
passing lifecycle based only on the successful stages.
