# Route 53: retained control plane and authoritative DNS

Route 53 owns typed public hosted zones, record sets and change receipts. The
existing `compute/dns.Server` serves their actual retained records over UDP and
TCP; there is no second record registry, DNS daemon, host-resolver fallback or
implicit change to host DNS settings. ACM uses an actual DNS protocol client
against this same endpoint, not an account-privileged Route 53 repository read.

## Configuration and ownership

For a DNS-only instance, select the listener explicitly:

```sh
go run ./cmd/stackd -listen 127.0.0.1:4566 \
  -database ./route53.sqlite -dns-listen 127.0.0.1:1053
```

Embedding uses `Config.DNSListenAddress` and discovers the bound address through
`Stack.DNSAddress()`. The existing ALB runtime also creates its documented
loopback ephemeral listener when explicitly enabled. No listener is created
solely by constructing a Route 53 service. Without an attached DNS authority,
zone creation and record changes return `NotImplemented` instead of claiming
that DNS publication succeeded. Retained reads and cleanup remain available.

DNS clients must select the resolver themselves, for example
`dig @127.0.0.1 -p 1053 app.example.test A` and the same command with `+tcp`.
The listener is authoritative only by default. Explicit selected upstreams and
client-scoped recursion are available through the [networking configuration](networking.md#dns-authority-and-optional-forwarding);
owned negative, delegated and error answers are never forwarded.

`route53.New(Config)` accepts the service-owned `Repository`, the current shared
IAM `Authorizer`, API-event `Recorder`, shared `Clock`, `DNSAuthority` and an
optional `AliasResolver`. Construction registers one read-only owner;
`Service.Close` unregisters it. The authority interface is
`Register(dns.Resolver) (func(), error)`.

External aliases use a consumer-defined boundary:

- `ValidateAlias(ctx, AliasTarget, dnsmessage.Type)` reads the actual target's
  retained identity within the admission transaction. It performs no network
  observation or credential renewal.
- `ResolveAlias(ctx, AliasTarget, dnsmessage.Type)` obtains current owner answers
  after the Route 53 snapshot has been released. No EC2 address, ALB listener or
  runtime node is copied into Route 53 storage.

## Implemented API behavior

The generated frontend comes from the pinned AWS SDK v2 `route-53` Smithy model.
Implemented commands are:

- `CreateHostedZone`, `GetHostedZone`, `ListHostedZones`,
  `ListHostedZonesByName`, `GetHostedZoneCount`;
- `UpdateHostedZoneComment`, `DeleteHostedZone`;
- `ChangeResourceRecordSets`, `ListResourceRecordSets`, `GetChange`.

The API is global within a partition and account; request region does not fork
hosted zones. Other accounts cannot read or mutate a zone/change by guessing its
ID. Lists filter to the caller's scope, use stable ordering and accept their
modeled pagination cursors. Record lists sort reversed DNS names, DNS type
numbers and set identifiers. Zone IDs and change IDs accept the standard
`/hostedzone/` and `/change/` prefixes.

Creation retains the caller reference, comment, timestamp, unique delegation
identity, apex NS and SOA records. Reusing a caller reference returns
`HostedZoneAlreadyExists`, including when the requested name differs. Duplicate
zone *names* are valid control-plane resources; their DNS ambiguity is handled
explicitly below. Apex NS/SOA records cannot be deleted. A hosted zone cannot be
deleted while other record sets remain. Its change receipts remain readable by
the owning account after deletion.

CREATE rejects an existing record-set key; UPSERT creates or replaces it;
DELETE must match the stored set's name, type, identifier, policy, TTL, all
values and alias target. Names and RDATA are parsed and normalized, including
case/trailing-dot equivalence for domain-name values; list output uses the
normalized presentation. Input record-value order does not affect DELETE.
Malformed RDATA, out-of-zone names, CNAME/apex conflicts, mixed routing policies,
duplicate values and alias cycles reject the entire change batch. Multiple
changes never partially commit, including failures after a preceding DELETE.
The default 1,000-record-element batch bound counts UPSERT twice.

Every command checks the current shared IAM evaluator inside its transaction.
`ChangeResourceRecordSets` supplies all requested normalized names, types and
actions through the documented `route53:ChangeResourceRecordSets*` condition
keys; a disallowed member cannot hide in an otherwise allowed batch. Hosted-zone
and change operations use their actual resource ARN. Successful API completions
commit through the existing event recorder with state; rejected calls use its
ordinary completion path. There is no service-specific audit log.

A committed batch is immediately visible to the single local authority. Its
change receipt is `PENDING` until `SubmittedAt + 1 second`, then `INSYNC`, using
the injected service clock. This is a local acknowledgement interval, not an
emulation of AWS's distributed propagation delay. The retained deadline makes
status survive restart without a process-local timer or background polling job.

## DNS resolution and delegation boundary

DNS itself is public and carries no caller account identity. Public records are
therefore intentionally visible to DNS clients independent of API IAM. Private
hosted-zone creation/VPC attachment is rejected: there is no isolated VPC DNS
boundary, and private records are never published on the global listener.

A local instance is an explicitly configured DNS authority, not the public DNS
root. For a query, the outermost retained matching zone controls its subtree:

1. One matching outermost zone supplies authority for the name.
2. Multiple outermost zones with the same name produce `SERVFAIL`. Creation
   order, account ID and lexicographic zone ID never select a shadow copy.
3. A more-specific hosted zone is hidden until its parent has an NS delegation
   matching that child's exact assigned name-server set. This can deliberately
   delegate to another account's public zone, just as public DNS can.
4. A matching unique delegated child becomes authoritative. An external or
   unmatched delegation returns an NS referral with only in-bailiwick retained
   address glue; it does not expose parent records below the delegation.

The assigned `ns-<n>.<zone-id>.stackd.invalid.` names distinguish delegation
identities on this one explicitly selected local endpoint. They are not real
Internet name servers or an automatically published parent delegation. To
resolve duplicate child names, install the selected child's returned delegation
set in its real retained parent. Ambiguous duplicate roots require a parent
boundary or removal; callers cannot select them with AWS credentials over DNS.

The built-in ALB owner is registered before Route 53. Its managed
`.elb.amazonaws.com` / `.elb.amazonaws.com.cn` authority therefore cannot be
shadowed by customer-created zones, including an exact ALB-name zone. Service
owners retain authority over their managed namespace rather than sharing copied
resource records.

Supported parsed DNS records are **A, AAAA, CNAME, TXT, MX, NS, SOA, PTR, SRV and
CAA**. CAA uses its standard type-257 wire encoding. TXT handles quoted string
segments and DNS character escapes. The authority provides:

- exact names, empty nonterminals and closest-encloser wildcard synthesis;
- NXDOMAIN for absent names, versus NOERROR/NODATA for an existing name without
  the requested type, with the zone SOA for negative caching;
- CNAME answers and bounded in-zone CNAME following, without recursion into an
  unrelated zone or through a delegation;
- `SERVFAIL` for CNAME/alias loops or unavailable external alias owners;
- UDP truncation with complete responses available over TCP;
- removal from actual DNS after record or zone deletion. With no remaining owner,
  an out-of-authority query is refused.

Weighted records require unique set identifiers and weights 0–255. A positive
weight excludes zero-weight alternatives; an all-zero group selects uniformly.
The selected set is returned, not all weighted values. Multivalue groups return
up to eight distinct sets, one resource record per set. All configured values
without health checks are eligible; this does not assert endpoint health. A
multivalue response uses a consistent minimum TTL for its returned RRset.
Health-check IDs, latency, failover, geo/geoproximity and CIDR policy inputs
return explicit errors rather than synthetic healthy/nearby answers.

Same-zone A/AAAA aliases require an existing same-type target and inherit its
TTL. Cycles and targets beneath delegation boundaries are rejected. ALB A aliases
require the actual `CanonicalHostedZoneId` and DNS name returned by ELB, resolve
current EC2-owned addresses, and survive owner restart without address copying.
The ALB adapter accepts its `dualstack.` name spelling but rejects AAAA because
its current runtime is IPv4-only. `EvaluateTargetHealth=true` is unsupported.

## Typed durability

Memory repositories join `storage/memory.Domain`. SQLite repositories use
`storage/sqlite/route53.New(*sql.DB)` and the shared transaction/savepoint kernel.
The service schema owns normalized `route53_zones`, `route53_record_sets`,
`route53_record_values` and `route53_changes` tables. There are no opaque JSON
resource rows. Record children and changes commit atomically with the zone;
change receipts deliberately outlive zone deletion. Canonical `sqlc.yaml`
generates `storage/sqlite/route53/internal/sqlcgen`.

## Evidence and limits

Focused verification on 2026-09-28:

- `go test ./internal/services/route53 ./storage/sqlite/route53` passed, including
  AWS Go SDK v2 decoded RESTXML outputs and modeled `InvalidChangeBatch` /
  `NoSuchHostedZone` errors, current IAM conditions/denial, atomic invalid changes,
  matching DELETE, wildcard/NODATA/CNAME, alias cycles, delegation isolation,
  weighted and multivalue behavior, and SQLite close/reopen.
- The durable test sends actual UDP and TCP packets before/after restart,
  checks the retained address and negative SOA, proves outer-transaction rollback,
  and verifies deleted records/zones do not revive.
- Scoped `go vet`, `go tool staticcheck`, and `go test -race` passed for the changed
  service/repository packages.
- A standalone executable exercised AWS Go SDK v2 HTTP lifecycle plus actual
  UDP/TCP `net.Resolver` clients, clock-driven INSYNC, deletion NXDOMAIN and exact
  cleanup. [Retained output](../internal/services/route53/testdata/local-dns-smoke.json)
  explicitly identifies its fixture-root identity boundary; it is not a claim of
  standalone SigV4 gateway verification.
- [Native calibration](../internal/services/route53/testdata/native-controls.json)
  records AWS caller-reference rejection, protected apex NS/SOA, multivalue
  one-RDATA admission and canonical-equivalent CNAME DELETE. The capture notes an
  interrupted tool kernel and subsequent exact-owned recovery; missing initial
  response bodies are not invented. The owned record/zone were deleted and a
  final native `NoSuchHostedZone` verified cleanup. No public delegation existed.
- The [assembled native workflow](../testdata/integration/route53_acm_smoke.json)
  uses signed SDK calls and unmodified `dig` over UDP/TCP for atomic changes,
  current IAM denial, CNAME publication, ALB aliases, restart and removal. It
  issues a real ACM certificate, serves it on an actual native ALB and observes
  a renewed leaf on that same listener. A customer-created exact ALB-name zone
  cannot shadow the managed owner. Deleting an alias while its ACM validation
  descendant remains yields NODATA; deleting the descendant then yields
  NXDOMAIN. Deleting the final hosted zone yields REFUSED. The successful run
  removed its two zones, certificate, IAM user/key, ALB, subnets, security group
  and VPC; exact-owned native ALB container absence was verified.
- A subsequent [signed SDK metadata probe](../testdata/integration/route53_metadata_smoke.json)
  checks the ordinary AWS request ID on successful create/read/delete responses.
  The SDK decodes the gateway-assigned `X-Amzn-Requestid`, without stackd-specific
  response headers; its exact-owned hosted zone was deleted.

Remaining explicit boundaries (`TODO: Comeback` in the owning source) are escaped
or binary DNS label codecs; health/location-based routing; non-A/AAAA same-zone
aliases and additional real external target owners; and the remaining generated
operations such as health checks, DNSSEC, traffic policies, reusable delegation
sets, tags and private-VPC zones. Unsupported record types are rejected. Query
logging, Internet recursion, DNSSEC signing, EDNS/client-subnet routing, public
registrar delegation and multi-server propagation are not implemented. These
bounds are not claims of complete Route 53 parity.

Primary contracts:

- [Change batches, DELETE matching and propagation](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html)
- [Resource-record policy, type and TTL constraints](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ResourceRecordSet.html)
- [DNS name and wildcard rules](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html)
- [Record value syntax](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html)
- [Weighted routing and all-zero groups](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy-weighted.html)
