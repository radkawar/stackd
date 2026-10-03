# GuardDuty

GuardDuty implements detector configuration, explicit sample-finding workflows
and structured detection rules over recorded API activity and native EKS audit
metadata. Enabled detectors
produce findings for root-credential use, IAM password-policy change attempts,
CloudTrail/S3 logging changes, S3 public-access-block disabling, public bucket ACL
grants, bounded anonymous bucket-policy grants and custom threat-list matches for IAM/S3 activity. S3 data-event protection
gates the implemented S3 data predicates, not management-event rules.
EKS audit protection gates system-pod exec, bounded anonymous-access rules and
admitted anonymous RBAC grants; it does not require CloudWatch log delivery.
DNS and flow-log statuses remain configuration responses, not active telemetry
consumers. Other optional protection activation fails rather than claiming to
start an absent scanner or agent. The generated inventory has 102 modeled
operations: 35 partial and 67 unimplemented. Counts do not establish completeness.

## Implemented workflow

- Account/region/partition-scoped detectors, one per regional account; retained
  tags, publishing frequency and client-token replay.
- Protected `AWSServiceRoleForAmazonGuardDuty` provisioning through current IAM,
  in the detector transaction. Existing roles are reused. Detector ownership
  protects the role across regions until the detectors are deleted, including
  suspended detectors.
- Explicit `CreateSampleFindings` uses 444 retained native sample variants, with
  account/detector/finding identities rebound to local ownership. These are
  examples requested by the caller, never detections of real activity. Samples
  are versioned immutable inputs; mutable finding state uses typed rows, not
  generic JSON resource blobs.
- Finding retrieval, stable keyset pagination, modeled scalar/nested criteria,
  sort order, archive/unarchive and feedback; repeat samples update active
  findings and archived identities remain independently retained.
- Saved filters, suppression for new occurrences, ranks, tags, and grouped finding
  statistics. Finding-type groups use the projected type for both observations
  and samples; totals count finding identities, not repeated occurrences.
  Suppression state is separate from manual archival.
- Memory and SQLC/SQLite share transactional API recording. Pending finding
  publications and last-publication cursors survive restart. The producer admits
  events through EventBridge; target policies and delivery remain EventBridge's
  responsibility. Initial and aggregated subsequent publication use the shared
  service clock and scheduler.

A detector request must explicitly disable unsupported optional features that
AWS would otherwise enable by default. No implementation of optional protection
is implied by the retained feature configuration.

## S3 publishing destinations

The five publishing-destination operations retain scoped destination properties,
tags, token replay and delivery health in memory or SQLC/SQLite. Admission checks
current GuardDuty IAM, then performs S3/KMS validation outside the resource
transaction. The commit rechecks current authority and destination incarnation.
Native lifecycle captures establish the one-destination quota, validation before
token replay, partial updates, lowercase child ARNs, epoch-millisecond failure
timestamps, and a continuation token on a full final list page.

Validation writes a real zero-byte, SSE-KMS `AWSLogs/` permission marker.
Delivery uses the GuardDuty service principal and source detector ARN/account,
not the caller's credentials or HTTP transport. S3 owns object-policy conditions
and KMS data-key authorization. Explicit-prefix existence discovery currently
uses the caller's S3 List/Head authority. Native
`publishing_destinations_prefix_authority.json` confirms this boundary with a
short-lived federated caller explicitly denied all S3/KMS access: root-bucket
creation succeeds, while existing/missing-prefix creation and existing-prefix
update return GuardDuty `BadRequestException`/HTTP 400 naming the required
`s3:GetObject`/`s3:ListBucket` permissions. The integration translates those
permission failures instead of leaking S3 `AccessDenied`/HTTP 403.

Finding changes and immutable wire payloads enter a transactional outbox.
The shared scheduler writes actual gzip JSONL objects with current S3/KMS
authority, outside transactions. Initial delivery uses a deterministic five-minute
deadline; subsequent occurrences coalesce at the detector's fifteen-minute,
one-hour or six-hour cadence. Retry retains the object key and publication ID.
Failures retry after five minutes, retain the original failure timestamp and
stop after ninety days; validated destination updates recover stopped work.
These precise local deadlines are not measurements of native AWS scheduling.

Archived findings are excluded from S3, including automatic suppression.
Explicit unarchive can queue an active finding again. EventBridge separately
continues publishing manually archived occurrences, as AWS documents.
Destination replacement/deletion, finding expiry and changed pending contents
fence stale jobs and completion writes. SQL deadline selection does not load
queued payloads. Destination state, publication IDs and cadence survive restart.

The executable workflow reads and decompresses S3 objects through signed SDK
calls. It verifies separate sample/observed identities, root-call aggregation,
archive exclusion, source-policy denial, KMS denial/recovery, retained deadlines,
prefix IAM grant/revocation, SQLite restart and owned-resource cleanup. This proves
local effects, not native payload or batching equivalence.

Native `publishing_destinations.json` and
`publishing_destinations_export.json` retain 120.56-second and 600.907-second
observation windows. The longer capture retained an active sample and a
`PUBLISHING` destination but no finding object. Permission markers are not
finding-delivery evidence. Both captures removed owned destinations, detectors
and buckets and scheduled owned KMS key deletion; the preexisting role was not
explicitly changed. Export payload equivalence and eligibility remain unresolved.

The prefix-authority capture creates no sample finding and does not calibrate
export payloads. It verifies deletion of its destination, detector and bucket,
and schedules its owned KMS key for deletion. Run
`python scripts/aws/guardduty_destinations_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID --prefix-authority --observe-seconds 0 --output <new-capture-path>`
to repeat on an empty regional boundary. Credentials remain process-local; no
persistent IAM identity is created or modified. The local SDK smoke also checks
list-only denial, complete read grants, revocation and unchanged destination state.

## Trusted IP and threat intelligence lists

The ten legacy `IPSet`/`ThreatIntelSet` operations own scoped metadata, tags,
ingested IPv4 intervals and activation recovery state in memory and SQLC/SQLite.
The captured regional quotas are one trusted list and six threat lists. Replay
uses name plus client token; replayed tags do not replace existing tags. Deleted
lists remain readable as `DELETED` tombstones with empty tags, leave list results
and release quota; repeated deletion returns an error.

Create/list authorization uses `*`; get/update/delete and tagging use the child
list ARN and current tags. Caller-authorized IAM policy changes commit with list
intent. Reads assume the real protected service-linked role and use S3's current
authorization, expected-owner check and KMS path outside the list transaction.
An authorized HEAD bounds the source to 35 MiB and pins its version or ETag before
GET. Sources are S3 URIs or S3 HTTP(S) URLs, never arbitrary HTTP fetches. SSE-C is
not accepted. Literal wildcard/variable bytes in object keys use IAM's predefined
literal variables so a list grant cannot authorize neighboring objects.

Activation parses TXT, ALIEN_VAULT, OTX_CSV, PROOF_POINT, FIRE_EYE or STIX into
sorted, disjoint IPv4 intervals. Entry limits apply before coalescing. Admission
failures roll back; an admitted activation whose read or parsing fails retains
`ERROR` and the attempted metadata. Deadline/version fencing prevents stale
completion from overwriting an update or deletion. `ACTIVE` snapshots do not
follow S3 overwrites: explicitly reactivate to ingest changed bytes.

An active trusted list takes precedence over threat matches and the implemented
API rules for public IPv4 origins. It does not erase earlier findings or affect
explicit samples. Active threat matches produce these management/S3 types;
the [native EKS path](#native-eks-audit-detection) also consumes these lists:

| Finding | Local API predicate |
| --- | --- |
| `Recon:IAMUser/MaliciousIPCaller.Custom` | Authenticated management `List*` and `Describe*` requests. |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` | Other authenticated management requests. |
| `Discovery:S3/MaliciousIPCaller.Custom` | Authenticated S3 data `GetObjectAcl`, `ListObjects` and `ListObjectsV2` requests; requires `S3_DATA_EVENTS`. |
| `UnauthorizedAccess:S3/MaliciousIPCaller.Custom` | Authenticated S3 data `PutObject` and `PutObjectAcl` requests; requires `S3_DATA_EVENTS`. |

Denied attempts retain their actual error. Finding evidence retains matching
list names in ordered SQL child rows, independently of later list changes.
S3 evidence requires the source event's bucket ARN to agree with its request;
that ARN survives restart and projects as `S3BucketDetails`, without inventing
the bucket owner's account. Private/special-purpose origins, IPv6 and service
origins do not trigger custom matches. The S3 operation subset follows the
documented examples, not a claim to AWS's complete private classification.
Other custom conditions, member propagation and entity lists remain open.

A signed-SDK smoke against the assembled SQLite Stack ingested a real S3
threat list, invoked IAM ListRoles/CreateUser and S3 ListObjectsV2/PutObject,
then verified all four types and retained S3 details after reopening the database.
The harness configured `RemoteAddr=8.8.8.8:12345` at the transport boundary:
this verifies the event pipeline, not traffic originating from that address.
Evidence database: `/tmp/stackd-custom-threat-1979565650/state.db`.
S3 management findings retain `AccessKey`; only S3 data findings use
`S3Bucket`. The existing executable smoke caught an overbroad projection during
integration; its unchanged assertions and the new data-event smoke both pass.

`testdata/aws/guardduty/ip_lists.json` records native lifecycle, source errors,
quota, token, tag and deletion behavior. In that capture, several modeled
`InternalServerErrorException` responses used HTTP **400**, not 500. Native
detection timing/grouping, policy naming/granularity and delayed transition
windows are not established by the capture. Its lists, detector and S3 objects
were cleaned up; the preexisting linked role was not deleted.

## Structured API detection

`internal/services/guardduty/detection_rules.go` defines typed rules: finding
type/severity, source/category, operations, credential predicate, success
requirement, feature gate and resource extraction. Adding a rule does not require
embedding behavior in the sample catalogue or a catch-all resource engine.

| Finding | Predicate |
| --- | --- |
| `Policy:IAMUser/RootCredentialUsage` | Recorded `Root` caller without temporary-session provenance; management API requests and authenticated S3 data requests when `S3_DATA_EVENTS` is enabled, including denials. |
| `Policy:IAMUser/ShortTermRootCredentialUsage` | Recorded `Root` caller with a session creation time; management API requests and authenticated S3 data requests when `S3_DATA_EVENTS` is enabled, including denials. A role assumed by root is not a root caller. |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | Successful named `StopLogging`, `DeleteTrail` or `UpdateTrail`; successful deletion of an S3 bucket associated with a current trail, or an authenticated log-object deletion when `S3_DATA_EVENTS` is enabled. Failed operations and unrelated deletions do not match. |
| `Stealth:S3/ServerAccessLoggingDisabled` | Successful `PutBucketLogging` with an explicit empty logging status. Enabled configurations, missing audit input and failed changes do not match. |
| `Policy:S3/BucketBlockPublicAccessDisabled` | Successful `PutBucketPublicAccessBlock` whose submitted configuration leaves any setting false (including omitted settings), or `DeleteBucketPublicAccessBlock`. Identifies the actual bucket. |
| `Policy:S3/AccountBlockPublicAccessDisabled` | Corresponding successful account-level PUT or DELETE. Identifies the authenticated account, which S3 Control requires to match the target account. |
| `Policy:S3/BucketAnonymousAccessGranted` | Successful `PutBucketAcl` granting `AllUsers`, or `PutBucketPolicy` with an S3-owned anonymous permission proof in the domain below. Evidence comes from admitted state, not proposed request text or `IsPublic`. |
| `Policy:S3/BucketPublicAccessGranted` | Successful `PutBucketAcl` whose admitted S3-owned ACL grants the `AuthenticatedUsers` group. A request granting both groups produces both finding types. |
| `Stealth:IAMUser/PasswordPolicyChange` | Recorded `UpdateAccountPasswordPolicy` or `DeleteAccountPasswordPolicy` attempts, including denials. Retains the actual account, caller and latest outcome; does not claim every update weakened the policy. |

These are explicit deterministic rules, not AWS's private anomaly models.
Trail updates match the documented operation condition; this is not an inference
that every changed setting necessarily reduced logging. S3 data-event predicates
are separately gated on `S3_DATA_EVENTS`, which can be enabled through detector
configuration. They consume the existing transactional S3 API producer without
requiring a customer CloudTrail trail. Anonymous requests are excluded. Enabling
the source does not replay disabled-period activity or imply implementation of
other S3 finding types or AWS's private risk models.
The S3 access-logging and public-access-block rules consume management events;
they work without S3 Protection. Their resource type is `AccessKey`, with the
affected bucket or account identified in the API action. Fully enabled public
access blocking, missing configuration evidence and denied changes do not match.
These are guardrail-change predicates, not proof that a bucket is public or that
an individual setting transitioned from true to false. Exact AWS partial-setting
eligibility and finding grouping have not been calibrated with native detections.

Public bucket ACL grant rules read the admitted ACL inside the S3 outcome's
transaction. They do not reconstruct grants from audit request text or claim
effective access after Block Public Access masking. Denied and private ACL
changes do not match. These are management findings (`AccessKey` resource type
with the actual bucket in `affectedResources`), independent of S3 Protection.
Memory/SQLite regressions verify atomic ACL/finding/journal rollback and private
replacement. The signed executable workflow exercises canned, grant-header and
XML ACLs, distinct anonymous/authenticated findings, aggregation and SQLite
restart. Evidence: `/tmp/stackd-guardduty-2527272515/state.db` and
`testdata/integration/guardduty_executable.json`.

Bucket-policy evidence uses S3's shared resource-policy parser and IAM's
action/resource language solver. Universal-principal allows, unconditional or
conditioned only on literal `aws:SecureTransport`, `aws:PrincipalAccount` and
`aws:PrincipalIsAWSService` comparisons, can prove
`ListBucket`, `GetObject`, `GetObjectVersion` or `PutObject` permissions.
Explicit denies subtract from the same action/resource pair, including wildcard,
`NotAction`, `NotResource` and anonymous-applicable `NotPrincipal` selectors.
Object witnesses require nonempty valid Unicode keys within 1024 UTF-8 bytes;
the solver does not substitute a guessed representative key.

The shared IAM condition interpreter evaluates HTTP and HTTPS independently;
allows and denies must agree on the same transport and action/resource pair.
The [AWS transport context key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-securetransport)
is present and single-valued. Anonymous
[`aws:PrincipalAccount`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalaccount)
is the literal `anonymous`;
[`aws:PrincipalIsAWSService`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-principalisawsservice)
is absent, not `false`. Shared IAM evaluation preserves `Bool`, `BoolIfExists`
and `Null` semantics. Neither the writer's identity nor its transport constrains
this permission proof. Other conditional and variable-resource allows provide no
proof. Other conditional denies are conservatively unconditional;
variable-resource denies conservatively cover all selected resources.
Unsupported parser features provide no proof rather than rejecting an admitted
source mutation. No proof does **not** mean private. Other conditions, variable
reasoning, additional unsigned operations and authenticated audiences remain
open; this is not AWS Zelkova equivalence or
proof of object existence, ownership, encryption compatibility or effective
access after Block Public Access. See the
[AWS grant finding definition](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#policy-s3-bucketanonymousaccessgranted).
Native event eligibility and grouping still require calibration.

Memory/SQLite regressions cover atomic policy/finding/journal rollback and
private replacement. The normal executable workflow verified actual unsigned
object bytes after public admission, denied private reads, IAM-denied unchanged
state, action/resource deny coverage, signed finding identity and retained
private policy/finding count across SQLite restart. It also verified exact bytes
under an HTTP-only allow, matching HTTP deny exclusion and denies covering both
transport branches. Principal-condition scenarios verified exact unsigned bytes,
signed-account exclusions, matching account denies, absent-service-key
`Bool`/`BoolIfExists`/`Null` behavior and combined HTTP/principal conditions.
A separate executable smoke verified certificate-checked
HTTPS reads, HTTPS-only/matching-deny/opposite-transport-deny policies, then
restarted the same SQLite state under HTTP and HTTPS. Actual unsigned access
changed with transport while signed SDK finding identity and counts remained
stable. Its evidence is `/tmp/stackd-guardduty-transport-120310088/evidence.json`,
retained under `transport_listener_smoke` in the shared fixture. Main smoke evidence:
`/tmp/stackd-guardduty-483164918/state.db` and
`testdata/integration/guardduty_executable.json`. Targeted transaction race checks
passed. The full race-instrumented smoke exceeded its existing three-minute
deadline during IP-list setup before this scenario; it is not passing evidence.

Password-policy detection implements the documented change-attempt condition,
not a comparison with the previous password policy or a private risk model.

The source API event, observed finding and pending publication commit in the same
memory/SQLite transaction. CloudTrail delivery selectors do not gate detection:
no customer trail is required for root-usage detection. The observer checks
detector status and the recorded partition/account/region at that boundary.
Calls made while disabled, before detector creation or in another scope do not
become findings later. There is no historical scan or second polling checkpoint.

Observations use typed SQL columns, not sample templates or generic JSON resource
blobs. They retain actual identity, API, outcome, source IP, affected resource and
event ID; geographic/threat-intelligence details are not invented. A deterministic
key groups rule, detector, caller, API, origin and target. Repeated activity
increments the retained count and replaces the projected evidence with the latest
outcome, including errors; suppression and publication use the existing finding
lifecycle. The latest source event is the publication's causal parent.
This local aggregation policy is not a claim about AWS's internal grouping key.

## Native EKS audit detection

`EKS_AUDIT_LOGS` consumes actual Kubernetes audit metadata and admitted RBAC
binding evidence independently of customer CloudWatch logging. This matches the independent source described in
the [AWS EKS auditing guide](https://docs.aws.amazon.com/eks/latest/best-practices/auditing-and-logging.html).
The EKS owner fences cluster incarnation and supplies AWS scope. Journal admission,
finding state and publication intent commit atomically; durable
scope/cluster/audit-ID/stage deduplication also covers disabled-period traffic.
Re-enabling protection does not replay that traffic.

The current predicates implement these observable subsets of the
[documented EKS findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html):

| Finding | Local predicate |
| --- | --- |
| `Execution:Kubernetes/ExecInKubeSystemPod` | Completed successful exec of a named `kube-system` pod; includes HTTP 101 stream upgrades. |
| `CredentialAccess:Kubernetes/SuccessfulAnonymousAccess` | Successful anonymous get/list/watch of core secrets. |
| `Discovery:Kubernetes/SuccessfulAnonymousAccess` | Successful anonymous reads of explicitly enumerated built-in inventory resources or `/api` and `/apis` discovery roots. |
| `Impact:Kubernetes/SuccessfulAnonymousAccess` | Successful anonymous delete/deletecollection of explicitly enumerated built-in resources. |
| `Policy:Kubernetes/AnonymousAccessGranted` | Successful native RBAC v1 RoleBinding/ClusterRoleBinding creation whose admitted response binds User `system:anonymous` or Group `system:unauthenticated`; server dry runs are excluded. |
| `CredentialAccess:Kubernetes/MaliciousIPCaller.Custom` | Core secrets get/list/watch from an active custom threat-list source, including denied requests. |
| `Discovery:Kubernetes/MaliciousIPCaller.Custom` | Enumerated built-in inventory reads and `/api`/`/apis` discovery from an active custom threat-list source, including denials. |
| `Impact:Kubernetes/MaliciousIPCaller.Custom` | Enumerated built-in delete/deletecollection APIs from an active custom threat-list source, including denials; not a claim of completed deletion. |

All require `ResponseComplete`. Failed requests do not match the successful-access,
exec or binding rules; custom-threat rules retain actual denied outcomes.
Health/version requests, authenticated callers for `SuccessfulAnonymousAccess`,
arbitrary custom API groups and non-system pod exec do not match those rules.
Effective impersonated identity is retained
separately from its actor. Findings project actual cluster identity, Kubernetes
user/groups, API path, verb, status and source IP; they do not invent pod specs,
geolocation, network reputation or sample fields. SQL observations reference
immutable native audit rows and retain ordered groups across restart.
Custom threat matches use the existing scoped, active public-IPv4 interval owner
inside the audit-admission transaction. Matching trusted entries suppress new
occurrences, never retained history, following the
[documented list precedence](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html).
Matching threat-list names survive list changes and restart in typed SQL child
rows and project as `Service.Evidence.ThreatIntelligenceDetails`. No external
reputation is invented. The explicit API subsets and EKS list precedence are
primary-documentation-based, not calibrated against native AWS findings; remaining
defense-evasion/persistence tactics and AWS-private classification remain open.

For binding creation only, the native audit policy records `RequestResponse`;
the security projection keeps the admitted role reference and ordered subjects,
not arbitrary object bodies or request claims. These fields occupy typed SQL
columns and ordered child rows and appear in finding `AdditionalInfo`.
Binding creation with `generateName` uses the actual name from the response when
the audit object's name is empty. Failed, ordinary-subject, update/patch/delete,
custom-group and server-dry-run bindings do not produce anonymous-grant findings.

Delete/deletecollection uses `Request` audit level to retain effective
`DeleteOptions`, not the deleted resource body. The security projection stores
`delete_options_observed` and `dry_run`; finding `AdditionalInfo.deleteOptions`
distinguishes observed options from older metadata-only events. A nonempty body
overrides URI options, matching the
[Kubernetes delete handler](https://github.com/kubernetes/kubernetes/blob/v1.33.3/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go).
Thus `dryRun=All` in the URI does not establish a dry run when a body was supplied.

The Impact rule reports successful anonymous **API access**, not proof of object
deletion. Dry-run access retains its actual options and may leave the object
untouched. Native AWS GuardDuty dry-run eligibility remains uncalibrated; the
local rule does not invent a dry-run exclusion from object survival.

Metadata cannot establish malicious workload configuration, RBAC privilege
changes, policy-dependent tactics or private anomaly models. Those predicates
and native AWS event eligibility/grouping calibration remain open; these five
rules do not establish complete EKS Protection.

The [retained native-runtime workflow](../testdata/integration/guardduty_eks_executable.json)
passed against a race-instrumented executable and real k3d v5.8.3:
system-pod exec reached count four through feature/detector gates and controller
restart; anonymous dummy-secret read, pod listing and ConfigMap deletion each
produced its corresponding finding. Signed Go SDK reads checked source-derived
identity, groups, URI, object, verb, status, IPs and user agent. Non-system exec
did not match, disabled periods did not replay, the pod UID survived restart and
CloudWatch logging remained disabled.

The [native binding workflow](../testdata/integration/guardduty_eks_binding_executable.json)
also passed on the race-instrumented executable. Native RoleBinding,
ClusterRoleBinding and generated-name creation retained actual role references
and ordered subjects. Ordinary-subject, RBAC-denied and server-dry-run creates
produced no grant findings. The Go SDK checked all seven EKS findings across five
types after SQLite/controller restart; recreating the same named binding advanced
its existing finding to count two. Native grant revocation, authentication
restoration and exact-owned cleanup passed.

The [retained audit-policy workflow](../testdata/integration/guardduty_eks_audit_policy_executable.json)
passed against the race-instrumented executable. It first proved that an unchanged
policy does not restart the API server. It then installed a genuine metadata-only
policy, observed a binding without a response body, and restarted the controller
with the old policy stamp absent. Reconciliation restored request/response audit
without replacing the server or either pod; a new binding advanced the existing
grant finding. Readiness checks used the authenticated Kubernetes proxy, not
retained `ACTIVE` status alone.

Actual anonymous DELETE requests proved body-over-query precedence, dry-run
object survival, and immutable option flags across SQLite restart. Signed Go SDK
reads verified eight findings across five types, including effective deletion
options. This proves the local successful-access rule, not native AWS dry-run
eligibility. Authentication restoration and exact-owned cleanup passed.

The smoke temporarily enables anonymous authentication only on its exact-owned
loopback control plane, grants narrowly scoped RBAC, then revokes the grant and
restores the original authentication behavior. Credentialless access returned
401 after restoration. This is a test fixture, not a production authentication
change. All owned cluster, detector, IAM and network resources were removed.
The retained evidence records corrected prerequisite failures rather than
presenting earlier attempts as successful.

Run with Python `boto3`, AWS CLI, kubectl, Go, Docker, the pinned k3d and the
runtime's pinned images available:

```sh
python3 scripts/guardduty_eks_smoke/main.py \
  --binary /path/to/stackd --k3d /path/to/k3d-v5.8.3 \
  --evidence /tmp/guardduty-eks-evidence.json
```

The [custom-list workflow](../testdata/integration/guardduty_eks_threat_lists_pinned.json)
ingests actual S3 list bytes and performs real authenticated Kubernetes secrets
reads, pod discovery, deletion and a denied impersonated secrets request.
The signed Go SDK verifies four findings across three types after controller/
SQLite restart. Trusted precedence survives restart; deactivation/reactivation
resumes occurrence counting without replaying suppressed requests. Unmatched and
private sources do not match. CloudWatch logging stays disabled, and all
exact-owned native resources are removed.

The native loopback requests use `X-Forwarded-For`; Kubernetes itself records the
public source, and the current security projection retains its first source IP.
This tests audit-metadata processing, not Internet-origin attribution or complete
multi-hop source projection. The first attempt's
[pinned-tool prerequisite failure](../testdata/integration/guardduty_eks_threat_lists_executable.json)
is retained separately, not reported as a successful detection run.

```sh
python3 scripts/guardduty_eks_smoke/threat_lists.py \
  --binary /path/to/stackd --k3d /path/to/k3d-v5.8.3 \
  --evidence /tmp/guardduty-eks-threat-lists.json
```

## Complete finding target

[guardduty-findings.json](guardduty-findings.json) preserves all **204 distinct
types** from `clones/aws-guardduty-findings-directory/findings.json`, including
resource, source, severity and service metadata. It pins the upstream revision
and SHA-256. `make generate-guardduty-findings` regenerates it;
`make generate-guardduty-findings-check` checks exact bytes. Regeneration needs
the reference clone; reading the versioned inventory does not.

The AST declaration scan currently finds 21 named types and 183 without local
predicate declarations. Neither a string declaration nor a sample establishes
detection behavior. All 204 remain implementation targets.

| Catalog source family | Current source owner and missing boundary |
| --- | --- |
| CloudTrail management/S3 data | Transactional API journal exists. Remaining anomaly baselines, reputation feeds, console sign-in and credential-location evidence are missing. |
| DNS | EC2 dnsmasq exists; query capture and a typed detection consumer do not. Hosted-zone answers are not resolver telemetry. |
| VPC flow | EC2 TAP counters exist; five-tuple/action flow records and detection windows do not. |
| EKS audit | Native admission feeds the typed journal, metadata/anonymous RBAC rules and three custom-threat API subsets independently of Logs. Pod-spec/privilege-policy context, external reputation, remaining custom tactics and anomaly classification are missing. |
| Lambda network | Function VPC attachment and network-flow capture are missing; source-poller networking is not function telemetry. |
| Runtime Monitoring | Real process/file/socket instrumentation for EC2/EKS/ECS is missing. Container inspect and platform logs are not runtime detection. |
| EBS malware | Snapshot blocks exist; filesystem scanning and attachment identity need a real scanner. |
| Backup malware | Backup/recovery-point ownership and scanning are missing. |
| S3 malware | Object bytes exist; scanner and committed scan jobs are missing. |
| RDS login | Native engines exist; authentication outcome capture and detection baselines are missing. |
| AI Protection | Bedrock invocation ownership and telemetry are missing. |
| Attack sequences | Stateful correlation and constituent source detections are missing; one API event is not an attack sequence. |

## Finding retention

Findings have a 90-day creation-based cap, measured by the shared service clock.
At the exact deadline, Get/List/Statistics exclude the finding even if the
scheduler has not swept its row yet. Archive rejects expired IDs; feedback
preserves the existing missing-ID behavior without reviving expired state.
Aggregation, feedback and archival do not extend the cap.

The existing transactional scheduler deletes active, archived and suppressed
findings, including observation child rows. Pending occurrences are not published
after expiry. Deadlines are reconstructed from retained timestamps on restart;
a stale selected job cannot expire a newer replacement before its own deadline.
New samples after expiry start with a new ID and count, without old feedback.
Existing journal records and already-admitted EventBridge events have independent
lifecycles and are not removed by finding expiry.

AWS documents a maximum retention of 90 days, but the cited documentation does
not specify whether the native deadline uses creation or the latest occurrence.
The creation-based cap is a conservative local contract, not native calibration.
That timestamp anchor and native refreshed-finding expiry remain open.



## Sources and evidence

Contracts come from the pinned Go SDK Smithy model; the native fixtures record
revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a` and model SHA-256
`4675cc38456fc0bdb85bd612cae1c7e3a24feed05ca19ecdb8eb71d35312270b`.

Primary references:

- [Detector creation](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateDetector.html)
- [Explicit sample findings](https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html)
- [Filter criteria](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateFilter.html)
- [Finding statistics](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindingsStatistics.html)
- [Finding events and suppression](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html)
- [Service-linked role](https://docs.aws.amazon.com/guardduty/latest/ug/using-service-linked-roles.html)
- [IAM finding conditions](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [S3 finding conditions and resource types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#stealth-s3-serveraccessloggingdisabled)
- [S3 account public-access-block settings](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PublicAccessBlockConfiguration.html)
- [S3 Protection source, authentication and regional boundaries](https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html)
- [Finding retention quota](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_limits.html)
- [Finding aggregation and latest occurrence](https://docs.aws.amazon.com/guardduty/latest/ug/finding-aggregation.html)
- [IP list formats and detection precedence](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html)
- [List role, S3 and KMS prerequisites](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-lists-prerequisites.html)
- [Custom malicious-IP reconnaissance](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#recon-iam-maliciousipcallercustom)
- [Custom IAM unauthorized access](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-maliciousipcallercustom)
- [Custom S3 discovery](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#discovery-s3-maliciousipcallercustom)
- [Custom S3 unauthorized access](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html#unauthorizedaccess-s3-maliciousipcallercustom)
- [IAM predefined literal variables](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
- [IANA special-purpose IPv4 registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [Finding exports and S3/KMS policies](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html)
- [Publishing destination creation](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreatePublishingDestination.html)

`testdata/aws/guardduty/` retains lifecycle, sample corpus, identity transitions,
filter/query and statistics captures, including interrupted attempts and cleanup
failures. Criteria visitors and sample identity traversal are generated from the
typed model. The documented selector allowlist includes 26 paths absent from the
pinned Finding shape; generation reports them and those paths remain unsupported.

Local executable verification:

```sh
go build -o /tmp/stackd-guardduty ./cmd/stackd
go run ./scripts/guardduty_smoke /tmp/stackd-guardduty
```

The signed Go SDK v2 workflow proves IAM denial/no orphan, conditional linked-role
admission, current resource-tag revocation, account/region isolation, all 444
sample variants, pagination, repeat/archive/feedback, suppression state,
statistics, role deletion dependencies, SQLite restart and cleanup. It also
exercises long-term root use, temporary-root IAM denial, named trail changes,
associated bucket deletion and S3 server-access logging enable/deny/disable
requests. Bucket/account public-access-block checks cover fully enabled settings,
denied changes, successful partial disable, omitted-setting reset and deletion.
Password-policy checks cover update aggregation, denied update/delete without
mutation, successful deletion and a subsequent missing-policy attempt retaining
the same finding identity with its latest audit error. Real S3 object reads prove
source enable/disable, rollback of a combined S3/unsupported-feature update, no
disabled-period replay, and retained source configuration and aggregation across
SQLite restart. Rule regressions exclude unauthenticated S3 data requests.
The list workflow exercises real private S3 ingestion, missing-source/owner
errors, current IAM/S3 denial and recovery, child-ARN/tag authorization, quotas,
pagination, retained ACTIVE state and cleanup across SQLite restart. Ingestion
creates real role sessions: the smoke verifies IAM deletion rejection while
sessions are active, then advances the shared clock to verify expiry and deletion.
An additional signed-SDK HTTP smoke injected connection addresses at the handler
boundary to exercise trusted precedence, retained threat evidence, explicit
snapshot reingestion, KMS-encrypted objects, current KMS denial/recovery and a
literal wildcard object key. This is not evidence of actual public-network traffic.
A separate manual-clock executable verifies the creation-based retention cap,
refreshed occurrences, archival/feedback, exact Get/List/Statistics boundaries,
regional isolation, saved-clock restart and fresh sample state. Memory/SQLite
regressions cover pre-sweep visibility, stale-job fencing, publication cutoff and
durable observation-child deletion.
It verifies aggregation, disabled-period exclusion and retained observation
identity after restart. Both sample and observed findings
reach SQS through EventBridge. Memory/SQLite regression checks cover source-event
rollback, suppression and partition/account/region isolation. See
`testdata/integration/guardduty_executable.json` for observed verification.

Local delivery is not native event conformance. Both disabled and enabled-core
native captures received zero finding events within their 300-second bounds.
That does not prove that AWS never delivers those events. The publisher follows
the documented envelope and GetFindings-shaped detail; native timing, export
eligibility and complete payload equivalence remain uncalibrated.

Native cleanup removed the probe detectors, rules and queues. The exact-owned
service-linked role remained after three terminal AWS deletion failures reporting
an internal error with no listed role usage. An October 3 shutdown retry returned
the same terminal failure. Detectors were absent in 32 accessible enabled Regions;
the `me-south-1` inventory could not be established because both standard and
dual-stack endpoints were unreachable. The enabled-event and earlier cleanup
investigation fixtures preserve the unresolved role; cleanup must not be
reported as complete.

## Remaining work

- Extend the explicit API rule inventory and source producers. Current rules
  cover root credentials, password-policy attempts and the listed logging,
  public-access-block, bucket ACL and bounded anonymous bucket-policy changes,
  not all GuardDuty finding types or private anomaly models. Extend conditional,
  variable-resource and authenticated-audience policy reasoning.
  Enabled S3 data events feed the implemented predicates only.
- Actual DNS and network-flow telemetry ingestion. An API event consumer alone
  cannot observe queried domains or network traffic.
- Optional EKS/RDS/Lambda sources, runtime/agent management, malware scanning
  and AI protection, with real owners and effects.
- Organizations/administrator/member workflows, invitations, trusted/threat
  entity sets, malware protection plans, investigations and custom detection
  rules. Their modeled operations return errors.
- Native S3 export payload/batching, object naming, failure/retry timing and
  concurrent destination-replacement errors.
- Native retention timestamp/refresh calibration, broader native edge semantics,
  missing model selectors and native event calibration.

Exact code markers: `internal/services/guardduty/service.go` (monitoring and
remaining operation owners), `features.go` (optional protections),
`retention.go` (native deadline anchor), `generatecriteria/main.go`
(documented selectors missing from the typed model), `destinations_outbox.go`
(native export batching/naming/retry calibration), `destinations_control.go`
(native concurrent-replacement error), `detection_s3_grants.go` (conditional and
authenticated-audience policy grants), `internal/services/s3/anonymous_policy.go`
(unsupported parser features, other conditional/variable allows,
additional audiences and unsigned operations, variable-resource denies and
other conditional denies).
