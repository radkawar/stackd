# IAM last-access reporting

`GenerateServiceLastAccessedDetails`, `GetServiceLastAccessedDetails`,
`GetServiceLastAccessedDetailsWithEntities` and
`ListPoliciesGrantingServiceAccess`, `GenerateOrganizationsAccessReport` and
`GetOrganizationsAccessReport` use generated SDK input/output contracts,
current policy relationships and actual authenticated API activity.
IAM remains incomplete; see the [completion audit](iam-completion.md).

## Activity and report lifetime

The gateway records recognized, authenticated API attempts before input validation,
session restrictions and service authorization. Denied requests count. Invalid
signatures and unsigned federation calls have no verified AWS caller to record.
SQS's actual KMS calls record KMS activity too; a queue data-key cache hit does not
invent a KMS call, and a permission dependency such as `iam:PassRole` is not an
API invocation.

Gateway authentication owns signature, credential status and expiry validation.
Activity consumers trust its principal metadata, including metadata retained by an
accepted background task. They do not reauthenticate a task after its initiating
session expires. Credential-use bookkeeping and principal activity commit in one
IAM repository transaction. Missing credential rows do not erase accepted work;
actual repository failures stop the request before service effects. Activity is
independent of the access-key report's 15-minute coalescing rule.

Typed activity rows retain the latest attempt per immutable principal ID, service,
action and region, within account and partition scope. Role sessions attribute
activity to their IAM role; user federation attributes activity to its issuer.
Renames preserve identity and replacements cannot inherit deleted principals'
activity. Raw history is retained. New identity/entity/Organizations snapshots use
service activity within `(snapshot time - 400 days, snapshot time]`; older and
future service attempts do not count. Action history is independent of that
rolling window, and completed reports remain frozen. AWS describes service
tracking as [the last 400 days](https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started-reduce-permissions-last-accessed.html)
and elsewhere as at least 400 days. The exact local sub-day boundary is a
convention, not a live observation. AWS action rollout dates do not discard
valid local activity at zero virtual time. No documented JobId expiry was found,
so there is no invented report-pruning job.

Generation freezes the current permission graph, associated entity IDs and
latest committed activity in the accepting IAM transaction. The shared scheduler
makes the snapshot available after one second of service time. This is the local
processing cadence, not an assertion about AWS timing: small captured AWS jobs
took about one second and the all-services job took about eight seconds. AWS's
usual telemetry publication delay, documented as within four hours, is not
reproduced as a fixed delay. Local committed activity is available to the next
snapshot. Tests can advance `Config.Clock` and call `RunDueJobs` without wall-clock
sleeping.

A pending response omits completion date, result lists and job granularity. These
omissions contradict required output traits in the pinned Smithy model. The
response serializer preserves service-owned field presence without applying
request requiredness to outputs; captured AWS response tests cover these cases.
Reads of completed reports
use stored services, membership IDs and usage even after permission or membership
changes. Entity reads resolve current names and paths by those immutable IDs,
omit deleted identities and do not add later members. Service rows remain readable
after deletion of the source resource. Pending work and completed results survive service
reconstruction when the same repository is retained. Memory state does not survive
process termination.

Job lookup is scoped to the account, partition and generating caller. IAM access
keys belonging to the same user share report ownership. Temporary sessions own
their jobs by credential ID, so two role sessions with an identical session name
cannot read one another's report. Unknown jobs and jobs belonging to another
caller return `NoSuchEntity`; ordinary IAM authorization still applies separately.

## Permission discovery

Reports consider user, inherited group, role and managed-policy permissions. They
exclude boundaries, session policies, trust policies, resource policies and
Organizations controls when determining potential service access. Group reports
use the group's policies; policy reports use that policy and its directly or
indirectly associated users and roles. An unattached managed policy still reports
its potential services, with zero authenticated entities.

The two discovery APIs have different observed contracts:

- Service reports enumerate real Service Authorization Reference actions, evaluate
  applicable resource types and combine unconditional explicit denies across
  source policies. They report a service when some action/resource remains
  potentially allowed. Conditions on grants and conditional denies do not establish
  definite restrictions in these reports.
- `ListPoliciesGrantingServiceAccess` considers each source document independently.
  It uses namespace and resource applicability, including unknown action names in a
  known namespace. A broad unconditional whole-service deny over all resources
  suppresses that document's grant. Scoped or individual-action denies do not have
  the same effect in the captured discovery results.

A shared selector parser owns those policy inputs. The reporting resource matcher
checks whether any resource remains after exclusions; it does not guess sample
ARNs. These are permission-discovery contracts, not authorization decisions.
Actual request enforcement retains the separate IAM policy evaluator.

Services sort by namespace. The observed default service page size is 200, despite
AWS documentation saying 100; explicit sizes from 1 to 1000 work. Entity results
sort by descending last-authenticated time, with deterministic ARN ordering for
ties and unused entities. Entity markers bind the job and API but can continue a
different namespace within that job, as the capture demonstrates. Service and
entity markers cannot be interchanged. Policy-discovery namespaces preserve first
request order and remove duplicates; source policy order is deterministic locally
but varied between AWS observations.

Action-level reports use AWS's published `IAM Action Last Accessed` metadata.
Data-plane classification alone is insufficient: some KMS cryptographic actions
are tracked, while SQS message operations and S3 object reads are not. Services
with no eligible tracked actions omit the action list. Never-used services and
entities omit activity dates rather than inventing an epoch.

## Organizations reports

Organizations owns current management-account membership, enabled SCPs, exact
entity paths and the selected account hierarchy. IAM owns report authorization,
jobs and activity aggregation. Its transaction context keeps Organizations reads
in the same memory domain as IAM's report snapshot and activity aggregation.
Independent organization changes cannot interleave with that accepting transaction.
Replacement backends must retain the shared boundary.

Root and OU reports consider the selected entity's SCPs and ancestors, without
intersecting each descendant account's extra restrictions. Accounts contribute
their authenticated attempts, including denials. Management-account activity is
excluded from those reports. A report specifically targeting the management
account includes all catalogued services and only that account's activity.
The optional policy ID is ignored for that target.

An explicit SCP selects its own potential services. Its account data is limited
to attachments at or below the selected entity; an unattached policy still
reports services with no activity. The shared permission selector unions allows
within each SCP level and intersects levels on the same action and resource.
Disjoint resource grants cannot combine into access. Unconditional denies apply
across levels, while conditions retain the captured potential-access behavior.
Cancellation reaches the resource-language traversal.

`TotalAuthenticatedEntities` counts distinct accounts, not users or sessions.
The latest attempt supplies an account path, timestamp and region. Generation
freezes these values, so moving an account or changing an SCP does not rewrite
the report. Never-used rows omit activity details; AWS nevertheless supplies
`us-east-1` for an unused IAM row. The generated default-region metadata preserves
that observation without inferring a rule from global endpoints.

IAM enforces the `access-report/<EntityPath>` resource ARN and
`iam:OrganizationsPolicyId` condition key. Missing Organizations read permissions
produce an accepted job that later reports `FAILED` with
`ORGANIZATIONS_REPORT_ACCESS_DENIED`. Missing entities, trailing-slash paths and
missing policies similarly become typed job failures. A different organization
ID is an immediate `AccessDenied`. Invalid shapes use generated validation.
Completed job reads require their IAM permission and current management/SCP
eligibility; removing Organizations read permissions does not hide the result.
User keys share ownership, while another authorized user cannot read the job.

Recent identical owner/path/policy requests reuse a job, including its failure.
The local reuse interval is one minute from creation, using service time; source
changes become visible in a newly generated snapshot after that interval. Older
job IDs remain readable. The same repository transaction owns lookup and
insertion, so concurrent identical requests publish one job.
The emulated generation limit follows the observed account: one Organizations
report may be in progress per account, across callers;
another selection receives modeled `ReportGenerationLimitExceeded` (409).
Completion releases the slot. Live controls observed reuse at 59 seconds and
fresh generation at 61 seconds; a separate idle-account test observed the
single active-job limit and successful generation after completion.

Organizations pages default to 100 services. All four namespace/time sorting
options are supported, with full-report accessible/unused counts on every page.
Continuation markers bind the job and sort key; the page size may change.
The full 455-service and three-service captures preserve the same relative order
among absent timestamps. Their observed rank is generated from the same service
metadata projection and breaks timestamp ties. Descending sorts reverse it;
namespace sorts continue to use alphabetical order.

## Sources and verification

Primary contracts:

- [GenerateServiceLastAccessedDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateServiceLastAccessedDetails.html)
- [GetServiceLastAccessedDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetServiceLastAccessedDetails.html)
- [GetServiceLastAccessedDetailsWithEntities](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetServiceLastAccessedDetailsWithEntities.html)
- [ListPoliciesGrantingServiceAccess](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPoliciesGrantingServiceAccess.html)
- [Action-last-accessed coverage](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed-action-last-accessed.html)
- [Machine-readable service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)
- [GenerateOrganizationsAccessReport](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateOrganizationsAccessReport.html)
- [GetOrganizationsAccessReport](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetOrganizationsAccessReport.html)
- [Organizations report permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_iam_service-accessed-data-orgs.html)

`testdata/aws/iam/last_access.json` contains 294 observations from owned IAM
resources, including permissions, conditional/scoped denies, pending field
presence, snapshot timing, pagination, ownership, source deletion and cleanup.
`testdata/aws/iam/last_access_service_names.json` retains the earlier 455-name
capture from a fresh unattached allow-all policy; 14 names differ from the SAR
labels. Both captures verify resource cleanup. The probe's explicit phases are
available through `python3 scripts/aws/iam_last_access_probe.py --help`;
`--account YOUR_12_DIGIT_ACCOUNT_ID --phase names --output .stackd/probes/iam/last_access_service_names.json` refreshes display
names using a temporary policy. The current production source for both service
names and default regions is the single `services` projection in
`testdata/aws/iam/organizations_access.json`, captured from all 455 unused rows
in an owned empty OU. `scripts/aws/iam_organizations_access_probe.py` captures
288 Organizations selection, ownership, failure, authorization and pagination
observations, with 106 cleanup/removal records and verified cleanup. Fresh policy IDs isolate selector changes from
AWS's report reuse and Organizations policy propagation; the earlier rapid
update observations are retained as evidence of that distinction.

`python3 scripts/aws/iam_service_reference.py` refreshes the public AWS snapshot
in `internal/iam/catalog/data/service_reference.json.gz` without credentials.
The same source owns action/resource conditions, ARN alternatives and last-access
tracking. `make generate-iam` generates action tracking and display-name
lookups alongside the permission catalogue. Normal builds need neither reference
clones nor network access; native generation checks detect drift.

SDK tests exercise activity through signed HTTP requests, denied calls, nested
SQS/KMS work, snapshot transitions, caller isolation, rollback, reconstruction and
fixture-derived permission results. Immediate live probes did not wait four hours
for AWS activity publication, so those local activity integration tests are not a
claim that the publication cadence has been differentially verified.

These fixtures and passing cases do not close the broader IAM semantic completion audit.
