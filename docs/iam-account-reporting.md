# IAM account reporting

`GetAccountSummary` and `GetAccountAuthorizationDetails` use generated Smithy
inputs and Query responses. Their handlers read the account's typed IAM state
inside the existing IAM transaction. Reports do not change resource records.
Every request still requires its IAM permission, including applicable boundaries,
session restrictions and Organizations controls. Neither operation requires
separate permission for each entity included in its report.

Account scope includes partition and account ID. IAM is global within that scope;
using another signing region does not select another permission graph. A single
response uses one state snapshot. Continuation pages read current state on their
subsequent requests; they do not hold a historical snapshot across requests.

## Counts and quotas

Summary counts come from stored identities, policies, versions, instance profiles,
certificates, providers and virtual MFA devices. AWS-owned policies are excluded
from customer policy counts. Root credential flags use explicitly persisted root
records; local bootstrap signing fixtures and STS sessions are excluded. IAM
user login profiles do not create a root sign-in password. Root recovery has a
separate profile; its summary mapping still needs positive AWS verification, as
recorded in [root access behavior](iam-root-access.md).

`PolicyVersionsInUse` counts distinct managed policies referenced by users,
groups or roles, including permissions boundaries and AWS-owned policies.
An unattached policy or extra retained version does not increase this counter;
multiple references to the same policy still count once. The current customer
policy quota plus the embedded AWS policy inventory is below the reported
10,000 in-use limit; an invariant test checks that bound across catalogue updates.

Reported default quotas share constants with enforcement. This includes 20
managed-policy attachments per role and 10 per user or group. Account-specific
quota increases in a captured AWS account do not change local defaults.
`GlobalEndpointTokenVersion` reports the current account preference, defaulting
to 1. `SetSecurityTokenServicePreferences` changes it; STS observes the change
after propagation. Regional endpoints always issue modern tokens. See
[STS token preferences](iam-sts-preferences.md) for behavior and evidence.

## Permission graph

User details include direct inline/managed policies, group names, boundaries and
tags. Group details include their own policies. Role details include current
rendered trust principals, direct policies, boundaries, tags, instance profiles
and tracked last use. Managed-policy details include metadata, attachment counts
and retained version documents. Nested relationships remain with their parent
entity when the top-level report is paginated.

The policy section includes all customer policies, including unattached ones,
and AWS-owned policies used by an attachment or boundary. It does not enumerate
the entire AWS-owned catalogue. Version documents appear in descending version
ID order, including nondefault versions. Creating any new version updates the
policy's `UpdateDate`, also visible through `GetPolicy`.

AWS omits managed-policy descriptions in this report despite their presence in
the response model and in `GetPolicy`. Empty user inline-policy lists are omitted;
empty group/role inline lists and user/role tags are present. Nested instance
profiles omit tags, and their nested roles contain only identity, creation time
and trust-document fields. Those field-presence differences are tested.
Role history distinguishes an unused role from actual use at the modeled zero
epoch. `GetRole` and authorization details preserve zero/earlier-epoch usage,
reject regression from older usage records and apply the same 400-day cutoff.

Filters select entity types with OR semantics. Duplicate or reordered filter
values describe the same report. Pagination is deterministic and markers are
bound to the partition, account, action and canonical filter set. IAM's declared
`MaxItems` range is 1–1000, default 100. Invalid filters and markers return
`ValidationError`. Policy documents use RFC 3986 URL encoding on the Query wire;
the Go SDK exposes those encoded strings to its caller.

The shared page budget visits users, roles, groups and then managed policies,
regardless of filter order. A marker permits a changed page size or equivalent
filter set, including default versus explicitly selecting all five types; a
different filter set is rejected. Resource ordering within each family is stable
locally; nested attachments, memberships and tags are compared as sets in
conformance tests because their AWS ordering is not established.

## Evidence

Primary contracts:

- [GetAccountSummary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html)
- [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [IAM quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
- [UserDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html),
  [GroupDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GroupDetail.html),
  [RoleDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleDetail.html),
  [ManagedPolicyDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ManagedPolicyDetail.html)

`testdata/aws/iam/account_reporting.json` records sanitized AWS observations,
timestamps, request cases, separate capture runs and verified resource cleanup.
Only owned resource details and selected public policy data are retained;
unrelated account resources contribute aggregate counts only. The probe is
`scripts/aws/iam_account_reporting_probe.py`. It uses explicitly supplied AWS CLI
credentials and creates uniquely named IAM fixtures, then verifies their removal.
Its smaller `--phase summary --preserve` and `--phase pagination --preserve`
modes can append focused observations without repeating policy-history reads.
Normal Go tests replay the committed fixture entirely offline.

SDK graph, validation, authorization, isolation and transaction tests live in
`internal/services/iam/account_authorization_details_test.go`; summary and quota
checks are in `internal/services/iam/account_summary_test.go`. Early-epoch history
is covered in `account_authorization_details_clock_test.go`; exact AWS field
presence and policy content are replayed in
`account_authorization_details_fixture_test.go`. The service remains
incomplete; these operations do not close credential reports, last-access reports,
new account APIs or the full IAM differential audit.
