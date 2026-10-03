# Organizations member account access

`CreateAccount` now creates the ordinary IAM role that the management account
uses to access its new member. The default is `OrganizationAccountAccessRole`;
`RoleName` selects a custom name. The role has path `/`, maximum session duration
3,600 seconds, trust in the management account's root ARN and an attachment to
the captured AWS-managed `AdministratorAccess` policy.

The caller needs `organizations:CreateAccount` and, when supplying tags,
`organizations:TagResource`. Initial role provisioning is a trusted Organizations
operation and does not require the caller's `iam:CreateRole` or
`iam:AttachRolePolicy` permissions in the member. Management-account IAM users
still need `sts:AssumeRole` to use the resulting role. Other accounts do not gain
access. Its sessions use the member account's current policies and SCPs, and the
role remains customer-manageable through ordinary IAM operations.

Organization creation and member provisioning also install
`AWSServiceRoleForOrganizations`, using its captured trust, description and
`AWSOrganizationsServiceTrustPolicy` attachment. An existing owned service role
is reused without changing its identity or description. Creating a missing role
in the management account requires `iam:CreateServiceLinkedRole` for the role ARN
and `iam:AWSServiceName = organizations.amazonaws.com`; missing permission yields
`AccessDeniedForDependencyException`. Member provisioning does not add this IAM
permission requirement to the management caller. See
[service-linked role ownership and deletion](iam-service-linked-roles.md).

Member creation copies the management account's stored primary contact, replacing
`FullName` with the requested account name. Alternate contacts are not copied.
Later updates to either account remain independent. The Account provider owns
this typed state and initializes it in the same transaction as membership and
IAM roles. If the management account has no local primary contact, creation does
not invent one; bootstrap initialization remains an explicit gap. See
[contact behavior and AWS evidence](account-contacts.md).

## Transaction ownership

`CreateAccount` validates and authorizes the request, reserves an account ID and
commits a typed `IN_PROGRESS` job. Its initial generated response contains the
request ID/name and requested timestamp; account ID, completion timestamp and
failure reason are absent. Invalid requests and failed admission commits leave
no job or consumed ID. At most five creations can be in progress per organization.
A pending duplicate email receives `ConcurrentModificationException`. An email
already registered in the partition fails asynchronously with `EMAIL_ALREADY_EXISTS`.
Deleting an organization while creation is pending is rejected as a concurrent
modification, so the accepted request cannot lose its parent organization.

The shared scheduler makes jobs due after one service-time second. This is a
modeled pending window, not an AWS completion guarantee or measured success latency.
`DescribeCreateAccountStatus` and `ListCreateAccountStatus` only read state.
Membership, parent/default policies, tags, initial IAM roles, copied primary contact
and terminal success commit together with a typed journal event. Acceptance and
terminal failure also append with their job transition. Events retain the
originating request ID, region and caller after recovery; they omit account
names, emails, tags and policies. See [the journal contract](event-journal.md).
IAM also records the account creation date in this transaction so later Account/IAM reads do not initialize it at read time.
The assembled `AccountProvisioner` composes
IAM and Account initialization with the Organizations revision check inside one
authority transaction. Revision conflicts
retry from current state. Storage failure or cancellation rolls back completion
and preserves the accepted job for retry. A permanent role conflict returns a
terminal `INTERNAL_FAILURE` without changing the existing role or publishing a
partial member. Completed timestamps use the worker's service time and retain
presence at both Go's zero instant and the Unix epoch.

Pending jobs recover when a stack opens retained backends, including jobs due
while the previous stack was closed. Closing joins provisioning before closing
IAM. Completed jobs do not run again. This is reconstruction recovery with the
memory backend; SQLite retains state and event history across process exits.
A subprocess test interrupts publication after the event insert, then verifies
that only the accepted intent survives and recovery emits one completion.
Request history has no invented expiry. The pending quota is separate from
total-account quotas and request throttling.

`storage.NewMemory` provides this shared domain. Replacement backends must join
Organizations and Account writes to IAM's transaction context. A standalone Organizations
provider without an IAM provisioner rejects organization/account creation with
`ServiceException`. Missing partition-specific templates or managed-policy data
reject unsupported organization creation without publishing membership. GovCloud
consolidated billing mode is rejected with its documented constraint reason.

## Account quotas

An organization defaults to ten accounts. The management account and suspended
or closed members count toward the limit. `CreateAccount` rejects a full
organization with `ConstraintViolationException` and reason
`ACCOUNT_NUMBER_LIMIT_EXCEEDED`, leaving no job or allocation. Accepted requests
compete for remaining capacity at completion: a job that can no longer create
its member becomes `FAILED / ACCOUNT_LIMIT_EXCEEDED`, without an account ID or
partial IAM roles. The revision check keeps membership and initial role
publication atomic with this capacity decision.

Use `Config.OrganizationAccountQuotas` to match a specific applied AWS quota:

```go
stackd.Config{
    OrganizationAccountQuotas: []stackd.OrganizationAccountQuota{
        {Partition: "aws", ManagementAccountID: "000000000000", Maximum: 5000},
    },
}
```

The CLI equivalent is `-organization-account-quota aws/000000000000=5000`.
Repeat the flag for other scopes. Overrides are global across regions and
isolated by management account and partition. Validation rejects duplicate scopes,
invalid account/partition syntax and limits outside 1–50,000. Unspecified scopes
use the default. The constructor detaches caller configuration; keep the intended
overrides when reopening retained backends.

Quota changes take effect on reconstruction. Decreases never remove existing
members or roles; they block further creation and can fail a recovered pending
job. Increases permit new requests without rewriting completed failure history.
This operator configuration does not implement the AWS Service Quotas APIs.
Pending invitations and permanent account closure need their own lifecycle
implementation before quota reservations can include those transitions.

## AWS evidence and verification

Primary contracts:

- [CreateAccount API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html):
  default/custom access roles, required permissions and account initialization.
- [Accessing an Organizations-created member](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access-cross-account-role.html):
  management-account trust and caller assumption permissions.
- [Creating the equivalent role in an invited account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create-cross-account-role.html):
  trust and administrator permission configuration.

`scripts/aws/organizations_roles_probe.py` assumed the default access role
in an existing active Organizations-created member and read its IAM role,
attachments, inline-policy names and STS identity, plus management/member service
roles. The normalized capture is
`testdata/aws/iam/organizations_roles.json`. It records the capture time and
comparison limits. No resources or policies were created or changed; the short
STS session was kept in memory. The read itself updates ordinary AWS usage history.
An existing role may have been edited since creation, so this capture does not
establish fresh provisioning timing, billing-mode provisioning or every
CreateAccount/CreateOrganization side effect.

The SDK integration tests replay those role fields and exercise assumption,
actual member administration, caller permission denial, cross-account denial,
current SCPs and attachment revocation. Custom-name coverage follows the API
contract. Fault injection exercises each store's publication and IAM cancellation;
concurrent duplicate-email requests must publish a single usable role.
Organizations package tests isolate domain behavior with an explicit provisioning
test double; they do not establish IAM behavior or cross-store atomicity.

`scripts/aws/organizations_account_creation_probe.py` submitted two simultaneous
requests using the active management account's already registered email. The
capture in `testdata/aws/iam/organizations_account_creation.json` records an
`IN_PROGRESS` response, a `ConcurrentModificationException` for its duplicate,
and terminal `FAILED / EMAIL_ALREADY_EXISTS` through both describe and list.
Pending output omits the account ID and completion timestamp; failed output
includes completion time and the reason, with no account ID. The organization
account set was unchanged. AWS retains these failed request-history records;
there is no deletion API for them. An earlier interrupted capture also left one
failed existing-email request, without creating an account.

The capture's requested timestamp changes between submission and terminal reads;
the emulator currently retains the admission timestamp. This discrepancy is
recorded rather than assigning an unsupported fixed timestamp adjustment.
The fixture replay checks states, field presence, failure reasons and list
projection. It does not claim successful creation or timing parity. Pending quota
coverage follows the [Organizations quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)
and [creation status contract](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccountStatus.html).
SDK tests also exercise paused-time reads, pagination, organization isolation,
quota release, admission/completion failures, cancellation, reconstruction and
preservation of a conflicting customer role.

`scripts/aws/organizations_quotas_probe.py` reads AWS Service Quotas in
`us-east-1`, recording the default and applied maximum-account quota in
`testdata/aws/iam/organizations_quotas.json`. The capture returned default 10 and
applied 5,000, confirming that using only the published default would fail to
represent this real organization. No quota requests, resources or settings were
changed. These reads establish quota values and scope, not the precise timing or
error precedence of concurrent creation at the live limit. Those limit tests
follow the published Organizations quota and creation-status contracts; no
thousands-account live experiment was performed.

## Remaining account creation work

AWS account initialization can outlast reported success. Post-success usability,
account billing access, native Service Quotas integration, invitation quota
reservations, request throttling and broader creation failure/timestamp conformance
remain required. Billing access needs a
real enforcing consumer. These gaps remain marked at `createAccount`.
China/GovCloud policy catalogues are also still required. Neither IAM nor
Organizations is complete.
