# Organizations resource-policy delegation

`PutResourcePolicy`, `DescribeResourcePolicy` and `DeleteResourcePolicy` use
generated Smithy bindings and the shared IAM evaluator. Each organization owns
one typed policy record, identified by `rp-…`, with ordinary resource tags.
Creation, replacement and deletion commit with the Organizations graph. Memory
and SQLC-backed SQLite implement the same storage contract; schema migration 9
adds the policy table without changing existing organizations.

Management-account identities need IAM permission to create, replace or delete
the delegation policy. Creating it with tags additionally requires
`organizations:TagResource`. Replacement preserves its ID, ARN and tags; supplying
nonempty tags on replacement fails with
`UPDATE_EXISTING_RESOURCE_POLICY_WITH_TAGS_NOT_SUPPORTED`. Use `TagResource` and
`UntagResource` to change existing tags. Deletion removes the policy and its tags;
recreation receives a new identity. See the
[PutResourcePolicy API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_PutResourcePolicy.html).

Member calls require their own IAM permissions and a resource-side grant.
Boundaries, session policies and the member's SCP hierarchy still apply:

| Caller authority | Resource-side grant | Effect of a matching resource-policy deny |
| --- | --- | --- |
| Organization membership | `DescribeOrganization` | Denied |
| Registered service administrator | The documented Organizations reads, including `DescribeResourcePolicy` | Denied |
| Resource-policy delegation | Actions permitted by the current policy | Denied |
| Management account | IAM authority in its own organization | Delegation policy does not restrict management access |

The shared evaluator models service-owned account grants separately from the
resource policy. It evaluates explicit denials before applying those grants and
records the account grant in its resource-layer explanation.

The management account owns global organization reads, delegation deletion and
AWS-managed Organizations policies for authorization purposes. Their resolved
owner supplies `aws:ResourceAccount`, including when the request selects `*` or
the returned ARN contains the `aws` alias. Member calls therefore retain
cross-account identity/session restrictions even with a wildcard principal.
These rules cover ordinary member descriptions, trusted-administrator listings,
resource-policy deletion and reads of `p-FullAWSAccess`.

Delegation reaches actual operations: policy creation, updates, deletion, tagging,
attachment and detachment use the current policy, resource tags and policy-type
conditions. Attach/detach require permission on both the policy and its target.
Tagged creation requires both IAM and delegated tag permission. A policy change
made by a delegate immediately participates in the existing SCP evaluation used
by other services. Revision conflicts restart authorization before a prepared
Organizations mutation can commit.

## Validation and AWS evidence

The shared policy parser owns JSON, selectors, principals, conditions and wildcard
matching. Organizations supplies its delegation action allowlist and verifies
account membership. Numeric account principals normalize to root ARNs. The
captured contract accepts account, wildcard and service principals, but rejects
IAM role principals and accounts outside the organization. `NotAction`,
`NotResource` and `NotPrincipal` are rejected. AWS's
[delegation guide](https://docs.aws.amazon.com/organizations/latest/userguide/orgs-policy-delegate.html)
records the June 30, 2026 removal of negative action/resource selectors and the
requirement for corresponding member IAM permissions.

Native captures from September 13, 2026 are committed:

- [Lifecycle, syntax and authorization](../testdata/aws/iam/organizations_resource_policy.json):
  9 lifecycle observations, 20 validation cases and 12 enforcement observations,
  including policy revocation, wildcard grants, restrictive STS sessions and
  resource-account conditions.
- [Delegated writes](../testdata/aws/iam/organizations_delegation_writes.json):
  22 observations covering dependent tag permissions, resource-policy tags,
  newer read actions, policy CRUD, target-scoped attachment and deletion.
  Describing a deleted policy with the captured delegated permissions returns
  `AccessDeniedException`; the management root can instead observe its absence.

[The authority capture](../testdata/aws/iam/organizations_delegation_authority.json)
adds 48 observations across 17 Organizations transitions. It verifies ordinary
membership, trusted-service grants, explicit resource-policy denials, current
writes, resource-account conditions and AWS-managed policy access. It confirms
that a registered administrator can describe an absent resource policy and
receive `ResourcePolicyNotFoundException`.

Three grant/revoke cycles returned the new decision on every sample. The first
responses completed 0.671–0.726 seconds after the successful policy update;
subsequent samples remained consistent. These are observed end-to-end probe
intervals, including signing/transport overhead, not a propagation SLA or a fixed
service delay. Local authorization reads committed policy state on subsequent
requests without advancing service time.

The captures also resolve documentation gaps: AWS accepts `Deny` statements,
`organizations:Describe*`, five newer reads omitted from the guide's action list,
and a condition using `s3:prefix`. The last observation establishes syntactic
acceptance only; it does not inject an S3 condition into Organizations requests.
`organizations:*` and non-Organizations actions are rejected.

The [first probe](../scripts/aws/organizations_resource_policy_probe.py) uses owned
roles and an unattached SCP. The [write probe](../scripts/aws/organizations_delegation_writes_probe.py)
adds an owned empty OU and attaches only its own SCP to that OU. Neither moves
accounts or changes existing policy attachments. Both require the designated
management account, refuse to replace an existing resource policy, retain
credentials only in memory, and record successful cleanup. No probe resources or
delegation policy remain from these captures.

The [authority probe](../scripts/aws/organizations_delegation_authority_probe.py)
uses owned member/management roles and an unattached SCP. It temporarily enables
Account Management trusted access and registers a previously unregistered member,
then restores the original settings. Captured cleanup confirms no resource policy
or delegated administrators remain and trusted access matches its initial state.
It changes no account metadata or policy attachments. AWS documents this
[Account Management integration](https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate-account.html)
and the [Organizations reads granted to service administrators](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_delegated_admin.html).

[SDK replay](../internal/services/organizations/resource_policy_aws_test.go) checks
native lifecycle/validation results through direct and signed gateway endpoints,
including unchanged stored content after rejected updates.
[IAM/STS integration](../integration/organizations_delegation_integration_test.go) checks
current policy composition and memory/SQLite recovery.
[Write integration](../integration/organizations_delegation_writes_integration_test.go) replays
the write captures and proves that a delegated SCP update blocks SQS publication
until detachment, without retaining the rejected message.
[Storage tests](../integration/organizations_delegation_storage_test.go) exercise failed
native transactions, revocation during a prepared mutation and migration of an
existing organization from schema 8.

[Authority replay](../integration/organizations_delegation_authority_integration_test.go) uses
real local IAM roles and STS session policies on memory and SQLite. It verifies
the captured decisions before and after service reconstruction, including a deny
that overrides a retained trusted-service grant, removal of that grant while
policy-based writes remain permitted, and membership visibility after deletion.
The standalone evaluator additionally verifies identity, boundary and session
restrictions and retains the denying policy's statement/source in its trace.

New policy documents may name recognized delegated actions whose service handlers
are still unimplemented; calling those handlers returns an unsupported-operation
error. The sampled transitions establish the recorded behavior without proving
all AWS timing or complete Organizations parity. Remaining service work is tracked
in [TODO.md](../TODO.md).
