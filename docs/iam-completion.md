# IAM completion audit

IAM is the active service. It is **incomplete**. The pinned SDK model has 180
operations; 170 currently have handlers. These counts describe API coverage,
not semantic parity. All remaining IAM behavior must be implemented and verified
before moving to the next service.

The current work includes transactional users/groups/roles, identity and managed
policies, access keys, virtual MFA, instance profiles, login profiles, account
password policies and aliases, service-specific credentials, OIDC/SAML provider
administration and actual STS token federation, service-linked role jobs,
context-key reporting, role use history, signing certificates, SSH public keys
and server certificates, account summary, authorization details, credential reports
and principal/custom policy simulation, plus identity/Organizations last-access
reports and policy-grant discovery, centralized root feature management and
STS root task enforcement, outbound issuer configuration, real JWT issuance and
global STS token preferences with enforced credential region compatibility, and
template-based role acquisition with underlying permission checks and configuration
reuse, plus account properties with namespace conditions and atomic Role Manager
service-role provisioning. See [role-template behavior](iam-role-templates.md) and
[account-property captures and remaining work](iam-account-properties.md). Commercial
role-template reads now use the native AWS resource-account condition in both
direct calls and acquisition; the role-template evidence includes 23 session-policy
observations across all five captured definitions. Verification
includes authorization, immutable identity
references, rollback, concurrent transitions and live AWS fixtures.
Existing implementations also need complete semantic audits.

All 170 implemented operations now return generated response types through one
encoder. This includes the remaining 35 policy, version, inline-policy,
attachment and permissions-boundary operations. Domain records no longer carry
XML serialization tags, and operation-specific projections own field presence
and policy-document encoding. Existing native fixture replays and SDK tests cover
policy lifecycles, pagination, authorization details and enforcement. All IAM
handlers, pagination and permission paths now consume generated inputs; the
semantic audit remains open.

Standalone IAM now validates requests through the same generated decoder as the
gateway, before authorization and state transitions. User, group and membership
handlers consume typed inputs; their shared lookups take names instead of Query
maps. The 28 create, 20 update and four name-lookup observations in
[`identity_inputs.json`](../testdata/aws/iam/identity_inputs.json) replay through
both endpoints, including state after rejected updates. AWS rejects `//`, missing
path delimiters, spaces, DEL, newlines and non-ASCII path characters, while accepting
`/a//b/`. Newline and non-ASCII names fail both creation and lookup. The upstream
`pathType` pattern anchors its alternatives incorrectly;
`cmd/awsgen/model_corrections.json` groups those alternatives using this capture.
The [CreateUser reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html)
and capture enforce the 64-character creation limit. The
[UpdateUser reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateUser.html)
also limits new names to 64 characters, with 128 allowed for existing-name input.
The AWS path descriptions mention DEL, but the pattern and live service reject
it. These captures do not establish complete user/group semantics.

Role, access-key and resource-tag handlers now consume generated inputs directly.
Generated tag inputs no longer round-trip through Query maps, and ordinary,
federation, instance-profile and server-certificate mutations share tag merge and
removal logic. User/role keys match without case; other resource keys remain case
sensitive. Resource-specific empty-request errors and certificate acceptance rules
remain at their owning handlers. The caller's resolved user still binds access-key/MFA
pagination when `UserName` is omitted.

The owned [resource-input capture](../testdata/aws/iam/resource_inputs.json) and
[SDK replay](../internal/services/iam/resource_inputs_aws_test.go) establish:

- Role descriptions accept 1,000 characters, including Latin-1 characters whose
  UTF-8 representation uses multiple bytes. Both role update APIs preserve state
  after oversized descriptions are rejected.
- `UpdateRole` preserves omitted settings and accepts an explicitly empty
  description. `UpdateRoleDescription` preserves the session-duration setting.
  The [UpdateRole reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateRole.html)
  says omitted duration applies a one-hour default, but the capture retains the
  existing 7,200-second setting. Creation still defaults to one hour.
- `CreateRole` and `UpdateRole` reject durations of -1, 0, 1 and 3,599 seconds with
  `ParamValidation`, and 43,201 seconds with `ValidationError`. IAM maps the generated
  minimum-range error to the native code without repeating bounds validation.
- Although the [UpdateAccessKey model/reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html)
  includes `Expired`, attempts to set it return `InvalidInput` and preserve the
  previous Active/Inactive status. The credential store owns allowed transitions.
- OIDC and SAML providers reject empty tag and untag lists with `InvalidInput`.
  Their differently cased keys coexist, and replacement/removal matches exact case.

The replay covers six description creations, five invalid-duration creations,
14 updates, four access-key status requests and 12 provider-tag mutations through
both standalone IAM and the signed gateway. All probe-owned roles, user/key and
providers were deleted. [Credential-default tests](../internal/services/iam/credential_defaults_test.go)
also exercise permission-gated implicit key creation, disabled/deleted key rejection
and owner-scoped key/MFA pagination. These checks do not complete IAM's semantic audit.

Credential conditions and all-user listing authorization, service-linked role
resource/protection rules, federation resources/discovery and instance-profile
PassRole checks also consume generated inputs. This removes independent raw-field
parsers from those permission paths and repeated discovery guards. Shared Query
parsing now handles the native integer/boolean forms used by these callers;
[the Query evidence](aws-query.md) records 31 IAM and nine STS observations and
SDK replay through standalone and signed gateway paths.

Shared pagination now consumes generated Marker/MaxItems accessors and typed
selections. It no longer reparses limits or reconstructs Query maps for reports
and instance profiles. Callers preserve canonical report filter sets, current
role/profile names, implicit access-key/MFA owners, Organizations sort defaults
and last-access namespace rules. Password preparation also consumes generated
inputs at its account-identity owner instead of selecting raw fields in dispatch.
The [pagination capture](../testdata/aws/iam/pagination_inputs.json) records 19
requests on owned users, tags and service credentials. Its
[SDK replay](../internal/services/iam/pagination_inputs_aws_test.go) covers accepted
and rejected page sizes, continued pages, ignored fields and equivalent boolean
spellings through both endpoints. Changing `AllUsers=false` to `AllUsers=0` now
preserves the marker's selection, matching AWS; the old raw Query hash rejected
that request. No older draft marker format is retained. These observations do
not establish universal pagination semantics.

Request conditions now consume generated member accessors for Tags, TagKeys,
PolicyArn, PermissionsBoundary and OrganizationsPolicyId. Input models determine
which operations expose each field. The redundant Query tag parser and repeated
modeled tag count/length/character checks are removed. Mutation handlers retain
reserved-prefix, resource-specific duplicate-key and accumulated-quota rules.
The [tag capture](../testdata/aws/iam/tag_inputs.json) contains 60 root/conditional
TagUser observations; [collection inspection](../testdata/aws/iam/query_collections.json)
adds 24 read-only policy-list observations. The
[SDK replay](../internal/services/iam/tag_inputs_aws_test.go) checks both endpoint
paths, denial precedence and retained tag state. Exactly repeated keys expose
the last supplied value to authorization: a denied value yields AccessDenied,
while an allowed value proceeds to InvalidInput for the duplicate request.
Leading-zero indices and split key/value index spellings bind together; gaps
remain missing elements and excessively sparse expansions return MalformedInput.
Unknown nested tag fields do not prevent a valid mutation.

Resource authorization now reads generated name/ARN accessors and typed creation
inputs. The generated action catalogue remains authoritative for resource kinds;
IAM's current records supply canonical paths, names, tags, boundaries and key
ownership. Operation handlers no longer receive Query maps. The redundant
modeled-field filter is deleted, and gateway-bound requests use their existing
decoded operation and input without reparsing the wire request. Standalone use
retains the same generated validation boundary.

The [resource authorization capture](../testdata/aws/iam/resource_authorization.json)
records 24 requests under grants restricted to owned resource ARNs. Its
[SDK replay](../internal/services/iam/resource_authorization_aws_test.go) covers
standalone IAM and the signed gateway:

- User, group, role and instance-profile lookups accept case-varied names and
  return their stored ARNs, including paths. Injected unmodeled Path fields do
  not change the selected resource. Customer-policy lookup uses its ARN.
- GetUser without UserName selects the caller. GetAccessKeyLastUsed selects the
  key's current owner, even with an injected unmodeled UserName field.
- GetContextKeysForPrincipalPolicy and SimulatePrincipalPolicy resolve the
  identity by name when a same-account PolicySourceArn has a different path;
  permission checks use that identity's stored ARN.
- CreateUser authorizes the requested creation path. A denied creation leaves
  no user. After the existing user's path changes, its old ARN grant no longer
  allows GetUser or GetAccessKeyLastUsed.

The probe waited for permission propagation before capture and for denial after
the path change; the observations do not measure propagation timing. It deleted
all owned users, keys, policies, group, role and profile. AWS documents
[GetUser's implicit caller](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html),
[GetRole's stored path/ARN](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRole.html)
and [access-key ownership](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html).
The capture supplies the additional path/name authorization evidence. It does
not establish all missing-resource, partition, authorization-error precedence
or IAM semantics; those remain in the service audit.

The 35 managed-policy/version, inline-policy, attachment and permissions-boundary
operations also consume generated inputs. Shared identity, policy and version
lookups use names or ARNs; obsolete Query name/Boolean parsers were removed.
Native [policy-management captures](../testdata/aws/iam/policy_management.json)
establish these behaviors for users, groups and roles:

- Inline policy names match without case sensitivity. Replacing `MixedName` via
  `mixedname` replaces its document and preserves `MixedName` in listings;
  `Get*Policy` echoes the requested spelling. Mixed-case deletion removes that
  same policy. The shared writer excludes the replaced document from its quota.
- `ListPolicies` uses `PolicyUsageFilter` only when `OnlyAttached` is true.
  `ListEntitiesForPolicy` without a usage filter includes both permission
  attachments and boundary uses. Explicit usage/entity filters and repeated
  boundary writes retain the captured membership and usage counts.
- Deleting an absent permissions boundary and detaching an existing policy that
  is not attached return `NoSuchEntity`. Authorization still precedes these
  resource-state checks.

The [ListPolicies reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html),
[ListEntitiesForPolicy reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListEntitiesForPolicy.html)
and [DeleteUserPermissionsBoundary reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteUserPermissionsBoundary.html)
define the corresponding API surfaces; the capture resolves their omitted/default
behavior. [SDK replay](../internal/services/iam/policy_management_aws_test.go)
covers nine policy listings, 27 entity listings, inline-name transitions for all
three identity kinds, missing-attachment/boundary errors and usage counts.
[SQLite/SQS integration](../integration/iam_policy_names_integration_test.go) verifies that
replacing a deny with an allow through a different name spelling changes actual
user, group-member and already-issued role-session permissions, survives database
reopening, and loses the grant after mixed-case deletion. Rejected sends publish
no messages. These cases do not establish complete policy-management conformance.

Ordinary authorization now carries generated scalar/list context types through
every policy layer and federation trust. Native IAM tagging captures and SDK
replay cover one-element list keys, set/scalar operators, empty values,
multivalued variables and authorization-before-validation. See
[condition behavior and evidence](iam-evaluation.md#condition-values-and-cardinality).
Typed comparison captures additionally cover numeric/Boolean spellings,
millisecond dates, unconvertible operands and distinct IAM-storage versus STS
session-policy validation. The broader condition audit remains open.
Native IP-condition captures additionally cover IPv4-mapped request normalization,
decimal prefix/address spellings, IPv6 subnet boundaries and noncanonical
networks, with SDK authorization, stored-policy and simulator replay. Actual
HTTP peer restrictions also gate SQS sends through the same IAM evaluator.
Native string captures now cover contextual lowercasing, supplementary-character
wildcards, variables and ARN/resource selectors. SDK replay verifies decisions
and actual tag state; current principal tags also gate SQS publication. See
[string behavior and scope](iam-evaluation.md#string-conditions-and-resource-wildcards).

Successful native root sessions now establish the independent IAM and S3/SQS
task-feature gates, delegated feature permissions, trusted-access constraints,
root recovery profile/summary/report fields and retained issued-session access.
Regional STS eligibility can lag IAM metadata after revocation; that transient
view and nonempty root key/certificate/MFA responses remain open in the
[centralized root audit](iam-root-access.md).

Resource-owner RCPs now restrict SQS, KMS and STS, including cross-account callers
and verified OIDC/SAML role issuance. The owner organization context follows
membership changes, and controls participate in the existing STS publication
transaction. [RCP behavior](iam-resource-controls.md) records live AWS syntax and
authorization captures, service-owned exemptions and remaining conformance work.
This does not increase the IAM operation count or establish complete IAM parity.

Organizations account creation now provisions the member's initial access role
through IAM, with management-account trust and `AdministratorAccess`. Account
membership and role publication share the transaction domain. Accepted requests
remain pending until the service-time worker completes; failed commits retain the
job for retry, and reopening retained backends recovers it. The Organizations
service-linked role also has sourced trust/permissions, automatic provisioning
and an actual membership-dependent deletion checker. The
[account-access guide](organizations-account-access.md) records live evidence,
cross-service SDK tests and the remaining provisioning dependencies.

Signed STS `AssumeRole`, `AssumeRoot`, `GetSessionToken` and `GetFederationToken` now use one
IAM authority transaction for current parent credentials, applicable role trust,
identity/boundary/session policies, managed session policy reads, MFA and new
credential rows. The callback borrows one repository and one timestamp captured
after storage acquisition. Failed commits and canceled callbacks persist no
issued session and return no credential payload. Caller account/partition
metadata remains intact while destination role and managed-policy reads use
their proper account scope.

`GetSessionToken` remains a permissionless authentication operation and skips
Organizations; this follows the [AWS API contract](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html).
Other signed issuance checks share a decoded caller-account SCP snapshot inside
the IAM transaction. The built-in memory backend joins IAM and Organizations in
one domain, keeping control policies, organization membership and root eligibility
stable through credential publication. IAM root-feature operations also use this
authority: their Organizations writes roll back if the IAM callback fails or is
canceled. Replacement backends must preserve the borrowed-context contract.

Detailed behavior and live evidence: [service credentials](iam-service-credentials.md),
[service-linked roles](iam-service-linked-roles.md), and
[context keys and role history](iam-context-keys.md), and
[certificates and SSH keys](iam-certificates.md), plus
[OIDC](oidc-federation.md) and [SAML](saml-federation.md) federation, and
[OIDC trust policy write controls](iam-oidc-trust-controls.md).
Account counts, quotas and permission graph reporting are documented in
[account reporting](iam-account-reporting.md); cached CSV generation and
credential history are covered in [credential reports](iam-credential-reports.md).
Current policy graphs, composition and diagnostics are documented in
[policy simulation](iam-simulation.md). Service/action activity, report snapshots,
caller ownership and live discovery semantics are documented in
[last-access reporting](iam-last-access.md).

| Area still open | Required behavior |
| --- | --- |
| Service-linked roles | Expand the six sourced commercial templates to all authoritative service/partition templates; finish Organizations and Role Manager transition/diagnostic conformance and bind each future service's actual usage checker |
| OIDC/SAML federation | Administration, cryptographic verification and atomic STS integration are implemented; finish the full differential audit, including live social-provider success paths |
| Regional STS activation | Commercial region opt-in and credential-owner enforcement are implemented; console-managed STS activation and variable credential-recognition propagation remain open; see [region evidence](account-regions.md) |
| MFA | Virtual-device bindings, code windows, synchronization history, ordered propagation, one-time STS consumption, mandatory self-management MFA and verification-budget recovery have live evidence; remaining transient replacement behavior, root/hardware/FIDO behavior and device APIs stay open; see [MFA audit](iam-mfa.md) |
| Reports and simulation | Full action/resource/context audit; finish the differential job lifetime and slot-order audit; service history applies the documented 400-day window |
| Centralized root access | Successful AWS feature/delegate transitions, root profile/report field conformance and issued-session revocation audit; see [root access](iam-root-access.md) |
| Outbound identity | Configuration, ordered propagation, signed JWTs and discovery are implemented with live captures; finish signing-key lifecycle and partition/context audit; see [outbound identity](iam-outbound-identity.md) |
| New account and delegation APIs | New-experience account onboarding and Role Manager's Access Analyzer transition; delegation lifecycle; noncommercial role-template resource-account context and full partition/version differential audit |
| Policy catalogue | Authoritative China and GovCloud catalogues, refresh/revalidation and reserved service-role lifecycle |
| Existing operations | Full AWS differential audit, current limits and permission relationships |

The ten unimplemented operations in the pinned model are `GetMFADevice`,
`AcceptDelegationRequest`, `AssociateDelegationRequest`, `CreateDelegationRequest`,
`GetDelegationRequest`, `GetHumanReadableSummary`, `ListDelegationRequests`,
`RejectDelegationRequest`, `SendDelegationToken` and `UpdateDelegationRequest`.
The unsupported dispatcher returns a protocol error. API coverage changes do not
close the behavior rows above.

The nine delegation operations require the partner request lifecycle, registered
templates, SNS token notification and usable STS delegated access. AWS requires
partner onboarding for request creation; see the
[partner guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-temporary-delegation-partner-guide.html).
`GetHumanReadableSummary` is an asynchronous LLM-backed summary of a delegation
request, not a local JSON reformatting operation. `GetMFADevice` requires FIDO
enrollment/metadata behavior; virtual TOTP enrollment does not implement it.

The current region dependency now has Account Management transitions, generated
REST JSON routes and destination-account checks inside STS publication. See
[Account region evidence and remaining scope](account-regions.md). This adds no
IAM operations and does not complete IAM or Account Management.
Account information/name operations also reuse IAM's creation metadata and the
Organizations registry used by default password restrictions. Their native SDK
behavior and remaining lifecycle audit are in [account information](account-information.md).

The public [policy evaluation library](iam-evaluation.md) now owns the built-in
permission-composition path and returns per-permission source/version,
statement, principal and condition traces. This does not close the full
condition/action/resource audit or diagnostics joining dependent actions.

## Sources and executable evidence

The SDK Smithy models generate protocol contracts. `cmd/iamgen` now reads the
pinned [AWS service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html)
for all 455 service prefixes. Action/resource conditions, multiple ARN forms and
last-access tracking come from one AWS snapshot. The cloned dataset remains
optional comparison material; its draft SDK mapping APIs and digest checks were
removed. See [generation and ownership](../internal/iam/catalog/README.md).

AWS's reference separates API operations from permissions and includes static
context such as `iam:PassedToService` for `iam:PassRole` during
`AddRoleToInstanceProfile`. These mappings omit some services and Forward Access
Session dependencies. IAM still resolves actual identities and enforces
operation-specific permissions in its transaction; a metadata edge cannot supply
resource state or grant access by itself.

The owned `service_reference.json` capture verifies policy discovery for HTTP/REST
API Gateway and both Greengrass deployment ARN forms, with an unrelated-service
negative case. The evaluator searches ARN alternatives independently while
retaining the intersection of policy levels and unconditional denies. The
keyless IAM user and its policies were deleted. Service parity remains open.

`internal/services/iam/authorization_metadata_test.go` verifies that unknown Query
parameters cannot spoof permission-boundary or tag conditions, resource conditions
use current state, and `iam:ResourceTag` cannot authorize customer policy access
where only `aws:ResourceTag` is supported.

`cmd/awspolicies` captures AWS-owned documents and version history from AWS IAM.
The commercial snapshot contains 1,575 policies and 7,006 retained versions.
Descriptions, policy IDs, timestamps and documents come from that capture;
attachment and boundary counts come from local identities. Original historical
documents are preserved even when they contain mistakes AWS would reject in a
new customer policy.

Live fixtures record their source, comparison scope and cleanup:

- `testdata/aws/iam/root_access.json`: feature permissions and eligibility, STS
  validation/routing, and all five current public root-task policy documents;
  successful AssumeRoot was unavailable with the organization configuration.

- `testdata/aws/iam/user_group_shapes.json`: create/get/list user fields, group
  member fields and idempotent group membership operations. Reproduced by
  `scripts/aws/iam_user_group_probe.py` and replayed by the SDK response-shape test.
- `testdata/aws/iam/identity_inputs.json`: user/group path creation and updates,
  state after rejected updates and user creation name limits. Reproduced by
  `scripts/aws/iam_identity_inputs_probe.py`; its owned keyless users and empty
  groups were deleted. SDK replay covers standalone IAM and gateway validation.
- `testdata/aws/iam/policy_management.json`: usage/entity filters, inline-name
  matching and preservation, missing boundary/attachment errors and usage counts.
  `scripts/aws/iam_policy_management_probe.py` deleted its owned keyless user,
  group, role and four managed policies after capture.
- `testdata/aws/iam/account_reporting.json`: resource/usage counters, quotas,
  report filters and markers, field presence, policy-version documents and dates;
  replayed through the SDK account-summary and authorization-detail tests.
- `testdata/aws/iam/credential_report.json`: generation/download lifecycle,
  byte-stable caching and ten owned user rows, replayed through CSV and SDK
  tests; four-hour expiry is documentation-derived, not observed live.
- `internal/services/iam/testdata/login_profile_aws.json`: default password
  rules, login-profile errors/reset state and signed password-change behavior.
- `internal/services/iam/testdata/instance_profiles_aws.json`: single-role
  constraint, duplicate association errors, deletion conflicts and field presence.
- `internal/services/iam/testdata/tags_aws.json`: tag case, reserved prefixes,
  empty lists, character validation and quota failure without partial mutation.
- `internal/services/iam/testdata/service_credentials*_aws.json`: six credential
  services, public formats, reset/status/expiry/rename rules and authorization.
- `internal/services/iam/testdata/service_linked*_aws.json` and `role_wire_aws.json`:
  protected role behavior, deletion jobs, instance profiles and output fields.
- `internal/services/iam/testdata/federation`: provider configuration, metadata,
  private-key rotation and OIDC/SAML response/error behavior; PEM files are
  generated test-only keys used solely by the owned provider probes.
- `internal/services/iam/testdata/certificates_aws.json`, `certificate_edges_aws.json`
  and `server_certificate*_aws.json`: cryptographic formats, duplicate handling,
  server-chain validation, identity/status behavior and update/tag transitions.
- `internal/services/sts/testdata/oidc` and `internal/services/sts/testdata/saml*_aws.json`:
  token verification, trust conditions, session duration, encryption and provider
  rotation; see the linked federation guides for exact replay scope.
- `internal/services/iam/testdata/context_keys_aws.json`: permissive reporting
  grammar, preserved case/duplicates and current principal policy composition.
- `internal/iam/managed/testdata`: AWS-owned policy mutation/attachment rules,
  authorization context and policy-variable behavior.
- `testdata/aws/iam` and `testdata/aws/sts`: policy decision fixtures and current
  managed-session policy behavior.

Normal tests use local endpoints and explicit test credentials. Live probes use
uniquely owned resources, record sanitized behavior and verify cleanup. Existing
account-wide password policy and aliases were read without modifying them.

Local authority regressions complement those AWS fixtures:

- [`integration/signed_session_authority_integration_test.go`](../integration/signed_session_authority_integration_test.go):
  SDK checks for current trust, role deletion/duration, caller policy/boundary,
  managed policy deletion, disabled MFA/key, expired-parent and caller-rename
  changes before issuance; cross-account policies, concurrent writers, captured
  transaction time, and failed/canceled commits with no returned or usable
  credentials.
- [`integration/session_authentication_integration_test.go`](../integration/session_authentication_integration_test.go):
  `GetSessionToken` succeeds with deny-all identity permissions and unavailable
  Organizations storage, while `GetFederationToken` requires its control source.
- [`session_authority_test.go`](../internal/services/iam/session_authority_test.go)
  and [`session_authority_atomicity_test.go`](../internal/services/iam/session_authority_atomicity_test.go):
  borrowed state, metadata and time, partition fencing, rollback/cancellation,
  callback lifetime and re-entry rejection.
- [`signed_clock_test.go`](../internal/services/sts/signed_clock_test.go):
  coherent permission-check time, parent expiry and explicit MFA at the zero epoch.
- [`policy_snapshot_test.go`](../internal/services/organizations/policy_snapshot_test.go):
  a stable SCP decision across an independent SDK policy write, updated controls
  on the next request, detached values, account/partition isolation and cancellation
  when the snapshot has no surrounding transaction.
- [`integration/session_controls_integration_test.go`](../integration/session_controls_integration_test.go):
  signed role/federation issuance blocks a concurrent Organizations write until
  publication, and the next request enforces a subsequently committed SCP deny.
- [`integration/root_access_features_integration_test.go`](../integration/root_access_features_integration_test.go):
  Organizations root-feature writes roll back on failed or canceled IAM authority
  commits, with successful retries using IAM permissions alone.
