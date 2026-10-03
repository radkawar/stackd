# Identity Store

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

Identity Store owns directory users, groups and current memberships. SSO owns
instances, passwords, login sessions, assignments and permission sets; IAM owns
AWS policy evaluation and credentials. Directory membership is not copied into
SSO as a second authority.

## Supported behavior

The generated AWS JSON 1.1 frontend implements the nineteen modeled directory
operations:

- Create, describe, update, delete and list users and groups.
- `GetUserId` by the unique `UserName` attribute and `GetGroupId` by `DisplayName`.
- Create, describe, delete and resolve group memberships.
- List memberships by group or user, and `IsMemberInGroups`.

Users retain their immutable resource ID, username, display name, structured name,
email (the AWS model permits one), nickname, profile URL, title, user type,
preferred language, locale, timezone, birthdate and website. Groups retain their
immutable ID, display name and description. Usernames and group display names
are unique within a store. Reserved names are rejected. Duplicate membership
creation returns a modeled `ConflictException`.

Updates apply the supplied attribute operations atomically. Supported paths are
these scalar user fields, `Name`, its six subfields, and `Emails`; group updates
support `DisplayName` and `Description`. Absent attribute values remove optional
attributes; required identity names cannot be removed. Rejected paths or duplicate
names do not partially update other attributes.

Lists are ordered by immutable resource ID. `MaxResults` is 1–100; continuation
cursors are bound to the operation, store and selection. User and group list
filters support `UserName` and `DisplayName` equality respectively. Name lookup
currently uses exact string equality. This deterministic ordering is a local
contract, not a claim about AWS's private ordering or pagination tokens.

Deletion removes memberships in the same transaction. Recreating a username or
group name gets a new resource ID and cannot inherit old memberships. The
membership check returns `false` for absent memberships, including nonexistent
user/group IDs in an existing owned store, matching the retained native probe.

## Ownership, transactions and authorization

A store has one partition/account/region owner. Public directory APIs cannot
create arbitrary stores. Identity Center provisions one through the trusted
`EnsureStore` boundary; unknown and foreign stores remain inaccessible even to
another account's root principal. IDs alone never grant cross-account access.

Every public command enters the service-owned transaction and invokes the shared
current IAM evaluator for `identitystore:<operation>`, the store ARN and the
applicable user/group/membership resource ARNs. ARN construction follows the
[Identity Store authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_identitystore.html).
The resource owner is supplied explicitly for accountless resource ARNs.
`identitystore:PrimaryRegion` comes from the admitted owner scope. IAM evaluation
and API completion timestamps use the injected shared clock.

The service's small trusted consumer boundary is:

```go
EnsureStore(ctx context.Context, scope Scope, storeID string) error
DeleteStore(ctx context.Context, scope Scope, storeID string) error
FindUser(ctx context.Context, scope Scope, storeID, userID string) (User, error)
UserByName(ctx context.Context, scope Scope, storeID, username string) (User, error)
GroupExists(ctx context.Context, scope Scope, storeID, groupID string) (bool, error)
IsMember(ctx context.Context, scope Scope, storeID, userID, groupID string) (bool, error)
```

`Scope` contains `Partition`, `AccountID` and `Region`. `User` exposes `ID`,
`UserName`, `DisplayName`, `Emails` and the retained profile. `ErrNotFound` covers
absent/foreign stores and missing user lookups. Missing groups and memberships in
an owned store return `false`. Consumers admitting a state transition pass their
enclosing transaction context so authority reads and the dependent transition
share one snapshot. These internal lookups do not confer public IAM authority.

`DeleteStore` joins Identity Center instance deletion and atomically removes the
store, users, emails, groups and memberships. Store provisioning never transfers
an existing ID to another owner. No password field or password-setting AWS API is
invented in Identity Store.

Memory storage joins `memory.Domain`; durable storage uses service-owned SQLC
queries in the shared SQLite transaction. Migration
`251_identitystore.sql` contains typed store/user/email/group/membership tables,
uniqueness constraints and cascading membership foreign keys. No resource JSON
blobs are persisted. Nested commands and trusted reads join the caller's existing
transaction; rollback restores directory membership as well as the dependent
service transition.

API completion metadata joins the journal transaction. Native field-level
CloudTrail request/response projections are not yet calibrated, so profile and
email data are not emitted by this owner.

## Evidence

Primary contracts:

- [CreateUser](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_CreateUser.html),
  including single-email cardinality and reserved names.
- [IsMemberInGroups](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_IsMemberInGroups.html).
- [AttributeOperation](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_AttributeOperation.html).
- AWS SDK Go v2 Smithy model revision
  `113bc91bf12edc3af1d3aba1c70be28494d54c2a`, model SHA-256
  `99b231521094672d22a01b4b7ccf085b6efea20e8ecaedc403576e60eea2ec8e`.

`testdata/aws/identitystore/read_only.json` records native read-only calls in the
verified account `000000000000`, `us-east-1`. A membership check for deliberately
absent user/group IDs returned `false`; describing that user returned
`ResourceNotFoundException`. The existing directory ID/prefix was consistently
normalized. No native baseline resources, users, groups, memberships, assignments
or policies were created or modified. This is limited negative-path evidence,
not native mutation parity.

The executable probe is:

```sh
go run ./scripts/identitystore_smoke
```

It uses the unmodified AWS SDK v2, real SigV4 gateway/decoder, the actual directory
service and a disposable SQLite database. Observed checks cover user/group/member
creation, duplicate membership modeled error, profile update and username lookup,
SQLite close/reopen, retained profile/email/member identity, signed cross-account
rejection, immediate trusted/public membership agreement after deletion, user
membership cleanup, and store retirement across another restart. It cleans up its
local database and listener; it does not contact AWS. Root built-in assembly and
the combined SSO login workflow are verified by the integrating Identity/SSO owner,
not substituted by this focused standalone probe.

Focused package tests passed for the service and both storage boundaries. Tests
exercise transactional deletion rollback, partition/account/region isolation,
username recreation without inherited membership, group cleanup after restart,
atomic rejected updates, cursor selection isolation and native negative fixtures.
Scoped `go vet` and `staticcheck` passed. A targeted race build did not execute:
Go failed compiling shared `internal/awscatalog` with `prepwrite: bad
 off=1073741824 siz=1`; this is not recorded as a passing race result.

## Explicit limits

- Addresses, phone numbers, photos, roles and enterprise extensions are rejected
  with an unsupported error, never silently stored or dropped. Extension-selected
  reads are rejected as well.
- External-ID/SCIM provisioning and lookup are not implemented. The public create
  model does not set external IDs.
- Legacy `sso-directory` action aliases and organization-member sharing are not
  admitted by this scoped owner. Cross-account store references are rejected.
- Resource `CreatedAt`/`UpdatedAt`, actor metadata, `UserStatus`, service quotas,
  propagation timing and customer-managed directory KMS behavior are not modeled.
  No fictional timestamps, identities or status are returned.
- Update document semantics beyond the paths listed above, native Unicode/name
  comparison calibration, detailed error-member parity and full CloudTrail field
  projections remain incomplete.

Intentional `TODO: Comeback` markers are at unsupported profile attributes in
`users.go`, external identifiers in `selection.go`, and legacy/shared directory
authority plus native audit projection calibration in `service.go`.
