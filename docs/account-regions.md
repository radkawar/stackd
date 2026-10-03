# Account regions and credential eligibility

Account Management is an IAM/STS dependency and remains **partial**. This guide
covers `ListRegions`, `GetRegionOptStatus`, `EnableRegion` and `DisableRegion`.
The five contact operations are described in [account contacts](account-contacts.md).
[Account information/name](account-information.md) adds two identity operations.
All 16 modeled operations have generated Smithy REST JSON routes and input/output
contracts. The remaining five operations return an explicit protocol error.

## State and authorization

New commercial accounts have the default-enabled regions from the owned EC2
`DescribeRegions` capture; opt-in regions start `DISABLED`. The generated catalogue
is account-independent. An account's opt-in records are separate typed state,
keyed by partition, account and target region.

`EnableRegion` accepts `DISABLED` and enters `ENABLING`. `DisableRegion` accepts
`ENABLED` and enters `DISABLING`. Either mutation during a pending transition
returns `ConflictException`. Repeating a completed transition or disabling a
default-enabled region returns `ValidationException`. Unknown regions and bad
pagination tokens include modeled `reason` and `fieldList` details.
Unknown status-filter values return `ValidationException` without those optional
details; duplicate valid values are accepted. The possible values come from the
Smithy legacy enum trait and retain its ordering in validation messages.

Transitions complete at stored service-time deadlines: two minutes to enable and
one minute to disable. These are deterministic modeled delays, **not AWS timing
guarantees**. No worker is needed to project elapsed state. Reads, authentication
and credential publication use the same projection. Pending state survives
reconstruction with retained backends and their caller-owned clock.

Regional requests check the authenticated caller's account. STS separately checks
the account receiving credentials, including cross-account role assumption,
external federation and root sessions. Enabled and disabling regions permit
issuance; disabled and enabling regions deny it. Existing regional resource
records survive disablement and become accessible again after re-enabling.
Global IAM, Organizations and Account APIs remain usable to manage access.
Token-format compatibility remains a separate [STS check](iam-sts-preferences.md).

Account, IAM and Organizations repositories share a `storage/memory.Domain`.
Account operations authorize inside their repository callback. STS reads Account
state through the borrowed IAM authority context and captured decision time,
preventing a stale region decision from publishing credentials. Replaceable
backends must preserve that transaction contract. This is in-memory coordination;
it does not implement durable SQL storage, an event journal or test forks.

Omitting `AccountId` selects standalone mode and the caller's
`arn:PARTITION:account::ACCOUNT:account` resource. Supplying it selects Organizations
mode and the management-owned
`arn:PARTITION:account::MANAGEMENT:account/ORGANIZATION/MEMBER` resource. That mode
requires all features, trusted `account.amazonaws.com` access, active membership
and a management or Account delegated-administrator caller. A delegate may target
itself; the management account must use standalone mode for itself. Delegation
supplies account trust while identity, boundary, session and SCP permissions still
apply. Conditions use current `account:TargetRegion`,
`account:AccountResourceOrgPaths` and `account:AccountResourceOrgTags/TAG` values.

Lists have deterministic name order, status filters and account/filter-bound
continuation positions. Each page independently authorizes its target account.
The token is an opaque client cursor, not an authorization grant.

## AWS evidence

Captured on 2026-09-12 using the real AWS CLI, an existing commercial management
account and an Organizations-created member:

- [`regions.json`](../testdata/aws/account/regions.json) records status, pagination,
  validation details, pending-transition conflicts and regional STS calls. The
  member session is explicitly issued through `us-west-2` before region enablement;
  the probe also tests fresh sessions issued in the target region.
- [`regions_initial_session.json`](../testdata/aws/account/regions_initial_session.json)
  retains the first lifecycle capture. Its ambient STS issuer configuration was
  not controlled; existing-session failures cannot establish region behavior by
  themselves. The later controlled capture resolves that ambiguity.
- [`organization_regions.json`](../testdata/aws/account/organization_regions.json)
  captures trusted-access and delegated-administration gates, both successful ARN
  modes, and denial from a session policy with the wrong region or ARN mode.
- [`validation.json`](../testdata/aws/account/validation.json) captures invalid and
  duplicate status filters alongside contact-type validation errors.

The lifecycle probe restored `af-south-1` to `DISABLED`. The organization probe
restored its original trusted access and delegation. Neither requested compute
resources, changed management-account regions, nor modified names, contacts,
email or root credentials. Fixtures omit issued credential material and normalize
account IDs. Reproduction scripts are `scripts/aws/account_regions_probe.py`
(`--lifecycle` explicitly selects mutations) and
`scripts/aws/account_organization_probe.py` (temporarily changes trusted access
and delegation).

In the captures, enabling took roughly two minutes and disabling roughly a minute.
Samples are observations of one member, not universal latency bounds. A separate
controlled run also observed an existing regional-issued session still accepted
at the first request after metadata reached `DISABLED`; the latest capture
observed immediate rejection there. The emulator currently changes authentication
eligibility with the metadata deadline. Variable credential-recognition lag and
re-enable races remain unimplemented and must not be inferred from the fixed model.

Offline SDK tests exercise the lifecycle, cross-account issuance, retained SQS
resources, input errors, policy conditions, deterministic pages and authority-time
state changes. Validation and Organizations tests read the native fixtures.
Storage tests verify that Account changes roll back with a failed IAM authority.

Primary contracts:
[region management](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-regions.html),
[API modes](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-api-modes-of-operation.html),
[EnableRegion](https://docs.aws.amazon.com/accounts/latest/APIReference/API_EnableRegion.html),
[DisableRegion](https://docs.aws.amazon.com/accounts/latest/APIReference/API_DisableRegion.html),
[Account authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_account.html),
and [regional STS activation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html).

## Remaining completion work

GovCloud associations remain unimplemented. Primary-email and contact conformance
gaps are tracked in the [email guide](account-primary-email.md) and
[contact guide](account-contacts.md).
Console-managed STS endpoint activation is separate from region opt-in and has
no implemented management path. China/GovCloud Account APIs and isolated-partition
behavior require their own evidence; the commercial capture cannot establish them.
China/GovCloud credential partition checks remain independent of commercial opt-in.
Complete throttling, concurrent-region limits, propagation/re-enable timing and
cross-account failure/condition conformance remain required before completion.
The generated frontend currently supports literal REST JSON paths and document
bodies; labels, header/payload bindings and streaming require further work.
