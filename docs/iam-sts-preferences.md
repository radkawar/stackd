# Global STS token preferences

`SetSecurityTokenServicePreferences` changes an account's global STS token
version through generated IAM Query bindings. `GetAccountSummary` reports
`GlobalEndpointTokenVersion`: 1 by default, or 2 after selecting `v2Token`.
The operation requires `iam:SetSecurityTokenServicePreferences` on resource `*`;
identity policies, boundaries, session restrictions and Organizations controls
apply through the existing IAM authorization boundary.

## Credential behavior

Global version-1 credentials work in commercial regions enabled by default and
fail authentication in opt-in regions. Version-2 credentials and credentials from
regional STS endpoints support all regions in their partition. Version changes
affect subsequently issued credentials. An already issued legacy credential
remains restricted after an upgrade; a modern credential remains compatible
after a downgrade. These rules follow the [IAM API contract](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetSecurityTokenServicePreferences.html)
and the owned AWS capture below.

Issuance covers `GetSessionToken`, `GetFederationToken`, `AssumeRole`,
`AssumeRoleWithWebIdentity` and `AssumeRoleWithSAML`. MFA sessions use the same
credential creation path. Role assumptions read the destination account's
preference inside the IAM authority transaction, alongside current identity,
role and policy state. They do not use a cross-account caller's preference.
Regional-only operations such as `AssumeRoot` continue rejecting the global
endpoint and issue modern credentials.

Requests addressed to `sts.amazonaws.com`, or explicitly carrying `aws-global`
service metadata, select global behavior. Normal local endpoint overrides use
their signed region. Both global and regional `us-east-1` requests sign for that
region, so the signed hostname distinguishes the real AWS endpoints.

Session tokens remain opaque cryptographically random handles. Modern handles
are longer than legacy handles, preserving the documented storage distinction.
AWS's private token encoding and exact lengths are not fixed public contracts.
No preference update rewrites credential rows or changes their expiry.

Invalid regional token authentication uses the service's actual wire error:
KMS returns `UnrecognizedClientException`/400; STS and SQS return
`InvalidClientTokenId`/403. Valid signatures and IAM permissions do not make an
incompatible token usable.

## Propagation and storage

IAM reports a successful setting change immediately. STS observes it after
**10 service-time seconds**. This deterministic interval models the roughly
ten-second changes captured against AWS; it is not an AWS timing guarantee.
Manual clocks advance the transition without waiting in wall time.

Rapid changes preserve order. The live capture changed v2 → v1 → v2 with a
three-second interval between writes and observed newly issued legacy tokens
after IAM had already returned to v2. Each pending change is committed with the
typed IAM settings. The shared `Propagated[T]` model also implements outbound
identity and MFA binding propagation; there are no separate timers or background caches.

Account settings and the selected token compatibility participate in the existing
IAM issuance transaction. Failed or canceled publication returns no usable
credential. Failed preference writes enqueue no changes. Retaining the memory
backend and clock preserves pending changes across provider reconstruction;
this does not provide durable crash recovery or the planned shared event journal.

## Evidence and remaining dependencies

`scripts/aws/iam_sts_preferences_probe.py` captures real IAM and STS requests
using the AWS CLI and signed Query requests. It temporarily changes the current
account preference, creates one owned role, restores the original preference and
verifies role deletion. It records token lengths and request outcomes; credential
secrets and bearer tokens remain in memory. Existing identity policies and region
activation settings are unchanged.

`testdata/aws/iam/sts_preferences.json` contains 117 commercial-account observations:
invalid enum values, account summary changes, global/regional user, federated-user
and role sessions, propagation, rapid changes, old-token compatibility and KMS/SQS
authentication errors. `us-east-1` and `ap-northeast-3` exercised default regions;
`ap-east-1` was already enabled in the account. Cleanup restores version 1 and
confirms the owned role no longer exists.

`sts_preferences_*test.go` exercises actual SDK operations, fixture error replay,
global-host signatures, cross-account role selection, OIDC federation, exact
service-time deadlines, reconstruction, permission denials and transaction
rollback. Cross-account selection and OIDC integration are local regressions;
the live preference fixture covers same-account sessions.

`cmd/awsgen/regions.json` captures AWS EC2 `DescribeRegions(AllRegions=true)`.
`make generate-aws` derives the legacy token region set from `OptInStatus`.
The probe refreshes this input; regeneration and drift checks require no AWS
credentials. Smithy endpoint-selection rules do not encode token compatibility,
so they are not substituted for the [EC2 region contract](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html).
The generated catalogue remains usable without either clone or network access.

Account Management now owns commercial region opt-in and its asynchronous phases.
The gateway checks the caller account; STS issuance checks the destination account
inside its IAM transaction. This is independent of token-format compatibility.
See [region behavior and live evidence](account-regions.md). Console-managed STS
endpoint activation and variable post-disable credential propagation remain open;
the [AWS regional STS guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html)
describes the separate endpoint setting. IAM, STS and Account remain incomplete.
