# KMS grants

Grants use generated Smithy contracts, typed KMS storage and the shared IAM
evaluator. IAM owns principal resolution. KMS owns operations, constraints,
tokens, named-request reuse and retirement/revocation. KMS remains partial.

## Principal and permission semantics

Grants accept accounts, IAM users/roles, assumed-role sessions and federated-user
sessions. Assumed-role grants bind the current role's immutable ID plus the
session name. Issuing credentials first is unnecessary. Repeated assumptions
with the same role/session name match; other names do not. STS ARNs omit the IAM
role path. Raw session IDs resolve to current ARNs. Federated-user grants bind
the account and federated name. Authentication still validates the actual issuer
and credentials; a grant token never substitutes for permission.

Owned AWS captures establish these distinctions:

| Grant and caller | Implicit permission limits |
| --- | --- |
| Same-account exact session grant | No IAM allow required; implicit session/boundary denials do not limit the grant |
| Same-account role grant | No IAM allow required; session/boundary limits apply |
| Cross-account grant issued by the key owner's account | Caller also needs effective identity permission |
| Cross-account grant issued by the caller's account | Direct grants can supply caller permission; role grants remain limited by session policies, while exact-session grants do not |

Explicit identity, session, boundary and key-policy denials and applicable
Organizations controls remain authoritative. `RetireGrant` uses grant/IAM
authorization; key policies do not authorize it. The native retirement capture
confirms cross-account caller permission is still necessary when the key owner
issued the grant, including an explicit retiring principal. See AWS's
[grant authorization](https://docs.aws.amazon.com/kms/latest/developerguide/grant-authorization.html)
and [retirement rules](https://docs.aws.amazon.com/kms/latest/developerguide/grant-delete.html).

`policy.GrantPermissions` carries evaluated permissions unchanged through the
server adapter and public evaluator. Caller-account trust retains its principal
kind: an unrelated role grant cannot supply trust to an exact-session grant and
bypass its cross-account identity requirement.

## Delegation, lifecycle and integration

Grant-authorized `CreateGrant` requires one parent permitting `CreateGrant`, all
requested operations and equally or more restrictive encryption-context
constraints. Separate parents cannot contribute additional operations. An
independent policy can authorize creation; permission for the cryptographic
operation alone cannot broaden the parent. The native capture verifies these
distinctions from AWS's [creation rules](https://docs.aws.amazon.com/kms/latest/developerguide/create-grant-overview.html).

Named retries compare bound identities and constraints. ARN and unique-ID
spellings reuse the grant and return interchangeable tokens. Deleting a role
leaves old bindings intact; list responses render its deleted unique ID.
Recreation cannot recover old permission or the old named grant. Principal
filters resolve current identities and reject invalid/deleted references. These
bindings and tokens survive reconstruction with retained typed storage.

SQS preserves the verified IAM/STS caller when forwarding to KMS. An exact-session
grant can authorize `GenerateDataKey` and `Decrypt` while the session policy
permits only SQS. Queue-specific encryption context still applies. Revocation
reaches sends and receives after the configured data-key reuse period expires.
This complete workflow is tested locally through both SDKs; it was not replayed
against AWS in this capture.

## Evidence and open work

[`grants.json`](../testdata/aws/kms/grants.json) records 82 AWS responses from
September 12, 2026 in `us-east-1`: role/session and boundary restrictions,
delegation, binding deletion/recreation, management/member-account trust and
retirement. Tokens and credentials are omitted; account, principal, key and grant
identifiers are normalized. Early `InvalidArnException` responses record actual
IAM-to-KMS propagation, including a filter immediately after role recreation.
Local tests assert converged identity state without inventing a fixed delay.

[`kms_grants_probe.py`](../scripts/aws/kms_grants_probe.py) captures ordinary
workflows; [`kms_grants_cross_account_probe.py`](../scripts/aws/kms_grants_cross_account_probe.py)
captures organization-member scenarios. Follow-ups in the checked-in capture
reused one owned key. Temporary users, access keys, policies and roles were
removed, and grants revoked. That key and the interrupted first setup's key are
scheduled for deletion after the minimum seven-day window, September 19. These
scripts provision owned resources when explicitly run; ordinary tests stay
offline. SDK tests compare native decisions and exercise plaintext, filtering,
retained storage and encrypted queue delivery.

Service-principal grants and trusted `SourceArn` constraints remain explicit
unsupported operations until their service consumers are implemented. SQS's
forwarded caller is not a service principal. Grant propagation, quotas, remaining
validation/error precedence and partition conformance remain open. Neither this
capture nor operation registration establishes complete KMS parity.
