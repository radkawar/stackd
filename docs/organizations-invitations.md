# Organizations invitations

Organizations implements the INVITE handshake lifecycle through generated Smithy
contracts: `InviteAccountToOrganization`, `DescribeHandshake`, both handshake
lists, `AcceptHandshake`, `DeclineHandshake` and `CancelHandshake`. These operations
have membership behavior, IAM enforcement and retained memory/SQLite state.
Organizations remains partial; this is not a claim of complete service parity.

## Membership and authorization

The management account creates invitations. The sender cancels; the recipient
accepts or declines. Participants can describe their handshake, and registered
service administrators can inspect organization handshakes subject to IAM and
resource-policy controls. Received lists select the caller's invitations and
sent lists select its organization. Management accounts cannot receive invitations
while they remain management accounts. Identity permissions, boundaries, session
policies and caller SCPs still apply. Handshake permissions resolve the actual
ARN and management owner. Received-list requests from members also use the current
management account for `aws:ResourceAccount`, as captured from AWS.

Invitations reserve account-quota capacity. Cancellation, decline and expiry
release that reservation; acceptance converts it into membership without counting
it twice. Pending account-creation jobs also respect reservations at completion.
The invitation attempt window is 24 service hours, with a limit of the greater of
20 and the applied account quota; accepted invitations do not count. Dependent
`organizations:TagResource` authorization gates invitation tags. Tags are staged
with the invitation and applied only when the account joins.

Acceptance places the existing account under the organization's root and attaches
the enabled default policies. Its IAM identities, account creation date, name,
email and contacts remain intact. Acceptance creates the protected
Organizations service-linked role if missing, requiring the caller's
`iam:CreateServiceLinkedRole` permission. It reuses an existing role. Invitation
acceptance does not automatically create `OrganizationAccountAccessRole`; AWS
requires customers to establish that access separately.

Membership, staged tags, the initial service-linked role and the handshake event
commit in the shared transaction. Dependency denial, cancellation or storage
failure leaves the invitation open with no new member, role or terminal event.

## Time, storage and history

An invitation expires after 15 service days. Terminal handshakes remain visible
for 30 days after their terminal transition, then are removed. List filters use
an action or parent handshake, and pagination binds the caller, partition, list
and filter. Recognized action filters without retained handshakes return an empty
list. [All-features migration](organizations-features.md) uses parent and member
consent handshakes; responsibility transfers remain unsupported.

The shared scheduler expires and removes retained invitations after restart.
Requests observe the same deadlines even before the worker runs. SQLite migration
12 stores invitations and staged tags in typed Organizations tables. Their
partition ownership lets terminal history survive organization deletion.
Migration 13 adds typed invitation event payloads to the shared journal.
Migrations 14 and 15 generalize those records and payloads to handshakes. Expiry
retains the originating request metadata; request-driven transitions retain their
own request IDs. Handshake removal does not erase committed event history.

## AWS evidence and reference workflows

The current AWS contract and capture determine wire and membership semantics:

- [Invite API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_InviteAccountToOrganization.html)
  and [invitation constraints](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_invites.html)
  describe tags, account reservations and delivery.
- [Accept API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_AcceptHandshake.html)
  and [accepting or declining](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_accept-decline-invite.html)
  define participant authority and service-role dependencies.
- [Handshake model](https://docs.aws.amazon.com/organizations/latest/APIReference/API_Handshake.html),
  [pending invitations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_manage-invites.html)
  and [quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)
  describe state transitions and retention.

The owned-account [capture](../testdata/aws/iam/organizations_handshakes.json) and
[probe](../scripts/aws/organizations_handshake_probe.py) record validation reasons,
handshake resources and parties, filters, received-list ownership, wrong-party
errors, duplicate invitations, decline and cancellation. The probe targets an
existing owned member and leaves no open invitation; the original membership
set and active states were verified unchanged. Terminal handshake history remains
in AWS for its retention window.

AWS rejects an account-ID invitation to an existing member with
`ALREADY_IN_AN_ORGANIZATION`, but opens an email invitation to that same account.
Attempting to accept it returns `HandshakeConstraintViolationException` while
changing the handshake to `ACCEPTED`. A following Describe confirms that state and
an ACCOUNT recipient party; the original EMAIL resource remains. Retrying accept
returns `HandshakeAlreadyInStateException`. The emulator commits this observed
terminal transition before returning the error. It does not modify membership
or apply the staged tags in this case.

SDK replay compares the captured errors, reasons, status codes, full handshake
projections and lifetime, normalizing generated IDs, absolute timestamps and party
ordering. Root integration tests exercise actual IAM users, role sessions,
permission boundaries, dependent permissions and inherited SCPs against SQS.
Memory/SQLite tests cover account preservation, failed commits, canceled
transactions, reconstruction, expiry, retention and journal origin. Quota tests
exercise competing account creation, acceptance and invitation cancellation.

A fresh CLI deployment used explicit local test credentials and a loopback
endpoint to join an account, verify its service role and tags, reopen SQLite,
restore manual time and expire a pending invitation. The typed journal retained
OPEN, ACCEPTED and EXPIRED transitions. That deployment created no AWS resources.

## Remaining work

Native standalone-account acceptance and dependency-failure captures remain open;
existing-account probes establish only the cases above. Billing/seller/partition
eligibility, account-state errors, tag-policy enforcement, notification delivery,
request throttling, and outstanding-handshake behavior around membership or
organization deletion need further implementation or AWS conformance evidence.
SMTP is explicitly deferred. [Standard all-features migration](organizations-features.md)
has a consent workflow with its own remaining native audit. Responsibility-transfer
workflows remain unsupported. Their generated contracts
alone do not establish behavior.
