# Account primary email

Account's four primary-email operations use the generated Smithy REST JSON
contracts. Organizations owns the account's published email and membership;
Account owns the pending verification request and its status. IAM reads the
same Organizations registry for its default account-email password restriction.
This workflow has working local behavior, but its complete AWS conformance audit
is still open.

## Access and native evidence

`GetPrimaryEmail`, `StartPrimaryEmailUpdate` and `AcceptPrimaryEmailUpdate` require
an explicit member `AccountId`. Organizations must have all features and trusted
access for `account.amazonaws.com`. The caller must be the management account or
an Account delegated administrator, with the applicable IAM permissions. Service
delegation does not replace identity, session, boundary or SCP evaluation.

`GetPrimaryEmailUpdateStatus` also permits an omitted `AccountId`, selecting the
caller's account. An explicit management-account target is denied. A member
without delegated administration cannot supply its own ID in Organizations mode.

[`primary_email_reads.json`](../testdata/aws/account/primary_email_reads.json)
records read-only calls against a commercial organization on 2026-09-12. It
captures trusted-access and caller/target errors, agreement between the Account
email and Organizations metadata, and the exact no-history `ValidationException`
message, `No email update found for account`. That error has no validation reason
or field list. Offline SDK tests replay those observations.

`scripts/aws/account_primary_email_reads_probe.py` temporarily enables Account
trusted access when necessary and restores its original setting. The capture
confirmed restoration. It stores email equality, not actual account email values,
and sends no OTP messages. It does not establish Start/Accept lifecycle fidelity.

## Verification and publication

`StartPrimaryEmailUpdate` authorizes and validates the target, checks published
email ownership, and stores a PENDING request with a cryptographically random
six-digit OTP. The OTP format follows the current Smithy input constraint; the
24-hour verification lifetime follows AWS's account-management guide. Codes are
kept in protected repository state and are absent from API responses and logs.

Delivery starts after commit through the injected `EmailSender`. The sender can
read committed state and does not hold an Account, IAM or Organizations storage
transaction. A failed send retains the intent and retries after one service-time
second until expiry. An interrupted send may deliver the same message again.
Replacing a pending request invalidates its previous code; generation checks
prevent a late delivery callback from overwriting the replacement or acceptance.

`AcceptPrimaryEmailUpdate` verifies the target, candidate email, current pending
state, expiry and code. It rechecks email ownership, marks ACCEPTED and erases the
OTP. The published email remains unchanged until the completion job. Completion
updates the Organizations registry, membership view and COMPLETED status in one
shared transaction. A rejected transaction rolls back all three. Existing IAM
login profiles, MFA and credentials are not replaced.

Local completion runs after one service-time second. Pending requests do not
reserve an email address: if competing accepted candidates reach completion,
the first publication owns the address and the other becomes FAILED. These delay,
replacement and competing-candidate rules are modeled behavior awaiting native
captures, not claims about AWS timing or all AWS failure transitions.

The shared clock controls expiry, retry and completion deadlines. Network I/O
uses real time and honors cancellation. Retaining the typed memory backend permits
service reconstruction to resume pending deliveries with the same code. These
records do not survive a process crash; the shared durable event journal remains
work described in [the verification kernel](verification-kernel.md).

## Offline delivery

Embedders provide `stackd.Config.EmailSender`. The supplied `mail.NewSMTP` sender
uses an explicitly configured relay, verifies STARTTLS when advertised, and has
a 30-second real-time timeout. It supports unauthenticated local relays. An absent
sender makes Start fail before saving a request; it never acknowledges a message
that was silently discarded.

For the CLI, run a local capture server such as
[Mailpit](https://mailpit.axllent.org/docs/install/docker/) and configure:

```sh
go run ./cmd/stackd -smtp-address 127.0.0.1:1025 -smtp-from no-reply@stackd.local
```

Retrieve the OTP from that server's inbox and pass it to the normal Account
Accept API. No special emulator endpoint bypasses verification.

Local verification on 2026-09-12 used the real Mailpit v1.27.4 SMTP server, bound
only to loopback. The AWS Go SDK started an update, Mailpit received its OTP,
Accept verified it, and advancing service time published the email to
Organizations. A separate message checked UTF-8 subject decoding, CRLF handling
and dot-leading text. The temporary container was removed after the check. No
messages were forwarded to external recipients.

Automated tests also exercise incorrect/expired codes, IAM-denied writes,
replacement during blocked delivery, same-address candidates, service
reconstruction, storage rollback, SMTP cancellation, and IAM's updated email
password restriction. These local tests establish implementation behavior;
they do not substitute for AWS observations.

## Remaining conformance work

Further SMTP/OTP work is deferred under the priorities in [TODO](../TODO.md).
When resumed with an authorized mailbox, capture successful
Start/Accept/completion, replacement and retry/attempt limits, email normalization,
expired and repeated acceptance errors, status retention, delivery and propagation
timing, competing account creation, and account membership/state changes while a
request is in progress. AWS documents up to four hours for propagation; the local
one-second completion is not a guarantee of instantaneous AWS-wide agreement.
GovCloud associations and the other Account conformance gaps remain open.

Primary contracts:

- [StartPrimaryEmailUpdate](https://docs.aws.amazon.com/accounts/latest/APIReference/API_StartPrimaryEmailUpdate.html).
- [AcceptPrimaryEmailUpdate](https://docs.aws.amazon.com/accounts/latest/APIReference/API_AcceptPrimaryEmailUpdate.html).
- [GetPrimaryEmail](https://docs.aws.amazon.com/accounts/latest/APIReference/API_GetPrimaryEmail.html).
- [GetPrimaryEmailUpdateStatus](https://docs.aws.amazon.com/accounts/latest/APIReference/API_GetPrimaryEmailUpdateStatus.html).
- [Root email changes and verification lifetime](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-root-user-email.html).
- [Organizations email updates preserve passwords and MFA](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_update_primary_email.html).
