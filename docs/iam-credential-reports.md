# IAM credential reports

`GenerateCredentialReport` and `GetCredentialReport` use generated Smithy inputs,
outputs and Query encoding. They have separate IAM permissions on `*`, evaluated
through the same identity, boundary, session and Organizations controls as other
IAM requests. Their implementation does not complete IAM's remaining reports or
its overall semantic audit.

## Generation and storage

A successful generation request commits one account/partition-scoped intent and
returns `STARTED`. An after-commit wake starts IAM's shared job driver. Repeated
requests for pending work return `INPROGRESS`; they do not replace the intent.
The worker builds the whole CSV from one IAM/credential transaction and commits
the artifact with its completion timestamp. Generation IDs fence stale work.
Canceled or failed storage commits leave the previous committed record intact.
An unusable credential snapshot produces a failed generation; a later Generate
request can retry it. No partial CSV is returned.

The completed response is `COMPLETE`, without a Description. Within four hours,
Generate reuses the stored artifact. Later generation requests replace it with
a new intent. Get reads the existing bytes; user/key/password changes cannot
silently rewrite a cached report. SDK clients receive decoded bytes through the
generated Base64 wire representation and `text/csv` format.

Get returns `ReportNotPresent` (410) before generation, `ReportInProgress` (404)
while work is pending, and `ReportExpired` (410) after the four-hour window.
The captured missing/pending error message is `Unknown`. The exact expiration
boundary is documentation-derived: the
[Get API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html)
links expiration to the guide's four-hour reporting window. It was not measured
by waiting four hours in AWS. Exact-age local tests accept four hours and expire
at the first instant after it. See also the
[Generate API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateCredentialReport.html).

`storage/iam` exposes typed `AccountMetadata` and `CredentialReportRecord` records.
Local bootstrap accounts get their creation timestamp on their first successful
IAM metadata initialization or Account information read, independently of credentials
or report generation. Organizations member provisioning writes creation metadata
with the initial roles. An invited account's join date is not its creation date.
See [shared Account/IAM identity behavior](account-information.md).
Imported account metadata may supply an earlier date, including the zero epoch. This is
local provisioning metadata; it does not claim to reconstruct an AWS account's
history. Reopening a retained
memory backend preserves pending work and completed artifacts. Process-crash
durability still requires the planned SQLC backend.

IAM's report and service-linked deletion sources share `internal/scheduler`.
Deadlines use the injected service clock, with stable source/key ordering and
bounded draining. `RunDueJobs` lets an embedded IAM consumer drain due work after
advancing time. External service-linked usage checks run outside the serialized
drain, so a slow checker cannot block report generation. A drain schedules those
checks without waiting for their external completion. Generation has actual
asynchronous work with no invented delay.
Repository decorators in the tests hold that work before storage acquisition to
exercise pending states without wall-clock sleeps. Shutdown cancels and joins
the driver; request cancellation is not inherited by already committed jobs.
Worker wakes precede response delivery, so client backpressure cannot prevent
committed work from starting.

## Credential data and AWS evidence

The CSV includes root and current users, actual login profile state, password
history/rotation, assigned MFA, long-term keys and signing certificates. It
excludes STS sessions, local bootstrap signing fixtures, SSH keys and
service-specific credentials. Root recovery profiles created through AssumeRoot
contribute local password-presence/date fields; their immediate AWS CSV behavior
still needs positive live verification. Root MFA, persisted keys and signing
certificates contribute their actual state. See [root access](iam-root-access.md).

Password history retains the first use within a five-minute span; long-term key
history retains the first date, service and region within a fifteen-minute span.
These windows are anchored to the recorded use, not undocumented wall-clock
buckets. Temporary sessions retain their separate per-request usage for role
history. Zero-epoch use is distinct from an unused credential. The
[AWS report guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)
documents the reporting windows and sentinel meanings.

The reproducible probe is
[`scripts/aws/iam_credential_report_probe.py`](../scripts/aws/iam_credential_report_probe.py).
Its sanitized [fixture](../testdata/aws/iam/credential_report.json) captures eleven
API cases and ten owned user rows. All 24 temporary resources and credentials
were deleted, with cleanup/absence verification recorded in the fixture. Other
account users and root secrets are absent from the fixture; only safe root
shapes and aggregate ordering observations are retained.

Observed differences from the current guide are preserved explicitly:

- The live normal-state report has 22 columns, ending at `cert_2_last_rotated`.
  The guide also describes `additional_credentials_info`. More than two imported
  keys/certificates exceed the currently enforced lifecycle quota and fail closed.
- Inactive keys and certificates retain their rotation timestamps in the live
  report. Missing credentials use `N/A` instead.
- Dates use UTC `Z`; rows use LF without a trailing newline. The root row is
  first and user ordering is case-insensitive. Cached bytes survive mutations
  and deletion of resources included in the report.
- Captured key pairs are consistent with ascending key ID and mixed certificate
  pairs place inactive entries first. Same-status certificate date/ID ordering
  is a deterministic local choice, not an established AWS ordering guarantee.

The probe could observe Get's pending error but not Generate's brief
`INPROGRESS` state. Four-hour aging, longer usage propagation and a report with
more than two credentials were not observed. Existing account password policy
and root settings were not changed. The fixture states those limits.

`credential_report_rows_replay_test.go` compares all ten owned rows exactly;
the SDK lifecycle suite also checks permissions, typed errors, raw Base64,
cache boundaries, reconstruction, concurrent generation, canceled/failed
commits and account/partition isolation. Local row tests cover credential
mutations, password expiry/reset, root credentials, escaping, zero epochs and
generation failures. These tests are evidence for their stated cases, not a
claim of complete IAM parity.
