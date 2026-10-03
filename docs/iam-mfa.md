# IAM virtual MFA behavior

Virtual MFA uses generated IAM request and response bindings, real TOTP seeds and
QR codes, typed account/partition-scoped records and the IAM credential authority.
IAM and STS remain incomplete; the remaining MFA work is listed below.

## Implemented behavior

Creation returns a cryptographically random seed, its Base32 bootstrap bytes, a
scannable QR code and requested tags. Lists omit bootstrap secrets and tags.
Assigned virtual-device entries include the current user's public list fields
and enable date. Deactivation removes the association and its enable date, while
retaining the device's seed, tags, clock adjustment and synchronization history.
Deleting an assigned virtual device or its user returns `DeleteConflict`.
Assignment is exclusive to one immutable user ID and enforces eight devices per
user. Existing account, partition, authorization and transaction boundaries
apply to all these operations.

IAM users may enroll their first device using a long-term access key. Once they
have an associated device, adding or removing their own devices requires an
MFA-authenticated session, even when an identity policy otherwise allows the
operation. This check precedes duplicate-device and missing-serial errors and
uses the current immutable user ID. Resynchronization with valid code pairs and
authorized management of another user remain available to long-term keys. An
MFA session can remove the device that authenticated it and then the last remaining
device; with none assigned, the long-term key may enroll again. This implements
[AWS's self-management requirement](https://aws.amazon.com/security/security-bulletins/AWS-2023-001/).

Enrollment and resynchronization require consecutive codes. Both counters must
be newer than the previously accepted pair's second counter. Reusing a pair,
overlapping its second code or deactivating/re-enabling to reuse it fails.
Successful synchronization records the second counter and updates the device's
clock adjustment. Neither code is consumed for STS authentication. After the
binding propagates, either code can authenticate while it remains inside the
ordinary TOTP window, including after a newer code has authenticated. Separate
devices confirmed both orders for enrollment, resynchronization and same-ARN
replacement. Failed writes preserve the previous synchronization state.
Synchronization-pair history is distinct from STS code consumption: AWS accepts
a new pair containing STS-used codes when both are newer than the last IAM pair.
Resynchronization does not release a code already used to obtain STS credentials.
Independent captures check a previously used first or second code: the used code
remains rejected before and after the other, unused code authenticates.

The captured enrollment search accepts a second counter from **998 steps behind
through 1,000 steps ahead** of the device's adjusted time, inclusive. Each step is
30 seconds. A fresh device has no adjustment. Resynchronization searches around
the existing adjustment; it does not reset the search to server time. These
bounds are observations of AWS's private implementation, not a published AWS
guarantee. Tests replay both accepted edges and their adjacent rejected counters.

STS accepts a current TOTP counter within **two steps in either direction** of
the adjusted device time. An accepted code cannot issue another session while
it remains in that window, including after another valid code is used. Unused
codes can arrive out of order; a last-accepted-counter watermark would incorrectly
reject valid requests. Captures also accept the opposite window edge after a
successful verification at either edge; these sequences do not shift the accepted
window to the last authenticated counter. The IAM record retains only relevant used counters,
distinguished by seed when a deleted device's ARN is reused. Verification and credential insertion
share a write transaction: concurrent attempts consume a code once, failed or
canceled publication permits a retry, and storage failures produce an internal
service error rather than an incorrect-code denial. Those storage-failure and
concurrency cases are local regressions; the live fixtures establish the code
acceptance behavior, not fault injection into AWS's storage.

Authentication allows **nine verifications per device ARN in a three-minute UTC
window**. Successful, invalid and reused codes spend the same budget. Exhaustion
returns the unavailable-device `AccessDenied` message, distinct from the invalid
one-time-code message. Sibling devices have independent budgets. Replacing the
seed at the same ARN retains the budget. Invalid-code outcomes commit their
attempt count without issuing credentials; storage errors and cancellation roll
back the transaction. The counter and its UTC window live in the typed IAM record,
using service time with no wall-clock sleeps or provider-local cache.

This is an observed model, not an AWS rate-limit guarantee. Independent bursts
exhausted after nine verifications whether preceded by zero, one or three successful
codes. Quiet intervals of 30 through 120 seconds did not reliably restore access.
Three aligned captures recovered at 21:24, 21:30 and 21:33 UTC, roughly ten seconds
after exhaustion; other captures stayed blocked across intervening minute
boundaries. These observations support a shared three-minute boundary rather than
a cooldown measured from the last request.

IAM reports enrollment, deactivation, resynchronization and reassignment
immediately. STS sees an ordered projection of those bindings after **10 service-time
seconds**. This is a deterministic approximation of observed propagation, not an
AWS latency guarantee. The capture observed old bindings working 1–3 seconds
after transitions and changed bindings approximately 13–14 seconds later.
Independent enrollment polling first succeeded about eight seconds after enablement.
AWS documents [eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html),
without a fixed deadline for IAM changes.

Deleting a device removes it from IAM lists and counts immediately. Its typed
record retains the preceding STS binding until revocation propagates and retains
the verification budget until its window expires. Successful IAM transactions
then reclaim retired rows in that account and partition.
Recreating the same ARN preserves pending visibility while installing a new seed
and fresh synchronization history. The new seed has independent consumed counters.
Pending transitions, consumption and retirement participate in the existing
transaction; provider reconstruction retains them when using the same repository.
Previously issued MFA sessions retain their authentication context after device
changes. Resynchronizing or replacing the control resource cannot release codes
already consumed against a binding that STS still observes.

## Evidence

The checked-in captures use only uniquely owned users, access keys and virtual
devices. All 25 captures listed below, containing 755 observations, completed and
verified cleanup. Seeds, QR payloads,
authentication codes, credential secrets and issued sessions remain in memory;
fixtures retain normalized resource metadata, counter offsets and API outcomes.
Existing identities, root MFA, account policies and organization settings are
unchanged. Temporary STS credentials expire normally.

| Capture under `testdata/aws/iam` | Behavior checked |
| --- | --- |
| `mfa.json` | Assignment/deactivation, duplicates, ownership, delete conflicts and public response fields |
| `mfa_time.json` | Enrollment visibility, synchronization-pair history and rapid authentication attempts |
| `mfa_verification.json` | STS acceptance boundaries and immediate reuse, with separate users/devices for each offset |
| `mfa_reuse.json` | Interleaved valid codes, rejected reuse and synchronization after STS use |
| `mfa_pair_window.json` | Fresh-device enrollment search, both edges and adjacent rejections |
| `mfa_resync_anchor.json` | Repeated clock adjustments and retained adjustment after deactivation |
| `mfa_propagation.json` | Independent before/after deactivation, deletion, resynchronization and reassignment; issued-session continuity and enrollment visibility |
| `mfa_recreation_fresh.json` | Same-ARN replacement without an early attempt against the new seed; independent code consumption across keys |
| `mfa_recreation.json`, `mfa_recreation_adjusted.json` | Supplemental replacement timing and authentication observations, including unresolved transient denials |
| `mfa_code_order.json` | Unused earlier counters accepted after later counters, with separate devices for each sequence |
| `mfa_self_management.json` | First enrollment, mandatory MFA for self-management, error precedence, resynchronization, administrator access and re-enrollment |
| `mfa_rejection.json`, `mfa_rejection_threshold.json` | Invalid bursts around the limit, independent sibling-device budgets and quiet-period retries |
| `mfa_rejection_no_baseline.json`, `mfa_rejection_success_count.json` | Nine verifications regardless of whether zero, one or three successful codes precede invalid codes |
| `mfa_rejection_recovery.json` | Independent devices remain blocked after 75, 90, 105 and 120 quiet seconds within the same UTC window |
| `mfa_rejection_aligned.json`, `mfa_rejection_aligned_second.json`, `mfa_rejection_odd_boundary.json` | Exhaustion just before three separate UTC boundaries and successful authentication immediately afterward |
| `mfa_recreation_limited.json`, `mfa_recreation_limited_delayed.json` | Exhausted ARN budgets survive seed replacement, including a gap after deletion, and recover at the next window |
| `mfa_synchronization_codes.json` | Both synchronization codes authenticate after enrollment, resynchronization and replacement, with independent devices for bootstrap-first and newer-code-first orders |
| `mfa_synchronization_reuse.json` | Resynchronization preserves STS consumption of either code in the pair while the other code remains usable |
| `mfa_authentication_drift.json` | Opposite TOTP-window edges remain valid after successful authentication at either edge; repeating a used counter fails |

Reproduce with `scripts/aws/iam_mfa_probe.py`, `iam_mfa_windows_probe.py`,
`iam_mfa_time_probe.py` (also `--reuse`) and `iam_mfa_pair_window_probe.py`
(also `--anchor`), selecting the corresponding `--output` paths for alternate
captures. The shared device helper registers cleanup before decoding bootstrap
material. Query probes preserve modeled MFA capitalization and nested inputs.
The additional `iam_mfa_propagation_probe.py` captures the transition matrix;
`--recreate` captures replacements, `--skip-early` omits the initial new-key attempt,
`--replacement-offset 4` adjusts the new device clock, and `--ordering` captures
out-of-order unused codes. Set `--output` to the corresponding fixture path.
`iam_mfa_self_management_probe.py` captures the mandatory self-management rule.
`iam_mfa_rejection_probe.py` selects invalid burst sizes with `--counts`, quiet
intervals with `--quiet-seconds`, preceding successful verifications with
`--valid-prefix 0|1|3`, and independent sibling devices with `--sibling`.
`--aligned` brackets a three-minute UTC boundary; `--odd-boundary` selects a
boundary outside a six-minute boundary. Reproduce limited replacement with
`iam_mfa_propagation_probe.py --recreate --exhaust --skip-early`, adding
`--replacement-delay 20` for the deletion-gap capture. Select each fixture with
`--output`; repeated runs retain their actual request times and outcomes.
`--synchronization-codes` checks bootstrap-code consumption with both call orders
after a 20-second propagation interval, aligned early in a TOTP step so code
expiry cannot explain rejection.
`--synchronization-reuse` checks that a pair containing an STS-used code leaves
that code consumed while allowing the other code to authenticate.
`--drift` checks opposite-edge sequences with fixed counters inside one TOTP step.
New captures record request start/end times and absolute synchronization counters
so a 30-second code boundary is distinguishable from propagation.

`internal/services/iam/mfa_aws_test.go` replays lifecycle errors and pair-window
transitions through the SDK. `integration/mfa_conformance_integration_test.go` exercises STS
windows, reuse and concurrent issuance through the assembled stack.
`integration/signed_session_authority_integration_test.go` covers failed/canceled credential
publication and MFA storage failure without consuming a code.
`integration/mfa_propagation_integration_test.go` checks the transition matrix and replacement
lifecycle. `internal/services/iam/mfa_propagation_test.go` checks ordered rapid
changes, failed writes, provider reconstruction and reclamation rollback. These
local deadline tests establish the deterministic model, not exact AWS timing.
The replacement tests replay the established lifecycle and key-isolation outcomes;
they do not claim all supplemental transient observations are implemented.
`integration/mfa_self_management_integration_test.go` replays the mandatory protection through
signed SDK requests and tests concurrent first-device enrollment locally. The
existing AssumeRoot integration suite covers the separate root-deactivation rule.
`integration/mfa_authentication_integration_test.go` replays the authentication captures through
signed SDK requests at their recorded service times, comparing error codes and
messages. It also checks concurrent verification and write, commit and cancellation
failures for both `AssumeRole` and `GetSessionToken`. Retirement tests ensure an
ordinary IAM request cannot discard an unexpired budget, and that reclaiming an
expired record rolls back on storage failure.

Primary references: [EnableMFADevice](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EnableMFADevice.html),
[ResyncMFADevice](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ResyncMFADevice.html),
[ListVirtualMFADevices](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListVirtualMFADevices.html),
and [MFA-protected API access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html).

## Remaining MFA work

- Explain transient replacement-device denials before claiming complete MFA
  behavior. The fresh replacement capture rejected its first bootstrap counter
  after accepting a newer code; the adjusted replacement capture rejected the
  first later authentication and accepted the next attempt with a different
  counter. Ordinary-device ordering captures accept unused earlier counters.
  These observations do not isolate replication timing from authentication state,
  so the implementation does not invent a cooldown or generalized ordering rule.
  The subsequent synchronization captures accept both bootstrap codes in either
  order after 20 seconds. They rule out unconditional bootstrap consumption as an
  explanation, but do not establish why the earlier, shorter-delay calls differed.
- Finish root MFA and hardware TOTP behavior, plus actual FIDO/WebAuthn enrollment
  and authentication. `GetMFADevice` is specifically a FIDO metadata API; it
  remains unimplemented. The public IAM API cannot enroll a FIDO key: AWS's
  [enrollment guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_fido.html)
  requires its console flow. A synthetic virtual-device success response would
  not implement that contract.
