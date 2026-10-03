# Centralized root access

IAM exposes the five generated Organizations root-feature APIs. Organizations
owns the two independent feature flags, IAM trusted access and IAM-specific
delegation. STS `AssumeRoot` issues usable, expiring root credentials for an active
member account. IAM remains incomplete; this is an implemented dependency slice,
not a claim of complete IAM or STS parity.

## Feature ownership and authorization

`ListOrganizationsFeatures`, `EnableOrganizationsRootCredentialsManagement`,
`DisableOrganizationsRootCredentialsManagement`, `EnableOrganizationsRootSessions`
and `DisableOrganizationsRootSessions` require their IAM permission on `*`.
The account must belong to an ALL-features organization with trusted access for
`iam.amazonaws.com`. The IAM APIs do not require caller `organizations:*`
permissions and do not automatically enable trusted access.

Listing and disabling accept the active management account or an active IAM
delegated administrator. Enabling requires the management account: AWS returns
`CallerIsNotManagementAccountException` for the delegate. Successful native
transitions now establish both boundaries. Delegation for another AWS service
grants no IAM authority.

Each mutation reads Organizations state and authorizes inside IAM's authority
transaction. The typed Organizations repository joins that transaction through
its context; feature writes remain staged until IAM commits. Failed or canceled
authority callbacks roll back the feature change. The Organizations source's
standalone use retains optimistic revision checks and authorization retries.
Feature state is preserved across service reconstruction with the same backend.
Disabling IAM trusted access makes the flags inaccessible; native re-enablement
preserves both flags. Organizations refuses to disable trusted access while a
delegate remains registered, with `ConstraintViolationException` and reason
`DELEGATED_ADMINISTRATOR_EXISTS_FOR_THIS_SERVICE`. Rejection preserves the state.
Neither root-feature transition deletes or restores any existing root credential.

## Root sessions and task enforcement

The caller must be an IAM user or assumed role in the management account or an
IAM delegated account. Ordinary root credentials cannot assume root. The request
requires explicit `sts:AssumeRoot` permission on the target root ARN, including
applicable caller boundaries, session policies and SCPs. `sts:TaskPolicyArn`
conditions restrict the selected task. The target account has no role trust policy;
Organizations membership, delegation and the applicable enabled root feature
supply the account relationship check. Eligibility uses current committed state locally; AWS's
transient views after revocation are described below.

The API accepts a member account ID or its root ARN, a documented AWS root-task
policy, and a duration from zero through 900 seconds, defaulting to 900. A zero
lifetime expires at issuance, including at a zero virtual-clock epoch.
The live task matrix is:

| Feature | Permitted task policies |
| --- | --- |
| RootCredentialsManagement | IAMAuditRootUserCredentials, IAMDeleteRootUserCredentials, IAMCreateRootUserPassword |
| RootSessions | S3UnlockBucketPolicy, SQSUnlockQueuePolicy |

Neither flag implies the other. In particular, RootSessions alone denies the
three IAM credential tasks. This corrects the earlier local interpretation of
the broader documentation's password-recovery wording. Regional
endpoints accept the operation; the global STS host returns `InvalidAction`.

The existing signed-session authority validates current IAM credentials and
permissions and inserts the session in one IAM transaction. Failed or canceled
commits return no credentials. Organizations eligibility joins the same memory
transaction, so a concurrent organization mutation cannot change eligibility
between the check and publication. Source identity comes from the current caller.

Issued credentials identify the member account root. The selected managed task
policy's current document is retained in the credential. All five captured AWS
task policies are deny-only ceilings on root's inherent permissions: a missing
Allow statement does not deny a permitted task. Explicit task denials precede
resource grants; target-account SCPs still apply. `aws:AssumedRoot=true` comes
only from trusted session metadata and cannot be supplied through request or
session context. Ordinary root credentials do not have this key.

The implemented IAM task paths audit root identity, keys, certificates, login
profile and MFA; delete root keys/certificates/login profiles and deactivate root
MFA; and enable root password recovery with `CreateLoginProfile`. Root recovery
has its own typed profile and accepts no user name or password. It is not an IAM
user password verifier. Account summary and credential reports consume that
profile. Completing recovery through the account email is outside the IAM API.
Bootstrap test keys remain operator fixtures rather than persisted root keys.
Organizations-created accounts use the recorded account creation date in root
GetUser and credential reports, even if first IAM use occurs later. Invited
account join dates are not substituted for unknown creation dates.

The SQS task can read and change a same-account queue policy even when that policy
denies every principal. Task restrictions and SCPs remain enforced. Other queue
actions do not acquire this exception. S3 task credentials have the correct task
policy, but S3 operations remain unimplemented and return protocol errors.

Root responses omit IAM-user-only fields rather than inventing a user name or
path. The shared response serializer follows service output presence and does
not reject nil fields merely because the SDK model marks them required. Request
required-field validation remains generated. The earlier per-field corrections
for pending last-access responses were removed; their AWS replay tests remain.

## Evidence and limits

`scripts/aws/iam_root_access_probe.py` captured
`testdata/aws/iam/root_access.json`: 32 observations, including feature permissions,
missing trusted access, regional/global STS routing, target/task/duration validation,
and fresh public documents for all five root-task policies. Twelve cleanup records
confirm owned resource removal and final user-deletion verification. The real organization was in
ALL mode but IAM trusted access was disabled. No existing organization settings
or root credentials were changed; there was no successful live AssumeRoot session.

The five captured public documents match the embedded managed-policy catalogue.
In particular the live IAMDeleteRootUserCredentials document still contains
`iam:DeleteVirtualMFADevice`, despite a conflicting documentation changelog.

The subsequent
[`root_sessions.json`](../testdata/aws/iam/root_sessions.json) capture contains 91
observations from 2026-09-12, including successful member-root sessions. The
probe temporarily enabled IAM trusted access, both root features and an IAM
delegated administrator in the existing all-features organization. It used two
existing member accounts and their initial access roles. After confirming the
target had no root profile/password, it created and deleted only a temporary
recovery profile. The probe supplied no password and did not change root keys,
certificates or MFA devices. Final native reads show empty feature and delegate lists, IAM
trusted access disabled, no recovery profile, and AccountPasswordPresent zero.
Temporary STS credentials were kept in memory and expire after 900 seconds.

The captured root GetUser omits UserName and Path. Create/GetLoginProfile omit
UserName, return the creation timestamp and PasswordResetRequired false, and
duplicate creation returns EntityAlreadyExists. Recovery profile creation sets
AccountPasswordPresent to one. A report generated after creation contains
password_enabled true, password_last_used no_information, the profile timestamp
as password_last_changed and password_next_rotation not_supported. Deletion
removes the profile and resets the summary flag. These fields now have native
evidence, replayed through the SDK in
[`integration/root_credentials_aws_test.go`](../integration/root_credentials_aws_test.go).

A separate native check performed CreateLoginProfile, GetLoginProfile,
GetAccountSummary and DeleteLoginProfile with only RootCredentialsManagement
enabled. All succeeded with the same profile and summary transitions, establishing
the recovery behavior beyond successful AssumeRoot issuance alone.

Removing a delegate or IAM trusted access affected IAM feature reads immediately.
Regional STS sometimes continued issuing new root sessions: a timed delegation
probe returned deny at zero seconds, allow at 15 seconds, then deny at 60 and
180 seconds; a fresh role session at the final check was also denied. After
trusted-access removal, issuance succeeded through 60 seconds and was denied
at 180 seconds. These are bounded observations, not a fixed propagation SLA.
Issued root credentials continued to call GetUser after these changes and after
both root features were disabled. Local eligibility changes affect new issuance
immediately; the transient STS views remain a marked implementation gap. No
additional revocation mechanism is applied to already-issued credentials.

[`iam_root_sessions_probe.py`](../scripts/aws/iam_root_sessions_probe.py) now
captures the task matrix, recovery profile and timed revocation observations.
The committed evidence includes follow-up timing probes after the initial run
discovered that trusted access cannot be disabled with a registered delegate.
The recovery report was fresh in this capture; AWS may return a cached report
on a quick rerun, which cannot establish a new profile's report fields.

Local signed SDK tests cover task issuance, root credential transitions, identity
and resource scoping, independent features, delegation, SCP enforcement, queue
policy recovery, expiry and rejection of implicit root ownership for role calls.
Repository tests cover cancellation, rollback, concurrent feature writes and
reconstruction. Nonempty native root key/certificate/MFA response fields and
completed password recovery through account sign-in still require further audit.

Primary contracts: [centralized root access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html),
[privileged tasks](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user-privileged-task.html),
[AssumeRoot](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html),
[CreateLoginProfile](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html),
[GetLoginProfile](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetLoginProfile.html),
and [aws:AssumedRoot](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-assumedroot).
