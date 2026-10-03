# Organizations effective management policies

`DescribeEffectivePolicy` returns the published management-policy view for an
account, combining attachments at the account, its parent OUs and its root. Generated Smithy contracts own request and
response binding. SCPs and RCPs continue through their separate authorization
intersection rules; this API rejects them as AWS does.

## Inheritance and account access

The resolver walks from root to account. At each level it uses the first
assignment in attachment order, applies all appends, then applies all removals.
Appending deduplicates values. Child-control operators intersect across peers and
remain restrictive down the hierarchy. Controls on a logical container do not
implicitly lock every nested setting: the native tag-policy capture changes a
nested value beneath a container with `@@none`.

Attachments now retain their order within each target. Detaching and reattaching
a policy changes its precedence. The existing SQLite `position` column stores
that order; no separate ordering ledger is required. Previously retained rows
keep their recorded order, because an earlier attachment time cannot be recovered
from an unordered historical map.

Members can read their own effective policy with IAM permission. The management
account owns the account resource ARN used for authorization, including the
`aws:ResourceAccount` condition. A member's account ID is not the resource owner.
Management and authorized delegated callers can select other organization
accounts. Roots and OUs are invalid targets, and accounts outside the organization
are not visible. A disabled policy type returns `EffectivePolicyNotFoundException`;
an enabled tag-policy type with no attachments returns an empty JSON object.

The native probe also exercises actual STS session policies. AWS accepts an empty
session-policy `Condition` object, so session parsing now treats it as imposing
no conditions. IAM stored-policy validation retains its separate contract.

## Tag policy behavior

Tag policy keys merge without regard to case. Their default tag-key spelling is
lowercase, and an omitted tag value resolves to `*`. Empty rules still create
those defaults; removing all explicitly inherited values retains an empty list.
AWS converts numeric, Boolean and null tag values to strings before merging.
Duplicate logical keys differing only in case, mismatched tag-key assignments,
unknown fields, non-array value operators, object values and multiple wildcards
in a tag value are rejected.

The validator uses generated resource support data from AWS's
[supported-resource table](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_supported-resources-enforcement.html).
Run `python3 scripts/aws/tag_policy_resources_capture.py` to regenerate it from
the current AWS page, or pass `--html` with a downloaded copy. The checked-in Go
data works offline. Basic enforcement and required-tag reporting use the table's
separate columns; for example, `ecs:ALL_SUPPORTED` is accepted and `ecs:*` is
rejected by the native capture.

This validates policy configuration. Enforcing tag policy decisions during
resource creation/tagging and publishing compliance reports remain work in the
owning service integrations.

The effective document is limited to 395,000 UTF-8 bytes after defaults and
inheritance, and each resource type can require at most 50 unique tag keys.
`ListEffectivePolicyValidationErrors` reports `ELEMENTS_TOO_MANY` with the
native message and path. Required-key errors list contributing policies; the
native oversized-document error has an empty contributing-policy list.

## AI services opt-out admission

Create and content-changing UpdatePolicy requests validate the `services` tree,
supported service names, the `opt_out_policy` field and case-sensitive `optIn` /
`optOut` assignments. AWS accepts empty services, empty service fragments and
empty settings; it rejects unknown service names even when their fragments are
empty. Stored source text is preserved. Rejected updates retain the previous
content, name and description atomically in both memory and SQLite.

Service names are generated from the current
[AWS syntax reference](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out_syntax.html)
by `python3 scripts/aws/ai_policy_services_capture.py`; `--markdown` accepts an
offline copy. The checked-in Go table works without network access. Native
CreatePolicy captures cover every generated name, including the `q` entry and
the separate `connecthealth::operations` / `connecthealth::training` keys.

The native captures accept child controls containing `@@append`, `@@remove` and
`@@all`, including combinations with `@@assign`. These accepted controls do not
make append/remove value operations valid under a service setting. Duplicate
controls and `@@none` combined with another operator are malformed. Tag and
backup captures confirm those same shared control rules and duplicate JSON-key
rejection. Parsing detects duplicate keys before decoding can discard them.

At the AI document root, AWS accepts unused assign/append/remove operators with
scalar, null or flat scalar-list values, while rejecting object or nested-list
values. Admission preserves that distinction without admitting these operations
on service containers. This is a native admission observation, not a documented
inheritance guarantee.

The September 13, 2026 captures are `organizations_ai_policy.json`,
`organizations_ai_policy_details.json`, `organizations_ai_policy_updates.json`,
`organizations_tags_controls.json` and `organizations_plans_controls.json` under
`testdata/aws/iam`. They use owned, unattached policies and record successful
cleanup. No AI preferences, account memberships or enabled policy types changed.
SDK replay exercises admission plus successful and rejected updates; AI effective
defaults, propagation, validation reports and owning-service enforcement still
require native conformance and implementation. Existing account preferences were
not changed to test opt-out effects that can delete historical training content.
A fresh SQLite deployment was also exercised with the real AWS CLI: generated
`q` service admission, root null operators, rejected-update atomicity, process
restart and a subsequent valid empty-fragment update all passed.

## Chat application policies

Chat policy admission validates the Slack, Microsoft Teams and Chime settings
described in the [AWS syntax reference](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_chatbot_syntax.html).
The organization default belongs under `chatbot.default`; the native API rejects
`chatbot.platforms.default` even though one example on that page places it there.
Client values, role settings, channel types, workspace selectors, tenant/team
selectors and both override hierarchies have separate validation contracts.

`scripts/aws/chat_policy_shapes_generate.py` derives identifier patterns from
the SDK's `chatbot.json` Smithy model; `--model` accepts another source copy.
The captured source revision is `113bc91bf12edc3af1d3aba1c70be28494d54c2a`.
Slack identifiers use uppercase letters/digits with a maximum length of 255.
That limit applies to each identifier, not the number of workspaces. Native
Organizations admission further requires lowercase Teams UUIDs, although the
SDK UUID pattern accepts either case. Override keys require concrete identifiers;
workspace and tenant/team selectors also accept wildcards. List operators retain
their native scalar conversion and duplicate handling.

Chat field names, inheritance operators and child-control names are insensitive
to case. Duplicate object keys differing only in case are rejected. Child-control
lists reject exact duplicate strings, but permit spelling variants such as
`@@assign` together with `@@Assign`; a `@@none` control cannot be combined with
another entry. Client/channel/role values retain their case-sensitive enums.
Like AI policies, chat policies admit unused scalar or flat scalar-list operators
at the document root. Source policy text is retained unchanged.

Publication lowercases every key, including Slack override identifiers that had
to be uppercase at admission. Peers merge through the shared inheritance rules.
Empty fragments disappear from the effective document; source-only controls do
not produce empty objects. Updates and detachments regenerate the cached view
through the shared scheduler. Validation reports read the published diagnostics;
the native valid-policy response omits `Path` and `EvaluationTimestamp`.

The September 13, 2026 `organizations_chat_policy*.json` admission captures and
`organizations_chat_effective.json` under `testdata/aws/iam` cover these rules.
Publication probes apply overrides only to a uniquely named unused workspace on
one existing member. They restore policy types, account membership and trusted
service access, and delete their owned policies. SDK replay covers memory and
SQLite, including recovery with pending updates. These captures do not establish
complete downstream enforcement by Amazon Q Developer chat configurations or
every effective-document size/diagnostic limit; those remain in the management
policy completion audit.
A fresh SQLite deployment also passed AWS CLI checks for source/published casing,
rejected-update atomicity, a pending peer merge after process restart, empty
fragment publication and validation-report metadata.

## S3 policies

`S3_POLICY` admission validates the documented
`s3_attributes.public_access_block_configuration` scalar assignment (`all` or
`none`) through the existing declarative grammar. Native field names, operator
names and child-control values are case-insensitive; assigned values remain
case-sensitive. Source content retains its spelling. Empty settings can inherit
an assignment; empty effective fragments disappear. Publication uses the same
retained jobs and root/OU/account inheritance path as other management policies.

The S3 consumer reads the **published** value, not a fresh merge of attachments.
Both values override retained account settings and prevent account-level edits.
`none` disables the account-level flags even when the retained configuration was
restrictive; bucket settings remain independent. Detachment/empty publication
restores retained account settings, while disabling the policy type removes the
override immediately. No second state store, propagation scheduler or public
DescribeEffectivePolicy call sits between the services.

`testdata/aws/s3control/s3_policy_admission_evidence.json.gz` retains 62 native
create/update outcomes on uniquely named, unattached policies. Creation did not
require enabling the policy type. The capture covers scalar/schema admission,
child controls, casing and rejected replacement preserving the preceding policy.
AWS admits distinct case spellings of an operator, validates every supplied
assignment, and rejects exact duplicate keys and folded field-name collisions.
All seven owned policies were removed; no attachments, policy-type settings,
account protections or memberships changed. A compact SDK fixture checks retained
admission on both backends; the actual SQLite-backed executable matched all 62
captured admission outcomes.

`testdata/aws/s3control/organization_block_replay.json` drives actual Organizations,
S3 Control and object requests on memory/SQLite, including pending-publication
reopen, denied account writes, restoration, bucket restrictions and explicit IAM
denial. The executable AWS CLI workflow also resumed a pending `none` update and
restored the original account mask after detachment. These are
documentation-backed local publication/enforcement scenarios, not native AWS
policy attachments. An uppercase source also survived executable restart,
published into all four S3 account flags and restored the original settings after
detachment. Native effective precedence for operator case aliases, S3 policy
diagnostics, conflict/default/propagation conformance and broader membership
transitions remain open; validation-report APIs do not fabricate S3 diagnostic
success.

Sources:
[S3 policy behavior](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3.html)
and [syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3_syntax.html).
The [S3 contract](cloudtrail.md#s3-ownership-acls-and-public-access) owns wire,
enforcement, evidence and account-state boundaries.

## Backup policy validation

Backup admission validates plans, rules, regions, selections, lifecycle settings,
copy destinations, tags, advanced settings, indexing and scanning configuration.
The supported resource selection patterns are generated from the
[AWS backup policy syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_backup_syntax.html)
by `scripts/aws/backup_policy_resources_capture.py`; `--markdown` accepts an
offline source copy. Source policy content is retained unchanged. Parsing preserves
numeric spelling: native admission distinguishes integer `60` from decimal `60.0`.

Partial backup fragments are allowed at admission. Empty fragments disappear
during inheritance; a nonempty combined plan requires rules, regions and selections.
Required fields, empty resolved lists, the ten-rule limit and scanning dependencies
produce diagnostics with the contributing policy IDs. A selection using conditions
does not require an explicit resource-type list. Valid effective documents retain
the supplied fields and literal `$account` placeholder; no defaults are invented.

Native admission requires explicit compatible retention for continuous backups and
rejects continuous backups with cold-storage transitions in the same source rule.
Archive opt-in requires compatible retention and an appropriate schedule, including
when it belongs to a copy action. The calendar parser supports ranges, steps,
lists, month/weekday names, last/nearest weekdays, offsets and ordinal weekdays.
Native admission accepts an omitted year and ignores fields beyond the sixth even
though AWS documents the six-field form.

Schedule admission uses the next two occurrences after request time: ordinary
backups require at least an hour between those occurrences, and archive backups
require at least 28 days. A schedule with fewer than two remaining occurrences is
rejected. This algorithm is inferred from native time-boundary, finite-year,
leap-day and multi-selector captures. It is not a claim that AWS guarantees every
later interval. For example, `cron(0 5 1,29 JAN,FEB ? *)` can pass archive admission
before January because its next occurrences are January 1 and January 29, even
though February 1 follows just three days later. Validation uses the shared service
clock; SDK replay pins that clock to each capture's time.

Reading stored policies does not rerun request-time admission. A native rollover
capture admits a schedule, waits for one occurrence, then successfully reads the
policy and changes its description while resubmitting the same content is rejected.
Publication parses and normalizes admitted sources independently, so elapsed time
does not turn an accepted source into a read failure or a stuck publication job.

The combined-policy validator checks inherited continuous-backup retention and
archive schedule/retention dependencies, with diagnostics identifying the policies
that supply the conflicting settings. Copy-action conflicts are reported at their
owning rule path, matching AWS. Multiple conflicts return separate diagnostics and
withhold the whole invalid document. Identical conflicts from multiple copy actions
coalesce into one diagnostic before storage and pagination. Native Organizations does not flag an inherited
cold-storage setting on a continuous rule, even though the single-source admission
rejects that combination; the effective validator preserves that distinction.

Organizations validation is separate from Backup execution. For example, the live
capture accepts a 30-day cold-storage transition with 60-day deletion at both
admission and effective-policy validation. Backup's documented cold-storage
retention requirement is a downstream contract; this report must not invent a
diagnostic that Organizations does not produce. Creating/executing Backup plans,
IAM role/vault checks and downstream failure reporting remain with that service.

## Validation reports

`ListEffectivePolicyValidationErrors` uses generated request/response binding,
account-resource IAM authorization and deterministic, scoped pagination. Management
and authorized delegated callers can inspect organization members. Ordinary members
are denied. Disabled types and unknown accounts retain their modeled errors.
Malformed input reasons are replayed through both standalone and gateway endpoints.
Tag, backup and chat policy reports are supported. Other management policy types
return an explicit unimplemented error until their service validators exist.

If any combined plan or tag rule is invalid, the entire new effective document is
withheld. The account retains its last valid document, rather than a partial set of
valid plans. With no previous valid document, the published content is `{}`.
The generation timestamp still advances on a completed invalid evaluation, as
observed on AWS. Reports contain the evaluation path and time only while errors
exist; clearing all errors removes both fields.

Report diagnostics, contributing IDs and the evaluated hierarchy path are part of
the published view. An update or account move leaves the old report readable until
the service-time worker finishes, including after a process restart. Native report
error ordering and contributor ordering vary; SDK replay compares those as sets.

## Publication and persistence

Policy updates, attachment changes, account movement and membership publication
schedule regeneration for affected accounts. Reads retain the last published
content and timestamp until the shared service-time worker publishes the latest
hierarchy. Metadata-only and identical-content updates also schedule publication.
Several mutations before publication coalesce into one pending job per account
and policy type, carrying the latest request origin. Before an account's first
publication, the API returns `EffectivePolicyNotFoundException`.

The local delay is one second of service time. This is a deterministic interval
for exercising asynchronous behavior, not an AWS latency guarantee. The native
capture observed prior views before convergence, and rapid updates converging
to the final document. AWS documents
[eventual visibility of changes](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_troubleshoot.html).
Use the shared clock and job drain to settle work without wall-clock sleeps.

Disabling a type removes its attachments and gates reads immediately. The cached
view remains while a pending job regenerates the empty policy. Re-enabling before
that publication can briefly expose the cached policy, as observed on AWS.
Removing an account or deleting the organization removes its cached and pending
views; a stale worker cannot recreate them. Membership joins schedule inheritance
from the new hierarchy.

SQLite migrations 17 and 18 replace timestamp-only rows with typed published
content, pending deadline and request-origin columns, and add typed journal
payloads. Policy/hierarchy mutations and `SCHEDULED` events commit together.
Publication clears the pending job and commits the new view and `PUBLISHED` event
in one transaction. Removal commits a `REMOVED` event. Revision conflicts discard
stale calculations; append errors, cancellation and failed commits leave the
previous view and pending job intact. The journal remains an inspection log,
without external delivery inside transactions.

Restart resumes pending work and preserves the previously published view.
Legacy schemas lack cached content, so migration schedules ordinary regeneration
of enabled account views. The worker supplies the actual new publication time;
it does not invent a historical document, timestamp or request origin.

Migration 19 adds typed error and contributing-policy rows plus the evaluated path.
Diagnostics commit with the effective view, pending-job removal and existing
`PUBLISHED` event. Failed appends, commits and cancellation preserve the previous
report, content and pending work. Pre-19 tag/backup content was not validated and
cannot be treated as a last-known-valid document: migration clears those cached
views and schedules regeneration while preserving pending origin/deadline fields.

## Evidence and remaining scope

The [native capture](../testdata/aws/iam/organizations_effective_policy.json) and
[probe](../scripts/aws/organizations_effective_policy_probe.py) use uniquely named,
non-enforcing tag policies on the designated organization. They do not move
accounts. Cleanup detaches/deletes the owned policies, restores tag policies to
disabled and checks original membership. Captures include inheritance,
reattachment order, defaults, malformed policies, generation observations and
STS session restrictions. SDK replay covers those results through memory and
SQLite, including reconstruction. Additional SDK scenarios exercise OU movement,
account isolation, rollback and retained-schema upgrades.

The [publication capture](../testdata/aws/iam/organizations_policy_publication.json)
and [probe](../scripts/aws/organizations_policy_publication_probe.py) record nine
transitions: enable, attach, update, rapid updates, detach, reattach, disable,
re-enable and disable again. The capture includes polling times and full observed
content/timestamps. It uses one temporary non-enforcing member tag policy,
restores the original root policy types and checks unchanged membership.
SDK replay verifies old and settled views on memory/SQLite, pending recovery,
request-origin events and cache visibility across disable/re-enable. Additional
SDK tests cover failed commits/appends, cancellation, concurrent revision changes,
account creation, removal/rejoin and deletion with pending work.

The [validation capture](../testdata/aws/iam/organizations_policy_validation.json),
[limit capture](../testdata/aws/iam/organizations_policy_limits.json) and
[additional combined-policy cases](../testdata/aws/iam/organizations_policy_limit_details.json)
record actual tag/backup admission, reports and retained effective documents.
Their probes use owned non-enforcing policies, leave account membership unchanged
and restore original policy types and trusted-service access. Backup trusted access
is required to remain disabled; configured plans use nonexistent uniquely named
vaults/roles and nonmatching resource tags. No backup jobs are executed.
The `organizations_backup_*.json` fixtures record unattached policy admission,
including malformed input and cross-field cases. SDK replay covers these fixtures
and report transitions through memory/SQLite. Separate tests cover transaction
failures, pending moves/repairs across restart and pre-validation schema recovery.

The `organizations_backup_calendar*.json`, `organizations_backup_cron_grammar.json`
and `organizations_backup_cadence.json` captures exercise the admission calendar.
The [rollover capture](../testdata/aws/iam/organizations_backup_rollover.json)
records request times across a real schedule occurrence on one unattached policy.
The [inherited-dependency capture](../testdata/aws/iam/organizations_backup_inheritance.json)
and [copy-action capture](../testdata/aws/iam/organizations_backup_copy_inheritance.json)
record parent/child conflicts and repair. The copy capture waits 20 seconds before
settled observations: an earlier four-second sample briefly returned no diagnostics
before both conflicts appeared. This is evidence of eventual evaluation, not a
fixed AWS latency guarantee. Memory/SQLite replay verifies these reports, retained
documents and metadata-triggered publication across restart after admission changes.
The [multiple-copy capture](../testdata/aws/iam/organizations_backup_copy_duplicates.json)
verifies report coalescing. Additional calendar-selector captures distinguish
ordinary lists/ranges from AWS's interpretation of mixed ordinal/nearest-weekday
selectors; those cases use the same calendar parser as ordinary schedules.

A fresh AWS CLI deployment also resolves root/OU inheritance through an actual
STS session, retains that session and the generation across SQLite restart,
resumes a pending generation after restart, settles inheritance after an account
move, rejects another-account access and gates reads when its type is disabled.
A fresh validation deployment confirms pending invalidation/repair across process
restart, whole-document retention, contributing-policy IDs, paginated reports,
token account binding, ordinary-member denial through STS and removal of report
metadata after repair.
A fresh calendar deployment also verifies request-time rollover, metadata publication
after restart, inherited simultaneous archive conflicts, contributing policy IDs,
retained valid content and repair using the real AWS CLI against the local endpoint.

Primary contracts are the
[DescribeEffectivePolicy API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeEffectivePolicy.html),
[inheritance operators](https://docs.aws.amazon.com/organizations/latest/userguide/policy-operators.html),
[worked inheritance examples](https://docs.aws.amazon.com/organizations/latest/userguide/inheritance-examples.html),
the [tag-policy syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_example-tag-policies.html),
[validation report API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListEffectivePolicyValidationErrors.html)
and [invalid-policy behavior](https://docs.aws.amazon.com/organizations/latest/userguide/invalid-policy-alerts.html).

The shared merge grammar is available to other management policy types. Remaining
service-specific schemas, defaults, validation reports and service execution still
require implementation and native conformance. Additional service-owned behavior and timing
across other policy types and delegated-access edge cases remain part of the
completion audit. Organizations remains partial.
