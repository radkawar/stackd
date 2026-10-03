# Organizations all-features migration

`EnableAllFeatures` starts the standard migration from consolidated billing to
all features. It creates actual consent handshakes. Member acceptance restores
required IAM service-linked roles, and management finalization changes the
organization's feature set. This workflow uses the shared handshake repository,
IAM transaction boundary, service clock and journal.

## Requests and authority

The migration has a management-owned `ENABLE_ALL_FEATURES` parent. Invited
members receive `APPROVE_ALL_FEATURES` children. Created members receive
`ADD_ORGANIZATIONS_SERVICE_LINKED_ROLE` children only when their protected
Organizations service-linked role is absent. Accounts created through Organizations
otherwise require no additional consent.

The parent remains `REQUESTED` while a current member's required approval is
outstanding. After those approvals, it becomes `OPEN`; management must explicitly
accept it to reach `ACCEPTED` and set the organization to `ALL`. An organization
with no required member approvals begins with an `OPEN` parent. Member acceptance
alone does not finalize migration. Root policy types remain separately controlled
through `EnablePolicyType`; migration does not silently attach an SCP.

IAM policies gate the parent and child operations against the actual handshake
ARN and management owner. Members cannot finalize the parent, and management
cannot accept a member's consent request. Restoring a missing service-linked role
requires the accepting caller's `iam:CreateServiceLinkedRole` permission. Existing
roles are reused without that additional permission. Role inspection and
finalization share the native IAM/Organizations transaction, so a concurrent role
deletion cannot invalidate the committed role check.

The same Organizations service-linked role is provisioned when accounts join
both feature sets. Consolidated billing permits deleting it; all-features
membership requires retaining it. This follows the
[AWS service integration contract](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html).

## Membership, time and recovery

Starting migration cancels pending membership invitations made under consolidated
billing. New invitations during migration offer `ALL`. Accepting that offer both
joins the account and records its consent, so it does not receive a redundant
approval request. Canceling migration cancels its still-pending child requests
and unaccepted membership offers. A declined request remains declined; management
can cancel the attempt and begin another. Removing an outstanding voter cancels
its pending child and updates parent readiness.

Migration has a 90-day service-time deadline. Expiry marks the parent `EXPIRED`
and cancels its remaining requests. The request path and worker observe the same
deadline, including quota reservations. A new migration and its offers survive
later draining of the previous attempt's expired jobs. These membership and
deadline rules follow the
[migration considerations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html)
and [standard workflow](https://docs.aws.amazon.com/organizations/latest/userguide/manage-begin-all-features-standard-migration.html).

Terminal handshakes have a 30-day retention period. A migration therefore retains
required-account approval state independently of its child history; deleting an
old accepted handshake cannot erase consent while the parent is still active.
This is derived from the migration's 90-day window and the
[handshake retention contract](https://docs.aws.amazon.com/organizations/latest/APIReference/API_Handshake.html).

SQLite migrations 14 and 15 generalize the retained invitation tables to
handshakes, add action/parent relationships and persist required-account approval
state. Existing invitation rows and events retain their identities and gain the
known `INVITE` action. The public journal now uses `handshake_changed_v1`, including
action and parent ID. Start, consent, readiness, cancellation, expiry and
finalization events commit with their resource changes. A failed append, commit
or canceled transaction cannot publish a partial family of requests.

## Evidence and limitations

AWS's [EnableAllFeatures API](https://docs.aws.amazon.com/organizations/latest/APIReference/API_EnableAllFeatures.html)
and worked standard-migration examples determine the parent/child flow.

There is a documentation discrepancy: the current Handshake/AcceptHandshake prose
reverses the parent and member action descriptions relative to the
[worked CLI examples](https://docs.aws.amazon.com/organizations/latest/userguide/manage-begin-all-features-standard-migration.html)
and EnableAllFeatures' finalization instruction. The implementation follows the
worked examples: management accepts `ENABLE_ALL_FEATURES`, and invited members
accept `APPROVE_ALL_FEATURES`. This discrepancy remains part of the native
migration audit.

The [owned AWS capture](../testdata/aws/iam/organizations_features.json) records
already-ALL and member rejection plus ignored-field behavior. The
[probe](../scripts/aws/organizations_features_probe.py) requires an already-ALL
organization, starts no migration, and verifies its feature set and original
memberships remain unchanged. SDK replay verifies the already-ALL error/reason
and member denial. Existing invitation replay remains the source for shared
validation and INVITE semantics.

SDK integration tests cover real IAM users, missing-role dependency denial,
existing-role reuse, created/invited member differences, consent retained after
child cleanup, memory/SQLite reconstruction and finalization. An enabled SCP
subsequently denies SQS calls from migrated members. Failure injection verifies
that canceled invitations, new requests, feature changes and events roll back
together. Native SQLite upgrade tests retain prior invitation/tag/event data.

A fresh local CLI deployment also completed the workflow using SQLite and manual
time. Two members accepted consent across a 31-day advance and two server
restarts; management finalized migration, explicitly enabled SCPs, and attached
a policy that denied the migrated member's SQS `CreateQueue`. The retained parent
journal contained `REQUESTED`, `OPEN` and `ACCEPTED` transitions.

These checks do not establish a complete AWS migration capture. Native successful
migration, resend behavior, exact cancellation/expiry transitions, concurrent
membership and role changes, policy availability and error precedence remain
open. Consent notification delivery shares the explicitly deferred email work.
Assisted migration is a separate AWS console/support process; this public API
implements standard migration. Organizations remains partial.
