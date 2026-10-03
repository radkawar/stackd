# Amazon MQ: standalone native brokers

Amazon MQ is a standalone service owner, independent of Lambda. Its generated
Smithy contract contains 25 operations. Registration is not conformance: `Promote`
currently validates current broker authority and rejects the missing native
replication relationship. The other operations expose the bounded behavior below.
**Whole-service completion remains open.**

## Actual execution and durable ownership

`internal/services/mq` owns scoped broker lifecycle, configuration revisions,
ActiveMQ users, tags and weekly maintenance admission. `storage/sqlite/mq` and
schema 283 retain normalized configuration/revision/tag, user/group and broker
configuration/history rows in the existing transaction domain; no resource JSON
blob or message ledger substitutes for an engine. Configuration and user mutation
acceptance commits with its API completion and durable pending work. Native calls
run outside transactions; version/due/operation comparisons fence stale results.
Schema 284 retains the maintenance-window adjustment count in the same broker
transaction. Older databases begin with an unused tracked budget; migration does
not invent historical adjustments or replace broker/configuration/user state.
Schema 285 retains effective/pending log flags, native file identities/byte
positions, delivery diagnostics and the next log collection deadline. Legacy
brokers start with logging disabled and no invented source position.

`compute/mq` runs the pinned real RabbitMQ 3.13.7 and ActiveMQ Classic 5.18.7
containers already selected by the runtime. Queues, deliveries, acknowledgements,
durable journals, authentication and authorization belong to those engines.
`Close` detaches; `DeleteBroker` removes only exactly owned native containers,
volumes and configuration directories before deleting the retained broker row.
A controller restart reconciles native identity before reporting a usable endpoint.
Lambda consumes the same unchanged `ResolveBroker`/`Connection` owner boundary.

RabbitMQ admission provisions IAM's protected `AWSServiceRoleForAmazonMQ` in the
same transaction as the broker, using the caller's `iam:CreateServiceLinkedRole`
authority and the captured `AmazonMQServiceRolePolicy`. An existing role is
reused without creation permission. ActiveMQ does not require this role. IAM
deletion checks all RabbitMQ brokers in the account across regions, including
pending creation/deletion, under a writable snapshot through the deletion
decision. A native broker must be removed before its dependency disappears.
The template is sourced for the commercial `aws` partition only.

`go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd roles` exercises
signed SDK denial/no-orphan admission, protected policy attachment, real
RabbitMQ startup, reuse under denied role-creation authority, retained role
identity after executable restart, blocked deletion and final cleanup.
The initial run exposed a read-only usage transaction that left deletion
`IN_PROGRESS`; the corrected writable boundary completed that retained job.
Memory/SQLite regression coverage verifies callback commit and rollback.
The successful rerun retained one successful and one rejected dependent IAM
creation event; reuse did not create another role. This is local executable
evidence, not native AWS error-message or audit-projection calibration.
RabbitMQ general logging uses this role at execution time, as described below.


ActiveMQ readiness completes native TLS/OpenWire wire-format negotiation without
creating a customer JMS connection/session. Customer ACLs can legitimately deny
connection advisories or every user and do not redefine engine health. Ordinary
JMS client checks remain the proof of authentication and destination authorization.
The restrictive advisory-enabled ACL reproduced the earlier reader-first startup
failure; the corrected native path remains healthy while the real reader is
denied, and also permits an intentional zero-user/deny-all broker.

Supported deployments are currently explicit public `SINGLE_INSTANCE` with
`mq.t3.micro`, SIMPLE authentication and the pinned engine version. Public client
endpoints are operator-local TLS loopback listeners, not AWS Internet DNS. No
private network isolation, replicated fleet or encrypted managed storage is
inferred from this mapping. Unsupported fields fail instead of becoming inert
metadata. Native failure preserves pending changes and prevents successful
RUNNING/configuration/user promotion.

### Configuration and user effects

Configurations may be created before brokers, described, tagged, listed,
versioned and deleted. Revisions retain their exact admitted data and creation
time. `UpdateBroker` selects a specific immutable revision (or the latest at
admission), not a pointer whose bytes can later change. Describe exposes current,
pending and prior configurations. Current/pending associations prevent deletion.
Updating configuration bytes alone does not update associated brokers.

New ActiveMQ brokers without an explicit configuration atomically create and
select an independent revision-1 `<broker-name>-configuration` resource. Its
initial bytes describe the installed runtime's admitted defaults. Broker tags
are not copied onto it. Successful create-token replay preserves the original
association even if the configuration has gained later revisions; rejected
admission and broker-write rollback cannot leave an orphan configuration.
This internal resource belongs to `CreateBroker` admission, not a second public
`CreateConfiguration` authorization request. Subsequent configuration APIs retain
their own current IAM checks.

`DeleteBroker` releases the association but does not delete the API configuration.
Delete it explicitly after the broker is gone. This ownership follows the
retained ActiveMQ maintenance capture, including its independently deleted
automatic configuration. The executable scenario verified SDK discovery,
cross-account denial, attached-configuration deletion protection, create replay,
SQLite/controller restart, retained JMS bytes and reboot-applied native ACLs.
The Lambda/MQ smoke now also retires its automatically created configuration.
Automatic resource materialization here is for newly created ActiveMQ brokers;
legacy records are not rewritten, and RabbitMQ bootstrap configuration remains
unchanged. The native capture does not establish identical AWS default XML bytes,
RabbitMQ automatic-resource behavior or configuration IAM error-code parity.

ActiveMQ `CreateUser`, `UpdateUser` and `DeleteUser` retain pending changes;
Describe/List show their status without revealing credentials. Successful native
reboot applies credentials, groups, console access and selected configuration
together. Failed native application leaves effective state unpromoted. Removing
the last user produces native deny-all authentication, not resurrection of
bootstrap credentials. Existing legacy users whose password was cleared from
the database retain owned native credentials when changing groups or console
access. Replication-user privileges still require an unavailable CRDR owner.

ActiveMQ exposes the installed native `/admin/` web console through an explicit
loopback HTTPS `ConsoleURL`. Only effective `ConsoleAccess` users enter its
dedicated realm; anonymous, image-default and messaging-only users are denied.
Pending grants, revocations, password changes and deletions do not hot-reload
before broker reboot. Native local JMX supplies administrative broker/queue
views; JMS-dependent browsing and sending use the HTTP user's current broker
credentials and destination ACLs. No remote JMX connector or Jolokia/API webapp
is enabled. The realm's OBF password representation is reversible encoding, not
encryption; the private owned state directory protects it.

Older containers gain the console through an exact-owned replacement retaining
the journal, keystore, customer credentials and JMS endpoint. Subsequent broker
and controller restarts preserve both console and JMS endpoints. Readiness
requires the native TLS authentication challenge without depending on a customer
being granted console access.

AWS's MQ user APIs do not apply to RabbitMQ. New RabbitMQ brokers instead expose
an authenticated real HTTPS management endpoint; its ordinary API owns subsequent
native users, permissions, queues and policies. Initial user definitions are
bootstrap-only and are not reimported on configuration reboot. Existing older
containers without a published management port are not advertised as having one.

A selected weekly maintenance window uses the shared service clock; pending user
or configuration changes become a retained reboot intent at that window. An
explicit reboot applies them sooner. Maintenance does not pretend to perform an
unavailable automatic engine upgrade. Accepted window time zones include UTC,
fixed offsets and installed IANA zone rules; AWS edge-case DST scheduling has not
been calibrated natively.
At most four changed maintenance windows are admitted before completed scheduled
maintenance. Repeating the current normalized window does not consume another
adjustment while budget remains, but AWS rejects even unchanged-window requests
after the fourth change. Invalid/rejected requests preserve the budget and window.
The count survives controller restart and manual reboot; claiming work or failing
native application does not reset it. A successful scheduled native reboot resets
the count and applies pending configuration/user work together. Manual reboot
applies pending changes without granting another adjustment budget.

### Native configuration admission

ActiveMQ input is base64 XML with the ActiveMQ core `broker` root. The allowlist
supports broker advisory/JMSX identity and scheduling booleans, destination
policies, initial queue/topic declarations and `authorizationPlugin` ACLs. User groups
feed the actual native authentication plugin; configured ACLs replace the default
ACL. Runtime-owned TLS, transport, storage and authentication-plugin definitions
cannot be overridden. XML directives/entities and processing instructions are
rejected. Schema-disallowed elements/attributes and property/SpEL attribute
expressions are removed with modeled warnings before native-capability validation.
Password expression delimiters remain rejected at the native execution boundary.

Destination policies admit one `sharedDeadLetterStrategy`,
`individualDeadLetterStrategy`, or `discarding` strategy per entry. Shared
strategies can select a named queue/topic or retain native `ActiveMQ.DLQ`;
individual strategies support queue/topic prefixes and suffixes, destination
type selection and per-durable-subscriber destinations. Native controls govern
expired/nonpersistent processing, audit enablement/capacity and DLQ expiration.
The broker, not the Go control plane, owns poison acknowledgements, redelivery
and DLQ message storage. Temporary DLQ destinations and object references remain
outside the admitted subset. Expiration on a wildcard DLQ policy can create
forwarding loops; scope expiring policies to source destinations.

The signed-SDK executable scenario exercised persistent/nonpersistent poison
messages, exact shared/per-queue DLQ payloads and original destinations, expired
message routing/discarding, and the discarding strategy against ActiveMQ 5.18.7.
It also verified inactive pending policies across SQLite/controller restart,
replacement rather than accumulation on reboot, stable JMS endpoints and DLQ
journal retention through another native reboot. This is local engine evidence,
not native AWS configuration sanitization or comprehensive topic/audit calibration.

RabbitMQ input is base64 Cuttlefish configuration. Implemented controls are
`heartbeat` (60–3600), `consumer_timeout` (0–2147483647 milliseconds),
`quorum_queue.property_equivalence.relaxed_checks_on_redeclaration`,
`management.restrictions.operator_policy_changes.disabled` and
`secure.management.http.headers.enabled` (literal `true`/`false`).
AWS's `consumer_timeout = 0` means infinity. The runtime translates it into
RabbitMQ's `advanced.config` `{consumer_timeout, undefined}` setting rather than
passing numeric zero to the engine. Returning to a finite value or omitting the
key clears that override. Both native configuration files are staged before
reboot; effective state is promoted only after the engine becomes ready.
Older containers acquire the advanced-config path through exact-owned container
replacement on reboot, retaining their journal volume, credentials and endpoints.
Unknown RabbitMQ settings are rejected, not silently accepted. Broader permitted
configuration and RabbitMQ sanitization/warning semantics remain open.

The two management controls default to true, following
[AWS's configurable values](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configurable-values.html).
Operator-policy editing is restricted by RabbitMQ itself, not an HTTP proxy.
The AWS security-header toggle translates to the pinned engine's native
`management.headers.content_type_options`, `management.headers.frame_options`
and `management.hsts.policy`: `nosniff`, `DENY` and
`max-age=47304000; includeSubDomains`. Explicit false removes these three headers;
explicit true or a later omitted-key revision restores them. Runtime-owned TLS,
listener and arbitrary header settings remain outside customer configuration.
Changes take effect only after successful native reboot; they do not erase
operator policies or queued messages.

`go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd rabbit-management`
verified signed immutable revisions, invalid-boolean rejection without new
revisions, pending settings, actual TLS management API mutation denial/permission,
exact security headers on API and console responses, and controller/SQLite plus
native reboot retention. Real AMQP publication/consumption proves a retained
`max-length=3` operator policy drops the oldest of four messages, including after
edits are restricted again. A separate persistent message survives the restarts.
Both false-to-explicit-true and false-to-omitted-key restoration are exercised.
Native HTTP 405 restriction responses are recorded as pinned RabbitMQ behavior,
not calibrated AWS error fidelity. No replicated HA policy is fabricated.

Relaxed quorum redeclaration also defaults to true for new/rebooted brokers,
matching AWS rather than upstream RabbitMQ's false default. Explicit false
restores strict checks; a later omitted-key revision restores true. The
`rabbit-quorum` executable scenario first reproduced AMQP 406 against the old
default, then verified default/strict/relaxed/omitted transitions, inactive
pending revisions across SQLite restart and an actual persistent quorum message
surviving all native reboots. Redeclaration never replaces the queue: native
management reads retain type `quorum` and durability.

The pinned 3.13.7 engine's relaxed path also accepts a migrated classic client's
non-durable declaration against an existing durable quorum queue; an explicit
quorum client still cannot declare it non-durable. This follows the
[pinned native limited-equivalence implementation](https://github.com/rabbitmq/rabbitmq-server/blob/v3.13.7/deps/rabbit/src/rabbit_amqqueue.erl),
not a custom emulator exception. The smoke records both outcomes; it does not
claim native AWS calibration of every relaxed property or multi-node quorum HA.

### Native ActiveMQ logs

`CreateBroker` and `UpdateBroker` accept ActiveMQ general/audit flags. Partial
updates merge with pending intent; `DescribeBroker.Logs` separates effective and
pending settings. Successful native reboot or maintenance applies pending flags;
failed native application leaves them pending. Disabling delivery does not erase
previously accepted CloudWatch events or reset the retained native cursor.

The installed Log4j2 engine writes real INFO general records and native HTTP/JMX
audit records to owned journal-volume files. HTTP auditing covers management
`*.action` requests, not read-only JSP navigation. Console message bodies,
including multiline/Unicode content, remain native audit payloads. No broker
events are synthesized from control-plane metadata.

Group preparation uses the current API caller's `logs:CreateLogGroup` authority.
A denied caller can still create/reboot a broker, but cannot create the group.
Delivery separately requires a current resource policy granting
`mq.amazonaws.com` `logs:CreateLogStream` and `logs:PutLogEvents`, with broker
`aws:SourceArn` and `aws:SourceAccount` context. Delivery never borrows the caller's
root credentials or creates missing groups as the service.
Destinations are `/aws/amazonmq/broker/<broker-id>/{general,audit}` and stream
`activemq-<broker-id>-1.log` for the implemented single native instance.

Native reads occur outside resource transactions. The worker rechecks broker
version/state/deadline and cursor before committing Logs events/subscription
intents and the source byte position in one shared memory/SQLite transaction.
Failure to persist the cursor rolls back accepted events and newly created
streams. Logs commands use the existing savepoint boundary so handled
missing-stream/already-existing-group errors do not poison the enclosing command.
Current authorization denial preserves source position for later recovery.

Collection preserves original timestamps and decoded message bytes, respects
one-request byte/event/time-span limits, and never acknowledges an incomplete
line. Each file rolls at 8 MiB with seven retained archives. File identity and a
boundary digest detect rotation/truncation; loss of a retained prefix is reported
by the scheduler and `mq_brokers.log_delivery_error`, never replaced by synthetic
records. Oversized or invalid records fail without advancing their cursor.
Finite retention can therefore lose records during prolonged denied delivery.
A separate real-engine source probe generated native management audit traffic
through physical rollover, then exhausted all seven archives. Retained rollover
preserved 110 records in order; archive exhaustion reported the lost prefix and
resumed at actual surviving records. Same-inode truncation both below the old
offset and followed by regrowth beyond it was detected, with all newly emitted
records recovered. This probes `ReadLogs` directly; it is not an end-to-end
CloudWatch overflow scenario or AWS-managed timing calibration.

The signed executable smoke verified real general records, real console sends
and matching JMS consumption, exact physical audit bytes/timestamps, caller
group denial, resource-policy denial/recovery, SQLite/controller restart without
replay, and reboot-applied disable/re-enable with retained JMS journal data.
Memory/SQLite regressions also cover cursor-write rollback and stale source-read
fencing. Evidence is retained in
[`mq_standalone_executable.json`](../testdata/integration/mq_standalone_executable.json).
These are local engine effects, not an AWS broker logging capture.

### Native RabbitMQ general logs

RabbitMQ supports general logs, not audit logs. Create/update rejects `Audit=true`
without changing admitted general-log intent. General settings share the existing
pending/effective and successful-native-reboot boundary with ActiveMQ.

The installed RabbitMQ JSON formatter writes native `time`/`msg` records into its
retained journal volume. Collection preserves decoded message bytes and native
timestamps at CloudWatch millisecond precision. The shared bounded reader uses
RabbitMQ's actual `.6` through `.0` archive order, file identities and boundary
digests; it does not synthesize records from API calls. Seven 8 MiB archives retain
the same finite-loss boundary described above. File-level regressions exercise
archive order, truncation/replacement and symlink rejection; physical RabbitMQ
archive exhaustion has not been exercised by the executable scenario.

Unlike ActiveMQ, RabbitMQ creates groups and publishes through its current
`AWSServiceRoleForAmazonMQ`. The adapter derives scope from the broker even when
the scheduler has no caller metadata, assumes current IAM trust and evaluates the
current protected managed policy. No Logs resource policy or caller Logs grant
is required. Missing groups can be recreated by the role. Events, source cursor
and role-session effects join the existing transaction domain.

`go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd rabbit-logs`
verified actual AMQP channel errors against captured native JSON timestamps and
messages, audit rejection, pending/reboot-applied disable and re-enable, protected
role deletion failure while a broker exists, SQLite/controller restart without
marker replay, retained native messages and deleted-group recreation. It discovers
streams rather than claiming AWS stream-name parity. Exact-owned brokers, volumes
and groups were removed; the private evidence database retains the role and its
normal active sessions.

Repository-level regression coverage verifies current trust/policy denial and
restoration plus cross-account rejection. The executable does **not** claim
public-SDK authority revocation/recovery: IAM correctly prohibits editing the
protected role and the live broker prevents its deletion. No protected state is
patched in that scenario. See the retained `rabbitmq_logging_evidence` in
[`mq_standalone_executable.json`](../testdata/integration/mq_standalone_executable.json).
These are local real-engine effects, not an AWS-managed logging capture.
AWS documents [RabbitMQ log controls and automatic linked-role delivery](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-rabbitmq-editing-broker-preferences.html)
and the [managed policy permissions](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonMQServiceRolePolicy.html).

### Native ActiveMQ broker and destination metrics

Real ActiveMQ 5.18.7 JMX supplies `CurrentConnectionsCount`,
`TotalConsumerCount`, `TotalMessageCount`, `TotalProducerCount` and
`InactiveDurableTopicSubscribersCount`.
Queue/topic destinations supply `ConsumerCount` and `ProducerCount`; only
queues supply `QueueSize`. All use `Count` units in `AWS/AmazonMQ`.
The `Broker` dimension is the broker name with the single-instance `-1` suffix;
destination series add either `Queue` or `Topic`, never both. A queue and topic
with the same physical name remain distinct identities.
[AWS definitions and dimensions](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/activemq-logging-monitoring.html)
define these instantaneous gauges. Per-minute activity counters, including AWS's
special polling-period treatment of `InFlightCount`, remain unimplemented.

The pinned JRE lacks `jdk.attach`. A bounded HotSpot `agentProperties` request
inside the exact-owned container discovers its already-enabled local connector;
it does not start a remote management agent. PID/executable/UID, broker name and
JMX broker identity are checked. OpenJDK's
[local socket factory](https://github.com/openjdk/jdk11u/blob/jdk-11.0.26-ga/src/jdk.management.agent/share/classes/sun/management/jmxremote/LocalRMIServerSocketFactory.java)
rejects clients outside the broker's network namespace interfaces. No customer
credentials, remote JMX port or fabricated management counters are used.
The reader checks queue/topic and temporary-destination catalogs against JMX,
reads actual destination names rather than encoded ObjectName properties, and
checks inventories and broker identity again afterward. Missing, malformed,
negative or unavailable counters fail the whole observation. These sequential
native reads are not an atomic cross-destination snapshot.
Inactive durable subscriptions come from the complete native JMX inventory,
validated for broker ownership, duplicates and changes during the read. The
CloudWatch projection caps the measured count at AWS's documented 2000 maximum;
the native snapshot retains the uncapped count.

Typed engine snapshots use the same retained reconciliation and transactional
CloudWatch publication described below. Wrong-engine snapshots are rejected;
sampling failures do not undo broker readiness.

`go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd active-metrics`
verified actual persistent JMS traffic and held producers/consumers against
signed `GetMetricData`, `GetMetricStatistics` and filtered/unfiltered
`ListMetrics`. The initial non-durable-topic workflow observed broker
connection/consumer/message/producer counts `2/2/7/2 → 1/1/7/1 → 0/0/0/0`;
post-restart traffic produced `2/2/4/2 → 0/0/0/0`.
Same-name queue/topic series remained distinct, with no
topic `QueueSize`, unsuffixed broker series or mixed destination dimensions.
Closed-minute history and sample counts survived SQLite/controller restart.
Foreign account/region reads were empty. Exact-owned broker, automatic
configuration, native container and volume were removed. The RabbitMQ workflow
also passed after the typed-snapshot cutover. Evidence is retained in
[mq_standalone_executable.json](../testdata/integration/mq_standalone_executable.json);
this proves local engine effects, not AWS-managed fleet or HA equivalence.

The expanded durable-topic workflow observes inactive subscribers
`0 → 1 → 1 → 1 after controller reopen → 0 on reactivation → 0 after unsubscribe`.
A stable JMS client ID/subscription name reactivates the existing subscription.
Native ActiveMQ retains durable topic `ConsumerCount=1` even when disconnected;
its broker `TotalConsumerCount` includes that subscription until explicit
unsubscribe. These counters are not rewritten as active socket counts.
All ten signed metric identities, closed-minute history, scope isolation and
exact-owned cleanup passed. Regression cases cover the 1999/2000/2001/3000
projection boundary and return to zero; the executable uses one durable
subscription, not a 2001-subscription native load test.

The subsequent workflow also publishes a persistent topic message while its
durable subscriber is offline, then restarts the controller and native broker.
Docker's exact-owned container start timestamp advances after signed
`RebootBroker`; fresh CloudWatch samples still report one inactive subscription.
Reactivation receives and acknowledges the exact retained payload, rejects an
extra duplicate, and explicit unsubscribe removes the subscription.

One native accounting limit is now exercised: upstream ActiveMQ's
[`Topic` statistics](https://github.com/apache/activemq/blob/activemq-5.18.7/activemq-broker/src/main/java/org/apache/activemq/broker/region/Topic.java)
exclude topic message counts from `BrokerView.TotalMessageCount`. The gauge can
therefore be zero while an offline durable subscriber has a retained topic
message. Stackd forwards that measured JMX value, not a fabricated all-message
total. AWS's treatment of this case remains a calibration gap, tracked beside
the projection in `internal/integrations/mq_metrics_activemq.go`.

### Native RabbitMQ queue metrics

`AWS/AmazonMQ` receives measured `ExchangeCount`, `ConnectionCount`,
`ChannelCount`, `QueueCount`, `MessageCount`, `MessageReadyCount`,
`MessageUnacknowledgedCount` and `ConsumerCount` broker gauges with the `Broker`
name dimension and `Count` units. RabbitMQ 3.x queues
also publish the four message/consumer gauges with `Broker`, `VirtualHost` and
`Queue` dimensions. Whitespace, control or non-ASCII queue/vhost names suppress
only their queue series; their actual queues/messages still count in broker
totals. RabbitMQ 4.x queue dimensions are not published.
[AWS metric definitions and dimensions](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/rabbitmq-logging-monitoring.html)
define this projection.

The source runs a bounded, owned-container query outside resource transactions.
Classic counters come from live queue processes; quorum counters come directly
from the live Ra FIFO state. RabbitMQ 3.13.7's ordinary quorum information API
can return zero for missing management statistics, so it is not used. The source
checks the complete durable/live inventory across all virtual hosts before and
after sampling. Missing counters, unavailable queues, unsupported queue types,
inventory churn, timeouts and responses over 8 MiB fail the whole observation.
Counters are per-queue observations, not an atomic cross-queue snapshot.
[Amazon MQ does not support streams](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/best-practices-rabbitmq.html);
an out-of-contract native stream therefore prevents this complete snapshot,
rather than receiving fabricated or stale management counters.

Exchange totals include every configured exchange across all virtual hosts,
including each nameless default exchange. The pinned single-node Mnesia runtime
uses actual exchange keys, not a table-size helper that can turn an unavailable
table into zero. Enabled/changing Khepri or multi-node membership is rejected.
Connection/channel totals use native AMQP process registries, excluding the
collector's Erlang distribution connection. A fresh broker's lazy-absent registry
is treated as empty only after actual AMQP listener and direct-channel supervision
prove there are no readers/channels. Missing supervision or changing registry
identity fails the observation. Native registry joins/leaves are asynchronous and
include AMQP handshakes; these are not atomic cross-inventory counts or a claim of
AWS-managed transition timing.

The existing retained 30-second reconciliation schedule drives observations.
Successful readiness commits independently of collection or publication failures.
Version, native container identity, running state and reconciliation deadline
fence publication after the native read. All metric batches join the shared
transaction domain; a later-batch failure rolls back earlier batches. Failed
samples retry on the next actual reconciliation, without synthetic catch-up.
CloudWatch stores these gauges at standard 60-second resolution. Publishing
uses broker scope and CloudWatch's internal service publisher, not the logging
linked role or the originating customer's `PutMetricData` permission.

`go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd rabbit-metrics`
verified confirmed persistent messages and a held quorum consumer, classic queue
totals, acknowledgement/drain/cancel transitions to zero, exact signed
`GetMetricData`/`GetMetricStatistics`/`ListMetrics` results, unsupported-name
exclusion and cross-account/region isolation. Closed minute windows prevent old
samples from satisfying a later phase. SQLite/controller restart retained
historical values and sample counts; new traffic produced later observations.
The broker, native container and volume were removed; CloudWatch history remains
in the private evidence database because AWS has no `DeleteMetrics` API.

The expanded executable workflow independently inventories default exchanges in
two real virtual hosts, creates/deletes two custom exchanges, opens distinct AMQP
connections/channels and closes channels independently of connections. Signed
CloudWatch reads observed exchange/connection/channel transitions
`16/3/6 → 15/2/3 → 14/0/0`; after SQLite reopen, retained historical values and
new transitions `15/2/3 → 14/0/0` also passed. Queue-state assertions remain active
throughout, so inventory changes cannot substitute for actual message counters.

Evidence is retained under `rabbitmq_queue_metric_evidence` and
`rabbitmq_inventory_metric_evidence` in
[`mq_standalone_executable.json`](../testdata/integration/mq_standalone_executable.json).
This is local pinned-engine proof, not native AWS cadence calibration. Queue
traffic uses the default virtual host; exchange inventory covers two virtual
hosts. No cluster workflow is exercised. ActiveMQ gauges and RabbitMQ node, rate
and network metric families remain unimplemented; EC2 capacities are not inferred
from broker size.

## Complete modeled operation map

| Operations | Current behavior and evidence boundary |
| --- | --- |
| CreateBroker, DescribeBroker, ListBrokers, DeleteBroker, RebootBroker | Real standalone engine lifecycle and retained messages; public single-instance subset only. Full CreatorRequestId payload-conflict semantics remain open. |
| UpdateBroker | Staged configuration revision and engine-supported log settings with actual reboot/weekly maintenance application; unsupported owner effects rejected. |
| CreateConfiguration, DescribeConfiguration, UpdateConfiguration, DeleteConfiguration | Typed scoped configuration and immutable revisions; bounded real native configuration vocabulary. |
| DescribeConfigurationRevision, ListConfigurationRevisions, ListConfigurations | Retained bytes/metadata with deterministic resource/scoped pagination. |
| CreateUser, UpdateUser, DeleteUser, DescribeUser, ListUsers | ActiveMQ pending/effective credentials, groups and real web-console access with native reboot effects; RabbitMQ correctly rejects these APIs. |
| CreateTags, DeleteTags, ListTags | Broker and configuration tags through current IAM; request-tag/tag-key conditions on mutations. |
| DescribeBrokerEngineTypes, DescribeBrokerInstanceOptions | Only implemented pinned runtime capabilities; no fictitious physical AZ or storage capacity. |
| DescribeSharedResources | Authorized empty result for the implemented public brokers; no private attachments are invented. |
| Promote | Authorized negative path only: native CRDR is not implemented. |

## Running the real scenario

Prepare the exact images named by `compute/mq/runtime.go`, Docker, Java/Javac and
OpenSSL. API calls do not download images. Assembly requires:

```
stackd -database /private/state.db -docker-host unix:///var/run/docker.sock \
  -mq-runtime -mq-state-directory /private/mq \
  -mq-tls-certificate /private/cert.pem -mq-tls-key /private/key.pem
```

The certificate must cover `127.0.0.1`; clients must explicitly trust it. The
standalone executable scenario creates its own local TLS material and controller
state, uses signed AWS SDK v2 controls, and connects ordinary JMS/OpenWire and
AMQP 0-9-1 clients without Lambda:

```
go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd
```

It exercises immutable revisions/tags, cross-account/region denial, configuration
association deletion protection, pending user rejection, actual ACL write denial,
password rotation/deletion, negotiated RabbitMQ heartbeat, infinite/finite/default
acknowledgement-timeout transitions, message retention across executable
replacement, and broker/configuration deletion. The timeout proof holds a real
AMQP delivery beyond RabbitMQ's minute-long timeout tick, then observes finite
timeout channel closure; it does not advance the service clock to simulate native
engine time. The scenario retains its printed private evidence directory and
controller log for inspection. The separate
`go run ./scripts/mq_engine_smoke` retains the existing native redelivery test;
`./scripts/lambda_mq_smoke` retains the existing real Lambda consumer scenario.

The new regression sources cover failed-native user commit, stale probe fences,
maintenance claims, deleted-user non-resurrection, IAM/scope/ARN boundaries,
configuration deletion associations and scoped pagination. Repository regressions
cover rollback, SQLite reopen, detached memory state and legacy migration.

The [retained assembled-executable evidence](../testdata/integration/mq_standalone_executable.json)
records successful signed SDK and direct JMS/AMQP scenarios for both engines,
including the restrictive-ACL readiness regression, password rotation and
actual message bytes through controller replacement. Both broker/configuration
records and their native containers/volumes were verified absent afterward.
The separate native engine and real Lambda-consumer scenarios also passed.
The additional timeout evidence records real infinite/finite timeout effects,
restoration of the default after an omitted key, and an old-to-new executable
upgrade preserving credentials, messages and endpoints. Fresh broker creation
with an infinite timeout was also exercised.
The maintenance SDK/executable scenario also passed persisted quota rejection
through controller restart and manual reboot, then advanced the service clock to
trigger a real broker reboot. The native connection closed, the pending RabbitMQ
timeout became effective, queued bytes survived and the renewed budget persisted.
Scoped service/storage/runtime tests, race checks, vet and staticcheck passed;
these results do not establish the unimplemented fleet/owner behavior below.
The extended console scenario passed initial access, pre-reboot denial,
grant/revocation/deletion, password rotation and SQLite/controller restart against
the actual TLS webapp. The old-to-new executable scenario preserved the original
JMS endpoint and journal, then a real browser displayed retained message bytes
and sent another message. An ordinary JMS client consumed both exact bodies.
After the console change, both native delivery/redelivery and MQ → real Python
Lambda → signed SQS scenarios passed for both engines, including current-secret
denial, failed invocation replay and SQLite source restart.
No native AWS console/user-lifecycle calibration is inferred from these local
scenarios.

## AWS sources and native calibration limits

Sources consulted for this implementation:

- [Complete MQ API resource/operation reference](https://docs.aws.amazon.com/amazon-mq/latest/api-reference/operations.md).
- [Broker updates and pending configuration](https://docs.aws.amazon.com/amazon-mq/latest/api-reference/brokers-broker-id.md).
- [Configuration revisions, deletion and base64 data](https://docs.aws.amazon.com/amazon-mq/latest/api-reference/configurations-configuration-id.md).
- [ActiveMQ user operations, validation and deferred effects](https://docs.aws.amazon.com/amazon-mq/latest/api-reference/brokers-broker-id-users-username.md).
- [Permitted ActiveMQ attributes](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-attributes.html),
  [collections](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-collections.html),
  and [RabbitMQ configurable values](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configurable-values.html).
- [Maintenance windows and adjustment limits](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/maintaining-brokers.html).
- [ActiveMQ broker users and reboot-applied console permissions](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-listing-managing-users.html).
- [ActiveMQ log sources, destinations, caller permissions and MQ resource policies](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html).
- [RabbitMQ-only protected service-linked role, permissions and deletion dependencies](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-service-linked-roles.html).
- [Installed ActiveMQ web console](https://activemq.apache.org/components/classic/documentation/web-console)
  and [local JMX management](https://activemq.apache.org/components/classic/documentation/jmx).
- [ActiveMQ message redelivery and dead-letter handling](https://activemq.apache.org/components/classic/documentation/message-redelivery-and-dlq-handling),
  including expired/nonpersistent filtering and the DLQ-expiration loop warning.
- [RabbitMQ acknowledgement timeout and its advanced-config representation](https://www.rabbitmq.com/docs/consumers#acknowledgement-timeout);
  [pinned 3.13.7 configuration-path discovery](https://github.com/rabbitmq/rabbitmq-server/blob/v3.13.7/deps/rabbit_common/src/rabbit_env.erl).

The generated shapes in `internal/awsapi/mq` and the pinned model tracked by the
operation inventory are the wire baseline. `testdata/aws/mq/admission.json` is a
2026-09-28 us-east-1 native capture of a missing broker, deliberately invalid
creation and a missing Lambda function. **No successful native AWS broker was
created for that capture.** It does not calibrate successful broker/config/user
responses, asynchronous timings, AWS maintenance, managed topology, data-plane
parity or comprehensive IAM/audit semantics.

The separate [maintenance capture](../testdata/aws/mq/maintenance.json) created
one ActiveMQ 5.19 `mq.t3.micro` broker in us-east-1. Two unchanged requests before
the limit succeeded without consuming its four changed-window admissions.
The fifth change and an unchanged request at the limit returned
`BadRequestException` (HTTP 400), without `ErrorAttribute`; manual reboot did not
restore the budget. The executable regression now exercises those boundaries.
The bounded observation expired without seeing a scheduled reset: `complete`
remains false. This does not show that AWS never resets the quota, nor calibrate
its completion timing. Local completed-reboot reset follows the documented rule.

Native broker deletion outlasted the initial five-minute cleanup window.
`cleanup_continuation` retains the subsequent broker/interface absence, deletion
of its exact-owned security group/subnet/VPC and automatically created
configuration, and final not-found responses. The route/gateway were removed in
the original cleanup; the service-linked role was absent before and afterward.
`initial_cleanup_verified` remains false and aggregate `cleanup_verified` is true.
The probe now retains automatic configuration ownership and refuses network
teardown until broker deletion and interface release complete. Five offline
fault-injected cleanup scenarios passed; the revised probe was not rerun against
another paid broker. Local real engines prove physical local effects, not
AWS-managed fleet equivalence.

## Missing-resource errors

Read-only native requests retained in
[`testdata/aws/mq/missing_resources.json`](../testdata/aws/mq/missing_resources.json)
calibrate the modeled `NotFoundException.ErrorAttribute`: broker reads and
user reads under an absent broker return `broker-id`; configuration reads and
revision listings return `configuration-id`. `DescribeConfigurationRevision`
returns `configuration-revision` even when the parent configuration is absent.
`ListTags` for either missing resource kind omits the attribute.
The capture creates no AWS resources; `scripts/aws/mq_missing_probe.py` reproduces it.

MQ now uses the generated REST JSON error shape rather than the generic JSON
envelope, so SDK clients receive the modeled attribute. Resource owners classify
misses before protocol serialization; revision and tag boundaries preserve their
distinct native contracts. Storage failures and authorization denials are not
converted into missing-resource responses.

`TestMQNativeMissingResourceErrors` replays the eight captured requests through
signed Go SDK clients on memory and SQLite, checking the modeled error type,
HTTP status and attribute presence/value, not incidental message wording.
An assembled-executable SDK smoke also verified those requests, foreign
account/region configuration and revision lookups, tag isolation, owner-state
preservation and exact-created configuration deletion. Retained evidence is in
`testdata/integration/mq_standalone_executable.json`.
This does not calibrate missing users on existing brokers, broker configuration
references, or every mutation-error precedence.

## Configuration revision pagination and validation

Native captures in `testdata/aws/mq/configuration_revisions.json` and
`configuration_revision_boundaries.json` retain two sequential exact-owned
ActiveMQ 5.18 configuration lifecycles. Both configurations were deleted; no
broker was provisioned. `scripts/aws/mq_configuration_probe.py` reproduces the
expanded workflow. `configuration_revision_precedence.json` adds read-only
malformed-revision requests against an absent parent.

Revisions are ordered oldest-first. Appending revision 8 after reading revisions
1–5 makes continuation return 6–8. Every nonempty page carries a continuation,
including a partial final page; the next empty page omits it. The local revision
list now preserves that termination contract and the observed default limit of
20. Tokens remain local, scoped to partition/account/region/configuration, not
copies of AWS's opaque encoding.

`testdata/aws/mq/pagination_defaults.json` additionally captures read-only engine
catalog, configuration-list and user-list responses with omitted `MaxResults`.
All report 20. The shared page helper now uses that default instead of 100;
revision listing no longer needs a separate override. Explicit limits are
unchanged. A 21-configuration SDK regression failed before the fix on memory and
SQLite, then passed with exact pages of 20 and 1, including retained continuation
after SQLite reopen. The actual executable returned the same two pages, honored
an explicit limit of 100, and reported the native catalog default of 20.
All 21 exact-owned local configurations were deleted afterward.

Revision identifiers accept decimal integers with an optional minus sign and
signed 32-bit bounds. Zero and negative IDs are valid syntax but missing
revisions; a plus sign, noninteger syntax or overflow is a modeled bad request.
Leading zeroes resolve the same retained revision. Syntax validation precedes
parent lookup. `ErrorAttribute` identifies `configuration-revision`, `maxResults`
or `nextToken`, including page-size failures rejected by generated input binding.
The captured zero page-size rejection is AWS CLI validation, not native service
evidence.

The memory/SQLite signed SDK regression checks ordering, append/continuation,
empty termination, original revision bytes, numeric/error boundaries, deletion
and SQLite reopen. An actual executable workflow also retained its first-page
token across controller restart, appended another revision and consumed all eight
revisions through three signed SDK page requests without duplication.
Its configuration was deleted and both controller processes exited cleanly.
These revision captures do not establish broader XML-sanitization equivalence.

## ActiveMQ API release and native runtime version

The public ActiveMQ engine version is `5.18`, distinct from the pinned native
`5.18.7` runtime and JMS client. Both discovery APIs, broker admission and
configuration admission use the public label; patch-qualified requests are
rejected, not accepted as compatibility aliases.

[AWS's version guide](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/activemq-version-management.html)
lists supported minor releases. Native configuration-only requests retained in
`testdata/aws/mq/engine_version_admission.json` reject `5.18.7` and `5.18.99`
with `BadRequestException` and `ErrorAttribute=engineVersion`. The revision
captures above establish successful native `5.18` creation. No AWS broker was
created for this calibration. AWS also advertises `5.19`; stackd does not advertise
or accept that release without its actual runtime integration.

Migration 295 changes only ActiveMQ broker/configuration rows carrying the former
`5.18.7` API value. Native identity, credentials, current/pending configuration,
revision data, scheduling state and logs remain unchanged. The storage regression
checks those retained columns and child rows across migration and repeated reopen,
including partition/account/region scopes and non-target engine/version rows.

The executable workflow starts the prior binary, creates a real ActiveMQ broker
and publishes a persistent JMS `BytesMessage` containing NUL/non-UTF-8 bytes.
The new binary opens the same SQLite/native state and returns public `5.18`.
Container ID, image, start time and journal volume identity remain unchanged;
the same credentials consume the exact 72-byte payload. Signed SDK calls verify
both discovery APIs and modeled rejection of patch-qualified broker/configuration
requests. Exact-owned broker, configuration, container and volume deletion passes.
The fresh-broker workflow also passes for ActiveMQ API `5.18` and unchanged
RabbitMQ: real JMS/AMQP authorization, HTTPS console controls, configuration
effects, controller restart and owned SDK deletion.

Run `go run ./scripts/mq_standalone_smoke /absolute/path/to/new-stackd engine-versions /absolute/path/to/prior-stackd`.
Checksummed evidence is retained in
`testdata/integration/mq_standalone_executable.json`. This is a public-label
cutover, not a runtime upgrade, replicated deployment or full AWS fleet claim.

## ActiveMQ configuration sanitization

`cmd/mqschemagen` derives element/attribute membership and local child contexts
from the retained [AWS 5.18.4 XSD](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/samples/amazon-mq-active-mq-5.18.4.xsd.zip),
the published schema for the public `5.18` release. The source is
`testdata/aws/mq/amazon-mq-active-mq-5.18.4.xsd`; generated output records its
SHA256 and source URL. `make generate-mq-schema-check` verifies offline drift.
This classifies membership; it is not a general-purpose XSD validator.

`UpdateConfiguration` removes schema-disallowed attributes and child subtrees,
including misplaced otherwise-known elements and foreign-namespace children.
Attribute expressions `${...}` and `#{...}` are removed rather than evaluated.
The response identifies the removed element/attribute using
`DISALLOWED_ATTRIBUTE_REMOVED`, `DISALLOWED_ELEMENT_REMOVED`, or
`INVALID_ATTRIBUTE_VALUE_REMOVED`. Attributes are visited in lexical order;
a removed subtree contributes one warning. Only sanitized data becomes a
retained revision.

Native configuration-only captures in `configuration_sanitization.json` and
`configuration_sanitization_boundaries.json` under `testdata/aws/mq` establish
these boundaries. Both owned configurations were deleted; no AWS broker was
provisioned. Signed SDK regression checks warnings and semantic XML on memory
and SQLite, including reopened revisions and unchanged state after rejection.

The executable `configuration-sanitization` workflow applies a sanitized
revision through a real broker reboot. Native XML and authenticated console
inventory contain the kept predeclared queue, not the removed subtree's queues.
The retained destination ACL permits a reader to connect but denies publication.
A persistent JMS message survives another broker reboot and controller restart.
Owned broker, configuration, container and volume cleanup completes.

Schema membership does not imply native implementation. Permitted but
unimplemented settings still fail after sanitization rather than disappearing.
The capture also shows AWS retaining a nonboolean `advisorySupport` value;
stackd still rejects it. Primitive coercion, references, byte-for-byte XML
serialization, remaining AWS-permitted effects and RabbitMQ sanitization remain
explicit gaps. Directives, duplicate attributes and processing instructions
cannot bypass the object boundary inside discarded subtrees.

## Native ActiveMQ delayed and repeated delivery

`schedulerSupport="true"` enables the actual broker's persistent message
scheduler. The runtime supplies exactly one scheduler attribute, using `false`
when omitted; enabling it does not replace the owned KahaDB journal, TLS,
authentication or listeners. Configuration changes stay pending until reboot,
using the same fenced configuration-application path as other native settings.

[ActiveMQ scheduling properties](https://activemq.apache.org/components/classic/documentation/delay-and-schedule-message-delivery)
are consumed by the engine, not a Go timer or an emulated queue. Native jobs and
payloads persist in the broker's owned data volume. Their clock is the real
engine clock, separate from deterministic control-plane maintenance scheduling.

`testdata/aws/mq/configuration_scheduling.json` records native AWS acceptance of
both boolean values and retained configuration revisions without warnings.
The owned AWS configuration was deleted; no AWS broker was provisioned.
The memory/SQLite SDK fixture replay now accepts the previously unsupported
`schedulerSupport` case instead of pinning that implementation gap.

The `active-scheduling` executable workflow published a persistent JMS message
with a 60-second delay, 2-second period and two repeats. It observed no early
delivery, then restarted the native broker and controller before the deadline.
A live consumer received exactly three matching persistent messages with native
`scheduledJobId`, no delivery before the lower bound and at least one-second
spacing. Container/journal identity remained stable; native start time advanced.
After disabling scheduling through another configuration/reboot, the same
headers produced one immediate message without a scheduled-job identity.
Broker, configuration, container and volume cleanup passed.

`maxSchedulerRepeatAllowed` configures the engine's repeat ceiling through the
same retained revision/reboot path. Native configuration-only admission of limits
`2` and `0` is captured in `testdata/aws/mq/configuration_repeat_limit.json`, with
retained values, no sanitization warnings and confirmed owned cleanup.
The [pinned native scheduler](https://raw.githubusercontent.com/apache/activemq/activemq-5.18.7/activemq-broker/src/main/java/org/apache/activemq/broker/scheduler/SchedulerBroker.java)
enforces this limit; the Go control plane does not intercept JMS sends.
The executable workflow verifies `MessageFormatException` for three repeats
under a ceiling of two, before and after native/controller restart, without
enqueuing a message. Two repeats still produce the three exact scheduled
deliveries. Updating the ceiling to zero rejects one repeat but permits one
scheduled delivery with zero repeats. Disabled scheduling bypasses repeat
processing and still delivers once immediately, even with a zero ceiling.

Run `go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd active-scheduling`.
This proves native delayed/repeated delivery and retained jobs, not AWS-managed
timing, CRON boundary behavior or replicated scheduler failover.

## Native durable consumer admission

`rejectDurableConsumers` applies through retained ActiveMQ configuration revisions
and real broker reboot. AWS permits this broker attribute in its
[configuration contract](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-attributes.html);
`testdata/aws/mq/configuration_durable_consumers.json` retains native admission
and revision bytes for both boolean values, with configuration-only cleanup.

The native engine rejects both new durable subscriptions and reactivation of
retained subscriptions while enabled. This is JMS admission, not Go-side message
filtering. Non-durable topic consumers still receive messages. Existing offline
durable subscriptions and their persistent messages remain in the engine journal:
disabling rejection allows exact payload recovery without duplication.

The `durable-policy` executable smoke checks pending-versus-effective configuration,
native reboot, unchanged container/volume on controller restart, rejection before
and after restart, non-durable delivery, retained payload recovery and new durable
delivery after disabling the policy. All owned broker/configuration/container/volume
resources were removed. Native AWS calibration covers configuration admission,
not AWS-managed delivery timing or replicated brokers.

## Native exclusive consumer policy

`allConsumersExclusiveByDefault` is admitted as a boolean destination-policy
attribute and applied by the actual ActiveMQ engine. The
[AWS permitted attributes](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-attributes.html)
and retained `testdata/aws/mq/configuration_exclusive_consumers.json` establish
admission and revision retention for both values. That capture created only one
configuration and verified its deletion; it does not calibrate AWS broker failover.

The local `exclusive-policy` smoke creates two real JMS consumers without
consumer-side exclusive flags. Both receive distinct payloads by default.
After a policy revision and native reboot, only the first consumer receives the
ordered payloads; closing it hands subsequent delivery to the standby without
duplication. Unmatched queues still distribute to both consumers. Pending
revisions leave current behavior unchanged, controller restart preserves the
native container/volume and policy, and disabling the policy restores sharing.
This follows ActiveMQ's
[exclusive consumer contract](https://activemq.apache.org/components/classic/documentation/exclusive-consumer),
not a Go-side delivery simulation. The smoke verifies orderly consumer closure,
not process-crash or replicated-broker failover.

Run `go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd exclusive-policy`.
The signed SDK regressions cover memory/SQLite configuration retention; the
executable verifies the real broker and removes its owned broker, configuration,
container and volume.

## Native producer backpressure

`sendFailIfNoSpace` and `sendFailIfNoSpaceAfterTimeout` pass through scoped
destination policies to the real engine. The native AWS capture
`testdata/aws/mq/configuration_producer_backpressure.json` retains both boolean
values and timeouts zero, 1000, -1 and the signed 64-bit maximum. This proves
configuration admission, not AWS-managed resource exhaustion or deadline timing.

The `producer-pressure` executable smoke holds actual unacknowledged deliveries
to exhaust a destination's memory. Persistent sends fail with
`ResourceAllocationException`, immediately or after the configured one-second
wait. Acknowledgement releases pressure, accepted payloads are exact, rejected
sends leave no message, and subsequent sends recover. Both persistent and
non-persistent paths verify payloads and recovery; the default file cursor can
offload non-persistent messages, so that path does not require exhaustion.
Unmatched queues remain usable. Pending revisions preserve current behavior,
native reboot changes it, and controller restart retains the native identity
and timed rejection behavior. Owned native and local configurations, broker,
container and volume were removed.

Run `go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd producer-pressure`.
See ActiveMQ's [producer flow control](https://activemq.apache.org/components/classic/documentation/producer-flow-control).
This does not prove disk-store exhaustion, broker-global limits or replicated
backpressure. Earlier failed harness attempts remain recorded in the evidence.

The separate `configuration_memory_cursor.json` capture proves AWS admits
`pendingQueuePolicy/vmQueueCursor`, but local admission remains unsupported.
An actual native experiment confirmed memory saturation without the expected
per-destination rejection. In pinned
[ActiveMQ Queue.initialize](https://github.com/apache/activemq/blob/activemq-5.18.7/activemq-broker/src/main/java/org/apache/activemq/broker/region/Queue.java#L399-L402),
the VM cursor replaces destination `SystemUsage` with the broker-wide instance.
Do not substitute a global failure policy for a destination policy. Native AWS
behavior and a compatible cursor implementation remain open.

## Native composite destinations

The bounded `destinationInterceptors/virtualDestinationInterceptor` configuration
path now admits `compositeQueue` and `compositeTopic` entries with named queue/topic
`forwardTo` destinations. `forwardOnly`, `copyMessage` and `concurrentSend` remain
native boolean properties; forwarding is performed by ActiveMQ, not a Go relay.
Arbitrary classes, references, expressions and external transport URLs remain
outside the configuration boundary.

The [AWS attribute contract](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/permitted-attributes.html)
and `testdata/aws/mq/configuration_composite_destinations.json` establish admission.
The capture retains both `forwardOnly` values for both source types, with
`copyMessage=true` and `concurrentSend=false`, and verifies owned configuration
deletion. It does not provision an AWS broker.

The actual broker smoke follows the native
[composite destination contract](https://activemq.apache.org/components/classic/documentation/virtual-destinations):
each source sends exact persistent payloads and properties to two physical queues
and one live topic subscriber. With `forwardOnly=false`, the source also delivers;
with `true`, it does not. Unmatched queues continue sharing messages normally.
Pending revisions preserve current routing; reboot changes new-send behavior
without dropping or replaying previously routed queue copies. Controller restart
retains native identity, queued payloads and routing. Owned broker, configuration,
container and volume deletion are verified.

Run `go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd composite-destinations`.
The SDK regression covers memory/SQLite and retained revisions. Boundary tests
cover object references, classes, missing names/targets, expressions and URLs;
sanitization rejection tests assert rejected output rather than error wording.
Wildcard composite names remain unsupported.
Concurrent fanout, partial-target failures and replicated routing have not been
exercised. Service support remains partial.

### Filtered forwarding and unmatched fallback

`filteredDestination` forwards to exactly one named queue or topic using the
native JMS selector evaluator. `sendWhenNotMatched` preserves the
[pinned native precedence](https://github.com/apache/activemq/blob/activemq-5.18.7/activemq-broker/src/main/java/org/apache/activemq/broker/region/virtual/CompositeDestinationFilter.java):
when true, only messages matching no forwarding target reach the source, even
when `forwardOnly=false`. With fallback disabled, `forwardOnly` controls source
delivery normally. Selectors are not translated into Go predicates.

`configuration_filtered_destinations.json` captures eight AWS admission cases:
both composite source types and all combinations of the two boolean flags.
The extended `composite-destinations` smoke uses real string equality, numeric
comparison/conjunction and absent-property nonmatches. Matching payloads arrive
only at their filtered targets; source delivery follows the fallback setting.
Filtered queue copies and source backlog retain exact payloads and properties
across native reboot and controller restart without re-routing or duplication.
The runtime cases hold `forwardOnly=false` for filtered entries to verify fallback
precedence, while unfiltered entries exercise both `forwardOnly` values.
Pending revisions, return to fallback-disabled behavior, native identity and
owned cleanup are verified. This is not exhaustive JMS-selector or native AWS
data-plane conformance; selector parsing and runtime errors remain engine-owned.

### Custom virtual topics and consumer groups

`virtualTopic` admits native name patterns, consumer-queue prefixes/postfixes and
its documented boolean properties. The AWS capture
`configuration_virtual_topics.json` retains a wildcard topic pattern, custom
`Groups.*.` prefix and `.work` suffix with both `selectorAware` values.
The actual smoke uses `transactedSend=true` and `concurrentSend=false`; ActiveMQ
owns fanout transactions and JMS selector evaluation.

The same executable smoke verifies two independent consumer-group queues:
two red-selector consumers share the red group's matching messages, while the
blue group independently receives its matching message. Ordinary topic subscribers
still receive every publication. Queues with the wrong prefix or suffix receive
none. With selector awareness disabled, nonmatching messages remain in each
group's queue and can be drained by unfiltered consumers; enabled awareness
prevents that backlog. Missing selector properties do not match.

Queues established before their consumers disconnect retain offline publications
only with `selectorAware=false`. Existing queue copies survive policy-changing
native reboot and controller restart unchanged, without replay. This uses live
consumer selectors, not a selector-cache plugin. Pending policy and transitions
in both directions, controller-retained native identity and owned native/local
cleanup are verified. Network-bridge `local` behavior, resource-limit dropping,
concurrent fanout, selector-cache persistence and replicated topology remain
unverified or unsupported; this is not complete virtual-topic conformance.

## Native CreateBroker replay identity

`testdata/aws/mq/create_identity.json` captures twelve replay cases against one
exact-owned AWS ActiveMQ broker. Same-token retries return the original broker
when passwords, console access, tags or maintenance settings differ, including
after explicit tag/window/password mutations. Explicit `SIMPLE` authentication
also replays. A changed instance type conflicts with `ErrorAttribute=brokerName`;
omitted, empty or different tokens conflict on the existing name. A complete
request fingerprint would incorrectly reject the observed successful retries.

The local transaction performs replay/conflict checks before creating the
automatic configuration or admitting a new native instance. Replay leaves
current and pending state unchanged. MQ uses the shared Smithy HTTP encoder,
including the captured empty HTTP 204 `CreateTags` response.

ActiveMQ broker descriptions and list summaries use the native `ActiveMQ`
spelling. Creation and catalog APIs still use `ACTIVEMQ`; typed persisted engine
identity and runtime dispatch are unchanged. The SDK regression and actual broker
smoke check this distinction alongside restart and replay.

`TestMQNativeCreateBrokerIdentity` replays the fixture on memory and SQLite and
checks retained mutations and account/region isolation. Run
`go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd create-identity`
for actual broker proof: original credentials remain active through replay and
controller restart; persistent JMS bytes survive without duplication; a native
reboot applies only the explicit pending password change. Broker, container,
volume, endpoints and configuration inventory retain their identities. Exact-owned
broker/container/volume/configuration cleanup passed.

The AWS probe incurred a broker charge. Its cleanup verifies broker/configuration
deletion, then removes detached replay-created interfaces only after checking
their exact VPC/account ownership and confirming their broker IDs are absent.
The retained cleanup also verifies removal of owned network dependencies.
Local replay adapts AWS engine release 5.19 to the supported 5.18 API release and
uses public local endpoints; it does not prove private networking or engine
rollout. Cross-name token reuse, remaining creation-field comparisons and
post-deletion reuse remain uncalibrated.

## Remaining owner integrations and TODO: Comeback

- `internal/services/mq/service.go`: private EC2 attachment, standby/cluster,
  managed KMS storage, automatic upgrades and replication; missing-user and broker
  configuration-reference error attribute calibration.
  `internal/services/mq/metrics.go` tracks remaining ActiveMQ gauges/calibrated
  per-minute counters and RabbitMQ node, rate and network metric families.
- `internal/services/mq/updates.go`: real version/capacity rollout, LDAP,
  encrypted storage/network updates; CRDR promotion requires actual replicated
  journals and fenced primary/replica role transitions. AWS maintenance completion
  timing and DST edges remain uncalibrated; the bounded capture saw no reset.
- `internal/services/mq/users.go`: CRDR replication identities.
- `internal/services/mq/configuration_validation.go`: remaining permitted native
  effects; `configuration_sanitization.go`: primitive coercion, references and
  XML serialization parity.
- `internal/services/mq/brokers.go`: cross-name token reuse and remaining creation
  fields; retain original instance/engine identity before implementing rollout.

Concrete dependencies are not generic missing services. EC2 already owns ENIs and
packet policy: `internal/services/ec2/task_networks.go` has Allocate/Resolve/Release
but enforces ECS-specific role and ARN authority. MQ requires its own fenced
service entrypoints, then native attachment of `compute/network.Specification`;
reusing ECS credentials would violate authority. `internal/services/ecs/task_networks.go`
and `internal/integrations/ecs_networks.go` show the transaction/effect boundary.

EBS's `internal/services/ec2/volumes.go` `VolumeControl` owns real storage, but the
MQ runtime currently mounts Docker volumes. KMS grant metadata alone does not
encrypt their journal bytes: native encrypted disk/filesystem mounting and release
must join the real EBS/KMS owners before accepting encryption/storage claims.
Both engines now use `internal/integrations/mq_logs.go` and the current Logs owner,
with distinct ActiveMQ resource-policy and RabbitMQ service-linked-role authority.
CloudWatch's shared publisher is usable (see ECS metrics and RDS MetricPublisher),
but broker management/JMX measurements must be acquired before publishing gauges.
Multi-node/CRDR itself is unresolved MQ runtime work, not an absent external API:
it needs topology, native journal replication, failover fencing and fault proof.
