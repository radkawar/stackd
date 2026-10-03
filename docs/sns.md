# SNS behavior and ownership

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

SNS is a partial service with real standard/FIFO topic publication, policy enforcement,
retained delivery, FIFO archives/replays, role-authorized delivery-status logs and
CloudWatch metrics.
It is not a complete SNS implementation.
The generated frontend contains all 43 operations in the pinned Smithy model;
19 registered commands implement topic controls, permissions, tags, subscriptions,
confirmation, `Publish` and `PublishBatch`. Other commands return protocol errors, not success.
The generated [service inventory](services.json) remains the operation target,
not evidence of semantic completeness.

## Ownership

`internal/services/sns` owns typed topics, topic incarnations, subscriptions,
publication admission, filtering, signing, retries, dead-letter transitions,
service metrics and feedback selection. Its repository interface is implemented
by the shared memory transaction domain and service-owned SQLC tables in SQLite.
Publications retain only the protocol variants needed by matching subscriptions
or an enabled FIFO archive: the native message ID is shared, while
`(message ID, protocol)` identifies retained body variants.
A body is not copied into a separate publication row for every subscriber.

Publication results, archive entries, selected delivery work, metric samples and source events
join the resource transaction. Delivery runs outside that transaction through
SNS's small consumer-defined interface. `internal/integrations/sns.go` enters
ordinary SQS send or Lambda asynchronous-acceptance commands under the SNS
service principal with the source topic. Current destination policies apply;
a successful Lambda acceptance does not claim successful customer execution.
EventBridge, CloudWatch alarm actions and CloudTrail log notifications use SNS
publication through typed adapters rather than inserting messages into SNS or
SQS tables. CloudTrail owns its preflight/publication status; SNS owns subscriber
retries. See [CloudTrail notification evidence](cloudtrail.md#sns-log-file-notifications).

Standard-topic SNS signing uses retained RSA-2048 material and the advertised `PublicEndpoint`.
Versions 1 and 2 produce actual SHA-1/SHA-256 signatures and serve the public PEM
certificate at that endpoint. The CLI supplies its listener origin unless
`-public-endpoint` overrides it. Container consumers need a container-reachable
origin. Missing delivery/signing configuration is not replaced with a fabricated
notification. Signing material and accepted work survive SQLite reopening;
consistent whole-instance snapshot/fork/restore remains broader kernel work.


## Regional SQS and Lambda delivery

SQS and Lambda subscriptions route through the same typed consumers across
Regions. The destination ARN selects the resource and request Region; the source
account, topic ARN and causal parent remain intact for authorization and audit.
The adapter uses the generated commercial opt-in Region catalog, not another
hand-maintained list or a separate policy evaluator.

Native SQS delivery established these accepted resource-policy principals:

| Source and destination | Accepted SNS principals |
| --- | --- |
| Default Region → default Region | `sns.amazonaws.com` |
| Default, same or different opt-in Region → opt-in Region | `sns.amazonaws.com` and `sns.<destination-region>.amazonaws.com` |
| Opt-in Region → default Region | `sns.<source-region>.amazonaws.com`, not the generic principal |

At an opt-in destination these are aliases of one service actor, not independent
fallback attempts. Default-to-opt-in condition probes exposed the generic
`aws:PrincipalServiceName` and both names in `aws:PrincipalServiceNamesList`;
an explicit deny against either alias defeated an allow against the other.
Opt-in-to-default probes exposed only the source-regional name; a deny against
the generic principal did not match that actor. See AWS's
[cross-Region delivery guidance](https://docs.aws.amazon.com/sns/latest/dg/sns-cross-region-delivery.html)
and [service-principal condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html).
Single-valued actor context for the other opt-in routes and non-commercial
principal behavior remain uncalibrated.

`testdata/aws/sns/regional_sqs.json` retains wrapped/raw delivery, FIFO ordering
identity, source-account/ARN denials, reciprocal alias denies, source DLQs and
repair. `regional_lambda.json` retains actual Python 3.12 alias execution in
default and opt-in Regions, permission removal, DLQ delivery and repair. Native
captures used one account; cross-account regional SQS source conditions were
exercised locally, not measured against AWS in these captures.

Memory and SQLite SDK replay consume those observations through real SQS and
Docker Lambda. An executable SQLite restart also preserved subscriptions,
queued receipts, the FIFO archive and a SHA-512-protected S3 Lambda package.
Subsequent regional denial/repair and archive replay succeeded; SNS metrics
recorded 13 deliveries, 3 failures and 3 source-DLQ redrives. This executable
stopped with no pending SNS intent; pending accepted-work recovery is covered by
the separate SDK reopen scenario rather than inferred from that restart.

## Cross-account SQS ownership

The subscriber owns a registration, independently of the account in its SNS ARN.
A queue-owner `Subscribe` is automatically confirmed and protected against
unauthorized deletion. Another account's `Subscribe` creates a pending
registration and delivers a signed `SubscriptionConfirmation` to the real queue.
It uses the same typed SQS adapter, source-topic policy context, transaction log
and retained delivery jobs as ordinary notifications; no separate confirmation bus
or in-process queue shortcut exists.

`cross_account_confirmation.json` captures both directions between the topic
owner and queue owner, including a real assumed role. New role subscriptions
expose the issuing IAM role in `SubscriptionPrincipal`, not its STS session ARN.
Get/SetSubscriptionAttributes require the subscription owner; being the topic owner
does not grant access to another account's subscription attributes. Duplicate
Subscribe returns the same ARN and preserves its owner. A queue-owner rejoin of an
existing pending registration does not auto-confirm it. A non-queue-owner repeat
can deliver another confirmation even when the registration is already active.

`AuthenticateOnUnsubscribe=true` requires a signed confirmation from the
subscription-owner account when changing protection. Default/false confirmation
does not transfer ownership; initial confirmation leaves
`ConfirmationWasAuthenticated=false`, including signed confirmation.
Repeating default/false confirmation on an already protected registration
preserves its protection and succeeds. Token possession supplies resource consent;
signed requests still enforce IAM identity permission and explicit denies.
An owner can subsequently protect a default/false-confirmed registration using
its token; another protected confirmation is rejected.

Unsigned SQS Unsubscribe is denied even for default/false confirmation. A signed
nonowner can unsubscribe an unprotected registration; the topic owner can also
unsubscribe a protected foreign-owned registration. Those transitions retain
`Deleted` list projection, owner-accessible attributes and an actual
`UnsubscribeConfirmation`. They cancel admitted notification delivery without
discarding earlier confirmation tokens. Token recovery restores the same ARN.
Queue-owner re-subscription returns that ARN but leaves the registration `Deleted`;
it does not resume delivery. `deleted_rejoin.json` captures four such listings
and four bounded absent-publication windows over 99 seconds, followed by actual
cancellation-token recovery and a positive queue receipt. Owner deletion removes
the registration, including an already `Deleted` registration.

FIFO control messages use SQS `MessageGroupId=Subscription` and the confirmation
envelope's `MessageId` as `MessageDeduplicationId`. Application notifications
retain their publisher-supplied group/deduplication values.

Schema 147 preserves protection for previously auto-confirmed AWS endpoint
subscriptions. The executable upgrade from schema 146 rejected an unrelated
account's deletion, received real standard/FIFO control envelopes, and restored
both old-token and cancellation-token subscriptions after another process
restart. Original ARNs and application FIFO grouping survived. SDK replay
exercises native ownership, denial, list-state, duplicate-Subscribe and recovery
observations on memory and SQLite, including independent signature verification.
Native cleanup independently found all three topics, eleven subscriptions and
eleven queues absent. This capture does not establish token-expiry timing,
third-account/same-account-other-principal behavior or every stale-token error.
Primary contracts: [cross-account queues](https://docs.aws.amazon.com/sns/latest/dg/sns-send-message-to-sqs-cross-account.html)
and [ConfirmSubscription](https://docs.aws.amazon.com/sns/latest/api/API_ConfirmSubscription.html).

## Confirmation token lifetime and authority

`confirmation_lifetime.json`, `confirmation_lifetime_supplement.json` and
`confirmation_lifetime_scope.json` retain fresh native SQS-delivered tokens,
cross-account callers and session-policy limits. A valid token identifies the
original subscription independently of the requested TopicArn. Native confirmation
accepted another account's topic and a nonexistent topic parameter, returning the
original subscription ARN. Signed IAM evaluation instead uses the **requested**
TopicArn: reciprocal topic-restricted STS sessions and an explicit deny establish
that distinction. Topic parameters remain syntactically and regionally validated.

Unknown tokens return `InvalidParameter`; valid tokens whose subscription was
physically removed return `NotFound`, including after a replacement registration
is created for the same endpoint. Default/false confirmation of a protected active
subscription is idempotent; repeating `AuthenticateOnUnsubscribe=true` returns
`AuthorizationError`. These calls never downgrade existing protection.

Native default confirmation of a previously confirmed registration can succeed
after topic deletion or same-name recreation without joining the new topic
incarnation. Pending registrations still require their original topic. The scope
capture retains an empty recreated-topic list and three bounded absent queue
receives after confirming a previously cancelled registration. This does not
supersede `deletion.json`: an already-active retained subscription can still route
new publications during deletion propagation, even though the new topic's
membership excludes it. Confirmation does not revive a cancelled old route;
publication fanout must not discard every retained active route by topic ID.

Schema 148 removes token deletion cascading from subscription deletion and
backfills existing tokens' typed subscription keys. Tokens retain the documented
two-day expiry; new token issuance prunes expired records in the same transaction.
Tokens already erased by an older database cannot be reconstructed. An actual
147→148 executable upgrade preserved a previously issued token, then a further
restart preserved `NotFound` after owner removal. Service-time advancement verified
the two-day `InvalidParameter` boundary and a fresh positive queue receipt.
The executable also reproduced and fixed cancelled old-subscription delivery from
a recreated topic. The native probes did not measure two-day expiration timing.
All six topics, three queues and their registrations were independently checked
absent; these captures left no pending subscription references.
The broader SNS race check exposed an overbroad current-topic fanout filter.
Removing that filter restored the earlier native active-route fixture without
reviving cancelled routes. A further executable SQLite restart delivered through
the retained active subscription, kept the cancelled token's old route silent,
and delivered exactly once through a newly subscribed replacement.

## Cross-account Lambda ownership

`cross_account_lambda.json` captures real Python 3.12 execution across two accounts.
The function owner's Subscribe auto-confirms; another account's Subscribe creates
a caller-owned pending registration. Repeating that latter request against an
already active function-owner registration preserves its ARN, owner and state
while delivering a real `SubscriptionConfirmation`.

Lambda confirmation uses the ordinary `Records[0].Sns` envelope, with
`EventSubscriptionArn=null`, `Token`, `SubscribeUrl` and `SigningCertUrl`.
It omits ordinary notification Subject, attributes and unsubscribe URL fields.
The same retained delivery interface invokes the actual Lambda runtime; no
in-process handler or special confirmation consumer exists. Function permission
is checked at delivery, not subscription admission. The native capture includes
successful admission without invoke permission, bounded absent publication, and
positive delivery after permission repair.

Subscription attributes remain owner-only. Protected confirmation of a
topic-owner-created pending subscription requires that topic owner's identity,
not merely the function owner's identity. Topic-owner cancellation of a
function-owner registration retains its owner-accessible metadata and `Deleted`
listing; repeating Subscribe does not reactivate it. The captured Lambda bucket
contains no cancellation-control invocation. Owner deletion removes the
registration; another Subscribe creates a new ARN and delivers again.
Repeated deletion of the removed registration succeeds with caller IAM
authorization, without requiring a new topic-policy grant.

Fixture replay uses the unchanged captured customer archive, actual IAM-user/STS
callers and real Docker Lambda execution on both memory and SQLite. It compares
full consumer payloads after checking signatures, identity and dynamic fields.
Setting `FilterPolicy={}` on a fresh registration leaves both filter attributes
absent, as captured natively. Account-wide fixture listings retain only the
probe's own topic entries; that projection is recorded in the fixture.

An actual executable upgrade from `d62116c` changed the cross-account Subscribe
result from `NotImplementedException` to real Lambda delivery. A further SQLite
restart preserved pending and deleted registrations and their original tokens;
confirmation resumed actual execution, and physical owner deletion produced a
new registration. Six delivered Lambda envelopes passed independent OpenSSL
signature verification. These local restart checks do not establish native
token-expiry or deletion deadlines.

All six native topics and three receiver functions, roles, buckets and log groups
were independently checked absent. One failed cleanup attempt used the wrong
confirmation owner before deleting its topic, leaving this nonbillable native
pending reference:
`arn:aws:sns:us-east-1:000000000000:stackd-xlambda-6d7e790aa8-A:06d5a60e-5550-45bf-a2bc-5d0a04938721`.
Owner Unsubscribe rejects pending state; the delivered token returns NotFound
after topic deletion, including an independently removed same-name recreation.
AWS-managed expiry remains outstanding. Failed cleanup is retained, not counted
as a successful lifecycle replay.

## HTTP/S confirmation and delivery

HTTP/S subscribers remain pending until the recipient uses a token delivered by
an actual HTTP POST. Pending publication is excluded rather than saved for later
backfill. `Subscribe` returns `pending confirmation` unless `ReturnSubscriptionArn`
is true; listings expose `PendingConfirmation`, while attributes retain the real
ARN. Repeated pending subscriptions keep the same ARN and issue independent
tokens: both previously delivered and newer links remain usable for their own
documented two-day lifetime.

Schema 142 retains typed subscription state, individual confirmation tokens,
native signed control messages and existing delivery jobs. The shared service
clock checks expiry and deletes expired pending subscriptions; subscription
deletion also collects its tokens and delivery work. No endpoint POST runs in a
repository transaction. Pending confirmation and accepted active delivery both
survive reopening without publisher credentials or a second envelope protocol.
Tokens are native endpoint capabilities and are redacted in confirmation audit
requests, including the observed signed CloudTrail projection.

Only `ConfirmSubscription` and `Unsubscribe` have the native unsigned Query
exception in the shared gateway. Generated Query binding, request limits and
rejection of partial signing material still apply. Anonymous requests do not
become topic-owner identities. Token scope/expiry authorizes anonymous confirmation;
signed requests also enforce current IAM permission for `sns:ConfirmSubscription`.
`AuthenticateOnUnsubscribe=true` requires an authenticated subscriber-owner
confirmation and prevents anonymous deletion. An already protected, confirmed
subscription rejects repeated confirmation rather than silently succeeding.
Anonymous unsubscription of an
unprotected HTTP endpoint emits a retained signed `UnsubscribeConfirmation`;
its separate token can reactivate the same subscription. Such subscriptions
list as `Deleted` until reactivation or cleanup and receive no publications.

`internal/integrations/sns_http.go` sends real POSTs with native message-type,
message-ID, topic/subscription ARN, raw-delivery and content-type metadata and the
SNS user agent. Wrapped messages use retained RSA signatures; raw HTTP bodies
contain only the publisher's selected protocol body, not message attributes.
Transport cancellation is bounded to 15 seconds. Current TLS certificate and
hostname verification remain enabled; redirects never forward bodies or inline
credentials. HTTPS inline credentials support challenge-based Basic and RFC 2617
MD5/MD5-sess Digest `auth`; unsupported authentication challenges fail instead
of claiming delivery. Operator-supplied HTTP clients may configure trusted CAs.
Local loopback/private endpoints are intentional emulator capability, not AWS
private-endpoint parity.

HTTP policies retain topic defaults, subscription overrides, override disabling,
content types, throttle limits and bounded retry phases. HTTP 2xx means endpoint
acceptance; 429/5xx and transport failures retry. Non-retryable HTTP responses
complete source delivery without redrive: a fresh native HTTP 400 capture produced
Delivered=1 and Failed=0, not a dead letter. This counter is not proof of application
acceptance. Exhausted notification retries enter the real SQS DLQ path; failed
confirmation attempts count in metrics but do not enter the DLQ.
Self-throttled work is requeued without consuming an attempt, using retained
per-subscription service-time capacity. Retry curves and throttling are a
deterministic local model, not AWS's randomized dispatch or exact timing:
native captures with one immediate retry still arrived roughly 17–21 seconds
apart. Token expiry follows documentation; the capture did not wait two days.

`testdata/aws/sns/http_delivery.json` records September 22, 2026 native requests
delivered to an owned Lambda Function URL and stored in owned S3 objects,
including wrapped/raw bytes, headers, repeated confirmation, invalid tokens,
authenticated deletion protection, cancellation/reactivation, HTTP 400/503
outcomes and actual SQS dead letters. The initial Basic/Digest 401 challenge
requests reached the receiver, but no authenticated second request reached the
Function URL handler; that service's own auth boundary prevents claiming a
completed native handshake. Local regressions use a real TLS challenge server.
Owned topic, active subscriptions, queue, bucket, Lambda URL/function and execution
role were deleted and absence independently checked. Four pending subscription
tombstones remained in native account listings: AWS rejected their actual-ARN
Unsubscribe as pending and their delivered-token Confirm as missing-topic, even
after a temporary owned same-name recreation (also deleted). Their AWS-managed
expiry could not be accelerated; exact residual references and all absence checks
are retained in the fixture. No billable receiver or delivery resource remains.

`http_confirmation_authority.json` captures a fresh native IAM user with a valid
delivered token: both missing identity permission and a propagated explicit deny
reject signed protected confirmation. A successful then explicitly denied
`GetTopicAttributes` call establishes policy propagation before the latter case.
Repeated protected confirmation also returned `AuthorizationError`. The regression
failed before adding the ordinary SNS authorization boundary.
All final-probe resources and active subscriptions were removed and absence checked.
Two earlier capture failures are retained rather than presented as conformance:
a CLI download-argument error and an unpropagated IAM access key. The first left
one additional pending native subscription reference awaiting AWS expiry; its
topic and all billable receiver resources are gone.

`http_metrics.json` isolates successful delivery, HTTP 400, exhausted HTTP 503,
and failed confirmation on separate native topics. The receiver retains its
actual response beside each request; direct HTTP controls verify the deployed
200/400/503 responses. CloudWatch confirms per-attempt failures, successful
confirmation counts, and no HTTP 400 redrive. The fixture retains two failed
setup attempts (control request encoding and topic-policy shape), their cleanup,
and the final successful deployment. Fixture-driven public SDK replay covers
both stores without assuming that a permanent HTTP error implies a dead letter.
All three deployments' functions, buckets, roles and queues were removed and
absence checked. Confirmed subscription remnants survived topic deletion; explicit
Unsubscribe removed them. No additional pending subscriptions remain from this probe.

Public SDK regressions in `integration/sns_http*_test.go` cover lifecycle,
payload identity, signature verification, independent retained tokens, reopen,
expiry, HTTP completion metrics and exhausted-retry DLQ boundaries on memory/SQLite.
Actual executable checks additionally verified encrypted HTTP retries with identical
payloads after SQLite restart, retained pending-token confirmation, independent
OpenSSL signature verification, and SNS → Firehose → S3 bytes after source deletion.

Primary contracts: [Subscribe](https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html),
[ConfirmSubscription](https://docs.aws.amazon.com/sns/latest/api/API_ConfirmSubscription.html),
[Unsubscribe](https://docs.aws.amazon.com/sns/latest/api/API_Unsubscribe.html),
[HTTP payloads](https://docs.aws.amazon.com/sns/latest/dg/http-notification-json.html),
[retry policies](https://docs.aws.amazon.com/sns/latest/dg/sns-message-delivery-retries.html)
and [HTTPS authentication](https://docs.aws.amazon.com/sns/latest/dg/sns-http-https-endpoint-as-subscriber.html).

## Role-authorized Firehose subscriptions

Firehose subscriptions retain `SubscriptionRoleArn`; Subscribe (including
idempotent calls) and role replacement enforce caller `iam:PassRole` plus current
SNS role trust, without sending a destination record or issuing admission-time
credentials. FIFO rejects Firehose. Endpoint syntax is validated, but destination
existence and write permission are delivery-time facts. Other-region stream ARNs
are admitted as observed natively.

Cross-account subscriptions require the caller to own the Firehose endpoint.
A topic owner cannot subscribe another account's stream, including when the role
attribute is missing. The stream owner can subscribe to an authorized foreign
topic with its own role; an explicit session-policy PassRole deny still rejects.
`cross_account_firehose.json` retains native ownership, foreign-role rejection,
trust repair and actual S3 consumer objects. Role trust receives the topic's
`aws:SourceArn` and **topic-owner** `aws:SourceAccount`, not the subscribing
account. A SourceAccount condition naming the stream owner was rejected;
the topic-owner condition succeeded and delivered.

Topic-owner cancellation retains the foreign-owned registration as `Deleted`.
The subscription owner can still read its attributes and then remove it.
Delivery-time role write denial produced a bounded absence while a direct
Firehose control reached S3; new publications delivered after permission repair.
All owned native streams, topics, subscriptions, buckets and roles were
independently checked absent. Memory/SQLite replay checks native metadata and
actual S3 bytes; an executable restart delivered a previously accepted
cross-account publication into an initially empty S3 bucket under topic-scoped
role trust.

The integration resolves current SNS role authority and enters ordinary Firehose
`PutRecordBatch` with one record, never a SNS-principal fallback. Native evidence
establishes this action: a batch-only role delivered real S3 bytes, while a
PutRecord-only role failed in SNS's delivery-status logs. Wrapped bodies omit SNS
signature fields and end with LF; raw records contain the exact supplied body
without an added delimiter. Firehose's retained S3 pipeline owns final object
delivery. See [Firehose evidence](firehose.md) for fixtures, role recovery,
session and batching limits.

## Delivery-status logging

HTTP/S, SQS, Lambda and Firehose feedback configuration is owned by SNS and
retained in typed memory/SQLC state. Success/failure role ARNs and optional
success-sample rates use the native protocol-prefixed topic attributes. An unset
rate remains absent from `GetTopicAttributes`, including after SQLite reopen;
explicit zero suppresses success logs and 100 includes them. Intermediate rates
use stable sampling from the retained delivery identity, without another ledger.
Role-only configuration enables success logging. A fresh native experiment first
established actual logging authority, then observed all 32 subsequent publications
delivered and logged while the sample-rate attribute remained absent; this does
not establish AWS's internal random-sampling algorithm.

Role assignment requires caller `iam:PassRole` for `sns.amazonaws.com` and current
SNS trust. Native configuration checks distinguish an existing wrong-trust role
(`InvalidParameter`) from a missing role (`AuthorizationError` for PassRole).
Clearing a role needs no PassRole and preserves the independently configured rate.
A trusted role without Logs permission is admitted: configuration does not write
log groups or preflight delivery-time permissions.

The endpoint adapter returns the actual target outcome; SNS owns completion,
retry, sampling and record construction. After the source transition commits,
`SNSFeedback` assumes the configured role with session name `AWS-SNS` and uses
ordinary authorized CloudWatch Logs commands. Success records use
`sns/<region>/<account>/<topic>`; failures use its `/Failure` group. Missing groups
and streams are created through the Logs service. Existing resources do not
require create authority merely to append, and every write still requires current
`logs:PutLogEvents` authority. There is no publisher/service-principal fallback.

Native records preserve these distinctions:

- SQS success uses status 200 and actual `sqsRequestId`/`sqsMessageId`; Lambda
  acceptance uses 202 and the request ID observed by the real runtime. Firehose
  uses the actual role-authorized `PutRecordBatch` request ID, not its record ID.
- Permanent denied SQS delivery reports status 400 with
  `AWS.SimpleQueueService.NonExistentQueue`; denied Lambda reports 403 with
  `AccessDeniedException`. Their native provider request identifier is
  `Unrecoverable`. Firehose denial uses its numeric error/status projection.
- HTTP records contain the actual response status and reason phrase, not the
  response body. Native 400/302 responses are `SUCCESS`; 429/503 failures are
  recorded per attempt. Retry records retain message identity, change delivery
  identity and expose prior-attempt count only after the initial attempt.
- HTTP confirmations and cancellation confirmations are logged without
  notification MD5 or redrive policy. Notifications retain body MD5 and any
  configured redrive policy as a JSON string. Endpoint passwords use the existing
  subscription display masking.

Dwell ends at the source's handoff to its endpoint adapter, using service time;
it does not include the endpoint's response latency. An actual two-second HTTP
consumer reproduced a 2023 ms post-response measurement; the corrected executable
reported 7 ms while the consumer still took 2000 ms. The existing HTTP replay
retains this boundary with a deterministic clock advance during cancellation.
Native internal timing and stream allocation are not inferred from those numbers;
the local sink currently uses one opaque stream identity per instance.

Feedback rejection is diagnosed after delivery and does not change target
acceptance or enqueue a new logging outbox. The native permission-denial window
delivered both SQS and Lambda notifications without feedback; restoring authority
logged a later publication, not the earlier denied-time message within the
roughly seven-minute observation. This is bounded evidence, not a universal
native logging-retry or replay guarantee.

`managed_feedback.json`, `external_feedback.json` and `feedback_sampling.json`
retain actual endpoint receipts, raw Logs records, authority transitions and
cleanup. Public SDK replay covers memory/SQLite, retained HTTP retries, role
changes, append-only Logs authority, real Docker Lambda request IDs and Firehose
S3 effects. Actual CLI restarts preserve feedback configuration, omitted rate
attributes and old log events; subsequent SQS receipts correlate with feedback,
and CloudTrail records the assumed `AWS-SNS` execution role.

Primary contracts: [delivery status](https://docs.aws.amazon.com/sns/latest/dg/sns-topic-attributes.html)
and [topic attributes](https://docs.aws.amazon.com/sns/latest/api/API_SetTopicAttributes.html).

## Native publication and subscription distinctions

The fixtures retain account, region, operation inputs, status/error results,
correlated notifications and cleanup. Their observed distinctions include:

- Standard topic controls, tags and policy updates preserve atomic rejection.
  `AddPermission` accepts SNS action names such as `Publish`, not `sns:Publish`
  or wildcard spellings. Empty policy statements and removing the last statement
  are not silently converted into a permissive policy.
- Ordinary IAM calls do not acquire the legacy `aws:SourceOwner` condition.
  Native CloudWatch service publication can satisfy the owner-scoped default
  topic policy. SNS reuses the existing IAM evaluator and resource-policy binder;
  it does not have a second permissive authorization path.
- Native EventBridge publication supplies the rule `aws:SourceArn` and its
  `aws:SourceAccount`, but not legacy `aws:SourceOwner`. Three allowed topic
  policies produced signed SNS notifications; wrong-source and source-owner
  policies produced EventBridge DLQs with `NO_PERMISSIONS`. Replay preserves
  SNS's `AuthorizationError` diagnosis rather than classifying it as an
  unspecified target failure.
- SQS queue owners can subscribe their own queues in the same or another Region,
  including to an authorized topic in another account. Same-account regional
  Lambda subscriptions are supported. Other endpoint-owner confirmation paths
  remain open.
- Deleting and recreating a topic name creates a new incarnation. Native old
  subscriptions remained addressable and routable during the captured window,
  while the recreated topic listed its new subscriptions. The local five-minute
  deletion propagation interval is a controllable choice, not a measured AWS
  deadline.
- Publication admission counts original UTF-8 message and attribute bytes against
  256 KiB. Subject is excluded from that size. Native subject limits use 100
  UTF-16 code units and reject control characters, rather than counting UTF-8
  bytes or Go runes.
- String attributes reject supplementary Unicode with `InvalidParameter`; BMP
  text remains valid. This SNS attribute restriction does not apply to the
  message body, Subject, or SQS string attributes.
  In `PublishBatch`, an invalid string attribute rejects the entire request,
  including otherwise valid entries; it is not a per-entry publication failure.
- Standard topics accept optional `MessageGroupId` containing 1–128 printable
  non-space ASCII characters. Empty, whitespace, non-ASCII and oversized values
  produce `InvalidParameter`; invalid batch groups fail their own entries rather
  than rejecting valid siblings. Validation shares the SQS identifier contract.
- The retained group reaches SQS standard subscriptions as the `MessageGroupId`
  system attribute, with raw or wrapped delivery, and survives SQS-subscription
  dead-letter routing. It is not inserted into the signed SNS JSON body or Lambda
  payload. SQS remains responsible for fair-queue scheduling, not FIFO ordering.
  [Publish](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html) defines
  this standard-topic forwarding contract.
- Structured publication selects the destination protocol body before body
  filtering. Missing overrides use `default`; repeated JSON keys use their final
  value. Captured numeric/null defaults become strings, container defaults fail,
  and selected empty string bodies are legal for wrapped delivery. Captured
  structured publications retain their message attributes.
- `PublishBatch` retains per-entry success/failure identity. Invalid numeric
  attributes reject the whole request; a missing structured default can reject
  one entry while another is accepted. A rejected request has no publication
  samples or delivered messages.
- SNS preserves the original Number attribute spelling in its notification.
  SQS normalizes Number values in its own attributes. Native SQS send checksums
  cover the original supplied spelling, while received checksums cover the
  selected, normalized attributes. Those response digests are computed at their
  response boundary, not persisted as unused message fields.

### FIFO acceptance and delivery

The [AWS FIFO deduplication contract](https://docs.aws.amazon.com/sns/latest/dg/fifo-message-dedup.html)
defines the five-minute window and topic/group scopes.
The September 22, 2026 native captures in `fifo.json`, `fifo_edges.json`,
`fifo_projection.json` and `fifo_redrive.json` establish these distinctions:

- FIFO topic names end in `.fifo` and require `FifoTopic=true` at creation.
  Topic mode is immutable; setting `true` again is accepted. Boolean values are
  case-insensitive `true`/`false`, not arbitrary truthy strings. Standard topics
  reject FIFO-only attribute updates. `ContentBasedDeduplication` is mutable.
  An omitted `FifoThroughputScope` behaves as Topic but is absent from the
  captured default attribute map. Explicit Topic→MessageGroup is accepted;
  MessageGroup→Topic is rejected.
- FIFO subscriptions support SQS, including standard queues, not Lambda.
  Standard SNS→FIFO SQS subscription is rejected with `InvalidParameter`;
  the earlier unimplemented-path comment was not a native admission contract.
  For FIFO topics, a subscription's DLQ must match its endpoint queue type.
  A standard topic accepted a FIFO DLQ setting; actual destination admission
  remains authoritative and configuration acceptance does not imply delivery.
- FIFO publications require a valid group and either an explicit deduplication
  ID or content-based deduplication. Topic scope deduplicates across groups;
  MessageGroup scope separates groups. IDs share SQS's 1–128 printable non-space
  ASCII boundary. Duplicate success returns the original SNS MessageId and
  SequenceNumber without new fanout. Receipt expiry belongs to the original
  acceptance, not the most recent duplicate; the native 310-second retry produced
  a new publication. Local service time uses the documented five-minute window.
- Content-based IDs are SHA-256 of the original message bytes, excluding
  attributes and Subject. Explicit IDs override hashing and share the same
  deduplication namespace. Structured JSON is accepted, including with
  content-based deduplication; differently ordered JSON maps have different
  hashes even when their projected SQS body is identical.
- FIFO batch duplicates preserve the same accepted identity, including duplicates
  within one batch. Captured missing/invalid group or deduplication values,
  empty messages and invalid Subjects reject the entire FIFO batch. Standard
  topics retain their existing per-entry content failure behavior.
- Deduplication happens before filtering. A filtered publication still suppresses
  a later matching publication with the same ID, while the next distinct
  publication progresses. Filters do not retain a blocking delivery placeholder.
- Raw FIFO receipts contain the projected body and message attributes. Wrapped
  FIFO-topic notifications are unsigned: Signature, SignatureVersion and
  SigningCertURL are absent. Ordinary envelopes contain the SNS SequenceNumber;
  the captured structured envelopes omit it. SQS FIFO receives the publisher's
  group and deduplication ID (or original-body hash), not SNS's generated
  MessageId. SQS generates its own distinct SequenceNumber. FIFO-topic delivery
  to standard SQS omits group/dedup system metadata; standard-topic fair-queue
  forwarding remains unchanged.

SNS retains deduplication receipts under the topic incarnation and sequences
accepted publications in the shared transaction with deliveries, audit and
metrics. Topic deletion drops that incarnation's receipts; recreation does not
reuse them. Each subscription/group has its own retained predecessor chain.
A pending or retrying predecessor prevents only its own later group work from
running; other groups and subscriptions remain eligible. Target acceptance or a
terminal primary failure releases the next work, including while separate DLQ
delivery is pending. SQLite schema 140 retains these boundaries across reopen.
SQS remains authoritative for its own ordering and deduplication: a queue scoped
deduplication setting can suppress messages from different SNS MessageGroups.
SNS does not promise an atomic transaction across an external send and its own
completion record; FIFO SQS protects retries within its deduplication window,
while standard SQS retains its at-least-once boundary.

The SDK regression `TestSNSNativeFIFO` replays the native controls, response
identity and actual raw/wrapped destination payloads on memory and SQLite.
`TestSQLiteSNSFIFORecoveryAndGroupProgress` covers retained pending-group
ordering, independent subscriptions/groups, restart receipts, expiry and
recreation. These focused checks passed. The fixture replay drains each accepted
publication before sending the next: queue-wide SQS deduplication chooses the
first arrival across independent SNS groups, not a promised cross-group order.
An actual AWS CLI workflow restarted the SQLite executable with pending topic
deduplication state, verified the original duplicate identity without another
delivery, then advanced service time beyond expiry and received the new
publication through raw/wrapped FIFO and wrapped standard SQS subscriptions.
Native captures do not establish throughput quotas, exact sequence-number
magnitudes or managed retry jitter. All eleven owned topics and ten queues across
the five native capture runs were deleted and independently returned not-found.
Standing identities and resource policies were not changed.

### Encrypted topic publication and retained delivery

`KmsMasterKeyId` is a literal topic setting, including key ID, key ARN, alias
name and alias ARN. Configuration does not claim that a key exists or is usable.
The September 22 `encryption.json` capture accepted `nonsense` and a nonexistent
alias at update, then rejected publication with native wire code `KMSNotFound`.
Empty reset removes the attribute from readback. Standard and FIFO topics accept
the setting; ordinary and batch publication use the same actual KMS boundary.

Cold publication preserves the publisher for `GenerateDataKey` and `Decrypt`
through `kms:ViaService`, with encryption context `aws:sns:topicArn` equal to the
topic ARN. Native IAM captures denied a publisher without KMS rights and one with
only GenerateDataKey; a settled policy granting both succeeded. A conditional
customer-key policy admitted the exact topic and denied a different fresh topic.
No additional `sns.amazonaws.com` key-policy grant is required. The EventBridge
capture delivered a real wrapped notification with an `events.amazonaws.com`
key grant and no SNS grant; its no-grant receive window was bounded to five
seconds, not proof of an AWS delivery deadline.

The AWS [encryption scope](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html)
protects message bodies, not Subject, attributes, IDs, timestamps, topic metadata
or metrics. SNS stores AES-256-GCM ciphertext with the actual KMS-wrapped data key
and resolved original CMK ARN. The actual KMS encryption context is retained with
each message in memory and typed SQLite rows, not reconstructed from a later
caller or current topic configuration. Migration 146 preserves the topic-only
binding of previously accepted keys. It never stores publisher secret keys, session
tokens or plaintext data keys. Filtering and signing see the original protocol-selected body; raw,
wrapped and unsigned FIFO projections remain unchanged. Key reset/replacement
affects new publications, not already accepted encrypted or plaintext work.

KMS and body encryption/decryption run outside SNS transactions. A preparation
miss rolls back provisional admission, then rechecks current topic incarnation,
configuration, authorization and subscriptions before committing messages,
deduplication receipts, delivery chains, metrics and audit. SQLite schema 141
retains encrypted work and its original key independently of topic settings.
Schema 145 also retains the verified publisher identity, session restrictions,
tags and condition context in typed rows. Cold live restoration calls ordinary
KMS Decrypt with that identity, the original key and exact topic context; current
IAM/key authority is re-evaluated and the actual outcome is audited. No private
decrypt bypass remains. Pre-145 encrypted live records lack that caller snapshot
and fail closed rather than borrowing topic-owner authority.

AWS documents [up-to-five-minute data-key reuse per publisher/topic](https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html).
Native warm standard/FIFO publishes succeeded after DisableKey and reached SQS;
a cold topic's Publish and whole PublishBatch failed with `KMSDisabled`.
An accepted-before-disable body was also received afterward.
`encryption_live_retry.json` adds actual HTTPS retries of one original message
while its source key remained Disabled: HTTP 503 receipts continued through age
579 seconds. A later SNS-invoked KMS Decrypt returned DisabledException at about
641 seconds, under the original IAMUser identity. Warm delivery therefore does
not eliminate the source-key dependency. No successful notification or DLQ
arrival was observed during the bounded post-repair window; a separate direct
HTTPS 200 control is not counted as SNS recovery.

`encryption_live_authority.json` isolates the original publisher's explicit
`kms:Decrypt` Deny while the CMK remains Enabled and its SNS service grant stays
unchanged. Actual HTTPS 503 attempts continued through age 591 seconds; a later
SNS-invoked Decrypt recorded the original IAMUser and an explicit identity-policy
denial. Removing Deny did not produce a same-message success or DLQ receipt
during the 755-second post-repair window. This establishes cold caller authority,
not a native recovery schedule or terminal result.

Forwarded KMS audit retains that caller, with `invokedBy`, source IP and user agent
identifying `sns.amazonaws.com`. Native `AccessDenied` records omit key/context
parameters and resources; the public KMS error remains `AccessDeniedException`.
AWS's provider-created forward-access credential IDs/session timestamps are not
manufactured locally and remain an audit conformance boundary.

`encryption_role_cache.json` captures restricted STS sessions with the same role
and session name as a successful publisher. They received `KMSAccessDenied` on
the warm topic, as did a differently named restricted session; a session policy
allowing the required SNS/KMS actions succeeded and reached SQS. Session policy
restrictions therefore cannot inherit a less-restricted session's warm authority.

`encryption_equivalent_sessions.json` distinguishes credential issuance from
authority. Within both a no-session-policy cohort and a byte-identical allowing
session-policy cohort, new credentials with the same or a different session name
published successfully after the warmed CMK was disabled; every publication
reached SQS. Fresh-topic controls required successful KMS calls while the key was
enabled. Ordinary AssumeRole publication reuse therefore keys on the role's
issuer identity and retained authority, not access-key ID or session name.
Session policies/ARNs, tags, source identity, MFA, trusted session context and
forwarding context remain cache dimensions. The capture does not establish
sharing across those dimensions, between the two policy cohorts, across other
credential classes or service sources, or an exact distributed cache TTL.

`encryption_alias_retarget.json` captures a warm topic through an alias retarget
from A to disabled B. The immediate publication reached SQS, while a fresh topic
returned `KMSDisabled` 3.707 seconds after retarget completion. The original topic
also returned `KMSDisabled` at baseline age 370 seconds. Enabling B initially
still produced that error; a retry after fifteen seconds reached SQS with
successful B crypto records. All three failed publications correlate to B's
native KMS request IDs. Baseline crypto establishes A use; the warm receipt alone
does not expose its envelope key. The capture bounds behavior, not a transition
instant or fleet-wide deadline. Replay covers the confirmed repair, not the one
transient post-enable failure: local KMS state changes remain immediate.

`encryption_service_sources.json` captures eight EventBridge custom-bus cases in
one account and `us-east-1`. Unconditional, exact rule ARN, exact source account
and exact organization key-policy grants produced actual SQS receipts. A source
ARN equal to the SNS topic and `Null=true` source ARN/account/organization grants
produced actual EventBridge `NO_PERMISSIONS` DLQs. The topic's source conditions
were unchanged; only topic-scoped KMS policy conditions differed.

AWS's [SNS key-management guide](https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html)
still calls those EventBridge KMS conditions unsupported. Unsupported is not
evidence that the values are absent: this measured path supplies them. Local
authorization preserves them; the capture does not establish a portable AWS
guarantee, default-bus, cross-account, role-target or other-region behavior.
No denied service-principal KMS audit record appeared in that capture's bounded
lookup window; it does not establish absent auditing.

`encryption_event_source_cache.json` isolates two rules on one encrypted topic.
With the key disabled, A delivered both before and after B's first publication;
B and a never-warmed fresh-topic control reached actual `NO_PERMISSIONS` DLQs.
The messages contain SNS `KMSDisabled` and KMS request IDs matching native
`DisabledException` records. B delivered after repair. Successful A/B crypto
retains distinct rule source ARNs; disabled-key crypto audits SNS and omits
encryption context. This supports retaining source ARN in the local cache
identity, not a claim about AWS's hidden cache implementation or all producers.
Disabled-key SNS and SQS targets have different native classifications: SNS
uses `NO_PERMISSIONS`, while `eventbridge/error_metrics.json` captures
`NO_RESOURCE` for SQS.

Successful EventBridge, CloudWatch alarm, S3 notification and CloudTrail
publications use `aws:sns:topicArn`, `aws:sns:sourceArn` and
`aws:sns:sourceAccount` in the KMS encryption context. The source ARN is the
rule, alarm, bucket or trail, not the topic. Each capture reached a real raw
SQS subscriber with only the originating service's KMS grant, not an additional
SNS grant. Authorization and audit identity are distinct:
EventBridge/CloudWatch/S3 crypto records identify `sns.amazonaws.com`;
CloudTrail validation and asynchronous log notifications retain
`cloudtrail.amazonaws.com`. Local projection changes only audit metadata,
not the principal evaluated by KMS.

`encryption_s3_source.json` captures both the real validation test event and a
real object-created notification. A separate topic CMK, a 330-second cutover
wait and the sole subsequent upload isolate the second crypto pair; object
bytes, key, ETag and size match the consumer. The service grant follows
[S3's documented KMS permission requirement](https://docs.aws.amazon.com/AmazonS3/latest/userguide/grant-destinations-permissions-to-s3.html).

`encryption_cloudtrail_notification.json` captures five asynchronous notifications
and fetches their actual gzip S3 logs. A fresh CMK installed after StartLogging
and the final trail validation distinguishes asynchronous crypto from validation.
An owned bucket-tagging response request ID matches a record in a notified log,
as required by the [CloudTrail notification contract](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html).
KMS records identify the dedicated key/topic/trail, not an SNS message or S3
object; they are not claimed to correspond individually to that later log.
These are positive one-account/region captures, not a negative-permission matrix
or a guarantee about other producers, accounts or regions.

Local publication reuse remains five minutes. Retained delivery/archive reuse
uses ten service minutes, a local choice within the observed warm/cold windows,
not a measured fleet-wide AWS cache deadline. Restart drops the cache. Cold live
recovery checks original key material/state and current publisher authority;
unavailable or unauthorized keys retain work and retry after twenty service
seconds rather than falling back to plaintext or losing the FIFO predecessor.
Accepted work is not re-admitted through SNS Publish after KMS repair. That retry
interval and terminal key-error/metric behavior remain conformance gaps.
Identifier/key-state propagation, cross-account/partition identifiers and HTTPS-only
native admission also remain conformance boundaries; local HTTP endpoints remain usable.

`TestSNSNativeEncryption`, `TestSNSNativeEncryptionAuthorization`,
`TestSNSNativeEncryptionPublisherCache`, `TestSNSNativeEncryptedSourceConditions` and
`TestSNSNativeEncryptedServiceSources` replay native controls, permissions,
cache sharing, producer context/audit and actual SQS delivery on both stores. The SQLite
`TestSQLiteSNSEncryptedWorkRecovery` scenario retains encrypted old/new-key and
plaintext work, revokes the publisher, disables the old key and upgrades a
schema-145 snapshot. It verifies the original topic-only context is recovered,
then restores authority and checks bodies, FIFO ordering and deduplication identity.
The integrated fixture replay passes on both stores, including permission/context
denials and EventBridge producer authority. Focused race checks cover the KMS
recovery boundary, SNS authorization, pending FIFO recovery and topic controls.

Native cleanup independently confirmed all seven topics, four queues, the rule,
alias and ephemeral IAM user absent. Customer key
`64f34e8b-b857-49fb-ad92-f11b5af3c809` remains **PendingDeletion**, scheduled with the
minimum seven-day window; no AWS-managed key was created. Sources were stackd
`411d578e3af8251e91ec7cb3a1fc84e25cab2656` and aws-sdk-go-v2
`113bc91bf12edc3af1d3aba1c70be28494d54c2a`.

#### Executable verification

The actual CLI and SQLite-backed executable delivered raw and wrapped FIFO
notifications with matching message/sequence identities. Warm publication still
delivered after disabling the customer key. After process restart, the same
topic rejected cold publication with `KMSDisabled`; enabling the key restored
delivery without changing retained deduplication identities. Resetting encryption
removed its attribute and delivered the new plaintext publication normally.
Both queues and the topic were removed after verification.

The source/session executable scenario replayed all eight EventBridge
receipt/DLQ outcomes and three distinct same-role credentials, including new
same-name and different-name sessions after CMK disable. An accepted source-rule
event then received an actual retryable HTTP 500. Restart discarded the KMS
cache; endpoint repair and a twenty-second service-time advance delivered the
original event and SNS message ID. The cold Decrypt retained all three source
context fields and audited SNS. The first attempted hold used a permanent SQS
permission denial and correctly settled work; that scenario was replaced, not
the production failure classification.

The S3/CloudTrail executable chain delivered a trail log containing an owned
CreateTopic, its CloudTrail SNS notification, and the log object's S3 notification
through separately encrypted topics to real SQS and HTTP consumers. After HTTP
500s and SQLite process restart, a twenty-second advance delivered both original
bodies and SNS message IDs. Cold Decrypt retained all three context fields and
the distinct SNS/CloudTrail audit actors. A separate pre-correction run recovered
old topic-only S3 ciphertext without reinterpreting its original key context.

The cache-identity CLI scenario delivered through alias A, retargeted to disabled
B, preserved warm publication, rejected cold and expired publication, and
delivered after repair using B. SQLite restart preserved the literal alias/topic
configuration and resolved B on the next cold publication. A separate corrected
executable replay exercised all seven native EventBridge rule-cache outcomes,
including both disabled-key DLQs, five collector receipts and SNS-identified
failure records without encryption context.

The stopped-worker SDK scenario above separately proves that unexecuted SNS
delivery work survives reopening, remains blocked behind an unavailable old
key, and resumes in order after that key becomes available.

### Filtering

The SNS-owned compiler implements attribute/body scopes, `$or`, nested body
objects and same-array-element matching, exact/null/boolean alternatives,
`exists`, numeric comparisons, prefix/suffix, `anything-but`, case-insensitive
matching, CIDR and wildcard predicates. Admission enforces the native policy-size,
five-leaf-key, 150-combination and 100-wildcard-point limits. Repeated leaf
occurrences across `$or` branches count toward the key limit. Attribute string
matching retains SNS's double-escaping distinction from decoded body strings.

Numeric filtering uses exact base-ten comparisons without rounding publication
values to the policy operand's five-decimal precision. Publication accepts some
spellings that cannot be parsed for filtering, including the captured `.5` case.
`String.Array` JSON syntax is not a publication-admission check: AWS accepted
`not-json`. With an active attribute filter, malformed referenced **or
unreferenced** attributes reject delivery and increment
`NumberOfNotificationsFilteredOut-InvalidAttributes`. A valid referenced
attribute does not bypass another malformed attribute. Unfiltered delivery does
not parse filter values; body scope evaluates the selected body.

### Destination payloads

Wrapped standard-topic SQS delivery contains the signed SNS notification. Raw SQS delivery
uses the original selected body and native SQS message attributes. Terminal
primary authorization failure can move the retained publication to its configured
SQS dead-letter queue; destination acceptance is verified by actual receives.
Native redrive fixtures preserve wrapped Subject/body/attributes and raw
binary/Number attributes, then repair the primary queue policy without replacing
the subscription. Raw receive checksums match AWS's normalized values. An
eleven-attribute raw publication was accepted but produced no DLQ receipt in the
captured window; a later three-attribute positive control reached the primary.
Retained native metrics distinguish primary failure from failed redrive:
the raw capture records Failed=2 across three primary outcomes and
FailedToRedriveToDlq=1 across two redrive outcomes. Replay checks these weighted
counts after topic deletion, without claiming the native poll latency is modeled.

Lambda receives the native `Records`/`Sns` event through asynchronous acceptance
and the real official Python 3.12 runtime. The capture uses `SigningCertUrl`
and `UnsubscribeUrl`, while ordinary SQS notifications use `SigningCertURL`
and `UnsubscribeURL`. Absent Lambda Subject is present as JSON null and is omitted
from canonical signing. Empty attributes remain an object; Number and String.Array
attributes become Lambda String attributes without changing their values.
The fixture's unchanged boto3 handler sends the actual event to an owned SQS
collector. Local replay injects only its queue URL and the standard
`AWS_ENDPOINT_URL`; no in-process handler or real-AWS fallback is used.

CloudWatch retains its structured `default`/`sms`/`email` publication and Subject
with the accepted action. Native fixtures cover long ASCII/Unicode alarm names,
metric-query and composite triggers, SMS projection and actual child transitions.
Mutation/deletion before a SQLite restart does not rebuild an accepted action
from the new alarm state. [CloudWatch](cloudwatch.md) owns alarm evaluation and
history; SNS owns subsequent publication and delivery.

## Service metrics

SNS retains weighted `(metric name, value)` samples per scoped topic and completed
UTC minute. Its scheduler publishes those samples through CloudWatch's existing
typed internal interface and consumes the pending group in the same shared
transaction. This is not a customer `PutMetricData` call and does not require an
additional permission from the publisher. Pending samples survive topic deletion
and restart. CloudWatch owns sample validation, aggregation and statistics.

Native captures distinguish these observations:

- `NumberOfMessagesPublished` counts accepted messages, but a successful batch
  contributes one sample whose value is the accepted entry count.
- `PublishSize` contributes one sample per successful API call. A batch's sample
  is the whole original batch size, including bytes of per-entry failures and
  excluding Subject. A captured partial batch published one message and size 64;
  a 256-KiB body with a 100-character Subject was accepted.
- Successful deliveries contribute Delivered=1 and Failed=0. Filter rejection
  also contributes a completed Failed=0 sample, not a delivery failure.
- Ordinary attribute/body mismatches contribute the general FilteredOut counter
  and their scope counter. Missing attributes, malformed attributes and invalid
  bodies contribute only their specific reason counter, not general FilteredOut.
- Managed-endpoint terminal failure contributes Failed=1 with one sample, not a
  prior zero plus a terminal one. Successful redrive contributes RedrivenToDlq=1
  and FailedToRedriveToDlq=0.
- HTTP/S counts every failed attempt, including confirmation attempts and retries.
  Successful confirmations contribute Delivered=1 and Failed=0. Native HTTP 400
  also completed with Delivered=1, Failed=0 and no DLQ; exhausted HTTP 503
  notifications contributed two failures and one actual SQS dead letter.
  This refines the general [AWS metric description](https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html)
  with the independently captured endpoint responses and metric outcomes.
- The native idle minute had no samples. No six-hour activity ledger or periodic
  zero samples are invented from the documentation's active-topic description.
  Native absence observations retain their bounded ingestion window.
- Native SNS metrics expose percentiles. A min/max/sum-only statistic set would
  discard required distributions; retained weighted values preserve them. Replay
  compares captured PublishSize Average/p50/p90 and Published Sum/p90 outputs,
  in addition to sum/count/min/max and namespace/account/region/dimension isolation.

## API observations

SNS supplies source-owned projections to the shared API-event fabric. The native
initial capture contains fourteen management records and one `PublishBatch` data record,
correlated by exact request IDs. Topic resources retain their account ID.
Message, Subject and the whole MessageAttributes value are redacted as native
security markers; generic map redaction remains unchanged for other services.

SDK replay checks management-only LookupEvents, an exact-topic data selector,
actual S3 gzip trail logs and a configured EventBridge-to-SQS consumer of those
projected documents. That initial SNS probe did not independently capture native
EventBridge delivery or a single-`Publish` record. The later cross-account capture
below supplies native single-publication evidence. Other management projections
use generated public shapes, not claimed extra captures.
CloudTrail Lake remains explicitly excluded.

`cross_account_audit.json` retains 41 request-correlated records: nine management
records in each account, eleven data records in the topic-owner account and
twelve in the queue-owner account. Data records came from two actual S3 gzip
objects; 36 publication-correlated SQS notifications and an unsubscribe control
message establish real effects. Successful cross-account Subscribe, Publish and
PublishBatch have caller and topic-owner records with a shared request/shared
event ID, distinct event IDs and the correct recipient account.

Owner copies use compact `AWSAccount` identity without the foreign actor's ARN,
session context or access key. Authorization-denied cross-account publications
also reach both accounts: native `AccessDenied`, null request/response parameters,
and `HIDDEN_DUE_TO_SECURITY_REASONS` as the caller copy's resource account.
The owner copy retains the actual topic account. Subscription Get/Set/Unsubscribe
instead appear in caller history without shared IDs, projecting the full
subscription ARN as `AWS::SNS::PlatformEndpoint` with the caller's account ID.
An attribute denial remains `AuthorizationErrorException` with request parameters.

The capture's 854.875-second collection window includes initial trail-propagation
omissions; replay does not manufacture missing records or treat them as permanent
absence guarantees. Later reciprocal publications, batches and own-account
positive controls establish both collectors. All owned trails, buckets, queues,
topics and subscriptions were independently absent after cleanup.

Both repositories replay these projections through actual CloudTrail history and
selected S3 delivery. An executable SQLite restart matched all 41 captured records,
downloaded two actual gzip objects and delivered the same data documents through
each account's configured EventBridge/SQS consumer: fourteen records per account.
No local test depends on a reference checkout or live AWS credentials.

`confirmation_audit.json` adds 35 request-correlated records, including nineteen
signed confirmation/cancellation requests. Signed `ConfirmSubscription` appears
only in caller history during the captured window; its resource uses the requested
topic ARN but the caller's account ID. Tokens are exactly `REDACTED`, rather than
the publication hidden-value marker. Successful responses retain `subscriptionArn`.
Semantic errors retain parameters and their modeled exception; IAM/session-policy
denials instead use `AccessDenied` with null request/response parameters.
The requested topic controls IAM independently of the token's original subscription.

Unauthenticated confirmation and cancellation are not logged, as specified by the
[SNS CloudTrail contract](https://docs.aws.amazon.com/sns/latest/dg/logging-using-cloudtrail.html).
The native capture retained anonymous success/denial and forty complete history
polls, twenty per account, over 866.972 seconds. A paired Subscribe positive
control proves both histories exposed owner copies; it does not turn the bounded
caller-only observations into a universal delivery-latency guarantee.

`cross_account_control_audit.json` retains 97 records and four actual gzip objects.
All nine captured topic controls—Get/SetTopicAttributes, ListSubscriptionsByTopic,
ListTagsForResource, TagResource, UntagResource, AddPermission, RemovePermission
and DeleteTopic—produce paired cross-account success and IAM-denial records.
Successful controls retain request parameters and null responses; denied controls
use the same caller-hidden/owner-visible resource account distinction as denied
publications. Tag operations require their explicit grants.

Cross-account missing FIFO groups, invalid structured JSON and duplicate batch IDs
also produce paired records, but retain redacted request parameters and the actual
topic-owner account in both resource copies. These are semantic errors, not IAM
denials. After topic deletion, an allowed owner publication returns NotFound;
a foreign publisher instead receives AuthorizationError and paired AccessDenied
audit records because the resource grant no longer exists.
The 1054.051-second capture preserves initial propagation omissions; every repeated
publication case has concrete expected-account records. Both probes independently
verified their owned resources absent without leaving pending subscriptions.

All three cross-account fixtures replay through memory and SQLite. A separate
executable reproduction exposed pre-fix anonymous audit records and foreign
missing-topic disclosure. After correction, two configured trails and EventBridge
rules delivered four real gzip objects and 22 SQS event envelopes across SQLite
restarts. The EventBridge detail documents exactly matched their trail records,
including caller-only confirmation, omitted anonymous requests, paired IAM
denials and paired semantic failures.

The shared wire encoder also honors generated Query-compatible error aliases.
A native SQS JSON response names `com.amazonaws.sqs#QueueDoesNotExist`, while
`X-Amzn-Query-Error` is `AWS.SimpleQueueService.NonExistentQueue;Sender` when the
client requests Query mode. Go SDK v2 returns a modeled `*types.QueueDoesNotExist`
with that legacy error code. The fixture keeps the actual SDK/header exchange;
replay does not normalize away the distinction.

`testdata/aws/sns/message_groups.json` captures native group admission, mixed-batch
results and correlated wrapped/raw/SQS-subscription DLQ receipts. The owned topic
and all four queues returned not-found after cleanup. Receipt sampling establishes
those observed paths, not delivery order or a native retry deadline.
The executable SQLite workflow accepted a grouped publication before shutdown,
then delivered its original body/group to wrapped, raw and dead-letter SQS queues
after restart. No destination delivery had occurred before that restart.

## FIFO archive and replay

FIFO topics retain accepted publications even without subscribers or matching
filters. Archive entries pin the same immutable, optionally encrypted message
used by deliveries; neither subscription deletion nor the last delivery collects
an archived body. Memory and SQLite share this repository contract. Schema 144
retains archive deadlines, subscription cursors/status/pause and replay delivery
markers. Cursor advancement and admitted delivery intents commit together;
source decryption and target delivery remain outside transactions.

Native controls and consumer receipts are retained in `archive_replay.json`,
`archive_create.json`, `archive_transitions.json` and `archive_encryption.json`:

- `MessageRetentionPeriod` accepts integer numbers or numeric strings from 1
  through 365; the accepted policy document is preserved. BeginningArchiveTime
  starts at enablement and is bounded by the current retention window.
- An enabled archive prevents topic deletion. `{}` removes archive attributes
  and entries; re-enabling starts a new archive. Retention changes cannot revive
  entries already expired, including when expiration work has not yet run.
- Repeated CreateTopic rejects an explicit enabled ArchivePolicy, even the
  identical document and regardless of whether archiving began at creation or
  through SetTopicAttributes. Omission remains idempotent; `{}` is accepted when
  the existing archive is already disabled.
- StartingPoint is inclusive and EndingPoint exclusive. Encountering a historical
  ending boundary completes the scan but leaves live delivery paused. Reaching
  EOF before that boundary completes and resumes live delivery.
- A currently active subscription keeps live fanout while replay is Pending;
  unbounded catchup can replay that same publication. A previously paused
  subscription stays paused until catchup reaches EOF. Current subscription
  filters apply to source selection.
- Wrapped replay preserves the original SNS identity, timestamp, sequence,
  subject and attributes and adds `"Replayed":"true"` as a string. Raw output
  adds no envelope. Original group/deduplication identifiers still pass through
  ordinary SQS delivery and its deduplication rules.
- Empty ReplayPolicy cancels the source cursor and removes replay attributes.
  Replacement supersedes source work through subscription versions. Already
  admitted notifications remain ordinary retained delivery work; source
  completion is not proof of endpoint receipt.

Processing counters use the original UTF-8 message and attribute bytes, excluding
Subject. Native replay delivery counters are separate from ordinary Delivered/
Failed counters. Archive processing and byte metrics use unit None; replay
delivery metrics use Count. Hourly archive gauges follow the documented
[archive metrics](https://docs.aws.amazon.com/sns/latest/dg/message-archiving-and-replay-topic-owner.html#message-archiving-and-replay-topic-cloudwatch);
the bounded native capture returned no gauge points, so their local cadence is
documentation-derived, not a measured native delivery schedule.

The earlier `archive_encryption.json` receipts survived a removed SNS grant,
330 seconds of idle time and a later key disable; elapsed time did not establish
a cold decision. `archive_kms_cold.json` extends this with two original keys and
publications, including an explicit SNS Decrypt Deny before first publication:

- Fresh queues received both originals immediately and at eight minutes despite
  the explicit service-principal Deny.
- At twenty minutes, with both original keys disabled and Deny retained, neither
  fresh queue received a message during its approximately 83-second window.
  AWS reported `ReplayStatus=Completed`, not `Failed`.
- Enabling the original keys and removing Deny allowed new replay requests to
  recover the exact originals. Correlated native Decrypt events identify
  `AWSService`, `invokedBy=sns.amazonaws.com`, the original CMK ARNs and exact topic
  encryption contexts. These are actual cold archive decisions, unlike the
  publication-time IAMUser Decrypt events.

`archive_kms_deny.json` isolates the service-policy decision with both original
keys Enabled throughout. After successful live and baseline replay controls, a
fresh treatment replay under only an explicit SNS Decrypt Deny completed without
a receipt during its 91-second watch; a same-age allowed control delivered its
original. Removing only Deny restored the treatment's exact original through a
fresh subscription. Successful cold control/repaired Decrypt records identify
SNS as AWSService. No corresponding failed Decrypt record was returned, so its
audit attribution is not inferred from the empty replay.

Cold archive reads now use normal KMS authorization as the SNS service principal,
enforcing the [documented decrypt grant](https://docs.aws.amazon.com/sns/latest/dg/message-archiving-and-replay-topic-owner.html#message-archiving-and-replay-topic-decrypt-permissions).
Unreadable entries advance the source cursor without admitting delivery; the
scan can complete with no receipts. Entries remain archived for a later fresh
replay after repair. Disabled-key-only recovery, failed-call audit and exact cache
lifetime remain uncalibrated. Automatic repair of earlier Completed subscriptions
is not claimed.

The actual SQLite CLI recovered two encrypted publications after restart with a
restored manual clock, then exercised current filters, raw FIFO delivery,
historical-end pause, unbounded catchup and live resumption. Four publications
produced 184 archived bytes, seven replay deliveries and three ordinary deliveries.
The hourly gauges reported four messages/184 bytes; advancing retention produced
no replay receipts. Fixture-driven SDK scenarios cover both backends, and retained
recovery checks cover source cursors, accepted deliveries, cancellation, source
key changes and topic incarnations.

An additional actual SQLite executable workflow verified warm disabled-key HTTP
retry, later cold key unavailability, and resumed delivery after local key repair.
Across restart, archive scans completed without receipts while the SNS grant was
missing; adding the source-bound Decrypt grant recovered the original body.
CloudTrail LookupEvents exposed both denied and successful SNS AWSService Decrypt
calls. The consumer's five-minute FIFO deduplication also survived restart and
message deletion; a later replay was received after that window expired.

The caller-authority executable workflows retained IAM-user and assumed-role
publishers across SQLite restart. A current KMS Deny prevented another HTTP
attempt both before and after restart. Repairing only Decrypt authority delivered
the original message while SNS Publish remained explicitly denied. The role
workflow also required its retained session policy, principal tag and regional
ViaService condition; CloudTrail exposed the assumed-role issuer, SNS forwarding
identity, denied attempts and successful recovery. These exercise local retained
authorization and recovery, not the uncaptured native terminal retry schedule.

## Data-protection availability

AWS [closed new SNS message-data-protection enrollment](https://docs.aws.amazon.com/sns/latest/dg/sns-message-data-protection-availability-change.html)
on April 30, 2026.
`data_protection.json` records actual us-east-1 and us-west-2 admission and real SQS
receipts in this account: valid nonempty PutDataProtectionPolicy requests were
rejected as unavailable; nonempty inline creation was rejected without creating
the candidate topic. Empty inline policies were accepted, and publications still
arrived unchanged after the rejected policy writes. FIFO policy requests returned
operation-specific InvalidAction, including for absent FIFO topics.

This does not establish legacy Deny, Deidentify or Audit enforcement. Those paths
remain unsupported pending an eligible native account/region; the local empty
inline CreateTopic policy is accepted, not treated as an enforcement request.

## Evidence and verification

The pinned SDK model is recorded in generated catalog headers.
[Behavior references](behavior-references.md) owns source revisions and inventory
rules. AWS primary references include [publication](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html),
[batch publication](https://docs.aws.amazon.com/sns/latest/api/API_PublishBatch.html),
[filtering](https://docs.aws.amazon.com/sns/latest/dg/sns-message-filtering.html),
[metrics](https://docs.aws.amazon.com/sns/latest/dg/sns-monitoring-using-cloudwatch.html),
[dead-letter queues](https://docs.aws.amazon.com/sns/latest/dg/sns-dead-letter-queues.html)
and [EventBridge target permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html).
The audit boundary also uses the official
[CloudTrail example](https://docs.aws.amazon.com/sns/latest/dg/sns-logging-using-cloudtrail.html).

| Retained native fixtures | Exercised behavior |
| --- | --- |
| `testdata/aws/sns/controls.json`, `policy_actions.json`, `policy_context.json`, `deletion.json` | Controls, atomic policy/tag rejection, source-owner distinction, retained subscription incarnations |
| `admission.json`, `numeric_attributes.json` in the same directory | Publication/batch admission, exact numeric values and native SQS consumer checksums |
| `attribute_unicode.json` | Native BMP acceptance, supplementary Unicode rejection and whole-batch attribute rejection |
| `filters.json`, `message_rules.json`, `subject_structure.json` | Filter language, protocol selection, Subject units and captured malformed-value distinctions |
| `metrics.json`, `metric_outcomes.json`, `metric_filter_attributes.json` | Real delivery/filter/DLQ outcomes, weighted metrics, partial versus request rejection and retained percentile queries |
| `lambda.json` | Actual official-runtime SNS events and unchanged customer boto3 collector |
| `eventbridge.json` | Native source-ARN/account permissions, absent legacy owner context, signed notifications and permission-denied EventBridge DLQs |
| `delivery.json` | Wrapped/raw authorization redrive, repaired primary delivery, normalized consumer digests and retained failure/redrive counters |
| `audit.json` | Request-correlated native management/data records and selective trail replay |
| `testdata/aws/cloudwatch/sns_publications.json` | Native alarm publication projections and retained action replay |
| `fifo.json`, `fifo_edges.json`, `fifo_projection.json`, `fifo_redrive.json` | FIFO admission/mode/scope, topic/group/content deduplication, original identity, expiry, filtering, structured projection, actual FIFO/standard raw/wrapped queues and DLQ type admission |
| `encryption.json` | Literal key controls/reset, ordinary/batch/FIFO publication, caller/context authorization, warm/cold disabled-key differences, actual raw/wrapped SQS payloads and EventBridge producer grant |
| `encryption_live_retry.json` | Actual disabled-key HTTPS retries beyond five minutes and a later failed KMS Decrypt; terminal recovery was not observed |
| `encryption_live_authority.json` | Enabled-key cold Decrypt under the original publisher's current explicit Deny; actual HTTP retries and bounded post-repair absence |
| `encryption_role_cache.json` | Warm/cold publications by same-role/same-name STS sessions with different restrictions, actual SQS receipts and KMS audit |
| `encryption_equivalent_sessions.json` | Same-role/same-authority warm reuse across fresh credentials and session names, disabled-key receipts and fresh-topic KMS controls |
| `encryption_alias_retarget.json` | Warm alias retarget, cold/expired rejection, repaired B delivery, exact failed-call KMS attribution and bounded enable propagation |
| `encryption_event_source_cache.json` | Distinct-rule warm/cold authority, real disabled-key DLQs, repaired receipts and source-specific successful/failed KMS audit |
| `encryption_service_sources.json` | Eight source-condition cases with actual EventBridge receipts/DLQs and successful source-bound KMS records |
| `encryption_cloudwatch_source.json`, `encryption_cloudtrail_source.json` | Actual alarm/validation publication, source encryption context and distinct KMS audit actors |
| `encryption_s3_source.json` | Validation and actual object notifications on separate CMKs, source context, SNS audit actor and original S3 authority |
| `encryption_cloudtrail_notification.json` | Asynchronous encrypted notifications, fetched S3 logs, request-correlated owned write and retained CloudTrail crypto actor |
| `http_delivery.json` | Actual HTTPS confirmation/notification/cancellation requests, metadata, raw output, protected deletion, native 400/503 outcomes, real SQS dead letters and independently verified cleanup |
| `cross_account_confirmation.json` | Caller-owned registration, real standard/FIFO confirmation, protected deletion, duplicate rejoin, Deleted projection, token recovery and independent cleanup |
| `cross_account_audit.json` | Paired Subscribe/publication outcomes, denied data redaction, compact owner identity, subscription resource projection and actual two-account gzip delivery |
| `confirmation_audit.json` | Signed caller-only confirmation/cancellation, requested-topic session limits, exact token redaction and documented anonymous omission |
| `cross_account_control_audit.json` | Nine paired topic controls, explicit tagging grants, paired semantic publication failures and foreign missing-topic authorization |
| `deleted_rejoin.json` | Deleted SQS re-subscription without resurrection, bounded absent delivery, real cancellation-token recovery and independent cleanup |
| `cross_account_lambda.json` | Caller-owned confirmation, actual Lambda control/notification envelopes, invoke denial/repair, Deleted rejoin, owner removal and retained failed cleanup |
| `cross_account_firehose.json` | Endpoint ownership, session PassRole denial, topic-scoped trust, write denial/repair, actual S3 objects and independent cleanup |
| `confirmation_lifetime.json`, `confirmation_lifetime_supplement.json`, `confirmation_lifetime_scope.json` | Original-token identity, requested-resource IAM/session limits, removed-subscription errors, idempotent protection, topic-incarnation isolation and independent cleanup |
| `managed_feedback.json`, `external_feedback.json` | Role admission/current authority, actual endpoint receipt IDs, HTTP status/attempt/control distinctions, Firehose S3 effects and independent cleanup |
| `feedback_sampling.json` | Positive logging-authority control followed by 32 actual role-only publications, all received/logged with the sample-rate attribute still absent |
| `archive_replay.json`, `archive_create.json`, `archive_transitions.json` | Archive/replay admission, original consumer identities, current filters, exact bounds, pause/EOF, active live/replay duplication, endpoint denial/repair and owned-resource cleanup |
| `archive_encryption.json` | Original encrypted publication replay through bounded key-authority changes; no confirmed cold native cache miss |
| `archive_kms_cold.json` | Explicit-deny warm receipts, empty Completed scans, repaired original receipts and correlated cold SNS AWSService Decrypt |
| `archive_kms_deny.json` | Isolated enabled-key SNS service Deny, same-age allowed control, empty Completed scan and fresh repaired original replay |
| `data_protection.json` | Closed-enrollment admission in two regions and unchanged real receipts; no positive enforcement claim |

The encryption captures' customer keys remain PendingDeletion. The archive probe
key `e6e0b6b1-a23d-4213-bd7a-c3a22b7784bb` is scheduled for deletion on
2026-09-29 at 22:30:27.032 UTC; all archive-probe topics, subscriptions and queues
were independently checked absent.
The September 23 retained-key probes independently verified their topics,
subscriptions, queues, receiver function/URL, role and log group absent. Their
three customer keys are PendingDeletion with seven-day deadlines on September
30; exact IDs, deadlines and absence checks are retained in the two fixtures.
The subsequent caller/session and isolated-archive captures also independently
verified their topics, subscriptions, queues, identities, receiver and log group
absent. Their four CMKs are PendingDeletion for September 30: caller
`f81554dc-1b49-4ffd-95a6-fb5dd145552f`, session
`900801d4-69ee-47c6-a1fb-f9ca5e1572d0`, and archive
`0d5cb5bd-4c6e-47a9-8f06-d9e218b7c801` /
`3d67b121-1c43-446f-acff-e5f2789b3675`. Exact native deadlines and cleanup checks
remain in the three fixtures.
The equivalent-session, EventBridge-source, CloudWatch-source and CloudTrail-source
probes independently verified their owned non-key resources absent. Their CMKs
remain PendingDeletion with September 30 UTC deadlines:
`36cf05ad-1163-4ddb-b236-aa33bf719393` at 03:00:37.524,
`f0fca34b-2eb2-425f-b47c-52bdb9b7cc27` at 02:58:25.610,
`38fcb72d-b096-477d-ba3f-5834b944b528` at 03:24:43.476 and
`b3a337c8-32d8-4126-a6da-7ae31aba9813` at 03:25:29.307.
Exact cleanup calls, source revisions and executed probe sources remain in the fixtures.
The S3 and asynchronous CloudTrail probes independently verified all owned
trails, buckets/contents, topics, subscriptions and queues absent, including the
first CloudTrail attempt whose CLI log-download command failed. Six CMKs remain
PendingDeletion with September 30 UTC deadlines:
`5711e391-d858-4e0b-937e-21f5ce15aab5` at 03:57:32.617,
`f79b8369-c338-4e74-8f63-88868f362e3d` at 03:57:34.010,
`4b031b81-8670-40e2-87a0-b66973687886` at 03:55:55.222,
`3c97825d-a4cb-4078-baf9-9bfed74bc578` at 03:55:56.612,
`4d73b4a2-06d8-49a8-82c0-51787b308dd5` at 04:07:04.937 and
`d756271e-288f-493f-8a7d-adb2c704cc1a` at 04:07:06.292.
The alias-retarget and EventBridge rule-cache captures independently verified all
owned non-key resources absent. Three CMKs remain PendingDeletion with September
30 UTC deadlines: `1b3ba30e-c1bf-43c0-b52e-6af47df87f1c` at 04:36:13.657,
`1c3d87b8-b548-4093-b655-73e44be84e78` at 04:36:15.050 and
`ffe051d3-732a-4197-a3c9-6da0d2eafd50` at 04:35:44.027. Their fixtures retain
executed sources, the stackd `12be160` revision and exact cleanup readbacks.
Five older HTTP pending registrations and the Lambda pending reference above await
native expiry; their topics and receivers are gone.
All new feedback-probe resources were removed and absence checked. Twenty older
confirmed subscription remnants were also explicitly removed after verifying
their captured source topics were absent; no live topic was touched. Negative
delivery and propagation windows are bounded observations, not universal AWS deadlines.
Ordinary replay needs neither a reference checkout nor AWS credentials. The
Docker-gated SNS Lambda replay requires the configured official runtime image.
Focused SDK replays pass on memory and SQLite. An actual CLI executable workflow
also delivered direct SNS, EventBridge and CloudWatch publications to SQS, verified
all three RSA/SHA-256 signatures and rejected tampering. Restart without a new
clock restored the saved instant; pending metrics remained absent until a
one-minute advance, then exposed Published=3, Delivered=3, Failed=0 and a retained
PublishSize percentile. Pre-restart notifications verified with the restored
certificate.

A second executable restart migrated the database from schema 42 to 43 with an
actual queued message. Body and normalized Number attributes survived; the
receive checksum matched the native attribute algorithm rather than the original
send checksum. The retained SNS certificate still verified all three earlier
notifications, and the same CloudWatch counts and percentile remained queryable.

## X-Ray propagation

Fresh topics omit `TracingConfig`; explicitly setting `PassThrough` retains that
value. Standard and FIFO publications preserve valid transport
`X-Amzn-Trace-Id` context through raw/wrapped SQS delivery and each batch entry.
The header is normalized to Root, Parent and Sampled; captured malformed headers
are omitted without rejecting the message. Whitespace/extensions and duplicate
Sampled fields follow the native capture's normalization. A user
`MessageAttributes.AWSTraceHeader` remains ordinary message data and cannot
override SQS's separate `AWSTraceHeader` system attribute.

Accepted work reuses the existing publisher metadata, including when the topic
is unencrypted. The delivery adapter enters SQS's ordinary send command with the
normalized system attribute. SQLite schema 150 retains the optional topic
setting; publisher context uses the existing typed columns. SDK fixture replay
covers default/PassThrough controls, malformed context, batch delivery and pending
standard/FIFO work after reopen. The actual executable preserved both raw and
wrapped trace headers and separate user attributes across a SQLite restart.

`testdata/aws/sns/tracing.json` retains the native publications and receipts,
including a separate default/PassThrough supplement. Its correction records that
the original attempted `Passive` transition failed and left Active enabled;
those rows are not falsely presented as PassThrough evidence. Native Active with
Sampled=1 rewrites delivery parents; Sampled=0 and PassThrough preserve them.
Parent rewriting alone is not Active tracing. Owned allow/deny controls, fresh
topics, classic-XRay destination checks, extended polling and a second account
retrieved publisher/consumer spans but no SNS-origin spans. Their schema,
authorization and emission therefore remain blocked. `Active` returns an explicit
unsupported error without changing the existing topic setting; `Passive` remains
invalid. All owned topics, queues, subscriptions and policies were independently
absent after cleanup. Submitted traces expire under AWS retention.

The [SNS tracing contract](https://docs.aws.amazon.com/sns/latest/dg/sns-active-tracing.html)
and [X-Ray SNS integration](https://docs.aws.amazon.com/xray/latest/devguide/xray-services-sns.html)
describe the intended service behavior. [X-Ray storage and audit](verification-kernel.md#x-ray-storage-and-audit)
owns the implemented dependency and its limits; SNS is not advertised as actively
traced, and Lambda tracing is not implied by this SQS propagation.

## Remaining boundaries

Explicit source markers retain these gaps rather than claiming unsupported
behavior: terminal live key-error handling, disabled-key-only archive recovery,
failed archive-call audit and cache/propagation boundaries; email/email-json,
SMS and platform/mobile protocols; data protection; sampled SNS-origin X-Ray spans;
and the remaining generated commands. SMTP remains an allowed deferral, not a
reason to claim those protocols are complete.

Managed retry jitter and initial-attempt counting, subscription-deletion timing
and uncaptured producer failure projections still need implementation or
calibration. PostgreSQL SNS persistence and consistent snapshot/fork semantics
remain open. This guide records exercised paths and explicit limits;
neither operation registration nor isolated passing fixtures establishes complete
AWS parity.
