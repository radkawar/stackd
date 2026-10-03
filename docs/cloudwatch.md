# CloudWatch

CloudWatch is a partial service. The runtime implements custom metric publication,
statistics/math/discovery queries and listing, the publication boundary used by
[Logs metric filters](logs.md), account-global dashboards, and metric/composite alarms.
Generated operation coverage is not full-service implementation or a claim of
universal statistical or alarm-evaluation parity.

## Ownership and protocols

`cmd/awsgen` consumes the pinned AWS SDK Smithy model. The generated catalog in
`internal/awscatalog/generated_cloudwatch.go` and types/codecs in
`internal/awsapi/cloudwatch` own operation shapes, validation and wire encoding;
`internal/services/cloudwatch/service.go` owns registration and execution. The
catalog advertises RPCv2 CBOR, AWS JSON 1.0 and AWS Query, with signing name
`monitoring`, API version `2010-08-01` and Query-compatible errors. The current
Go SDK defaults to RPCv2 CBOR; Query is an explicit SDK protocol alternative, not
the assumed default. Advertised protocols use the same typed service commands.

`internal/gateway/protocol.go` selects an advertised protocol and validates its
operation path/headers. Signature verification consumes the original request
bytes before gzip decoding. Both the original body and decompressed input are
bounded by the gateway body limit; unsupported content encodings and malformed
gzip fail rather than bypassing admission. Shared CBOR/JSON/Query codecs live in
`internal/awsapi`; modeled error handling lives in `internal/awswire`.

Native `protocol_errors.json` records an important difference: RPCv2/JSON errors
use `com.amazon.coral.service#InvalidParameterCombinationException`, whereas the
generated model names `com.amazonaws.cloudwatch#InvalidParameterCombinationException`.
The runtime retains the generated modeled namespace; there is no namespace
override scheme. The real SDK checks in
`integration/cloudwatch_metrics_test.go` compare HTTP status, modeled exception
class and code, not raw namespace equality. Native RPCv2 with
`X-Amzn-Query-Mode: true` returns the legacy `InvalidParameterCombination` code
through `X-Amzn-Query-Error`; the explicit Query SDK capture resolves the same
modeled class with code `InvalidParameterCombinationException`. The directly
signed native JSON request omitted Query mode and did not receive that header.
This narrow invalid-publication capture is not an exhaustive error contract.

## State and publication

`internal/services/cloudwatch/repository.go` owns the typed `Reader`,
`Transaction`, metric identity and observation contracts. `storage/cloudwatch`
exposes that contract; `internal/services/cloudwatch/memory.go` and
`storage/sqlite/cloudwatch` implement it in the shared memory/SQLite transaction
domain. Identity is partition/account/region, namespace, metric name and an exact
canonical dimension set. Dimension order does not change identity; unit and
storage resolution belong to observations, not identity. Reads visit points
inside the transaction rather than requiring an unbounded repository result
slice.

Public metric commands authorize `cloudwatch:<operation>` against `*`;
`PutMetricData` supplies the `cloudwatch:namespace` condition. Admission validates
all data before appending points. Successful commands and their API journal
outcomes commit together; failed commands roll back state and record their
failure outcome separately. `Service.Publish` joins a source transaction without
inventing a customer `PutMetricData` call or requiring that customer's identity
to have `cloudwatch:PutMetricData`. Thus Logs ingestion, extracted metric points
and journal outcomes can commit or roll back together. [SNS](sns.md#service-metrics),
[Lambda](lambda.md#asynchronous-outcomes-and-metrics), SQS and
[EventBridge](eventbridge.md#cloudwatch-metrics) publish their own lifecycle-derived
samples; [ECS](ecs.md#service-metrics) publishes actual runtime utilization and
task counts through this same boundary. CloudWatch does not infer service metrics
from generic API traffic. Retained service observations keep their original
timestamps after delayed publication or a large manual-time advance. Public
timestamp-age admission is not reapplied to this already-accepted source work.

`publication.go` admits scalar values, weighted `Values`/`Counts`, and supplied
statistic sets. Important current semantics, backed by the retained native
publication/statistics observations, are:

- Omitted counts mean one. Fractional and zero counts are retained; counts must
  be finite and nonnegative. A zero-weight value still contributes an extremum.
- A statistic set requires positive finite `SampleCount`, finite supported
  numbers and `Maximum >= Minimum`. An inconsistent sum is retained, not
  repaired; `Average` is `Sum / SampleCount`. `StatisticValues` takes precedence
  over simultaneously supplied `Values`; scalar `Value` conflicts with either.
- Units are kept separately and never converted. Omitted units become `None`.
  Storage resolution is 1 or 60 seconds; admitted timestamps are truncated to
  that resolution. Standard and high-resolution observations can share identity.
- The public publication window is two weeks in the past through two hours in
  the future. Numeric values are finite and within ±2^360; a public request has at most
  1,000 data entries and a values array at most 150 entries. `AWS/` publication
  is rejected. Entity-associated publication explicitly remains unsupported.

There is no metric/sample deletion API. Accepted native samples remain under
AWS retention after the finite publishers stop.

## Queries, statistics and labels

`query_statistics.go` aggregates the five basic statistics and implements
percentiles, TM/TC/TS/WM, PR and IQM syntax. `query_distribution.go` owns histogram
indexing and retained-bin boundaries. Basic aggregates preserve supplied
weights and extrema. Distribution eligibility is distinct: general statistic
sets cannot reconstruct arbitrary distributions. Negative minima suppress
interior percentiles and percentage trims, but fixed ranges can use nonnegative
samples from a mixed-negative publication while retaining the full basic count.
The captured all-negative distribution omits every requested fixed-range result.
Observed p0/p100 behavior is broader than interior percentiles.
Eligible degenerate and observed single-sample sets can contribute
distributions. Subunit and all-zero count cases have explicit omission and
nonfinite-result behavior; accepting a publication does not imply every
statistic is available.

**[INFERENCE]** The extended-statistic implementation uses an inferred
base-1.1 histogram with extrema clipping, geometric percentile interpolation and
separate trimmed/winsorized calculations. Native returned values—not candidate
arithmetic—are the oracle. The
inferred histogram is not universal parity. Retained zero-count positive-bin
fixed trims now replay native NaN, omission and numeric results across scaled,
shifted and interior-empty-bin layouts, including positive-weight zero values.
Empty positive bins participate in endpoint selection without percentile mass;
selection uses the full logarithmic bin, not its extrema-clipped coordinates.
A single populated positive bin next to an empty endpoint uses its whole-bin
midpoint. Its winsor tails count whole outside bins, admitting earlier zero-valued
mass only when a populated positive bin also precedes the selected bin. Explicit
zero and an omitted lower bound remain distinct.

Native exact-edge captures distinguish adjacent floating-point inputs, including
`1.21` from `1.2100000000000002`; inputs are not rounded before indexing.
The captured tiny-value floor is implemented as minimum logarithmic index
`-7000`. Extrema clipping can reverse that bottom bin's endpoints: percentage
trims retain its interpolation direction, fixed ranges select its ordered span,
and interior percentiles remain within raw extrema. Geometric interior weights
avoid forming `low * high`, which underflows for accepted values near `1e-200`.

Statistic literals permit at most ten decimal places, including trailing zeros.
The native precision captures cover percentile, fixed/percentage trim, rank and
short winsor forms; invalid literals fail before metric lookup.
The independent corpus covers subnormal values through the publication limit
`2^360`, not every possible floating-point input or distribution. The inferred
algorithm remains distinct from AWS's documented guarantees.

Query windows use start-time age rounding and period availability rules, with
1/5/10/20/30-second or whole-minute periods, progressively coarser reads for older
data and a 455-day query cutoff. `GetMetricStatistics` enforces the 1,440-point
window limit. These are local query rules, not evidence of native asynchronous
rollup, expiry or visibility cadence.

The query planner shares typed discovery, retained bucket reads and expression
evaluation between `GetMetricData` and alarms:

- `GetMetricData` supports up to 500 queries, dependency resolution, hidden
  inputs, scalar/time-series/array math and scan direction. Direct metric and
  SEARCH sources share a dense retrieval-window budget: empty period slots count,
  unused hidden direct queries do not, and hidden SEARCH sources do. A direct
  query and SEARCH for the same identity remain separate sources. Mixed periods
  advance independently. Continuation stores request-and-scope-bound source
  offsets, not a durable cursor ledger. Undefined IDs, cycles and invalid result
  types fail.
- Math covers arithmetic/comparisons, reductions, `METRICS`, conditional/fill,
  running/difference/rate, time and array operations. FILL uses the allocated
  source window; generated `TIME_SERIES` is not capped like a stored metric.
  Partial derived results retain native status/messages without inventing a
  continuation token. Sparse-array MIN/MAX ignore absent samples; AVG/STDDEV
  account for absent members in their denominator. Anomaly/external-service
  functions and scalar-result period resampling remain explicitly unsupported.
- With no unit filter, `GetMetricStatistics` can return multiple unit rows per
  period. `GetMetricData` reports `MultipleUnits` and chooses one unit per period
  in deterministic unit order; it does not add incompatible units or select one
  global unit that erases earlier periods. Exact native selection beyond the
  retained mixed-unit cases is not established.
- Automatic labels remove shared namespace/dimension context, retain differing
  dimension values and distinguish statistics/periods of the same metric.
  Explicitly labelled and hidden direct queries do not contribute; discovered
  SEARCH sources contribute even when their expression is hidden.
  Dynamic labels expand the implemented metric properties, summary values and
  times with optional timezone; unsupported properties fail explicitly.
- Reads stay in the request's account/region scope. A foreign metric-stat
  `AccountId` returns per-result `Forbidden`, including dependent expressions. Listing with
  linked-account options does not create an observability link or grant access.
  `ListMetrics` supports name/namespace and dimension-subset filters, 500-item
  keyset pages, a two-week publication-activity window and `RecentlyActive=PT3H`.
  Metric reads still require the exact dimension set; listing is not aggregation
  across dimension variants.

## Metric discovery

`query_search.go` parses SEARCH into typed predicates; `query_sources.go` selects
identities through the existing scoped `Reader.Metrics`, then reads their retained
points through the same bucket/statistic owner as direct queries. There is no
second metric database or service-specific discovery cache.

SEARCH supports exact dimension-set schemas, namespace/name/dimension/account
designators, implicit and explicit AND, OR, NOT, grouping and grouped property
values. Quoted exact values are case-sensitive. Partial matching uses meaningful
camel-case, digit and punctuation token boundaries: a composite can span whole
tokens, but cannot split one. Native lowercase composites match despite the
documentation's stricter description. Escaping belongs to the enclosing math
string and the inner SEARCH grammar separately. SEARCH's explicit period wins
over its query period; omission inherits that period, and omitting both fails.
Positive fractional periods truncate before ordinary period validation.
Expanded members retain the query ID and source identity for automatic/dynamic
labels. SEARCH selection uses the two-week activity window and caps expansion
at 500 identities with `MaxMetricsExceeded`.

`query_insights_parse.go` and `query_insights.go` implement SELECT with
AVG/COUNT/MIN/MAX/SUM, namespace or exact SCHEMA selection, equality/inequality
predicates joined by AND, GROUP BY, aggregate ORDER BY and LIMIT. Aggregation
merges retained count/sum/extrema summaries, preserving weighted means rather
than averaging per-metric averages. Missing dimensions participate in inequality
and form `Other` groups; account predicates and `CURRENT_ACCOUNT_ID()` use scoped
ownership. Quoted identifiers and values preserve native case/escaping.

GetMetricData permits one SELECT, including hidden queries, and requires its
period. Native sub-minute periods promote to one minute; start/end round to
minutes and larger periods anchor at the rounded start. An empty rounded window
is Complete. The two-week Insights window has its own clipping/error messages.
Insights does not use the direct/SEARCH retrieval budget and ignores NextToken;
mixed requests still budget their direct sources. Arrays feed the existing math
engine. Captured COUNT rank ties do not establish a native tie-breaker; local
ties are deterministic without copying fixture-specific identity order.

`query_insights_keywords.go` is derived from native admission observations:
917 documented words were exercised, 494 were accepted unquoted, and 422
identifier-shaped words were rejected. The additional rejected `END-EXEC` is
lexically invalid. Quoted controls and measured identifier positions are retained
in `metric_insights_keywords.json`; this is empirical admission evidence, not a
claim that the published reserved-word table describes every native context.

Native discovery fixtures are `metric_search.json`, `metric_search_order.json`,
`metric_search_windows.json`, `metric_insights.json` and
`metric_insights_keywords.json`. The fixture-driven SDK replay uses memory/SQLite
and RPCv2-CBOR/Query, preserving statuses, message codes, values, timestamps,
labels and pagination. It compares query identities rather than incidental
response ordering. Explicit exclusions retain inconclusive publication visibility,
unowned account-wide SEARCH results and two old mutable-input capture errors;
independent native recapture verifies the corrected query identities. Historical
points that never passed their direct visibility control do not prove a retention
cutoff. CLI checks exercised discovery, weighted grouping, sparse FILL, region
isolation and mixed-period pagination across an actual SQLite process restart.
A retained scalar Insights alarm evaluated weighted AVG 6.5 above threshold 5,
then transitioned to OK after the next value became 1.

Resource-tag predicates have measured absent-tag semantics for custom metrics.
Positive AWS resource associations remain unsupported. They require the
[Observability Admin/Resource Explorer opt-in lifecycle](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/EnableResourceTagsOnTelemetry.html),
eligible metric/resource mappings and retained tag versions, not a query-time join
to whichever resource currently has that name. Source services already own typed
resource identities/tags and transactional publication; delayed observations can
outlive source deletion. No account-wide native telemetry setting was changed.
The documented fourteen-day discoverability after disabling enrichment rules out
an immediate boolean switch that erases historical associations.
These unsupported AWS tag queries fail during shared query-plan admission,
including `PutMetricAlarm`, before an alarm or scheduled evaluation is retained.

Primary references: [SEARCH syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/search-expression-syntax.html),
[Insights language](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch-metrics-insights-querylanguage.html),
[limits](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch-metrics-insights-limits.html)
and [eligible tagged-resource metrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/SupportedMetricsForResourceTagsForTelemetry.html).

## Alarms

The generated frontend dispatches `PutMetricAlarm`, `PutCompositeAlarm`,
`DescribeAlarms`, `DescribeAlarmsForMetric`, `DescribeAlarmHistory`, `SetAlarmState`,
`DeleteAlarms`, `EnableAlarmActions`, `DisableAlarmActions`, `TagResource`,
`UntagResource` and `ListTagsForResource` into typed commands. These are real
resource transitions, not stored request documents or successful no-op handlers.

### State and control

`alarms_repository.go` owns alarm configuration, current state, dependency queries,
history and ready action records. The existing CloudWatch repository implements
these contracts in the shared memory domain and service-owned SQLite schema 40.
Configuration, state, native EventBridge events and ready action intents commit
together. Evaluation-only writes cannot replace configuration or tags.

Alarms are scoped by partition/account/region and alarm name. IAM uses alarm ARNs,
resource tags, request tags and tag-key conditions; composite creation and
composite/relationship reads require the documented wildcard permission.
Create-time tags require `TagResource`; tags supplied during configuration
replacement are ignored. Tag writes enforce the native reserved prefix and
50-tag limit atomically.

Configuration writes replace rather than merge the previous configuration.
Identical complete writes preserve configuration/state timestamps, history and
the generated scalar-query ID. A real update preserves current state while
replacing configuration. Same-state `SetAlarmState` is also a no-op, including
its reason; a changed manual state retains the caller's reason and JSON data.
Configuration update time, state update time and state transition time are
distinct. Suppression-only changes update state time, not transition time.

Lists use deterministic name-keyset pagination and native relationship
projections. Deletion checks inbound rule and suppressor dependencies before any
member is removed, including cycles; a batch can remove at most one composite.
History survives deletion and is visible for 30 days of service time. Scoped
history writes and reads lazily prune older rows; idle scopes do not require
another maintenance scheduler. History cursors retain the requested selection,
not a moving derived retention cutoff.

### Evaluation and composite dependencies

Scalar alarms and single-series metric-math alarms share the existing metric
query compiler, statistic implementation and raw observation buckets. Admission
checks query dependencies, result type, M-of-N constraints and period/window
limits. An empty single-series expression is valid; missing data is not a
validation failure. Scalar low-sample percentile evaluation uses the documented
sample-significance threshold.

SEARCH is rejected even when hidden or reduced. Scalar Insights and grouped
queries reduced to a single series use the shared query engine. Direct grouped
Insights queries with ORDER BY produce contributor alarms. Sub-minute Insights
periods and evaluation windows beyond three hours are rejected; Insights alarm
retrieval is bounded to the most recent three hours.

**Contributor ownership.** Each selected attribute tuple uses the same sample,
M-of-N and missing-data evaluator as scalar alarms, without a second metric store.
Only ALARM contributors are retained as active rows. First-selected OK series do
not invent a transition. Displacement or disappearance removes an active row
and emits its OK transition, independently of the parent's missing-data policy.
An entirely empty query applies that policy to the parent; an ALARM parent can
therefore have no active contributors.
With `ignore`, the empty query retains the parent state but still updates its
reason and state-update timestamp; retaining state does not freeze its explanation.

Contributor IDs are opaque and stable for their attribute tuple across rank
changes, namespace/alarm changes and deletion/recreation. Native missing
attributes project as `Other`; a literal `Other` and a missing value collapse
to the same contributor, with the last ranked selected row supplying its value.
History and accepted actions retain their own identity/attribute snapshot and
outlive the alarm. `DescribeAlarmContributors` uses scoped, incarnation-bound
keyset tokens; the local page size of 100 is not a measured AWS page-size promise.
Untyped history is parent-only; contributor history types or an ID select the
contributor family and require an alarm name.
Changing a grouped alarm to scalar SQL or a scalar metric clears active membership
without synthesizing contributor OK history. Returning to grouped starts empty;
the next breach reuses the tuple's ID with a fresh transition timestamp.

Parent reason-only changes append StateUpdate history and update state time,
not transition time. They emit neither a parent state event nor an action.
Contributor state changes emit `CloudWatch Alarm Contributor State Change`
through EventBridge and deliver configured SNS/Lambda actions even while the
parent remains ALARM. Their shared reduced event/Lambda document contains
`alarmContributor`, no `previousState`, and no state `reasonData`. SNS retains
its distinct notification format with contributor ID/attributes and old state.
Grouped Insights rejects Auto Scaling actions and contributor-level
INSUFFICIENT_DATA actions rather than silently accepting unusable targets.

Native evidence includes `metric_discovery_alarms.json`,
`metric_insights_alarm_contributors.json`,
`metric_insights_contributor_lifetime.json`,
`metric_insights_contributor_delivery.json`,
`metric_insights_contributor_actions.json`,
`metric_insights_contributor_samples.json` and
`metric_insights_contributor_conversion.json`. Fixture-driven SDK replay covers
memory/SQLite identity lifetimes, sparse M-of-N/missing-data decisions, the
three-hour admission boundary, configuration conversions, action admission
and real SNS/EventBridge queue deliveries.
Actual CLI checks cover SQLite restart, 205 contributors without pagination
loss, account/region isolation, incarnation-bound tokens and scoped IAM.
A real Python Lambda container received all four a-ALARM/b-ALARM/a-OK/b-OK
transitions with four contributor actions and no parent actions.
Inconclusive native reads do not become fresh-evaluation evidence; interrupted
capture windows do not measure AWS delivery latency.

Primary references: [contributor discovery](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarmContributors.html),
[missing-data behavior](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarms-and-missing-data.html)
and [action levels](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-actions.html).

The service clock drives retained evaluation deadlines: high-resolution alarms
every ten seconds, ordinary alarms every minute, and multi-day windows hourly.
Evaluation implements nonconsecutive M-of-N, real-sample precedence over missing
fill, all four missing-data policies, premature-breach handling and decisive
datapoint reason data. An unchanged scalar evaluated state retains its previous state
timestamp and reason, rather than inventing a transition on every poll.

An omitted `TreatMissingData` remains absent in public configuration. Its local
default is `ignore` when every configured `MetricStat` is in `AWS/DynamoDB`, and
`missing` otherwise; a metric-free expression also defaults to `missing`.
Unused hidden queries participate: adding an ordinary-namespace metric disables
the DynamoDB-only default even when the returned expression does not reference
it. Explicit values override the default, and replacement with omission removes
the old override.

Native scalar, direct-query, identity-expression and arithmetic captures support
these distinctions. The current [missing-data guide](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarms-and-missing-data.html)
allows DynamoDB overrides; the API reference and pinned Smithy documentation
still say they are always ignored. Captured transitions establish that explicit
`breaching` and `notBreaching` work. Retained manual states without a subsequent
`queryDate` remain bounded non-observations, not proof of an internal evaluation.

The local scalar retrieval window uses a ten-second cutoff and a bounded extra
range; expression windows use their captured query time. These choices reproduce
the retained native cases, not a universal AWS ingestion/lookback algorithm.
Generated explanation prose is not byte-identical to AWS. Native `queryDate`,
not the time of a later polling request, anchors evaluation fixtures.

Composite rules support state predicates, names/ARNs, parentheses, `NOT`, `AND`,
`OR`, constants and captured `AT_LEAST` count/percentage forms, including duplicate
occurrences. Admission enforces 100 unique children, 500 expression elements and
150 referring composites. The reducer stages an affected dependency component,
stops a repeated active evaluation path and emits only its final transitions.
It does not retain an evaluation-path ledger or run a cyclic graph forever.
The native oscillating-cycle capture establishes a bounded stable result with
transient triggering-state evidence; it does not establish AWS's internal
algorithm or an indefinitely observed fixed point.

Suppression has explicit `WaitPeriod`, `Alarm` and `ExtensionPeriod` phases.
An expired episode is not restarted by a late suppressor transition.
Phase-only release emits its native state event and performs the pending state
actions. Deadlines, causal origins and state survive SQLite restart.

### Events, actions and causality

Alarm-owned `CloudWatch Alarm Configuration Change` and
`CloudWatch Alarm State Change` events enter the default EventBridge bus through
`AlarmEventPublisher`, independently of CloudTrail configuration. Their native
configuration, previous/current state and suppression fields remain distinct
from CloudTrail API observations and Lambda action payloads.

`AlarmActionSender` currently delivers Lambda actions through the ordinary
asynchronous Lambda command with principal
`lambda.alarms.cloudwatch.amazonaws.com` and the alarm source ARN. Lambda owns
resource-policy authorization and actual container execution. Missing functions
and permission denials are terminal action failures; other rejected acceptance
attempts retain deterministic exponential retries, starting at two seconds and
capped at 256 seconds. After acceptance, execution retries belong to Lambda.
Action history and accepted ready work do not depend on a live alarm row.
External calls run outside storage; a crash after acceptance but before progress
can duplicate delivery.

Each state event retains its immediate cause. Manual state changes, composite
propagation, suppression changes/releases and Lambda acceptance therefore form
a journal chain across restart. Periodic metric evaluation is currently rooted
in alarm configuration, not individual metric publications: observation rows do
not yet carry per-sample causes. Runtime stdout/stderr is also generation-scoped
and has no trustworthy invocation delimiter; it is delivered to Logs without
reusing a preparation context as a warm invocation's parent. Active, signed SDK
calls from customer code use Lambda's separate invocation-attribution boundary.

Native SDK fixtures exercise both stores; Docker fixtures consume real
EventBridge/SQS events and actual Python handler payloads. An additional running
CLI/SQLite workflow verified denied then authorized actions, acceptance retry
while a function was pending, restart during extension, phase-only release and
its retained ancestry. A service-time advance verified deleted history at the
thirty-day boundary, expiry after it and an independent newer same-name alarm in
another region. These checks do not establish complete CloudWatch parity.

## Dashboards

`PutDashboard`, `GetDashboard`, `ListDashboards` and `DeleteDashboards` use the
generated frontend and the existing transactional repository. Dashboards are
partition/account scoped, not region scoped: their ARN is
`arn:PARTITION:cloudwatch::ACCOUNT:dashboard/NAME`. Reads and replacements through
another regional endpoint address the same resource. The typed dashboard record
owns body, tags, whole-second modification time and native-reported size;
metadata-only listing does not load every dashboard body. SQLite schema 153
retains this state and typed tag rows alongside the shared event journal.

The body is an opaque string in Smithy, so `dashboard_body.schema.json` owns
service-level JSON validation, not transport encoding. It covers the captured
metric, text, log, alarm, explorer, chart, custom Lambda, timeline and X-Ray
widget boundaries, coordinates, metric rows and dashboard variables. The
compiled schema is shared across requests. Unknown properties and advisory
enum/root-field failures return validation warnings **and remain in the stored
body**, matching native reads despite AWS's warning wording. Fatal schema
failures return `InvalidParameterInput` and leave the previous body, tags,
modification time and size unchanged. Invalid JSON/root shapes and the
500-widget/25-variable boundaries are fixture-backed.

Native validation is not uniformly stricter than the documentation: empty
log/explorer properties are accepted, while a chart requires `title` even though
the current body reference calls it optional. Metric periods distinguish
1/5/10/30 seconds from invalid 20/90-second controls. A custom widget requires a
Lambda function ARN; a timeline requires an alarm ARN, but neither definition
write executes or requires the referenced resource to exist. Storing a dashboard
does not implement image rendering, a console, PromQL or custom-widget invocation,
nor does it execute referenced Insights queries. The downstream query engine owns those
operations. Unmeasured nested widget/rendering constraints are not claimed as
exhaustively verified.

Create-time tags require both `cloudwatch:PutDashboard` and
`cloudwatch:TagResource`; replacement tags are ignored, including an otherwise
oversized replacement tag list. Dashboard and alarm tagging share one handler
and condition-context owner while retaining resource-owned metadata updates.
Successful dashboard tag mutations advance modification time and initialize
native size-accounting metadata, even when removing an absent key. Removing the
last tag retains that metadata; deleting/recreating the dashboard clears it.
The observed size includes HTML-safe JSON accounting, body overhead and tag
metadata, not merely the UTF-8 length of `GetDashboard.DashboardBody`. This is an
API observation, not a claim about AWS's physical storage format.

Named commands authorize global named ARNs. `ListDashboards` authorizes the
global `dashboard/*` ARN, not a named or prefix-limited ARN, even when the request
has a prefix. Listing is lexical, prefix-sensitive and paginated in 1,000-entry
pages; continuation tokens bind the account/partition and prefix. Deletion
validates and authorizes the entire deletion set before removing anything.
The native 100-name limit counts **distinct** names: 101 duplicate names succeed,
101 distinct names fail atomically, and missing names are idempotent.

The native fixtures `dashboards.json`, `dashboard_widgets.json`,
`dashboard_size.json` and `dashboards_authority.json` retain inputs, observations,
exact probe sources and cleanup under `testdata/aws/cloudwatch/`. They include
cross-region controls, retained invalid replacements, Unicode/HTML-sensitive size
accounting, tag-history transitions, ARN rejection distinctions, named/list/
session/tag authority and correlated S3 audit records. The SDK runner replays
them through RPCv2-CBOR and Query on both memory and SQLite, including reopen.
An actual CLI workflow used a stored widget to query a retained metric sample,
enforced a read-only role, and delivered dashboard API events through CloudTrail
to S3 and EventBridge to SQS. A process restart preserved global body/tag reads
and a 1,001-dashboard SDK listing as 1,000 + 1 ordered entries, including reuse of
the pre-restart continuation token and rejection under a different prefix.
Owned native dashboards and supporting roles, trail and bucket were removed;
cleanup observations remain in the fixtures.

Primary references: [dashboard body](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Dashboard-Body-Structure.html),
[PutDashboard](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutDashboard.html),
[GetDashboard](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetDashboard.html),
[ListDashboards](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListDashboards.html),
[DeleteDashboards](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DeleteDashboards.html).

## Native audit classification and projection

The [CloudWatch CloudTrail reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/logging_cw_api_calls.html)
and delivered S3 records in `testdata/aws/cloudwatch/audit.json` establish the four
implemented **metric APIs** as Data events, not Event history management events.
The capture contains four successes and rejected publication/statistics requests.
They use `monitoring.amazonaws.com`, `managementEvent: false`, and resources
exactly `[{"type":"AWS::CloudWatch::Metric"}]`: no metric ARN, namespace or account
is invented inside that resource entry. `PutMetricData` is writable; the three
read operations are read-only. `responseElements` is present and null even for
failures.

`observations.go` applies this projection through the shared API-event recorder:

- Publication retains namespace and ordered metric-name/dimension identities,
  omitting values, counts, statistic sets, timestamp, unit and resolution.
  An omitted dimensions member remains omitted. Failure projection also excludes
  measurement data.
- Query projection retains nested metric queries, math/labels and query options.
  Start/end times use whole-second UTC RFC3339, not the locale-formatted example
  in the AWS documentation.
- `ListMetrics` adds `includeLinkedAccounts: false` when the input omitted it.
  The observed invalid-value failures have wire code `InvalidParameterValue`
  but audit code `InvalidParameterValueException`; audit error messages retain
  the service message. Success records omit error fields.

The twelve alarm control/tagging operations are **Management events**, with native
read-only classification, null `responseElements` and no invented alarm resource
entry. `alarm_audit.json` retains fourteen outcomes covering all twelve commands.
Successful deletion projects only alarms actually removed; the captured reserved
tag denial has null request parameters. The integration replay checks LookupEvents,
configured management-event S3 delivery and EventBridge/SQS consumption. Read-only
management delivery uses the corresponding EventBridge rule state. These captures
do not establish every authorization/error projection.

Dashboard controls are **Management events**. The correlated native records
retain `[{"type":"AWS::CloudWatch::Metric"}]` without an ARN or `apiVersion`.
Put/Delete are writable; Get/List are read-only. Put redacts `dashboardBody` to
`HIDDEN_DUE_TO_SECURITY_REASONS` and retains its validation-message response.
Other dashboard responses are null. Denials project `AccessDenied`, null request/
response parameters and no resources; invalid body errors use the native audit
name `DashboardInvalidInputError`, distinct from the wire name. Audit region
follows the called endpoint even though the resource is global.
The [CloudWatch Monitoring EventBridge reference](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-monitoring.html)
uses `aws.monitoring` for these CloudTrail API events, not the `aws.cloudwatch`
source used by direct alarm events. Read-only API delivery requires
`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`.

Trail delivery and selector behavior belong to [CloudTrail](cloudtrail.md) and
[event-journal](event-journal.md), not a second CloudWatch audit store. CloudTrail
Lake is outside this bound. The native audit capture did not exercise entity
metrics, pagination tokens, access-denied/cross-account failures, an
omitted-statistics query or every validation error. Initial-batch non-observation
is not proof of absence or guaranteed delivery timing.

`integration/cloudtrail_cloudwatch_audit_test.go` replays the six correlated
native outcomes through actual SDK requests on memory and SQLite. Configured
CloudTrail S3 delivery and EventBridge-to-SQS consumers compare the public
documents, projection omissions, request IDs and service time. A separate
ARN-required selector excludes the captured type-only resource shape locally;
this is not presented as a native negative-delivery experiment.

## Evidence and remaining boundaries

The current evidence is in `testdata/aws/cloudwatch/`:

| Fixture | Scope and limits |
| --- | --- |
| `metrics.json` | Custom publication, ordinary queries/math, dimensions, resolution, units and account rejection. Its arithmetic expectations are not substitutes for returned observations. CLI-side rejections are not AWS responses; no native 500-item listing experiment or historical rollup experiment was performed. |
| `statistics.json` | Weighted/scaled/expanded distributions, inconsistent/eligible sets, fixed/percent trims and zero-count follow-ups. The obsolete Python predictor and duplicated derived comparisons were removed; actual requests, responses and capture accounting remain. |
| `zero_count_boundaries.json` | Thirteen native calls: three publications add nine points to the existing owned metric identity; ten reads capture retained empty-bin selection, zero-valued mass, tail admission and initial visibility lag. No additional metric identity or infrastructure was created. |
| `exact_bin_boundaries.json` | Fourteen native calls: one STS verification, one publication of 36 one-second distributions, and twelve reads. Adjacent inputs, decimal spellings after CLI parsing, extrema clipping and ten-decimal statistic validation. No new metric identity. |
| `extreme_bin_boundaries.json` | Thirty-three native calls: one STS verification, 26 one-second publications, and six reads. Subnormal/tiny/large values, asymmetric floor interpolation and mixed/all-negative fixed-range eligibility. Partial visibility is retained separately. No new metric identity. |
| `metric_labels.json` | Read-only native label queries against the already-owned statistical series; no additional publication or infrastructure mutation. |
| `protocol_errors.json` | Rejected conflicting scalar/array publication through real Go SDK RPCv2 and Query plus directly signed JSON; repeated-run accounting and Query capture are recorded separately. |
| `audit.json` | Delivered CloudTrail S3 JSON for the six named cases, selector propagation limits and cleanup verification across reused owned resource lifecycles. |
| `alarm_controls.json` | Native replacement, no-op state writes, tag/error/selection semantics, deletion and history; replayed through SDK commands on both stores. |
| `alarm_evaluation.json` | Thirty-one independent native transitions anchored by queryDate: missing-data/M-of-N, percentile significance, math and unpublished single-series expressions. Early ambiguous snapshots remain evidence only. |
| `alarm_composites.json` | Native rule admission, quorum/dependency behavior, cycles and suppression, plus explicitly derived Boolean cases. Cycle observations are time-bounded. |
| `alarm_namespaces.json` | DynamoDB omission/override/replacement, direct and expression queries, and used/unused mixed namespaces. State/configuration comparisons use explicit local ticks, not native latency. The two captures created eleven owned alarms, no tables or metric samples, and verified deletion. |
| `alarm_delivery.json` | Native EventBridge documents, action histories and real handler payloads, including wait/extension release; local Docker replay uses actual consumers. |
| `alarm_audit.json` | Management-event projections and the limits of request/time correlation; one reserved-tag denial has exact request-ID correlation. |
| `alarm_idempotence.json` | Exact repeated scalar/composite writes preserve public state/history; a description-only control changes them. Missing duplicate configuration events is a bounded queue observation. |
| `alarm_query_admission.json` | Empty-series expressions and constant expressions are admitted and evaluated; scalar/unknown/dependency failures preserve configuration. No metric data was published. |

Each fixture records its own request counts, scope, normalization and cleanup;
these are not summed into an ambiguous cross-run total. Fixture-specific
normalization preserves meaningful differing identities, native numeric values
and field presence. Audit trail/bucket resources were
cleaned up; metric publishers stopped, but accepted metric series cannot be
deleted. Bounded native visibility does not establish permanent absence.

The boundary regressions failed before their fixes on both memory and SQLite,
then passed through real SDK requests. A separate actual `stackd` process with
SQLite and the AWS CLI exercised 56 calls from the three boundary fixtures:
18 successful queries and eight modeled validation errors matched 6,569 native
numeric/NaN results plus timestamps and omissions. Numeric comparisons use
relative tolerance without treating every tiny value as effectively zero.
Incomplete native publication visibility is retained as evidence, not asserted
as permanent absence. The probe records native observations; the Go runtime and
SDK replay own the implemented algorithm rather than maintaining a second
Python predictor.

Alarm captures cleaned up all owned alarms, rules, queues, functions, roles and
log groups. Two additional custom metric identities retain eleven scalar points
and three weighted percentile points (300 samples); AWS has no deletion API for
those samples. Empty-query/idempotence captures created no metric samples.
Namespace workflows share the control/composite fixture runner. The language
scenario explicitly settles its preceding nonmatching quorum before adding
suppression; otherwise background configuration coalescing can erase the
native-observed transition into `WaitPeriod`. A real CLI/SQLite process verified
namespace defaults, explicit overrides, omission replacement and restart.

SNS publishes weighted service samples through the existing internal metric
interface. Its publication and terminal-delivery samples survive restart and
retain native percentile distributions; this is not customer `PutMetricData`.
Alarm actions retain native structured SNS payloads and Subject, including long
names, Unicode, metric-query and composite projections. [SNS](sns.md) owns these
captures, downstream delivery, metric distinctions and remaining boundaries.

Entity/resource-tag associations, widget-image rendering, metric streams,
other service-owned metrics, observability links and native
visibility/retention/rollup cadence remain open.
Alarm gaps include anomaly detection, PromQL, log alarms/contributors, explicit
evaluation windows/warm-up, metric-query low-sample percentile evaluation,
cross-account observation links and actions beyond Lambda/SNS. Query-engine limitations
also apply to alarms; unsupported configurations/actions fail explicitly rather
than being accepted as inert behavior. Other namespace-specific alarm behavior
and full per-sample causality still need their owning service integrations.

Primary API references:
[PutMetricData](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html),
[MetricDatum](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricDatum.html),
[StatisticSet](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_StatisticSet.html),
[statistic definitions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Statistics-definitions.html),
[GetMetricStatistics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html),
[GetMetricData](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html),
[MetricDataQuery](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricDataQuery.html),
and [ListMetrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListMetrics.html).

Alarm references:
[metric alarms](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html),
[composite alarms and cycle handling](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html),
[history after deletion](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarmHistory.html),
[thirty-day history and evaluation limits](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Alarms.html),
and [low-sample percentiles](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/percentiles-with-low-samples.html).
