# IAM policy evaluation library

Import `stackd/iam/policy` to evaluate policies without the HTTP server, a store
or a clock. The built-in IAM, STS, Organizations, KMS and SQS authorization path
uses `policy.Authorize`; the server has no second policy-composition engine.
Verified OIDC/SAML federation uses `policy.AuthorizeResourceControls` before
credential publication, in addition to its existing provider and trust checks.

The caller authenticates the principal, reads a consistent snapshot of current
attachments and immutable principal bindings, supplies trusted condition context,
and selects every applicable action, resource and Organizations level. The
library evaluates that snapshot without I/O or mutation. It does not infer
service-specific dependencies, authenticate credentials or manufacture context.
Keep input maps and slices stable during the call. Results are detached and can
be retained or modified by the caller.

```go
import "stackd/iam/policy"

result, err := policy.Authorize(policy.Request{
    Action:   "sqs:SendMessage",
    Resource: "arn:aws:sqs:us-east-1:123456789012:work",
}, policy.Authorization{
    Principal: policy.Principal{
        ARN:       "arn:aws:iam::123456789012:user/worker",
        ID:        "AIDAEXAMPLE",
        AccountID: "123456789012",
        Partition: "aws",
    },
    ResourceAccountID: "123456789012",
    Identity: []policy.Policy{{
        Source:  "arn:aws:iam::123456789012:policy/send",
        Version: "v2",
        Document: `{"Statement":{"Sid":"Send","Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:work"}}`,
    }},
})
if err != nil {
    // Reject an invalid or unevaluable request.
    return err
}
if result.Decision != policy.Allow {
    // Reject access; result.Reason and result.Layers explain this decision.
}
```

`Principal.HasBoundary` and `HasSessionPolicy` distinguish an absent restriction
from an attached restriction with no grants. Each SCP/RCP `PolicyLevel` retains
its root, OU or account target and the policies attached there. A resource ARN's
account is authoritative for cross-account composition. `ResourceAccountID`
supplies the service-resolved owner for global operations selecting `*`, including
delegated Organizations listings, and for ARNs without an account or with the
AWS-owned alias. It cannot replace an ARN's numeric account. The caller
selects RCP levels using action applicability and the resource owner's
organization, independently of the principal's SCPs. `ResourceControlExempt`,
`ServiceLinkedRole`, `RootSession` and the KMS grant fields require verified
service state. They must never be copied from user-supplied request parameters.

`ResourceAccountGrant` represents current service-owned access granted to the
caller's account, such as Organizations membership or a registered service
administrator's read permissions. It supplies the resource-side grant while
retaining identity, boundary, session and Organizations restrictions. An explicit
resource-policy denial still wins. The resource-layer explanation records this
authority alongside the evaluated document; it does not synthesize or replace a
policy. Services must derive the grant from their own state. See
[Organizations authority evidence](organizations-delegation.md).

`AuthorizationResult.ServiceGrantRequired` identifies an Allow that depends on
`ResourceAccountGrant` or `ResourcePublicGrant`, rather than an independent policy
permission. Both decisions compose the same already-evaluated permissions; no
policy is evaluated twice. S3 consumes this result for CloudTrail and server
access-log ACL attribution, instead of implementing another authorization check.

`Authorization.Grants` carries KMS-validated `GrantPermissions`. Exact-session
and role grants have different implicit boundary/session limits. Caller-account
trust preserves that distinction during cross-account evaluation; independent
grants cannot combine trust and principal kinds to bypass the limits. See the
[KMS grant evidence](kms-grants.md).

Before passing a role trust policy as `Authorization.Resource`, apply
`TrustResourcePolicy` and `RewriteResourcePrincipals` using current stored
bindings, as the server adapter does. `RequireResourcePolicy` applies to role
trust and KMS key-policy decisions. The standalone matcher also exposes parsing,
resource matching, policy variables and condition evaluation for consumers that
need those primitives.

The authoritative resource-policy binder takes explicit `ResourcePolicyOptions`.
Its zero value rejects federated selectors, preserving existing service
admission. Lambda's whole-function policy API opts in to opaque federated string
selectors under its [native-backed contract](lambda.md#resource-policies-and-asynchronous-delivery).
Parsing and rendering retain those strings, including a literal `*`, without
treating them as wildcard AWS-principal grants. Role trust still applies strict
provider grammar and current IAM provider validation; resource-policy admission
never converts a function policy into a trust policy.

## Identity Center reserved roles

Identity Center delegates permission-set provisioning to IAM's trusted
`ProvisionIdentityCenterRole` command after its own administration and target
account checks. This does not impersonate a root or require the SSO administrator
to hold public IAM mutation permissions. IAM applies its ordinary role validation,
trust binding, managed-policy lookup, attachment limits and inline-policy limits.
Customer-managed policy references resolve existing names and paths in the target
account; provisioning does not create copies of those policies.

IAM retains typed instance and permission-set ownership alongside the actual role
ID. New roles receive `AWSReservedSSO_<permission-set-name>_<random16hex>` names;
updates preserve the name, ARN and principal ID. Removing the last assignment
deletes that exact incarnation and reconciles attachment/boundary usage. A later
assignment creates a different suffix and role ID, so references and credentials
for the deleted role do not gain authority over its replacement. SQLite retains
these ownership fields as typed columns. The reserved path includes the Identity
Center region except for `us-east-1`, matching the
[AWS role-reference contract](https://docs.aws.amazon.com/singlesignon/latest/userguide/referencingpermissionsets.html).

The public IAM mutation gate recognizes that retained ownership and returns
`UnmodifiableEntity` for trust, policy, boundary, duration, metadata and lifecycle
changes. A caller's IAM allow does not bypass
[AWS's protected-role contract](https://docs.aws.amazon.com/singlesignon/latest/userguide/troubleshooting.html#issue4).
Trusted Identity Center provisioning/removal remains available; the roles are not
reclassified as service-linked roles to obtain this protection.

Credential issuance uses the existing transactional service-role authority with
`sso.amazonaws.com` and the instance ARN as `aws:SourceArn`. Exact ownership and
the role ID are checked before evaluating current IAM trust. Issued credentials
remain ordinary role sessions: current inline/managed policies, boundaries, SCPs
and RCPs apply rather than a snapshot of the permission set. These roles do not
receive service-linked-role exemptions.
Session lifetime is resolved from the provisioned IAM role in that same authority
transaction, not from unprovisioned permission-set duration edits.

Cross-account admission reads authoritative Organizations state in the enclosing
transaction. Targets must be active members of the same organization, with SSO
trusted access enabled and a management-account or registered SSO-delegated owner.
Delegation does not grant management-account access; local instance-owner targets
remain allowed without inventing an organization. See
[AWS delegated administration](https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html).
Permission-set deletion rechecks this current eligibility for every provisioned
account, including unassigned provisionings, and rolls back all account effects
if any target is no longer eligible. Its IAM resource authorization remains the
documented instance/permission-set scope, without an added Account requirement.

## Condition values and cardinality

`Request.ContextTypes` carries the scalar or list classification separately from
its values, using IAM's `string`, `numeric`, `boolean`, `date`, `ip` and `binary`
types with an optional `List` suffix. Declare multivalued keys even when the
request supplies only one element. The server derives these declarations from
the pinned AWS service reference, with the global and OpenID classifications
owned by `internal/iam/catalog/conditions.go`. The standalone library accepts
caller declarations and has no catalog dependency. Undeclared keys infer
cardinality from their values; this cannot identify a one-element AWS list.

A present multivalued key never matches a scalar operator, including negated and
`IfExists` forms. This is a nonmatching statement, so it does not invalidate an
independent allow. Missing keys retain the operator's missing-value behavior.
Set operators compare every supplied string, including an empty string. `Null`
checks presence: an empty tag value is present; a missing key or nil slice is
absent; a nonnil empty slice is a present empty set. Multivalued values cannot
expand a policy variable, including with a fallback; a negated comparison can
still match that unresolved value.

The context map owns this distinction directly, and server cloning preserves it.
An empty set contains no matching scalar or `ForAnyValue` operand,
`ForAllValues` retains its empty-set result, and `IfExists` does not skip it.
Service builders omit absent lists or supply nil rather than manufacturing an
empty set. Lambda's mixed-principal legacy-removal captures exercise the
present-empty case without a separate presence inventory or invented scalar.
Server guards still reject attempts to invent verified principal, session,
transport or identity-provider claims through service context.

The native [TagUser capture](../testdata/aws/iam/condition_sets.json) contains 91
calls authorized through real STS role session policies. It covers positive and
negated scalar/set operators, `IfExists`, explicit denies, one/two/missing tag
keys, empty tag values and multivalued policy variables. Allowed empty-tag
requests reach `InvalidInput`; unauthorized ones receive `AccessDenied` first.
The SDK replay uses actual local IAM users, role policies and STS credentials,
checks the AWS error codes and verifies that only authorized tags are written.
The capture script deletes its owned keyless users, roles and inline policies;
temporary credentials remain in memory. It provisions no other services.

AWS's [cardinality contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html)
explains why `aws:TagKeys` needs a set operator regardless of element count.
These captures establish ordinary tagging authorization, separately from the
[simulator's typed input conversions](iam-simulation.md). They do not establish
complete condition, service or partition conformance.

### Case-distinct service tags

Case-colliding tag conditions are a known compatibility boundary, not multivalued
tags. `tag_condition_case.json` captures positive/negated string and set operators
with real immutable STS session policies, insertion-order controls and root
before/after readbacks. The `Case`/`case` matrix resolves to one value; `aws:TagKeys`
still contains both distinct keys. The replay covers this matrix through the same
SDK/STS runner rather than a separate policy mock.

AWS did not expose a general collision-winner rule: `CaSe`/`cASe` selected different
keys for resource tags versus request tags, independently of JSON insertion order
and condition-key spelling. The local evaluator selects the lexically last context
key deterministically. This is **not native precedence parity**, and policies that
depend on a particular mixed-case collision winner can differ from AWS. The
supplemental observations are retained as evidence, not encoded as a speculative
hash-table algorithm. Avoid case-colliding tag names in authorization policies.

The server adapter owns this canonicalization; verified principal and federation
claims remain authoritative and cannot be overridden by service context.
AWS documents [case-insensitive condition keys and unexpected tag collisions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).

## String conditions and resource wildcards

`StringEqualsIgnoreCase` and its negated form compare lowercased text. Unicode
case folding is a different operation: AWS does not equate `S` with long s (`ſ`)
or capital sigma (`Σ`) with final sigma (`ς`). It does equate `ΟΣ` with `ος`,
because the sigma occurs at the end of a word. Dotted capital I (`İ`) lowers to
`i` plus a combining dot. Composed and decomposed accents remain distinct.
The evaluator uses Go's maintained `golang.org/x/text/cases` tables for this
contextual casing, with a separate mapper per call. Native AWS retains
supplementary characters during this comparison, including Deseret case pairs,
while still considering them when determining a neighboring sigma's context.
Policy variables use the same comparison after expansion. Stored policy and tag
strings retain their original text.

String/ARN wildcard comparisons and resource selectors count UTF-16 units:
`?` does not match the supplementary character `𐐀`, while `??` does. Literal
supplementary characters still match themselves, and a substituted character
remains literal. Stars cross newlines and resource suffix separators; brackets
and backslashes do not introduce another pattern language. Permission-report
resource searches use the same token representation. The coarse
`ListPoliciesGrantingServiceAccess` contract still ignores partial resource/action
denies; changing character handling does not turn it into an authorization API.

The owned [string capture](../testdata/aws/iam/condition_strings.json) contains
184 TagUser requests through STS session policies, 52 simulator requests and
four policy-discovery requests after inline policy writes. It covers Allow/Deny,
positive/negated comparisons, list operators, variables, Unicode case/context,
literal/wildcard supplementary characters and ARN/Resource/NotResource matching.
Some invalid tag characters produce boundary validation errors before the
permission check; those rows are validation evidence, not comparison evidence.
The simulator can separately supply those strings as hypothetical context.
All owned users, roles and inline policies were deleted; no S3 resources were
created. Reproduce with `scripts/aws/iam_string_conditions_probe.py`.

The shared [SDK replay](../integration/iam_conditions_integration_test.go) checks native
errors, decisions, resource reports and subsequent tag state. The
[SQS integration](../integration/iam_string_conditions_integration_test.go) changes current
principal tags and policies between sends, then checks that denied messages
were never published. AWS's [string operator contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String)
and [policy variable contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html)
describe the intended comparisons; these captures establish the concrete Unicode
cases above, not completion of the broader condition audit.

## Typed comparisons and policy validation

The [value capture](../testdata/aws/iam/condition_values.json) checks actual
`TagUser` authorization using STS session policies, plus separate native
`PutUserPolicy` and `SimulateCustomPolicy` calls. Legal tag text that cannot be
converted does not invalidate an independent allow. Ordinary numeric and date
negation treat unconvertible text as unequal; malformed request IPs and ARNs
never match, including negated operators. Boolean conversion recognizes `true`
without regard to case and treats other strings as false. Numeric comparisons
accept leading zeroes and a leading plus while retaining decimal precision.
Dates compare at millisecond precision, including policy literals.

The simulator preserves its separate numeric conversion rule: unconvertible
numeric text does not match `NumericNotEquals`. Date negation follows ordinary
authorization. The SDK replay checks those differences directly, along with
Boolean conversion, malformed IPs/ARNs and the native policy-storage errors.

IAM storage validates condition operators and literals through the shared
compiler. It rejects malformed numeric, date, IP, ARN and binary literals.
STS accepts malformed numeric/date/IP/ARN literals in inline session policies;
`ParseSession` preserves them for evaluation while retaining structural and
binary-value validation. This applies both at credential issuance and when
current policies authorize later requests. IAM identity, managed and trust
policy writes retain their stricter storage boundary.

An unconvertible ARN policy operand cannot grant access. With a valid request
ARN, it contributes to a Deny; with a malformed request ARN, the comparison does
not match. Policy-value order is preserved: a matching ARN before a malformed
operand can finish the comparison, while encountering the malformed operand
first uses that effect-dependent result. The trace retains the failed operand without invalidating an
independent allow. `PolicyEvaluation.Decision` remains authoritative even when
another condition in that policy has `Failed=true`.

Refresh the native suites with `python3 scripts/aws/iam_conditions_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID sets`
or `python3 scripts/aws/iam_conditions_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID values`. Both use uniquely owned
keyless users and roles, delete their inline policies and resources, and retain
temporary credentials only in memory. Ordinary tests never call AWS. These
observations cover the captured comparisons and validation boundaries; the
full IAM condition and service audit remains open.

## IP conditions

IP comparisons use one parser for condition literals and request addresses,
with the distinct AWS request normalization kept at that boundary. IPv4 octets
and prefix lengths accept decimal leading zeroes; prefix lengths also accept a
leading plus. IPv4-mapped IPv6 request addresses compare as IPv4. Policy network
literals retain their written family, so a mapped IPv6 network does not grant
access to an IPv4 request. Ordinary IPv6 addresses without a prefix match one
address, using `/128`.

IPv4 CIDRs ignore host bits in their network literal. AWS treats IPv6 differently:
an IPv6 network with host bits set never matches, even its literal address.
For example, `2001:db8::5/64` matches neither `2001:db8::1` nor `2001:db8::5`,
while `2001:db8::4/127` matches `2001:db8::4` and `2001:db8::5`. The evaluator
preserves that difference rather than applying Go's masking behavior to both
families. Negated operators still use the shared NOR and missing-key rules.
IAM policy writes reject these IPv6 networks and dotted IPv6 policy literals.
STS accepts them in session policies: a malformed operand does not match, and
ordinary negation still applies. Simulation also accepts invalid IP literals,
but encountering one ends the comparison as false before negation. Policy-value
order matters: a preceding match short-circuits before an invalid operand.
This simulator rule applies to both identity and resource-policy inputs; actual
policy writes retain the stricter validation boundary.

AWS also accepts some nonstandard IPv6 spellings. A trailing colon is ignored;
a single leading empty group is zero, so `:2001:db8::1` means
`0:2001:db8::1`. One compressed run can include an adjacent empty group, such as
`2001:db8:::1`; multiple compressed runs remain invalid. The shared parser
retains the captured behavior for comparisons and stored-network validation.

The native [IP capture](../testdata/aws/iam/condition_ip.json) retains 256
`TagUser` authorization scenarios under STS session policies, covering positive and negated Allow/Deny
statements, IPv4/IPv6 subnet boundaries and address syntax. Its 144 simulator
requests and 28 stored-policy cases test those separate input contracts. SDK replay verifies
both decisions and that denied calls cannot write tags. An additional SDK test
uses the HTTP peer's `aws:SourceIp` to allow or deny real SQS sends after IAM
policy changes. IP normalization does not rewrite a simulator context string:
String comparisons retain the supplied spelling, including mapped addresses.

Refresh this suite with `python3 scripts/aws/iam_conditions_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID ip`. The
probe owns only keyless users, inline policies and actor roles; temporary
credentials remain in memory, and cleanup removes the owned resources. The
capture completed across three owned-resource runs after one CLI call timed out;
read-only simulations also identified the spelling and array cases. The timeout is
not treated as an authorization decision. AWS's
[IP condition documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_IPAddress)
and [source-IP contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourceip)
describe IPv4/IPv6 support. These native cases supply the more precise parsing
and comparison evidence; the broader IAM audit remains open.

## Decision explanations

`AuthorizationResult` contains the final decision, its composition reason and
the evaluated policy layers. Each layer records its decision, hierarchy target
and policy sources/versions. Statements retain their SID, index, positions in
the supplied document, matching outcome, principal-binding category and the
condition comparisons actually reached. An explicit deny or a request/document
error ends the layer traversal; a missing layer does not imply that it permitted access.

IAM snapshots identify managed policies by ARN and selected default version.
Inline sources use the owning user/group/role ARN followed by `#policy-name`.
Boundaries and managed session policies retain the same managed metadata.
Organizations snapshots retain policy ARNs and ancestry targets; Organizations
has no policy-version API, so their version fields remain empty. Inline session
sources identify their position in the verified session; AssumeRoot retains the
selected task-policy ARN. No version is invented for an unversioned snapshot.

A statement can fail to match its action, resource, principal or conditions.
Conditions record the operator, key name, missing input, comparison result and
any evaluation failure. Only reached comparisons appear. Missing input can
legally match `IfExists`, `Null` or negated operators; missing input is not itself
a denial reason. Context values, credentials and policy document bodies are
excluded from the trace. Source identifiers and key names remain visible.

Enforcement shares the existing matchers with simulation. Simulation-specific
missing-context summaries deliberately include unrelated statements in some
cases; the enforcement trace records the matching path instead. Neither a trace
nor a simulator result proves complete AWS behavior. No response labels,
provenance headers or durable diagnostic ledger are introduced.

## Verification and remaining work

The existing SDK authorization suites exercise the public composition path,
including immutable principal bindings, policy changes, cross-account access,
root task sessions, SCP/RCP restrictions, KMS grants and queue delivery. Retained
IAM snapshots are evaluated before and after managed default-version changes;
Organizations snapshots preserve policy sources across concurrent SDK mutation.
Focused library tests cover actual matching paths, missing-condition semantics,
boundary/direct-grant explanations and independent grants alongside failed ARN
comparisons. The moved matcher tests retain the captured AWS simulator cases.

AWS's [policy evaluation overview](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
and [enforcement rules](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
provide the composition contract. The existing [simulation](iam-simulation.md),
[resource-control](iam-resource-controls.md) and [root-access](iam-root-access.md)
guides own their live AWS evidence. The SQS delivery guide owns the
[forwarded authorization captures](sqs-delivery.md#forwarded-authorization).

Complete action/resource/condition conformance and traces joining dependent
permission checks remain open. A trace covers one required permission; callers
must still enforce every service-owned dependency. Canonical-user resource
principals await their service consumers. See [IAM's completion audit](iam-completion.md)
and [TODO.md](../TODO.md) for the remaining service work.

## Forwarded caller context

The server carries an ordered `CalledVia` chain in authenticated request
metadata. Internal service adapters add hops; queue policies, federation claims
and HTTP parameters cannot supply that chain. The shared authorization boundary
derives `aws:CalledVia`, `aws:CalledViaFirst`, `aws:CalledViaLast` and
`aws:ViaAWSService`. Direct requests have no chain and `ViaAWSService=false`.
The principal remains the original IAM identity, so `PrincipalIsAWSService`
remains false. Identity policies, boundaries, session policies, resource policies
and Organizations controls continue to apply.

SQS-to-KMS calls add the SQS service principal while retaining `kms:ViaService`'s
regional endpoint value. Redrive admission checks the direct caller's dependent
permissions; accepted delivery steps use forwarded permissions for the actual
message and destination. Held messages do not trigger a delivery authorization
failure until eligible. The
[AWS FAS contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_forward_access_sessions.html)
also retains the original public endpoint source IP. VPC endpoint context and
noncommercial service-principal conformance remain outside these native captures.
