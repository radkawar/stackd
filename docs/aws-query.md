# AWS Query input behavior

The generated IAM and STS bindings use the shared Query decoder in
`internal/awsapi`. Smithy types select primitive parsing; generated constraints
then validate the parsed value before handlers or IAM authorization consume it.
The internal JSON representation does not define the accepted Query syntax.

[Smithy's Query protocol](https://smithy.io/2.0/aws/protocols/aws-query-protocol.html)
defines form-encoded requests and XML responses, with textual primitive values.
SDK serialization emits conventional decimal integers and `true`/`false` booleans.
Native captures establish additional accepted forms and rejection behavior:

| Input | Captured behavior |
| --- | --- |
| IAM `CredentialAgeDays=1`, `01`, `%2B1` | Each creates a credential expiring exactly 86,400 seconds after creation |
| STS `DurationSeconds=900`, `0900`, `%2B900` | Each issues a session with the requested 900-second duration |
| Integer whitespace, fractional or exponent notation | `MalformedInput`, HTTP 400 |
| STS integer exceeding the modeled signed 32-bit type | `MalformedInput`, HTTP 400 |
| Valid integer syntax outside an operation's allowed range | Modeled validation, with service-specific error mapping where captured |
| IAM `AllUsers=true` or `1` | Requires permission on the account's `user/*` resource |
| IAM `AllUsers=false` or `0` | Uses the requested/default user |
| Boolean whitespace, mixed/upper case, empty value, `null` or arbitrary text | `MalformedInput`, HTTP 400 |

An encoded plus sign is `%2B`; an unescaped `+` is a form-encoded space. Integer
parsing preserves the signed value while discarding insignificant leading zeroes.
IAM's `iam:ServiceSpecificCredentialAgeDays` condition receives the parsed decimal
value: the native `StringEquals: "1"` policy permits all three accepted one-day
forms. Authorization and mutation consume the same generated input.

`internal/awswire.QueryInputError` maps primitive parsing failures, modeled
validation failures and unknown operations. IAM layers its captured role-duration
mapping over that shared behavior. Standalone IAM/STS and gateway dispatch use the
same error classification. JSON protocols retain their own primitive syntax.

## Evidence and scope

- [IAM capture](../testdata/aws/iam/credential_inputs.json): ten integer inputs,
  seven condition-controlled creations and fourteen boolean inputs. The
  [SDK replay](../internal/services/iam/credential_inputs_aws_test.go) checks errors,
  expiration, permission enforcement and unchanged state after rejection through
  standalone IAM and the signed gateway.
- [STS capture](../testdata/aws/sts/query_inputs.json): nine integer inputs after
  an authenticated propagation control succeeded. The
  [SDK replay](../internal/services/sts/query_inputs_aws_test.go) checks errors,
  deterministic expiration, stored identity and usable signed session credentials.
- [IAM role-duration capture](../testdata/aws/iam/resource_inputs.json) retains
  the distinct `ParamValidation` minimum and `ValidationError` maximum failures;
  see [the IAM audit](iam-completion.md).

The probes are `scripts/aws/iam_credential_inputs_probe.py` and
`scripts/aws/sts_query_inputs_probe.py`. They use owned users, credentials and
permission policies, delete those resources, and never persist secret material.
Normal tests replay the fixtures offline. The SDK fixture helper changes selected
wire values after serialization and before signing, so signatures and decoded
responses still exercise the ordinary SDK and service paths.

These captures establish the listed requests with valid credentials. They do not
establish complete Query behavior, combined authentication/validation error ordering,
or complete IAM/STS semantics. The API surfaces and value limits are documented by
[CreateServiceSpecificCredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceSpecificCredential.html),
[ListServiceSpecificCredentials](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListServiceSpecificCredentials.html)
and [GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html).

## Pagination consumes parsed values

IAM's shared paginator receives the generated request type. `awsgen` derives
pagination accessors from the input's `Marker` and `MaxItems` members, including
report and service-credential operations whose models lack SDK paginator traits.
The accessor returns the token, optional size and a typed copy without those two
controls. Modeled validation owns numeric bounds; pagination does not reparse or
validate them again.

Continuation markers bind partition, account, operation and the typed selection.
The owning handler supplies any effective filter defaults: canonical account-report
filter sets, report sort keys, current instance-profile/role names and omitted
access-key/MFA usernames. Last-access entity reports retain their captured
namespace-independent continuation. The shared paginator retains the 200-item
last-access service default and 100-item default for its other callers. It uses
stable resource keys and does not include page size in the selection.

The [pagination capture](../testdata/aws/iam/pagination_inputs.json) and
[SDK replay](../internal/services/iam/pagination_inputs_aws_test.go) cover 19 native
requests: nine page-size representations, a user-list first page and four
continuations, two tag pages, and three service-credential pages. AWS accepts
continuation from `AllUsers=false` with `AllUsers=0`; the previous raw Query hash
incorrectly rejected that equivalent selection. Unknown tag fields on ListUsers
do not change its continuation. Accepted size forms and size changes preserve
nonoverlapping results. The SDK replay checks page counts, truncation, token
presence, errors and overlap on standalone IAM and the signed gateway.

The probe `scripts/aws/iam_pagination_inputs_probe.py` created three users with
tags and two Bedrock service credentials, then deleted those owned resources.
The workflow extends the IAM identity-management reference recorded in
[behavior references](behavior-references.md). AWS documents the limits and
continuation controls for
[ListUsers](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html)
and [ListServiceSpecificCredentials](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListServiceSpecificCredentials.html).
The captures do not establish all filter/default equivalences, mutation during
pagination, or complete IAM semantics. There is no compatibility path for the
superseded draft marker representation.

## Indexed collections and tag authorization

The [tag input capture](../testdata/aws/iam/tag_inputs.json) records 60 TagUser
requests under an administrator and an owned actor whose policy allows only
`team=approved` with `aws:TagKeys` restricted to `team`. The
[collection capture](../testdata/aws/iam/query_collections.json) records 24 read-only
GetContextKeysForCustomPolicy requests. Together they establish:

- `Tags.member.1` and `Tags.member.01` identify the same element. A key at `01`
  and its value at `1` form one tag. Unknown nested members are ignored.
- Missing positions are preserved for modeled validation. Sending only element
  two does not turn it into element one. Index zero, negative indices and
  consecutive numeric path segments produce `MalformedInput`.
- Collection construction starts at position one and permits each supplied index
  to extend the current extent by ten. Initial index 11 reaches validation; 12
  produces `MalformedInput`, even with index one also present. Supplying positions
  1, 8 and 15 reaches validation, confirming the limit applies to each expansion.
- Nonnumeric member names retain their nested structure. Tag structures then
  fail required-field validation; primitive policy strings reject the unexpected
  nesting with `MalformedInput`. Integer scalar syntax does not define index syntax.
- Generated constraints reject invalid tag text and missing values before
  authorization. Reserved prefixes and duplicate-key rules run in the mutation
  handler after authorization. A denied reserved-key request returns AccessDenied;
  the administrator receives InvalidInput for the same fields.
- For an exactly repeated tag key, the last value controls the permission test.
  `team=other, team=approved` reaches InvalidInput for duplicates, while the reverse
  order returns AccessDenied. `aws:TagKeys` retains distinct key spellings.

IAM's shared condition evaluator uses generated member accessors. An operation
without a modeled Tags, TagKeys, PolicyArn, PermissionsBoundary or
OrganizationsPolicyId field cannot acquire that request condition from an injected
Query parameter. Resource tag/boundary conditions still come from current state.
The domain tag helper owns reserved-prefix and resource-specific duplicate rules;
it does not repeat the generated count, length or character constraints.

The [SDK replay](../internal/services/iam/tag_inputs_aws_test.go) checks codes,
HTTP status and complete retained tag state on standalone IAM and the signed
gateway. It also checks the policy-inspection output. The fixture middleware
changes/removes selected serialized fields before signing, retaining the captured
list grammar while using ordinary SDK response/error decoding.

The probes are `scripts/aws/iam_tag_inputs_probe.py` and
`scripts/aws/iam_query_collections_probe.py`. The former deletes its owned users,
access key and policy; the latter creates no resources. These workflows extend
the permission-enforcement references in [behavior references](behavior-references.md).
AWS documents [TagUser](https://docs.aws.amazon.com/IAM/latest/APIReference/API_TagUser.html),
[request-tag conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-requesttag)
and [policy context inspection](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForCustomPolicy.html).
The additional lexical forms, sparse expansion behavior and denial precedence
come from the captures, not solely from those documents or the Smithy models.
These cases do not establish all Query maps/nesting, authentication/error ordering,
case-variant request-tag value combinations or complete IAM behavior.
