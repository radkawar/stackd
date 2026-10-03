# IAM policy simulation

`SimulateCustomPolicy` and `SimulatePrincipalPolicy` use generated Query inputs
and outputs and the shared policy matcher. Simulation is hypothetical: it does
not invoke the requested service action or mutate the supplied principal's
policies. The authenticated API request must independently pass IAM, boundary,
session and Organizations authorization before it can inspect a principal.

Principal simulation reads the current user, group or role, its inline policies,
attached managed-policy default versions, user group memberships and permissions
boundary from the IAM transaction. Role trust is not an identity permissions
policy. Extra policy documents apply only to this evaluation; an explicit
boundary replaces the attached boundary. The configured Organizations source
supplies the current ordered SCP hierarchy. Its read joins the IAM transaction
in the default memory bundle and the coordinated SQLite adapters.

Policy exclusions select inline attachments, AWS-managed or customer-managed
identity policies, boundaries or SCPs. Exclusions do not modify storage, and
request-supplied policies survive exclusions of attached policies. RCP exclusion
is accepted and ignored by this API, as documented by AWS; this does not implement
RCP enforcement. A user's managed policy attached through multiple groups is
loaded once. Source identities retain friendly policy names and inline owners.

Each result retains the requested action, resource decisions, applicable boundary
and organization decisions, contributing statement locations and missing context
keys. Action and resource order, including duplicates, is preserved. Pagination
counts actions and retains all resource results for each action; continuations
accept changed action/policy/resource inputs, while local tokens retain account,
partition and operation scope. Statement and missing-key sets have deterministic
local ordering; AWS does not document their ordering.

## Simulation and authorization are distinct contracts

The simulation entry points share condition, principal and resource matching with
enforcement, while retaining simulator-specific input and output behavior. Unknown
and wildcard action spellings are evaluated literally against policy patterns.
Typed context entries preserve scalar/list and value-kind distinctions. Caller
context defaults can be overridden by explicit hypothetical entries; those entries
never become the authenticated API request's authorization context.
The IAM input boundary normalizes typed context once.
[Native comparison captures](iam-evaluation.md#typed-comparisons-and-policy-validation)
separate simulator numeric conversion from ordinary authorization and verify
date negation, Boolean conversion and malformed IP/ARN comparisons. Explicit empty strings
remain present for simulation's `Null` and set operators; they do not become
missing context merely because the value is empty.
The [IP condition capture](iam-evaluation.md#ip-conditions) adds IPv4-mapped
addresses, CIDR parsing and IPv6 network boundaries. An `ip` context entry
validates the supplied address but retains its text for String comparisons;
normalization for an IP comparison happens in the shared matcher.

Same-account resource-policy grants can allow a simulated request despite an
implicit identity or boundary denial, including grants to the account root.
Explicit denies still apply. Cross-account simulations require applicable
identity, resource and boundary permissions. These are captured simulator
observations, not a reason to weaken live service authorization. SCP levels are
unions within each level and intersections across the hierarchy; SCP denial
suppresses statement attribution and missing keys from other layers.

Several current model/documentation statements differ from the observed API:

- An empty custom `PolicyInputList` succeeds with an implicit denial.
- Inline exclusion owner names accept prefix `*` and `?` patterns; a bare `*`
  fails the upstream service's nonempty-name pattern.
- Principal source ARNs resolve by entity name despite a different path.
  Managed policy ARN exclusions match a pathless friendly-name ARN, and do not
  remove a boundary, even when the same policy also grants identity permissions.
- Source policy types in responses are `IAM Policy`, `Resource Policy` and
  `Permissions Boundary Policy`, rather than the published source-type enum.
- Resource policies work with user, group and role callers. `ResourceOwner`
  accepts an IAM ARN; numeric account IDs were rejected in the capture.
- Resource-policy simulations require ARN-scoped request resources and reject a
  policy resource of `*`.

Input-model differences are explicit, evidence-backed entries in
[`cmd/awsgen/model_corrections.json`](../cmd/awsgen/model_corrections.json).
Generation checks exact local or inherited target traits before applying a
correction. Source and manifest hashes are passive provenance; changes elsewhere
in a reviewed upstream model do not block an unrelated correction. Native
generation checks detect output drift. Normal builds remain independent of
the reference checkout.

## Evidence and remaining audit

[`testdata/aws/iam/simulation.json`](../testdata/aws/iam/simulation.json) records
245 live custom/principal cases, owned resource changes and verified cleanup.
[`scripts/aws/iam_simulation_probe.py`](../scripts/aws/iam_simulation_probe.py)
reproduces the opt-in capture. Offline SDK replay compares decisions, modeled
errors, diagnostics, positions and action/resource order, normalizing only
unordered sets and SDK empty collections. The separate
[`simulation_inputs.json`](../testdata/aws/iam/simulation_inputs.json) capture
covers typed value conversion, validation and resource combinations; its probe
performs no resource writes. Package tests additionally exercise current graph
changes, caller permission separation, boundary replacements,
exclusions, tenant isolation and storage coherence. Root integration checks the
Organizations source against actual SQS authorization.

Custom simulation without `CallerArn` uses the literal `aws:userid` value
`STUB_PRINCIPAL_FOR_POLICY_SIMULATOR`. With `CallerArn`, the default user ID is
that ARN, including its path. Explicit context entries override these defaults.
The [default-context capture](../testdata/aws/iam/simulation_defaults.json)
records direct equality checks, variable expansion and caller overrides. This
simulator context never substitutes for an authenticated principal's IAM ID.

The [action capture](../testdata/aws/iam/simulation_catalog.json) supplies
`cmd/simgen` with AWS simulator recognition and resource display metadata for
21,894 action spellings across 455 service namespaces, each with default,
single-resource and multiple-resource observations. Thirty catalogued
spellings fall into AWS's unrecognized-action group, and 535 actions omit the
aggregate resource name in the multiple-resource scenario. Recognition is
separate from case-insensitive policy matching. The generated table replaces
handwritten service templates and does not grant permissions. A single explicit
resource is echoed even for an unrecognized action. With resources omitted,
153 actions have special resource names; these include concrete account-scoped
ARNs and templates whose placeholders AWS leaves literal. Concrete account
values use the authenticated account, independently of hypothetical `CallerArn`.
The IAM list-action controls confirm those synthetic ARNs are display names;
the omitted-resource policy evaluation still uses `*`.

Resource-handling options are generated separately from the native
`service_reference.json` capture. Its 41 calls cover six EC2 instance scenarios,
eight CloudWatch resource scenarios for each tagging operation and two Device
Farm scheduling scenarios, plus unknown and mismatched options. The captures
include successful EC2-Classic, CloudWatch and Device Farm options beyond the
four VPC scenarios listed in the API page. These names are simulator controls;
they are not resource types in the service authorization catalog.

These cases establish the recorded behavior, not universal AWS parity. Resource
eligibility still uses the generated authorization reference and observed
simulator differences; the action sweep does not exercise every resource type,
condition or policy combination.

The [IAM completion audit](iam-completion.md) remains open, including the full policy
context/action/resource matrix, other IAM operations and resource-policy principal
forms still identified in the shared evaluator. Local simulation never falls back
to AWS. No fidelity or provenance headers are added to responses.

Primary references: [custom simulation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html),
[principal simulation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html),
[evaluation results](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html),
[policy exclusions](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PolicyIdentifier.html),
[inline selectors](https://docs.aws.amazon.com/IAM/latest/APIReference/API_InlinePolicyIdentifierType.html),
and [ordered organization policies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_OrderedOrganizationPolicyType.html).
