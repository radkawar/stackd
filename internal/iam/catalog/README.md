# IAM metadata catalog

`cmd/iamgen` generates this package from AWS's public
[service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html).
The pinned `data/service_reference.json.gz` contains all 456 service documents,
the source URL and capture time. It includes AWS's original operations,
annotations and condition definitions. Generation retains the fields used by
current authorization and reporting callers: actions, resource types, every ARN
form, applicable action/resource conditions, condition types and action-last-access support.

Refresh explicitly with `python3 scripts/aws/iam_service_reference.py`, then run
`make generate-iam`. `make generate-iam-check` compares generated output without
writing or contacting AWS. Normal builds need no clone, credentials or network.
The same AWS snapshot supplies last-access action tracking; report display names,
default regions and ordering still come from the owned Organizations capture.

The September 27 refresh is paired with
`testdata/aws/iam/organizations_access_metadata_20260927.json`, captured from one
uniquely owned empty OU without changing account placements, policies or trusted
access. It records all 456 report namespaces, exact default-region presence and
native time ordering. The OU was deleted and its absence verified.
`last_access_service_names_20260927.json` independently captures the same service
names through an owned IAM policy; `last_access_pending_policy_20260927.json`
preserves report snapshot behavior across a default-policy version change.
Those policies were deleted and cleanup verified. Older captures remain unchanged
as historical evidence; their former 455-service inventory is not a current
reporting contract.

RCP generation combines that same reference's action resource types with the
62 supported service prefixes and explicit exceptions captured from the current
Organizations guide in `data/resource_control_source.json`. Unscoped actions are
not enabled merely because their service supports RCPs. See the
[resource-control contract](../../../docs/iam-resource-controls.md) for source
dates, exemptions and the historical ListQueues discrepancy.

The catalog returns detached records. IAM resolves resource names and paths from
current transactional state before enforcing permissions. Multiple ARN forms
remain separate alternatives for policy discovery and simulation. Action
conditions combine the action's keys with keys of its supported resource types.
Resource-handling scenarios belong to the IAM simulator and its native captures.

AWS's operation-action mappings are incomplete for some services and omit
permissions required through Forward Access Sessions. They are retained as source
material, not executed as an authorization shortcut. Current service code owns
dependency conditions, resource resolution and policy enforcement. The old cloned
draft SDK mappings, their unused runtime APIs and source-digest checks are removed.

The native `testdata/aws/iam/service_reference.json` capture and SDK replay cover
HTTP/REST API Gateway and both Greengrass deployment ARN forms in
`ListPoliciesGrantingServiceAccess`, plus a policy with an unrelated service ARN.
The owned keyless IAM user and inline policies were deleted. API Gateway and
Greengrass resources were not created. These reporting cases do not establish
complete IAM behavior or implement those services.

The same capture retains 41 native simulator calls. `cmd/simgen` generates
resource-handling options from successful responses; SDK replay checks both
accepted scenarios and invalid/mismatched options. The ARN evaluator searches
resource alternatives independently, retaining policy-level intersections and
denies without exploring the product of unrelated ARN languages.

`condition_types_generated.go` supplies unambiguous scalar/list declarations for
trusted context in ordinary authorization and federation trust. `ContextTypes`
looks up concrete keys; overloaded definitions and unknown names stay
undeclared, and source templates do not manufacture request values. The IAM
global key reference supplies global arrays absent from the service snapshot;
the OpenID contract supplies issuer-specific `amr` arrays, including Cognito's
incorrectly scalar service-reference entry. These explicit corrections live in
`conditions.go`. [Native tagging evidence](../../../docs/iam-evaluation.md#condition-values-and-cardinality)
verifies one-element list handling, empty values and policy variables.
