# IAM role templates

`GetRoleTemplateVersion` and `AcquireRole` use generated Smithy contracts and
five templates captured from AWS on 2026-09-12: PowerUser, Backup, SageMaker
Studio administrator/user, and Secrets Manager rotation. Each has major version
1 and default minor version 0. Unknown ARNs and versions return `NoSuchEntity`.
The [AWS directory](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_role-template.html)
also lists seven CloudWatch templates; all seven returned `NoSuchEntity` during
the capture. Their definitions are not invented locally.

## Creation and reuse

Acquisition substitutes defaults, String and StringList values into captured
trust and permission documents. JSON substitution preserves string boundaries.
Disabled statements are removed before resolving their parameters, so parameters
used only there may be omitted even when metadata says `IsRequired`. A fully
disabled inline policy is omitted. Unknown parameter names produce `InvalidInput`;
multiple values for a String produce `ValidationError`. Ordinary IAM validators
enforce the resulting names, trust, policy syntax and quotas.

Role creation, policies and the template association commit in one repository
transaction after dependent permission checks. Denial, cancellation or a failed
commit publishes no partial role or attachment. Created roles use normal STS and
IAM evaluation; detaching a policy changes an existing session's permissions.

Repeated acquisition preserves the role ID and creation timestamp. Description
and maximum-session-duration edits permit reuse. Trust, tags, managed attachments,
inline policies and the boundary are compared with the original template rendered
using its saved inputs. Changes return `RoleModified`; restoring configuration
permits reuse. Different template/parameter results, including RoleName casing,
return `NameConflict`. An ordinary role with matching policies also conflicts.
The typed template association retains version and inputs, with no digest or
modification ledger. `GetRole` exposes `SourceRoleTemplate`; captured acquisition
and list responses omit it.

## Permissions and observed documentation difference

Acquisition first requires `iam:GetRoleTemplateVersion` on the template ARN.
Reuse requires `iam:GetRole`; creation requires `iam:CreateRole` and applicable
`iam:AttachRolePolicy`/`iam:PutRolePolicy` permissions. There is no separate
`iam:AcquireRole` permission grant. Role decisions receive trusted
`iam:RoleTemplateARN`; attachment decisions also receive `iam:PolicyARN`.
Ordinary API requests cannot supply template context. Boundaries, session
policies and SCPs use the existing evaluator.

The [AWS permission guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_role-manager_enable-use.html)
includes `GetRoleTemplateVersion` in a template-context SCP example. The live
API omits `iam:RoleTemplateARN` from that action's decision, including during
acquisition. An Allow conditioned on that key denied both operations in the
owned-user probe. Stackd follows that observation and the generated catalogue's
condition-key list. AWS-owned template reads require identity permissions without
a customer resource-policy grant; other accounts' resources remain isolated.

Direct acquisition does not require enabling Role Manager. The
[account-property implementation](iam-account-properties.md) enforces namespace
conditions and provisions its service-linked role atomically. Role Manager's
new-account/Access Analyzer integration and deletion conformance remain open.
Commercial template reads expose `aws:ResourceAccount=639982225848`, the same
service account as AWS-managed policies. The public ARN alias `aws` and the
caller's account do not match that condition. IAM supplies this account for both
direct `GetRoleTemplateVersion` calls and the dependent read inside `AcquireRole`.
The later CreateRole/GetRole/AttachRolePolicy checks continue to use the customer's
resource account. One service-owned resolver serves both permission paths.

The [resource-account capture](../testdata/aws/iam/template_account.json) contains
23 requests using owned STS role sessions with immutable condition policies. All
five captured commercial templates accept the service account and reject the
public alias. PowerUser acquisition/reuse has the same behavior. The key is
present and has twelve characters; an absent-key grant fails. A missing major or
minor version yields NoSuchEntity with a matching account grant and AccessDenied
with the alias grant, retaining authorization before lookup. The
[SDK replay](../integration/role_template_account_integration_test.go) verifies these outcomes,
returned versions, stable acquired-role identity and the resulting policy attachment.
The probe deleted its roles and policies. See AWS's
[ResourceAccount contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-resourceaccount);
the exact account value and template behavior come from the live capture.
Noncommercial resource-account values and the complete partition/version audit
remain unverified; these captures do not complete IAM.

## Evidence and refresh

- `testdata/aws/iam/role_template_catalogue.json`: twelve directory lookups and
  an account-property read, including all seven unavailable entries.
- `testdata/aws/iam/role_templates.json`: rendered trust/inline policies,
  attachments, reuse and parameter errors.
- `testdata/aws/iam/role_acquisition.json`: restricted-user permissions,
  edits/restoration, ordinary-role conflicts and read/list field presence.
- `testdata/aws/iam/template_account.json`: conditional direct/dependent template
  reads, all five commercial definitions and missing-version denial precedence.
- `integration/role_templates_integration_test.go` and `integration/role_template_reuse_integration_test.go`:
  SDK replay, STS/SQS permission changes, concurrency and account isolation.
  IAM repository tests cover rollback, cancellation, detached inputs, partition
  isolation and retained reuse. Policy comparisons normalize formatting,
  unordered arrays and scalar versus single-element list notation; separate
  assertions preserve identity and creation-time relationships.

Refresh definitions without creating roles:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/aws/iam_role_templates_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID --catalogue-only
```

Without that flag, the script also probes owned roles.
`scripts/aws/iam_role_acquisition_probe.py` uses owned roles, an IAM user and an
access key. Both mutation probes delete their resources and verify cleanup.
`scripts/aws/iam_template_account_probe.py` uses an owned role, scoped STS sessions
and an acquired target role; it deletes both roles and their policy attachments.
They do not enable Role Manager, change Organizations settings or launch compute.
Normal tests and builds use checked-in data and never contact AWS. Review newly
captured definitions and their semantics before replacing the embedded snapshot.

Primary contracts: [AcquireRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AcquireRole.html)
and [GetRoleTemplateVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRoleTemplateVersion.html).
The snapshot preserves AWS template IDs and timestamps independently of Smithy
operation definitions and the AWS-managed policy catalogue.
