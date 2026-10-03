# IAM account properties

`GetAccountProperties` and `PutAccountProperties` consume generated Smithy
bindings. IAM stores the `RoleManager/Enabled` boolean in its typed account
settings, scoped by partition and account and shared across regions. Ordinary
accounts default to `false`. Unsupported namespaces and invalid values return
errors; extra properties in the recognized namespace are ignored when `Enabled`
is present, matching the live capture.

## Permissions and transitions

Both operations supply trusted `iam:AccountPropertyNamespaces` to the existing
IAM evaluator. Enabling also checks `iam:CreateServiceLinkedRole` against
`role/aws-service-role/role-manager.iam.amazonaws.com/AWSServiceRoleForIAMRoleManager`,
with `iam:AWSServiceName` set to `role-manager.iam.amazonaws.com`. AWS requires this
permission even when the role already exists. Disabling requires only the account
property permission. Namespace conditions cannot be supplied independently of the
decoded request.

Enablement creates a missing service-owned role with the captured trust document
and `AWSIAMRoleManagerServiceRolePolicy` attachment. The role and setting commit
together. Existing owned roles retain identity, creation time and description;
ordinary same-named roles are not adopted. Explicit `CreateServiceLinkedRole`
uses the same definition and rejects custom suffixes. Disabling leaves roles
intact. Direct `AcquireRole` remains available independently of the setting.

The Role Manager usage adapter currently treats the enabled account feature as
a deletion dependency and holds IAM's transaction through deletion after it is
disabled. **That deletion rule is a model, not an AWS-confirmed transition.**
The AWS probe returned terminal internal errors in both states, without usage
resources. Successful Role Manager deletion and its exact diagnostics remain
an explicit `TODO: Comeback`; this work does not establish complete Role Manager
behavior or IAM parity.

## AWS evidence and unresolved cleanup

Captured on 2026-09-12 in a commercial management account:

- `testdata/aws/iam/account_properties.json`: validation, namespace conditions,
  denied enablement and disablement without service-role creation permission.
  Its owned IAM user and access key were removed; initial account state was
  restored.
- `testdata/aws/iam/account_properties_toggle.json`: enable, repeated enable,
  disable and preserved role identity. The original disabled setting was restored.
  This capture reused the role from the lifecycle probe and created no credentials
  or resources; it does not prove provisioning from an absent role.
- `testdata/aws/iam/role_manager_cleanup.json`: service-role definition, managed
  attachment and five terminal failed deletion jobs, including a delayed retry. The owned role
  `AWSServiceRoleForIAMRoleManager` (sanitized ID `AROAQAAAAAAACQWNVES36`, created at
  `2026-09-12T00:38:42Z`) remains in the probe account. AWS reports
  `Role could not be deleted because of an internal error.` The temporary user
  `stackd-properties-6c579f8ee136` and its keys are deleted; Role Manager is disabled.
  A read of Access Analyzer in `us-east-1` found no analyzers. No compute was launched
  and no Organizations configuration was changed.

The September 22 follow-through verified the same owned role ID and the disabled
account property, then submitted one new native deletion task after reading the
previous terminal failure. AWS again returned `FAILED` with the same internal
error and an empty usage list. A final `GetRole` still returned the original role;
Role Manager remained disabled. The task ID and current readbacks are appended to
the existing cleanup fixture. No account setting, policy attachment or standing
identity was changed. This remains an AWS-side cleanup blocker, not successful
deletion or a reason to repeat the lifecycle probe.

The lifecycle script originally failed during cleanup before writing its final
observations. The surviving AWS readbacks are recorded separately; missing
observations have not been reconstructed as fixtures. The probe now saves each
observation, removes temporary credentials before service-role cleanup and polls
the same accepted deletion task through temporary `NoSuchEntity` responses.

`scripts/aws/iam_account_properties_probe.py` runs negative cases using an owned
user. `--lifecycle` additionally requires the role absent, creates it and toggles
the account setting. **Do not run that option again while the existing cleanup
failure is unresolved.** Recover the existing owned role through AWS's native
`DeleteServiceLinkedRole` and `GetServiceLinkedRoleDeletionStatus` APIs; inspect a
terminal result before submitting a replacement task. Do not treat an accepted
task or observation timeout as successful deletion.

SDK tests replay the validation and role-definition capture and cover exact
dependency permissions, namespace restrictions, immutable ownership, retained
state, cancellation, failed commits, concurrent enablement and account/partition
isolation. Organizations SDK tests enforce both account-property and dependency
SCP denials without publishing partial state. The local deletion test verifies
the stated model only. Tests do not contact AWS.

## Remaining dependencies and primary contracts

AWS's new account experience can enable Role Manager by default and prevent
disablement until advanced features are activated. After that experience's first
disablement, AWS provides a free unused-access analyzer for 90 days. This is
**not** a documented side effect of toggling every ordinary account. That account
onboarding transition and Access Analyzer consumer are not yet implemented;
there is no dormant configuration flag pretending to supply them.

Sources: [GetAccountProperties](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountProperties.html),
[PutAccountProperties](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutAccountProperties.html),
[Role Manager](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_role-manager.html),
[permissions and SCPs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_role-manager_enable-use.html),
[least-privilege and analyzer transition](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_role-manager_least-privilege.html),
[service-role policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMRoleManagerServiceRolePolicy.html).
See [behavior references](behavior-references.md) for evidence and generation rules.
