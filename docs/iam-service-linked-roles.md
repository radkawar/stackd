# IAM service-linked roles

Create, delete and deletion-status APIs use generated inputs and outputs. A role
has explicit service ownership stored separately from its name, path, tags and
trust policy. Ordinary roles cannot acquire that ownership through API parameters.
Current immutable role identity supplies the Organizations SCP exemption; identity,
resource, boundary and session restrictions still apply.

The built-in providers install sourced commercial templates for Auto Scaling, ECS,
Elastic Load Balancing, RDS, Organizations, IAM Role Manager and KMS multi-Region keys. Templates specify role names, default descriptions where captured,
trust policies, immutable AWS-managed policy attachments and custom-suffix rules.
Unknown services and uncaptured partitions return `NotImplemented`. The SDK and
permission dataset do not supply this template catalogue. Completing all templates
remains an explicit code gap and part of the active IAM completion target.

Service consumers register their usage checks before worker startup. The checker
passes a callback context and holds dependent resources stable through the final IAM transaction so a new
dependency cannot race with deletion. Currently absent consumers are represented
explicitly; adding one requires binding its actual usage boundary. The Organizations
provider opens the shared IAM transaction and reads membership through its borrowed
context. Its deletion callback joins that context; a concurrent native Organizations
write must wait until the final IAM decision commits. External providers retain
their own usage lock and pass the caller context. Deletion also
checks active role sessions. Credential issuance verifies the current role ID
inside that same repository domain, preventing publication from a stale snapshot.

Deletion requests persist an immutable role ID and resource ARN. The worker
advances pending jobs through `NOT_STARTED`, `IN_PROGRESS` and terminal
`SUCCEEDED` or `FAILED` states. It recovers pending jobs from the repository,
including after cancellation. Duplicate pending requests return the existing job;
failed jobs remain readable and permit a new request. Status reads never advance
work. A role replacement with the same name cannot be removed by an old job.
Role removal and terminal success commit atomically. Stack shutdown cancels and
waits for the worker. Current storage remains in memory; crash durability requires
the pending SQLC backend.

AWS probes confirm that trust, permission, duration and instance-profile membership
changes are protected, while tags and descriptions can change. They also establish
the role response fields, suffix restrictions, duplicate deletion behavior and
missing-job errors. Fixtures and reproduction scripts are under
`internal/services/iam/testdata/service_linked*` and `role_wire*`. All owned probe
roles and profiles from those fixtures were deleted. The later Role Manager probe
has unresolved AWS deletion failures; see [account-property evidence](iam-account-properties.md).
The KMS probe also retains its service role while regional key deletion windows
run; see [KMS role provisioning, usage checks and evidence](kms-multi-region.md).
Tests cover API replay, resource authorization,
recovery, cancellation, active sessions, replacement identities and rollback.

Sources are attached to each template definition; the
[Organizations SCP documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
defines the service-linked role exemption.

## Organizations role

`organization_roles.go` registers the Organizations template with its actual
membership checker. Organization creation and member-account provisioning install
`AWSServiceRoleForOrganizations` through the shared account/role transaction.
Explicit IAM creation uses the same role builder. Registration owns template
validation; creation applies the captured default description unless the caller
supplies its own. Existing service-owned roles retain identity and description
during organization provisioning. Ordinary same-named roles are never adopted.

All-features membership prevents deletion. Consolidated-billing membership does
not require the role, and leaving/deleting the organization releases the dependency.
The documented behavior comes from
[Organizations service-linked roles](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html#orgs_integrate_services-using_slrs).
Management-account creation checks the missing role's IAM permission and returns
the [CreateOrganization dependency error](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateOrganization.html)
when it is denied. These transitions are covered through SDK requests, including
rollback in both stores, caller service-name conditions, protected mutations,
restoration, current membership and reuse of an existing role.

`scripts/aws/organizations_roles_probe.py` reads the access role and both existing
management/member service roles. `testdata/aws/iam/organizations_roles.json`
captures trust, path, names, default descriptions, attachments and session limits;
the SDK tests replay these fields. It replaces the earlier access-role-only capture.
No resources or policies were changed. Existing-role reads do not establish
fresh organization creation, billing-mode provisioning or exact deletion diagnostics.
Those conformance checks remain marked in the Organizations usage adapter. The
current blocked-deletion response identifies the actual organization dependency
in `RoleUsageList`; its exact correspondence to AWS's diagnostic shape remains open.
