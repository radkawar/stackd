# Terraform identity lifecycle

## Purpose

This fixture uses **Terraform 1.15.9** and **AWS provider 6.68.0**. It uses the
published provider and the checked-in checksum lock. It does not use a provider
fork, a development override, an older provider, or native AWS credentials.

The fixture contains 38 resource instances from 34 resource types. It covers
IAM, KMS, Secrets Manager, Identity Store, and Account Management. It does not
establish full support for these services or for all provider resource types.

The runner records completed stages in its private `lifecycle.json`; only a
complete successful run establishes this fixture's lifecycle result. See the
[provider inventory](../../docs/terraform-provider-apis.json) for broader scope.

## Prerequisites

Complete the shared [Python environment and build setup](../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Install Terraform **exactly 1.15.9** on `PATH`;
`main.tf` and the runner both enforce it. AWS provider **6.68.0** is pinned with
a checked-in checksum lock. Shared Python requirements suffice; no Docker or
other runtime is needed.

## Run

Run these commands from the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform-identity/run.py --port 14701
```

To use an unpacked provider mirror with no direct download fallback:

```sh
"$EXAMPLE_PYTHON" examples/terraform-identity/run.py --port 14701 \
  --provider-mirror /absolute/path/to/provider-mirror
```

The mirror must contain the official provider 6.68.0 package in this layout:

```text
registry.terraform.io/hashicorp/aws/6.68.0/linux_amd64/
  terraform-provider-aws_v6.68.0_x5
```


Do not run `main.tf` against an existing account or endpoint. The runner is the
safety boundary. It clears inherited AWS/Terraform environment overrides and
proxy settings. It creates its own fresh SQLite database and loopback process.
It refuses an occupied port. Every service endpoint is explicit. Account-ID
discovery stays enabled through local STS because provider key-policy deletion
constructs the default root policy from the discovered account ID.

The run directory is private, with mode `0700` and a `0077` file-creation mask.
It contains secret values, access keys, Terraform state, plans, backups, and
controller logs. These are local fixture secrets, not production secrets. Do
not commit or publish that directory. The controller stops after the run. The
runner retains only its owned directory so that a failure can be inspected.

`--stackd /absolute/path/to/stackd` selects a prepared binary;
`--work-parent /existing/directory` selects the parent of the new unique run
directory. `--port` selects an unused unprivileged controller port. Omitting
`--provider-mirror` permits the normal registry installation; an explicit mirror
has no direct-download fallback.

## Expected results

A successful run prints completed stages and finishes the lifecycle after
create, native consumers, imports, update, two database reopens and destroy.
`lifecycle.json`, `outputs.json`, saved plans, state and `stackd.sqlite` stay in
the printed directory. `stackd.log` is the active controller log.

## Lifecycle and real consumers

The runner performs these steps:

1. Seed a local primary-contact before-image. Create an owned Identity Center
   instance with the signed `sso-admin` API. Read its real `IdentityStoreId`.
   A generated-looking directory ID is not a valid prerequisite.
2. Apply the configuration. Read actual secret bytes with an IAM user. Decrypt
   provider-produced ciphertext with the ordinary user and a separate,
   constrained KMS-grant principal. Test wrong context and changed ciphertext.
3. Reject the wrong secret principal, untrusted role caller, disabled access
   key, directory reader, and account-contact reader. Disable the actual KMS key
   and check that stored-secret decryption fails. Add a current IAM Deny and
   check that an existing resource grant cannot bypass it. Restore each change.
4. Assume the IAM role through STS and use the returned session credentials.
   Remove its managed-policy attachment. Check that an already-issued session
   loses KMS decrypt authority, then restore the attachment.
5. Require an empty normal plan and apply the saved no-change plan. Import each
   recoverable resource into its existing declaration. Reconcile provider-local
   settings such as deletion windows once. Require another empty plan.
6. Apply `v2`. Update managed/inline policy documents, role description and
   session duration, user/profile/key tags, group path and both membership
   forms, key description and rotation period, alias target, constrained grant,
   ciphertext, secret bytes/stages/policy/tag, directory contacts, and account
   contacts. Read the current values and the old encrypted secret version.
7. Stop the controller. Open the same SQLite database in a new controller
   process. Read the updated directory address and phone number, current secret
   bytes, old version, grant, and bindings. Refresh and require an empty plan.
8. Remove directory addresses and phone numbers through Terraform. Require an
   empty plan. Stop and reopen the controller again. Check that removed contacts
   do not return. Refresh and require an empty plan.
9. Destroy. Check resource absence with signed APIs, reject the removed access
   key, and check that both KMS keys are `PendingDeletion` and cannot decrypt.
   Check an empty Terraform resource state. Restore the primary-contact
   before-image. Delete the Identity Center instance and its directory.

Scope checks use a wrong region, a nonexistent directory, and foreign-account
resource ARNs. These checks do not prove an authorized cross-account sharing
workflow. IAM resources are account-global; regional directory, secret, and key
resources must not leak into another region.

KMS key deletion is scheduled for seven days, as AWS requires. Terraform destroy
is not immediate physical key deletion. Ciphertext has no server-side resource
of its own. The local KMS owner performs actual symmetric authenticated
cryptography; the fixture does not establish AWS ciphertext interchange,
cryptographic certification, hardware security, or asymmetric-key support.
Rotation settings are read back; no time-based material rotation is claimed.
The instance profile is checked through IAM, not through a real EC2 workload.

Primary contacts have no Delete API, and the provider removes only their state
on destroy. The runner therefore restores its seeded before-image, even on
failure. Alternate contacts have a real Delete API. No native account contact,
account IAM setting, or shared sandbox is changed.

## Cleanup

The runner destroys owned resources and restores the primary-contact before-image,
then removes its Identity Center prerequisite. The owned controller stops on
exit. KMS deletion is scheduled, not immediate. A failed cleanup is not a
successful lifecycle: keep the printed private workspace for diagnosis.
After all owned processes stop and evidence is no longer needed, remove only
that exact printed directory. Do not use an existing account or shared state.

## Limitations

The specific import, cryptographic and account cleanup boundaries above apply;
the detailed resource table below is scope, not a full service-support claim.

### Import limits

The ordinary CLI import loop covers 34 instances. It does not import:

- The two `aws_iam_access_key` instances. IAM cannot return a created secret
  access key again. Import cannot reconstruct these consumer credentials.
- `aws_iam_group_membership`. Provider 6.68.0 has no importer for this resource.
- `aws_kms_ciphertext`. It is a provider-generated value with no remote identity
  and no importer. Its bytes are tested through actual decrypt calls.

The user-scoped membership importer is tested while its group list is nonempty.
The six exclusive policy resources do not delete the policies or attachments
on destroy. Their ordinary companion resources perform that cleanup.

## Resource-level scope

All names below refer to provider 6.68.0. The first table lists declarations in
this fixture. Lifecycle evidence remains unverified until a complete run passes.

| Owner | Resource types in this fixture |
| --- | --- |
| IAM | `aws_iam_user`, `aws_iam_group`, `aws_iam_role`, `aws_iam_policy`, `aws_iam_instance_profile`, `aws_iam_access_key`, `aws_iam_group_membership`, `aws_iam_user_group_membership` |
| IAM inline policies | `aws_iam_user_policy`, `aws_iam_group_policy`, `aws_iam_role_policy` |
| IAM managed bindings | `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, `aws_iam_role_policy_attachment` |
| IAM exclusive inline ownership | `aws_iam_user_policies_exclusive`, `aws_iam_group_policies_exclusive`, `aws_iam_role_policies_exclusive` |
| IAM exclusive managed ownership | `aws_iam_user_policy_attachments_exclusive`, `aws_iam_group_policy_attachments_exclusive`, `aws_iam_role_policy_attachments_exclusive` |
| KMS | `aws_kms_key`, `aws_kms_alias`, `aws_kms_key_policy`, `aws_kms_grant`, `aws_kms_ciphertext` |
| Secrets Manager | `aws_secretsmanager_secret`, `aws_secretsmanager_secret_version`, `aws_secretsmanager_secret_policy`, `aws_secretsmanager_tag` |
| Identity Store | `aws_identitystore_user`, `aws_identitystore_group`, `aws_identitystore_group_membership` |
| Account | `aws_account_primary_contact`, `aws_account_alternate_contact` |

The next table accounts for the other 21 managed resource types in these five
provider packages. **Not in this fixture** means unverified, not unsupported.
The current typed owners implement many of their API prerequisites. Each type
still needs its own create/read/update/refresh/import/destroy path and real
consumer checks before a Terraform support claim is valid.

| Remaining types | Required continuation or known boundary |
| --- | --- |
| `aws_iam_account_alias`, `aws_iam_account_password_policy`, `aws_iam_security_token_service_preferences` | Run account-global settings in an owned sandbox. Capture and restore their real before-images. Password and regional-STS behavior need consumer checks. |
| `aws_iam_openid_connect_provider`, `aws_iam_saml_provider`, `aws_iam_outbound_web_identity_federation` | Add real issuer/metadata and signed token consumers. Do not replace trust or token validation with retained provider state. |
| `aws_iam_organizations_features` | Add the real Organizations prerequisite and member/root-access authority checks. |
| `aws_iam_policy_attachment` | Use separate policies and principals. Its account-wide exclusive attachment ownership must not conflict with the per-entity resources. The provider has no importer. |
| `aws_iam_server_certificate`, `aws_iam_signing_certificate` | Add actual certificate material and TLS/signature consumers. Private-key import recovery is limited. |
| `aws_iam_service_linked_role` | Run each service-owned template with its real usage/deletion fence. This change also adds the sourced MSK template, but this fixture does not run MSK. |
| `aws_iam_service_specific_credential`, `aws_iam_user_login_profile`, `aws_iam_user_ssh_key`, `aws_iam_virtual_mfa_device` | Add real service login, password, SSH, or TOTP consumers. Read/list metadata alone is not credential support. |
| `aws_kms_external_key`, `aws_kms_replica_external_key`, `aws_kms_replica_key` | Exercise real imported material, its expiry, second-region replicas, current grants, and actual cryptographic consumers. These are existing owner paths, not claims of absent implementations. |
| `aws_kms_custom_key_store` | The four provider lifecycle APIs are unimplemented in the static inventory. Hardware/custom-store execution remains outside this fixture. |
| `aws_secretsmanager_secret_rotation` | Add a real rotation Lambda and its create/set/test/finish steps. This API-only fixture has no Lambda runtime. |
| `aws_account_region` | Exercise opt-in region admission, transition waiters, and safe restore in an owned account. |

Important settings not covered here include IAM permissions boundaries,
credential secret recovery, federation variants, certificate rotation,
service-specific role templates, grant retirement/propagation and SourceArn
constraints, KMS asymmetric/HMAC/agreement and external-key material,
Secrets Manager replicas, binary/write-only values, rotation schedules, and
cross-account policy grants. Directory addresses and phone numbers now use typed
child rows. Photos, roles, enterprise extensions, SCIM ExternalId lookup,
legacy directory aliases/sharing, and newer response fields such as computed
`user_status` remain outside this path. The pinned stackd model is not the full
current AWS API model.

## Diagnosed owner gaps and evidence

Historical diagnosis found unsupported Identity Store contact lists and empty-map
KMS grant constraint handling. The fixture now exercises those boundaries through
create/update/removal, signed consumers and SQLite reopen. The runner's own
completed-stage record is authoritative for a new run; earlier partial applies
are not a passing lifecycle. No private work-directory path is a prerequisite.

### AWS and provider contracts

- [Identity Store CreateUser](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_CreateUser.html): one address and one phone item when supplied.
- [Identity Store UpdateUser](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_UpdateUser.html): whole-attribute updates and removal.
- [KMS grant constraints](https://docs.aws.amazon.com/kms/latest/APIReference/API_GrantConstraints.html): actual context-bound cryptographic operations.
- [Provider grant expansion](https://github.com/hashicorp/terraform-provider-aws/blob/c9b83d813022cdd05fc955480b07e269c6e18023/internal/service/kms/grant.go#L369-L411): empty map serialization.
- [Provider user updates](https://github.com/hashicorp/terraform-provider-aws/blob/c9b83d813022cdd05fc955480b07e269c6e18023/internal/service/identitystore/user.go#L378-L613): whole contact lists and null removal.
- [Provider primary contact](https://github.com/hashicorp/terraform-provider-aws/blob/c9b83d813022cdd05fc955480b07e269c6e18023/internal/service/account/primary_contact.go#L28-L38): destroy removes only Terraform state.
- [MSK service-linked role](https://docs.aws.amazon.com/msk/latest/developerguide/slr-permissions.html) and [KafkaServiceRolePolicy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/KafkaServiceRolePolicy.html): exact service trust and managed permissions.
