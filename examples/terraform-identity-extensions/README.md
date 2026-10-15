# Terraform identity extensions

This fixture covers the 20 remaining **already-built managed resource types** in
the IAM, KMS, Secrets Manager and Account owners. Use it with
[`terraform-identity`](../terraform-identity/README.md), which covers 34 other
types, including all three Identity Store resources. Of the 55 managed types in
these five provider packages, `aws_kms_custom_key_store` remains absent. The two
fixtures do not establish full AWS service or setting parity.

**Status: declared local lifecycle verified on 2026-10-15 for all 20 targeted
built resource types.** `coverage.json` records the exact evidence and remaining
branches; it does not claim their unimplemented authentication protocols or full
service parity. The runner sets `verified` only after both strict plan kinds
return zero and all owned processes close. This is not an AWS behavior capture.

The source fix in this extension closes an OIDC TLS hostname-check gap for IP
issuers/JWKS. Go omits TLS SNI for an IP address; a configured thumbprint must not
therefore accept a pinned DNS-only certificate at that address. Discovery now
checks the explicit endpoint hostname, including its IP SAN. A regression test
covers the rejection. Parent-owned CLI wiring enables this genuine discovery only
when `-oidc-discovery` is given.

## Executed local evidence (2026-10-15)

The complete runner exited zero using official Terraform **1.16.6** and AWS
provider **6.68.0**, the canonical
`.stackd/storage420-native-cli-20261014` controller
(SHA-256 `22b61a3ae6ff9d6e1c6f0192b8d14f5a22c534ef3c16ea987dace64c25951031`),
the installed real native ALB relay/desync classifier and Lambda telemetry helper,
and the pinned official Python Lambda image. No native AWS resources were
provisioned, no provider was downgraded, and no service code was changed to accept
an invalid provider request.

Private evidence is retained in
`.stackd/stackd-terraform-identity-extensions-8yt5hvpl`, account `896391435671`,
resource prefix `stackd-identity-ext-4f2b6facd8`:

| Boundary | Exercised result |
| --- | --- |
| Create/update | Every declared signed/native consumer passed at `v1` and `v2`: real OIDC/JWKS and XMLDSig SAML sessions, outbound RS256/ES384 signatures, imported/generated multi-region KMS ciphertext/expiry/reimport/rotation, password/MFA/current-authority fences, real four-callback Lambda password rotation, verified ALB TLS/SNI/DNS, root-task sessions and opt-in Region issuance. |
| Native import | All **59** import operations exited zero. Saved reconciliation excluded every create/delete/replacement. All consumers then ran again, preserving original key/certificate identities and creation-only material. |
| Actual controller reopen | A stopped/new process opened the same SQLite file/account/clock. Old ciphertext, federated sessions, signing authority and changed application passwords were consumed without reseeding. |
| Independent strict plans | Create, update, import and reopen each produced a new refresh-only plan and ordinary configuration plan, **eight exit-zero results**. Separately saved exit-two observations contain only the inspected native consumer effects documented below; none was labeled strict no-change. |
| Destroy/absence | Terraform state became empty. Signed APIs verified absence/revoked credentials, KMS retained genuine seven-day deletion schedules, and native checks found no owned ALB containers, old sockets, DNS records or ENIs and no owned Lambda containers/volumes. Globals/Region were restored; the local member was closed/detached and the organization removed. |
| Process closure | Controller, issuer, password application, clock pump and DNS all closed. Host socket inspection found no listener on TCP 443/14711/14712/14713 or UDP 14713. The private Python bind capability was removed. |

`lifecycle.json`, `imports.json`, numbered Terraform receipts, before/after
controller logs, `keys/evidence.json`, `federation/consumer-checkpoint.json`,
`tls/evidence.json`, `rotation/evidence.json` and
`rotation/native-absence.json` hold the corresponding local evidence. The Python
syntax check passed for all seven fixture modules. No controller rebuild, Go
package tests or formatter was run during this verification.

Earlier failed provider-compatibility runs remain distinct: `q5u6lxy3` retained
the simultaneous certificate rename/tag error; `au3zsoe9` retained the dependent
listener's inconsistent-ARN final plan; and `r8fgrx84` retained the incorrect
import replacements detected by the key-identity fence. These suffixes refer to
private `.stackd/stackd-terraform-identity-extensions-*` directories, not passing
evidence. The last run's exact leftover MFA/global/organization state was cleaned
through signed APIs; its cleanup and original deletion-window receipts are
retained alongside the failure. The final passing run did not replace identities.

## Requirements and exact commands

Run from the repository root. The parent must generate the allocated SQL adapters
and rebuild the controller first. Terraform is pinned to **1.16.6**. AWS provider
is pinned to **6.68.0**, with the official provider checksums in the lock file.
Do not downgrade either version.

```sh
make build
CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node
# After the parent prepares the pinned Rust/cbindgen prerequisites:
make -C compute/elbv2/desync/adapter GUARDIAN="$PWD/clones/http-desync-guardian" PREFIX="$PWD/.stackd/native" install
python3 -m venv /tmp/stackd-identity-extensions-python
/tmp/stackd-identity-extensions-python/bin/pip install -r examples/terraform-identity-extensions/requirements.txt
export PATH="$PWD/.stackd/terraform-1.16.6/bin:$PATH"

docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
docker pull nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61

/tmp/stackd-identity-extensions-python/bin/python examples/terraform-identity-extensions/run.py \
  --stackd bin/stackd --port 14711 --consumer-port 14712 --dns-port 14713 \
  --elbv2-node-executable bin/stackd-elbv2-node \
  --desync-executable .stackd/native/bin/stackd-http-desync-guardian \
  --provider-mirror /tmp/stackd-terraform-eip-59nmy6o_/.terraform/providers
```

The mirror must contain the official AWS 6.68.0 package. When `--provider-mirror`
is given, the runner has no direct-install fallback. Omit it only to allow the
normal official registry installation. The local SDK requirement is newer than
`examples/requirements.txt`: its models must include STS `GetWebIdentityToken`
and the IAM outbound federation operations. Installing the extension's private
requirements does not change the shared examples environment.

The TLS issuer must exclusively bind `127.0.0.1:443`. The host must permit that
bind; an occupied or forbidden port fails. There is no alternate remote issuer,
TLS verification bypass, hosts-file edit or remote fallback. On Linux with
privileged ports, an administrator can grant `cap_net_bind_service=ep` to a
private copy of the virtual environment's Python executable (never its symlink
to the system interpreter); use that private executable for the runner and remove
the capability when finished. This does not require changing global port policy.
The generated issuer CA is trusted through `SSL_CERT_FILE` only while this fixture
runs. The controller uses the explicit `-oidc-discovery` opt-in. It does not enable
network discovery by default.

Docker must reach `host.docker.internal` on the selected controller and application
ports. The shared controller helper binds the controller on `0.0.0.0` for this
purpose. The password application also binds there. Restrict host-network access;
these are local fixture processes, not public services. Full execution also needs
the genuine native ALB bridge/packet-policy host admission, installed static Linux
relay, pinned real desync adapter and BIND `dig`. Follow the
[ALB runtime guide](../../docs/runtime-containers.md#alb-relay) and
[Compute prerequisite record](../terraform-compute/network-alb/procedure.json).
The complete native TLS procedure targets a local Linux Docker/native-network
host. `--desktop` selects Lambda callback routing only; it does not create ALB
routing on a Desktop host. ARM64 requires matching installed relay/runtime
binaries and the exact ARM64 Lambda image in [the Lambda guide](../../docs/lambda.md).
`--docker-host` selects an existing daemon. The runner starts no daemon, pulls no
image, builds no helper and installs no classifier.

All processes, accounts, resources and databases belong to this run. A fresh
random 12-digit account and unique resource-name prefix are retained across the
same run's reopen. There is no option to adopt an existing endpoint, account or
state file. Inherited AWS credentials, endpoint overrides, proxies and Terraform
arguments are removed by `examples/local.py`. The run directory is private, with
private state, passwords, imported master bytes, signing keys, authenticators,
plans and receipts. Keep it private or remove it after inspection. Do not commit
those artifacts.

## Completed-stage procedure

The runner performs this procedure, in order:

1. Create a new SQLite controller and owned Organizations ALL-features/member
   prerequisites. Enable IAM trusted access. Capture global setting before-images.
2. Apply revision `v1` to create the real native ALB/DNS prerequisites. Issue an
   actual certificate with that exact hostname in SAN, then apply its IAM owner
   and HTTPS listener. Run signed consumers, actual verified TLS and negative
   authority checks. Inspect and separately baseline only the computed native
   consumer readback described below, then save new independent refresh-only and
   configuration plans and require detailed exit code zero for both.
3. Save and inspect a revision-`v2` rename/path plan targeting exactly the two
   owned IAM certificate resources, with their tags retained at `v1`. Apply that
   plan, then perform the full ordinary `v2` apply with certificate tags at `v2`
   and the listener referring to the retained actual renamed ARN. Check all real
   updates/current authority, inspect native consumer readback and require both
   new strict plans to be empty.
4. Remove each recoverable resource from Terraform state and use its native
   importer. Inspect a saved reconciliation plan and forbid every resource
   create/delete/replacement before applying it. Re-run all signed/native
   consumers, inspect their computed readback and require both strict plans to be
   empty. Create-only material updates finish before import.
5. Stop the actual controller. Start a new controller against the same SQLite
   file, endpoint and saved manual clock. Consume retained ciphertext, old/live
   sessions, signing authority and the application's changed password. Require
   both strict plans to be empty; no state reseed or metadata reconstruction occurs.
6. Terraform-destroy the owned auxiliary ALB first, wait for actual native
   processes and managed ENIs to retire, then let its real one-hour service
   sessions expire on the explicit clock. IAM's deletion fences are not bypassed.
   Destroy the remaining resources; the provider performs real MFA deactivation
   and device deletion before its explicitly dependent user is removed.
   Check actual socket/DNS/container/volume absence, signed API absence,
   removed-key rejection and empty Terraform state.
   Restore captured account-global settings and opt-in Region state. Close the
   solely owned local member, remove its membership, then delete the organization.
7. Stop and join the controller, TLS issuer, password application and clock pump.

The provider waiters observe real owner transitions. A bounded clock pump advances
manual service time while Terraform applies, imports or destroys. Consumer checks
also use that clock for TOTP, expiry, rotation and outbound propagation. This is
not a promise about AWS completion times.

The real MFA enrollment is a native IAM subresource operation not represented by
`aws_iam_virtual_mfa_device`; it changes computed `user_name` and `enable_date`.
The current-provider SAML negative test replaces and restores metadata, updating
computed `valid_until`. The genuine second `finishSecret` callback also removes
`AWSPREVIOUS` from the original seed version; its `version_stages` is deliberately
unconfigured in Terraform. Before the strict gates, the runner saves a separate
refresh-only **observation**, inspects its JSON and allows only those exact
address/field pairs after comparing them with current signed responses. Seed
label retirement must be exactly `["AWSPREVIOUS"]` to `[]`, match the original
version ID in signed `GetSecretValue`/`DescribeSecret`, remain unconfigured, and
link to all four real callback receipts and the promoted version's `AWSCURRENT`.
Any unrelated drift, managed action, output change or deferred plan fails.
An independent ordinary observation must also be empty. Only then may that
specific saved readback plan be applied. Original exit-two receipts remain
distinct and are never labeled strict no-change; both **new** strict plans must
return zero. There is no blanket refresh-only apply.

AWS provider 6.68.0's SDKv2 tag interceptor runs before its certificate rename
handler and targets the planned new name. A simultaneous name/tag update fails
`NoSuchEntity` against native IAM semantics. The same provider leaves the old
certificate ARN known in a dependent listener's plan, then rejects the actual
renamed ARN as an inconsistent final plan. The fixture inspects and applies a
plan containing only the two real certificate rename/path updates before the
full ordinary tag/listener update. Both changes genuinely occur; there are no
listener ignores, fictional ARNs, altered IAM lookups or accepted tags on missing
names. The owned OIDC JWKS omits `key_ops`, which retained native AWS captures
reject even when set to `["verify"]`; TLS and token-signature verification remain
mandatory.


Private `lifecycle.json` records completed stages and every strict plan exit code.
`imports.json` lists actual address/ID pairs attempted. Each Terraform command has
private numbered stdout/stderr/argument/exit-code receipts. Controller logs before
and after reopen, module checkpoints and real Lambda logs remain for diagnosis.
Exit code two is never accepted as a no-change result: independent consumers,
reopen and teardown may finish, but the runner fails and leaves `verified=false`.
No committed file is a native success capture.

## Resource and consumer coverage

| Resource types | Lifecycle and actual consumer boundary |
| --- | --- |
| `aws_iam_account_alias`, `aws_iam_account_password_policy`, `aws_iam_security_token_service_preferences` | Create/read/update and account-global before-image restoration. Signed `ChangePassword` verifies the current password hash and policy; wrong old passwords, inadequate passwords and history reuse fail. Regional STS tokens are issued and consumed. Global-host legacy compatibility is not claimed. |
| `aws_iam_policy_attachment` | Exclusive user/group/role binding transitions. Signed SSM reads and assumed-role sessions receive actual parameter bytes. Current detach and deny stop existing consumers. |
| `aws_iam_user_login_profile` | Real password creation and signed change/password-policy checks. This is not a console-session test. |
| `aws_iam_virtual_mfa_device` | Genuine service-generated seed, RFC6238 codes, enrollment, STS session issuance and MFA-conditioned SSM reads. Wrong user/code, replay, deactivation and current IAM deny fail. The seed remains private. |
| `aws_iam_server_certificate`, `aws_iam_signing_certificate`, `aws_iam_user_ssh_key` | Real RSA/PEM/OpenSSH material, public-key correspondence, fingerprints and signatures with tamper rejection. An additional genuine IAM server certificate deploys to owned native ELBV2 HTTPS sockets. The normal client resolves authoritative DNS, verifies the real hostname/SNI and certificate bytes, then consumes current HTTP bytes. Rename/path/import/reopen preserve immutable certificate identity; in-use deletion fails, wrong hostname/trust fail, and real sockets/containers/ENIs are removed. No SSH or legacy certificate-authenticated AWS request is claimed. |
| `aws_iam_service_specific_credential` | Genuine credential creation/status update, native metadata import and deletion. No CodeCommit Git, Keyspaces or Bedrock API-key protocol consumer is claimed. |
| `aws_iam_openid_connect_provider` | Owned CA-verified TLS issuer/JWKS and RSA-signed tokens. `AssumeRoleWithWebIdentity` returns real credentials that consume current SSM bytes. Wrong signature, retired audience, current provider, trust and permission failures are checked. |
| `aws_iam_saml_provider` | Real RSA-SHA256 XMLDSig assertions and provider signing-certificate updates. `AssumeRoleWithSAML` returns actual consuming credentials. Wrong/retired signing authorities fail. |
| `aws_iam_outbound_web_identity_federation` | Actual RS256/ES384 tokens, independent signature and caller-context verification, corrupted-signature rejection, current vending authorization and disable behavior. Reopen preserves the issuer and public signing keys. |
| `aws_iam_organizations_features` | Real prerequisite ownership and feature transitions. An authorized IAM user obtains an STS member-root task session, reads the member's provisioned role count and cannot create a user. Current feature disable and IAM deny stop fresh issuance. Native root/test credentials cannot bypass the caller-kind rule. |
| `aws_iam_service_linked_role` | Sourced ELB trust and exact managed policy; description/tag updates, native import, protected-policy mutation and wrong-human-assumption rejection. The genuine ALB/EC2 network consumer uses this role; deleting it while that resource exists fails with the actual resource ARN in `RoleUsageList`. After native retirement and genuine service-session expiry, Terraform completes asynchronous role deletion. Further templates/consumers remain separate. |
| `aws_kms_external_key`, `aws_kms_replica_external_key`, `aws_kms_replica_key` | Actual random AES-256 import/wrapping, external/generated multi-region primaries and west replicas. Signed bidirectional encryption/decryption, alias lookup, wrong key/region/context/tamper and current regional/IAM/credential restrictions. Real expiry, wrong-material reimport failure, correct reimport recovery, independent regional deletion and imported/generated on-demand rotations. Historical ciphertext is consumed after import and controller reopen. Independent AES-GCM byte checks are explicitly for stackd's local ciphertext format, not AWS ciphertext-wire parity. |
| `aws_secretsmanager_secret_rotation` | All four callbacks execute in the official Python Lambda RIC under a scoped execution role. `createSecret` stores actual encrypted pending bytes; `setSecret` atomically changes a retained application's password; `testSecret` authenticates to that application; `finishSecret` promotes the genuine version. Old passwords fail. Actual Lambda logs record all four steps. Warm consumers fail under current IAM deny and disabled KMS key, then recover when authority is restored. |
| `aws_account_region` | Real local account opt-in enable/disable transitions and before-image restoration. Regional STS credential issuance is allowed only when the owner enables that Region. This does not claim console-managed regional STS activation or every AWS error-propagation edge. |

The password application is an independent local consumer, not an AWS service
emulator or secret-version metadata substitute. It retains a salted password hash
in its own private SQLite database. Requests authenticate with the current real
password before a transactional update. The Lambda role uses only scoped Secrets
Manager, KMS and log permissions; it receives no root credential or fake execution
receipt. The application closes with this run; deleting a secret does not falsely
reset an unrelated application's credential.

## Import and deletion limits

- Provider 6.68.0 has no importer for `aws_iam_policy_attachment`,
  `aws_iam_security_token_service_preferences`, or prerequisite
  `aws_iam_group_membership`. These stay in their original Terraform state.
- Access-key secrets, service-specific passwords, login passwords, virtual-MFA
  seeds and server private keys cannot be read back from AWS. Metadata imports
  use the original private creation material for consumers, not a fabricated
  response. Some access keys are deliberately not imported. The server certificate
  ignores its unreadable private-key argument after native import.
- KMS never exports imported master bytes. External-key resources ignore the
  create-only `key_material_base64` field to prevent false replacement after
  import. Update `valid_to` before import: this provider cannot later reimport
  material from a fresh state that has lost that secret. The fixture's retained
  raw material is used for independent cryptographic proof, not as a fake Get API.
- The external-key provider's read handler omits `key_spec`; the login-profile
  read handler omits `password_reset_required`. Explicitly configuring even their
  native defaults forces replacement after import. The fixture leaves those two
  redundant defaults unconfigured and independently asserts signed
  `KeySpec=SYMMETRIC_DEFAULT`/`KeyUsage=ENCRYPT_DECRYPT` and
  `PasswordResetRequired=false` after create, import and reopen. It never modifies
  imported state or ignores these native fields.
- The MFA provider retains computed `user_name` after out-of-band deactivation,
  then returns early on a repeated deactivation's `NoSuchEntity` without deleting
  the device. The runner does not pre-deactivate it; Terraform owns the actual
  deactivation/deletion, with an explicit dependency on the enrolled user.
- Account Region and STS-preference provider deletion are no-ops. The runner
  explicitly restores captured values rather than treating state removal as
  service cleanup.
- KMS destruction schedules genuine seven-day deletion. Replicas/single keys enter
  `PendingDeletion`; primaries with retained replicas can enter
  `PendingReplicaDeletion`. No physical erasure claim is made before the windows
  expire. Removed aliases and unavailable cryptographic use are checked.
- Outbound federation disable stops vending after the modeled delay but intentionally
  retains discovery/JWKS for already-issued tokens. Deletion does not erase keys.
- AWS has no account-deletion API. The owned local member is closed and detached;
  retained account/provisioning records are not falsely reported as erased.

## Explicit remaining gaps

`coverage.json` names every one of the 21 originally remaining managed types.
Twenty have this permanent procedure; `aws_kms_custom_key_store` has no owner for
Create/Describe/Update/DeleteCustomKeyStore and no CloudHSM/external-store consumer.
It remains an implementation gap, not an unverified existing path.

The following built-resource branches remain outside this procedure: console and
Git/service-specific/SSH/legacy-certificate authentication wire runtimes; global
STS token compatibility/activation; root/hardware/FIDO MFA; further service-linked
role templates and their service-usage fences; OIDC
algorithms beyond RS256, built-in/social or external issuers; encrypted SAML,
decryption keys and the full session-tag/lifetime/error matrix; outbound key
rotation/retention parity; non-commercial/further Regions, key promotion,
asymmetric/HMAC/recipient-attestation KMS operations; secret external-partner
rotation, secret replica branches and write-only/binary variants. Identity Store
photos/roles/extensions and all SCIM/ExternalID branches are not added here.

Official contracts and existing owner sources:

- [IAM OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
  and [SAML assertions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html).
- [STS outbound tokens](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html)
  and [AssumeRoot](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html).
- [KMS import](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html)
  and [multi-region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html).
- [Secrets Manager rotation function](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html).
- Existing [OIDC](../../docs/oidc-federation.md), [SAML](../../docs/saml-federation.md),
  [KMS import](../../docs/kms-imports.md), [multi-region](../../docs/kms-multi-region.md),
  [IAM certificates](../../docs/iam-certificates.md), [IAM service credentials](../../docs/iam-service-credentials.md),
  [STS preferences](../../docs/iam-sts-preferences.md), and [Account Regions](../../docs/account-regions.md) contracts.

Main-agent checks after integration: the scoped OIDC discovery regression tests,
repository build/syntax checks, both pinned identity runners and their complete
consumer/import/reopen/teardown stages. Only exercised stages may be marked verified.
