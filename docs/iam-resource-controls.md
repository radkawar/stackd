# Resource control policies

Organizations resource control policies (RCPs) now participate in the shared
authorization evaluator. The applicable hierarchy belongs to the resource owner:
root, ancestor OUs and member account. A denial restricts member roots, ordinary
users and roles, and callers outside the organization, including its management
account. Resources owned by the management account are exempt. RCPs never grant
permissions; identity, resource, boundary, session and SCP decisions still apply.

Organizations keeps RCPs and their attachments in its existing typed repository.
Enabling RCPs attaches AWS's `RCPFullAWSAccess` policy throughout the hierarchy;
that policy cannot be detached. Customer policies contain only denials. Moving
an account, updating or detaching a policy, and disabling the policy type change
the next authorization decision. Current owner ancestry supplies
`aws:ResourceOrgID` and `aws:ResourceOrgPaths` even when RCPs are disabled.
The caller's ancestry separately supplies the principal organization keys.
Services cannot override verified organization or AWS-service identity context.

All implemented owners whose AWS action namespace is RCP-supported use this same
evaluator: S3, Secrets Manager, SQS, KMS, STS, Logs, DynamoDB, ECR, Cognito user
pools, EC2 Auto Scaling, CodeBuild, EventBridge, Firehose, MemoryDB and X-Ray.
There is no service-local RCP engine. S3 supplies bucket/access-point ownership
for accountless ARNs; Secrets Manager resolves names and partial/full ARNs to the
actual secret owner. Copies, batch items and service dependencies retain their
existing independent resource authorization.

Signed STS role assumption checks the destination's RCPs alongside its trust
policy. OIDC and SAML validate the token and provider, then intersect trust with
RCPs for assumption and required session actions such as `sts:TagSession`. Generic
service-role issuance checks both actions when session tags are supplied, passes
the request-tag and transitive-tag conditions to the same evaluator, and fences
an explicitly bound immutable role identity against deletion/recreation. A denial
publishes no credentials. The existing IAM authority transaction keeps
Organizations reads stable through credential publication in the shared memory
or SQLite transaction domain.

AWS exempts service-linked role principals, assumption of service-linked roles,
AWS-managed KMS keys and `kms:RetireGrant`. IAM role records and KMS key records
own the resource exemptions. An ordinary role with a service-looking path is
not a service-linked role. Exemptions do not bypass identity or resource denials.

## Generated applicability

`make generate-iam` combines
[`resource_control_source.json`](../internal/iam/catalog/data/resource_control_source.json)
with the existing pinned AWS service-authorization reference. The 2026-09-27
primary capture contains **62 service prefixes**, up from the earlier 45, and the
`kms:RetireGrant` exception. The public authorization-reference snapshot was
refreshed on the same date; its action `Resources` fields determine eligibility.
Only actions with a resource type participate in RCP evaluation, not a blind
`service:*` expansion. An unknown action can be accepted in a customer policy
without becoming an implemented or resource-authorizing API.

The guide lists `opensearch`, not `es`. The implemented OpenSearch domain/data
APIs use `es`; ordinary IAM action aliases do not invent Organizations coverage.
Seven published namespaces currently have no resource-typed actions in the
reference (`autoscaling-plans`, `comprehendmedical`, `compute-optimizer`,
`cost-optimization-hub`, `inspector-scan`, `pricing`, `support`). Their acceptance
in RCP policy syntax does not make their unscoped actions resource-authorizing.
The versioned source and generated output need no clone or network at runtime.
Refreshing the existing service reference and running `make generate-iam` keeps
one authoritative action/resource catalog, rather than a second RCP action list.
This describes AWS policy applicability, not stackd service implementation;
unimplemented APIs retain their ordinary unsupported errors.

## AWS observations and local verification

[`resource_controls.json`](../testdata/aws/iam/resource_controls.json) records
2026-09-12 AWS CLI requests against owned resources in an existing organization
member. Account IDs and resource names are normalized; temporary credentials,
plaintext and ciphertext are omitted. The probe is
[`organizations_rcp_probe.py`](../scripts/aws/organizations_rcp_probe.py).

| Captured case | AWS result |
| --- | --- |
| Create an unattached RCP while its policy type is disabled | Accepted; attachment still requires enablement |
| Customer `Allow`, unqualified `Action: "*"`, unsupported service prefix | `MalformedPolicyDocumentException` |
| Unknown action within SQS; uppercase `SQS` prefix | Accepted |
| `Principal: "*"` or `{"AWS":"*"}` | Accepted |
| Principal array or specific AWS account principal | Rejected |
| `NotAction` or `NotPrincipal` | Rejected |
| `NotResource`, missing Version, or Version `2008-10-17` | Accepted |
| Member and management callers send to the restricted member queue | `AccessDenied` |
| Member caller sends to the management-owned queue | Allowed |
| Restricted member lists queues; encrypts with its customer KMS key | `AccessDenied`; `AccessDeniedException` |
| Management caller assumes the restricted member role | `AccessDenied` |
| Retire a grant with a bare key ID | `NotFoundException`, `Invalid arn` |
| Retire the grant with its key ARN despite an RCP denial | Allowed; grant removed |
| Detach the RCP and retry queue delivery | Allowed after propagation |

The SDK integration suite replays the captured syntax and SQS/KMS/STS decisions,
with one explicitly named source-version discrepancy: the 2026-09-12 native
`restricted_list` observation denied `sqs:ListQueues`, while the current
[RCP resource-type rule](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-effects-on-permissions)
and [SQS action table](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sqs.html)
exclude that unscoped action. The historical capture remains unchanged; current
replay follows the newer primary contract and checks that queue discovery still
returns the retained member queue. This is not a new live AWS observation.

[`resource_control_current.json`](../testdata/aws/iam/resource_control_current.json)
records primary-backed resource and unscoped action cases across every published
namespace, the KMS retirement exception and the OpenSearch prefix distinction.
The shared evaluator replay applies owner-organization conditions rather than
just comparing generated strings. Its organization-mutation sequence drives
actual cross-account S3 object and customer-KMS-encrypted Secrets Manager reads
on memory and reopened SQLite: OU/root/account attachment, policy replacement,
account movement, detachment, disablement and management-owner exemption.

The standalone CLI also ran all 11 mutations through signed SDK calls against
SQLite and repeated the retained-data decisions after a process restart.
[`ram_rcp_mutations.json`](../testdata/integration/ram_rcp_mutations.json)
records those 118 local calls; this executable proof is separate from native AWS
evidence and does not establish whole-service parity.

The [merged STS authority proof](../testdata/integration/ram_merge_sts_authority.json)
attaches a member-role RCP denying `sts:TagSession`. Untagged assumption still
succeeds; tagged assumption returns `AccessDenied` before and after a real
SQLite process restart. Both rejected requests appear in CloudTrail history,
without a credentials response. Detaching the policy restores tagged assumption.
This exercises the shared IAM transaction boundary; it does not infer absence of
credential rows from the error response. The owned policy/role were deleted and
the private runtime state disposed, without native AWS calls.

Additional local cases cover direct resource grants, unavailable policy sources,
service-linked role exemptions, SQS use of AWS-managed KMS keys, tagged service
trust, and verified OIDC/SAML denials before credential publication. These cases
follow primary documentation; they are not all independent native captures.

The historical native probe runs deleted their owned queues, IAM roles and
policies and restored RCPs to disabled. Their captured KMS readbacks recorded two
keys `PendingDeletion` with deletion dates on 2026-09-19; these are historical
observations, not a fresh claim about native state. The 2026-09-27 refresh reads
public primary metadata only and makes no AWS Organizations mutations.

RCP propagation currently takes effect on the next local request. Native probes
observed delayed attachment and detachment; their exact timing distribution is
not modeled. Complete action/context and denial-message conformance remains in
the shared authorization audit. Service support remains partial in
[`services.json`](services.json); neither the catalog nor fixture cases establish
whole-service semantic parity.

## References

- AWS [RCP applicability and exceptions](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html),
  [evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_evaluation.html)
  and [syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_syntax.html).
  Live captures above preserve accepted version and principal forms where the
  prose documentation is narrower than observed validation.
- AWS [global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
  define resource ownership and organization paths.
- AWS [session-tag trust permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
  define the separate `sts:TagSession` check and request/transitive-tag conditions.
- AWS [CreatePolicy](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreatePolicy.html)
  and [RetireGrant](https://docs.aws.amazon.com/kms/latest/APIReference/API_RetireGrant.html),
  particularly the latter's KeyId member requiring a key ARN.
- Captured AWS `CreatePolicy` behavior permits creation before type enablement;
  stackd enforces enablement at attachment.
