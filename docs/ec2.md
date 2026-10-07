# EC2, VPC, EBS snapshots and instance execution

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

EC2 currently provides typed VPC, subnet, security-group/rule, route-table,
internet-gateway, IPv4 network-interface, public IPv4/Elastic IP, network-ACL,
DHCP-options, regional-discovery, key-pair, launch-template, instance/image and EBS controls. QEMU/KVM executes
compatible HVM guests against real native volumes; EBS retains immutable snapshot
blocks. These exercised workflows do not establish complete EC2 parity.
Remaining operations are recognized through SDK Smithy-generated EC2 Query
contracts and return explicit protocol errors.
The generated [inventory](services.json) reports registration as partial.

## Key pairs

`CreateKeyPair`, `ImportKeyPair`, `DescribeKeyPairs` and `DeleteKeyPair` execute
real key operations through the generated EC2 Query frontend. Creation generates
2048-bit RSA or Ed25519 keys in PEM/OpenSSH or unencrypted PuTTY v2 PPK format.
The private material is returned once, never stored in the key-pair repository.
Public material, fingerprints, creation times and ordered tags survive SQLite
reopen in service-owned schema 186.

Fingerprints follow [AWS's distinct algorithms](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-keys.html):
created RSA uses SHA-1 over PKCS8 private DER; imported RSA uses MD5 over public
SPKI DER; Ed25519 uses padded base64 SHA-256 over the SSH public blob.
Native captures admit RSA OpenSSH, RFC4716 and ASCII-base64 SPKI DER imports,
and Ed25519 OpenSSH imports. They reject PEM public keys and base64 PKCS1.
The observed import boundary is 2,048 material bytes; accepted public-only RSA
inputs include sizes outside the user guide's listed lengths, so the service
does not invent a stricter modulus-size rule.

Shared IAM and tagging apply to scoped key-pair resources. The
[Service Authorization Reference](https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json)
defines name-based `key-pair/${KeyPairName}` ARNs, not key-pair-ID ARNs.
SDK selection and tag operations still use the actual `key-*` resource IDs.
Native-backed owner validation preserves DryRun precedence over key type/format
admission; those generated enum constraints are explicitly opened through
fixture-backed model corrections rather than disabling frontend validation.

Audit records replace generated private material with `<sensitiveDataRemoved>`.
Successful imports retain their admitted public-material request context.
Unlike native AWS, rejected imports omit the unvalidated blob: accidentally
uploaded private material must not enter retained audit records. Fixture replay
checks that deliberate confidentiality boundary separately from native API errors.

Evidence: `scripts/aws/ec2_key_pairs_probe.py` and
`testdata/aws/ec2/key_pairs{,_supplement,_import_boundaries,_dry_run}.json`.
SDK replay covers both repositories, reopen after mutations, public/private
correspondence, fingerprints, tags, selectors, errors, IAM and scope isolation.
An actual CLI process/restart workflow also generated all four type/format
combinations; OpenSSH and PuTTY recovered matching public keys, and OpenSSH
signed and verified messages with the generated private keys. Native probe keys
were deleted. This does not implement instance SSH admission, key installation
or Windows password retrieval. CloudFormation key creation stores actual
generated private material in an encrypted `/ec2/keypair/<key-pair-id>` Parameter
Store value in the same native transaction; imported keys have no private-key
parameter. Recovery uses the scoped immutable key-pair ID, while the public
CloudFormation identifier and Ref remain the key name.
Creation retries reject supplied physical identities that differ from the
native incarnation's private admission, including attempts to attach an
unadmitted foreign ID. Current native IAM is checked before that fence.
Customer tag changes cannot grant or revoke private admission, which survives
repository reopen.

## EBS direct snapshot data plane

All six EBS direct APIs use Smithy-generated request, response and error
contracts: `StartSnapshot`, `PutSnapshotBlock`, `CompleteSnapshot`,
`ListSnapshotBlocks`, `ListChangedBlocks` and `GetSnapshotBlock`.
The generated `unsignedPayload` trait admits EBS's streaming upload signature;
block SHA-256 validation remains in the snapshot command. The native signing
capture also accepts individually unsigned checksum headers, so the gateway
does not invent an additional signed-header requirement.

`internal/services/ebs` is the single owner of snapshot metadata, sparse
512-KiB blocks, immutable parent references, tags, sharing permissions and regional
encryption/public-access defaults. EC2 consumes `SnapshotControl` for discovery,
deletion, tagging, snapshot attributes and those account settings; it has no second
snapshot catalog. Typed memory and SQLC repositories share the existing transaction
domain and journal. Schema 187 separates block metadata from payload BLOBs: listing,
lineage comparison and quota admission do not read all block bytes. Schema 188
retains private grants, publication deadlines, recipient-private tags and regional
public-access settings in service-owned tables.

Writes validate actual bytes and checksums; overwrites count once per index.
Explicit zero blocks remain allocated. Completion validates distinct changed
indexes and optional LINEAR SHA-256 over ordered raw block digests. Children
inherit unwritten indexes; an identical-byte rewrite still counts as changed.
Deleted parents disappear from EC2 while descendants retain their data layers.
Scoped block/page tokens survive reopen, reject different snapshots/pairs,
and remain valid across later listings. An empty block list advertises current
time, not a lifetime for nonexistent block tokens.

Completion, direct-read readiness, inactivity failure and deletion visibility
use retained deadlines and the shared scheduler. Local policies separate
completion by one second from another five seconds of read readiness, use ten
minutes for changed-count failure and five seconds for deletion visibility.
These are deterministic emulator choices, not measured AWS latency guarantees.
Nonempty pages advertise the captured 585,000-second token lifetime; natural
AWS expiration rejection has not been measured. Regional API rates and pending/
total snapshot quotas follow the [EBS quota catalog](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-resource-quotas.html).
Rate buckets are process-local; their one-second burst capacity is a local
policy, not a measurement of AWS's distributed throttling.

Encryption uses real KMS 64-byte data keys and AES-GCM block ciphertext.
Encrypted children rewrap the inherited key from parent to child
`aws:ebs:id` context. IAM retains the caller/session; `kms:ViaService` is
`ec2.<region>.amazonaws.com`, while the audit invoker is `ebs.amazonaws.com`.
No KMS grant is invented. Request conditions, actual parent tags and the
resolved resource owner govern permissions despite snapshot ARNs having an
empty account component. A child's requested tags cannot authorize its parent.

Start/complete are management events; the four block/list operations are data
events with `AWS::EC2::Snapshot` resources. Native shared-read resources carry the
requester's account even in the owner's delivered copy; IAM separately uses the
actual resource owner. Reads have null response documents, block payloads are
omitted, and IAM access denials suppress request/response documents while preserving
resources. Shared Get outcomes and rejected shared-parent/writer requests retain
paired caller/owner records with distinct event IDs and a common shared event ID.
Positive native records establish these pairs; missing eventual list records do
not establish an owner-delivery exclusion. Actual sanitized child
KMS outcomes survive a failed EBS command without retaining rolled-back state
or repeating cryptographic operations. Successful commands do not duplicate
those outcomes; explicit enclosing rollback still owns all state and events.

Evidence: `scripts/aws/ebs_{blocks,encryption}_probe.py` and
`testdata/aws/ebs/` retain native blocks, lineage, tokens, terminal states,
encryption, IAM, KMS context, CloudTrail and signing observations. SDK fixtures
exercise memory and SQLite reopening. The actual executable/AWS CLI uploaded
an encrypted ext4 filesystem, made an inherited child with an identical rewrite
and an additional block, deleted its parent and restarted SQLite. Pre-restart
tokens recovered identical filesystem bytes; `e2fsck` passed and `debugfs`
read the original file. A configured rule delivered `aws.ebs` StartSnapshot to
SQS, and a configured trail delivered all six API outcomes in S3 gzip logs.

Primary contracts: [direct API behavior](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-accessing-snapshot.html),
[encryption](https://docs.aws.amazon.com/ebs/latest/userguide/ebsapis-using-encryption.html),
[permissions](https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-permissions.html),
[CloudTrail](https://docs.aws.amazon.com/ebs/latest/userguide/logging-ebs-apis-using-cloudtrail.html)
and [EventBridge source](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-ebs.html).
Native probe snapshots and IAM resources were deleted; three owned KMS keys
were scheduled for deletion on 2026-10-02. Account encryption defaults were not changed.

Native `GetEbsDefaultKmsKeyId` returns `alias/aws/ebs` when no explicit key is
configured, including after managed-key snapshot creation. This corrects the
earlier documentation-derived assumption that the getter always returns an ARN.
Reset retains canonical-key resolution; native default-key mutation was not
performed on the standing account.

### Shared snapshots and public-access controls

`DescribeSnapshotAttribute`, `ModifySnapshotAttribute` and
`ResetSnapshotAttribute` own create-volume permissions, atomic validation,
canonical/legacy precedence, self/duplicate grants and the raw 500-entry mutation
limit. Product-code discovery is empty for direct-created snapshots. AWS-managed
default-key snapshots cannot be shared; customer-key private grants do not
implicitly grant KMS permission. Encrypted snapshots cannot become public.
IAM evaluates actual ownership, snapshot properties, resource tags and Add/Remove
conditions. Distinct batch recipients produce a multivalued condition context:
native plain `StringEquals` rejects that batch even when its policy lists both
accounts; duplicate recipients collapse to one value. Decoded native authorization
messages establish this distinction. Native requests do not supply `ec2:Attribute`
merely because the authorization catalog names it.

Private grants permit direct block/list reads, not writes or using a shared
snapshot as a new direct snapshot's parent. Shared encrypted lists and reads
require actual KMS Decrypt authority; owner-only listing does not require Decrypt.
An owner-issued block token works for an authorized
recipient, fails after revocation and works again after re-sharing; tokens never
replace current IAM/KMS/sharing admission. Public snapshots reject foreign direct
reads even when an explicit private grant or previously valid token exists.
Owner direct reads remain available.

Grant/revoke publication uses one retained five-second local deadline, not an AWS
SLA. Explicit-ID EC2 metadata can see a requested grant before published discovery
and EBS access. Recipient tags are independent from owner tags and supply the
recipient's resource-tag authorization context. After revocation those private
tags remain discoverable/deletable, while new tagging and snapshot discovery fail.

`GetSnapshotBlockPublicAccessState`, `EnableSnapshotBlockPublicAccess` and
`DisableSnapshotBlockPublicAccess` retain account/region settings. Block-new
prevents new public grants; block-all also hides existing public-only visibility
without erasing the public attribute. Private grants remain usable. Published
Organizations `DECLARATIVE_POLICY_EC2` snapshot settings override every Region
without overwriting underlying account settings. The local default is the
captured account's `unblocked` setting, not a claim about newly created AWS accounts.
Mutation admission uses the published one-request burst/0.1-per-second refill.

Evidence: `scripts/aws/ebs_sharing_{controls,data}_probe.py` and
`testdata/aws/ebs/sharing_*.json` retain native permissions, IAM, shared plaintext/
encrypted bytes, discovery, tag namespaces, limits and delivered audit records.
Native probes left standing account settings and organization roles unchanged,
deleted their snapshots/roles/trails/buckets and scheduled three additional owned
CMKs for deletion on 2026-10-02. Public-block mutations and organization override
semantics are documentation-derived, not native mutation captures.
The real executable smoke verified 524,288 shared bytes across SQLite restart,
old-token reuse/revocation, private tags after revoke, customer-key trust for
encrypted sharing, public guards, and published all-Region organization
override/release through signed boto3 requests.

Primary contracts: [snapshot permissions](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html),
[public-access blocking](https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html),
[direct API restrictions](https://docs.aws.amazon.com/ebs/latest/userguide/ebsapi-faq.html)
and [declarative policy syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ec2_syntax.html).

### Independent snapshot copies

`CopySnapshot` uses the same owner and generated EC2 Query frontend. It copies
actual sparse blocks into a destination-owned layer, preserving lineage.
Admission retains work and private source references; a completed copy has no
payload dependency on the source. Same-Region, cross-Region, private shared and
public sources are supported. Copies survive source deletion or permission
revocation and can become the recipient's own `StartSnapshot` parent.
Source tags and sharing permissions are not inherited.
The logical writing-snapshot identity travels with each block: copying preserves
it, whereas an explicit direct-API rewrite remains a change even for equal bytes.

IAM authorizes both the source snapshot and destination `snapshot/*`. Resource
accounts differ across account transfers; `ec2:Owner` belongs to the source.
Creation tags additionally require `ec2:CreateTags` with
`ec2:CreateAction=CopySnapshot`. Copying does not borrow the caller's EC2 discovery
or direct-EBS read permissions. Failed source visibility/completion produces a
retained pending copy followed by the captured error, rather than a fake success
or a synchronous source-read error.

Schema 189 separates authoritative size/description from direct-API replay input
and retains copy origin, duration and causal identifiers. Schema 238 retains
pending block work and admitted KMS authority. Transfer reads one detached block,
performs payload cryptography outside the transaction, and commits the destination
block independently. Existing block rows allow restart without a second cursor.
Completion and readability delays start after payload work finishes; the original
creation time stays unchanged. Time-based admission accepts 15-minute increments
through 2,880 minutes. A late recovery can miss that bound, and its completion
notification reports the actual outcome. Native intermediate metadata-publication
latency is not reproduced. Regional concurrent copy admission follows the
published limit of 20.

Encrypted copies select the destination's default key unless a key is supplied;
`Encrypted=false` never decrypts an encrypted source. Fresh destination keys use
real KMS `GenerateDataKeyWithoutPlaintext` with 64 bytes. The caller authorizes
constrained regional EC2 service grants; that service decrypts the source and
destination keys and retires the grants. Incremental key reuse follows the
observed grant-based `Encrypt` path. Caller `Decrypt`, `ReEncrypt` or
`GenerateDataKey` permission is not substituted for these dependencies.
Destination `DescribeKey` denial rejects admission; source/destination
`CreateGrant` or fresh-key generation denial produces the captured terminal
copy error. Source `DescribeKey` is not required.

Completion/failure publishes `aws.ec2` / `EBS Snapshot Notification` in the
destination account and Region, atomically with lifecycle state. Native
`copySnapshot` details contain string-valued `incremental` and
`metCompletionDuration`, an empty `request-id`, and the unusual observed
`arn:aws:ec2::REGION:snapshot/ID` layout. CloudTrail management records retain
paired caller/source-owner views without resources; the owner view hides the
recipient's request/response tags. Copy key selection is recorded as
`masterEncryptionKeyId`. Forwarded KMS denial records survive rejected copy
admission, use native `AccessDenied`, and omit key/context parameters and
resources. Raw presigned URLs are never retained.

Native captures differ from several API-documentation expectations: unsigned
and zero-signature legacy `PresignedUrl` values completed real encrypted copies;
malformed protocol or mismatched source/destination identifiers rejected
synchronously. The emulator validates those identifiers, never fetches the URL,
and still authenticates and authorizes the ordinary signed API request.
Nonexistent and disabled destination KMS keys likewise rejected synchronously.

Evidence: `scripts/aws/ebs_copy_{controls,data}_probe.py` and
`testdata/aws/ebs/copy_*.json` retain finite native admission, IAM/KMS, bytes,
lineage, notifications and delivered audit observations. Native probes deleted
61 snapshots and their temporary IAM/trail/bucket/rule/queue resources; 24 owned
CMKs were scheduled for deletion. Standing encryption/public-block settings
were unchanged. The executable smoke copied 524,288 encrypted bytes to three
same/cross-Region snapshots, deleted the source, delivered standard/time-based
notifications to SQS, restarted SQLite and reused all three old block tokens.
A subsequent executable copy checked the native key-selection audit field and
verified that its temporary KMS grants were retired.

Primary contracts: [CopySnapshot](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CopySnapshot.html),
[copy semantics](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-copy-snapshot.html)
and [native snapshot notifications](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-cloud-watch-events.html).

This is not complete EBS/EC2 parity. Archive/lock/fast-restore workflows and copy
placement in Outposts/Local Zones remain open. Instance/AMI consumers are described
below. Regional EC2 KMS service grants outside the commercial partition remain
unsupported. Native disabled-key/cache propagation is not calibrated: current
operations enforce current KMS authority rather than inventing a cache bypass.
Default-key mutation currently resolves keys synchronously; the
[documented asynchronous admission](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyEbsDefaultKmsKeyId.html)
and invalid-key timing remain uncalibrated.
EBS is a selected workload prerequisite; implemented API names do not establish
semantic completeness.


### Volumes and volume-derived snapshots

EC2 consumes the EBS owner's `VolumeControl` interface for volume creation,
discovery, modification, deletion, attributes, I/O status and `CreateSnapshot`.
It does not maintain another disk catalog. Service-owned schema 190 retains
typed volume configuration, modification history, lifecycle deadlines, causal
request IDs, sparse blocks and snapshot provenance alongside the shared journal.
Original creation inputs remain authoritative for client-token comparison;
replaying an admitted request returns the volume's current configuration.

Snapshot hydration copies actual allocated blocks. Deleting the source snapshot
does not remove the volume's data, and deleting a volume does not remove snapshots
already taken from it. Ciphertext records retain their immutable AEAD origin
separately from current storage location. This is necessary when native KMS
authority permits rewrapping a key but does not permit decrypting its data.

Native KMS behavior distinguishes owned same-key hydration from shared or rekeyed
hydration. Owned same-key copies use `ReEncrypt` from snapshot context to volume
context without requiring a plaintext key or inventing a service grant.
Shared snapshots, including same-CMK sharing, use a fresh 64-byte data key and a
constrained destination decrypt grant. Temporary grants are retired after use.
`CreateSnapshot` does not introduce another KMS operation: it retains the volume's
wrapped key and `aws:ebs:id` context. Later block reads and snapshot copies use that
retained volume context even after the source volume has been deleted.

Standalone snapshot-backed volume admission also retains work rather than copying
payloads inside the API transaction. A volume cannot become available or boot
until its blocks have finished hydrating. `CreateSnapshot` and standalone
`CreateImage` capture the immutable SQL block set at admission, even if the source
is later deleted or handed to a native disk that receives new guest writes.
Only that historical set remains pinned; native writes are not mirrored into it.
Each destination block commits separately, and completion or discard releases
the pin and obsolete source bytes. No additional KMS grant is required to preserve
the admitted ciphertext, wrapped key and authenticated block origin.

Signed recovery scenarios exercise partial-read rejection, unrelated SQS
responsiveness, source/destination deletion, native byte-authority handoff, image
failure and exact recovered blocks on memory and reopened SQLite. A standalone
HTTP/SQLite smoke interrupted after one block, deleted the source, replaced the
stack and database connection, then downloaded both original blocks and observed
source-pin reclamation. Already-revoked service grants do not wedge terminal
cleanup; other KMS failures still propagate.

Create/delete and modification phases run through the existing shared scheduler.
The local policy is one second for creation/deletion, one second to publish a
modification's target configuration and two seconds to complete it. Those are
deterministic choices, not measured AWS latency guarantees. The observed four
accepted modifications per rolling 24 hours include no-op modifications.
Snapshot admission currently separates accepted requests for one volume by one
minute; native captures bracket rapid rejection and later acceptance, not AWS's
exact distributed rate algorithm. Initial `CreateSnapshot` progress is empty;
pending `DescribeSnapshots` progress is a percentage.
Snapshot-backed disk status preserves the native default/provisioned-rate
initialization shape. Sparse bytes hydrate after admission; pending payload work
prevents initialization completion even after the two-second service-time
publication delay. Provisioned-rate responses retain the captured zero estimate
while initializing. That estimate is not a completion signal or a measured
throughput model, and logical GiB is not treated as allocated data size.

Volume notifications carry the originating EC2 request ID and account-filled
volume ARN. Failed creation emits a failure followed by automatic deletion;
failure resources include the destination key when its ARN is known.
Modification emits the observed optimizing/completed phases. Volume-derived
snapshot notifications preserve the native snapshot/source ARN spelling.
Shared creation audit records retain distinct caller/owner attribution and hide
request/response tags in the owner's copy.

Native evidence is retained in `testdata/aws/ebs/volume_controls*.json` and
`volume_data*.json`, with the corresponding probes under `scripts/aws`.
An actual executable workflow hydrated encrypted bytes, modified the volume,
replayed its original client token, deleted the source snapshot, took a new
snapshot and deleted the volume. After SQLite restart, the original block token
and a new snapshot copy each returned the same 524,288 bytes. EventBridge delivered
the lifecycle notifications to SQS without requiring a Describe call, and a
configured CloudTrail trail delivered 34 records to S3.

Opaque long snapshot-ID validity encoding is explicitly deferred. The retained
`volume_controls_snapshot_ids{,_contract}.json` and
`volume_controls_snapshot_id_bits.json` contain 310 read-only/DryRun observations:
AWS rejects some lowercase 17-digit IDs according to additional digit-dependent
constraints, but the observations do not establish a general decoder.
Current public syntax/existence checks can therefore return `InvalidSnapshot.NotFound`
where AWS returns `InvalidSnapshotID.Malformed`. The affected native scenario is
explicitly skipped in replay, not rewritten or presented as a passing comparison.
No example-ID blacklist or guessed checksum is implemented.

Primary contracts: [CreateVolume](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html),
[ModifyVolume](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVolume.html),
[CreateSnapshot](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshot.html)
and [EBS encryption](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html).
Unattached sparse disks do not establish guest attachment, physical device I/O,
Outpost/service-managed ownership or complete EC2/EBS parity.

## Images, instance types and metadata

AMI registration, discovery, attributes and private sharing use typed EC2 state
and EBS-owned snapshot references. Native SDK replay consumes
`testdata/aws/ec2/images_{controls,sharing,snapshot_references}.json`.
Registration establishes an image record, not guest-driver compatibility.
Opaque AMI identifier encoding is explicitly deferred by the user: the
`images_sharing/describe-unknown-valid-id` discrepancy remains captured and
excluded from replay. No captured identifier is blacklisted.

`cmd/awsgen` generates the instance-type catalog from
`testdata/aws/ec2/instance_types.json`; `instance_type_inputs.json` retains native
selection/DryRun boundaries. These API facts are independent of the configured
backend's executable hardware capabilities. Native lifecycle and storage/KMS
observations live in `instances_lifecycle*.json` and
`instances_storage_encryption*.json`, with capture scripts under `scripts/aws/`.

### Launch templates and instance admission

The create/describe/modify/delete template and version APIs retain scoped names,
ordered tags, immutable version data, default/latest pointers and idempotency
tokens in the shared memory/SQLC transaction domain. Schema 229 stores typed
version fields and ordered child relations; deleting the latest version does
not rewind the allocation counter. Explicit repeated version selectors retain
their repeated results. Pagination binds account/region, selectors and filters.

`CreateLaunchTemplateVersion` replaces supplied top-level data members over its
selected source; omitted source means no inheritance. Native captures retain
an inherited EBS snapshot ID despite the API reference's snapshot caveat.
Storing a launch configuration is not a promise that the local hardware or
referenced resources can execute it. Unsupported guest effects remain errors
when consumed, not successful inert options.

`RunInstances` resolves the scoped template and numeric/default/latest version,
merges explicit launch overrides, and uses the existing instance, image, network,
EBS and profile owners. Current IAM, creation-tag policy and PassRole still apply,
including `ec2:LaunchTemplate` and `ec2:IsLaunchTemplateResource`. Launch origin
appears in protected `aws:ec2launchtemplate:id` and `aws:ec2launchtemplate:version`
instance tags; deleting the template or customer tags does not erase that origin.
For an interface-based template, subnet overrides belong in the corresponding
`NetworkInterfaces` entry. A top-level `SubnetId` still conflicts with inherited
interfaces; it is not silently translated. The retained
[before/after executable admission record](../testdata/integration/ec2_launch_template_network_admission.json)
reproduces the former incorrect DryRun acceptance, verifies the native
`InvalidParameterCombination` correction, and admits the interface-list override
after reopening the same SQLite state. This probe never launched an instance.
Dry-run admission requires the real image, subnet, EBS and instance-type owners,
but not a guest executor. The same image/type/architecture/volume/IAM/PassRole
checks run before `DryRunOperation`; an actual launch without an executor still
returns `UnsupportedOperation` before allocating instances, interfaces or volumes.
`GetLaunchTemplateData` reads current instance attributes, tags and actual EBS
attachments rather than copying a stale reservation. The documented dependent
DescribeInstanceAttribute, DescribeInstanceCreditSpecifications and DescribeVolumes
permissions remain current-caller requirements for the data being returned.

Native fixtures `launch_templates.json`, `launch_template_edges.json` and
`launch_template_deletion.json` under `testdata/aws/ec2/` replay SDK results and
exact-request CloudTrail envelopes against memory and reopened SQLite.
`launch_template_instance.json` additionally records one owned native t3.nano,
explicit overrides, protected tags and template deletion while it ran. Its
bounded console observations remained empty: they do not establish native IMDS
behavior. Exact instance termination, root-volume absence and owned
template/security-group/subnet/VPC absence are retained.

The assembled CLI workflow in `scripts/ec2_launch_template_smoke.py` imported
the existing read-only Ubuntu raw image through signed EBS direct APIs, booted
an actual SeaBIOS/QEMU guest from the template, and observed overridden values
and protected launch-origin tags through guest IMDSv2. The same guest observed
a changed tag after controller/SQLite restart. The
[successful record](../testdata/integration/ec2_launch_template_guest.json)
also covers current PassRole/launch-template conditions, denied and restored
dependent Get-data permissions, retained unsupported configuration with honest
launch rejection, default/latest transitions, pagination and exact cleanup.
The [interrupted incompatible-firmware attempt](../testdata/integration/ec2_launch_template_guest_interrupted.json)
and [console-observer decoding failure](../testdata/integration/ec2_launch_template_guest_decoder_failure.json)
remain separate, with completed cleanup; neither is reported as a passing boot.

Primary references: [version inheritance](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateLaunchTemplateVersion.html),
[launch-template permissions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/permissions-for-launch-templates.html),
[launch admission conditions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/use-launch-templates-to-control-launching-instances.html)
and [current-instance data/dependent permissions](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetLaunchTemplateData.html).
SSM AMI-alias resolution, managed operators, attribute-based Fleet selection and
unsupported specialty guest hardware remain explicit boundaries. The corresponding
`TODO: Comeback` marker names the existing Parameter Store dependency; no alternate
template state, telemetry store or execution backend is introduced.

### EC2 Auto Scaling

The generated Auto Scaling Query frontend has a separate typed service owner.
Groups, memberships, activities, policies, schedules, hooks and action deadlines
share the memory/SQLite transaction domain; schema 231 uses normalized relations,
not opaque resource documents. EC2 remains authoritative for instances, templates,
networks, images and EBS. ASG does not create fictional instances or a second
compute store.

Creation and template/network updates validate the original caller through
ordinary EC2 `RunInstances` dry-run admission, including current `iam:PassRole`.
Capacity-only updates do not repeat that preflight. Execution freshly assumes the
configured Auto Scaling service-linked role. A launch activity freezes its numeric
template version, subnet, propagated tags and warmup; its activity ID is the EC2
client token for recovery. Native effects run outside the group transaction and
outside the shared scheduler's serial drain gate. Reserved group membership tags
are written by the EC2 owner before guest startup, not by a later public tag call.
IAM's role-deletion decision holds the actual all-region group dependencies stable.

Lifecycle actions retain their tokens, heartbeat/global deadlines and multi-hook
barriers. Launch `ABANDON` rejects that launch and still enters configured
termination hooks. Termination completes ALB deregistration/draining before
entering its hook, then waits for the hook outcome before EC2 retirement or
retention. Scale-in protection starts at `InService`, not
`Pending:Wait`; it does not prevent unhealthy-instance replacement. Accepted
desired capacity is distinct from actual membership and completed activity.
Activity history survives group deletion.

CloudFormation group, policy, schedule and hook ownership is private native-row
incarnation metadata, not public tags or a generated-name/token hash. Recovery
and mutations still enter current native IAM; admitted lost replies retain the
same private owner. A scaling policy's full scoped ARN, including its immutable
UUID, fences updates and deletion against same-name replacements. Reads recover
native group/policy identity from that ARN without template properties and omit
the optional `AutoScalingGroupName` filter when it is absent.
[`PolicyName` is a read-only CloudFormation return value](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-scalingpolicy.html#aws-resource-autoscaling-scalingpolicy-return-values),
not a writable template property. Declarative group-property removals restore
native create defaults; ordinary native updates retain their merge semantics.

Simple/step policy decisions, one-shot/Unix-calendar schedules, cooldowns, warmup
and target-tracking alarms use the shared clock and existing CloudWatch owner.
Custom metric and ALB target tracking consume actual CloudWatch samples; ALB
resource labels must identify a target group attached to the ASG. EC2 CPU/network
predefined policies consume [actual native guest measurements](#native-cpu-and-network-monitoring).
Missing observations do not become invented CPU load or network traffic.
Enabled group-capacity gauges publish through `AWS/AutoScaling` at one-minute
service-time boundaries; downtime does not manufacture backfilled observations.

#### Native Auto Scaling evidence

`testdata/aws/autoscaling/controls.json` and `lifecycle_native.json` retain the
SDK inputs/outputs and exact-request CloudTrail records. The latter includes
757 recorded outcomes, 573 exact request-ID matches, 122 related service records
and 16 EventBridge events. Every in-scope management request was collected;
SQS data calls and out-of-scope CloudWatch/SSM reads are not relabeled as history
coverage. All five launched native instances terminated, their five root volumes
and interfaces disappeared, and the owned control resources were removed.
The standing service-linked role and borrowed metrics subnet were untouched.

`failure_boundaries_native.json` preserves a failed notification-role admission:
`sqs:SendMessage` alone returned `ValidationError`. The corrected independent
`failure_boundaries_native_complete.json` adds `sqs:GetQueueUrl`, completes its
one-instance workflow and retains 191 CloudTrail records with no missing
in-scope request IDs. These are bounded management-history observations, not
SQS data-event coverage. The instance, root volume, interface, owned IAM and
control/network resources were removed; the standing service-linked role was
unchanged.

Measured distinctions include:

- Caller RunInstances/PassRole denies reject group creation and explicit template
  updates, but not capacity-only updates. Inline creation tags do not require a
  separate `CreateOrUpdateTags` grant in the captured bounded-role scenario.
- `$Latest` and `$Default` stay aliases on the group; launched membership records
  the actual numeric version. Group instance tags override matching template
  instance tags without rewriting template volume tags.
- Launch activities expose `PreInService`/30 then `MidLifecycleAction`/40;
  termination-hook activities expose `MidTerminatingLifecycleAction`/60.
  Public activity end times are second-truncated, unlike event milliseconds.
  Event `RequestId` equals the activity ID, not the triggering API request ID.
- Protected desired-zero scale-in produced one `Cancelled`/100 activity with
  empty details across three 15-second-spaced observations. This bounds native
  deduplication evidence; it is not a universal timing guarantee.
- Direct force deletion of a protected desired-one group entered its termination
  hook and waited for the 30-second default continuation. A separate sequence
  with preceding scale-in also waited. These observations contradict the blanket
  force-delete exemption in the [lifecycle-hook guide](https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html);
  the captured transition, not that exemption, governs the implemented path.
- Five queried enabled gauges reported zero with `Unit=None`, including
  `GroupAndWarmPoolDesiredCapacity`, `WarmPoolDesiredCapacity` and
  `WarmPoolTotalCapacity` without any warm pool. The
  [metric guide](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html)
  alone does not establish omission for an absent pool. Other catalog entries
  were observed as enabled, not exhaustively sampled.
- After a previously accepted notification queue was deleted, launch and
  termination hooks with `CONTINUE` completed before their 30-second heartbeat
  deadlines. Notification rejection applies the configured default immediately,
  through the same multi-hook barrier as explicit completion and expiry.
  Internal storage failures remain failures, not fabricated continuation.
- `Launch` suspension rejected `AttachInstances` and `ExitStandby` with
  `ValidationError`. `Terminate` suspension retained an explicitly unhealthy
  `InService` member across three observations; resumption retired it.
- `DisableApiTermination=true` rejected public EC2 termination with
  `OperationNotPermitted`, but did not prevent subsequent service-owned ASG
  retirement. The trusted EC2 command checks immutable group ownership and
  current execution-role authority; it does not clear the customer flag.

Original connection loss, a 150-second deletion observation timeout and the empty
default-subnet lookup remain in the evidence alongside completed cleanup and
independent successful controls. A direct-force event observation window returned
no event; API membership proved the hook wait, not event non-emission.

Primary semantics also use the [CreateAutoScalingGroup](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html),
[Activity](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_Activity.html)
and [retained-instance](https://docs.aws.amazon.com/autoscaling/ec2/userguide/manage-retained-instances.html)
contracts.

Additional primary contracts: [notification preparation](https://docs.aws.amazon.com/autoscaling/ec2/userguide/prepare-for-lifecycle-notifications.html),
[notification-role permissions](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AutoScalingNotificationAccessRole.html),
[process suspension effects](https://docs.aws.amazon.com/autoscaling/ec2/userguide/understand-how-suspending-processes-affects-other-processes.html)
and [suspension considerations](https://docs.aws.amazon.com/autoscaling/ec2/userguide/suspend-resume-considerations.html).
Health-check suspension does not suppress explicit manual unhealthy state.
Resuming `AddToLoadBalancer` does not retroactively register members admitted
while that process was suspended. Subnet-only updates derive their new zones;
an explicitly supplied incompatible zone remains an admission error.
EC2 status-check `initializing` and `insufficient-data` are not impairment;
the [health-check contract](https://docs.aws.amazon.com/autoscaling/ec2/userguide/health-checks-overview.html)
distinguishes them from failed checks and nonrunning instances. This matters
with the SDK's zero grace period: an unobserved check must not trigger immediate
replacement of a newly launched guest.

#### Actual local execution

`testdata/integration/autoscaling_guest_verified.json` records signed SDK calls
to the actual race-enabled CLI, firmware-booted QEMU guests and native ALB HTTP.
It retains schema-228 ALB/image state through the schema-231 upgrade, preserves
the same guest boot across controller restart in `Pending:Wait`, then exercises
hook continuation, protected scale-in cancellation, an actual CloudWatch alarm
changing capacity, scheduled capacity, overlapping unhealthy replacement,
group gauges and detach/attach without reboot. Force deletion waits for its
termination hook before actual guest, root-volume and interface retirement.
The original setup/observation failures remain in the earlier captures; the
successful capture is not a claim that those runs passed.

`testdata/integration/autoscaling_failure_boundaries_verified.json` exercises the
corrected executable with zero health-check grace and 69 recorded signed SDK
outcomes. Deleted SQS and SNS notification destinations apply `CONTINUE` through
their shared launch barrier; EventBridge still delivers the lifecycle event.
The guest serves actual HTTP with its instance/group identity. Resuming
`AddToLoadBalancer` leaves the excluded member unregistered; later reattachment
registers it and routes a real ALB request. Launch suspension rejects attach and
standby exit. Health-check suspension preserves a stopped healthy member; a
subsequent start serves HTTP with a new boot ID. Explicit unhealthy state survives
Terminate suspension, then resumption retires the actual API-protected guest.
The instance, volume, interfaces and owned control resources are removed.

The same SQLite journal retains the hook role's failed SQS lookup and SNS publish
outcomes: one `AccessDenied`, two `QueueDoesNotExist`, and one
`NotFoundException`. These are retained typed Data API outcomes, not a claim of
configured-trail S3 delivery. Earlier captures retain the observer's SQS error
alias mismatch, an unbound target-group prerequisite failure, and the reproduced
initialization-health replacement bug; all three completed cleanup.

#### Retained termination and handoff

`InstanceLifecyclePolicy.RetentionTriggers.TerminateHookAbandon=retain` preserves
the actual guest when a termination hook explicitly abandons or reaches its
default `ABANDON` deadline. Membership becomes `Terminating:Retained` and the
termination activity becomes terminal `Cancelled`. The existing membership row
and activity own this transition; there is no separate retention store.
Retained membership does not satisfy desired capacity, so replacement can leave
two actual guests in a group with desired/max capacity one.

Native captures establish these distinctions:

- Manual `TerminateInstanceInAutoScalingGroup` with decrement disabled creates
  a **new termination activity and hook token**, not a hook bypass. Another
  default `ABANDON` retains the guest again; `CONTINUE` allows actual retirement.
  Decrement enabled is rejected even when desired capacity exceeds the minimum.
- Force deletion is rejected while the policy says `retain`, even for an empty
  group. Changing the policy alone does not release already retained membership.
  After changing it to `terminate`, force deletion starts a fresh termination
  hook for the retained guest; its eventual abandonment no longer retains it.
- `DetachInstances` without decrement transfers the still-running guest out of
  the group and removes the automatic group-ownership tag. Retained scale-in
  protection and standby entry are rejected; setting health to `Healthy` succeeds
  without returning the instance to active capacity. The
  [detach contract](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-detach-attach-instances.html)
  additionally forbids decrementing desired capacity when detaching a retained
  instance; that rejection is documentation-derived, not a captured native call.
- Native one-minute gauges with one retained and one in-service member report
  desired/in-service/retained counts of one, ordinary terminating count zero,
  and **total count two**, with `Unit=None`. Retained membership is excluded from
  capacity planning, not from total-instance accounting.
- Retained protection rejection is Query `ValidationError`, but its native
  CloudTrail record uses `InvalidParameterValueException` and
  `An unknown error occurred`. Other captured retained validation failures use
  `ValidationException`; nonempty ordinary deletion uses `ResourceInUseFault`.
  The wire diagnosis remains separate from this native audit projection.

Sources under `testdata/aws/autoscaling/` are `retention_native.json`,
`retention_intervention.json`, `retention_decrement_native.json` and
`retention_membership_native.json`. The first observation bound expired because
manual release re-entered its hook and retained again; the failure and separate
continuation remain recorded. Three independent resource scopes terminated five
owned guests and removed their five roots/interfaces, networking, IAM and control
resources. Account defaults were unchanged. Every in-scope management request in
the four history collections has an exact request-ID match; related events
overlap and SQS data events are outside that history evidence.

The [actual retained-guest workflow](../testdata/integration/autoscaling_retention_guest.json)
drains ALB targets before the termination hook while direct guest HTTP still
works, retains the original guest, and serves replacement traffic through ALB.
SQLite controller restart preserves the original boot ID, root mapping and
membership. Manual release emits a new hook, keeps the original serving until
`CONTINUE`, then retires only that guest while the replacement remains usable.
The executable also observes the protection error through CloudTrail history.
Cleanup completed. Native multi-hook retention, policy changes during a waiting
action, unhealthy retained mutation and broader weighted metrics remain
uncalibrated; warm-pool retention follows the transitions below.

Primary contracts:
[retention configuration](https://docs.aws.amazon.com/autoscaling/ec2/userguide/configure-instance-retention.html),
[retained instance management](https://docs.aws.amazon.com/autoscaling/ec2/userguide/manage-retained-instances.html)
and [pre-hook connection draining](https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks-overview.html).

#### Warm pools

`PutWarmPool`, `DescribeWarmPool` and `DeleteWarmPool` use generated Query
contracts and the existing group, activity and instance repositories. A pool
prepares `max(MinSize, prepared capacity - DesiredCapacity)` instances; prepared
capacity defaults to the group's maximum. Warm members are separate from active
desired capacity and are promoted before a cold launch. Suspending `Launch`
reserves prepared instances for the unmet active demand instead of destroying
them; explicit pool deletion still removes that reservation.

Stopped, Running and Hibernated destinations execute through EC2's real lifecycle
owner, not a metadata-only pool state. A selected activity retains its destination
state, so changing pool configuration does not convert already-settled members.
Hibernated preparation requires the encrypted-root/image/type prerequisites below
and enables EC2 hibernation at launch. Reuse returns eligible scaled-in instances
to the pool, after target draining and lifecycle hooks. Reusing an instance without
hibernation configured falls back to stopping.

Warm launch, activation, return and final termination use the existing lifecycle
action tokens, notification targets and retained-instance policy. Force deletion
does not bypass hooks. Abandoned return without retention still returns the
instance to the pool; retention preserves `Warmed:Pending:Retained`. A retained
warm termination during pending deletion re-enters a fresh termination hook
without another delete request. Empty-pool deletion completes independently of an
unrelated active launch failure.

Warm gauges come from membership, not EC2 tags. EC2 asks the Auto Scaling owner
for the group dimension at measurement time: warm guests retain instance CPU/
network samples but contribute no active-group series. Historical contributions
remain attributed to the group that owned the sample.

Metric deadlines remain eligible while native reconciliation is active or
scheduled later. Publication and the next metric deadline commit together;
reopening SQLite does not repeat the sample. The
[actual suspended-warm-pool workflow](../testdata/integration/autoscaling_metric_deadlines.json)
publishes desired capacity at `04:06:00` despite a native reconciliation deadline
of `04:06:04`, then restarts the executable and observes a sample count of one.
Launch is suspended throughout: the fixture reports zero actual warm instances,
not fabricated guest capacity.

Native sources are `testdata/aws/autoscaling/warm_pool*.json`, including the
suspended-launch, return-abandon, sizing and force-retained captures. They retain
signed boto3 1.43.98 controls, observed lifecycle/metric states, exact request-ID
CloudTrail matches and owned-resource cleanup in account `000000000000`,
`us-east-1`. Signed SDK replay covers memory and SQLite reconstruction.
Primary contracts: [warm-pool concepts and prerequisites](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-warm-pools.html),
[lifecycle transitions](https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pool-instance-lifecycle.html)
and [warm-pool events](https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pools-eventbridge-events.html).

The [actual warm-guest workflow](../testdata/integration/autoscaling_warm_pool_guest.json)
upgrades populated schema 235 to 238 and exercises all three pool states through
signed APIs, encrypted roots, lifecycle hooks, SQLite controller restart, ALB
traffic and reuse. Stopped activation changes boot ID and the RAM-only nonce
while retaining the root marker. Running and Hibernated activation preserve boot
ID, process PID, RAM nonce and counter; Hibernated uses a fresh VMM after guest S4.
Warm-only CPU samples exist for the instance and are absent from the group.
All three guests terminate after the final pool-deletion hook. The initial
cleanup raced asynchronous group disappearance; a separate continuation exercised
that real missing-group response and completed owned-resource cleanup without
repeating the guest lifecycle.

#### Scaling activity time filters

`DescribeScalingActivities` implements inclusive `StartTimeLowerBound` and
`StartTimeUpperBound` together with `Status`. Native owned-resource histories in
`activity_filters_native.json` and `activity_filters_edges_native.json` calibrate
millisecond precision, explicit offsets, lower-case ISO separators, whitespace,
minute precision and invalid/duplicate filter errors. Unlike the API reference's
UTC-default wording, the captured service rejects timestamps with no zone.
Unusual month-end normalization is not directly established by those histories.

Fixture replay checks selected activity IDs and modeled error codes; the signed
executable call now accepts a lower bound that previously returned
`NotImplemented`. Pagination retains scope/group/deleted-group binding but allows
selection filters to change, as observed natively. One captured changed-filter
continuation omitted the oldest record exactly equal to its upper bound, while a
first-page query included it. That cursor-boundary anomaly remains uncalibrated;
the implementation preserves documented inclusive selection rather than
special-casing a captured timestamp.
Primary contract:
[DescribeScalingActivities](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeScalingActivities.html).

#### Rolling instance refresh

`StartInstanceRefresh`, `DescribeInstanceRefreshes`, `CancelInstanceRefresh` and
`RollbackInstanceRefresh` use the existing EC2, launch-template, IAM, lifecycle,
ALB and CloudWatch owners. Typed schema 239 retains the original configuration,
target configuration, member progress and service-time deadlines. Preparing EC2
admission happens outside the state transaction; commit rejects a concurrently
changed group configuration instead of applying a stale plan.

Rolling refresh handles health/warmup gates, checkpoint delays, bake time,
skip-matching, cancellation and rollback. It retains the configured launch
template until the rollout succeeds. Mixed-instance desired configurations and
`ReplaceRootVolume` still require their unimplemented capacity/EC2 owners; they
return explicit errors rather than pretending to refresh instances.

The [actual guest workflow](../testdata/integration/autoscaling_refresh.json)
imports the firmware image through signed EBS APIs and serves distinct version
responses through the real ALB. It observes replacement overlap, retirement of
the original guest, baking, and controller restart with the replacement's same
instance and boot ID. Explicit rollback produces a newly booted original-version
guest and `RollbackSuccessful`; a subsequent refresh serves version two and
commits launch-template version two. Every owned guest, volume, interface,
load-balancer resource and network is removed afterward.

That workflow exposed a native DHCP lease-retirement bug on recycled addresses.
The fix retires the old lease in dnsmasq, not in a parallel Go lease cache; see
the [guest network implementation](#execution-and-shared-compute-ownership). Earlier failed and
interrupted captures remain historical evidence, not passing refresh runs.

#### Lambda-backed termination selection

A Lambda ARN in `TerminationPolicies` invokes the actual Lambda runtime under
current Auto Scaling execution authority. The two-second selection deadline,
eligible membership and subsequent built-in ordering remain Auto Scaling-owned;
the function does not acquire permission to retire arbitrary instances.

The [actual termination workflow](../testdata/integration/autoscaling_termination.json)
boots two ALB-backed guests and invokes real customer code. Empty selections,
function errors, timeout, protected-only and foreign-instance selections all
leave both guests running. Current authority denial still blocks selection after
controller/SQLite restart. Returning candidates in reverse order does not bypass
the following `OldestInstance` policy: the oldest guest enters its real lifecycle
hook, while the surviving guest continues serving packets. Unhealthy-instance
retirement bypasses the custom scale-in selector but still enters the configured
termination hook. Final cleanup removes the guests and the Lambda function.

#### Remaining boundaries

Predictive scaling, metric math, mixed/Spot/fleet capacity, legacy launch
configurations and Classic Load Balancers remain explicit unsupported paths.
Instance-derived group creation, explicit zone-ID placement, non-ELBv2 traffic
sources, and allocation/launch-configuration termination policies are also
unimplemented.
AZ rebalancing and best-effort failed-zone fallback still need their runtime
owners. Native tolerance of intermittent EC2 impairment for a few minutes needs
calibration; current failed-check replacement does not yet model that window.
Scheduled-event/application health dependencies remain EC2-owned gaps.
These boundaries and remaining generated operations stay in the backlog; this is
not ASG parity.

### IMDS ownership and HTTP behavior

IMDS routing, historical categories and leaf introductions are generated from
`instances_metadata_depth_handoff.json` and its retained primary documentation.
Successful older native leaves override later documentation dates: for example,
`placement/region` already works under `2019-10-01`. The earlier matrix/routes
fixtures remain historical evidence, not competing routing definitions. The
captured release vocabulary is fixed; this does not implement a moving
per-instance Nitro release-upgrade model.

Authentication precedes version/method rejection. Required-token requests without
a token return 401; token issuance belongs to `/latest/api/token`. Native captures
accept TTL zero with HTTP 200, then reject that token immediately with 401.
Negative, excessive and nonnumeric TTLs return 400. Reads expose remaining token
TTL; HEAD, OPTIONS, trailing slashes and path cleaning follow retained native
observations. POST/DELETE metadata reads return 403.

Values come from their resource owners: current ENI/subnet/VPC configuration,
retained instance placement/type, launch public key, tags and the launch/last-start
block-device snapshot. Hot attachment does not rewrite that snapshot. Native
`instances_metadata_secondary{,_handoff}.json` establishes `ebs1=sdf` for a
`/dev/sdf` launch mapping, while `root=/dev/xvda` and `ami=xvda` deliberately differ.
The fixture failed against the previous secondary-device projection before its
correction. A real Ubuntu guest verified a hot disk becoming `ebs2` only after
stop/start. Schema 198 retains device snapshots; older databases cannot reconstruct
already-detached historical mappings, and the next start establishes fresh state.

Tags and `tag-sets/instance` use the current tag owner; the latter is a text/plain
JSON object. With tags enabled but no tags present, `tags`, `tags/instance` and
their leaf paths return 404; `tag-sets` still lists `instance` and
`tag-sets/instance` returns `{}`. Disable/re-enable uses the same current tags.
An earlier native capture still exposed a removed tag after 125 seconds; a later
running-guest capture observed convergence in about three seconds. Neither is a
minimum lag or deadline. AWS permits running updates without stop/start, so there
is no second publication store, generation counter or invented fixed delay.

Successful `ModifyInstanceMetadataOptions` calls return `pending` acceptance,
including running/stopped no-ops. A no-op leaves committed state unchanged;
effective running changes apply immediately, and nonrunning changes remain
pending until the existing start transition applies them. Native stopped
Describe observations can initially retain the old applied view; no fixed lag
is inferred from those samples.

Public IPv4, public hostnames and per-interface IPv4 associations now derive from
the current EC2 address owner. Reserved group tags come from ASG membership before
guest startup. Maintenance/Spot and `autoscaling/target-lifecycle-state` metadata,
IPv6 and multi-card metadata still need their respective owners; unsupported
categories are not populated with invented values.

The actual executable also verified IMDSv2, zero-TTL rejection, historical leaves,
HTTP methods, changed tags and restored metadata access after controller restart
without advancing its manual clock. Startup now reconnects prepared native
controllers separately from future lifecycle observation deadlines; it does not
require a Describe call or clock advance to restore a surviving guest's listener.

Evidence: `scripts/aws/ec2_instance_metadata_probe.py`,
`instances_metadata_{depth,identity,empty_tags,tag_convergence,secondary}{,_handoff}.json`.
All five probes verified termination and removal of owned disks, profiles, roles,
SSH key pairs and networks; standing account defaults were unchanged.
`scripts/aws/ec2_instance_tag_publication_probe.py` and
`instances_tag_publication{,_handoff}.json` additionally retain 26 guest samples
covering update/add/remove, disabled updates, re-enable and empty tags.
The actual Ubuntu workflow verified those settled HTTP outcomes and pending
metadata-option acceptance through the executable.
Primary contracts: [metadata retrieval](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html),
[metadata categories](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html),
[block-device metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-block-device-mapping.html),
[guest identification](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html),
[tag metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/work-with-tags-in-IMDS.html)
and [metadata-option changes](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceMetadataOptions.html).

### Intrinsic instance credentials

`identity-credentials/ec2/` exposes text/plain directories, `info`, and
`security-credentials/ec2-instance`. The instance's intrinsic identity is
independent of an attached instance profile. Its real signing material lives in
the shared IAM credential repository; EC2 retains one reference per IMDS delivery
version. Issuance and its reference commit in the existing shared transaction. No IAM
role record, trust policy, AssumeRole call or second credential store is created.
Schema 200 retains the reference and independent info publication timestamp;
schema 201 retains the credential's typed public source scope.

Native STS `GetCallerIdentity` returns
`arn:<partition>:sts::<account>:assumed-role/aws:ec2-instance/<instance-id>` and
UserId `<account>:aws:ec2-instance:<instance-id>`. Intrinsic `GetSessionToken`
returns HTTP 403 `InvalidClientTokenId`. SQS returns HTTP 403
`UnrecognizedClientException` even under an explicit account resource-policy
grant; the same grant authorizes the distinct attached-profile credentials.
Ordinary IAM grants cannot turn intrinsic credentials into general-purpose
role sessions.

CloudTrail uses the native public issuer `role/aws:ec2-instance`, issuer ID
`<account>:aws:ec2-instance`, and `inScopeOf` identifying the exact EC2 instance.
Attached-profile credentials also retain their captured EC2 source scope.
These fields survive credential storage and controller restart; they are not
inferred from an HTTP caller's claimed ARN.

Six-hour validity with replacement on expiry is local policy, not an established
AWS lifetime/rotation distribution. Native keys changed during a first boot;
no causal relationship to profile attachment or fixed interval was established.
Native info `LastUpdated` differs from launch and credential timestamps and can
move backwards. Local admission initializes its independently retained timestamp
from service time without claiming AWS timestamp equivalence or stability.
Long-lived rotation, prior-key validity across lifecycle changes, info refresh,
and documented Instance Connect/GuardDuty/SSM/Lambda Managed Instances/AgentCore
consumers remain open.

Evidence: `scripts/aws/ec2_instance_identity_probe.py`,
`instance_identity_credentials{,_handoff,_audit}.json`, including eight exact
native STS/CloudTrail request-ID joins. Earlier private-transport failures remain
separate network evidence, not authorization denials; owned resources were
cleaned up after every capture. An actual Ubuntu/SQLite executable workflow
verified intrinsic STS identity, both native denial codes, bad-signature rejection,
profile grant independence, native-shaped CloudTrail issuer/source scope, frozen-
clock controller restart, old-token expiry/reissuance, and a new guest boot
preserving the principal. Primary contract:
[instance identity roles](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#ec2-instance-identity-roles).

### IMDS credential delivery versions

Validated metadata-token presence selects v1 or v2; the instance's `HttpTokens`
setting does not assign a version to credentials. Both intrinsic and attached-
profile identities receive distinct access keys, secrets and session tokens for
the two protocols, while retaining the same principal identity. Requiring v2
rejects new tokenless metadata reads with 401; it neither revokes nor relabels
previously delivered v1 credentials.

The trusted issuer retains `ec2:roledelivery` in the existing IAM session context,
with the single value `1.0` or `2.0`. The shared evaluator consumes it across
services. A native SQS resource grant plus an identity-policy
`NumericLessThan ec2:RoleDelivery 2.0` denial rejects v1 while allowing v2.
Intrinsic credentials retain their separate service restrictions in both versions.
CloudTrail emits the corresponding string `sessionContext.ec2RoleDelivery`, not
a value inferred from current instance options or caller-supplied HTTP fields.

Schema 202 retains independent references for each version; secrets remain in
IAM. Legacy unclassified references are replaced on retrieval rather than
retroactively assigning a version to existing credentials. Schema 203 retains
the audit field with the shared API event, preserving historical context across
restart. No additional issuer, credential cache or event-history store is added.

Evidence: `scripts/aws/ec2_credential_delivery_probe.py` and
`credential_delivery_versions{,_handoff,_audit}.json` retain three optional
samples, the required-v2 transition and 18 exact STS/CloudTrail request-ID joins.
Owned native resources were removed and standing EBS/KMS/IMDS defaults were
unchanged. Memory/SQLite fixtures replay the permission and audit contrasts.
Native direct SQS JSON returns `AccessDeniedException`; query-compatible SDKs
retain `AccessDenied` through the protocol's error header.

An actual Ubuntu 24.04 guest running AWS SDK for Go v2 verified the same policy
boundary, distinct material, retained v1 use after requiring v2, schema 201→203
upgrade, frozen-clock controller restart and retained audit history without a
guest reboot. Advancing service time seven hours expired both old variants;
fresh delivery restored their respective contexts. This proves local expiry
handling, not AWS's unpublished rotation distribution. Primary contract:
[transitioning to IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html).

### Instance-role credential origin

Attached-profile issuance retains `ec2:SourceInstanceARN`,
`aws:Ec2InstanceSourceVpc` and `aws:Ec2InstanceSourcePrivateIPv4` in the existing
trusted IAM session context. The typed EC2 record supplies the issuing instance,
VPC and primary private IPv4; the shared evaluator consumes their canonical
lowercase keys. Caller-supplied service context cannot manufacture these claims.
Both IMDS versions retain the same origin and their separate delivery versions.
Previously issued credentials are not retroactively relabeled.

These are credential-origin claims, not request-network claims. They do not
populate `aws:SourceVpc` or `aws:VpcSourceIp` for public-endpoint requests.
Intrinsic credentials are not assigned unobserved origin attributes.
No additional credential authority, cache or SQL schema is introduced.
Primary contract: [IAM global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html).

`scripts/aws/ec2_credential_origin_probe.py` reuses the identity probe's CLI and
owned-resource lifecycle. `credential_origin_context{,_handoff}.json` retains
three complete v1/v2 samples: twelve queues distinguish matching and mismatched
instance/VPC/private-IP conditions, absent versus present endpoint keys, and
positive permission controls. Native SQS rejected `ec2:SourceInstanceARN` in a
queue resource policy; that separate admission capture is retained in
`credential_origin_queue_policy_rejection{,_handoff}.json`. The completed matrix
therefore uses identity-policy conditions. All owned AWS resources were removed;
standing EBS/KMS/IMDS defaults were unchanged.

Memory/SQLite fixtures replay the matrix before and after reopen. An actual
Ubuntu 24.04 Go SDK guest enforced the same conditions with current and cached
v1/v2 credentials across controller restart, retaining its boot ID and signing
material. `testdata/integration/ec2_credential_origin.json` retains that proof
and a teardown diagnostic: native scope collection raced inspect-then-stop.
The shared EC2/ECS stop boundary now accepts observed collection after an ordinary
command failure, while preserving transport and helper-cleanup failures.
Native busctl diagnostics go to captured stderr. A separate real-systemd smoke
verified normal stop, collection, surviving-unit failure, helper-cleanup failure
and ownership rejection; the original guest diagnostic remains in the evidence.

### Instance identity signatures

The identity document and all signatures consume one retained-instance JSON
projection. IMDS exposes `document`, `signature`, `pkcs7` and `rsa2048` as
text/plain. AWS's three formats are implemented with real cryptography:

| IMDS leaf | Signature | Local public certificate |
| --- | --- | --- |
| `signature` | Raw RSA-1024/SHA-256 | `rsa.pem` |
| `pkcs7` | Content-bearing DSA-1024/SHA-1 CMS | `dsa.pem` |
| `rsa2048` | Content-bearing RSA-2048/SHA-256 CMS | `rsa2048.pem` |

Public certificates are exported at
`/_stackd/ec2/identity-certificates/{dsa,rsa,rsa2048}.pem`. Private keys remain in
the typed repository and SQLite schema 199. These are **local emulator
authorities, not AWS certificates**. Consumers must obtain and explicitly trust
them through their operator; consumers pinned to AWS's certificates cannot accept
these signatures. Prefer `rsa2048` for new local consumers; the weaker legacy
algorithms exist solely for native-format interoperability.

CMS contains the exact document, signed attributes and signer identification,
but no embedded certificates. On-demand signing uses service time and may produce
different signature bytes across reads; the native fixture's repeated signatures
were stable. Keys survive SQLite/controller restart, while instance stop/start
updates the document's pending time.

Independent OpenSSL verification covers the locally re-signed, account-anonymized
capture derivatives and runtime-generated local formats. It rejects changed
documents and wrong trusted certificates and recovers byte-identical CMS
documents. Original AWS-signed documents are retained only in the private history
backup; the published derivatives contain explicit local fixture certificates
and do not authenticate against AWS certificates. The actual encrypted Ubuntu workflow
verified all three exported authorities before/after controller restart and
after guest stop/start, preserving certificates across those transitions.
Evidence includes `instances_metadata_identity{,_handoff}.json` and the public-only
`instance_identity_certificates.json`. Primary contracts:
[identity documents](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html),
[verification](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html)
and [regional AWS certificates](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html).

### Instance-profile associations

`AssociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation`,
`DisassociateIamInstanceProfile` and `DescribeIamInstanceProfileAssociations`
use scoped typed associations and schema 198, the existing IAM owner and its
credential repository. Replacement allocates a new association ID; replacing with
the same profile preserves it. Retiring an old association cannot clear a newer
replacement. Empty profiles and denied role trust remain distinct: fresh empty
profiles expose no IAM subtree, while denied trust produces the native
`AssumeRoleUnauthorizedAccess` credential document and pending association.

Authorization checks instance conditions/tags, the current `ec2:InstanceProfile`,
requested `ec2:NewInstanceProfile`, PassRole and `iam:PassedToService`.
Native PassRole `iam:AssociatedResourceArn` uses the regional `instance/*` context,
not the specific instance ID. Disassociation requires no PassRole. ARN takes
precedence over a conflicting profile name. Native-backed model corrections add
the four Query DryRun members absent from SDK models and move page-size admission
to the service: positive sizes including 1 and 1001 are accepted.

Association transitions use a local one-second deadline and failed credential
delivery retries after five seconds, not measured AWS latency guarantees.
EC2 retains only the issued credential ID, never a second secret catalog.
EC2 issues a fixed 6h35m service session independently of the IAM role's
`MaxSessionDuration`. Four native deliveries had this interval between
`iam/info.LastUpdated` and credential expiration; that observation does not
establish AWS's complete lifetime distribution. Ordinary user/federated STS
assumptions still enforce the role limit.

Profile publication separately refreshes after 55 minutes, keeping membership
rechecks within the documented one-hour window. This is a local rotation policy,
not measured native rotation timing. Previously delivered credentials remain
valid until their own expiration; profile, trust and association changes do not
revoke them. The persisted credential reference is authoritative, without a
second EC2 session cache. Empty profiles and trust rejections commit their
delivery outcome instead of aborting the enclosing EC2 transaction; credential
issuance and audit failures still roll back writes.

Long-lived native rotation/publication timing, opaque association-ID admission
and exact pagination-token binding remain incomplete.

Evidence: `scripts/aws/ec2_instance_profiles_probe.py` and
`instance_profiles{,_lifecycle,_transitions,_authorization}.json`. The transitions
capture completed the full scenario; earlier failed attempts retain their errors
and verified cleanup. Signed Go SDK v2 fixtures exercise memory and SQLite reopen.
The actual Ubuntu workflow exercised all four operations, profile A/B credentials
with different S3/EC2 allows and denials, surviving guest/session identity after
controller restart, and removal of IMDS credentials after disassociation.
A further actual guest workflow verified role removal publication within an hour,
native-shaped denied-trust metadata and recovery, overlapping valid credentials
beyond the one-hour role limit, and rejection at the old credential's own expiry.
Memory/SQLite SDK regressions cover empty-profile completion and denied-trust
recovery without poisoning the shared transaction.
Primary contracts: [instance profiles and roles](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html),
[credential delivery](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)
and [service session duration](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage-assume.html).

### Console screenshots

`GetConsoleScreenshot` captures the actual QEMU VGA framebuffer through QMP,
not serial text or a stored/generated picture. Headless guests have an explicit
graphics device. `WakeUp` sends a real Shift press/release; it does not start or
resume a VMM. Go image codecs produce JPEG, with borrowed image scaling only
when needed to meet the documented 100-kB response limit.

IAM instance/tag/type/Region conditions and DryRun use the current resource
snapshot. Related IAM reads reuse its transaction context; native capture runs
outside the transaction under the existing lifecycle owner. Native pending
requests reject with `UnsupportedOperation`; stopped/terminated requests return
`InvalidInstanceID.NotFound` without a message. Running/stopping capture remains
available while the native framebuffer exists. Unsupported Regions and hardware
reject rather than returning a substitute image.

CloudTrail records the native `GetConsoleScreenshotRequest` envelope, omits
DryRun, marks the operation read-only and excludes the sensitive response.
Evidence: `scripts/aws/ec2_console_screenshot_probe.py` and
`console_screenshot{,_boundaries}.json`; both bounded native captures verified
cleanup and left account defaults unchanged. Native serial activity did not
change the retained bootloader screenshot, so those captures do not prove
native console-unblank behavior.

The actual Ubuntu/SDK workflow changed the guest's virtual console from blue
to red and recovered corresponding JPEG pixels. A guest evdev reader observed
the requested keyboard press/release. Capture survived controller restart with
unchanged manual time and guest boot identity. A signed-SDK memory/SQLite
regression covers cross-service authorization without a second transaction.
Primary contracts: [API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetConsoleScreenshot.html)
and [screenshots and limitations](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/troubleshoot-unreachable-instance.html#instance-console-screenshot).

## Next service priority

EC2/VPC and related services remain an active implementation priority.
Independently owned Glue/Athena and ECR/CodeBuild workstreams proceed in parallel;
EKS follows the analytics application path.
Build outward from the existing networking
owner: real instance/image/key-pair lifecycle, ENI attachments and instance
profiles/IMDSv2; EBS volumes/snapshots and KMS; routing, security groups, NACLs,
DNS/DHCP, public/elastic addresses, NAT and VPC endpoints. Extend dependent
load-balancing, Auto Scaling, Systems Manager and DNS services as runnable
workflows require them. Every operation in the selected services' pinned Smithy
models remains inventoried; this ordering is not a reduction to instance CRUD.

### Execution and shared compute ownership

QEMU/KVM is the selected EC2 backend for firmware-booted Linux HVM images.
It runs a guest kernel; a Docker container or separately supplied kernel/rootfs
is not an invisible replacement for an AMI. EC2 owns AWS instance/image intent,
networking and lifecycle; EBS owns disk contents. Existing Lambda/ECS container
execution is unchanged.

`compute/ec2` manages one external QEMU process per running instance through
its private QMP socket. The current backend presents x86_64 Q35, NVMe disks and
virtio networking, with explicit BIOS or UEFI firmware. Images must supply those
drivers. It does not claim Amazon NVMe/ENA hardware identity, Graviton, GPUs,
Nitro enclaves, instance-store disks or Windows support. Native capability
failures remain errors; there is no alternate backend fallback.

The CLI enables this dependency with `-ec2-state-directory`, a SQLite database
and local rootful `-docker-host`. QEMU tools, dnsmasq and its native `dhcp_release`
utility (`dnsmasq-utils` on Ubuntu) must already be installed.
`-ec2-bios`, `-ec2-uefi-code` and `-ec2-uefi-vars` select operator-owned firmware;
no runtime/image download happens implicitly. `-ec2-dns-upstream` explicitly
configures forwarding; without it the guest resolver serves local names only.
The exercised SeaBIOS input is `/usr/share/seabios/bios-256k.bin`; the smaller
installed `bios.bin` did not progress to disk reads in the observed NVMe setup.

Prepare image mounts in a private mount namespace so they do not propagate into
host services. A chroot or mount namespace alone does **not** isolate networking:
start guest daemons only inside the actual VM or a separate network namespace.
In particular, Docker's `--bridge=none` can delete `docker0` in its current
network namespace; it is not protection for the host bridge. Keep package
installation from autostarting services, and verify runtime prerequisites in the
booted guest rather than treating an offline install as runtime proof.

The selected state directory must fit the native Linux Unix-socket limit:
the full generated `vm-<digest>/qmp.sock` address may contain at most 107 bytes,
not 107 Unicode characters. `NewQEMU` derives the path from the same naming
owner and rejects overlong configurations before creating native runtime state.
There is no hidden alternate directory or retry fallback. A real 108-byte
configuration left an instance pending, its EBS disk attaching and its console empty;
the retained [failure and exact recovery](../testdata/aws/ssm/managed_execution_local_qmp_path_failure.json.gz)
includes the original Go dial error and corrected CLI admission failure.

The injected instance contract separates prepare/reopen, observation, lifecycle,
disk attachment, CPU accounting/limits, console output and owned cleanup.
QMP/process observations, not desired state, determine native outcomes.
Reopening the controller does not reboot a surviving guest. Guest execution and
operating-system time remain outside deterministic service time.

`compute/network` owns shared bridge and packet-policy mechanics. EC2 remains
authoritative for VPC/subnet/ENI addresses, DHCP, routes, security groups and
NACLs; ECS and guests consume this state rather than reimplementing it.
Guest retirement sends the owning MAC/address's native DHCP release before
returning the address to EC2. Deleting a static reservation and reloading dnsmasq
does not remove its infinite in-memory lease; that left replacement guests
without IPv4 during actual refresh rollback. The native daemon remains the lease
owner; Go does not add another lease store or restart unrelated guests' DNS.
The firewall admits those releases only through host loopback to the owning
gateway's DHCP port. It must not assume the gateway is also the packet's source:
an actual host-routed release used the host's uplink address. An isolated native
dnsmasq/`dhcp_release` probe reproduced the dropped 576-byte packet under that
source restriction, then acknowledged the same address for a replacement MAC
after the loopback-only rule admitted release. Guest DHCP ingress restrictions
remain separate and unchanged.
Bridge cleanup observes native TAP ports as well as Docker endpoints. The
authorized IMDS path uses the existing instance/ENI owner, not a second IP
catalog. Docker supplies privileged host operations, not the guest kernel.
Lambda Runtime API/warm environments, ECS coordination and EC2 guest lifecycle
remain separate contracts. Dependencies are per-instance, with no global
registration or new plugin ABI.

Historical reference input: `clones/firecracker` revision
`8ff4940e6a723c541331e74c92cc2caeb26b6e31`, especially `README.md`,
`SPECIFICATION.md`, `docs/rootfs-and-kernel-setup.md`, `docs/network-setup.md`
and `src/firecracker/swagger/firecracker.yaml`. Upstream documents KVM,
file-backed block devices, network interfaces and explicit kernel/rootfs boot
inputs; this is not evidence of EC2 AMI or Nitro compatibility.

#### Linux hibernation

`HibernationOptions.Configured` is admitted at launch, using instance-type
capability and encrypted EBS-root prerequisites. It cannot be enabled afterward.
`StopInstances(Hibernate=true)` uses the existing retained instance intent,
effect and deadline. The runtime sends QGA `guest-suspend-disk`; Linux writes RAM
to root-volume swap and powers off. Starting uses a fresh firmware-booted QEMU
process and the guest's configured resume path. There is no host VMState image,
in-process handler substitute or persisted RAM-attestation header.

The image must supply `qemu-guest-agent`, enabled suspend-to-disk support, enough
root-backed swap for RAM, and kernel/initramfs resume configuration. The exercised
custom Ubuntu 24.04 image uses an 8-GiB root, a 1.5-GiB swap file, its root UUID and
physical `resume_offset`, rebuilt initramfs/GRUB, and `nokaslr`. Those are explicit
image prerequisites, not guest modifications silently performed by EC2.
Hibernation readiness is observed through the guest-agent channel. An early
request returns `UnsupportedOperation`; Auto Scaling retries through its existing
clock-owned reconciliation. An admitted request that cannot complete may fall
back to an ordinary stop, as AWS documents.

Configured instances stopped normally can change instance type; a hibernated
instance cannot, because resumption depends on its saved hardware/RAM state.
The Q35 layout packs the 28 reserved disk root ports into multifunction slots,
leaving room for VGA, networking and the hibernation agent without reducing disk
attachment capacity.

Native sources `testdata/aws/ec2/hibernation*.json` capture launch/admission,
readiness, type mutation and actual AL2023 RAM continuity across hibernate/resume,
contrasted with an ordinary cold stop. The captures retain owned-resource cleanup.
Primary contracts: [hibernation prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-prerequisites.html),
[hibernate an instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-instances.html)
and [resume an instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-resuming.html).

#### Exercised guest execution boundary

A local investigation booted the official
[Firecracker v1.17.0 x86_64 release](https://github.com/firecracker-microvm/firecracker/releases/tag/v1.17.0)
with [the upstream 6.1.186 guest kernel](https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260923-6f82ac4cf331-0/x86_64/vmlinux-6.1.186).
The guest used one vCPU, 128 MiB RAM and a 64 MiB writable ext4 disk containing
a temporary statically compiled Go PID 1. No host networking configuration was
changed and no network device was attached.

- Configuration through `PUT /machine-config`, `/boot-source`, `/drives/rootfs`
  and `/actions` (`InstanceStart`) returned 204. The real guest reported PID 1,
  kernel `6.1.186` and one CPU on its serial console.
- `PATCH /vm` paused and resumed the VM; `GET /` reported `Running`, `Paused`,
  then `Running`.
- The guest wrote and synced a boot counter. A new VMM process booting the same
  disk observed counter 2, demonstrating disk retention across process replacement.
- Guest `LINUX_REBOOT_CMD_POWER_OFF` printed `System halted` but left the VMM
  alive and its API state `Running`. That process required host-side termination.
- With kernel Ctrl-Alt-Delete reboot enabled by PID 1, `SendCtrlAltDel` returned
  204, the guest printed `Restarting system`, and the VMM exited with code 0.
  This proves that configured reboot path, not general graceful guest shutdown.

Consequently VMM `Running` is not guest health or proof of completed shutdown.
Instance-initiated shutdown/reboot and host-requested stop need an explicit
compatible-image contract and observed outcomes. This investigation does not
establish arbitrary HVM AMI boot, jailer isolation, networking, IMDS, hotplug,
snapshots or EC2 API behavior. QEMU/KVM supersedes this direct-kernel experiment
as the selected implementation; the observations above remain bounded evidence.

#### Retained integration boundaries

EC2 reuses its transaction/audit wrapper, ENI allocation, IAM evaluator and typed
memory/SQLC repositories. Schemas 191/192 retain AMIs, instances, reservations,
credit accounting and instance identity on ENI attachments; schema 195 owns
image-creation work. API intent and events commit together; IAM/KMS commands join
the shared transaction domain. Native VM, disk and network effects run outside it.

EBS snapshot layers remain immutable typed encrypted blocks. After hydration,
the native qcow2 disk becomes the sole mutable volume-byte authority; schema
193 retains its path. Superseded SQL blocks are removed unless an admitted
standalone snapshot still owns their historical capture edge. Schema 238 releases
that pin after transfer or discard. Schema 194 retains native snapshot work until
its captured bytes have become ordinary immutable snapshot blocks. No plaintext
disk mirror, resource ledger or duplicate attachment catalog is introduced.

Hydration and snapshot publication each hold one native disk session. This
avoids unlocking LUKS once per 512-KiB block. A real QEMU smoke wrote and read
32 distinct sparse block patterns plus a zero hole in both plaintext and LUKS
disks. Encrypted write/read phases took about 2.6/2.4 seconds each, versus
2.4 seconds merely opening a LUKS disk for two writes in the original path.
Only transient anonymous memory files carry plaintext between Go and QEMU.

#### Exercised firmware-booted workflow

The actual CLI, signed boto3 calls and SSH exercised the official
[Ubuntu 24.04 server cloud image](https://cloud-images.ubuntu.com/releases/noble/release/)
release `20260911`, kernel `6.8.0-139-generic`, through BIOS boot and NVMe root/data
devices. The disk was imported through EBS direct APIs, not injected into the
runtime behind its control plane.

- Cloud-init retrieved the generated SSH public key and user data through required
  IMDSv2. Tokenless access returned 401; guest-vended profile credentials signed
  a real STS request with the instance's assumed-role identity.
- The controller restarted without changing guest boot ID. Stop/start produced
  a new boot ID while retaining attachments and written root/data bytes.
- A KMS-encrypted volume containing distinct snapshot block patterns was attached
  to the running guest, read and modified there, snapshotted through EC2 and
  detached. EBS direct reads recovered the exact guest-written bytes.
- `CreateImage(NoReboot=true)` captured a running encrypted guest without changing
  its boot ID. Default `CreateImage` observed graceful shutdown and booted the
  source again, including a concurrent metadata-options mutation.
- After terminating the original instance, a new instance booted the derived AMI
  and recovered both root and data markers. Disks were selected by EBS serial,
  never by unstable Linux NVMe enumeration order.
- EventBridge delivered all six lifecycle states to SQS. CloudWatch returned
  positive CPU-credit usage from measured execution. CloudTrail delivered actual
  S3 gzip management records, redacted user data and EC2-scoped KMS identities.
  A 90-second audit wait was insufficient for the existing five-minute batching
  policy; verification completed after retained-database restart and delivery.

The same imported Ubuntu image also passed a Go SDK v2 UEFI lifecycle using
`OVMF_CODE_4M.fd` and `OVMF_VARS_4M.fd`. SSH observed `/sys/firmware/efi`;
`RebootInstances` changed the guest boot ID, and stop/start changed it again while
preserving a root-file marker. Firmware flash is not an EBS attachment:
`TestQEMUUEFIDiskDiscovery` exercises real QMP discovery with OVMF and both known
and unknown NVMe devices. QMP's explicit device IDs and absolute QOM paths are
resolved according to the [native contract](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#object-QMP-block-core.BlockInfo).
Startup failures retain their native cause in structured controller logs;
bounded QEMU startup stderr survives automatic resource cleanup.

Earlier input failures remain useful boundaries: CirrOS's initramfs lacked an
NVMe root driver, and Ubuntu Minimal `20260905` contained a microcode-only initrd.
Neither was treated as a successful persistent-root guest. The runtime did not
substitute virtio block devices or direct kernel boot to make those images pass.
`TestQEMUGroupedBackupSnapshotBytes` also runs actual QMP backup operations on
plaintext/encrypted disks and verifies snapshot bytes after deleting their sources,
without needing a guest image, KVM or privileged networking.

#### Retained CPU-credit transitions

Stopped-instance type changes preserve earned credit instead of rejecting a
cross-family or reduced-cap transition. The original stopped-retention deadline
survives repeated resizes and fixed-performance detours; resizing does not renew
it. Existing balances above the destination's accrual cap remain spendable, while
new accrual is limited by that cap. Fixed-performance execution does not accrue
burstable credits or retain the prior burstable CPU quota. These rules follow the
[credit lifecycle](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-credits-baseline-concepts.html)
and [type-change contract](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-performance-instances-how-to.html);
they do not introduce a second balance or resize ledger.

`scripts/aws/ec2_instance_credits_probe.py --transitions` captured one owned
Standard guest through T3 micro, T3a micro, stopped M5/T2 detours and T3 nano.
`instance_credits_transitions_owned.json` retains the actual API and console
observations; `instance_credits_transitions_metrics.json` retains the post-cleanup
CloudWatch harvest. Balances of 1.3575797 and 1.82781395 exceeded conservative
zero-reset upper bounds of 0.47281393 and 0.131787365 respectively. This excludes
a complete reset on those observed transitions, not partial loss or exact
nanosecond conservation. Immediate stopped type descriptions briefly lagged
successful changes; later running observations confirmed the destinations.
All owned resources were cleaned up. The earlier setup-only failure is retained
separately and did not launch a guest.

The separate `--unlimited-detour` capture, retained as
`instance_credits_unlimited_detour.json`, observed an Unlimited nano resized to
stopped M5 and back. Both explicit-ID discovery and the filtered default listing
continued to return Unlimited, including repeated observations 20 seconds apart.
A fixed-performance type therefore does not imply a Standard setting: discovery
reports the retained mode, while runtime accounting uses the active type.
The existing fixture replay failed against the old type-derived fallback and
passes with that fallback removed. The actual CLI/SQLite SDK workflow also
matched both projections through the same stopped detour. The native guest and
its dependencies were removed; account defaults were unchanged.

The actual local CLI/SQLite workflow accrued 287.8920154319333 credits from a real
Ubuntu guest under advanced service time, resized through T3a micro, booted M5
with 8,132,476 KiB guest-visible memory, and restarted as nano with 468,860 KiB.
The final guest produced its own changed framebuffer and a new boot ID.
After five more service minutes, CloudWatch reported 287.85848027816667 credits,
still above nano's 144-credit accrual cap. Real execution consumed credit;
the resize did not clamp the retained balance. The guest was then terminated.

Fixture-based transition tests cover original retention expiry and above-cap
spending/accrual. Native above-cap conservation, the seven-day expiry boundary,
running T2/fixed-performance detours and T4g/T8i transitions remain unmeasured;
local execution and documentation-derived cases do not establish those native
boundaries.

#### Native CPU and network monitoring

`CPUUtilization`, `NetworkIn` and `NetworkOut` come from the actual guest
execution boundary. CPU uses the existing QMP-identified vCPU `schedstat`
measurements divided by elapsed native time and the admitted CPU count.
Service-clock advancement schedules observations; it does not manufacture CPU
usage, traffic or missing historical samples. Host TAP transmit bytes are guest
inbound bytes, and host TAP receive bytes are guest outbound bytes.

Basic monitoring publishes five-minute periods; detailed monitoring publishes
one-minute periods. CPU retains measured sample count, sum, minimum and maximum;
network bytes form one scalar period total, not a per-minute average. Instance,
Auto Scaling group, and detailed-only image/type rollups use distinct dimension
sets. Group detach/reattach retains separate group contributions without splitting
the unchanged instance network total. Counter cursors and unpublished statistics
share the EC2/CloudWatch transaction and survive SQLite reopen. Stop and image
capture checkpoint retiring counters before native destruction; failed cleanup
does not erase the last measurement or publish a partial period twice.

`MonitorInstances`, `UnmonitorInstances` and launch-time `Monitoring.Enabled`
configure that publisher. Native fixtures
`testdata/aws/ec2/instance_monitoring_owned.json` and
`instance_monitoring_edges.json` cover detailed launch, duplicate IDs, mixed-ID
atomicity, lifecycle states, IAM and DryRun precedence. The owned AWS instance,
root volume and networking were removed. Local mode changes converge immediately
to `enabled`/`disabled`; AWS's observed `pending`/`disabling` subscription timing
is not simulated. The native
[performance harvest](../testdata/aws/autoscaling/instance_performance_native.json)
records basic CPU sample count two versus one network period sample; it does not
establish complete timing or Auto Scaling membership-transition equivalence.

The [actual firmware-guest capture](../testdata/integration/ec2_performance_verified.json)
records 33,660,780 inbound and 8,488,541 outbound bytes after a 32-MiB upload and
8-MiB download. The basic network period has sample count one; the CPU period
contains three measured observations. A controller restart retained the same
guest boot and unpublished counters. Detailed monitoring measured approximately
50% CPU under a real busy guest process, and the group metric drove target
tracking from desired capacity one to two without customer `PutMetricData`.
Stopping and starting the original instance produced a different guest boot ID.
All owned resources were cleaned up. That capture observes the second member
being admitted; it is not evidence that the second guest served application traffic.

The [completed scale-out capture](../testdata/integration/ec2_performance_scaleout_verified.json)
continues through both members becoming healthy and `InService`, then reads actual
HTTP responses from both guests with distinct boot IDs. Its group CPU period
contains observations from both guests. Cleanup completed for this run as well.

This is native local measurement, not a claim of identical AWS host overhead or
all EC2 performance metrics. Disk, packet and remaining EBS performance metrics
remain unfinished. Primary contracts:
[available metrics and dimensions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html),
[monitoring modes](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html),
and [Auto Scaling instance monitoring](https://docs.aws.amazon.com/autoscaling/ec2/userguide/enable-as-instance-metrics.html).

#### Native guest status checks

`DescribeInstanceStatus` projects retained observations, not the VMM's running
flag. The [AWS check contract](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-system-instance-status-check.html)
separates host infrastructure, guest ARP reachability and attached-volume I/O.
The native adapter observes the live QMP state and bridge/TAP attachment, sends
actual ARP probes, and reads every attached NVMe through the live QEMU NBD
export. It does not infer success from a neighbor cache, SSH, an open disk file
or security-group rules. Firmware flash is excluded from disk discovery.
Observation-tool/control failures produce `insufficient-data`, not fabricated
healthy results or disk impairments.
Attached-EBS checking and its metric apply only to Nitro instance types, selected
from the authoritative instance-type catalog. Xen types omit that result and
aggregate only system/instance checks; they do not perform unused disk probes.

Schema 197 retains typed check results, continuous-failure origins and the last
observation minute. Native effects run outside the transaction; the generation
check, observation and scoped CloudWatch metric admission commit together.
Recovery removes `ImpairedSince`; continuous failure preserves it across
controller restart. Entering running initializes checks again. Nonrunning
instances have `not-applicable` system/instance status without details, and omit
attached-EBS status. The default running-only selection precedes pagination.

One-minute checks use service time. Advancing time samples the real guest at
execution, not imagined historical states. Known results contribute Count
samples to `StatusCheckFailed`, `_System`, `_Instance` and `_AttachedEBS` through
the existing service-metric boundary, independently of detailed monitoring.
Initialization and unavailable observations do not invent zero-valued metrics.
The current three-check aggregate follows the primary documentation; isolated
attached-EBS impairment and its aggregate effect have not been captured on AWS.

Native evidence in `testdata/aws/ec2/instance_status*.json` includes initialization,
actual guest NIC/ARP loss, recovery, stopped/terminated projections, minute
metrics and request admission. `scripts/aws/ec2_instance_status_probe.py` captures
the Nitro workflow. An initial capture's datetime-printing failure interrupted observation;
cleanup completed, and a sequential replacement captured recovery. Both guests
and their owned dependencies were removed without changing account defaults.
The replacement restored its NIC at 10:05:42Z; the API first published impairment
at 10:06:39Z with `ImpairedSince=10:04:00Z`, then recovered at 10:08:42Z.
These are observations, not fixed publication-delay guarantees. Local sampling
does not reproduce that delayed/transitional AWS publication sequence.
The separate `instance_status_xen.json` capture retains its probe source and
observed a healthy native `t2.nano` without attached-EBS status. Its owned guest,
disk, ENI, network and IAM dependencies were removed and account defaults stayed
unchanged. All four CloudWatch queries were empty in that capture's observation
window; those empty results alone do not establish metric applicability.

The actual CLI/Go SDK v2 workflow booted the imported Ubuntu image with a
KMS-encrypted root. It verified healthy checks with no SG rules, actual ARP loss
and recovery, preserved failure origin after SQLite/controller restart, host
TAP disconnection, and a QEMU-injected NVMe read EIO. CloudWatch returned the
corresponding exact minute vectors: aggregate/system/instance/EBS
`1/0/1/0`, `1/1/1/0` and `1/0/0/1`. Stop/start reinitialized observations;
stopped and terminated instances omitted attached-EBS status.
A separate fresh `t2.micro` launch then verified healthy/failed/recovered guest
checks, Go SDK v2 omission of attached-EBS status, and metric values
`1/0/1` with no attached-EBS sample. Its stop/start cycle reinitialized checks.
This exercises Xen-type API applicability on the configured QEMU backend,
not physical Xen hardware emulation. A signed executable replay also matched
35 retained native status-admission cases, including page sizes above 1,000.

Admission fixtures cover raw 100-ID limits before deduplication, DryRun
precedence, status-specific filters, minimum page size and case-sensitive
lookup. Native AWS accepts some one-to-eight-digit short IDs and rejects some
lexically valid 17-digit IDs. The opaque long-ID encoding is not implemented;
there is no blacklist standing in for that contract.

## Ownership and retention

`internal/services/ec2` owns resource commands and IAM decisions. Resource keys
include partition, account and region. Its repository interface returns detached
typed records; the memory implementation shares the coordinated memory domain,
and SQLC SQLite adapters use service-owned resource/child tables. Resource
changes, default-resource creation and audit events share one transaction.

Creating a VPC creates its real default security group, main route table, default
ACL and a discoverable regional DHCP-options record. Subnets bind actual zone
identities and default routing/ACL associations. Deletes enforce the implemented
dependency constraints. IPv4 ENIs reserve and release actual subnet addresses.
EC2 guests and the separate [ECS runtime](ecs.md) consume the same networking
authority through their respective native attachments.

Lambda capacity launches enter the ordinary EC2 transaction under the current
assumed operator role. A private service marker supplies
`ec2:ManagedResourceOperator=scaler.lambda.amazonaws.com`; public `Operator`
input cannot claim that authority. The initial instance record retains the
capacity-provider ARN and guest-generation client token, and discovery projects
the managed operator across SQLite restart. Termination requires the current
`AWSServiceRoleForLambda` session and exact provider-owned instance IDs. A mixed
request cannot terminate a customer instance or partially change the managed
instances. Lambda retains provider-incarnation-to-guest membership; EC2 retains
the immutable resource ownership. The [Lambda linked-role contract](https://docs.aws.amazon.com/lambda/latest/dg/using-service-linked-roles.html)
and [managed policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSLambdaServiceRolePolicy.html)
define the role and its managed-resource condition.

Lambda source ENIs use the same subnet allocator and native network specification
as other compute consumers. Their immutable mapping ARN is distinct from ECS task
ownership and mutable descriptions. Allocation retries return the exact retained
interface; creation tokens survive deletion to reject stale resurrection.
Selection/allocation, lookup/resolve and release evaluate current execution-role
Create/Describe/Delete authority, respectively. The Lambda adapter keeps its
function SourceARN for role trust while passing the mapping ARN as explicit EC2
ownership. Focused memory/SQLite coverage exercises policy revocation, role
recreation, restart recovery, wrong-owner/customer-ENI rejection and retained
deletion. A separate executable owner workflow exercised actual EC2/IAM commands,
SQLite reopen and managed launch dry-run authorization; guest execution and
packet transport remain the native consumers' responsibility.

Route-table and ACL creation tokens retain the admitted VPC and ordered tags,
not a digest of arbitrary resource JSON. Outcomes outlive resource deletion and
survive reopen. Native captures establish these distinctions:

- Identical requests return the same resource; changed VPC, changed/omitted tags
  and reordered tags reject with `IdempotentParameterMismatch`.
- Replay after deletion rejects rather than creating a replacement.
- Replay returns the original request tags without overwriting current tags.
  ACL replay includes current entries, including rules added since creation.
- Surrounding ASCII whitespace is trimmed. Whitespace-only tokens disable
  idempotency, allocate on every request and omit the response token. Explicit
  empty tokens fail. Nonblank tokens enforce the 64-character raw-input limit;
  whitespace-only input still bypasses idempotency above that length.

Token expiry is not established; local outcomes remain retained. Three native
case-only token variants repeatedly returned `InternalError`, despite the
[documented case-sensitive contract](https://docs.aws.amazon.com/ec2/latest/devguide/ec2-api-idempotency.html).
Their exact observations remain in the route-table fixture and are explicitly
skipped as unresolved native anomalies, not claimed conformant. Local keys follow
the documented case-sensitive contract.

### CloudFormation networking ownership

CloudFormation and Cloud Control ownership of VPCs, subnets, internet gateways,
route tables, NAT gateways, VPC endpoints, security groups and their rules, EIPs,
network ACLs, DHCP options and ENIs is a private typed claim on the native row
(schema 390), not a public tag. The claim and an immutable per-incarnation
creation receipt commit in the same EC2 transaction as the creating command and
only for identifiers that command allocated; idempotent token replay or a
supplied existing ID never adopts an unclaimed or foreign row. Rows that existed
before schema 390 stay unclaimed. Security-group creation also claims its
automatic egress rule; rules authorized under the group's stack mutation inherit
the group's claim.

Stack mutations run the ordinary command first, so current IAM decides before
the claim fence; a stale or foreign incarnation then rolls the whole transaction
back. Ordinary native and direct Cloud Control mutations retain an existing claim
without transferring it. Deletion removes the claim, a recreated row starts
unclaimed, and recovery of a deleted incarnation fails rather than recreating.
Creation recovery and ownership observation require the current resource-family
`Describe*` permission and are exact to partition, account and region.

Embedded relations (gateway attachments, routes, subnet route-table and ACL
associations, ACL entries, DHCP associations and EIP associations) use private
relation receipts: an immutable incarnation-to-edge admission plus the current
slot owner, both written atomically with the native edge. Routes use the
`<route-table-id>|<canonical destination>` slot. A direct EC2 change of the slot
invalidates the current owner. None of these flows writes, reads or requires
`stackd:cloudformation:*` tags; such keys are customer metadata and forging or
removing them changes no ownership. `TestCloudFormationNetworkOwnerPrivateClaims`
covers tag forgery/removal, lost replies, IAM revocation, scope isolation,
delete/recreate and SQLite reopen.

Interface endpoint admission accepts the official Kinesis Data Streams name
`com.amazonaws.<region>.kinesis-streams`. Reads retain that service name; Lambda
packet routing resolves it to the existing Kinesis owner without bypassing
endpoint policy or ENI/SG/NACL authority.

Endpoint service discovery and endpoint creation now share a service-owned
control-plane catalog, independent of enabled emulator providers.
`DescribeVpcEndpointServices` returns matching names and modeled service details,
including `com.amazonaws.us-east-2.bedrock-runtime` as an Interface service.
The retained documented subset covers S3, DynamoDB, EC2, EC2 Messages, ELB,
Kinesis Streams, CloudWatch/Logs, SQS, SNS, Lambda, SSM/SSM Messages, ECR,
API Gateway invocation, KMS, Secrets Manager, STS, CloudFormation, CloudTrail,
Step Functions, EventBridge and Bedrock Runtime. Service-specific regional SDK
metadata scopes ordinary services; Bedrock Runtime uses AWS's distinct runtime
region table, not its broader control-plane table. Commercial, China and
GovCloud service names are partition-scoped; Bedrock Runtime is not advertised
in China or in an undocumented runtime region. Unknown services and services
from another partition/region cannot create physical endpoint controls.

Discovery supports the documented owner, service-name, service-region,
service-type, supported-ip-address-types, tag-key and tag-key/value filters.
Filter values are ORed and filters are ANDed; AWS catalog services have no
customer tags. Names and pages are lexically ordered. Positive `MaxResults`
values are capped at 1,000; continuations bind the account, partition, region,
operation and selection. Explicit cross-region discovery/creation remains an
unsupported operation, not a fabricated regional listing. AZ names use EC2's
existing account-dependent physical-zone mapping; uncaptured noncommercial
AZ metadata, AWS-assigned service IDs and hosted-zone IDs are not invented.
Optional endpoint-policy support is returned where separately evidenced.
Discovery advertises the IPv4 controls implemented here, not IPv6 allocation.

Bedrock Interface endpoints use the ordinary typed endpoint row and actual
requester-managed subnet-capacity-reserving ENIs, VPC security groups,
validated IAM endpoint policies, private-DNS admission and deletion lifecycle.
The same memory/SQLite transactions retain those controls and immutable
CloudFormation incarnation fences. DNS options and private-DNS enablement are
durable; no public AWS hosted zone or AWS TLS endpoint is fabricated.
Existing native Lambda endpoint routing still reaches the actual stackd HTTP
service handler through the endpoint ENI and policy/SG/NACL authority. Adding
an EC2 endpoint does **not** enable an absent service provider: Bedrock invocation,
model inference and successful Bedrock runtime responses remain unsupported.

The combined executable SQLite workflow deploys the reported regional Bedrock
Interface endpoint through CloudFormation, verifies its SG-controlled ENI and
reopens with the same controls. Stack deletion leaves the endpoint's retained
`deleted` record with no interface IDs and no surviving VPC ENIs; the tombstone
is not an active endpoint. Memory/SQLite fixtures cover policy/DNS mutation,
incarnation fences and teardown. Endpoint-specific physical-zone availability
still requires calibration, as marked in `endpoint_services.go`.

Sources: [PrivateLink service names](https://docs.aws.amazon.com/vpc/latest/privatelink/aws-services-privatelink-support.html),
[regional endpoint metadata](https://github.com/boto/botocore/blob/develop/botocore/data/endpoints.json),
[EC2 endpoint discovery](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcEndpointServices.html),
[modeled service details](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ServiceDetail.html),
[Bedrock interface endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html)
and [Bedrock runtime regions](https://docs.aws.amazon.com/general/latest/gr/bedrock.html).
Source URLs and the regional metadata SHA-256 are retained in
`internal/services/ec2/endpoint_services.json`. This is source-based behavior,
not a claim of an exercised native AWS Bedrock endpoint capture.

For a local stackd CloudFormation control-plane reproduction, save the following
as `bedrock-endpoint.yml`, then run the commands below in `us-east-2`. It invokes
no models and creates no inference resources.

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.78.0.0/24
      EnableDnsSupport: true
      EnableDnsHostnames: true
  Subnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.78.0.0/25
      AvailabilityZone: !Select [0, !GetAZs '']
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      VpcId: !Ref Vpc
      GroupDescription: Bedrock endpoint HTTPS
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 10.78.0.0/24
  BedrockEndpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties:
      VpcEndpointType: Interface
      VpcId: !Ref Vpc
      SubnetIds: [!Ref Subnet]
      SecurityGroupIds: [!Ref Sg]
      PrivateDnsEnabled: true
      ServiceName: !Sub com.amazonaws.${AWS::Region}.bedrock-runtime
Outputs:
  EndpointId:
    Value: !Ref BedrockEndpoint
```

```sh
ENDPOINT=http://127.0.0.1:4567
aws --endpoint-url "$ENDPOINT" --region us-east-2 ec2 describe-vpc-endpoint-services \
  --service-names com.amazonaws.us-east-2.bedrock-runtime
aws --endpoint-url "$ENDPOINT" --region us-east-2 cloudformation create-stack \
  --stack-name bedrock-endpoint-control \
  --template-body file://bedrock-endpoint.yml
aws --endpoint-url "$ENDPOINT" --region us-east-2 cloudformation wait stack-create-complete \
  --stack-name bedrock-endpoint-control
ID=$(aws --endpoint-url "$ENDPOINT" --region us-east-2 cloudformation describe-stacks \
  --stack-name bedrock-endpoint-control \
  --query 'Stacks[0].Outputs[?OutputKey==`EndpointId`].OutputValue | [0]' --output text)
aws --endpoint-url "$ENDPOINT" --region us-east-2 ec2 describe-vpc-endpoints --vpc-endpoint-ids "$ID"
aws --endpoint-url "$ENDPOINT" --region us-east-2 ec2 describe-network-interfaces \
  --filters Name=description,Values="*${ID}*"
aws --endpoint-url "$ENDPOINT" --region us-east-2 cloudformation delete-stack --stack-name bedrock-endpoint-control
aws --endpoint-url "$ENDPOINT" --region us-east-2 cloudformation wait stack-delete-complete \
  --stack-name bedrock-endpoint-control
```

For stackd, add `--endpoint-url "$E"` to every AWS CLI command and configure
its local credentials/account. The native recipe and the newly extended
behavioral tests have not been executed as part of this implementation.

### CloudFormation compute ownership

Instances, launch templates and key pairs use the same private native claim and
immutable creation-receipt admission (schema 399). Volumes and deletion snapshots
use the authoritative EBS owner's private claim and receipt tables (schema 400),
not a second EC2 disk catalog. Volume attachments use the instance-owned mapping
and private native relation slot. Every recovery and ownership observation still
requires current native IAM; caller scope and resource incarnation must match.
Direct native and Cloud Control mutations retain, but cannot acquire or transfer,
an existing stack claim. Customer tags remain mutable and visible metadata.

A key pair's public CloudFormation physical identifier remains its key name;
private authority and creation recovery name its immutable native `KeyPairId`.
Generated private-key material is retained through the trusted transactional SSM
sink. A separate native receipt certifies that exact key's material retention;
imported or unclaimed keys never authorize SSM cleanup. Cleanup addresses only
the current authorized native key's exact parameter, never public tagged
discovery. A key deleted outside CloudFormation cannot authorize parameter
cleanup by a missing row or a newly recreated key with the same name.

Private ownership does not simulate runtime success. Instance launch still
requires the configured real native backend and volume creation retains the real
EBS engine prerequisites. Rejected native admission writes no private owner or
creation receipt; instance recovery rejects shutting-down or terminated rows.
The native instance tombstone retains its exact private claim solely for
authorized deletion stabilization. It is not a new creation admission, never
matches a different native instance ID, and cannot bypass native terminal-state
mutation checks. `TestCloudFormationInstanceTerminalClaimTransition` exercises
this native control-plane transition without claiming guest execution; the
real-backend prerequisite regression verifies rejected launches admit no claim.

## Internet gateways and routes

Gateway creation, discovery, attachment, detachment and deletion retain real VPC
relationships. Attached gateways block VPC deletion. Route creation/replacement
validates the destination and target; repeating creation with the same valid
target succeeds, while another valid target rejects with `RouteAlreadyExists`.
Local routes retain their mutation restrictions and supported `LocalTarget`
restoration behavior.

Detaching a gateway makes its routes `blackhole` without dropping the gateway ID.
Reattaching it to the same VPC restores `active`; deleting a detached gateway
leaves dangling blackhole routes. These transitions survive SQLite reopen.
An attached public address blocks gateway detachment until its ENI association is
removed. Other route-target families remain unsupported prerequisites, not
simulated connectivity.

## Public IPv4 and Elastic IPs

`AllocateAddress`, `DescribeAddresses`, `AssociateAddress`, `DisassociateAddress`
and `ReleaseAddress` use generated Query contracts, current shared IAM, and EC2's
existing transaction domain. Migration `225_ec2_public_network.sql` retains typed
address reservations, allocation/association identities and ordered tags. ENI,
instance, IMDS and native-packet projections read that one owner; there is no
parallel address catalog in QEMU or ECS.
The migration converts existing public-enabled task ENIs to distinct automatic
reservations across all stored scopes, while leaving private-only tasks unchanged.
The retained local evidence includes a real SQLite upgrade/reopen of that cutover.

New primary instance ENIs inherit `MapPublicIpOnLaunch` unless an explicit
`AssociatePublicIpAddress` overrides it. Existing ENIs do not acquire automatic
launch addresses. Automatic addresses have owner `amazon`, no customer allocation
or association ID, and do not appear in `DescribeAddresses`. Stop releases the
ephemeral address; start allocates a new one. An EIP replaces it; disassociation
restores a new automatic address only when that ENI's launch intent permits one.
EIPs retain their allocation across stop/start. Deleting an ENI, including a
delete-on-termination primary ENI, disassociates its EIP without releasing the
allocation. Preserved ENIs retain their own elastic association.

Association accepts the allocation/public-IP selector and a primary-instance or
ordinary ENI/private-IPv4 target. It requires an attached IGW, not an existing
default route. A same-target association retains its ID. Moving an already
associated EIP honors `AllowReassociation`; replacing the target's different EIP
leaves that former allocation available. Disassociation and release remove
exact current ownership, not another attachment's later mapping. Associated
nondefault-VPC release rejects with `InvalidIPAddress.InUse`; default-VPC release
follows the documented implicit-disassociation contract. Resource tags, address,
ENI/subnet and instance conditions use current IAM, including DryRun.
Elastic-address authorization includes current `ec2:AllocationId`,
`ec2:PublicIpAddress` and `ec2:Domain`, including tagging and DryRun. New launch
ENI authorization supplies `ec2:AssociatePublicIpAddress` only when the caller
explicitly supplies it: subnet-derived defaults do not invent the IAM key.
Consequently `BoolIfExists` can require an explicit false request even on a
private-by-default subnet; this is distinct from effective launch assignment.

Fresh native evidence:
`scripts/aws/ec2_public_addresses_probe.py`,
`testdata/aws/ec2/public_addresses{,_handoff,_contracts,_conclusions}.json`.
The 227-call capture used one temporary `t3.micro` for under three minutes and at
most two simultaneous EIPs; both allocations, three ENIs, root volume and all
owned VPC resources were removed. Terminated-instance history remains native
provider history. Native-backed replay runs admission, selection, reassociation,
ENI dependencies and error/DryRun precedence on memory and reopened SQLite.
The native capture did not measure the five-EIP quota, default-VPC release,
denied-principal IAM, no-auto disassociation or private-address moves; those
contracts are distinguished from observations in the retained conclusions.
Two captured malformed opaque long-instance-ID observations remain excluded from
replay under the existing opaque-ID admission boundary. They are retained, not
implemented through a literal zero-ID exception or a changed short-ID contract.

The separate `public_addresses_iam_federation.json` native capture establishes
matching/nonmatching address-condition denies and the omitted/false/true launch
matrix under both subnet defaults. `public_addresses_iam_role_readiness.json`
retains an earlier failed fresh-role baseline whose readiness cause is not
established; it is not used as evidence for condition semantics. Both temporary
IAM workflows cleaned their exact-owned resources without launching an instance.
All 66 exact-request CloudTrail records are retained in
`public_addresses_iam_audit.json`. SDK/API/audit replay uses memory and reopened
SQLite; `testdata/ec2/public_network_iam_runtime.json` separately proves all 24
native DryRun outcomes through the real CLI, retained sessions and process reopen.

`public_addresses_lifecycle_audit.json` additionally retains 400 records for 396
exact EC2 request IDs from the original address capture and four SSM execution
captures, with no missing calls. Address replay compares 114 actual SDK API/audit
outcomes on each repository, including SQLite reopening after mutations.
`public_addresses_launch_projection.json` retains two successful SDK launch
responses whose independent CloudTrail records calibrate launch request/response
envelopes, omitted empty fields, millisecond timestamps and sensitive user-data
redaction. Projection replay is not a substitute for the real firmware proof.
`testdata/ec2/public_network_audit_runtime.json` separately records exact-request
CloudTrail lookup through the real CLI after address allocation, discovery,
association and a read-only launch authorization, followed by exact API cleanup.

### Actual local packet path

Local public addresses come from the reserved `198.18.0.0/15` benchmark pool.
They are host-local addresses, **not Internet-advertised AWS public addresses**.
Each assigned address has an exact owned `/32` route, destination NAT to the
ENI's real private address, return mapping and source enforcement. Host-local and
forwarded clients reach the actual guest/task through the assigned address.
External egress uses the Docker host's routable source, not benchmark space.
An IGW route alone never grants public egress: a current address, active route,
security-group permission and ordered stateless NACL admission are all required.
The host-local DNAT path also evaluates both ingress and return NACLs, even when
the host selects its bridge-gateway address as the packet source.

The same native bridge policy applies to QEMU TAPs and ECS task peers. SG changes
deny new unauthorized flows without discarding authorized connection tracking;
NACL changes also apply to tracked flows. Remapping quarantines the old public
path and retires its public/SNAT conntrack tuples before enabling the new target.
For a public transition, the current attachment's authoritative policy is staged
before quarantine in the same atomic nft transaction. This upgrades retained
pre-public-network bridge tables without assuming they already contain today's
`public_from`/`public_to` chains. The shared native owner admission also accepts
retained `stackd_elbv2_*` attachment identities through this same packet path,
not a separate public-address pool or direct-nft bypass.
Unrelated established private flows, including same-VPC flows carrying other
native SNAT, retain their connection identities and SG-established admission.
External MASQ retirement inspects the old native bridge gateway/pool; a missing
bridge is distinguished from a failed inspection or an existing bridge missing
its retained gateway, which fail closed. Exact
native ownership witnesses, a host lock and persistent controller identity
prevent another controller or delayed old-ENI cleanup from stealing the mapping.
Public/private overlap fails closed in both creation orders, including a
quarantined public-table witness before its `/32` route exists. Nonoverlapping
and private-only benchmark-range VPCs remain usable; foreign native ownership
also fails closed.
The daemon-side helper holds `flock` across packet mutation or the complete
bridge Engine operation, not merely while a controller waits for its response.
A duplex admission handshake occurs only after acquiring that lock: an orphan
waiter receives EOF and cannot apply stale work, while an admitted operation
finishes under the lock even after controller cancellation or death. Native
auto-removal owns helper cleanup. No controller-liveness poll or second address
registry substitutes for operation ownership.
Native bridge, TAP, packet-policy and container identities are derived from AWS
resource identities, not controller database paths. Controllers using the same
VPC ARN therefore share its native bridge: matching IPAM reuses it, while a
different pool, prefix length or gateway rejects under the admission lock before
attachment. Separate databases are **not** independent native namespaces.
Independent controllers on one Engine must not reuse AWS resource identities:
choose account, region and resource-ID seed explicitly, and use nonoverlapping
host pools. Host CIDR overlap is not isolated VPC networking. The observed
independent ECS/SSM controller collision demonstrates this current boundary.
True per-emulator native isolation remains backlog across bridges, TAPs, packet
tables and containers together; neither the lock nor IPAM validation provides it.

`testdata/ec2/public_network_legacy_upgrade.json` retains the original failed
schema-224-to-225 ECS upgrade: missing new public chains caused a native policy
failure and runtime terminal cleanup of that receiver. Its failure is not
reclassified as success. A separate live native regression installs the exact
schema-224 policy compiler's rules, then upgrades in place: container ID, PID,
start time and an open private TCP connection survive, while public and private
HTTP reach the same process. It also exercises ELBv2 native owner admission,
reapplication and removal; this is a shared packet-boundary proof, not an ALB
API/end-to-end claim. Exact-owned containers, bridge, tables and route are absent
after cleanup.

`testdata/integration/ec2_public_network_upgrade.json` separately records the
complete corrected executable migration from a fresh schema-224 database to
schema 225. The original ECS container ID survives automatic public-address
backfill, serves HTTP through both private and public addresses, and survives a
second controller restart with the same address and container. IAM identity,
SSM state, EventBridge Connection/destination identity and CloudFormation/SQS
state remain intact. Explicit deletion removes the owned task, ENI, network and
retained controls; all three controllers exit normally.

Guest DHCP, IMDS and the scoped emulator callback retain their private paths.
Guest DNS resolves its current EC2 public hostname to its private address and
withdraws replaced names; this is local split-horizon DNS, not AWS public DNS.

This path requires local rootful Linux Docker, the installed pinned network
toolkit, `NET_ADMIN`, nftables bridge/netdev connection tracking and Docker's
iptables-nft `DOCKER-USER`/raw chains. A containerized controller must share the
daemon host's `/run/lock/stackd-public-network.lock` inode; a read-only bind works
when the inode already exists. Never unlink that shared lock. Bridge admission
also requires daemon-host `/var/run/docker.sock` to identify the same selected
Engine. Helpers fail closed on host/inode/Engine mismatch; read-only socket
mounting does not make the Docker API read-only. These are privileged trusted
runtime helpers, never customer-container mounts. Remote/rootless/Desktop
Docker, overlapping VPC bridges, secondary-address/multi-ENI guest execution,
arbitrary Internet advertisement, IPv6/carrier/BYOIP/CoIP/IPAM pools, allocation recovery/transfers
and mutable ENI auto-public-IP attributes remain outside the implemented path.
Ordinary unattached ENI secondary-address controls retain their existing scope.

Executable reproduction: `scripts/aws/ec2_public_network_smoke.py` uses signed
SDK calls against an explicit local endpoint, imported real Ubuntu firmware,
actual HTTP/SSH/IMDS/DNS and real ECS containers. Its phases are `import`, `launch`,
`egress`, `exercise`, `policy`, `ecs`, `restart-check`, `lifecycle`, and `cleanup`;
restart the CLI with the same SQLite database/native state directory before
`restart-check`. Retained local evidence lives in
`testdata/ec2/public_network_runtime.json` and
`testdata/ec2/public_network_physical.json`; these are not native AWS captures.
Initial review regressions retain their disposable reproduction sources and
exact-owned cleanup in `testdata/ec2/public_network_overlap.json` and
`testdata/ec2/public_network_conntrack.json`: both overlap creation orders,
quarantine, independently contending controllers, cancellation and existing
private connection survival versus retired old public/upstream flows. The first
overlap correction's controller-held lock did not establish crash-safe lifetime;
its evidence is explicitly marked historical rather than relabeled as final.
`testdata/ec2/public_network_crash_lifetime.json` retains the final before/after
proof: a paused admitted helper and a delayed real Engine network-create request
both survive controller `SIGKILL` without allowing successor mutation to race;
orphan lock waiters exit without mutation, canceled admitted bridge operations
finish under ownership, and start-refused helpers are removed. It also repeats
the original overlap checks against the final implementation and verifies exact
helper/table/route/bridge cleanup. The Engine delay uses an exact-owned Unix
transport proxy, not a dockerd scheduling hook. Rootless/userns/non-Linux
rejections and a second distinct Engine-ID mismatch are not runtime claims.
`testdata/ec2/public_network_ipam_reuse.json` proves two independent controllers
reuse a matching exact-owned live bridge, reject changed pool/prefix/gateway
without invoking attachment or altering its configuration, preserve TCP traffic
through every rejection, and remove only their owned resources afterward.
Primary references:
[Elastic IPs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html),
[IPv4 addressing](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html),
[IGW prerequisites](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html),
the [address API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AssociateAddress.html),
and [explicit public-IP IAM controls](https://docs.aws.amazon.com/eks/latest/userguide/auto-controls.html#_associate_public_ip_address).

## IPv4 network interfaces

The implemented path covers creation/discovery/deletion, description/group/source-
destination-check attributes, and private-address assignment/release. Each primary
or secondary consumes subnet capacity. The first four addresses and the final
address are reserved; occupied addresses reject, exhaustion fails atomically,
and deletion/release makes addresses reusable. Explicit secondary lists without
a primary receive an additional automatic primary. Reassignment can move a
secondary between interfaces in the same subnet, but never another interface's
primary; a move does not consume additional capacity.

Creation returns `pending`; subsequent reads expose `available`. Default groups
are resolved from the actual VPC. Group replacement validates membership, and
referenced groups/subnets cannot be deleted. IAM evaluates each dependency's own
VPC ARN as `ec2:Vpc`, including the resolved default group; the fixture regression
uses the [AWS VPC CNI scope-down policy](https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/docs/iam-policy.md)
and explicit denies. These controls alone do not provide EC2 instance forwarding.

ENI creation-token behavior differs from route tables and ACLs:

- Explicit address availability is checked before token comparison, so a retry
  with an occupied explicit address fails with `InvalidIPAddress.InUse`.
- Automatic-address retries return the same interface's **current** description,
  groups and addresses. Request tags are echoed without overwriting stored tags.
- Group ordering and tag changes do not change token identity. Changed admitted
  description, subnet, group membership or secondary count reject. Omitted
  interface type differs from explicit `interface`, even though both are valid.
- Deleted-resource retries return `IdempotentParameterMismatch`. Outcomes and
  ordered admitted arguments survive reopen independently of live interfaces.
- Surrounding whitespace is trimmed; captured 65-byte and Unicode tokens succeed.
  Blank tokens caused native `InternalError`; stackd rejects that unsupported
  input rather than copying an AWS crash. The captured case-only mismatch and
  token retention limit remain unresolved; local token keys are case-sensitive.

Native-backed model corrections keep type admission and attribute selection in
the service: AWS accepts the unmodeled creation type `interface`, and authorized
`DryRun` takes precedence over an invalid attribute. Automatic addresses, MACs and
automatic subnet placement are consistently bound during replay, not pinned to
AWS's arbitrary allocation choices. Pagination compares complete membership and
continuation behavior rather than requiring identical physical page boundaries.

### RAM shared VPC subnets

RAM's `ec2:Subnet` integration resolves the existing EC2 subnet owner. Sharing
requires an available non-default subnet outside a default VPC, owner-side
`ec2:DescribeSubnets`/`ec2:DescribeVpcs` authority, and RAM-enabled membership in
the same Organizations organization. Account/organization grants are evaluated
live alongside the participant's IAM, session, boundary and Organizations
restrictions; neither a successful resource association nor a discovery result
is a substitute for data-plane authorization.

Participants can discover the shared subnet, containing VPC and its read-only
route-table, ACL, internet-gateway and DHCP context. Owner tags remain private;
subnet AZ names are projected through the participant's catalog using the
physical AZ ID. Participants create their own security groups in that VPC and
must supply one for ENI creation or `RunInstances`: the owner's default group is
not a fallback. Subnet sharing does not grant subnet/VPC mutation, owner security
group mutation, owner ENI mutation, or authority to reshare the subnet. Explicit
cross-account group references are limited to the same owner-qualified VPC.

IPv4 allocations consume the **one owner subnet's** address pool and capacity,
including collision checks against all participant interfaces. ENIs and instances
remain participant-owned. The guest backend receives the owner's actual VPC
network ID, DHCP settings, routes and ACLs, composed with the participant's
current security-group rules. No subnet/VPC is copied into the participant
account, and no owner principal is substituted into the request.

Unsharing a resource, removing its principal or losing current organization
membership prevents new ENIs, launches and participant security-group creation.
Previously admitted ENIs retain their network, current owner packet policy and
participant management/deletion rights. Their existence blocks owner subnet
deletion. A successful deletion also disassociates its RAM resources atomically;
generated subnet IDs are never reused. SQLite retains only the additional
network-owner account bindings, not a duplicate resource identity or grant cache.

The permanent shared-subnet fixtures exercise real RAM grants, ENI allocation,
IAM denial, RunInstances admission, revocation, deletion rollback and reopened
SQLite state. A separate network-specification regression targets owner bridge,
DHCP/ACL and participant SG composition.

[`ram_shared_subnet_guest.json`](../testdata/integration/ram_shared_subnet_guest.json)
records the actual CLI, signed cross-account SDK calls and a firmware-booted QEMU
guest in the owner's subnet. The participant owned its image, SG and ENI.
Private TCP nonce responses and the kernel boot ID survived controller restart
and share revocation; revoked sharing denied new ENIs and actual RunInstances.
Changing the participant SG then blocked and restored the existing guest's
traffic. A second restart retained that revoked state and original guest boot.
Owned compute, storage, networking, sharing, organization and identity cleanup
completed. This is local executable evidence, not a native AWS capture.

The explicit QEMU/KVM and host-network prerequisites still apply. Shared security
groups as independent RAM resources, IPv6 and broader service-specific shared-VPC
workflows are outside this subnet integration.

Primary contracts:
[owner and participant responsibilities](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-share-limitations.html),
[sharing, AZ mapping and unsharing](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-sharing-share-subnet-working-with.html).

## Wire, selection and zones

Generated EC2 Query bindings own modeled inputs/outputs. Native raw requests
cover GET/POST duplicates, indexed lists, errors, XML namespace/content type and
unit responses. Unlike the AWS Query transport, EC2 accepts sparse indexed
collections; duplicate GET values select the first and POST values the last.

Security-group pagination limits a VPC-scoped scan before secondary filters,
so filtered pages may be short. Its token binds VPC selection but permits tag
filter changes; omitting `MaxResults` exhausts the remainder without a terminal
token. Subnet captures establish different continuation behavior when VPC
selection changes. Repeated tokens and reopened stores preserve local results.
Opaque AWS scan ordering is not reproduced: fixture replay checks joined
membership, resource bodies, continuation behavior and unfiltered page sizes,
not identical filtered page partitions for independently allocated IDs.

Embedded physical-zone metadata covers 32 of the 34 commercial regions captured
in the regional catalogue. Account Management owns region enablement. The eight
AWS-documented legacy regions receive stable account-specific name-to-physical-ID
assignments; other captured regions retain uniform mappings. `ap-east-2` returned
native `AuthFailure`, and `me-south-1` repeatedly timed out during capture.
Uncaptured regions and non-commercial partitions return explicit unsupported
errors instead of fabricated physical IDs. Native automatic subnet placement
varied between captures and is not a fixed-zone guarantee.

## CloudTrail and EventBridge

VPC creation/deletion commit `CreateVpcResourceCreation` and
`DeleteVpcResourceDeletion` service events with the default ACL, route-table and
security-group ARNs. These are distinct from API-call events. Their CloudTrail
shape is `AwsServiceEvent`, with account/service identity, EC2 source address and
agent, and `serviceEventDetails.vpcId`. Failed event append rolls back the VPC,
default resources and event together.

A live configured-trail/EventBridge/SQS capture confirmed both events with
`detail-type: AWS Service Event via CloudTrail`, empty top-level `resources`,
and full native resource ARNs inside `detail`. Their detail bodies matched
regional CloudTrail history. A fresh trail delivered other S3 gzip batches, but
these VPC records were not observed during the bounded 594-second window. That
is neither evidence of exclusion nor a native S3-delivery claim. Local S3 delivery
and ReadOnly-selector exclusion are tested against the documented CloudTrail
management-event contract, using the captured history shapes.

Gateway/route and ENI API captures also retain their native request/response
collection envelopes, omitted fields and failures. The shared CloudTrail
serializer emits whole-second UTC `eventTime` for history, EventBridge detail
and S3 logs; journal timestamps retain their original precision.

## Evidence

Native inputs, outputs, raw wire bodies and cleanup results are retained under
[`testdata/aws/ec2`](../testdata/aws/ec2): `networking.json`, `dhcp_options.json`,
`availability_zones_supplement.json`, `pagination.json`, the route-table/ACL token
fixtures, `network_creation_whitespace.json`, `network_creation_token_length.json`,
`audit.json`, `service_event_delivery.json`, `internet_gateways.json`,
`network_interfaces.json`, `network_interface_idempotency.json`,
`network_interface_addresses.json` and `network_interface_types.json`.
Owned native networking resources and the delivery probe's trail/rule/queue/bucket
were removed, with absence checks retained.

```sh
go test ./integration -run '^Test(EC2|CloudTrailEC2)' -count=1
```

The actual executable was also exercised with AWS CLI against SQLite: CIDR
canonicalization, real DHCP discovery, zone-ID subnet placement, token replay and
tag preservation, current ACL entries, dependency failures, deletion mismatch
across process restart, and both VPC service-event history records.

The gateway/ENI executable workflow verifies address reassignment and capacity,
scoped lookup, dependency errors, retained current-state retries, deleted-token
rejection and active/blackhole routes across process restart. With a configured
trail and rule, the same EC2 API records reached SQS through EventBridge and
actual CloudTrail gzip objects in S3. These are local end-to-end checks, not a
claim of native packet-path or managed-task execution.

The complete instance/SSH/container workflow remains a target beyond the
exercised guest paths above. AWS semantics use retained native evidence and primary
[EC2 API documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Welcome.html).

## Remaining boundaries

Broader guest hardware, EC2-backed ECS/container placement and nonlocal reachability;
general public requester/operator-managed ENI creation beyond the service-owned
consumer hooks; secondary-address/multi-subnet, EFA and trunk/branch guest attachments;
connection-tracking/ENA SRD controls; IPv6/IPAM and
delegated prefixes remain unfinished. Public-address pool/transfer boundaries are
listed above. Routes to ENIs/instances, NAT, peering,
virtual/transit/egress-only/local/carrier gateways, endpoints, core/ODB networks
and managed prefix lists need their owning resource lifecycles. Physical-zone
coverage, token retention/case anomalies and unmeasured pagination scope/ordering
remain explicit gaps. SQL retention is not snapshot/fork support.
`running` is not an assertion of OS or application health. Scheduled maintenance,
application status checks, automatic recovery and AWS's delayed status publication
remain open, as does opaque long-instance-ID admission. Remaining IMDS categories,
additional architectures/hardware and specialty launch/monitoring options are
not implemented. Live NVMe growth and forced hot detach
are rejected rather than represented as successful physical changes.
AMI Organizations/OU launch grants, instance-store/PV/Mac registration, licensed
billing products, SR-IOV, NitroTPM and imported Secure Boot variables remain open.
Registration also rejects instance-store/suppressed mappings and placement, KMS,
initialization-rate or EBS-card overrides. `DeleteAssociatedSnapshots` remains
unsupported; callers must deregister the image and delete its snapshots explicitly.
Disabling source/destination checks requires a real forwarding-appliance path
and is rejected until that path exists.
