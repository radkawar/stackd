package ec2

import (
	"context"
	"slices"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	stsapi "stackd/internal/awsapi/sts"
)

// InstanceVolumes is EBS service admission, never a public CreateVolume call.
// Plan and Admit join the caller's resource transaction; Plan resolves all image,
// snapshot and regional encryption defaults before EC2 evaluates launch IAM.
// Prepare, Stop and Terminate perform idempotent native effects outside that
// transaction. EBS owns their metadata transactions, bytes and KMS grants.
// Stop preserves public in-use attachments. Terminate honors DeleteOnTermination.
type InstanceVolumes interface {
	PlanInstanceVolumes(context.Context, api.Image, api.BlockDeviceMappingRequestList, AvailabilityZone) (api.BlockDeviceMappingRequestList, error)
	// InstanceLaunchMappings projects current attached-volume configuration for
	// GetLaunchTemplateData without requiring a second public DescribeVolumes call.
	InstanceLaunchMappings(context.Context, api.Instance) (api.BlockDeviceMappingRequestList, error)
	AdmitInstanceVolumes(context.Context, string, AvailabilityZone, api.BlockDeviceMappingRequestList, api.TagList) (api.InstanceBlockDeviceMappingList, error)
	// AdmitInstanceVolumeStart restores start-scoped infrastructure grants under
	// the actual StartInstances caller, joining the command transaction. Native
	// KMS launch failures remain asynchronous in the EBS owner's state.
	AdmitInstanceVolumeStart(context.Context, api.Instance) error
	AdmitInstanceVolumeAttachment(context.Context, api.Instance, api.InstanceBlockDeviceMapping) error
	// Resolve returns authoritative native references without key unwrap, for
	// reconnecting a surviving VM whose native secret remains loaded.
	ResolveInstanceVolumes(context.Context, api.Instance) ([]native.Disk, error)
	PrepareInstanceVolumes(context.Context, api.Instance) ([]native.Disk, error)
	StopInstanceVolumes(context.Context, api.Instance) error
	TerminateInstanceVolumes(context.Context, api.Instance) error
}

// InstanceProfiles resolves current IAM ownership and issues delegated EC2 role
// credentials. Neither operation requires public GetInstanceProfile/AssumeRole
// authority from the launcher. EC2 separately evaluates iam:PassRole.
type InstanceProfiles interface {
	ResolveInstanceProfile(context.Context, api.IamInstanceProfileSpecification) (iamapi.InstanceProfile, error)
	// The previous ID is a reference to IAM's retained issued credential, never
	// another credential store. Membership/trust changes apply on refresh; old
	// issued credentials are not revoked by association mutations.
	InstanceProfileCredentials(ctx context.Context, origin InstanceCredentialOrigin, profile api.IamInstanceProfile, previousID string, imdsv2 bool) (InstanceProfileCredential, error)
}

// InstanceCredentialOrigin is the EC2-owned location captured at issuance, not
// the network path or peer of a later request signed with those credentials.
type InstanceCredentialOrigin struct {
	InstanceARN, VPCID, PrivateIPv4 string
}

func (r *InstanceRecord) credentialOrigin() InstanceCredentialOrigin {
	return InstanceCredentialOrigin{
		InstanceARN: resourceARN(r.Key.Scope, "instance", r.Key.ID),
		VPCID:       str(r.Data.VpcId), PrivateIPv4: str(r.Data.PrivateIpAddress),
	}
}

type InstanceProfileCredential struct {
	RoleName    string
	Credentials *stsapi.Credentials
	LastUpdated time.Time
}

// InstanceIdentities issues the instance's own restricted service identity,
// independently of IAM instance profiles. The previous ID references the
// credential authority's retained record; EC2 never retains its secret material.
type InstanceIdentities interface {
	InstanceIdentityCredentials(ctx context.Context, instanceARN, previousID string, imdsv2 bool) (InstanceIdentityCredential, error)
}

type InstanceIdentityCredential struct {
	Credentials *stsapi.Credentials
	LastUpdated time.Time
}

// InstanceCredentialReferences retains each delivery version independently.
// IAM owns credential material and validity; changing HttpTokens does not revoke
// credentials previously delivered through either metadata protocol.
type InstanceCredentialReferences struct {
	V1, V2 string
}

func (r *InstanceCredentialReferences) forVersion(imdsv2 bool) *string {
	if imdsv2 {
		return &r.V2
	}
	return &r.V1
}

// InstanceTypes supplies captured/generated facts, not guessed AWS hardware.
type InstanceTypes interface {
	ResolveInstanceType(context.Context, api.InstanceType) (api.InstanceTypeInfo, error)
}

type InstanceStateChangeEvent struct {
	Key                    ResourceKey
	State                  string
	At                     time.Time
	CommandID, CausationID string
}

// InstanceEvents admits native state-change events in the instance transaction.
// Implementations must not deliver externally before the transaction commits.
type InstanceEvents interface {
	PublishInstanceStateChange(context.Context, InstanceStateChangeEvent) error
}

type InstanceIntent string

const (
	InstanceIntentObserve   InstanceIntent = "observe"
	InstanceIntentStart     InstanceIntent = "start"
	InstanceIntentStop      InstanceIntent = "stop"
	InstanceIntentHibernate InstanceIntent = "hibernate"
	InstanceIntentTerminate InstanceIntent = "terminate"
	InstanceIntentReboot    InstanceIntent = "reboot"
)

// InstanceRecord owns current state. RuntimePrepared is only a durable native
// identity hint: it never implies the VMM or guest is running. Console and health
// fields contain observed backend output, not synthesized guest success.
type InstanceRecord struct {
	Key                 ResourceKey
	CloudFormationOwner CloudFormationOwner
	Data                api.Instance
	ReservationID       string
	// These service-only launch identities cannot be changed by EC2 attributes.
	LambdaCapacityProviderARN string
	LambdaManagedGeneration   string
	UserData                  []byte
	MetadataTokenKey          []byte
	IdentityCredentials       InstanceCredentialReferences
	// IdentityInfoLastUpdated retains the intrinsic info publication timestamp.
	IdentityInfoLastUpdated time.Time
	// MetadataBlockDevices captures the launch/last-start attachment view used
	// by IMDS; live hotplug changes do not alter this boot-specific projection.
	MetadataBlockDevices                  []string
	Credits                               InstanceCreditRecord
	Performance                           InstancePerformanceRecord
	PublicKey                             string
	ShutdownBehavior                      string
	DisableAPIStop, DisableAPITermination bool
	Intent                                InstanceIntent
	// Generation prevents completion of an outside-transaction start/reboot
	// from overwriting a newer Stop/Terminate command committed during the effect.
	Generation                     uint64
	RuntimePrepared                bool
	EffectStarted                  bool
	Force                          bool
	NextActionAt, ShutdownDeadline time.Time
	CommandID, CausationID         string
	Console                        []byte
	ConsoleOffset                  int64
	ConsoleAt                      time.Time
	Health                         InstanceHealthRecord
}

// InstanceMetrics resolves contribution ownership and joins the existing metric
// transaction, independently of public PutMetricData permission.
type InstanceMetrics interface {
	InstanceMetricGroup(context.Context, ResourceKey) (string, error)
	RecordInstanceCreditMetrics(context.Context, InstanceCreditMetricSample) error
	RecordInstanceHealthMetrics(context.Context, ResourceKey, *InstanceHealthRecord) error
	RecordInstancePerformanceMetrics(context.Context, ResourceKey, *api.Instance, InstancePerformanceMetricSample) error
}

// InstanceLaunchFailure is an asynchronous launch failure observed by EBS or
// the runtime. In particular caller KMS grant/key-generation denial terminates
// an admitted launch rather than inventing a synchronous RunInstances failure.
type InstanceLaunchFailure struct{ Code, Message string }

func (e *InstanceLaunchFailure) Error() string { return e.Code + ": " + e.Message }

func cloneInstance(v InstanceRecord) InstanceRecord {
	v.Data = api.CloneInstance(v.Data)
	v.Performance.Groups = slices.Clone(v.Performance.Groups)
	v.MetadataTokenKey = slices.Clone(v.MetadataTokenKey)
	v.MetadataBlockDevices = slices.Clone(v.MetadataBlockDevices)
	v.UserData = slices.Clone(v.UserData)
	v.Console = slices.Clone(v.Console)
	return v
}
