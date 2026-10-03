package lambda

import (
	"context"
	"time"

	"stackd/compute/lambda/managed"
)

type CapacityProviderKey struct {
	Scope
	Name string
}

func (k CapacityProviderKey) ARN() string {
	return "arn:" + k.Partition + ":lambda:" + k.Region + ":" + k.Account + ":capacity-provider:" + k.Name
}

// CapacityProviderRecord owns provider intent. EC2 remains authoritative for
// instance, ENI, EBS/KMS and actual guest lifecycle state.
type CapacityProviderRecord struct {
	Key                                                                      CapacityProviderKey
	Generation, State, StateReason                                           string
	OperatorRoleARN, KMSKeyARN, Architecture                                 string
	SubnetIDs, SecurityGroupIDs, AllowedInstanceTypes, ExcludedInstanceTypes []string
	ScalingMode                                                              string
	MaxVCPUs                                                                 int32
	TargetCPU                                                                float64
	PropagateTags                                                            map[string]string
	Tags                                                                     map[string]string
	LogGroup, SystemLogLevel                                                 string
	Modified                                                                 time.Time
}
type CapacityFunctionConfig struct {
	ProviderARN      string
	MemoryGiBPerVCPU float64
	MaxConcurrency   int
}
type CapacityScalingRecord struct {
	Key                              FunctionReference
	Generation                       string
	MinEnvironments, MaxEnvironments int32
	AppliedMin, AppliedMax           int32
	Modified                         time.Time
}

// CapacityGuestRecord is the retained effect identity, not an EC2 metadata copy.
// The token and certificate authenticate the exact guest incarnation after a
// controller restart. Secret material must never enter API/audit projection.
type CapacityGuestRecord struct {
	Provider                                                     CapacityProviderKey
	ID, Generation, InstanceID, SubnetID, InstanceType, Endpoint string
	AgentToken                                                   string
	AgentCertificate, AgentPrivateKey                            []byte
	CommandID, State, Error                                      string
	VCPUs, MemoryMB                                              int32
	Modified                                                     time.Time
}
type CapacityEnvironmentRecord struct {
	Key                                   FunctionVersionKey
	ID, Generation, GuestID, State, Error string
	CredentialsExpire                     time.Time
	Modified                              time.Time
}
type CapacityReader interface {
	CapacityProvider(CapacityProviderKey) (CapacityProviderRecord, error)
	CapacityProviders(Scope) ([]CapacityProviderRecord, error)
	AllCapacityProviders() ([]CapacityProviderRecord, error)
	CapacityScaling(FunctionReference) (CapacityScalingRecord, error)
	CapacityScalings(FunctionKey) ([]CapacityScalingRecord, error)
	CapacityGuests(CapacityProviderKey) ([]CapacityGuestRecord, error)
	CapacityEnvironments(FunctionVersionKey) ([]CapacityEnvironmentRecord, error)
	AllCapacityEnvironments() ([]CapacityEnvironmentRecord, error)
}
type CapacityWriter interface {
	PutCapacityProvider(CapacityProviderRecord) error
	DeleteCapacityProvider(CapacityProviderKey) error
	PutCapacityScaling(CapacityScalingRecord) error
	DeleteCapacityScaling(FunctionReference) error
	PutCapacityGuest(CapacityGuestRecord) error
	DeleteCapacityGuest(CapacityProviderKey, string) error
	PutCapacityEnvironment(CapacityEnvironmentRecord) error
	DeleteCapacityEnvironment(string) error
	ReplaceCapacityPublishedFunction(FunctionRecord) error
	SetCapacityDeploymentState(FunctionRecord) error
}

// CapacityBackend is consumed by Lambda; its adapter executes ordinary EC2 and
// official SSM commands with fresh service-role authority outside transactions.
type CapacityBackend interface {
	Validate(context.Context, CapacityProviderRecord) error
	Launch(context.Context, CapacityProviderRecord, CapacityGuestRecord) (CapacityGuestRecord, error)
	Observe(context.Context, CapacityProviderRecord, CapacityGuestRecord) (CapacityGuestRecord, error)
	Terminate(context.Context, CapacityProviderRecord, CapacityGuestRecord) error
	Client(context.Context, CapacityProviderRecord, CapacityGuestRecord) (*managed.Client, error)
}
