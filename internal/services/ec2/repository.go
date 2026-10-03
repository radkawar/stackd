package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	api "stackd/internal/awsapi/ec2"
)

var ErrNotFound = errors.New("ec2: resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ResourceKey struct {
	Scope Scope
	ID    string
}
type VPCRecord struct {
	Key                                                  ResourceKey
	Data                                                 api.Vpc
	DNSHostnames, DNSSupport, NetworkAddressUsageMetrics bool
}
type SubnetRecord struct {
	Key  ResourceKey
	Data api.Subnet
}
type SecurityGroupRecord struct {
	Key               ResourceKey
	Data              api.SecurityGroup
	VPCOwnerAccountID string
}
type SecurityGroupRuleRecord struct {
	Key  ResourceKey
	Data api.SecurityGroupRule
}
type RouteTableRecord struct {
	Key  ResourceKey
	Data api.RouteTable
}
type InternetGatewayRecord struct {
	Key  ResourceKey
	Data api.InternetGateway
}
type NetworkInterfaceRecord struct {
	Key  ResourceKey
	Data api.NetworkInterface
	// Task ownership is service-only authority, never a public ENI attribute.
	TaskOwnerARN         string
	TaskPublicNetworking bool
	// Lambda mapping ownership is immutable and independent of description.
	LambdaMappingOwnerARN string
	// Network ownership is independent of the participant owning this ENI.
	SubnetOwnerAccountID string
}
type NetworkACLRecord struct {
	Key  ResourceKey
	Data api.NetworkAcl
}
type DHCPOptionsRecord struct {
	Key  ResourceKey
	Data api.DhcpOptions
}

// PublicAddressRecord is the single owner of elastic and automatic public IPv4.
// Automatic records retain launch intent across stop; a nil PublicIp then means
// that the ephemeral address has been released, not that it remains reserved.
type PublicAddressRecord struct {
	Key       ResourceKey
	Data      api.Address
	Automatic bool
}

// KeyPairRecord retains only public metadata; generated private material is
// returned by CreateKeyPair and never enters repository state.
type KeyPairRecord struct {
	Key  ResourceKey
	Data api.KeyPairInfo
}

// DHCPDefaultsRecord distinguishes an uninitialized region from a deleted default.
// An empty OptionsID means the default was explicitly deleted.
type DHCPDefaultsRecord struct {
	Scope     Scope
	OptionsID string
}

type NetworkCreationKey struct {
	Scope         Scope
	Action, Token string
}

// NetworkCreationRecord retains admitted arguments after resource deletion so
// replay cannot silently create a different route table or network ACL.
type NetworkCreationRecord struct {
	Key               NetworkCreationKey
	VPCID, ResourceID string
	Tags              api.TagList
}

type NetworkInterfaceCreationKey struct {
	Scope Scope
	Token string
}

// NetworkInterfaceCreationRecord retains admitted creation arguments after ENI
// deletion. Input excludes ClientToken, DryRun and TagSpecifications: tags on a
// retry affect its response, not the original token's equality or retained tags.
type NetworkInterfaceCreationRecord struct {
	Key        NetworkInterfaceCreationKey
	ResourceID string
	Input      api.CreateNetworkInterfaceRequest
}

type Reader interface {
	Context() context.Context
	LaunchTemplate(ResourceKey) (LaunchTemplateRecord, error)
	LaunchTemplates(Scope) ([]LaunchTemplateRecord, error)
	LaunchTemplateVersion(LaunchTemplateVersionKey) (LaunchTemplateVersionRecord, error)
	LaunchTemplateVersions(ResourceKey) ([]LaunchTemplateVersionRecord, error)
	LaunchTemplateToken(LaunchTemplateTokenKey) (LaunchTemplateTokenRecord, error)
	PublicAddress(ResourceKey) (PublicAddressRecord, error)
	PublicAddresses(Scope) ([]PublicAddressRecord, error)
	// PublicIPv4Reservations is allocator-only host-wide collision admission.
	PublicIPv4Reservations() ([]string, error)
	VPC(ResourceKey) (VPCRecord, error)
	VPCs(Scope) ([]VPCRecord, error)
	Subnet(ResourceKey) (SubnetRecord, error)
	Subnets(Scope) ([]SubnetRecord, error)
	SecurityGroup(ResourceKey) (SecurityGroupRecord, error)
	SecurityGroups(Scope) ([]SecurityGroupRecord, error)
	SecurityGroupRule(ResourceKey) (SecurityGroupRuleRecord, error)
	SecurityGroupRules(Scope) ([]SecurityGroupRuleRecord, error)
	RouteTable(ResourceKey) (RouteTableRecord, error)
	RouteTables(Scope) ([]RouteTableRecord, error)
	InternetGateway(ResourceKey) (InternetGatewayRecord, error)
	InternetGateways(Scope) ([]InternetGatewayRecord, error)
	NetworkInterface(ResourceKey) (NetworkInterfaceRecord, error)
	NetworkInterfaces(Scope) ([]NetworkInterfaceRecord, error)
	// RegionalNetworkInterfaces is internal network authority for allocation,
	// dependencies and packet policy, never unfiltered customer discovery.
	RegionalNetworkInterfaces(Scope) ([]NetworkInterfaceRecord, error)
	RegionalSecurityGroups(Scope) ([]SecurityGroupRecord, error)
	NetworkInterfaceCreation(NetworkInterfaceCreationKey) (NetworkInterfaceCreationRecord, error)
	NetworkACL(ResourceKey) (NetworkACLRecord, error)
	NetworkACLs(Scope) ([]NetworkACLRecord, error)
	DHCPOptions(ResourceKey) (DHCPOptionsRecord, error)
	DHCPOptionsSets(Scope) ([]DHCPOptionsRecord, error)
	DHCPDefaults(Scope) (DHCPDefaultsRecord, error)
	NetworkCreation(NetworkCreationKey) (NetworkCreationRecord, error)
	KeyPair(ResourceKey) (KeyPairRecord, error)
	KeyPairs(Scope) ([]KeyPairRecord, error)
	Image(ResourceKey) (ImageRecord, error)
	RegionalImage(scope Scope, id string) (ImageRecord, error)
	Images(Scope) ([]ImageRecord, error)
	// RegionalImages includes all owners in the partition and region. Service
	// selectors must apply launch permissions before exposing any record.
	RegionalImages(Scope) ([]ImageRecord, error)
	ImageReferencingSnapshot(scope Scope, snapshotOwnerAccount, snapshotID string) (string, error)
	PendingImages(time.Time) ([]ImageRecord, error)
	NextImageDeadline() (time.Time, bool, error)
	Instance(ResourceKey) (InstanceRecord, error)
	Instances(Scope) ([]InstanceRecord, error)
	Reservation(ResourceKey) (ReservationRecord, error)
	InstanceReservationsByToken(Scope, string) ([]ReservationRecord, error)
	PreparedInstances() ([]InstanceRecord, error)
	PendingInstances(time.Time) ([]InstanceRecord, error)
	NextInstanceDeadline() (time.Time, bool, error)
	InstanceVolumeAttachments(ResourceKey) ([]InstanceVolumeAttachmentRecord, error)
	InstanceCreditDefault(Scope, string) (InstanceCreditDefaultRecord, error)
	InstanceCreditLaunches(Scope) (InstanceCreditLaunchRecord, error)
	InstanceCreditModification(InstanceCreditModificationKey) (InstanceCreditModificationRecord, error)
	InstanceProfileAssociation(ResourceKey) (InstanceProfileAssociationRecord, error)
	InstanceProfileAssociations(Scope) ([]InstanceProfileAssociationRecord, error)
	PendingInstanceProfileAssociations(time.Time) ([]InstanceProfileAssociationRecord, error)
	NextInstanceProfileAssociationDeadline() (time.Time, bool, error)
	IdentitySigningKey(string) (IdentitySigningKeyRecord, error)
}
type Transaction interface {
	Reader
	NextID(Scope, string) (string, error)
	PutLaunchTemplate(LaunchTemplateRecord) error
	DeleteLaunchTemplate(ResourceKey) error
	PutLaunchTemplateVersion(LaunchTemplateVersionRecord) error
	DeleteLaunchTemplateVersion(LaunchTemplateVersionKey) error
	PutLaunchTemplateToken(LaunchTemplateTokenRecord) error
	PutPublicAddress(PublicAddressRecord) error
	DeletePublicAddress(ResourceKey) error
	PutVPC(VPCRecord) error
	DeleteVPC(ResourceKey) error
	PutSubnet(SubnetRecord) error
	DeleteSubnet(ResourceKey) error
	PutSecurityGroup(SecurityGroupRecord) error
	DeleteSecurityGroup(ResourceKey) error
	PutSecurityGroupRule(SecurityGroupRuleRecord) error
	DeleteSecurityGroupRule(ResourceKey) error
	PutRouteTable(RouteTableRecord) error
	DeleteRouteTable(ResourceKey) error
	PutInternetGateway(InternetGatewayRecord) error
	DeleteInternetGateway(ResourceKey) error
	PutNetworkInterface(NetworkInterfaceRecord) error
	DeleteNetworkInterface(ResourceKey) error
	PutNetworkInterfaceCreation(NetworkInterfaceCreationRecord) error
	PutNetworkACL(NetworkACLRecord) error
	DeleteNetworkACL(ResourceKey) error
	PutDHCPOptions(DHCPOptionsRecord) error
	DeleteDHCPOptions(ResourceKey) error
	PutDHCPDefaults(DHCPDefaultsRecord) error
	PutNetworkCreation(NetworkCreationRecord) error
	PutKeyPair(KeyPairRecord) error
	DeleteKeyPair(ResourceKey) error
	PutImage(ImageRecord) error
	DeleteImage(ResourceKey) error
	PutInstance(InstanceRecord) error
	PutReservation(ReservationRecord) error
	PutInstanceCreditDefault(InstanceCreditDefaultRecord) error
	PutInstanceCreditLaunches(InstanceCreditLaunchRecord) error
	PutInstanceCreditModification(InstanceCreditModificationRecord) error
	PutInstanceProfileAssociation(InstanceProfileAssociationRecord) error
	DeleteInstanceProfileAssociation(ResourceKey) error
	PutIdentitySigningKey(IdentitySigningKeyRecord) error
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}

// FormatResourceID shares deterministic identifiers across repository backends.
// Sequence zero is the uint64 exhaustion sentinel, never an allocated identifier.
func FormatResourceID(scope Scope, prefix string, sequence uint64) (string, error) {
	if sequence == 0 {
		return "", failure("ResourceLimitExceeded", "Resource identifier space exhausted.")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", scope.Partition, scope.AccountID, scope.Region, prefix, sequence)))
	return fmt.Sprintf("%s-%x", prefix, sum[:9])[:len(prefix)+18], nil
}
