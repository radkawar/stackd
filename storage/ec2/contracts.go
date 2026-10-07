// Package ec2 exposes service-owned EC2 resource storage contracts.
package ec2

import (
	domain "stackd/internal/services/ec2"
	"stackd/storage/memory"
)

type (
	Repository                       = domain.Repository
	Reader                           = domain.Reader
	Transaction                      = domain.Transaction
	Scope                            = domain.Scope
	ResourceKey                      = domain.ResourceKey
	CloudFormationOwner              = domain.CloudFormationOwner
	LaunchTemplateRecord             = domain.LaunchTemplateRecord
	LaunchTemplateVersionKey         = domain.LaunchTemplateVersionKey
	LaunchTemplateVersionRecord      = domain.LaunchTemplateVersionRecord
	LaunchTemplateTokenKey           = domain.LaunchTemplateTokenKey
	LaunchTemplateTokenRecord        = domain.LaunchTemplateTokenRecord
	VPCRecord                        = domain.VPCRecord
	SubnetRecord                     = domain.SubnetRecord
	SecurityGroupRecord              = domain.SecurityGroupRecord
	KeyPairRecord                    = domain.KeyPairRecord
	PublicAddressRecord              = domain.PublicAddressRecord
	ImageRecord                      = domain.ImageRecord
	ImageCreation                    = domain.ImageCreation
	InstanceRecord                   = domain.InstanceRecord
	InstanceProfileAssociationRecord = domain.InstanceProfileAssociationRecord
	InstanceCredentialReferences     = domain.InstanceCredentialReferences
	IdentitySigningKeyRecord         = domain.IdentitySigningKeyRecord
	ReservationRecord                = domain.ReservationRecord
	InstanceIntent                   = domain.InstanceIntent
	InstanceVolumeAttachmentRecord   = domain.InstanceVolumeAttachmentRecord
	InstanceCreditRecord             = domain.InstanceCreditRecord
	InstancePerformanceRecord        = domain.InstancePerformanceRecord
	InstancePerformanceStatistics    = domain.InstancePerformanceStatistics
	InstancePerformanceGroup         = domain.InstancePerformanceGroup
	InstanceCreditDefaultRecord      = domain.InstanceCreditDefaultRecord
	InstanceCreditLaunchRecord       = domain.InstanceCreditLaunchRecord
	InstanceCreditModificationKey    = domain.InstanceCreditModificationKey
	InstanceCreditModification       = domain.InstanceCreditModification
	InstanceCreditModificationRecord = domain.InstanceCreditModificationRecord
	SecurityGroupRuleRecord          = domain.SecurityGroupRuleRecord
	RouteTableRecord                 = domain.RouteTableRecord
	InternetGatewayRecord            = domain.InternetGatewayRecord
	NetworkInterfaceRecord           = domain.NetworkInterfaceRecord
	NetworkInterfaceCreationKey      = domain.NetworkInterfaceCreationKey
	NetworkInterfaceCreationRecord   = domain.NetworkInterfaceCreationRecord
	NetworkACLRecord                 = domain.NetworkACLRecord
	DHCPOptionsRecord                = domain.DHCPOptionsRecord
	DHCPDefaultsRecord               = domain.DHCPDefaultsRecord
	NetworkCreationKey               = domain.NetworkCreationKey
	NetworkCreationRecord            = domain.NetworkCreationRecord
	NatGatewayRecord                 = domain.NatGatewayRecord
	VPCEndpointRecord                = domain.VPCEndpointRecord
	NetworkOwnerCreationRecord       = domain.NetworkOwnerCreationRecord
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }

func FormatResourceID(scope Scope, prefix string, sequence uint64) (string, error) {
	return domain.FormatResourceID(scope, prefix, sequence)
}
