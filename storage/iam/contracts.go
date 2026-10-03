// Package iam exposes the typed IAM storage contract for backend implementations.
// Aliases preserve the service's domain types without duplicating their schemas.
package iam

import (
	domain "stackd/internal/services/iam"
	"stackd/storage/memory"
)

// Storage contracts and records retain the service-defined transaction and
// ownership rules. See the aliased types for their full documentation.
type (
	Repository                      = domain.Repository
	ReadTx                          = domain.ReadTx
	WriteTx                         = domain.WriteTx
	Scope                           = domain.Scope
	Tag                             = domain.Tag
	Boundary                        = domain.Boundary
	IdentityPolicies                = domain.IdentityPolicies
	User                            = domain.User
	Group                           = domain.Group
	Role                            = domain.Role
	RoleTemplateSource              = domain.RoleTemplateSource
	RoleLastUse                     = domain.RoleLastUse
	ManagedPolicy                   = domain.ManagedPolicy
	PolicyVersion                   = domain.PolicyVersion
	MFADevice                       = domain.MFADevice
	MFABinding                      = domain.MFABinding
	MFAUsedCode                     = domain.MFAUsedCode
	MFAVerificationCount            = domain.MFAVerificationCount
	InstanceProfile                 = domain.InstanceProfile
	PasswordDigest                  = domain.PasswordDigest
	LoginProfileRecord              = domain.LoginProfileRecord
	RootLoginProfileRecord          = domain.RootLoginProfileRecord
	AccountPasswordPolicy           = domain.AccountPasswordPolicy
	AccountSettingsRecord           = domain.AccountSettingsRecord
	OutboundWebIdentityRecord       = domain.OutboundWebIdentityRecord
	OutboundSigningKey              = domain.OutboundSigningKey
	Propagated[T comparable]        = domain.Propagated[T]
	PropagationChange[T comparable] = domain.PropagationChange[T]
	AccountMetadata                 = domain.AccountMetadata
	CredentialReportRecord          = domain.CredentialReportRecord
	CredentialReportState           = domain.CredentialReportState
	PrincipalActivity               = domain.PrincipalActivity
	AccessReport                    = domain.AccessReport
	OrganizationAccessReport        = domain.OrganizationAccessReport
	OrganizationServiceAccess       = domain.OrganizationServiceAccess
	AccountActivity                 = domain.AccountActivity
	AccessReportError               = domain.AccessReportError
	ServiceAccess                   = domain.ServiceAccess
	ActionAccess                    = domain.ActionAccess
	EntityAccess                    = domain.EntityAccess
	ServiceCredentialRecord         = domain.ServiceCredentialRecord
	SigningCertificateRecord        = domain.SigningCertificateRecord
	SSHPublicKeyRecord              = domain.SSHPublicKeyRecord
	ServerCertificateRecord         = domain.ServerCertificateRecord
	OIDCProviderRecord              = domain.OIDCProviderRecord
	SAMLProviderRecord              = domain.SAMLProviderRecord
	SAMLIssuerRecord                = domain.SAMLIssuerRecord
	SAMLPrivateKeyRecord            = domain.SAMLPrivateKeyRecord
	ServiceLinkedRoleDeletion       = domain.ServiceLinkedRoleDeletion
	ServiceLinkedRoleUsage          = domain.ServiceLinkedRoleUsage
	ServiceLinkedRoleInUseError     = domain.ServiceLinkedRoleInUseError
)

const (
	CredentialReportPending  = domain.CredentialReportPending
	CredentialReportComplete = domain.CredentialReportComplete
	CredentialReportFailed   = domain.CredentialReportFailed
)

// NewMemory constructs an empty backend using the shared memory transaction engine.
func NewMemory(transactionDomain *memory.Domain) Repository {
	return domain.NewMemoryRepository(transactionDomain)
}

var ErrRecordNotFound = domain.ErrRecordNotFound
var ErrClosedTransaction = domain.ErrClosedTransaction
