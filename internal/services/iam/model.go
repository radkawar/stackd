// Package iam implements the AWS IAM Query API for local cloud applications.
package iam

import "time"

type Tag struct {
	Key   string
	Value string
}

type Boundary struct {
	PermissionsBoundaryType string
	PermissionsBoundaryArn  string
}

type IdentityPolicies struct {
	Inline   map[string]string
	Attached map[string]struct{}
}

func newIdentityPolicies() identityPolicies {
	return identityPolicies{Inline: make(map[string]string), Attached: make(map[string]struct{})}
}

type User struct {
	Path                string
	UserName            string
	UserId              string
	Arn                 string
	CreateDate          time.Time
	PasswordLastUsed    *time.Time
	PermissionsBoundary *boundary
	Tags                []tag
	IdentityPolicies
}

type Group struct {
	Path       string
	GroupName  string
	GroupId    string
	Arn        string
	CreateDate time.Time
	IdentityPolicies
	Members map[string]struct{}
}

type Role struct {
	Path                     string
	RoleName                 string
	RoleId                   string
	Arn                      string
	CreateDate               time.Time
	AssumeRolePolicyDocument string
	Description              string
	MaxSessionDuration       int
	PermissionsBoundary      *boundary
	Tags                     []tag
	TrustPrincipalIDs        map[string]string
	ServiceLinkedService     string
	// Identity Center ownership is service-managed, never inferred from names,
	// tags, trust documents or caller-supplied IAM metadata.
	IdentityCenterInstanceARN      string
	IdentityCenterPermissionSetARN string
	SourceRoleTemplate             *RoleTemplateSource
	LastUsed                       RoleLastUse
	IdentityPolicies
}

// RoleTemplateSource retains the native template association and the inputs
// needed to compare current policies with that immutable version during reuse.
// Customer edits to description and session duration do not affect reuse.
type RoleTemplateSource struct {
	ARN          string
	MinorVersion int32
	Parameters   map[string][]string
}

// RoleLastUse survives the expiration or deletion of individual STS sessions.
// IAM reports use during the trailing 400 days of tracked request history.
// A zero date and empty region together represent no observed use.
type RoleLastUse struct {
	Date   time.Time
	Region string
}

func (use RoleLastUse) recorded() bool {
	// A real request at the zero epoch still has its gateway-recorded region.
	return !use.Date.IsZero() || use.Region != ""
}

type ManagedPolicy struct {
	PolicyName                    string
	PolicyId                      string
	Arn                           string
	Path                          string
	DefaultVersionId              string
	AttachmentCount               int
	PermissionsBoundaryUsageCount int
	IsAttachable                  bool
	Description                   string
	CreateDate                    time.Time
	UpdateDate                    time.Time
	Tags                          []tag
	Versions                      map[string]*policyVersion
	NextVersion                   int
}

type PolicyVersion struct {
	Document         string
	VersionId        string
	IsDefaultVersion bool
	CreateDate       time.Time
}

type account struct {
	// currentTime is the transient transaction instant, never a stored record.
	currentTime         time.Time
	signingCertificates map[string]*SigningCertificateRecord
	sshKeys             map[string]*SSHPublicKeyRecord
	serverCertificates  map[string]*ServerCertificateRecord

	partition              string
	users                  map[string]*user
	groups                 map[string]*group
	roles                  map[string]*role
	policies               map[string]*policy
	mfaDevices             map[string]*MFADevice
	instanceProfiles       map[string]*InstanceProfile
	loginProfiles          map[string]*LoginProfileRecord
	serviceCredentials     map[string]*ServiceCredentialRecord
	oidcProviders          map[string]*OIDCProviderRecord
	samlProviders          map[string]*SAMLProviderRecord
	serviceLinkedDeletions map[string]*ServiceLinkedRoleDeletion
	settings               AccountSettingsRecord
	metadata               *AccountMetadata
}

func newAccount() *account {
	return &account{
		signingCertificates: make(map[string]*SigningCertificateRecord),
		sshKeys:             make(map[string]*SSHPublicKeyRecord),
		serverCertificates:  make(map[string]*ServerCertificateRecord),

		users: make(map[string]*user), groups: make(map[string]*group), roles: make(map[string]*role), policies: make(map[string]*policy),
		mfaDevices: make(map[string]*MFADevice), instanceProfiles: make(map[string]*InstanceProfile), loginProfiles: make(map[string]*LoginProfileRecord),
		serviceCredentials: make(map[string]*ServiceCredentialRecord), oidcProviders: make(map[string]*OIDCProviderRecord), samlProviders: make(map[string]*SAMLProviderRecord),
		serviceLinkedDeletions: make(map[string]*ServiceLinkedRoleDeletion),
	}
}

// Internal aliases retain concise operation code while repository contracts use exported resource records.
type tag = Tag
type boundary = Boundary
type identityPolicies = IdentityPolicies
type user = User
type group = Group
type role = Role
type policy = ManagedPolicy
type policyVersion = PolicyVersion
