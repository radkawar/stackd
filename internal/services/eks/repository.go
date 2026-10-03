// Package eks owns EKS cluster intent and IAM-bound Kubernetes access.
package eks

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("eks resource not found")

type Scope struct{ Partition, AccountID, Region string }
type Key struct {
	Scope
	Name string
}

func (k Key) ARN() string {
	return "arn:" + k.Partition + ":eks:" + k.Region + ":" + k.AccountID + ":cluster/" + k.Name
}

// Cluster contains AWS intent and observed endpoint metadata, never Kubernetes admin credentials.
type Cluster struct {
	Key                                                      Key
	ID, RoleARN, KubernetesVersion, Status, Operation, Error string
	Endpoint, CertificateAuthority, VPCID                    string
	Subnets, SecurityGroups                                  []string
	Tags                                                     map[string]string
	EnabledLogTypes                                          []string
	Created, Due                                             time.Time
	Generation                                               int64
	ClientToken, RequestHash, CreatorARN, CreatorID          string
	AuthenticationMode                                       string
	BootstrapAdmin, DeletionProtection                       bool
}
type AccessEntry struct {
	Key                                       Key
	PrincipalARN, PrincipalID, Username, Type string
	ID, ClientToken, RequestHash              string
	Groups                                    []string
	Tags                                      map[string]string
	Created, Modified                         time.Time
}

// AccessMutation prevents a replayed older update from resurrecting revoked groups.
type AccessMutation struct {
	Key                              Key
	PrincipalARN, Token, RequestHash string
}
type AccessPolicy struct {
	Key                                Key
	PrincipalARN, PolicyARN, ScopeType string
	Namespaces                         []string
	Associated, Modified               time.Time
}
type UpdateParam struct {
	Type, Value string
}

type Update struct {
	Key                                                                 Key
	ID, Type, Status, ErrorCode, ErrorMessage, ClientToken, RequestHash string
	Created                                                             time.Time
	DeletionProtection                                                  *bool
	AuthenticationMode                                                  string
	KubernetesVersion                                                   string
	EnabledLogTypes                                                     []string
	ResourceType, ResourceName                                          string
	Params                                                              []UpdateParam
}

// Callbacks join the shared transaction domain. Native effects never run inside them.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	AddonReader
	FargateReader
	NodegroupReader
	PodIdentityReader
	Cluster(Key) (Cluster, error)
	Clusters(Scope) ([]Cluster, error)
	AllClusters() ([]Cluster, error)
	AccessEntry(Key, string) (AccessEntry, error)
	AccessEntries(Key) ([]AccessEntry, error)
	AccessMutation(Key, string, string) (AccessMutation, error)
	AccessPolicies(Key, string) ([]AccessPolicy, error)
	ClusterUpdate(Key, string) (Update, error)
	ClusterUpdates(Key) ([]Update, error)
}
type Transaction interface {
	Reader
	AddonTransaction
	FargateTransaction
	NodegroupTransaction
	PodIdentityTransaction
	PutCluster(Cluster) error
	DeleteCluster(Key) error
	PutAccessEntry(AccessEntry) error
	DeleteAccessEntry(Key, string) error
	PutAccessMutation(AccessMutation) error
	PutAccessPolicy(AccessPolicy) error
	DeleteAccessPolicy(Key, string, string) error
	PutClusterUpdate(Update) error
}

// Networks resolves current EC2 subnet and security-group ownership in the cluster transaction.
type Networks interface {
	ValidateClusterNetwork(context.Context, string, string, []string, []string) (string, error)
}

// Principals binds access entries to immutable current IAM identity, not reusable ARNs.
type Principals interface {
	ResolvePrincipal(context.Context, string) (string, error)
}

// ServiceLinkedRoles provisions EKS service authority in the same command transaction.
type ServiceLinkedRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}
