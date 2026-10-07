// Package kafka owns MSK controls and retained native Kafka intent.
package kafka

import (
	"context"
	"errors"
	"stackd/internal/authorization"
	"time"
)

var ErrNotFound = errors.New("MSK resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ClusterRecord struct {
	Scope
	ARN, Name, Incarnation, KafkaVersion, SecurityMode  string
	State, Failure, Operation, OperationARN             string
	ConfigurationARN, PendingConfigurationARN           string
	ConfigurationRevision, PendingConfigurationRevision int64
	ServerProperties, PendingServerProperties           string
	Brokers                                             int32
	RebootBrokerID                                      int32
	Version                                             int64
	Created, Due                                        time.Time
	Endpoint                                            Endpoint
	Tags                                                map[string]string
	Secrets                                             []string
	Policy                                              authorization.BoundPolicy
	PolicyVersion                                       int64
	// Private immutable CloudFormation incarnation claim set at CreateCluster;
	// unlike Tags it is never accepted from or rendered by an MSK API.
	OwnerStackID, OwnerLogicalID, OwnerToken string
}
type ConfigurationRecord struct {
	Scope
	ARN, Name, Description                   string
	Created                                  time.Time
	LatestRevision                           int64
	KafkaVersions                            []string
	OwnerStackID, OwnerLogicalID, OwnerToken string
}
type RevisionRecord struct {
	ARN                           string
	Revision                      int64
	Description, ServerProperties string
	Created                       time.Time
}
type OperationRecord struct {
	Scope
	ARN, ClusterARN, Type, State, Failure          string
	SourceConfigurationARN, TargetConfigurationARN string
	SourceRevision, TargetRevision                 int64
	Created, Ended                                 time.Time
}

// All callbacks join the shared state/journal domain. Native effects are never
// permitted in callbacks; the scheduler fences results against Version/Incarnation.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Cluster(string) (ClusterRecord, error)
	Clusters(Scope) ([]ClusterRecord, error)
	AllClusters() ([]ClusterRecord, error)
	Configuration(string) (ConfigurationRecord, error)
	Configurations(Scope) ([]ConfigurationRecord, error)
	Revision(string, int64) (RevisionRecord, error)
	Revisions(string) ([]RevisionRecord, error)
	Operation(string) (OperationRecord, error)
	Operations(string) ([]OperationRecord, error)
}
type Transaction interface {
	Reader
	PutCluster(ClusterRecord) error
	DeleteCluster(string) error
	PutConfiguration(ConfigurationRecord) error
	DeleteConfiguration(string) error
	PutRevision(RevisionRecord) error
	PutOperation(OperationRecord) error
}
