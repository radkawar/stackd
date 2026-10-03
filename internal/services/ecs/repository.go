// Package ecs owns regional ECS clusters, task definitions and retained tasks.
package ecs

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/ecs"
	"strconv"
	"time"
)

var ErrNotFound = errors.New("ECS resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ClusterKey struct {
	Scope
	Name string
}

func (k ClusterKey) ARN() string {
	return "arn:" + k.Partition + ":ecs:" + k.Region + ":" + k.AccountID + ":cluster/" + k.Name
}

type FamilyKey struct {
	Scope
	Family string
}
type TaskDefinitionKey struct {
	FamilyKey
	Revision int32
}

func (k TaskDefinitionKey) ARN() string {
	return "arn:" + k.Partition + ":ecs:" + k.Region + ":" + k.AccountID + ":task-definition/" + k.Family + ":" + strconv.FormatInt(int64(k.Revision), 10)
}

// Data is canonical generated resource state, not a second parallel resource model.
// Tags live exclusively in TagRecord; Data.Tags must be nil in storage.
// CreateInput retains the admitted idempotency arguments independently of updates.
// Deletion retains INACTIVE data. Recreation replaces this row and its tags.
type ClusterRecord struct {
	Key              ClusterKey
	Data             api.Cluster
	CreateInput      api.CreateClusterInput
	Created, Updated time.Time
}

// PreviousStatus is a transition-response field and must be nil in Data.
// DELETE_IN_PROGRESS remains addressable until the service reaps unreferenced revisions.
// The family revision high-water mark survives every resource deletion.
type TaskDefinitionRecord struct {
	Key  TaskDefinitionKey
	Data api.TaskDefinition
}
type TagKey struct {
	Scope
	ResourceARN string
}
type TagRecord struct {
	Key  TagKey
	Tags api.Tags
}
type ClusterQuery struct {
	Scope
	After           string
	Limit           int
	IncludeInactive bool
}
type TaskDefinitionQuery struct {
	Scope
	Family, FamilyPrefix, Status, AfterFamily string
	AfterRevision                             int32
	Descending                                bool
	Limit                                     int
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	// Attempt isolates a public command rejection within an enclosing write.
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	MetricReader
	Context() context.Context
	Cluster(ClusterKey) (ClusterRecord, error)
	Clusters(ClusterQuery) ([]ClusterRecord, error)
	// ActiveClusterKeys includes every region, ordered by region and name.
	ActiveClusterKeys(partition, accountID string) ([]ClusterKey, error)
	Service(ServiceKey) (ServiceRecord, error)
	Services(ServiceQuery) ([]ServiceRecord, error)
	ServiceRevision(ServiceRevisionKey) (ServiceRevisionRecord, error)
	// ActiveServiceKeys includes ACTIVE and DRAINING services across every scope.
	ActiveServiceKeys() ([]ServiceKey, error)
	TaskDefinition(TaskDefinitionKey) (TaskDefinitionRecord, error)
	TaskDefinitions(TaskDefinitionQuery) ([]TaskDefinitionRecord, error)
	Task(TaskKey) (TaskRecord, error)
	Tasks(TaskQuery) ([]TaskRecord, error)
	// ActiveTaskKeys spans all scopes, ordered by partition, account, region, cluster and ID.
	ActiveTaskKeys() ([]TaskKey, error)
	TaskRun(TaskRunKey) (TaskRunRecord, error)
	Tags(TagKey) (TagRecord, error)
}
type Transaction interface {
	Reader
	MetricWriter
	PutCluster(ClusterRecord) error
	PutService(ServiceRecord) error
	PutServiceRevision(ServiceRevisionRecord) error
	DeleteServiceRevisions(ServiceKey) error
	PutTaskDefinition(TaskDefinitionRecord) error
	// DeleteTaskDefinition removes the revision and its tags, preserving family history.
	DeleteTaskDefinition(TaskDefinitionKey) error
	NextTaskDefinitionRevision(FamilyKey) (int32, error)
	PutTask(TaskRecord) error
	PutTaskRun(TaskRunRecord) error
	PutTags(TagRecord) error
}
