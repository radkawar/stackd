package codebuild

import (
	"context"
	"errors"
	api "stackd/internal/awsapi/codebuild"
	"time"
)

var ErrNotFound = errors.New("CodeBuild resource not found")

type Scope struct{ Partition, AccountID, Region string }
type ProjectKey struct {
	Scope
	Name string
}

func (k ProjectKey) ARN() string {
	return "arn:" + k.Partition + ":codebuild:" + k.Region + ":" + k.AccountID + ":project/" + k.Name
}

type BuildKey struct {
	Scope
	ID string
}

func (k BuildKey) ARN() string {
	return "arn:" + k.Partition + ":codebuild:" + k.Region + ":" + k.AccountID + ":build/" + k.ID
}

type FleetKey struct {
	Scope
	Name string
}

// ARN identifies a single fleet incarnation; its name alone is only a storage key.
func (k FleetKey) ARN(id string) string {
	return "arn:" + k.Partition + ":codebuild:" + k.Region + ":" + k.AccountID + ":fleet/" + k.Name + ":" + id
}

type CredentialKey struct {
	Scope
	ServerType, AuthType string
}
type ProjectRecord struct {
	Key         ProjectKey
	Data        api.Project
	BuildNumber int64
}
type BuildRecord struct {
	Key                           BuildKey
	Data                          api.Build
	Artifacts                     api.ProjectArtifacts
	SecondaryArtifacts            api.ProjectArtifactsList
	Logs                          api.LogsConfig
	PipelineActionID              string
	PipelineInputs                []PipelineInput
	PipelineOutputs               []PipelineOutput
	AcceptedEventID               string
	IdempotencyToken, RequestHash string
	// RetrySourceID is the original build, not a pipeline action or runtime lease.
	// It survives deletion of that build and fences the RetryBuild token namespace.
	RetrySourceID                                  string
	Deadline, QueuedDeadline                       time.Time
	StopRequested, DeleteRequested, CleanupPending bool
	LogOffset                                      int64
	Failure                                        string
	FleetARN                                       string
	CredentialToken                                string
}
type FleetRecord struct {
	Key  FleetKey
	Data api.Fleet
}

// Imported source credentials retain KMS ciphertext, never plaintext tokens.
type CredentialRecord struct {
	Key        CredentialKey
	ARN        string
	Ciphertext []byte
}
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
	Attempt(context.Context, func(Transaction) error) error
}
type Reader interface {
	Context() context.Context
	Project(ProjectKey) (ProjectRecord, error)
	Projects(Scope) ([]ProjectRecord, error)
	Build(BuildKey) (BuildRecord, error)
	Builds(Scope) ([]BuildRecord, error)
	ActiveBuilds() ([]BuildRecord, error)
	Fleet(FleetKey) (FleetRecord, error)
	Fleets(Scope) ([]FleetRecord, error)
	AllFleets() ([]FleetRecord, error)
	Credential(CredentialKey) (CredentialRecord, error)
	Credentials(Scope) ([]CredentialRecord, error)
}
type Transaction interface {
	Reader
	PutProject(ProjectRecord) error
	DeleteProject(ProjectKey) error
	PutBuild(BuildRecord) error
	DeleteBuild(BuildKey) error
	PutFleet(FleetRecord) error
	DeleteFleet(FleetKey) error
	PutCredential(CredentialRecord) error
	DeleteCredential(CredentialKey) error
}
