package lambda

import (
	"context"
	"errors"
	"time"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
)

var ErrNotFound = errors.New("lambda function not found")

type Scope struct{ Partition, Account, Region string }
type FunctionKey struct {
	Scope
	Name string
}

func (k FunctionKey) ARN() string {
	return "arn:" + k.Partition + ":lambda:" + k.Region + ":" + k.Account + ":function:" + k.Name
}

// FunctionRecord is an authoritative deployment configuration. The repository
// keeps active and pending slots separate until real runtime readiness commits.
// ZIP bytes live in the referenced CodeArchive; runtime environments are external.
type FunctionRecord struct {
	Key                                               FunctionKey
	Version                                           uint64
	Runtime, Handler, Role, Description, Architecture string
	// Image retains the deployed image ID, never a mutable tag resolution.
	Image              *runtime.Image
	ImageConfig        *api.ImageConfig
	NetworkIncarnation string
	VpcConfig          FunctionNetworkConfiguration
	Owner              FunctionOwner
	DeadLetterARN      string
	// LogGroup is empty for the derived /aws/lambda/<name> destination.
	LogGroup                                string
	Logging                                 runtime.LoggingConfig
	CodeSize                                int64
	CodeSHA256                              string
	Layers                                  []LayerAttachment
	Reference                               *S3ObjectReference
	Durable                                 *api.DurableConfig
	Capacity                                *CapacityFunctionConfig
	SigningProfileVersionARN, SigningJobARN string
	// CodeSourceCheckAt belongs to the optional own-code reference, not layers.
	CodeSourceCheckAt              time.Time
	Variables, Tags                map[string]string
	Timeout, MemoryMB, EphemeralMB int
	Revision                       string
	// DeploymentRevision changes only when code or runtime configuration changes.
	// Metadata-only API revision changes must not retire running environments.
	DeploymentRevision                  string
	Modified                            time.Time
	State, StateReason, StateReasonCode string
	UpdateStatus, UpdateReason          string
}

type Reader interface {
	PolicyReader
	AsyncReader
	OutcomeReader
	MetricReader
	ConcurrencyReader
	CodeReader
	VersionReader
	AliasReader
	LayerReader
	CodeSourceReader
	FunctionURLReader
	EventSourceMappingReader
	StreamReader
	DocumentDBCheckpointReader
	RuntimeControlReader
	CodeSigningReader
	DurableReader
	CapacityReader
	Context() context.Context
	Function(FunctionKey) (FunctionRecord, error)
	Functions(Scope) ([]FunctionRecord, error)
	AllFunctions() ([]FunctionRecord, error)
	PendingFunction(FunctionKey) (FunctionRecord, error)
	PendingFunctions() ([]FunctionRecord, error)
}
type Transaction interface {
	Reader
	PolicyWriter
	AsyncWriter
	OutcomeWriter
	MetricWriter
	ConcurrencyWriter
	CodeWriter
	VersionWriter
	AliasWriter
	LayerWriter
	CodeSourceWriter
	FunctionURLWriter
	EventSourceMappingWriter
	StreamWriter
	DocumentDBCheckpointWriter
	RuntimeControlWriter
	CodeSigningWriter
	DurableTransaction
	CapacityWriter
	PutFunction(FunctionRecord) error
	DeleteFunction(FunctionKey) error
	PutPendingFunction(FunctionRecord) error
	DeletePendingFunction(FunctionKey) error
}

// Repository joins the instance transaction domain for current IAM decisions.
// Callback failures publish neither deployment state nor related identity writes.
type Repository interface {
	View(context.Context, func(Reader) error) error
	Update(context.Context, func(Transaction) error) error
}
