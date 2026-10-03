package athena

import (
	"context"

	api "stackd/internal/awsapi/athena"
	metricsapi "stackd/internal/awsapi/cloudwatch"
	glueapi "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
)

// Catalog delegates to the ordinary generated Glue command edge, preserving
// current caller authorization and Glue as the sole metadata authority.
type Catalog interface {
	GetDatabase(context.Context, *glueapi.GetDatabaseInput) (*glueapi.GetDatabaseOutput, *awswire.Error)
	GetDatabases(context.Context, *glueapi.GetDatabasesInput) (*glueapi.GetDatabasesOutput, *awswire.Error)
	GetTable(context.Context, *glueapi.GetTableInput) (*glueapi.GetTableOutput, *awswire.Error)
	GetTables(context.Context, *glueapi.GetTablesInput) (*glueapi.GetTablesOutput, *awswire.Error)
}

// ExecutionRequest captures the accepted query and resolved catalog registration.
// PreparedStatements belong to this workgroup only. The runtime must read real
// S3 bytes with the current caller, not ambient host credentials.
type ExecutionRequest struct {
	Query              QueryRecord
	Catalog            api.DataCatalog
	PreparedStatements []api.PreparedStatement
}
type ExecutionResult struct {
	Columns api.ColumnInfoList
	// CSV includes a header row; null fields are unquoted empty fields. Empty
	// strings must be quoted so GetQueryResults can preserve SQL NULL semantics.
	CSV                                         []byte
	UpdateCount, DataScannedBytes, EngineMillis int64
	StatementType, SubstatementType             string
	ManifestLocation                            string
}

// ExecutionFailure classifies a real native error at the Athena boundary. The
// adapter supplies evidenced AWS error categories; the original diagnostic is
// retained in the authorized query status rather than replaced with success.
type ExecutionFailure struct {
	Message        string
	Category, Type int32
	Retryable      bool
	Cancelled      bool
}

func (e *ExecutionFailure) Error() string { return e.Message }

// Engine executes actual SQL outside transactions. started MUST retain an opaque
// owned execution handle before creating any native resource or running SQL.
// Failure to retain the handle aborts execution. Cancel addresses only that
// execution and is idempotent for an absent resource. Recovery never replays an
// ambiguous SQL write: it cancels retained handles and fails interrupted work.
type Engine interface {
	Execute(context.Context, ExecutionRequest, func(string) error) (ExecutionResult, error)
	Cancel(context.Context, string) error
}

// Results uses normal authorized S3 commands, including expected-owner, ACL and
// server-side encryption/KMS checks. Read uses the requesting caller, not the
// original query submitter, as required by GetQueryResults.
type Results interface {
	Write(context.Context, QueryRecord, []byte) *awswire.Error
	Read(context.Context, QueryRecord) ([]byte, *awswire.Error)
}

type QueryEvent struct {
	Query         QueryRecord
	PreviousState string
}

// QueryEvents admits the native state-change event in the same transaction as
// query metadata; it must use the shared EventBridge/journal owner.
type QueryEvents interface {
	Publish(context.Context, QueryEvent) error
}
type MetricPublisher interface {
	Publish(context.Context, string, []metricsapi.MetricDatum) error
}
