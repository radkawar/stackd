// Package athena runs pinned native Trino SQL. AWS identity, Glue metadata,
// query state and S3 object ownership remain with the Go service owners.
package athena

import (
	"context"
	"encoding/json"
	"net/http"
)

// Runtime executes a query outside service transactions. The retained handle is
// published before native creation so controller recovery can remove an orphan
// without replaying a possibly committed SQL write. Cancel is idempotent.
type Runtime interface {
	Execute(context.Context, Request, func(string) error, func(Page) error) error
	Cancel(context.Context, string) error
}

// Request supplies an authenticated, query-scoped Glue/S3 callback. That handler
// must invoke the ordinary owners as the caller, never as an engine-wide role.
// The runtime authenticates the container callback before invoking Handler.
type Request struct {
	ID, Partition, AccountID, Region  string
	SQL, Catalog, Database, CatalogID string
	PreparedStatements                map[string]string
	Parameters                        []string
	BytesCutoff                       int64
	Handler                           http.Handler
}

// Column retains the native type spelling and signature, including precision,
// scale and nested types. Values use raw JSON to avoid float64 precision loss.
type Column struct {
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	TypeSignature TypeSignature `json:"typeSignature"`
}
type TypeSignature struct {
	RawType   string         `json:"rawType"`
	Arguments []TypeArgument `json:"arguments"`
}
type TypeArgument struct {
	Kind  string          `json:"kind"`
	Value json.RawMessage `json:"value"`
}

type Statistics struct {
	State              string `json:"state"`
	ElapsedMillis      int64  `json:"elapsedTimeMillis"`
	CPUTimeMillis      int64  `json:"cpuTimeMillis"`
	ProcessedRows      int64  `json:"processedRows"`
	ProcessedBytes     int64  `json:"processedBytes"`
	PhysicalInputBytes int64  `json:"physicalInputBytes"`
	PeakMemoryBytes    int64  `json:"peakMemoryBytes"`
}

// Page is consumed before fetching its successor; result rows are never retained
// by the runtime. A final page has no NextURI, even when Stats.State lags behind.
type Page struct {
	ID          string              `json:"id"`
	NextURI     string              `json:"nextUri"`
	Columns     []Column            `json:"columns"`
	Data        [][]json.RawMessage `json:"data"`
	Stats       Statistics          `json:"stats"`
	Error       *QueryError         `json:"error"`
	UpdateType  string              `json:"updateType"`
	UpdateCount *int64              `json:"updateCount"`
	HiveDDL     *HiveDDL            `json:"-"`
	QueryType   string              `json:"-"`
}

// QueryError is the native SQL failure, not a fabricated Athena success.
type QueryError struct {
	Message       string                                  `json:"message"`
	ErrorCode     int64                                   `json:"errorCode"`
	ErrorName     string                                  `json:"errorName"`
	ErrorType     string                                  `json:"errorType"`
	ErrorLocation *struct{ LineNumber, ColumnNumber int } `json:"errorLocation"`
}

func (e *QueryError) Error() string { return e.ErrorName + ": " + e.Message }
