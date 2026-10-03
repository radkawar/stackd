package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	native "stackd/engine/athena"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/athena"
	glueapi "stackd/internal/awsapi/glue"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/services/athena"
)

// AthenaEngine connects the native SQL engine to the existing, authenticated
// Glue and S3 command owners. These are service providers, not the public gateway:
// the runtime has already verified an unguessable per-execution capability.
type AthenaGlueProvider interface {
	http.Handler
	AthenaGlueCommands
}

type AthenaEngine struct {
	Runtime native.Runtime
	Glue    AthenaGlueProvider
	S3      http.Handler
}

var _ athena.Engine = (*AthenaEngine)(nil)

func (a *AthenaEngine) Cancel(ctx context.Context, handle string) error {
	if a.Runtime == nil {
		return errors.New("athena SQL engine is not configured")
	}
	return a.Runtime.Cancel(ctx, handle)
}

func (a *AthenaEngine) Execute(ctx context.Context, request athena.ExecutionRequest, started func(string) error) (athena.ExecutionResult, error) {
	var result athena.ExecutionResult
	if a.Runtime == nil || a.Glue == nil || a.S3 == nil {
		return result, errors.New("athena native SQL, Glue and S3 adapters are required")
	}
	if request.Catalog.Type != nil && *request.Catalog.Type != "GLUE" {
		return result, &awswire.Error{Code: "InvalidRequestException", Message: "Only authoritative Glue catalogs are supported by the native SQL engine.", StatusCode: 400}
	}
	query := request.Query
	if query.Data.Query == nil {
		return result, errors.New("athena query text is missing")
	}
	bridge := &athenaDataPlane{execution: ctx, glue: a.Glue, s3: a.S3, caller: query.Caller, parent: query.ParentEventID, requesterPays: query.RequesterPays}
	nativeRequest := native.Request{ID: query.Key.Name, Partition: query.Key.Partition, AccountID: query.Key.AccountID, Region: query.Key.Region, SQL: string(*query.Data.Query), Catalog: "awsdatacatalog", CatalogID: query.Key.AccountID, Handler: bridge, BytesCutoff: query.BytesCutoff}
	if execution := query.Data.QueryExecutionContext; execution != nil {
		if execution.Catalog != nil {
			nativeRequest.Catalog = string(*execution.Catalog)
		}
		if execution.Database != nil {
			nativeRequest.Database = string(*execution.Database)
		}
	}
	if catalogID, ok := request.Catalog.Parameters["catalog-id"]; ok {
		nativeRequest.CatalogID = string(catalogID)
	}
	if len(request.PreparedStatements) > 0 {
		nativeRequest.PreparedStatements = make(map[string]string, len(request.PreparedStatements))
	}
	for _, statement := range request.PreparedStatements {
		if statement.StatementName != nil && statement.QueryStatement != nil {
			nativeRequest.PreparedStatements[string(*statement.StatementName)] = string(*statement.QueryStatement)
		}
	}
	if len(query.Data.ExecutionParameters) > 0 {
		nativeRequest.Parameters = make([]string, len(query.Data.ExecutionParameters))
		for i, parameter := range query.Data.ExecutionParameters {
			nativeRequest.Parameters[i] = string(parameter)
		}
	}
	var csv bytes.Buffer
	var columns []native.Column
	err := a.Runtime.Execute(ctx, nativeRequest, started, func(page native.Page) error {
		result.EngineMillis = page.Stats.ElapsedMillis
		result.DataScannedBytes = page.Stats.PhysicalInputBytes
		if page.UpdateCount != nil {
			result.UpdateCount = *page.UpdateCount
		}
		if page.QueryType != "" {
			result.StatementType = "DML"
			switch page.QueryType {
			case "DATA_DEFINITION", "ALTER_TABLE_EXECUTE":
				result.StatementType = "DDL"
			case "EXPLAIN", "DESCRIBE":
				result.StatementType = "UTILITY"
			}
			result.SubstatementType = page.QueryType
		}
		if page.UpdateType != "" {
			result.SubstatementType = strings.ReplaceAll(page.UpdateType, " ", "_")
		}
		if page.HiveDDL != nil {
			result.StatementType = "DDL"
		}
		if page.HiveDDL != nil {
			if err := a.applyHiveDDL(ctx, request, *page.HiveDDL); err != nil {
				return err
			}
		}
		if columns == nil && len(page.Columns) != 0 {
			columns = page.Columns
			result.Columns = make(api.ColumnInfoList, len(columns))
			for i, column := range columns {
				result.Columns[i] = athenaColumn(column)
				if i != 0 {
					csv.WriteByte(',')
				}
				athenaCSVString(&csv, column.Name)
			}
			csv.WriteByte('\n')
		}
		for _, row := range page.Data {
			if len(row) != len(columns) {
				return errors.New("native SQL row does not match its result columns")
			}
			for i, cell := range row {
				if i != 0 {
					csv.WriteByte(',')
				}
				if bytes.Equal(cell, []byte("null")) {
					continue
				}
				value, err := athenaCell(cell, columns[i].TypeSignature)
				if err != nil {
					return err
				}
				athenaCSVString(&csv, value)
			}
			csv.WriteByte('\n')
		}
		return nil
	})
	if err != nil {
		var nativeError *native.QueryError
		if errors.As(err, &nativeError) {
			switch nativeError.ErrorName {
			case "EXCEEDED_SCAN_LIMIT":
				return result, &athena.ExecutionFailure{Message: err.Error(), Cancelled: true}
			case "COLUMN_NOT_FOUND", "FUNCTION_NOT_FOUND", "SYNTAX_ERROR":
				return result, &athena.ExecutionFailure{Message: err.Error(), Category: 2, Type: 1006}
			}
		}
		return result, err
	}
	// The native protocol streams pages, but the service/S3 contract currently
	// owns a complete CSV body. TODO: Comeback stream result object multipart
	// publication and result pagination without retaining the full CSV in Go.
	result.CSV = csv.Bytes()
	return result, nil
}

func athenaCSVString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for {
		before, after, found := strings.Cut(value, "\"")
		out.WriteString(before)
		if !found {
			break
		}
		out.WriteString("\"\"")
		value = after
	}
	out.WriteByte('"')
}

func athenaColumn(column native.Column) api.ColumnInfo {
	typ := column.TypeSignature.RawType
	if typ == "" {
		typ, _, _ = strings.Cut(column.Type, "(")
	}
	info := api.ColumnInfo{Name: new(api.String(column.Name)), Label: new(api.String(column.Name)), Type: new(api.String(typ)), Nullable: new(api.ColumnNullable("UNKNOWN")), CaseSensitive: new(api.Boolean(typ == "varchar" || typ == "char")), CatalogName: new(api.String("hive")), SchemaName: new(api.String("")), TableName: new(api.String(""))}
	var precision, scale int32
	switch typ {
	case "boolean":
		precision = 1
	case "tinyint":
		precision = 3
	case "smallint":
		precision = 5
	case "integer":
		precision = 10
	case "bigint":
		precision = 19
	case "real":
		precision = 9
	case "double":
		precision = 17
	case "varchar":
		precision = 2147483647
	}
	if (typ == "decimal" || typ == "varchar" || typ == "char" || typ == "timestamp" || typ == "time") && len(column.TypeSignature.Arguments) > 0 {
		_ = json.Unmarshal(column.TypeSignature.Arguments[0].Value, &precision)
	}
	if typ == "decimal" && len(column.TypeSignature.Arguments) > 1 {
		_ = json.Unmarshal(column.TypeSignature.Arguments[1].Value, &scale)
	}
	info.Precision, info.Scale = new(api.Integer(precision)), new(api.Integer(scale))
	return info
}

func athenaCell(cell json.RawMessage, signature native.TypeSignature) (string, error) {
	// TODO: Comeback calibrate varbinary, unnamed rows, intervals and zoned
	// temporal display beyond the retained native Athena scalar/nested fixture.
	if len(cell) == 0 {
		return "", errors.New("empty native result cell")
	}
	if bytes.Equal(cell, []byte("null")) {
		return "null", nil
	}
	if cell[0] == '"' {
		var value string
		if err := json.Unmarshal(cell, &value); err != nil {
			return "", err
		}
		return value, nil
	}
	switch signature.RawType {
	case "array", "row":
		var cells []json.RawMessage
		if err := json.Unmarshal(cell, &cells); err != nil {
			return "", err
		}
		var elementType native.TypeSignature
		if signature.RawType == "array" {
			if len(signature.Arguments) != 1 {
				return "", errors.New("invalid native array type")
			}
			if err := json.Unmarshal(signature.Arguments[0].Value, &elementType); err != nil {
				return "", err
			}
		}
		var out strings.Builder
		if signature.RawType == "array" {
			out.WriteByte('[')
		} else {
			out.WriteByte('{')
		}
		for index, child := range cells {
			if index != 0 {
				out.WriteString(", ")
			}
			childType := elementType
			if signature.RawType == "row" {
				if index >= len(signature.Arguments) {
					return "", errors.New("invalid native row type")
				}
				var named struct {
					FieldName     *struct{ Name string } `json:"fieldName"`
					TypeSignature native.TypeSignature   `json:"typeSignature"`
				}
				if err := json.Unmarshal(signature.Arguments[index].Value, &named); err != nil {
					return "", err
				}
				childType = named.TypeSignature
				if named.FieldName != nil {
					out.WriteString(named.FieldName.Name + "=")
				}
			}
			value, err := athenaCell(child, childType)
			if err != nil {
				return "", err
			}
			out.WriteString(value)
		}
		if signature.RawType == "array" {
			out.WriteByte(']')
		} else {
			out.WriteByte('}')
		}
		return out.String(), nil
	case "map":
		if len(signature.Arguments) != 2 {
			return "", errors.New("invalid native map type")
		}
		var valueType native.TypeSignature
		if err := json.Unmarshal(signature.Arguments[1].Value, &valueType); err != nil {
			return "", err
		}
		decoder := json.NewDecoder(bytes.NewReader(cell))
		if _, err := decoder.Token(); err != nil {
			return "", err
		}
		var out strings.Builder
		out.WriteByte('{')
		first := true
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return "", err
			}
			text, ok := key.(string)
			if !ok {
				return "", errors.New("invalid native map key")
			}
			var child json.RawMessage
			if err := decoder.Decode(&child); err != nil {
				return "", err
			}
			if !first {
				out.WriteString(", ")
			}
			first = false
			out.WriteString(text + "=")
			value, err := athenaCell(child, valueType)
			if err != nil {
				return "", err
			}
			out.WriteString(value)
		}
		if _, err := decoder.Token(); err != nil {
			return "", err
		}
		out.WriteByte('}')
		return out.String(), nil
	}
	return string(cell), nil
}

type athenaDataPlane struct {
	execution     context.Context
	glue, s3      http.Handler
	caller        awsctx.Metadata
	parent        string
	requesterPays bool
}

func (a *athenaDataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestContext, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(a.execution, cancel)
	defer stop()
	metadata := awsctx.Clone(a.caller)
	metadata.RequestID, metadata.ParentEventID, metadata.InvokedBy = uuid.NewString(), a.parent, "athena.amazonaws.com"
	ctx := awsctx.WithViaService(awsctx.WithMetadata(requestContext, metadata), "athena.amazonaws.com")
	input := awsapi.Request{Header: r.Header, Host: r.Host, Query: r.URL.Query()}
	var err error
	input.Body, err = io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read native request", http.StatusBadRequest)
		return
	}
	if r.Header.Get("X-Amz-Target") != "" {
		_, operation, valid := awswire.JSONTarget(r.Header.Get("X-Amz-Target"))
		if !valid {
			awswire.JSONError(w, r, &awswire.Error{Code: "InvalidInputException", Message: "Invalid Glue target", StatusCode: 400})
			return
		}
		input.JSON = input.Body
		decoded, err := glueapi.DecodeRequest(operation, input)
		if err != nil {
			awswire.JSONError(w, r, &awswire.Error{Code: "InvalidInputException", Message: err.Error(), StatusCode: 400})
			return
		}
		a.glue.ServeHTTP(w, r.WithContext(awsapi.WithDecodedRequest(ctx, decoded)))
		return
	}
	if a.requesterPays {
		r.Header.Set("X-Amz-Request-Payer", "requester")
	}
	model, _ := awscatalog.LookupService("s3")
	operation, labels, ok := model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), input.Query, r.Header)
	if !ok {
		awswire.RESTXMLError(w, r, &model, &awswire.Error{Code: "NotImplemented", Message: "Unsupported native S3 operation", StatusCode: 501})
		return
	}
	if rejected := gateway.ValidateS3DocumentChecksum(&model, operation, r.Header, input.Body); rejected != nil {
		awswire.RESTXMLError(w, r, &model, rejected)
		return
	}
	input.Labels = labels
	decoded, err := s3api.DecodeRequest(string(operation.Name), input)
	if err != nil {
		awswire.RESTXMLError(w, r, &model, &awswire.Error{Code: "InvalidRequest", Message: err.Error(), StatusCode: 400})
		return
	}
	a.s3.ServeHTTP(w, r.WithContext(awsapi.WithDecodedRequest(ctx, decoded)))
}
