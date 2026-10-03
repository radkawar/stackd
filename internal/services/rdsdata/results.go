package rdsdata

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	api "stackd/internal/awsapi/rdsdata"
)

func readResults(rows *sql.Rows, in *api.ExecuteStatementRequest, mutation bool) (*api.ExecuteStatementResponse, error) {
	columns, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	formatted := value(in.FormatRecordsAs) == "JSON"
	out := &api.ExecuteStatementResponse{NumberOfRecordsUpdated: new(api.RecordsUpdated(0))}
	if formatted {
		names := make(map[string]bool, len(columns))
		for _, c := range columns {
			if names[c.Name()] {
				return nil, failure("BadRequestException", "JSON result column labels must be unique.")
			}
			names[c.Name()] = true
		}
	} else if enabled(in.IncludeResultMetadata) {
		out.ColumnMetadata = make(api.Metadata, len(columns))
		for i, c := range columns {
			out.ColumnMetadata[i] = columnMetadata(c)
		}
	}
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for i := range values {
		destinations[i] = &values[i]
	}
	var jsonRows bytes.Buffer
	if formatted {
		jsonRows.WriteByte('[')
	} else {
		out.Records = api.SqlRecords{}
	}
	total := 0
	count := 0
	for rows.Next() {
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		var fields api.FieldList
		var jsonRow map[string]any
		if formatted {
			jsonRow = make(map[string]any, len(columns))
		} else {
			fields = make(api.FieldList, len(columns))
		}
		for i, v := range values {
			field, err := resultField(v, columns[i].DatabaseTypeName(), in.ResultSetOptions)
			if err != nil {
				return nil, err
			}
			if formatted {
				jsonRow[columns[i].Name()] = fieldJSON(field)
			} else {
				fields[i] = field
			}
		}
		var encoded []byte
		if formatted {
			encoded, err = json.Marshal(jsonRow)
		} else {
			encoded, err = json.Marshal(fields)
		}
		if err != nil {
			return nil, failure("UnsupportedResultException", "The result cannot be represented by the Data API.")
		}
		total += len(encoded) + 1
		limit := 1 << 20
		if formatted {
			limit = 10 * 1024 * 1024
		}
		if total+2 > limit {
			return nil, failure("UnsupportedResultException", "The result exceeds the Data API response size limit.")
		}
		if formatted {
			if count > 0 {
				jsonRows.WriteByte(',')
			}
			jsonRows.Write(encoded)
		} else {
			out.Records = append(out.Records, fields)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if rows.NextResultSet() {
		return nil, failure("UnsupportedResultException", "Multiple result sets are not supported.")
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if formatted {
		jsonRows.WriteByte(']')
		out.FormattedRecords = new(api.FormattedSqlRecords(jsonRows.String()))
	}
	if mutation {
		out.NumberOfRecordsUpdated = new(api.RecordsUpdated(count))
	}
	return out, nil
}
func columnMetadata(c *sql.ColumnType) api.ColumnMetadata {
	name := c.Name()
	typ := strings.ToUpper(c.DatabaseTypeName())
	code := jdbcType(typ)
	m := api.ColumnMetadata{Name: new(api.String(name)), Label: new(api.String(name)), TypeName: new(api.String(strings.ToLower(typ))), Type: new(api.Integer(code)), Nullable: new(api.Integer(2))}
	if nullable, ok := c.Nullable(); ok {
		n := api.Integer(0)
		if nullable {
			n = 1
		}
		m.Nullable = &n
	}
	if precision, scale, ok := c.DecimalSize(); ok {
		m.Precision = new(api.Integer(precision))
		m.Scale = new(api.Integer(scale))
	}
	if length, ok := c.Length(); ok && length <= math.MaxInt32 && m.Precision == nil {
		m.Precision = new(api.Integer(length))
	}
	if code == 2 || code == 3 || code == 4 || code == 5 || code == 6 || code == 7 || code == 8 || code == -5 {
		m.IsSigned = new(api.Boolean(!strings.HasPrefix(typ, "UNSIGNED")))
	}
	if code == 12 || code == 1 || code == -1 {
		m.IsCaseSensitive = new(api.Boolean(true))
	}
	if strings.HasPrefix(typ, "_") {
		m.ArrayBaseColumnType = new(api.Integer(jdbcType(strings.TrimPrefix(typ, "_"))))
	}
	return m
}
func jdbcType(typ string) int32 {
	typ = strings.TrimPrefix(typ, "UNSIGNED ")
	if strings.HasPrefix(typ, "_") {
		return 2003
	}
	switch typ {
	case "BOOL", "BOOLEAN", "BIT":
		return -7
	case "INT2", "SMALLINT":
		return 5
	case "INT4", "INT", "INTEGER", "MEDIUMINT":
		return 4
	case "INT8", "BIGINT":
		return -5
	case "TINYINT":
		return -6
	case "NUMERIC":
		return 2
	case "DECIMAL":
		return 3
	case "FLOAT4", "FLOAT", "REAL":
		return 7
	case "FLOAT8", "DOUBLE":
		return 8
	case "BYTEA", "BLOB", "TINYBLOB", "MEDIUMBLOB", "LONGBLOB", "BINARY", "VARBINARY":
		return -3
	case "DATE":
		return 91
	case "TIME", "TIMETZ":
		return 92
	case "TIMESTAMP", "TIMESTAMPTZ", "DATETIME":
		return 93
	case "CHAR", "BPCHAR":
		return 1
	case "TEXT", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT":
		return -1
	case "VARCHAR", "NAME":
		return 12
	default:
		return 1111
	}
}
func resultField(v any, typ string, options *api.ResultSetOptions) (api.Field, error) {
	if v == nil {
		return api.Field{IsNull: new(api.BoxedBoolean(true))}, nil
	}
	typ = strings.ToUpper(typ)
	if strings.HasPrefix(typ, "_") {
		return arrayField(v, typ, options)
	}
	decimal := typ == "NUMERIC" || typ == "DECIMAL"
	text := func(v string) (api.Field, error) {
		if decimal {
			if options == nil || value(options.DecimalReturnType) != "DOUBLE_OR_LONG" {
				return api.Field{StringValue: new(api.String(v))}, nil
			}
			if !strings.ContainsAny(v, ".eE") {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					return api.Field{LongValue: new(api.BoxedLong(n))}, nil
				}
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
				return api.Field{}, failure("UnsupportedResultException", "Decimal cannot be represented as a finite number.")
			}
			return api.Field{DoubleValue: new(api.BoxedDouble(n))}, nil
		}
		return api.Field{StringValue: new(api.String(v))}, nil
	}
	switch n := v.(type) {
	case string:
		return text(n)
	case []byte:
		switch jdbcType(typ) {
		case -3:
			b := make(api.Blob, len(n))
			copy(b, n)
			return api.Field{BlobValue: b}, nil
		case -7:
			if typ == "BIT" && len(n) == 1 {
				return api.Field{BooleanValue: new(api.BoxedBoolean(n[0] != 0))}, nil
			}
		}
		return text(string(n))
	case int64:
		if options != nil && value(options.LongReturnType) == "STRING" {
			return api.Field{StringValue: new(api.String(strconv.FormatInt(n, 10)))}, nil
		}
		return api.Field{LongValue: new(api.BoxedLong(n))}, nil
	case int32:
		return resultField(int64(n), typ, options)
	case int16:
		return resultField(int64(n), typ, options)
	case uint64:
		if n > math.MaxInt64 || options != nil && value(options.LongReturnType) == "STRING" {
			return api.Field{StringValue: new(api.String(strconv.FormatUint(n, 10)))}, nil
		}
		return resultField(int64(n), typ, options)
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return api.Field{}, failure("UnsupportedResultException", "Non-finite floating point results are not supported.")
		}
		return api.Field{DoubleValue: new(api.BoxedDouble(n))}, nil
	case float32:
		return resultField(float64(n), typ, options)
	case bool:
		return api.Field{BooleanValue: new(api.BoxedBoolean(n))}, nil
	case time.Time:
		layout := "2006-01-02 15:04:05.999999"
		switch typ {
		case "DATE":
			layout = "2006-01-02"
		case "TIME", "TIMETZ":
			layout = "15:04:05.999999"
		}
		return text(n.UTC().Format(layout))
	default:
		return api.Field{}, failure("UnsupportedResultException", fmt.Sprintf("Unsupported native result type %T.", v))
	}
}
func fieldJSON(f api.Field) any {
	switch {
	case f.IsNull != nil:
		return nil
	case f.StringValue != nil:
		return string(*f.StringValue)
	case f.LongValue != nil:
		return int64(*f.LongValue)
	case f.DoubleValue != nil:
		return float64(*f.DoubleValue)
	case f.BooleanValue != nil:
		return bool(*f.BooleanValue)
	case f.BlobValue != nil:
		return []byte(f.BlobValue)
	case f.ArrayValue != nil:
		a := f.ArrayValue
		switch {
		case a.LongValues != nil:
			return a.LongValues
		case a.DoubleValues != nil:
			return a.DoubleValues
		case a.BooleanValues != nil:
			return a.BooleanValues
		case a.StringValues != nil:
			return a.StringValues
		}
	}
	return nil
}
func arrayField(v any, typ string, options *api.ResultSetOptions) (api.Field, error) {
	var raw []byte
	switch n := v.(type) {
	case string:
		raw = []byte(n)
	case []byte:
		raw = n
	default:
		return api.Field{}, failure("UnsupportedResultException", "Unsupported array encoding.")
	}
	types := pgtype.NewMap()
	descriptor, ok := types.TypeForName(strings.ToLower(typ))
	if !ok {
		return api.Field{}, failure("UnsupportedResultException", "Unsupported array type.")
	}
	var array pgtype.Array[any]
	if err := types.Scan(descriptor.OID, pgtype.TextFormatCode, raw, &array); err != nil {
		return api.Field{}, failure("UnsupportedResultException", "Unsupported array encoding.")
	}
	if len(array.Dims) > 1 {
		return api.Field{}, failure("UnsupportedResultException", "Multidimensional arrays are not supported.")
	}
	base := strings.TrimPrefix(typ, "_")
	code := jdbcType(base)
	out := &api.ArrayValue{}
	switch code {
	case -7:
		out.BooleanValues = make(api.BooleanArray, 0, len(array.Elements))
	case -5, 4, 5, -6:
		if options != nil && value(options.LongReturnType) == "STRING" {
			out.StringValues = make(api.StringArray, 0, len(array.Elements))
		} else {
			out.LongValues = make(api.LongArray, 0, len(array.Elements))
		}
	case 7, 8:
		out.DoubleValues = make(api.DoubleArray, 0, len(array.Elements))
	case 2, 3:
		if options != nil && value(options.DecimalReturnType) == "DOUBLE_OR_LONG" {
			out.DoubleValues = make(api.DoubleArray, 0, len(array.Elements))
		} else {
			out.StringValues = make(api.StringArray, 0, len(array.Elements))
		}
	case 1, 12, -1, 1111, 91, 92, 93:
		out.StringValues = make(api.StringArray, 0, len(array.Elements))
	default:
		return api.Field{}, failure("UnsupportedResultException", "Unsupported array element type.")
	}
	for _, element := range array.Elements {
		// pgx array numeric decoding yields pgtype.Numeric; its Value preserves text.
		if n, ok := element.(pgtype.Numeric); ok {
			var err error
			element, err = n.Value()
			if err != nil {
				return api.Field{}, err
			}
		}
		field, err := resultField(element, base, options)
		if err != nil {
			return api.Field{}, err
		}
		switch {
		case out.BooleanValues != nil:
			out.BooleanValues = append(out.BooleanValues, field.BooleanValue)
		case out.LongValues != nil:
			out.LongValues = append(out.LongValues, field.LongValue)
		case out.DoubleValues != nil:
			if field.LongValue != nil {
				field.DoubleValue = new(api.BoxedDouble(*field.LongValue))
			}
			out.DoubleValues = append(out.DoubleValues, field.DoubleValue)
		case out.StringValues != nil:
			out.StringValues = append(out.StringValues, field.StringValue)
		}
	}
	return api.Field{ArrayValue: out}, nil
}
