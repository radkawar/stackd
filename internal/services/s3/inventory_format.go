package s3

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"
	"github.com/parquet-go/parquet-go/deprecated"
)

// inventoryColumns follows the AWS Inventory Athena schema order, not the
// configuration's optional-field order. EventHoldDuration selects two columns.
func inventoryColumns(config InventoryConfiguration) []inventoryColumn {
	canonical := [...]inventoryColumn{
		{"Bucket", "bucket", "string"},
		{"Key", "key", "string"},
		{"VersionId", "version_id", "string"},
		{"IsLatest", "is_latest", "boolean"},
		{"IsDeleteMarker", "is_delete_marker", "boolean"},
		{"Size", "size", "bigint"},
		{"LastModifiedDate", "last_modified_date", "timestamp"},
		{"ETag", "e_tag", "string"},
		{"StorageClass", "storage_class", "string"},
		{"IsMultipartUploaded", "is_multipart_uploaded", "boolean"},
		{"ReplicationStatus", "replication_status", "string"},
		{"EncryptionStatus", "encryption_status", "string"},
		{"ObjectLockRetainUntilDate", "object_lock_retain_until_date", "timestamp"},
		{"ObjectLockMode", "object_lock_mode", "string"},
		{"ObjectLockLegalHoldStatus", "object_lock_legal_hold_status", "string"},
		{"ObjectLockEventHoldStatus", "object_lock_event_hold_status", "string"},
		{"ObjectLockEventHoldDuration", "object_lock_event_hold_duration", "int"},
		{"ObjectLockEventHoldDurationUnit", "object_lock_event_hold_duration_unit", "string"},
		{"IntelligentTieringAccessTier", "intelligent_tiering_access_tier", "string"},
		{"BucketKeyStatus", "bucket_key_status", "string"},
		{"ChecksumAlgorithm", "checksum_algorithm", "string"},
		{"ObjectAccessControlList", "object_access_control_list", "string"},
		{"ObjectOwner", "object_owner", "string"},
		{"LifecycleExpirationDate", "lifecycle_expiration_date", "timestamp"},
	}
	columns := make([]inventoryColumn, 0, len(canonical))
	for i, column := range canonical {
		selected := i < 2 || (i < 5 && config.AllVersions)
		if i >= 5 {
			selection := column.Name
			if selection == "ObjectLockEventHoldDurationUnit" {
				selection = "ObjectLockEventHoldDuration"
			}
			selected = slices.Contains(config.OptionalFields, selection)
		}
		if selected {
			columns = append(columns, column)
		}
	}
	return columns
}

func encodeInventory(ctx context.Context, format string, columns []inventoryColumn, rows [][]any, orc InventoryORCEncoder) (data []byte, schema string, extension string, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	switch format {
	case "CSV":
		data, schema, err = encodeInventoryCSV(ctx, columns, rows)
		extension = "csv.gz"
	case "ORC":
		data, schema, err = encodeInventoryORC(ctx, columns, rows, orc)
		extension = "orc"
	case "Parquet":
		data, schema, err = encodeInventoryParquet(ctx, columns, rows)
		extension = "parquet"
	default:
		err = fmt.Errorf("unsupported inventory format %q", format)
	}
	return
}

func encodeInventoryCSV(ctx context.Context, columns []inventoryColumn, rows [][]any) ([]byte, string, error) {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	writer := csv.NewWriter(compressed)
	record := make([]string, len(columns))
	for i, column := range columns {
		record[i] = column.Name
	}
	schema := strings.Join(record, ", ")
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		for i, cell := range row {
			switch value := cell.(type) {
			case nil:
				record[i] = ""
			case string:
				record[i] = value
				if columns[i].Field == "key" {
					record[i] = strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
				}
			case bool:
				record[i] = strconv.FormatBool(value)
			case int64:
				record[i] = strconv.FormatInt(value, 10)
			case time.Time:
				record[i] = value.UTC().Format("2006-01-02T15:04:05.000Z")
			default:
				return nil, "", fmt.Errorf("inventory column %s has unsupported value type %T", columns[i].Name, cell)
			}
		}
		if err := writer.Write(record); err != nil {
			return nil, "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, "", err
	}
	if err := compressed.Close(); err != nil {
		return nil, "", err
	}
	return output.Bytes(), schema, nil
}

func encodeInventoryORC(ctx context.Context, columns []inventoryColumn, rows [][]any, orc InventoryORCEncoder) ([]byte, string, error) {
	if orc == nil {
		return nil, "", errors.New("ORC inventory requires the installed Apache ORC encoding engine")
	}
	var schema strings.Builder
	schema.WriteString("struct<")
	for i, column := range columns {
		if i != 0 {
			schema.WriteByte(',')
		}
		schema.WriteString(column.Field)
		schema.WriteByte(':')
		schema.WriteString(column.Kind)
	}
	schema.WriteByte('>')
	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	encoder.SetEscapeHTML(false)
	record := make(map[string]any, len(columns))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		for i, value := range row {
			if at, ok := value.(time.Time); ok {
				value = at.UTC().Format("2006-01-02T15:04:05.000Z")
			}
			record[columns[i].Field] = value
		}
		if err := encoder.Encode(record); err != nil {
			return nil, "", fmt.Errorf("encoding inventory ORC input: %w", err)
		}
	}
	text := schema.String()
	data, err := orc.Encode(ctx, text, input.Bytes())
	if err != nil {
		return nil, "", fmt.Errorf("encoding inventory ORC: %w", err)
	}
	return data, text, nil
}

// Group.Fields sorts map keys. Override only its traversal order so both the
// Parquet footer and WriteRows column indexes retain the AWS schema order.
// WriteRows avoids reflection and dynamically generated Go struct types.
type inventoryParquetGroup struct {
	parquet.Group
	fields []parquet.Field
}

func (g inventoryParquetGroup) Fields() []parquet.Field { return g.fields }

func inventoryParquetSchema(columns []inventoryColumn) (*parquet.Schema, string, error) {
	group := inventoryParquetGroup{
		Group:  make(parquet.Group, len(columns)),
		fields: make([]parquet.Field, len(columns)),
	}
	positions := make(map[string]int, len(columns))
	for i, column := range columns {
		var node parquet.Node
		switch column.Kind {
		case "string":
			node = parquet.String()
		case "boolean":
			node = parquet.Leaf(parquet.BooleanType)
		case "bigint":
			node = parquet.Leaf(parquet.Int64Type)
		case "int":
			node = parquet.Leaf(parquet.Int32Type)
		case "timestamp":
			// Timestamp writes both modern UTC logical type and the legacy
			// TIMESTAMP_MILLIS converted type required by Inventory readers.
			node = parquet.Timestamp(parquet.Millisecond)
		default:
			return nil, "", fmt.Errorf("unsupported inventory column kind %q", column.Kind)
		}
		if column.Field != "bucket" && column.Field != "key" {
			node = parquet.Optional(node)
		}
		group.Group[column.Field] = node
		positions[column.Field] = i
	}
	for _, field := range group.Group.Fields() {
		group.fields[positions[field.Name()]] = field
	}
	schema := parquet.NewSchema("s3.inventory", group)
	// Render the AWS legacy-annotation spelling from the actual writer schema,
	// rather than maintaining a second independently specified manifest schema.
	var manifest strings.Builder
	manifest.WriteString("message ")
	manifest.WriteString(schema.Name())
	manifest.WriteString(" { ")
	for _, field := range schema.Fields() {
		if field.Required() {
			manifest.WriteString("required ")
		} else {
			manifest.WriteString("optional ")
		}
		typ := field.Type()
		if typ.Kind() == parquet.ByteArray {
			manifest.WriteString("binary")
		} else {
			manifest.WriteString(strings.ToLower(typ.Kind().String()))
		}
		manifest.WriteByte(' ')
		manifest.WriteString(field.Name())
		if converted := typ.ConvertedType(); converted != nil {
			switch *converted {
			case deprecated.UTF8:
				manifest.WriteString(" (UTF8)")
			case deprecated.TimestampMillis:
				manifest.WriteString(" (TIMESTAMP_MILLIS)")
			default:
				return nil, "", fmt.Errorf("unsupported inventory Parquet annotation %d", *converted)
			}
		}
		manifest.WriteString("; ")
	}
	manifest.WriteByte('}')
	return schema, manifest.String(), nil
}

func encodeInventoryParquet(ctx context.Context, columns []inventoryColumn, rows [][]any) ([]byte, string, error) {
	schema, manifest, err := inventoryParquetSchema(columns)
	if err != nil {
		return nil, "", err
	}
	var output bytes.Buffer
	writer := parquet.NewWriter(&output, schema, parquet.Compression(&snappy.Codec{}))
	// Close also releases any library-owned page buffers on a conversion error.
	defer func() {
		if writer != nil {
			_ = writer.Close()
		}
	}()
	const batchSize = 128
	fields := schema.Fields()
	batch := make([]parquet.Row, min(batchSize, len(rows)))
	values := make([]parquet.Value, len(batch)*len(columns))
	for i := range batch {
		batch[i] = values[i*len(columns) : (i+1)*len(columns)]
	}
	for start := 0; start < len(rows); start += len(batch) {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		count := min(len(batch), len(rows)-start)
		for i, row := range rows[start : start+count] {
			for j, cell := range row {
				value := parquet.NullValue()
				definition := 0
				if cell != nil {
					switch columns[j].Kind {
					case "string", "boolean", "bigint":
						value = parquet.ValueOf(cell)
					case "int":
						number := cell.(int64)
						if number < math.MinInt32 || number > math.MaxInt32 {
							return nil, "", fmt.Errorf("inventory column %s exceeds int32 range: %d", columns[j].Name, number)
						}
						value = parquet.Int32Value(int32(number))
					case "timestamp":
						value = parquet.Int64Value(cell.(time.Time).UnixMilli())
					}
					if fields[j].Optional() {
						definition = 1
					}
				} else if fields[j].Required() {
					return nil, "", fmt.Errorf("inventory column %s cannot be null", columns[j].Name)
				}
				batch[i][j] = value.Level(0, definition, j)
			}
		}
		if _, err := writer.WriteRows(batch[:count]); err != nil {
			return nil, "", fmt.Errorf("writing inventory Parquet: %w", err)
		}
	}
	err = writer.Close()
	writer = nil
	if err != nil {
		return nil, "", fmt.Errorf("closing inventory Parquet: %w", err)
	}
	return output.Bytes(), manifest, nil
}
