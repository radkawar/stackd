package integrations

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/parquet-go/parquet-go"
	parquetgzip "github.com/parquet-go/parquet-go/compress/gzip"
	"stackd/internal/services/ec2"
)

// parquet.Group sorts its fields by name. Preserve the subscription's selected
// column order instead; rows below use the same retained header order.
type flowLogParquetGroup struct {
	parquet.Group
	fields []parquet.Field
}

func (g flowLogParquetGroup) Fields() []parquet.Field { return g.fields }

// These are the fields supported by flow-log capture, not an enrichment layer.
// Physical types follow the VPC Flow Logs field reference (including INT32 for
// protocol, despite the wider bigint in Athena's example DDL).
// https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
func flowLogParquetType(field string) (parquet.Node, bool) {
	switch field {
	case "version", "srcport", "dstport", "protocol", "tcp-flags":
		return parquet.Optional(parquet.Leaf(parquet.Int32Type)), true
	case "packets", "bytes", "start", "end":
		return parquet.Optional(parquet.Leaf(parquet.Int64Type)), true
	case "account-id", "interface-id", "srcaddr", "dstaddr", "action", "log-status",
		"vpc-id", "subnet-id", "instance-id", "type", "pkt-srcaddr", "pkt-dstaddr",
		"region", "az-id", "flow-direction":
		return parquet.String(), true
	default:
		return nil, false
	}
}

func encodeFlowLogParquet(header string, lines []ec2.FlowLogLine) ([]byte, error) {
	names := strings.Fields(header)
	if len(names) == 0 {
		return nil, fmt.Errorf("the Parquet flow log has no selected columns")
	}
	group := make(parquet.Group, len(names))
	kinds := make([]parquet.Kind, len(names))
	positions := make(map[string]int, len(names))
	for i, name := range names {
		node, ok := flowLogParquetType(name)
		if !ok {
			return nil, fmt.Errorf("unsupported Parquet flow log column %q", name)
		}
		// Athena's published Parquet schema uses underscores, not the hyphens
		// present in the plain-text header and subscription field tokens.
		column := strings.ReplaceAll(name, "-", "_")
		if _, exists := group[column]; exists {
			return nil, fmt.Errorf("duplicate Parquet flow log column %q", name)
		}
		group[column], kinds[i], positions[column] = node, node.Type().Kind(), i
	}
	fields := make([]parquet.Field, len(names))
	for _, field := range group.Fields() {
		fields[positions[field.Name()]] = field
	}
	schema := parquet.NewSchema("vpc_flow_logs", flowLogParquetGroup{Group: group, fields: fields})
	var body bytes.Buffer
	writer := parquet.NewWriter(&body, schema, parquet.Compression(&parquetgzip.Codec{Level: parquetgzip.DefaultCompression}))
	// Closing also releases the writer's compression/buffer resources on error.
	closed := false
	defer func() {
		if !closed {
			_ = writer.Close()
		}
	}()
	rows := []parquet.Row{make(parquet.Row, len(names))}
	for rowIndex, line := range lines {
		rest := line.Message
		for column, kind := range kinds {
			cell, remaining, more := strings.Cut(rest, " ")
			if cell == "" || more != (column < len(kinds)-1) {
				return nil, fmt.Errorf("parquet flow log row %d does not match its retained header", rowIndex+1)
			}
			rest = remaining
			var value parquet.Value
			if kind == parquet.ByteArray {
				if !utf8.ValidString(cell) || strings.ContainsAny(cell, "\t\r\n") {
					return nil, fmt.Errorf("parquet flow log row %d column %q has a malformed string", rowIndex+1, names[column])
				}
				// Preserve the documented unavailable STRING sentinel literally.
				// Numeric '-' cannot be represented as an integer: use an
				// optional null, never an invented zero or wrapped counter.
				value = parquet.ValueOf(cell).Level(0, 0, column)
			} else if cell == "-" {
				value = parquet.NullValue().Level(0, 0, column)
			} else {
				bits := 64
				if kind == parquet.Int32 {
					bits = 32
				}
				number, err := strconv.ParseInt(cell, 10, bits)
				if err != nil {
					return nil, fmt.Errorf("parquet flow log row %d column %q is not an INT%d: %w", rowIndex+1, names[column], bits, err)
				}
				if kind == parquet.Int32 {
					value = parquet.Int32Value(int32(number))
				} else {
					value = parquet.Int64Value(number)
				}
				value = value.Level(0, 1, column)
			}
			rows[0][column] = value
		}
		if _, err := writer.WriteRows(rows); err != nil {
			return nil, fmt.Errorf("encoding Parquet flow log row %d: %w", rowIndex+1, err)
		}
	}
	// A successful close writes the real Parquet footer; never send partial
	// bytes to S3. GZIP is a column codec, not an outer HTTP content encoding.
	closed = true
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing Parquet flow log: %w", err)
	}
	return body.Bytes(), nil
}
