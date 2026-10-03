package integrations

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/parquet-go/parquet-go"

	"stackd/internal/services/stepfunctions"
)

// ParseMapReaderData exposes the same data parser to TestState's supplied mock
// input without performing resource access or manufacturing manifest objects.
func (t *StepFunctionsTasks) ParseMapReaderData(ctx context.Context, request stepfunctions.MapReaderRequest, raw []byte) (stepfunctions.MapReaderOutput, error) {
	bucket, _ := request.Parameters["Bucket"].(string)
	key, _ := request.Parameters["Key"].(string)
	output := stepfunctions.MapReaderOutput{Source: mapObjectSource(bucket, key)}
	body, err := mapDecompress(raw, key)
	if err != nil {
		return output, err
	}
	output.Items, output.Keys, err = parseMapData(ctx, body, request.ReaderConfig, request.ReaderConfig.MaxItems)
	return output, err
}

const mapReaderFileLimit int64 = 10 * 1024 * 1024 * 1024

func mapDecompress(body []byte, key string) ([]byte, error) {
	var reader io.Reader
	var closer func()
	switch {
	case strings.HasSuffix(key, ".gz") || strings.HasSuffix(key, ".gzip"):
		stream, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		reader, closer = stream, func() { _ = stream.Close() }
	case strings.HasSuffix(key, ".zstd") || strings.HasSuffix(key, ".zst"):
		stream, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		reader, closer = stream, stream.Close
	default:
		if int64(len(body)) > mapReaderFileLimit {
			return nil, fmt.Errorf("ItemReader file exceeds 10 GiB")
		}
		return body, nil
	}
	defer closer()
	decoded, err := io.ReadAll(io.LimitReader(reader, mapReaderFileLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(decoded)) > mapReaderFileLimit {
		return nil, fmt.Errorf("ItemReader decompressed file exceeds 10 GiB")
	}
	return decoded, nil
}

func parseMapData(ctx context.Context, body []byte, config stepfunctions.MapReaderConfig, limit int64) ([]any, []string, error) {
	switch config.InputType {
	case "JSON":
		return parseMapJSON(ctx, body, config.ItemsPointer, limit)
	case "JSONL":
		items := make([]any, 0)
		for len(body) > 0 && (limit == 0 || int64(len(items)) < limit) {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			line, rest, _ := bytes.Cut(body, []byte{'\n'})
			body = rest
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			value, err := decodeMapJSON(line)
			if err != nil {
				return nil, nil, err
			}
			items = append(items, value)
		}
		return items, nil, nil
	case "CSV":
		delimiter := byte(',')
		switch config.CSVDelimiter {
		case "", "COMMA":
		case "PIPE":
			delimiter = '|'
		case "SEMICOLON":
			delimiter = ';'
		case "SPACE":
			delimiter = ' '
		case "TAB":
			delimiter = '\t'
		default:
			return nil, nil, fmt.Errorf("invalid CSV delimiter %q", config.CSVDelimiter)
		}
		reader := newMapCSVReader(body, delimiter)
		headers := config.CSVHeaders
		switch config.CSVHeaderLocation {
		case "FIRST_ROW":
			var err error
			headers, err = reader.read()
			if err == io.EOF {
				return []any{}, nil, nil
			}
			if err != nil {
				return nil, nil, err
			}
		case "GIVEN":
		default:
			return nil, nil, fmt.Errorf("CSV input requires CSVHeaderLocation")
		}
		headerBytes := 0
		for _, header := range headers {
			headerBytes += len(header)
		}
		if len(headers) == 0 || headerBytes > 10*1024 {
			return nil, nil, fmt.Errorf("CSV headers must be nonempty and at most 10 KiB")
		}
		items := make([]any, 0)
		for limit == 0 || int64(len(items)) < limit {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			row, err := reader.read()
			if err != nil {
				return items, nil, mapCSVEnd(err)
			}
			item := make(map[string]any, len(headers))
			for index, header := range headers {
				value := ""
				if index < len(row) {
					value = row[index]
				}
				item[header] = value
			}
			items = append(items, item)
		}
		return items, nil, nil
	case "PARQUET":
		return parseMapParquet(ctx, body, limit)
	default:
		return nil, nil, fmt.Errorf("unsupported ItemReader InputType %q", config.InputType)
	}
}

func decodeMapJSON(body []byte) (any, error) {
	if len(body) > 8*1024*1024 {
		return nil, fmt.Errorf("ItemReader item exceeds 8 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values in one item")
		}
		return nil, err
	}
	return value, nil
}

func parseMapJSON(ctx context.Context, body []byte, pointer string, limit int64) ([]any, []string, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if pointer != "" {
		if !strings.HasPrefix(pointer, "/") {
			return nil, nil, fmt.Errorf("invalid ItemsPointer")
		}
		parts := strings.Split(pointer[1:], "/")
		for index := range parts {
			parts[index] = strings.ReplaceAll(strings.ReplaceAll(parts[index], "~1", "/"), "~0", "~")
		}
		if err := seekMapJSON(ctx, decoder, parts); err != nil {
			return nil, nil, err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, nil, err
	}
	if pointer != "" && decoder.InputOffset()-1 >= 16*1024*1024 {
		return nil, nil, fmt.Errorf("ItemsPointer target starts beyond the first 16 MiB")
	}
	if token != json.Delim('[') && token != json.Delim('{') {
		return nil, nil, fmt.Errorf("JSON ItemReader requires an array or object")
	}
	items := make([]any, 0)
	var keys []string
	if token == json.Delim('{') {
		keys = make([]string, 0)
	}
	for decoder.More() && (keys != nil || limit == 0 || int64(len(items)) < limit) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if keys != nil {
			key, err := decoder.Token()
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, key.(string))
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, nil, err
		}
		value, err := decodeMapJSON(raw)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, value)
	}
	if keys != nil || limit == 0 || int64(len(items)) < limit {
		if _, err := decoder.Token(); err != nil {
			return nil, nil, err
		}
		if pointer == "" {
			if err := decoder.Decode(new(any)); err != io.EOF {
				if err == nil {
					err = fmt.Errorf("multiple JSON documents in ItemReader input")
				}
				return nil, nil, err
			}
		}
	}
	// As with in-state JSON object iteration, keys have deterministic lexical
	// ordering; array, CSV, JSONL and S3 listing orders remain unchanged.
	if keys != nil {
		values := make(map[string]any, len(keys))
		for index, key := range keys {
			values[key] = items[index]
		}
		keys = keys[:0]
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if limit > 0 && int64(len(keys)) > limit {
			keys = keys[:limit]
		}
		items = items[:len(keys)]
		for index, key := range keys {
			items[index] = values[key]
		}
	}
	return items, keys, nil
}

func seekMapJSON(ctx context.Context, decoder *json.Decoder, parts []string) error {
	if len(parts) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			if key == parts[0] {
				return seekMapJSON(ctx, decoder, parts[1:])
			}
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return err
			}
		}
	case json.Delim('['):
		index, err := strconv.Atoi(parts[0])
		if err != nil || index < 0 || strconv.Itoa(index) != parts[0] {
			return fmt.Errorf("invalid ItemsPointer array index %q", parts[0])
		}
		for current := 0; decoder.More(); current++ {
			if current == index {
				return seekMapJSON(ctx, decoder, parts[1:])
			}
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("ItemsPointer target does not exist")
}

func parseMapParquet(ctx context.Context, body []byte, limit int64) ([]any, []string, error) {
	if len(body) < 12 {
		return nil, nil, fmt.Errorf("invalid Parquet file")
	}
	if binary.LittleEndian.Uint32(body[len(body)-8:]) > 5*1024*1024 {
		return nil, nil, fmt.Errorf("parquet footer exceeds 5 MiB")
	}
	file, err := parquet.OpenFile(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, nil, err
	}
	for _, group := range file.Metadata().RowGroups {
		if group.TotalByteSize > 256*1024*1024 {
			return nil, nil, fmt.Errorf("parquet row group exceeds 256 MiB")
		}
	}
	items := make([]any, 0)
	for _, group := range file.RowGroups() {
		reader := parquet.NewGenericRowGroupReader[any](group)
		rows := make([]any, 128)
		for limit == 0 || int64(len(items)) < limit {
			if err := ctx.Err(); err != nil {
				_ = reader.Close()
				return nil, nil, err
			}
			count := len(rows)
			if limit > 0 && int64(count) > limit-int64(len(items)) {
				count = int(limit - int64(len(items)))
			}
			n, err := reader.Read(rows[:count])
			items = append(items, rows[:n]...)
			clear(rows)
			if err != nil {
				if err != io.EOF {
					_ = reader.Close()
					return nil, nil, err
				}
				break
			}
		}
		if err := reader.Close(); err != nil {
			return nil, nil, err
		}
		if limit > 0 && int64(len(items)) >= limit {
			break
		}
	}
	return items, nil, nil
}

// Step Functions CSV permits quote pairs in unquoted fields and backslash
// escapes, unlike encoding/csv. Keep the parser local to this input contract.
type mapCSVReader struct {
	body      []byte
	delimiter byte
}

func newMapCSVReader(body []byte, delimiter byte) *mapCSVReader {
	return &mapCSVReader{body: bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}), delimiter: delimiter}
}

func mapCSVEnd(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

func (r *mapCSVReader) read() ([]string, error) {
	if len(r.body) == 0 {
		return nil, io.EOF
	}
	var fields []string
	var field strings.Builder
	quoted, beginning := false, true
	consumed := 0
	for len(r.body) > 0 {
		char := r.body[0]
		r.body = r.body[1:]
		consumed++
		if consumed > 8*1024*1024 {
			return nil, fmt.Errorf("CSV item exceeds 8 MiB")
		}
		switch {
		case char == '\\':
			if len(r.body) > 0 {
				next := r.body[0]
				if next == '\\' || next == '"' || next == r.delimiter {
					field.WriteByte(next)
					r.body = r.body[1:]
				}
			}
		case char == '"':
			if beginning {
				quoted = true
			} else if len(r.body) > 0 && r.body[0] == '"' {
				field.WriteByte('"')
				r.body = r.body[1:]
			} else if quoted {
				quoted = false
			} else {
				field.WriteByte(char)
			}
		case !quoted && char == r.delimiter:
			fields = append(fields, field.String())
			field.Reset()
			beginning = true
			continue
		case !quoted && (char == '\n' || char == '\r'):
			if char == '\r' && len(r.body) > 0 && r.body[0] == '\n' {
				r.body = r.body[1:]
			}
			return append(fields, field.String()), nil
		default:
			field.WriteByte(char)
		}
		beginning = false
	}
	if quoted {
		return nil, fmt.Errorf("unterminated quoted CSV field")
	}
	return append(fields, field.String()), nil
}
