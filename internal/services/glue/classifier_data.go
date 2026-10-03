package glue

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/ohler55/ojg/jp"
	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/format"
	api "stackd/internal/awsapi/glue"
)

type crawlerSchema struct {
	Columns         api.ColumnList
	Classification  string
	InputFormat     string
	OutputFormat    string
	Serde           string
	Parameters      api.ParametersMap
	SerdeParameters api.ParametersMap
}

func textCrawlerSchema(columns api.ColumnList, kind, serde string) crawlerSchema {
	return crawlerSchema{Columns: columns, Classification: kind, InputFormat: "org.apache.hadoop.mapred.TextInputFormat", OutputFormat: "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat", Serde: serde, Parameters: api.ParametersMap{}, SerdeParameters: api.ParametersMap{}}
}
func classifyCrawlerObject(data []byte, classifiers []ClassifierRecord) (crawlerSchema, error) {
	compressed := false
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return crawlerSchema{}, failure("InvalidInputException", "Invalid gzip object.")
		}
		data, err = io.ReadAll(io.LimitReader(reader, 64<<20+1))
		reader.Close()
		if err != nil || len(data) > 64<<20 {
			return crawlerSchema{}, failure("InvalidInputException", "Compressed object exceeds the supported sample bound or is invalid.")
		}
		compressed = true
	}
	var schema crawlerSchema
	matched := false
	for _, record := range classifiers {
		var err error
		switch c := record.Classifier; {
		case c.JsonClassifier != nil:
			schema, matched, err = classifyJSON(data, value(c.JsonClassifier.JsonPath))
		case c.CsvClassifier != nil:
			schema, matched, err = classifyCSV(data, c.CsvClassifier)
		case c.XMLClassifier != nil:
			schema, matched, err = classifyXML(data, c.XMLClassifier)
		case c.GrokClassifier != nil:
			schema, matched, err = classifyGrok(data, c.GrokClassifier)
		}
		if err != nil {
			return crawlerSchema{}, err
		}
		if matched {
			break
		}
	}
	if !matched && len(data) >= 4 && string(data[:4]) == "PAR1" {
		var err error
		schema, err = classifyParquet(data)
		if err != nil {
			return crawlerSchema{}, err
		}
		matched = true
	}
	if !matched {
		var err error
		schema, matched, err = classifyJSON(data, "$")
		if err != nil {
			return crawlerSchema{}, err
		}
	}
	if !matched {
		for _, delimiter := range []string{",", "\t", "|", ";"} {
			var err error
			schema, matched, err = classifyCSV(data, &api.CsvClassifier{Delimiter: new(api.CsvColumnDelimiter(delimiter))})
			if err != nil {
				return crawlerSchema{}, err
			}
			if matched {
				break
			}
		}
	}
	if !matched {
		return crawlerSchema{}, unsupported("No supported classifier matched the object; built-ins support JSON, CSV and Parquet.")
	}
	if compressed {
		schema.Parameters["compressionType"] = "gzip"
	}
	return schema, nil
}

type crawlerType struct {
	kind    string
	fields  map[string]*crawlerType
	element *crawlerType
}

func inferCrawlerType(v any) *crawlerType {
	switch v := v.(type) {
	case nil:
		return &crawlerType{}
	case bool:
		return &crawlerType{kind: "boolean"}
	case json.Number:
		if _, err := v.Int64(); err == nil {
			return &crawlerType{kind: "bigint"}
		}
		return &crawlerType{kind: "double"}
	case float64:
		return &crawlerType{kind: "double"}
	case string:
		return &crawlerType{kind: "string"}
	case map[string]any:
		out := &crawlerType{kind: "struct", fields: map[string]*crawlerType{}}
		for name, field := range v {
			key := strings.ToLower(name)
			out.fields[key] = mergeCrawlerType(out.fields[key], inferCrawlerType(field))
		}
		return out
	case []any:
		out := &crawlerType{kind: "array", element: &crawlerType{}}
		for _, element := range v {
			out.element = mergeCrawlerType(out.element, inferCrawlerType(element))
		}
		return out
	default:
		return &crawlerType{kind: "string"}
	}
}
func mergeCrawlerType(a, b *crawlerType) *crawlerType {
	if a == nil || a.kind == "" {
		return b
	}
	if b == nil || b.kind == "" {
		return a
	}
	if a.kind != b.kind {
		if a.kind == "bigint" && b.kind == "double" || a.kind == "double" && b.kind == "bigint" {
			a.kind = "double"
			return a
		}
		return &crawlerType{kind: "string"}
	}
	if a.kind == "struct" {
		for key, field := range b.fields {
			a.fields[key] = mergeCrawlerType(a.fields[key], field)
		}
	}
	if a.kind == "array" {
		a.element = mergeCrawlerType(a.element, b.element)
	}
	return a
}
func (v *crawlerType) hive() string {
	if v == nil || v.kind == "" {
		return "string"
	}
	switch v.kind {
	case "array":
		return "array<" + v.element.hive() + ">"
	case "struct":
		names := make([]string, 0, len(v.fields))
		for name := range v.fields {
			names = append(names, name)
		}
		slices.Sort(names)
		fields := make([]string, 0, len(names))
		for _, name := range names {
			fields = append(fields, name+":"+v.fields[name].hive())
		}
		return "struct<" + strings.Join(fields, ",") + ">"
	default:
		return v.kind
	}
}
func columnsFromCrawlerType(v *crawlerType) api.ColumnList {
	columns := api.ColumnList{}
	if v == nil || v.kind != "struct" {
		return columns
	}
	names := make([]string, 0, len(v.fields))
	for name := range v.fields {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		columns = append(columns, api.Column{Name: new(api.NameString(name)), Type: new(api.ColumnTypeString(v.fields[name].hive()))})
	}
	return columns
}
func classifyJSON(data []byte, path string) (crawlerSchema, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' && trimmed[0] != '[' {
		return crawlerSchema{}, false, nil
	}
	expr, err := jp.ParseString(path)
	if err != nil {
		return crawlerSchema{}, false, failure("InvalidInputException", "Invalid JSON classifier path.")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var shape *crawlerType
	for {
		var document any
		err = decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return crawlerSchema{}, false, nil
		}
		selected := expr.Get(document)
		for _, record := range selected {
			if rows, ok := record.([]any); ok {
				for _, row := range rows {
					shape = mergeCrawlerType(shape, inferCrawlerType(row))
				}
			} else {
				shape = mergeCrawlerType(shape, inferCrawlerType(record))
			}
		}
	}
	columns := columnsFromCrawlerType(shape)
	if len(columns) == 0 {
		return crawlerSchema{}, false, nil
	}
	return textCrawlerSchema(columns, "json", "org.openx.data.jsonserde.JsonSerDe"), true, nil
}
func scalarCrawlerType(v string) string {
	if v == "" {
		return ""
	}
	if v == "true" || v == "false" {
		return "boolean"
	}
	if _, err := strconv.ParseInt(v, 10, 64); err == nil {
		return "bigint"
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return "double"
	}
	return "string"
}
func mergeColumnType(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || a == b {
		return a
	}
	if a == "bigint" && b == "double" || a == "double" && b == "bigint" {
		return "double"
	}
	return "string"
}
func classifyCSV(data []byte, c *api.CsvClassifier) (crawlerSchema, bool, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return crawlerSchema{}, false, nil
	}
	// TODO: Comeback support additional custom CSV quote symbols/datatype recognizers and native all-string header confidence rules.
	if c.QuoteSymbol != nil && value(c.QuoteSymbol) != "\"" {
		return crawlerSchema{}, false, unsupported("CSV custom quote symbols other than double quote are not supported.")
	}
	if c.CustomDatatypeConfigured != nil && bool(*c.CustomDatatypeConfigured) {
		return crawlerSchema{}, false, unsupported("CSV custom datatype recognizers are not supported.")
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.ReuseRecord = false
	if c.Delimiter != nil {
		runes := []rune(value(c.Delimiter))
		if len(runes) != 1 {
			return crawlerSchema{}, false, failure("InvalidInputException", "Invalid CSV delimiter.")
		}
		reader.Comma = runes[0]
	}
	rows, err := reader.ReadAll()
	if err != nil || len(rows) == 0 || len(rows[0]) < 2 && (c.AllowSingleColumn == nil || !bool(*c.AllowSingleColumn)) {
		return crawlerSchema{}, false, nil
	}
	header := value(c.ContainsHeader) == "PRESENT"
	if c.ContainsHeader == nil || value(c.ContainsHeader) == "UNKNOWN" {
		header = len(rows) > 1
		differentType := false
		seen := map[string]bool{}
		for i, name := range rows[0] {
			if name == "" || scalarCrawlerType(name) != "string" || seen[name] {
				header = false
				break
			}
			seen[name] = true
			if len(rows) > 1 && scalarCrawlerType(rows[1][i]) != "string" {
				differentType = true
			}
		}
		header = header && differentType
	}
	names := make([]string, len(rows[0]))
	for i := range names {
		names[i] = "col" + strconv.Itoa(i)
	}
	if header {
		for i, name := range rows[0] {
			names[i] = strings.ToLower(strings.TrimSpace(name))
		}
		rows = rows[1:]
	}
	if len(c.Header) != 0 {
		if len(c.Header) != len(names) {
			return crawlerSchema{}, false, failure("InvalidInputException", "CSV header column count does not match the object.")
		}
		for i, name := range c.Header {
			names[i] = string(name)
		}
	}
	types := make([]string, len(names))
	for _, row := range rows {
		for i, field := range row {
			if c.DisableValueTrimming == nil || !bool(*c.DisableValueTrimming) {
				field = strings.TrimSpace(field)
			}
			types[i] = mergeColumnType(types[i], scalarCrawlerType(field))
		}
	}
	columns := make(api.ColumnList, 0, len(names))
	seen := map[string]bool{}
	for i, name := range names {
		if name == "" || seen[name] {
			return crawlerSchema{}, false, failure("InvalidInputException", "CSV column names must be nonempty and unique.")
		}
		seen[name] = true
		if types[i] == "" {
			types[i] = "string"
		}
		columns = append(columns, api.Column{Name: new(api.NameString(name)), Type: new(api.ColumnTypeString(types[i]))})
	}
	serde := "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
	if value(c.Serde) == "OpenCSVSerDe" || (c.Serde == nil || value(c.Serde) == "None") && bytes.ContainsRune(data, '"') {
		serde = "org.apache.hadoop.hive.serde2.OpenCSVSerde"
	}
	schema := textCrawlerSchema(columns, "csv", serde)
	schema.SerdeParameters["field.delim"] = api.ParametersMapValue(string(reader.Comma))
	if serde == "org.apache.hadoop.hive.serde2.OpenCSVSerde" {
		schema.SerdeParameters["separatorChar"] = api.ParametersMapValue(string(reader.Comma))
		schema.SerdeParameters["quoteChar"] = "\""
		schema.SerdeParameters["escapeChar"] = "\\"
	}
	schema.Parameters["delimiter"] = api.ParametersMapValue(string(reader.Comma))
	if header {
		schema.Parameters["skip.header.line.count"] = "1"
	}
	return schema, true, nil
}
func classifyXML(data []byte, c *api.XMLClassifier) (crawlerSchema, bool, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	shape := &crawlerType{kind: "struct", fields: map[string]*crawlerType{}}
	matched := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return crawlerSchema{}, false, nil
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != value(c.RowTag) {
			continue
		}
		offset := decoder.InputOffset()
		if offset >= 2 && string(data[offset-2:offset]) == "/>" {
			continue
		}
		row, _, err := crawlerXMLValue(decoder, start, 0)
		if err != nil {
			return crawlerSchema{}, false, err
		}
		if len(row) != 0 {
			matched = true
			for name, val := range row {
				shape.fields[name] = mergeCrawlerType(shape.fields[name], inferXMLType(val))
			}
		}
	}
	if !matched {
		return crawlerSchema{}, false, nil
	}
	schema := textCrawlerSchema(columnsFromCrawlerType(shape), value(c.Classification), "com.ibm.spss.hive.serde2.xml.XmlSerDe")
	schema.SerdeParameters["rowTag"] = api.ParametersMapValue(value(c.RowTag))
	return schema, true, nil
}
func inferXMLType(v any) *crawlerType {
	switch v := v.(type) {
	case string:
		return &crawlerType{kind: scalarCrawlerType(strings.TrimSpace(v))}
	case map[string]any:
		out := &crawlerType{kind: "struct", fields: map[string]*crawlerType{}}
		for name, field := range v {
			out.fields[name] = inferXMLType(field)
		}
		return out
	case []any:
		out := &crawlerType{kind: "array", element: &crawlerType{}}
		for _, element := range v {
			out.element = mergeCrawlerType(out.element, inferXMLType(element))
		}
		return out
	default:
		return inferCrawlerType(v)
	}
}
func crawlerXMLField(row map[string]any, name string, v any) {
	if existing, ok := row[name]; ok {
		if values, ok := existing.([]any); ok {
			row[name] = append(values, v)
		} else {
			row[name] = []any{existing, v}
		}
	} else {
		row[name] = v
	}
}
func crawlerXMLValue(decoder *xml.Decoder, start xml.StartElement, depth int) (map[string]any, string, error) {
	if depth > 128 {
		return nil, "", unsupported("XML classifier nesting exceeds the supported depth.")
	}
	out := map[string]any{}
	for _, attr := range start.Attr {
		out["_"+strings.ToLower(attr.Name.Local)] = attr.Value
	}
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, "", failure("InvalidInputException", "Invalid XML object.")
		}
		switch token := token.(type) {
		case xml.CharData:
			text.Write(token)
		case xml.StartElement:
			child, val, err := crawlerXMLValue(decoder, token, depth+1)
			if err != nil {
				return nil, "", err
			}
			if len(child) == 0 {
				crawlerXMLField(out, strings.ToLower(token.Name.Local), val)
			} else {
				crawlerXMLField(out, strings.ToLower(token.Name.Local), child)
			}
		case xml.EndElement:
			if token.Name == start.Name {
				return out, text.String(), nil
			}
		}
	}
}
func classifyParquet(data []byte) (crawlerSchema, error) {
	file, err := parquet.OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return crawlerSchema{}, failure("InvalidInputException", "Invalid Parquet object.")
	}
	columns := api.ColumnList{}
	for _, field := range file.Schema().Fields() {
		kind, err := parquetHiveType(field)
		if err != nil {
			return crawlerSchema{}, err
		}
		columns = append(columns, api.Column{Name: new(api.NameString(strings.ToLower(field.Name()))), Type: new(api.ColumnTypeString(kind))})
	}
	return crawlerSchema{Columns: columns, Classification: "parquet", InputFormat: "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat", OutputFormat: "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat", Serde: "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe", Parameters: api.ParametersMap{}, SerdeParameters: api.ParametersMap{}}, nil
}
func parquetHiveType(node parquet.Node) (string, error) {
	if node.Repeated() {
		kind, err := parquetHiveType(parquet.Required(node))
		return "array<" + kind + ">", err
	}
	if logical := node.Type().LogicalType(); logical != nil {
		switch logical.Value.(type) {
		case *format.ListType:
			fields := node.Fields()
			if len(fields) != 1 {
				return "", unsupported("Unsupported Parquet list layout.")
			}
			elements := fields[0].Fields()
			if len(elements) != 1 {
				return "", unsupported("Unsupported Parquet list layout.")
			}
			kind, err := parquetHiveType(elements[0])
			return "array<" + kind + ">", err
		case *format.MapType:
			fields := node.Fields()
			if len(fields) != 1 {
				return "", unsupported("Unsupported Parquet map layout.")
			}
			entries := fields[0].Fields()
			if len(entries) != 2 {
				return "", unsupported("Unsupported Parquet map layout.")
			}
			key, err := parquetHiveType(entries[0])
			if err != nil {
				return "", err
			}
			val, err := parquetHiveType(entries[1])
			return "map<" + key + "," + val + ">", err
		}
	}
	if !node.Leaf() {
		fields := node.Fields()
		parts := make([]string, 0, len(fields))
		for _, field := range fields {
			kind, err := parquetHiveType(field)
			if err != nil {
				return "", err
			}
			parts = append(parts, strings.ToLower(field.Name())+":"+kind)
		}
		return "struct<" + strings.Join(parts, ",") + ">", nil
	}
	t := node.Type()
	if logical := t.LogicalType(); logical != nil {
		switch logical := logical.Value.(type) {
		case *format.StringType:
			return "string", nil
		case *format.DateType:
			return "date", nil
		case *format.TimestampType:
			return "timestamp", nil
		case *format.DecimalType:
			return fmt.Sprintf("decimal(%d,%d)", logical.Precision, logical.Scale), nil
		}
	}
	switch t.Kind() {
	case parquet.Boolean:
		return "boolean", nil
	case parquet.Int32:
		return "int", nil
	case parquet.Int64:
		return "bigint", nil
	case parquet.Int96:
		return "timestamp", nil
	case parquet.Float:
		return "float", nil
	case parquet.Double:
		return "double", nil
	case parquet.ByteArray, parquet.FixedLenByteArray:
		return "binary", nil
	default:
		return "", unsupported("Unsupported Parquet physical type.")
	}
}
func crawlerTableName(v string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(v) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			out.WriteRune(r)
		} else {
			out.WriteByte('_')
		}
	}
	name := out.String()
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}
