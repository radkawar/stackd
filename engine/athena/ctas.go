package athena

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"stackd/compute/docker"
)

//go:embed ctas_parser.java
var ctasParserSource string

// ctasPlan contains only typed Trino 476 AST projections. Query, Aliases and
// property SQL are produced by Trino's own formatters, never SQL substring scans.
type ctasPlan struct {
	Identifier []string       `json:"identifier"`
	Query      string         `json:"query"`
	SaveMode   string         `json:"saveMode"`
	WithData   bool           `json:"withData"`
	Aliases    []string       `json:"aliases"`
	Comment    *string        `json:"comment"`
	Properties []ctasProperty `json:"properties"`
}

type ctasProperty struct {
	Name  string    `json:"name"`
	Value ctasValue `json:"value"`
}

type ctasValue struct {
	Kind     string      `json:"kind"`
	SQL      string      `json:"sql"`
	Text     string      `json:"text"`
	Boolean  bool        `json:"boolean"`
	Elements []ctasValue `json:"elements"`
}

// parseCTAS runs only the parser bundled with our pinned SQL engine. Source-mode
// Java avoids an extra image, downloaded dependencies or a second SQL grammar.
// An exec has no independent ownership: cancellation/failure retires its parent
// engine through Execute's existing deferred cleanup, killing any parser too.
func (d *Docker) parseCTAS(ctx context.Context, engine *warmEngine, sql string) (*ctasPlan, error) {
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	// /tmp is a runtime tmpfs. Docker's archive API cannot reliably access
	// files in tmpfs mounts; stage SQL inside the container namespace instead.
	// The pinned source is extracted with the startup configuration before
	// engine readiness. Bound individual arguments below Linux's argv limit.
	encoded := base64.StdEncoding.EncodeToString([]byte(sql))
	args := []string{"/bin/sh", "-c", `set -eu; umask 077; printf '%s' "$@" | base64 -d > /tmp/stackd-athena/ctas.sql; exec java -Xmx128m --class-path '/usr/lib/trino/lib/*' /tmp/stackd-athena/StackdCTAS.java /tmp/stackd-athena/ctas.sql`, "stackd-ctas"}
	const chunkSize = 32 << 10
	for len(encoded) > 0 {
		size := min(len(encoded), chunkSize)
		args = append(args, encoded[:size])
		encoded = encoded[size:]
	}
	var created struct {
		ID string `json:"Id"`
	}
	command := map[string]any{
		"AttachStdout": true, "AttachStderr": true,
		"Cmd": args,
	}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/"+engine.containerID+"/exec", command, &created); err != nil {
		return nil, err
	}
	if created.ID == "" {
		return nil, errors.New("native CTAS parser exec has no identity")
	}
	response, err := d.client.Request(ctx, http.MethodPost, "/exec/"+created.ID+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var stdout, stderr bytes.Buffer
	if err := docker.CopyStream(&stdout, &stderr, response.Body); err != nil {
		return nil, err
	}
	var status struct {
		Running  bool
		ExitCode int
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/exec/"+created.ID+"/json", nil, &status); err != nil {
		return nil, err
	}
	if status.Running || status.ExitCode != 0 {
		return nil, fmt.Errorf("native Trino CTAS parser failed (running=%t, exit=%d): %s", status.Running, status.ExitCode, stderr.String())
	}
	var envelope struct {
		Plan        *ctasPlan `json:"plan"`
		SyntaxError string    `json:"syntaxError"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		return nil, fmt.Errorf("native Trino CTAS parser output: %w", err)
	}
	return envelope.Plan, nil
}

func ctasPropertyError(format string, args ...any) error {
	return &QueryError{ErrorName: "INVALID_TABLE_PROPERTY", ErrorType: "USER_ERROR", Message: fmt.Sprintf(format, args...)}
}

func ctasString(properties map[string]ctasValue, name, fallback string) (string, error) {
	value, found := properties[name]
	if !found {
		return fallback, nil
	}
	if value.Kind != "string" {
		return "", ctasPropertyError("CTAS property %s must be a string literal", name)
	}
	return value.Text, nil
}

// ctasDDL maps Athena's CTAS controls to actual connector properties and a
// query-scoped native compression session. It never manufactures Glue metadata.
// Sources: docs.aws.amazon.com/athena/latest/ug/create-table-as.html;
// trinodb/trino/476 HiveTableProperties, IcebergTableProperties,
// HiveSessionProperties, IcebergSessionProperties and HiveCompressionCodec.
func ctasDDL(plan *ctasPlan, request Request) (string, string, error) {
	properties := make(map[string]ctasValue, len(plan.Properties))
	for _, property := range plan.Properties {
		name := strings.ToLower(property.Name)
		if _, found := properties[name]; found {
			return "", "", ctasPropertyError("Duplicate CTAS property %s", name)
		}
		if name == "format" && property.Name != "format" {
			return "", "", ctasPropertyError("CTAS format property must be lowercase")
		}
		properties[name] = property.Value
	}
	tableType, err := ctasString(properties, "table_type", "HIVE")
	if err != nil {
		return "", "", err
	}
	iceberg := strings.EqualFold(tableType, "ICEBERG")
	if !iceberg && !strings.EqualFold(tableType, "HIVE") {
		return "", "", ctasPropertyError("Unsupported CTAS table_type %q", tableType)
	}
	external := true
	if value, found := properties["is_external"]; found {
		if value.Kind != "boolean" {
			return "", "", ctasPropertyError("CTAS is_external must be a boolean")
		}
		external = value.Boolean
	}
	if iceberg && external {
		return "", "", ctasPropertyError("Iceberg CTAS requires is_external=false")
	}
	if len(plan.Identifier) == 0 || len(plan.Identifier) > 3 || plan.Query == "" {
		return "", "", ctasPropertyError("CTAS requires a table name and query")
	}
	catalog, database, table := request.Catalog, request.Database, plan.Identifier[len(plan.Identifier)-1]
	if catalog == "" {
		catalog = "awsdatacatalog"
	}
	if len(plan.Identifier) > 1 {
		database = plan.Identifier[len(plan.Identifier)-2]
	}
	if len(plan.Identifier) == 3 {
		catalog = strings.ToLower(plan.Identifier[0])
	}
	if _, err := request.CatalogIDFor(catalog); err != nil {
		return "", "", ctasPropertyError("%s", err)
	}
	if database == "" {
		return "", "", ctasPropertyError("CTAS requires a database")
	}
	if iceberg {
		catalog, err = icebergCatalogFor(request, catalog)
		if err != nil {
			return "", "", ctasPropertyError("%s", err)
		}
	}
	format, err := ctasString(properties, "format", "PARQUET")
	if err != nil {
		return "", "", err
	}
	format = strings.ToUpper(format)
	if iceberg {
		if format != "PARQUET" && format != "ORC" && format != "AVRO" {
			return "", "", ctasPropertyError("Unsupported Iceberg CTAS format %q", format)
		}
	} else {
		switch format {
		case "PARQUET", "ORC", "AVRO", "JSON", "TEXTFILE", "CSV":
		default:
			return "", "", ctasPropertyError("CTAS format %q is not writable by Trino 476", format)
		}
	}
	output := map[string]string{"format": quoteSQLString(format)}
	if iceberg {
		output["format_version"] = "2"
	}
	compression, compressionProperty := "", ""
	for _, name := range []string{"write_compression", "parquet_compression", "orc_compression"} {
		if _, found := properties[name]; !found {
			continue
		}
		if compressionProperty != "" {
			return "", "", ctasPropertyError("Multiple CTAS compression properties cannot be specified together")
		}
		compression, err = ctasString(properties, name, "")
		if err != nil {
			return "", "", err
		}
		if compression == "" {
			return "", "", ctasPropertyError("CTAS %s must name a compression codec", name)
		}
		compressionProperty = name
	}
	if compressionProperty == "parquet_compression" && format != "PARQUET" || compressionProperty == "orc_compression" && format != "ORC" {
		return "", "", ctasPropertyError("CTAS %s does not apply to %s", compressionProperty, format)
	}
	if compressionProperty == "" {
		// Athena's format-specific defaults differ from Trino's connector default.
		if iceberg {
			compression = "ZSTD"
		} else {
			switch format {
			case "PARQUET", "JSON", "TEXTFILE", "CSV":
				compression = "GZIP"
			case "ORC":
				compression = "ZLIB"
			}
		}
	}
	if compression != "" {
		compression = strings.ToUpper(compression)
		if compression == "GZIP" && format == "ORC" || compression == "GZIP" && format == "AVRO" && !iceberg {
			return "", "", ctasPropertyError("GZIP does not apply to %s CTAS format %s", tableType, format)
		}
		if compression == "DEFLATE" && format == "AVRO" {
			compression = "GZIP"
		} // Native GZIP selects Avro DEFLATE.
		if compression == "ZLIB" && format == "ORC" {
			compression = "GZIP"
		} // Native GZIP selects ORC ZLIB.
		if compression == "UNCOMPRESSED" {
			compression = "NONE"
		}
		switch compression {
		case "NONE", "GZIP", "SNAPPY", "ZSTD":
		case "LZ4":
			if format == "PARQUET" || format == "AVRO" {
				return "", "", ctasPropertyError("LZ4 is not writable for %s in Trino 476", format)
			}
		default:
			return "", "", ctasPropertyError("Unsupported CTAS compression %q for %s", compression, format)
		}
	}
	for _, property := range plan.Properties {
		name, value := strings.ToLower(property.Name), property.Value
		switch name {
		case "table_type", "is_external", "format", "write_compression", "parquet_compression", "orc_compression":
		case "external_location", "location":
			if name == "external_location" && request.EnforceCTASDestination {
				return "", "", ctasPropertyError("external_location is not allowed when the workgroup enforces its query results location")
			}
			if iceberg != (name == "location") {
				return "", "", ctasPropertyError("CTAS %s does not apply to table_type %s", name, tableType)
			}
			location, err := ctasString(properties, name, "")
			if err != nil {
				return "", "", err
			}
			parsed, parseErr := url.Parse(location)
			if parseErr != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return "", "", ctasPropertyError("CTAS %s must be an S3 location", name)
			}
			if !iceberg && !external {
				return "", "", ctasPropertyError("external_location requires is_external=true")
			}
			output[name] = quoteSQLString(location)
		case "partitioned_by", "partitioning", "bucketed_by":
			if iceberg != (name == "partitioning") {
				return "", "", ctasPropertyError("CTAS %s does not apply to table_type %s", name, tableType)
			}
			if value.Kind != "array" {
				return "", "", ctasPropertyError("CTAS %s must be an array of strings", name)
			}
			for _, element := range value.Elements {
				if element.Kind != "string" || element.Text == "" {
					return "", "", ctasPropertyError("CTAS %s must be an array of nonempty strings", name)
				}
			}
			output[name] = value.SQL
		case "bucket_count":
			count, err := strconv.ParseInt(value.Text, 10, 32)
			if iceberg || value.Kind != "integer" || err != nil || count <= 0 {
				return "", "", ctasPropertyError("Hive CTAS bucket_count must be a positive integer")
			}
			output[name] = value.SQL
		case "field_delimiter":
			if iceberg || (format != "TEXTFILE" && format != "CSV") {
				return "", "", ctasPropertyError("field_delimiter requires a text-based delimited format")
			}
			if value.Kind != "string" || utf8.RuneCountInString(value.Text) != 1 {
				return "", "", ctasPropertyError("field_delimiter must contain exactly one character")
			}
			key := "textfile_field_separator"
			if format == "CSV" {
				key = "csv_separator"
			}
			output[key] = quoteSQLString(value.Text)
		default:
			if !iceberg || !ctasIcebergProperty(name) {
				return "", "", ctasPropertyError("Unsupported CTAS property %q", property.Name)
			}
			// These are real, typed Trino Iceberg table properties, not arbitrary
			// metadata. Native analysis validates their values before any writes.
			output[name] = value.SQL
		}
	}
	if iceberg && output["location"] == "" {
		return "", "", ctasPropertyError("Iceberg CTAS requires location")
	}
	if !iceberg && external && output["external_location"] == "" {
		if request.CTASLocation == "" {
			return "", "", ctasPropertyError("External CTAS requires external_location or a query result location")
		}
		output["external_location"] = quoteSQLString(request.CTASLocation)
	}
	if !iceberg {
		_, buckets := output["bucketed_by"]
		_, count := output["bucket_count"]
		if buckets != count || buckets && len(properties["bucketed_by"].Elements) == 0 {
			return "", "", ctasPropertyError("bucketed_by and bucket_count must be specified together with nonempty columns")
		}
	}
	var sql strings.Builder
	switch plan.SaveMode {
	case "FAIL":
		sql.WriteString("CREATE TABLE ")
	case "IGNORE":
		sql.WriteString("CREATE TABLE IF NOT EXISTS ")
	case "REPLACE":
		sql.WriteString("CREATE OR REPLACE TABLE ")
	default:
		return "", "", ctasPropertyError("Unsupported native CTAS save mode %q", plan.SaveMode)
	}
	sql.WriteString(quoteSQLIdentifier(catalog) + "." + quoteSQLIdentifier(database) + "." + quoteSQLIdentifier(table))
	if len(plan.Aliases) > 0 {
		sql.WriteString(" (" + strings.Join(plan.Aliases, ", ") + ")")
	}
	if plan.Comment != nil {
		sql.WriteString(" COMMENT " + quoteSQLString(*plan.Comment))
	}
	keys := make([]string, 0, len(output))
	for key := range output {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sql.WriteString(" WITH (")
	for i, key := range keys {
		if i > 0 {
			sql.WriteString(", ")
		}
		sql.WriteString(key + " = " + output[key])
	}
	sql.WriteString(") AS " + plan.Query)
	if !plan.WithData {
		sql.WriteString(" WITH NO DATA")
	}
	session := ""
	if compression != "" {
		session = catalog + ".compression_codec=" + compression
	}
	return sql.String(), session, nil
}

func ctasIcebergProperty(name string) bool {
	switch name {
	case "format_version", "sorted_by", "max_commit_retry", "orc_bloom_filter_columns", "orc_bloom_filter_fpp", "parquet_bloom_filter_columns", "object_store_layout_enabled", "data_location":
		return true
	}
	return false
}

// A private HTTP client wrapper scopes writer compression to this one execution,
// including pagination/cancellation, without mutating shared transport state or
// leaking SET SESSION into later users of a warm engine.
type ctasSessionTransport struct {
	base    http.RoundTripper
	session string
}

func (transport ctasSessionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.Header.Add("X-Trino-Session", transport.session)
	return transport.base.RoundTrip(copy)
}

func executeCTAS(ctx context.Context, client *http.Client, endpoint string, request Request, session string, consume func(Page) error) error {
	if session == "" {
		return executeSQL(ctx, client, endpoint, request, "athena", consume)
	}
	copy := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	copy.Transport = ctasSessionTransport{base: base, session: session}
	return executeSQL(ctx, &copy, endpoint, request, "athena", consume)
}
