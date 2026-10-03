package athena

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"stackd/compute/docker"
)

// HiveDDLImage supplies Apache Spark 4.1.3's native Hive-compatible parser only.
// No Spark SQL execution, data access or metastore is used by this adapter.
const HiveDDLImage = "apache/spark@sha256:9b0a6c2c860f5e7d18dd5270286fef32a09c7f5a7e2b0dbe5642de8a3a02ab3e"

//go:embed hive_ddl.py
var hiveDDLParser string

// HiveDDL is projected from Spark's typed logical plan, never parsed from SQL
// with regular expressions. The service applies Hive metadata through Glue;
// Iceberg CREATE is emitted back to Trino to create real Iceberg metadata bytes.
type HiveDDL struct {
	Kind                             string   `json:"kind"`
	Identifier                       []string `json:"identifier"`
	IfNotExists                      bool     `json:"ifNotExists"`
	External                         bool     `json:"external"`
	Location, Comment                string
	Columns                          []DDLColumn       `json:"columns"`
	PartitionColumns                 []string          `json:"partitionColumns"`
	Properties                       map[string]string `json:"properties"`
	InputFormat, OutputFormat, Serde string
	SerdeProperties                  map[string]string `json:"serdeProperties"`
}
type DDLColumn struct{ Name, Type, TrinoType, Comment string }

func (d *Docker) parseHiveDDL(ctx context.Context, handle, sql string) (_ *HiveDDL, retErr error) {
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config := d.containerConfig(handle, nil)
	config.Image = d.hiveDDLImageID
	config.Hostname = "localhost"
	// Docker's "none" network keeps the loopback sandbox required by Py4J.
	// NetworkDisabled bypasses that sandbox and breaks localhost resolution.
	config.HostConfig.NetworkMode = "none"
	config.ExposedPorts, config.HostConfig.PortBindings = nil, nil
	config.HostConfig.ExtraHosts = nil
	config.User = ""
	config.HostConfig.Memory, config.HostConfig.MemorySwap = 2<<30, 2<<30
	config.HostConfig.Tmpfs = map[string]string{"/tmp": "rw,nosuid,nodev,exec,size=512m,mode=1777"}
	config.Env = []string{"AWS_EC2_METADATA_DISABLED=true", "SPARK_LOCAL_IP=127.0.0.1", "PYTHONPATH=/opt/spark/python:/opt/spark/python/lib/py4j-0.10.9.9-src.zip", "PYSPARK_SUBMIT_ARGS=--driver-memory 512m pyspark-shell", "STACKD_HIVE_SQL=" + base64.StdEncoding.EncodeToString([]byte(sql))}
	config.Entrypoint = []string{"python3"}
	config.Cmd = []string{"-c", hiveDDLParser}
	var created struct {
		ID string `json:"Id"`
	}
	createCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	err := d.client.JSON(createCtx, http.MethodPost, "/containers/create?name="+handle+"-hiveddl", config, &created)
	stop()
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, d.client.RemoveContainer(cleanup, created.ID))
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return nil, err
	}
	var status struct {
		StatusCode int64
		Error      *struct{ Message string }
	}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/"+created.ID+"/wait?condition=not-running", nil, &status); err != nil {
		return nil, err
	}
	if status.Error != nil {
		return nil, errors.New(status.Error.Message)
	}
	response, err := d.client.Request(ctx, http.MethodGet, "/containers/"+created.ID+"/logs?stdout=true&stderr=true", nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var stdout bytes.Buffer
	if err := docker.CopyStream(&stdout, io.Discard, response.Body); err != nil {
		return nil, err
	}
	if status.StatusCode != 0 {
		return nil, fmt.Errorf("native Hive DDL parser exited with status %d", status.StatusCode)
	}
	var envelope struct {
		Plan      *HiveDDL `json:"plan"`
		Error     string   `json:"error"`
		ErrorKind string   `json:"errorKind"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		return nil, fmt.Errorf("native Hive DDL parser output: %w", err)
	}
	if envelope.Error != "" {
		switch envelope.ErrorKind {
		case "SYNTAX_ERROR":
			return nil, &QueryError{ErrorName: "SYNTAX_ERROR", ErrorType: "USER_ERROR", Message: envelope.Error}
		case "UNSUPPORTED_DDL":
			return nil, &QueryError{ErrorName: "NOT_SUPPORTED", ErrorType: "USER_ERROR", Message: envelope.Error}
		default:
			return nil, fmt.Errorf("native Hive DDL parser runtime failure: %s", envelope.Error)
		}
	}
	if envelope.Plan == nil {
		return nil, errors.New("native Hive parser did not produce a DDL plan")
	}
	return envelope.Plan, nil
}

func quoteSQLIdentifier(value string) string {
	return "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
}
func quoteSQLString(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func icebergDDL(plan *HiveDDL, request Request) (string, error) {
	if plan.Kind != "CREATE_TABLE" || !strings.EqualFold(plan.Properties["table_type"], "ICEBERG") {
		return "", nil
	}
	if len(plan.Identifier) == 0 || len(plan.Identifier) > 3 || len(plan.Columns) == 0 || plan.Location == "" {
		return "", errors.New("iceberg CREATE requires a table name, columns and S3 location")
	}
	database, table, catalog := request.Database, plan.Identifier[len(plan.Identifier)-1], request.Catalog
	if len(plan.Identifier) > 1 {
		database = plan.Identifier[len(plan.Identifier)-2]
	}
	if len(plan.Identifier) == 3 {
		catalog = strings.ToLower(plan.Identifier[0])
	}
	if catalog != request.Catalog && catalog != "awsdatacatalog" && catalog != "iceberg" {
		return "", errors.New("iceberg CREATE references an unconfigured catalog")
	}
	nativeCatalog := "iceberg"
	if catalog == "awsdatacatalog" && request.CatalogID != "" && request.CatalogID != request.AccountID {
		nativeCatalog = "awsdatacatalog_iceberg"
	}
	var out strings.Builder
	out.WriteString("CREATE TABLE ")
	if plan.IfNotExists {
		out.WriteString("IF NOT EXISTS ")
	}
	out.WriteString(quoteSQLIdentifier(nativeCatalog) + "." + quoteSQLIdentifier(database) + "." + quoteSQLIdentifier(table) + " (")
	for i, column := range plan.Columns {
		if i != 0 {
			out.WriteString(", ")
		}
		out.WriteString(quoteSQLIdentifier(column.Name) + " " + column.TrinoType)
		if column.Comment != "" {
			out.WriteString(" COMMENT " + quoteSQLString(column.Comment))
		}
	}
	out.WriteByte(')')
	if plan.Comment != "" {
		out.WriteString(" COMMENT " + quoteSQLString(plan.Comment))
	}
	out.WriteString(" WITH (format_version=2, location=" + quoteSQLString(plan.Location))
	for key, value := range plan.Properties {
		switch strings.ToLower(key) {
		case "table_type":
		case "format":
			out.WriteString(", format=" + quoteSQLString(strings.ToUpper(value)))
		case "write_compression":
			out.WriteString(", compression_codec=" + quoteSQLString(strings.ToUpper(value)))
		default:
			return "", fmt.Errorf("unsupported Iceberg table property %q", key)
		}
	}
	if len(plan.PartitionColumns) > 0 {
		out.WriteString(", partitioning=ARRAY[")
		for i, name := range plan.PartitionColumns {
			if i != 0 {
				out.WriteByte(',')
			}
			out.WriteString(quoteSQLString(name))
		}
		out.WriteByte(']')
	}
	out.WriteByte(')')
	return out.String(), nil
}
