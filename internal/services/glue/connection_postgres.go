package glue

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/glue"
)

// PostgreSQL discovery uses the installed native libpq client. It never returns
// fabricated table metadata and never logs the password, URI, or process stderr.
// TODO: Comeback add actual JDBC drivers for other vendors, VPC connectivity,
// JDBC driver jars, certificate material and secret rotation during a native scan.
func (s *Service) crawlJDBC(ctx context.Context, crawler CrawlerRecord) ([]crawlerDerivedTable, error) {
	out := []crawlerDerivedTable{}
	for _, target := range crawler.Crawler.Targets.JdbcTargets {
		if len(target.EnableAdditionalMetadata) != 0 {
			return nil, unsupported("Additional JDBC metadata extraction is not supported.")
		}
		var connection ConnectionRecord
		err := s.repository.View(ctx, func(r Reader) error {
			key := ResourceKey{Scope: crawler.Key.Scope, Name: value(target.ConnectionName)}
			var err error
			connection, err = r.Connection(key)
			if err != nil {
				return err
			}
			return s.authorize(r.Context(), r, "GetConnection", key.Scope, key.ARN("connection"), connection.Tags)
		})
		if err != nil {
			return nil, err
		}
		c := connection.Connection
		if value(c.ConnectionType) != "JDBC" {
			return nil, failure("InvalidInputException", "JDBC crawler target requires a JDBC connection.")
		}
		if c.PhysicalConnectionRequirements != nil {
			return nil, unsupported("JDBC VPC/subnet connectivity is not implemented; only direct native PostgreSQL connections are available.")
		}
		properties := c.ConnectionProperties
		for _, key := range []api.ConnectionPropertyKey{"JDBC_DRIVER_JAR_URI", "JDBC_DRIVER_CLASS_NAME", "CUSTOM_JDBC_CERT", "CUSTOM_JDBC_CERT_STRING", "SKIP_CUSTOM_JDBC_CERT_VALIDATION"} {
			if properties[key] != "" {
				return nil, unsupported("Custom JDBC drivers and certificates require an unconfigured native adapter.")
			}
		}
		raw := string(properties["JDBC_CONNECTION_URL"])
		if !strings.HasPrefix(raw, "jdbc:postgresql://") {
			return nil, unsupported("Only native PostgreSQL JDBC target discovery is configured.")
		}
		u, err := url.Parse(strings.TrimPrefix(raw, "jdbc:"))
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, failure("InvalidInputException", "Invalid PostgreSQL JDBC URL; keep credentials in connection properties or Secrets Manager.")
		}
		database := strings.TrimPrefix(u.Path, "/")
		if database == "" || strings.Contains(database, "/") {
			return nil, failure("InvalidInputException", "PostgreSQL JDBC URL must name one database.")
		}
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, failure("InvalidInputException", "Invalid PostgreSQL JDBC URL options.")
		}
		sslmode := "prefer"
		for key, values := range query {
			if key != "sslmode" || len(values) != 1 {
				return nil, unsupported("This PostgreSQL JDBC URL option is not implemented.")
			}
			sslmode = values[0]
		}
		if properties["JDBC_ENFORCE_SSL"] == "true" {
			sslmode = "require"
		}
		if !slices.Contains([]string{"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}, sslmode) {
			return nil, failure("InvalidInputException", "Invalid PostgreSQL SSL mode.")
		}
		username, password := string(properties["USERNAME"]), connection.Password
		if len(connection.PasswordCipher) > 0 {
			if s.connectionCrypto == nil {
				return nil, unsupported("Connection password KMS adapter is not configured.")
			}
			plain, _, rejected := s.connectionCrypto.Decrypt(ctx, connection.PasswordCipher, connectionEncryptionContext(connection.Key))
			if rejected != nil {
				return nil, rejected
			}
			password = string(plain)
		}
		if secret := string(properties["SECRET_ID"]); secret != "" {
			if s.connectionSecrets == nil {
				return nil, unsupported("Connection Secrets Manager adapter is not configured.")
			}
			username, password, err = s.connectionSecrets.Read(ctx, secret)
			if err != nil {
				return nil, err
			}
		}
		if username == "" || password == "" {
			return nil, failure("InvalidInputException", "JDBC credentials are not available.")
		}
		port := u.Port()
		if port == "" {
			port = "5432"
		}
		client, err := exec.LookPath("psql")
		if err != nil {
			return nil, unsupported("Native PostgreSQL crawler requires the psql executable.")
		}
		// libpq falls back to getpwuid's home when HOME is absent, including
		// ~/.postgresql client certificates and root trust. Never use host identity.
		// GSS can also select host Kerberos caches/keytabs despite PGPASSWORD:
		// disable GSS encryption and isolate credentials if the server requests GSS auth.
		home, err := os.MkdirTemp("", "stackd-glue-postgres-")
		if err != nil {
			return nil, failure("InvalidInputException", "Native PostgreSQL isolated home could not be created.")
		}
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		cmd := exec.CommandContext(callCtx, client, "--no-psqlrc", "--no-password", "--csv", "--set", "ON_ERROR_STOP=1", "--command", crawlerPostgresColumns)
		cmd.Env = []string{"HOME=" + home, "LC_ALL=C", "PGHOST=" + u.Hostname(), "PGPORT=" + port, "PGDATABASE=" + database, "PGUSER=" + username, "PGPASSWORD=" + password, "PGSSLMODE=" + sslmode, "PGGSSENCMODE=disable", "KRB5CCNAME=FILE:" + home + "/krb5cc", "KRB5_CLIENT_KTNAME=FILE:" + home + "/client.keytab", "KRB5_KTNAME=FILE:" + home + "/server.keytab", "PGCONNECT_TIMEOUT=10", "PGAPPNAME=stackd-glue-crawler"}
		data, err := cmd.Output()
		cancel()
		cleanupErr := os.RemoveAll(home)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, failure("InvalidInputException", "Native PostgreSQL connection or metadata discovery failed.")
		}
		if cleanupErr != nil {
			return nil, failure("InvalidInputException", "Native PostgreSQL isolated home could not be removed.")
		}
		tables, err := postgresCrawlerTables(data, database, target, value(crawler.Crawler.TablePrefix), crawler.Key.Name, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, tables...)
	}
	return out, nil
}

const crawlerPostgresColumns = `SELECT table_schema, table_name, column_name, data_type, udt_name,
 COALESCE(numeric_precision::text,''), COALESCE(numeric_scale::text,''), ordinal_position
 FROM information_schema.columns
 WHERE table_schema NOT IN ('pg_catalog','information_schema')
 ORDER BY table_schema, table_name, ordinal_position LIMIT 10001`

func postgresCrawlerTables(data []byte, database string, target api.JdbcTarget, prefix, crawlerName, location string) ([]crawlerDerivedTable, error) {
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, failure("InvalidInputException", "Invalid native PostgreSQL metadata response.")
	}
	if len(rows) > 10001 {
		return nil, unsupported("PostgreSQL schema exceeds the local 10000-column discovery bound.")
	}
	parts := strings.Split(value(target.Path), "/")
	if len(parts) != 3 {
		return nil, failure("InvalidInputException", "PostgreSQL target path must be database/schema/table; % is a wildcard.")
	}
	filters := make([]func(string) bool, 3)
	for i, part := range parts {
		pattern, err := crawlerGlob(strings.ReplaceAll(part, "%", "*"))
		if err != nil {
			return nil, err
		}
		filters[i] = pattern.MatchString
	}
	if !filters[0](database) {
		return nil, failure("InvalidInputException", "JDBC target database does not match the connected database.")
	}
	tables := map[string]*crawlerDerivedTable{}
	order := []string{}
	for _, fields := range rows[1:] {
		if len(fields) != 8 {
			return nil, failure("InvalidInputException", "Invalid native PostgreSQL metadata columns.")
		}
		schema, name := fields[0], fields[1]
		if !filters[1](schema) || !filters[2](name) {
			continue
		}
		excluded := false
		for _, exclusion := range target.Exclusions {
			pattern, err := crawlerGlob(strings.ReplaceAll(string(exclusion), "%", "*"))
			if err != nil {
				return nil, err
			}
			if pattern.MatchString(database+"/"+schema+"/"+name) || pattern.MatchString(schema+"/"+name) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		key := schema + "." + name
		table := tables[key]
		if table == nil {
			table = &crawlerDerivedTable{Table: api.TableInput{Name: new(api.NameString(crawlerTableName(prefix + database + "_" + schema + "_" + name))), TableType: new(api.TableTypeString("EXTERNAL_TABLE")), StorageDescriptor: &api.StorageDescriptor{Location: new(api.LocationString(location + "/" + schema + "/" + name)), Columns: api.ColumnList{}}, Parameters: api.ParametersMap{"classification": "postgresql", "typeOfData": "table", "connectionName": api.ParametersMapValue(value(target.ConnectionName)), "UPDATED_BY_CRAWLER": api.ParametersMapValue(crawlerName)}}}
			tables[key] = table
			order = append(order, key)
		}
		kind, err := postgresCrawlerType(fields[3], fields[4], fields[5], fields[6])
		if err != nil {
			return nil, err
		}
		table.Table.StorageDescriptor.Columns = append(table.Table.StorageDescriptor.Columns, api.Column{Name: new(api.NameString(strings.ToLower(fields[2]))), Type: new(api.ColumnTypeString(kind))})
	}
	out := make([]crawlerDerivedTable, 0, len(order))
	for _, key := range order {
		out = append(out, *tables[key])
	}
	return out, nil
}
func postgresCrawlerType(kind, udt, precision, scale string) (string, error) {
	switch kind {
	case "boolean":
		return "boolean", nil
	case "smallint":
		return "smallint", nil
	case "integer":
		return "int", nil
	case "bigint":
		return "bigint", nil
	case "real":
		return "float", nil
	case "double precision":
		return "double", nil
	case "numeric":
		p, e1 := strconv.Atoi(precision)
		s, e2 := strconv.Atoi(scale)
		if e1 != nil || e2 != nil || p > 38 || s < 0 || s > p {
			return "", unsupported("PostgreSQL unconstrained or large numeric types require an additional catalog mapping.")
		}
		return "decimal(" + precision + "," + scale + ")", nil
	case "date":
		return "date", nil
	case "timestamp without time zone", "timestamp with time zone":
		return "timestamp", nil
	case "bytea":
		return "binary", nil
	case "character varying", "character", "text", "uuid", "json", "jsonb", "time without time zone", "time with time zone":
		return "string", nil
	case "ARRAY":
		switch udt {
		case "_int2":
			return "array<smallint>", nil
		case "_int4":
			return "array<int>", nil
		case "_int8":
			return "array<bigint>", nil
		case "_text", "_varchar":
			return "array<string>", nil
		case "_bool":
			return "array<boolean>", nil
		case "_float4":
			return "array<float>", nil
		case "_float8":
			return "array<double>", nil
		}
	}
	return "", unsupported("The native PostgreSQL column type is not supported by this crawler mapping.")
}
