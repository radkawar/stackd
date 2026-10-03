package sqlite_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"stackd/storage/sqlite"
)

func TestMQActiveMQAPIVersionUpgradeRetainsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mq.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("schema/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	version := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_mq_activemq_api_version.sql") {
			break
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(t.Context(), string(body)); err != nil {
			t.Fatalf("historical migration %s: %v", file, err)
		}
		version++
	}
	if version == len(files) {
		t.Fatal("MQ API version migration not found")
	}
	if _, err := tx.ExecContext(t.Context(), fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for i, fixture := range []struct {
		partition, account, region, engine, version string
	}{
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.18.7"},
		{"aws-cn", "222222222222", "cn-north-1", "ACTIVEMQ", "5.18.7"},
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.18"},
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.18.99"},
		{"aws", "111111111111", "us-east-1", "ACTIVEMQ", "5.17.6"},
		{"aws", "111111111111", "us-east-1", "RABBITMQ", "5.18.7"},
		{"aws", "111111111111", "us-east-1", "RABBITMQ", "3.13"},
	} {
		id := fmt.Sprintf("retained-%d", i)
		brokerARN := fmt.Sprintf("arn:%s:mq:%s:%s:broker:%s:%s", fixture.partition, fixture.region, fixture.account, id, id)
		configARN := fmt.Sprintf("arn:%s:mq:%s:%s:configuration:%s:%s", fixture.partition, fixture.region, fixture.account, id, id)
		exec(`INSERT INTO mq_brokers
			(partition,account_id,region,id,arn,name,engine,engine_version,instance_type,state,creator_request_id,username,password,operation,failure,version,created,due,endpoint_address,endpoint_console_url,endpoint_native_id,endpoint_ca_pem,
			maintenance_day,maintenance_time,maintenance_zone,maintenance_due,maintenance_adjustments,
			log_general,log_audit,log_pending_general,log_pending_audit,log_general_file_id,log_general_offset,log_audit_file_id,log_audit_offset,log_delivery_error,log_due)
			VALUES(?,?,?,?,?,?,?,?,'mq.m5.large','REBOOT_IN_PROGRESS','request','initial','initial-password','reboot','retained failure',19,'2031-01-01T00:00:00Z','2031-01-02T00:00:00Z','ssl://localhost:61617','https://localhost:8162','native-container',X'010203',
			'MONDAY','03:00','UTC','2031-01-03T00:00:00Z',2,
			1,0,0,1,'general-file',123,'audit-file',456,'delivery failure','2031-01-04T00:00:00Z')`,
			fixture.partition, fixture.account, fixture.region, id, brokerARN, id, fixture.engine, fixture.version)
		exec(`INSERT INTO mq_broker_tags VALUES(?,'owner','retained')`, brokerARN)
		exec(`INSERT INTO mq_broker_users VALUES(?,'initial','native-password',1,'UPDATE','pending-password',0)`, brokerARN)
		exec(`INSERT INTO mq_broker_user_groups VALUES(?,'initial',0,'effective-group'),(?,'initial',1,'pending-group')`, brokerARN, brokerARN)
		exec(`INSERT INTO mq_configurations VALUES(?,?,?,?,?,?,'retained description',?,?,'simple','2031-01-01T00:00:00Z')`,
			fixture.partition, fixture.account, fixture.region, id, configARN, id, fixture.engine, fixture.version)
		exec(`INSERT INTO mq_configuration_tags VALUES(?,'owner','configuration')`, configARN)
		exec(`INSERT INTO mq_configuration_revisions VALUES(?,1,'effective','<broker name="effective"/>','2031-01-01T00:00:00Z'),(?,2,'pending','<broker name="pending"/>','2031-01-02T00:00:00Z')`, configARN, configARN)
		exec(`INSERT INTO mq_broker_configurations VALUES(?,'current',0,?,1,'<broker name="effective"/>'),(?,'pending',0,?,2,'<broker name="pending"/>'),(?,'history',0,?,1,'<broker name="historical"/>'),(?,'history',1,?,1,'<broker name="historical"/>')`, brokerARN, id, brokerARN, id, brokerARN, id, brokerARN, id)
	}
	tables := []string{"mq_brokers", "mq_broker_tags", "mq_broker_users", "mq_broker_user_groups", "mq_configurations", "mq_configuration_tags", "mq_configuration_revisions", "mq_broker_configurations"}
	readRows := func(table string, upgradeExpected bool) []map[string]any {
		t.Helper()
		rows, err := db.QueryContext(t.Context(), "SELECT * FROM "+table+" ORDER BY rowid")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var out []map[string]any
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			row := make(map[string]any, len(columns))
			for i, column := range columns {
				row[column] = values[i]
			}
			if upgradeExpected && row["engine"] == "ACTIVEMQ" && row["engine_version"] == "5.18.7" {
				row["engine_version"] = "5.18"
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := make(map[string][]map[string]any, len(tables))
	for _, table := range tables {
		want[table] = readRows(table, true)
	}
	for reopen := range 2 {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range tables {
			if got := readRows(table, false); !reflect.DeepEqual(got, want[table]) {
				t.Fatalf("reopen %d changed retained MQ state in %s: got %#v, want %#v", reopen, table, got, want[table])
			}
		}
		var currentVersion int
		if err := db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&currentVersion); err != nil {
			t.Fatal(err)
		}
		if currentVersion != len(files) {
			t.Fatalf("schema version = %d, want %d", currentVersion, len(files))
		}
		rows, err := db.QueryContext(t.Context(), "PRAGMA foreign_key_check")
		if err != nil {
			t.Fatal(err)
		}
		if rows.Next() {
			rows.Close()
			t.Fatal("upgraded MQ storage has broken foreign keys")
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
