package sqlite_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite"
	lambdasqlite "stackd/storage/sqlite/lambda"
)

func TestSourceMappingIdentityUpgradeRetainsCheckpointsAndPlacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.sqlite")
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
		if strings.HasSuffix(file, "_lambda_source_mapping_identity.sql") {
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
		t.Fatal("source identity migration not found")
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
	mapping := func(id, source string) {
		t.Helper()
		exec(`INSERT INTO lambda_event_source_mappings
			(partition,account,region,uuid,function_partition,function_account,function_region,function_name,function_qualifier,event_source_arn,version,state,state_transition_reason,last_modified,transition_at,batch_size,batching_window_seconds,report_batch_item_failures)
			VALUES('aws','111111111111','us-east-1',?,'aws','111111111111','us-east-1','consumer','1',?,7,'Enabled','USER_INITIATED','2031-01-01T00:00:00Z','2031-01-01T00:00:00Z',100,1,false)`, id, source)
	}
	for _, source := range []string{"sqs", "encrypted", "kafka", "docdb", "mq", "stream"} {
		mapping(source, "arn:aws:"+source+":us-east-1:111111111111:source")
	}
	exec(`INSERT INTO lambda_event_source_mapping_filters VALUES('aws','111111111111','us-east-1','sqs',0,'{"body":{"accepted":[true]}}')`)
	exec(`INSERT INTO lambda_event_source_mapping_metrics VALUES('aws','111111111111','us-east-1','sqs',0,'EventCount')`)
	exec(`INSERT INTO lambda_event_source_mapping_tags VALUES('aws','111111111111','us-east-1','sqs','owner','retained')`)
	exec(`INSERT INTO lambda_event_source_filter_encryption VALUES('aws','111111111111','us-east-1','encrypted','key','function',X'010203',X'040506')`)
	exec(`INSERT INTO lambda_kafka_mappings VALUES('aws','111111111111','us-east-1','kafka','first','consumer-group','LATEST','2031-01-01T00:00:00Z',500000000,'SASL_SCRAM_512_AUTH','credential','cluster-incarnation','topic-incarnation','root-ca','role')`)
	exec(`INSERT INTO lambda_kafka_bootstrap_servers VALUES('aws','111111111111','us-east-1','kafka',0,'broker:9093')`)
	exec(`INSERT INTO lambda_kafka_network_components VALUES('aws','111111111111','us-east-1','kafka','subnet','subnet-retained')`)
	exec(`INSERT INTO lambda_kafka_network_components VALUES('aws','111111111111','us-east-1','kafka','security_group','sg-retained')`)
	exec(`INSERT INTO lambda_documentdb_mappings VALUES('aws','111111111111','us-east-1','docdb','database','first','UpdateLookup','credential','TRIM_HORIZON','2031-01-01T00:00:00Z',500000000,'native-incarnation')`)
	exec(`INSERT INTO lambda_documentdb_checkpoints VALUES('aws','111111111111','us-east-1','docdb','native-incarnation',X'102030',99,7)`)
	exec(`INSERT INTO lambda_mq_mappings VALUES('aws','111111111111','us-east-1','mq','first','/tenant','credential','broker-incarnation','RABBITMQ',500000000)`)
	mapping("mq-root", "arn:aws:mq:us-east-1:111111111111:root-source")
	exec(`INSERT INTO lambda_mq_mappings VALUES('aws','111111111111','us-east-1','mq-root','root-queue','/','credential','broker-incarnation','RABBITMQ',500000000)`)
	exec(`UPDATE lambda_event_source_mappings SET transition_state='Enabled',last_processing_result='OK',stream_starting_position='TRIM_HORIZON',stream_parallelization_factor=2,stream_maximum_retry_attempts=3,stream_maximum_record_age_seconds=60,stream_bisect_batch_on_function_error=true,stream_tumbling_window_seconds=30,stream_on_failure='destination',stream_starting_position_timestamp='2031-01-01T00:00:00Z' WHERE uuid='stream'`)
	tables := []string{"lambda_event_source_mappings", "lambda_event_source_mapping_filters", "lambda_event_source_mapping_metrics", "lambda_event_source_mapping_tags", "lambda_event_source_filter_encryption", "lambda_kafka_mappings", "lambda_kafka_bootstrap_servers", "lambda_kafka_network_components", "lambda_documentdb_mappings", "lambda_documentdb_checkpoints", "lambda_mq_mappings"}
	// Compare retained data, not table shape: later migrations may add state.
	retainedColumns := make(map[string]string, len(tables))
	readRows := func(table string) [][]any {
		t.Helper()
		projection := retainedColumns[table]
		if projection == "" {
			projection = "*"
		}
		rows, err := db.QueryContext(t.Context(), "SELECT "+projection+" FROM "+table+" ORDER BY partition,account,region,uuid")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		retainedColumns[table] = strings.Join(columns, ",")
		var out [][]any
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			out = append(out, values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := make(map[string][][]any, len(tables))
	for _, table := range tables {
		before[table] = readRows(table)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		if got := readRows(table); !reflect.DeepEqual(got, before[table]) {
			t.Fatalf("upgrade changed retained source state in %s: got %#v, want %#v", table, got, before[table])
		}
	}
	for _, row := range []struct {
		id, host string
		explicit bool
	}{
		{"mq", "/tenant", true},
		{"mq-root", "/", false},
	} {
		var host string
		var explicit bool
		if err := db.QueryRowContext(t.Context(), `SELECT virtual_host,virtual_host_set FROM lambda_mq_mappings WHERE uuid=?`, row.id).Scan(&host, &explicit); err != nil {
			t.Fatal(err)
		}
		if host != row.host || explicit != row.explicit {
			t.Fatalf("migration changed source host identity for %s: host=%q explicit=%v", row.id, host, explicit)
		}
	}
	// Distinct native watch/queue/topic identities can share a source ARN and
	// function. The service's transaction owns duplicate identity admission.
	for _, source := range []string{"docdb", "mq", "kafka"} {
		mapping(source+"-second", "arn:aws:"+source+":us-east-1:111111111111:source")
	}
	exec(`INSERT INTO lambda_documentdb_mappings SELECT partition,account,region,'docdb-second',database_name,'second',full_document,secret_arn,starting_position,starting_position_timestamp,batching_window_ns,incarnation FROM lambda_documentdb_mappings WHERE uuid='docdb'`)
	exec(`INSERT INTO lambda_mq_mappings SELECT partition,account,region,'mq-second','second',virtual_host,secret_arn,broker_id,engine,batching_window_ns,virtual_host_set FROM lambda_mq_mappings WHERE uuid='mq'`)
	exec(`INSERT INTO lambda_kafka_mappings SELECT partition,account,region,'kafka-second','second','second-group',starting_position,starting_position_timestamp,batching_window_ns,authentication,secret_arn,cluster_id,'second-topic-incarnation',root_ca_secret_arn,network_role_arn FROM lambda_kafka_mappings WHERE uuid='kafka'`)
	// Deletion must still retire nested source placement and checkpoint data.
	exec("DELETE FROM lambda_event_source_mappings")
	for _, table := range tables[1:] {
		if got := readRows(table); len(got) != 0 {
			t.Fatalf("source deletion retained %s rows: %#v", table, got)
		}
	}
	rows, err := db.QueryContext(t.Context(), "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("upgraded source storage has broken foreign keys")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestFilterEnvelopeFormatUpgradeAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-envelope.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
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
		if strings.HasSuffix(file, "_lambda_filter_envelope_format.sql") {
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
	if version != 305 {
		t.Fatalf("filter envelope migration must upgrade schema 305, got %d", version)
	}
	if _, err := tx.ExecContext(t.Context(), "PRAGMA user_version=305"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(t.Context(), `INSERT INTO lambda_event_source_mappings
		(partition,account,region,uuid,function_partition,function_account,function_region,function_name,function_qualifier,event_source_arn,version,state,state_transition_reason,last_modified,transition_at,batch_size,batching_window_seconds,report_batch_item_failures)
		VALUES('aws','111111111111','us-east-1','legacy','aws','111111111111','us-east-1','consumer','1','arn:aws:sqs:us-east-1:111111111111:source',?,'Enabled','USER_INITIATED','2031-01-01T00:00:00Z','2031-01-01T00:00:00Z',100,1,false)`, sqlite.Uint64(7)); err != nil {
		t.Fatal(err)
	}
	keyARN := "arn:aws:kms:us-east-1:111111111111:key/retained"
	legacy := &domain.EncryptedMappingFilters{
		Content: []byte{0, 1, 2, 255}, DataKey: []byte{255, 3, 4, 0},
		FunctionARN: "arn:aws:lambda:us-east-1:111111111111:function:consumer:1",
	}
	if _, err := tx.ExecContext(t.Context(), `INSERT INTO lambda_event_source_filter_encryption
		(partition,account,region,uuid,key_arn,function_arn,content,data_key)
		VALUES('aws','111111111111','us-east-1','legacy',?,?,?,?)`,
		keyARN, legacy.FunctionARN, legacy.Content, legacy.DataKey); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	repo := lambdasqlite.New(db)
	var retained domain.EventSourceMappingRecord
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		var err error
		retained, err = r.EventSourceMapping(domain.EventSourceMappingKey{Scope: scope, UUID: "legacy"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if retained.Settings.KMSKeyARN != keyARN || !reflect.DeepEqual(retained.Settings.EncryptedFilters, legacy) {
		t.Fatalf("upgrade changed legacy key, context, or ciphertext: %+v", retained.Settings)
	}
	expected := map[string]*domain.EncryptedMappingFilters{"legacy": legacy}
	for _, format := range []string{"aws-encryption-sdk-v2", "unknown-format-retained"} {
		fresh := retained
		fresh.Key.UUID = format
		fresh.Settings.EncryptedFilters = &domain.EncryptedMappingFilters{
			Format: format, FunctionARN: legacy.FunctionARN,
			Content: []byte{2, 5, 120, 0, 255}, DataKey: []byte{7, 8, 255, 0},
		}
		expected[format] = fresh.Settings.EncryptedFilters
		if err := repo.Update(t.Context(), func(w domain.Transaction) error {
			return w.PutEventSourceMapping(fresh)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = lambdasqlite.New(db)
	if err := repo.View(t.Context(), func(r domain.Reader) error {
		for id, want := range expected {
			got, err := r.EventSourceMapping(domain.EventSourceMappingKey{Scope: scope, UUID: id})
			if err != nil {
				return err
			}
			if got.Settings.KMSKeyARN != keyARN || !reflect.DeepEqual(got.Settings.EncryptedFilters, want) {
				t.Fatalf("reopen changed %s key, format, context, or ciphertext: %+v", id, got.Settings)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
