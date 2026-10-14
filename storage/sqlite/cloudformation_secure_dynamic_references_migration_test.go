package sqlite_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
	"stackd/internal/services/cloudformation"
)

func TestCloudFormationSecureDynamicReferencePinMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"schema/223_cloudformation.sql", "schema/405_cloudformation_dynamic_references.sql", "schema/407_cloudformation_replacement_progress.sql"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		exec(string(body))
	}
	const columns = "stack_id,logical_id,type,physical_id,ref,token,generation,current,status,status_reason,deletion_policy,update_replace_policy,properties,event_properties,attributes,updated,dynamic_references"
	const numeric = `{"{{resolve:ssm:/first}}":1,"{{resolve:ssm:/second:7}}":7}`
	exec(`INSERT INTO cloudformation_resources (`+columns+`) VALUES ('stack','User','AWS::IAM::User','user','user','owner',1,1,'CREATE_COMPLETE','','Delete','Delete','{}','{}','{}','2031-01-01T00:00:00Z',?)`, numeric)
	var before, after, values []string
	for _, column := range strings.Split(columns, ",") {
		before = append(before, "before_"+column)
		after = append(after, "after_"+column)
		values = append(values, column)
	}
	exec(`INSERT INTO cloudformation_steps (parent_id,ordinal,position,logical_id,action,state,error,` + strings.Join(before, ",") + "," + strings.Join(after, ",") + `,restore_dynamic_references) SELECT 'operation',0,0,'User','UPDATE','RUNNING','',` + strings.Join(values, ",") + "," + strings.Join(values, ",") + `,dynamic_references FROM cloudformation_resources`)
	migration, err := os.ReadFile("schema/410_cloudformation_secure_dynamic_references.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(migration))
	for _, location := range []struct{ table, column string }{
		{"cloudformation_resources", "dynamic_references"},
		{"cloudformation_steps", "before_dynamic_references"},
		{"cloudformation_steps", "after_dynamic_references"},
		{"cloudformation_steps", "restore_dynamic_references"},
	} {
		var document string
		if err := db.QueryRowContext(t.Context(), "SELECT "+location.column+" FROM "+location.table).Scan(&document); err != nil {
			t.Fatal(err)
		}
		var pins map[string]cloudformation.DynamicReferencePin
		if err := json.Unmarshal([]byte(document), &pins); err != nil {
			t.Fatal(err)
		}
		if pins["{{resolve:ssm:/first}}"] != (cloudformation.DynamicReferencePin{Service: "ssm", ParameterVersion: 1}) || pins["{{resolve:ssm:/second:7}}"] != (cloudformation.DynamicReferencePin{Service: "ssm", ParameterVersion: 7}) {
			t.Fatalf("%s.%s lost numeric selectors: %#v", location.table, location.column, pins)
		}
	}
}
