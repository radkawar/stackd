package sqlite_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// The retained operation images are as important as current resources: resuming
// a deletion or rollback must address the same rule as a fresh stack read.
func TestCloudFormationRuleIdentityMigration(t *testing.T) {
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
	// Use the immutable historical schema rather than hand-built test tables.
	for _, file := range []string{"schema/223_cloudformation.sql"} {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		exec(string(body))
	}
	cases := []struct {
		label, bus, kind, physical, want string
	}{
		{"omitted", "", "AWS::Events::Rule", "rule", "rule"},
		{"default", "default", "AWS::Events::Rule", "rule", "rule"},
		{"default-arn", "arn:aws:events:us-east-1:123456789012:event-bus/default", "AWS::Events::Rule", "rule", "rule"},
		{"custom", "custom", "AWS::Events::Rule", "rule", "custom|rule"},
		{"custom-arn", "arn:aws:events:us-east-1:123456789012:event-bus/custom", "AWS::Events::Rule", "rule", "custom|rule"},
		{"partner", "arn:aws:events:us-east-1:123456789012:event-bus/aws.partner/vendor/source", "AWS::Events::Rule", "rule", "aws.partner/vendor/source|rule"},
		{"pending", "custom", "AWS::Events::Rule", "", ""},
		{"unrelated", "custom", "AWS::Events::EventBus", "bus", "bus"},
		{"qualified", "custom", "AWS::Events::Rule", "custom|rule", "custom|rule"},
	}
	const resourceColumns = "stack_id,logical_id,type,physical_id,ref,token,generation,current,status,status_reason,deletion_policy,update_replace_policy,properties,event_properties,attributes,updated"
	for _, tc := range cases {
		properties := map[string]string{}
		if tc.bus != "" {
			properties["EventBusName"] = tc.bus
		}
		body, err := json.Marshal(properties)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO cloudformation_resources (`+resourceColumns+`) VALUES ('stack',?,?,?,?, 'owner-token',7,1,'UPDATE_COMPLETE','','Retain','Delete',?,'{}','{"Arn":"retained-arn"}','2031-01-01T00:00:00Z')`, tc.label, tc.kind, tc.physical, tc.physical, string(body))
	}
	columns := strings.Split(resourceColumns, ",")
	var beforeColumns, afterColumns, beforeValues, afterValues []string
	for _, column := range columns {
		beforeColumns = append(beforeColumns, "before_"+column)
		afterColumns = append(afterColumns, "after_"+column)
		beforeValues = append(beforeValues, "b."+column)
		afterValues = append(afterValues, "a."+column)
	}
	exec(`INSERT INTO cloudformation_steps (parent_id,ordinal,position,logical_id,action,state,error,` + strings.Join(beforeColumns, ",") + "," + strings.Join(afterColumns, ",") + `) SELECT 'operation',0,0,'Rule','REPLACE','RUNNING','',` + strings.Join(beforeValues, ",") + "," + strings.Join(afterValues, ",") + ` FROM cloudformation_resources b CROSS JOIN cloudformation_resources a WHERE b.logical_id='custom-arn' AND a.logical_id='partner'`)
	migration, err := os.ReadFile("schema/303_cloudformation_rule_identity.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(migration))
	for _, tc := range cases {
		var physical, ref, token, ruleARN string
		var generation int
		if err := db.QueryRowContext(t.Context(), `SELECT physical_id,ref,token,generation,json_extract(attributes,'$.Arn') FROM cloudformation_resources WHERE logical_id=?`, tc.label).Scan(&physical, &ref, &token, &generation, &ruleARN); err != nil {
			t.Fatal(err)
		}
		if physical != tc.want || ref != tc.want || token != "owner-token" || generation != 7 || ruleARN != "retained-arn" {
			t.Fatalf("%s: changed resource identity or ownership incorrectly: %q %q %q %d %q", tc.label, physical, ref, token, generation, ruleARN)
		}
	}
	for prefix, want := range map[string]string{"before": "custom|rule", "after": "aws.partner/vendor/source|rule"} {
		var physical, ref, name, token string
		if err := db.QueryRowContext(t.Context(), `SELECT `+prefix+`_physical_id,`+prefix+`_ref,json_extract(`+prefix+`_attributes,'$.RuleName'),`+prefix+`_token FROM cloudformation_steps`).Scan(&physical, &ref, &name, &token); err != nil {
			t.Fatal(err)
		}
		if physical != want || ref != want || name != "rule" || token != "owner-token" {
			t.Fatalf("%s recovery image lost rule identity: %q %q %q %q", prefix, physical, ref, name, token)
		}
	}
}
