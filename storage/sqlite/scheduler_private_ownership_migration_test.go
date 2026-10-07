package sqlite_test

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSchedulerPrivateOwnershipMigrationLeavesExistingRowsUnclaimed(t *testing.T) {
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
	original, err := os.ReadFile("schema/216_scheduler.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(original))
	type scope struct{ partition, account, region string }
	scopes := []scope{{"aws", "123456789012", "us-east-1"}, {"aws", "123456789012", "us-west-2"}, {"aws", "999999999999", "us-east-1"}, {"aws-cn", "123456789012", "cn-north-1"}}
	for _, s := range scopes {
		group := "arn:" + s.partition + ":scheduler:" + s.region + ":" + s.account + ":schedule-group/shared"
		schedule := "arn:" + s.partition + ":scheduler:" + s.region + ":" + s.account + ":schedule/shared/child"
		exec(`INSERT INTO scheduler_groups(partition,account,region,name,arn,created,modified,client_token) VALUES(?,?,?,'shared',?,1,1,'copied-public-token')`, s.partition, s.account, s.region, group)
		exec(`INSERT INTO scheduler_group_tags(group_arn,key,value) VALUES(?,'stackd:cloudformation:owner','copied-public-owner')`, group)
		exec(`INSERT INTO scheduler_schedules(partition,account,region,group_name,name,arn,created,modified,expression,timezone,state,description,has_description,action_after_completion,window_mode,window_minutes,has_window_minutes,kms_key_arn,ciphertext,data_key,revision,create_token,update_token,create_hash,update_hash) VALUES(?,?,?,'shared','child',?,1,1,'rate(1 day)','UTC','DISABLED','',0,'NONE','OFF',0,0,'',x'',x'',1,'copied-public-token','','original-hash','')`, s.partition, s.account, s.region, schedule)
	}
	migration, err := os.ReadFile("schema/394_scheduler_cloudformation_ownership.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(migration))
	ids := map[string]bool{}
	for _, s := range scopes {
		var id, owner, parent, childOwner, token, tag string
		if err := db.QueryRowContext(t.Context(), `SELECT g.id,g.cfn_owner,s.parent_id,s.cfn_owner,s.create_token,t.value FROM scheduler_groups g JOIN scheduler_schedules s ON s.partition=g.partition AND s.account=g.account AND s.region=g.region AND s.group_name=g.name JOIN scheduler_group_tags t ON t.group_arn=g.arn WHERE g.partition=? AND g.account=? AND g.region=?`, s.partition, s.account, s.region).Scan(&id, &owner, &parent, &childOwner, &token, &tag); err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 || ids[id] || parent != id || owner != "" || childOwner != "" || token != "copied-public-token" || tag != "copied-public-owner" {
			t.Fatalf("migration adopted public metadata, shared identities, lost parent fence, or rewrote native state: id=%q owner=%q parent=%q child=%q token=%q tag=%q", id, owner, parent, childOwner, token, tag)
		}
		ids[id] = true
	}
}
