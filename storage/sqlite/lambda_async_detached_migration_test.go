package sqlite_test

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"stackd/internal/awstest"
	domain "stackd/storage/lambda"
	"stackd/storage/sqlite"
	lambdasqlite "stackd/storage/sqlite/lambda"
)

func TestLambdaAsyncDeletedTargetSettingsHistoricalUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "async-detached.sqlite")
	db := awstest.HistoricalSQLite(t, path, "schema", 312, "", nil)
	exec := func(query string, arguments ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query, arguments...); err != nil {
			t.Fatal(err)
		}
	}
	// Use historical columns, never today's adapter against an old schema.
	exec(`INSERT INTO lambda_functions
		(partition,account,region,name,pending,version,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason)
		VALUES('aws','111111111111','us-east-1','same',false,0,'python3.12','handler.handler','role','','x86_64','code',30,128,512,'revision','2026-10-01T00:00:00Z','Active','','','Successful','')`)
	exec(`INSERT INTO lambda_functions
		(partition,account,region,name,pending,version,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason)
		SELECT partition,account,region,'pending-only',true,0,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason FROM lambda_functions WHERE name='same'`)
	exec(`INSERT INTO lambda_functions
		(partition,account,region,name,pending,version,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason)
		SELECT partition,account,region,'version-only',false,1,runtime,handler,role,description,architecture,code_sha256,timeout,memory_mb,ephemeral_mb,revision,modified,state,state_reason,state_reason_code,update_status,update_reason FROM lambda_functions WHERE name='same'`)
	cases := []struct {
		id, partition, account, region, name, state string
		detached                                    bool
	}{
		{"absent", "aws", "111111111111", "us-east-1", "absent", "queued", true},
		{"existing", "aws", "111111111111", "us-east-1", "same", "queued", false},
		{"completed", "aws", "111111111111", "us-east-1", "absent", "completed", false},
		{"in-flight", "aws", "111111111111", "us-east-1", "absent", "in-flight", true},
		{"other-account", "aws", "222222222222", "us-east-1", "same", "queued", true},
		{"other-region", "aws", "111111111111", "us-west-2", "same", "queued", true},
		{"other-partition", "aws-cn", "111111111111", "us-east-1", "same", "queued", true},
		{"pending-only", "aws", "111111111111", "us-east-1", "pending-only", "queued", true},
		{"version-only", "aws", "111111111111", "us-east-1", "version-only", "queued", true},
	}
	accepted := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	payload := []byte(" {\"owned\":true,\"value\":17} ")
	for _, row := range cases {
		key := domain.FunctionKey{Scope: domain.Scope{Partition: row.partition, Account: row.account, Region: row.region}, Name: row.name}
		exec(`INSERT INTO lambda_invocations
			(id,partition,account,region,function_name,function_arn,payload,request_id,parent_event_id,accepted,due,version,state,invoke_count,system_errors,role_arn,max_age_seconds,max_retries,on_success_arn,on_failure_arn)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, row.id, row.partition, row.account, row.region, row.name,
			key.ARN(), payload, "request-"+row.id, "parent", accepted, accepted.Add(time.Minute), 7, row.state, 1, 3, "old-role", 180, 1, "old-success", "old-failure")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := lambdasqlite.New(db)
	if err := repository.View(t.Context(), func(reader domain.Reader) error {
		for _, row := range cases {
			invocation, err := reader.Invocation(row.id)
			if err != nil {
				return err
			}
			if invocation.SettingsDetached != row.detached {
				t.Fatalf("%s detached=%v, want %v", row.id, invocation.SettingsDetached, row.detached)
			}
			if invocation.RequestID != "request-"+row.id || !bytes.Equal(invocation.Payload, payload) || invocation.State != row.state ||
				!invocation.Accepted.Equal(accepted) || !invocation.Due.Equal(accepted.Add(time.Minute)) || invocation.Version != 7 ||
				invocation.InvokeCount != 1 || invocation.SystemErrors != 3 || invocation.RoleARN != "old-role" ||
				invocation.Settings != (domain.EventInvokeSettings{MaxAgeSeconds: 180, MaxRetries: 1, OnSuccessARN: "old-success", OnFailureARN: "old-failure"}) {
				t.Fatalf("upgrade changed accepted work for %s: %+v", row.id, invocation)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A later same-name creation must not erase the historical detachment before
	// the service's explicit replacement configuration application transition.
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
		root, err := tx.Function(domain.FunctionKey{Scope: domain.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "same"})
		if err != nil {
			return err
		}
		root.Key.Name = "absent"
		return tx.PutFunction(root)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(reader domain.Reader) error {
		invocation, err := reader.Invocation("absent")
		if err == nil && (!invocation.SettingsDetached || invocation.Settings.OnSuccessARN != "old-success") {
			t.Fatalf("same-name recreation erased upgraded controls: %+v", invocation)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
