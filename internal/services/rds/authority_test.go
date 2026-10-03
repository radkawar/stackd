package rds

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

type capturedAudit struct {
	calls []journal.APICallCompleted
}

func (r *capturedAudit) Record(_ context.Context, _ journal.Envelope, call journal.APICallCompleted) error {
	r.calls = append(r.calls, call)
	return nil
}

func TestRejectedCredentialRequestDoesNotExposePasswordInAudit(t *testing.T) {
	recorder := &capturedAudit{}
	s := New(Config{Recorder: recorder})
	t.Cleanup(func() {
		_ = s.Close()
	})
	model, _ := awscatalog.LookupService("rds")
	op, _ := model.Operation("CreateDBInstance")
	secret := "master-secret-DO-NOT-RECORD"
	in := &api.CreateDBInstanceMessage{DBInstanceIdentifier: new(api.String("owned")), Engine: new(api.String("postgres")), DBInstanceClass: new(api.String("db.t3.micro")), MasterUsername: new(api.String("owner")), MasterUserPassword: new(api.SensitiveString(secret))}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"})
	if e := s.RecordRequestError(ctx, awsapi.DecodedRequest{Operation: op, Input: in}, failure("InvalidParameterCombination", "Unsupported configuration.")); e != nil {
		t.Fatal(e)
	}
	if len(recorder.calls) != 1 {
		t.Fatalf("expected one rejected command event, got %d", len(recorder.calls))
	}
	body, e := json.Marshal(recorder.calls[0])
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(body), secret) {
		t.Fatal("master password escaped into rejected-request audit")
	}
	if !strings.Contains(string(body), "owned") {
		t.Fatal("credential redaction discarded nonsensitive resource identity")
	}
}

type denyEveryAction struct{}

func (denyEveryAction) Authorize(context.Context, authorization.Request) *awswire.Error {
	return failure("AccessDenied", "Denied")
}

func TestDataResolverDoesNotBorrowDescribeAuthorityOrCrossScope(t *testing.T) {
	s := New(Config{Authorizer: denyEveryAction{}})
	t.Cleanup(func() {
		_ = s.Close()
	})
	v := retainedDatabase(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	v.Key.Kind = "cluster"
	v.Engine = "aurora-postgresql"
	v.Tags = map[string]string{"environment": "test"}
	v.HTTPEnabled = true
	seedDatabase(t, s, v)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region})
	out, e := s.ResolveDataCluster(ctx, v.Key.ARN())
	if e != nil {
		t.Fatal(e)
	}
	if out.ARN != v.Key.ARN() || out.Tags["environment"] != "test" || out.Endpoint.Address != "" || out.Status != "creating" {
		t.Fatalf("resolver lost cluster scope/tags or fabricated native readiness: %#v", out)
	}
	for _, metadata := range []awsctx.Metadata{{Partition: "aws-cn", AccountID: v.Key.AccountID, Region: v.Key.Region}, {Partition: v.Key.Partition, AccountID: "222222222222", Region: v.Key.Region}, {Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: "us-west-2"}} {
		if _, e = s.ResolveDataCluster(awsctx.WithMetadata(t.Context(), metadata), v.Key.ARN()); e == nil {
			t.Fatalf("cluster ARN crossed scope: %#v", metadata)
		}
	}
}
