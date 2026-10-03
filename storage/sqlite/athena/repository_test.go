package athena_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
	"stackd/journal"
	domain "stackd/storage/athena"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/athena"
)

type retainedStore struct {
	path string
	db   *sql.DB
	repo *backend.Repository
}

func openStore(t *testing.T) *retainedStore {
	t.Helper()
	s := &retainedStore{path: filepath.Join(t.TempDir(), "athena.sqlite")}
	s.reopen(t)
	t.Cleanup(func() { _ = s.db.Close() })
	return s
}
func (s *retainedStore) reopen(t *testing.T) {
	t.Helper()
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sqlite.Open(t.Context(), s.path)
	if err != nil {
		t.Fatal(err)
	}
	s.db = db
	s.repo = backend.New(db)
}
func scope() domain.Scope {
	return domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
}
func key(name string) domain.ResourceKey { return domain.ResourceKey{Scope: scope(), Name: name} }

func retainedQuery() domain.QueryRecord {
	at := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	return domain.QueryRecord{
		Key: key("query-a"), Token: "same-client-token", Fingerprint: "accepted-statement-fingerprint", ParentEventID: "accepted-api-event", Version: 7,
		Due: at.Add(time.Minute), Started: &at, EngineID: "owned-engine-handle", UpdateCount: 2, PublishMetrics: true, RequesterPays: true, BytesCutoff: 10485760,
		Caller: awsctx.Metadata{
			AccountID: "111111111111", Region: "us-east-1", Partition: "aws", AccessKeyID: "ASIAEXAMPLEPUBLIC", RequestID: "request-a", ParentEventID: "caller-parent", TraceHeader: "Root=1-00000000-000000000000000000000000",
			PrincipalARN: "arn:aws:sts::111111111111:assumed-role/analyst/session", PrincipalID: "role:session", UserName: "analyst", SessionType: "AssumedRole", IssuerARN: "arn:aws:iam::111111111111:role/analyst", IssuerID: "role-id",
			SessionPolicies:   []string{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}`},
			SessionPolicyARNs: []string{"arn:aws:iam::111111111111:policy/query-read"}, HasSessionPolicy: true,
			SessionContext: map[string][]string{"claim": {"analyst", "research"}, "empty": {}, "nil": nil}, FederatedProvider: "oidc.example", SessionTags: map[string]string{"team": "research", "empty": ""}, TransitiveTagKeys: []string{"team"}, SourceIdentity: "human",
			MFAPresent: true, MFAAuthenticatedAt: at.Add(-time.Minute), TokenIssueTime: at.Add(-time.Hour), CalledVia: []string{"athena.amazonaws.com", "s3.amazonaws.com"}, TransportKnown: true, SourceIP: "192.0.2.1", SecureTransport: true, UserAgent: "owned-client", SignatureVersion: "SigV4", AuthenticationMethod: "AuthHeader",
			ServicePrincipal: awsctx.ServicePrincipal{Name: "athena.amazonaws.com", SourceARN: "arn:aws:athena:us-east-1:111111111111:workgroup/research", Type: "AWSService", Aliases: []string{"athena.us-east-1.amazonaws.com"}}, InvokedBy: "athena.amazonaws.com", InScopeOf: journal.APIIdentityScope{IssuerType: "AWS::EC2::Instance", CredentialsIssuedTo: "arn:aws:ec2:us-east-1:111111111111:instance/i-owned"},
		},
		Data: api.QueryExecution{
			Query: new(api.QueryString("SELECT ? AS value")), QueryExecutionId: new(api.QueryExecutionId("query-a")), WorkGroup: new(api.WorkGroupName("research")), ExecutionParameters: api.ExecutionParameters{"'quoted value'", "NULL", ""},
			EngineVersion:                           &api.EngineVersion{EffectiveEngineVersion: new(api.NameString("Athena engine version 3")), SelectedEngineVersion: new(api.NameString("AUTO"))},
			ManagedQueryResultsConfiguration:        &api.ManagedQueryResultsConfiguration{Enabled: new(api.Boolean(false)), EncryptionConfiguration: &api.ManagedQueryResultsEncryptionConfiguration{KmsKey: new(api.KmsKey("managed-kms"))}},
			QueryExecutionContext:                   &api.QueryExecutionContext{Catalog: new(api.CatalogNameString("AwsDataCatalog")), Database: new(api.DatabaseString("research"))},
			QueryResultsS3AccessGrantsConfiguration: &api.QueryResultsS3AccessGrantsConfiguration{AuthenticationType: new(api.AuthenticationType("DIRECTORY_IDENTITY")), CreateUserLevelPrefix: new(api.BoxedBoolean(false)), EnableS3AccessGrants: new(api.BoxedBoolean(true))},
			ResultConfiguration:                     &api.ResultConfiguration{AclConfiguration: &api.AclConfiguration{S3AclOption: new(api.S3AclOption("BUCKET_OWNER_FULL_CONTROL"))}, EncryptionConfiguration: &api.EncryptionConfiguration{EncryptionOption: new(api.EncryptionOption("SSE_KMS")), KmsKey: new(api.String("query-kms"))}, ExpectedBucketOwner: new(api.AwsAccountId("111111111111")), OutputLocation: new(api.ResultOutputLocation("s3://results/query-a.csv"))},
			ResultReuseConfiguration:                &api.ResultReuseConfiguration{ResultReuseByAgeConfiguration: &api.ResultReuseByAgeConfiguration{Enabled: new(api.Boolean(false)), MaxAgeInMinutes: new(api.Age(0))}},
			StatementType:                           new(api.StatementType("DML")), SubstatementType: new(api.String("SELECT")),
			Statistics: &api.QueryExecutionStatistics{DataManifestLocation: new(api.String("s3://results/manifest.csv")), DataScannedInBytes: new(api.Long(8192)), DpuCount: new(api.DpuCount(2.5)), EngineExecutionTimeInMillis: new(api.Long(31)), QueryPlanningTimeInMillis: new(api.Long(7)), QueryQueueTimeInMillis: new(api.Long(2)), ResultReuseInformation: &api.ResultReuseInformation{ReusedPreviousResult: new(api.Boolean(false))}, ServicePreProcessingTimeInMillis: new(api.Long(3)), ServiceProcessingTimeInMillis: new(api.Long(5)), TotalExecutionTimeInMillis: new(api.Long(41))},
			Status:     &api.QueryExecutionStatus{State: new(api.QueryExecutionState("FAILED")), SubmissionDateTime: &at, CompletionDateTime: new(at.Add(time.Second)), StateChangeReason: new(api.String("engine interrupted")), AthenaError: &api.AthenaError{ErrorCategory: new(api.ErrorCategory(1)), ErrorType: new(api.ErrorType(100)), ErrorMessage: new(api.String("owned engine unavailable")), Retryable: new(api.Boolean(false))}},
		},
		Columns: api.ColumnInfoList{{CaseSensitive: new(api.Boolean(false)), CatalogName: new(api.String("AwsDataCatalog")), Label: new(api.String("value")), Name: new(api.String("value")), Nullable: new(api.ColumnNullable("UNKNOWN")), Precision: new(api.Integer(38)), Scale: new(api.Integer(0)), SchemaName: new(api.String("research")), TableName: new(api.String("events")), Type: new(api.String("decimal"))}, {Name: new(api.String("empty_label")), Label: new(api.String("")), Type: new(api.String("varchar"))}},
	}
}

func TestQueryRestartPreservesCallerAuthorityResultsMetadataAndScope(t *testing.T) {
	s := openStore(t)
	original := retainedQuery()
	scopes := []domain.Scope{scope(), {Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"}, {Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2"}}
	for i, sc := range scopes {
		want := original
		want.Key.Scope = sc
		want.Version = int64(i + 1)
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutQuery(want) }); err != nil {
			t.Fatal(err)
		}
	}
	s.reopen(t)
	for i, sc := range scopes {
		want := original
		want.Key.Scope = sc
		want.Version = int64(i + 1)
		if err := s.repo.View(t.Context(), func(r domain.Reader) error {
			got, err := r.QueryByToken(sc, original.Token)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("query or authenticated caller changed across restart in %+v:\ngot %#v\nwant %#v", sc, got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Replacing collections must remove old child rows while retaining empty vs nil.
	changed := original
	changed.Version = 9
	changed.Data.ExecutionParameters = api.ExecutionParameters{}
	changed.Columns = nil
	changed.Caller.SessionPolicies = nil
	changed.Caller.SessionPolicyARNs = []string{}
	changed.Caller.SessionTags = map[string]string{}
	changed.Caller.SessionContext = map[string][]string{"claim": {}, "empty": nil}
	changed.Caller.CalledVia = nil
	changed.Caller.ServicePrincipal.Aliases = []string{}
	changed.Data.ResultReuseConfiguration = &api.ResultReuseConfiguration{}
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutQuery(changed) }); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.Query(changed.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, changed) {
			t.Fatalf("replacement retained stale children or lost field presence:\ngot %#v\nwant %#v", got, changed)
		}
		_, err = r.QueryByToken(scope(), "")
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("empty token resolved an execution: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQueryRecoveryOrderingAndPaginationSurviveRestart(t *testing.T) {
	s := openStore(t)
	at := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	records := []domain.QueryRecord{
		{Key: key("queued-later"), Due: at.Add(time.Second), Data: api.QueryExecution{WorkGroup: new(api.WorkGroupName("one")), Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("QUEUED"))}}},
		{Key: key("queued-first"), Due: at, Data: api.QueryExecution{WorkGroup: new(api.WorkGroupName("one")), Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("QUEUED"))}}},
		{Key: key("running"), Due: at.Add(-time.Hour), EngineID: "running-handle", Data: api.QueryExecution{WorkGroup: new(api.WorkGroupName("two")), Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("RUNNING"))}}},
		{Key: key("cancelled-cleanup"), Due: at.Add(-time.Minute), EngineID: "cancel-handle", Data: api.QueryExecution{Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("CANCELLED"))}}},
		{Key: key("failed-cleanup"), Due: at.Add(-time.Minute), EngineID: "failure-handle", Data: api.QueryExecution{Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("FAILED"))}}},
		{Key: key("finished"), Due: at.Add(-time.Hour), Data: api.QueryExecution{Status: &api.QueryExecutionStatus{State: new(api.QueryExecutionState("SUCCEEDED"))}}},
	}
	// Identical IDs and due times in different accounts must have a stable tie break.
	other := records[1]
	other.Key.AccountID = "222222222222"
	records = append(records, other)
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		for _, v := range records {
			if err := tx.PutQuery(v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	for _, want := range []domain.ResourceKey{key("cancelled-cleanup"), key("failed-cleanup"), key("queued-first"), other.Key, key("queued-later")} {
		if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
			got, err := tx.NextQuery()
			if err != nil {
				return err
			}
			if got.Key != want {
				t.Fatalf("next retained work = %+v; want %+v", got.Key, want)
			}
			got.EngineID = ""
			got.Data.Status.State = new(api.QueryExecutionState("SUCCEEDED"))
			return tx.PutQuery(got)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		if _, err := r.NextQuery(); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("terminal or running query selected as due: %v", err)
		}
		active, err := r.ActiveQueries()
		if err != nil {
			return err
		}
		if len(active) != 1 || active[0].Key != key("running") {
			t.Fatalf("recovery included settled work: %#v", active)
		}
		first, err := r.Queries(domain.ResourceQuery{Scope: scope(), WorkGroup: "one", Limit: 1})
		if err != nil {
			return err
		}
		if len(first) != 1 || first[0].Key != key("queued-first") {
			t.Fatalf("first scoped workgroup page: %#v", first)
		}
		next, err := r.Queries(domain.ResourceQuery{Scope: scope(), WorkGroup: "one", After: first[0].Key.Name, Limit: 1})
		if err != nil {
			return err
		}
		if len(next) != 1 || next[0].Key != key("queued-later") {
			t.Fatalf("continuation crossed scope or repeated an ID: %#v", next)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
