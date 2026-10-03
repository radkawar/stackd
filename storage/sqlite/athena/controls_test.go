package athena_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/athena"
	domain "stackd/storage/athena"
)

func retainedWorkGroup() domain.WorkGroupRecord {
	at := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	return domain.WorkGroupRecord{Key: key("research"), Tags: map[string]string{"owner": "analyst", "empty": ""}, Data: api.WorkGroup{
		Name: new(api.WorkGroupName("research")), State: new(api.WorkGroupState("ENABLED")), CreationTime: &at, Description: new(api.WorkGroupDescriptionString("")), IdentityCenterApplicationArn: new(api.IdentityCenterApplicationArn("arn:aws:sso::111111111111:application/owned")),
		Configuration: &api.WorkGroupConfiguration{
			AdditionalConfiguration: new(api.NameString("{\"spark.executor.memory\":\"1g\"}")), BytesScannedCutoffPerQuery: new(api.BytesScannedCutoffValue(10485760)), CustomerContentEncryptionConfiguration: &api.CustomerContentEncryptionConfiguration{KmsKey: new(api.KmsKey("customer-key"))}, EnableMinimumEncryptionConfiguration: new(api.BoxedBoolean(false)), EnforceWorkGroupConfiguration: new(api.BoxedBoolean(true)),
			EngineConfiguration: &api.EngineConfiguration{AdditionalConfigs: api.ParametersMap{"driver": "small", "empty": ""}, Classifications: api.ClassificationList{{Name: new(api.NameString("spark-defaults")), Properties: api.ParametersMap{"spark.executor.cores": "2"}}, {Name: new(api.NameString("empty")), Properties: api.ParametersMap{}}, {Name: new(api.NameString("unset"))}}, CoordinatorDpuSize: new(api.CoordinatorDpuSize(1)), DefaultExecutorDpuSize: new(api.DefaultExecutorDpuSize(2)), MaxConcurrentDpus: new(api.MaxConcurrentDpus(4)), SparkProperties: api.ParametersMap{}},
			EngineVersion:       &api.EngineVersion{EffectiveEngineVersion: new(api.NameString("Athena engine version 3")), SelectedEngineVersion: new(api.NameString("AUTO"))}, ExecutionRole: new(api.RoleArn("arn:aws:iam::111111111111:role/analyst")), IdentityCenterConfiguration: &api.IdentityCenterConfiguration{EnableIdentityCenter: new(api.BoxedBoolean(false)), IdentityCenterInstanceArn: new(api.IdentityCenterInstanceArn("arn:aws:sso:::instance/owned"))},
			ManagedQueryResultsConfiguration: &api.ManagedQueryResultsConfiguration{Enabled: new(api.Boolean(false)), EncryptionConfiguration: &api.ManagedQueryResultsEncryptionConfiguration{}},
			MonitoringConfiguration: &api.MonitoringConfiguration{
				CloudWatchLoggingConfiguration: &api.CloudWatchLoggingConfiguration{Enabled: new(api.BoxedBoolean(true)), LogGroup: new(api.LogGroupName("/athena/research")), LogStreamNamePrefix: new(api.LogStreamNamePrefix("query/")), LogTypes: api.LogTypesMap{"DRIVER": {"STDOUT", "STDERR"}, "EXECUTOR": {}, "UNSET": nil}},
				ManagedLoggingConfiguration:    &api.ManagedLoggingConfiguration{Enabled: new(api.BoxedBoolean(false)), KmsKey: new(api.KmsKey("logs-key"))}, S3LoggingConfiguration: &api.S3LoggingConfiguration{Enabled: new(api.BoxedBoolean(true)), KmsKey: new(api.KmsKey("s3-logs-key")), LogLocation: new(api.S3OutputLocation("s3://logs/research/"))},
			},
			PublishCloudWatchMetricsEnabled: new(api.BoxedBoolean(false)), QueryResultsS3AccessGrantsConfiguration: &api.QueryResultsS3AccessGrantsConfiguration{AuthenticationType: new(api.AuthenticationType("DIRECTORY_IDENTITY")), CreateUserLevelPrefix: new(api.BoxedBoolean(false)), EnableS3AccessGrants: new(api.BoxedBoolean(false))}, RequesterPaysEnabled: new(api.BoxedBoolean(true)),
			ResultConfiguration: &api.ResultConfiguration{OutputLocation: new(api.ResultOutputLocation("s3://results/research/")), ExpectedBucketOwner: new(api.AwsAccountId("111111111111")), AclConfiguration: &api.AclConfiguration{}, EncryptionConfiguration: &api.EncryptionConfiguration{EncryptionOption: new(api.EncryptionOption("SSE_KMS")), KmsKey: new(api.String("results-key"))}},
		},
	}}
}

func TestControlRestartRetainsNestedConfigurationAndDeletion(t *testing.T) {
	s := openStore(t)
	workgroup := retainedWorkGroup()
	catalog := domain.CatalogRecord{Key: key("catalog"), Tags: map[string]string{}, Data: api.DataCatalog{Name: new(api.CatalogNameString("catalog")), Description: new(api.DescriptionString("")), ConnectionType: new(api.ConnectionType("LAMBDA")), Error: new(api.ErrorMessage("")), Status: new(api.DataCatalogStatus("CREATE_COMPLETE")), Type: new(api.DataCatalogType("FEDERATED")), Parameters: api.ParametersMap{"connection-arn": "arn:aws:glue:us-east-1:111111111111:connection/owned", "empty": ""}}}
	named := domain.NamedQueryRecord{Key: key("named-id"), Token: "named-token", Fingerprint: "named-fingerprint", Data: api.NamedQuery{Database: new(api.DatabaseString("db")), Description: new(api.DescriptionString("")), Name: new(api.NameString("saved")), NamedQueryId: new(api.NamedQueryId("named-id")), QueryString: new(api.QueryString("SELECT 1")), WorkGroup: new(api.WorkGroupName("research"))}}
	prepared := domain.PreparedStatementRecord{Key: domain.StatementKey{WorkGroup: workgroup.Key, Name: "select"}, Data: api.PreparedStatement{Description: new(api.DescriptionString("")), LastModifiedTime: new(time.Date(2031, 1, 1, 0, 0, 0, 99, time.UTC)), QueryStatement: new(api.QueryString("SELECT ?")), StatementName: new(api.StatementName("select")), WorkGroupName: new(api.WorkGroupName("research"))}}
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutWorkGroup(workgroup); err != nil {
			return err
		}
		if err := tx.PutCatalog(catalog); err != nil {
			return err
		}
		if err := tx.PutNamedQuery(named); err != nil {
			return err
		}
		if err := tx.PutPreparedStatement(prepared); err != nil {
			return err
		}
		other := prepared
		other.Key.WorkGroup.Name = "another-group"
		other.Data.QueryStatement = new(api.QueryString("SELECT 'different'"))
		return tx.PutPreparedStatement(other)
	}); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		gotWG, err := r.WorkGroup(workgroup.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(gotWG, workgroup) {
			t.Fatalf("workgroup configuration changed after restart: %#v", gotWG)
		}
		gotCatalog, err := r.Catalog(catalog.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(gotCatalog, catalog) {
			t.Fatalf("catalog configuration changed after restart: %#v", gotCatalog)
		}
		gotNamed, err := r.NamedQueryByToken(scope(), named.Token)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(gotNamed, named) {
			t.Fatalf("saved query idempotency changed: %#v", gotNamed)
		}
		statements, err := r.PreparedStatements(domain.ResourceQuery{Scope: scope(), WorkGroup: "research"})
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(statements, []domain.PreparedStatementRecord{prepared}) {
			t.Fatalf("prepared statement crossed workgroup scope: %#v", statements)
		}
		alien := scope()
		alien.AccountID = "222222222222"
		if _, err := r.NamedQueryByToken(alien, named.Token); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("saved query token crossed account scope: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Replacing an optional parent must discard all classifications, maps and
	// nested log lists, not resurrect them when the resource is later re-read.
	workgroup.Data.Configuration = &api.WorkGroupConfiguration{}
	workgroup.Tags = nil
	catalog.Data.Parameters = api.ParametersMap{}
	catalog.Tags = nil
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutWorkGroup(workgroup); err != nil {
			return err
		}
		if err := tx.PutCatalog(catalog); err != nil {
			return err
		}
		if err := tx.DeleteNamedQuery(named.Key); err != nil {
			return err
		}
		return tx.DeletePreparedStatement(prepared.Key)
	}); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.WorkGroup(workgroup.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, workgroup) {
			t.Fatalf("removed nested configuration returned: %#v", got)
		}
		gotCatalog, err := r.Catalog(catalog.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(gotCatalog, catalog) {
			t.Fatalf("empty parameters or absent tags changed: %#v", gotCatalog)
		}
		if _, err := r.NamedQueryByToken(scope(), named.Token); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted token remains: %v", err)
		}
		if _, err := r.PreparedStatement(prepared.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted prepared statement remains: %v", err)
		}
		other := prepared.Key
		other.WorkGroup.Name = "another-group"
		_, err = r.PreparedStatement(other)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.DeleteWorkGroup(workgroup.Key); err != nil {
			return err
		}
		return tx.DeleteCatalog(catalog.Key)
	}); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		if _, err := r.WorkGroup(workgroup.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted workgroup remains: %v", err)
		}
		if _, err := r.Catalog(catalog.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted catalog remains: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecreatedWorkGroupDoesNotRecoverDeletedExecutionHistory(t *testing.T) {
	s := openStore(t)
	group := domain.WorkGroupRecord{Key: key("research")}
	removed := retainedQuery()
	removed.EngineID = ""
	removed.Data.Status.State = new(api.QueryExecutionState("SUCCEEDED"))
	survivors := []domain.QueryRecord{}
	for _, sc := range []domain.Scope{
		{Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"},
		{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"},
		{Partition: "aws", AccountID: "111111111111", Region: "us-west-2"},
	} {
		v := removed
		v.Key.Scope = sc
		survivors = append(survivors, v)
	}
	otherGroup := removed
	otherGroup.Key.Name = "other-query"
	otherGroup.Token = "other-group-token"
	otherGroup.Data.WorkGroup = new(api.WorkGroupName("another-group"))
	survivors = append(survivors, otherGroup)
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.PutWorkGroup(group); err != nil {
			return err
		}
		if err := tx.PutQuery(removed); err != nil {
			return err
		}
		for _, v := range survivors {
			if err := tx.PutQuery(v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rejected := errors.New("enclosing delete rejected")
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.DeleteWorkGroup(group.Key); err != nil {
			return err
		}
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatal(err)
	}
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		got, err := r.QueryByToken(scope(), removed.Token)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, removed) {
			t.Fatal("aborted deletion changed execution metadata or children")
		}
		_, err = r.WorkGroup(group.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repo.Update(t.Context(), func(tx domain.Transaction) error {
		if err := tx.DeleteWorkGroup(group.Key); err != nil {
			return err
		}
		return tx.PutWorkGroup(group)
	}); err != nil {
		t.Fatal(err)
	}
	s.reopen(t)
	if err := s.repo.View(t.Context(), func(r domain.Reader) error {
		if _, err := r.Query(removed.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("recreated workgroup recovered old execution: %v", err)
		}
		if _, err := r.QueryByToken(scope(), removed.Token); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("recreated workgroup recovered old token: %v", err)
		}
		rows, err := r.Queries(domain.ResourceQuery{Scope: scope(), WorkGroup: "research"})
		if err != nil {
			return err
		}
		if len(rows) != 0 {
			t.Fatalf("recreated workgroup recovered query history: %#v", rows)
		}
		for _, want := range survivors {
			got, err := r.Query(want.Key)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("workgroup deletion crossed scope or group: %+v", want.Key)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
