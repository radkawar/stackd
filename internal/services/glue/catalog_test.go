package glue_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

func catalogTestContext(account, region string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: region, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account})
}
func catalogTestExecute(s *glue.Service, ctx context.Context, action string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("glue")
	op, _ := model.Operation(action)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: awscatalog.AWSJSON11, Input: input})
}
func catalogTestCall[O any](t *testing.T, s *glue.Service, ctx context.Context, action string, input any) *O {
	t.Helper()
	out, rejected := catalogTestExecute(s, ctx, action, input)
	if rejected != nil {
		t.Fatalf("%s: %v", action, rejected)
	}
	result, ok := out.(*O)
	if !ok {
		t.Fatalf("%s output %T", action, out)
	}
	return result
}
func catalogTestError(t *testing.T, s *glue.Service, ctx context.Context, action string, input any, code string) {
	t.Helper()
	_, err := catalogTestExecute(s, ctx, action, input)
	if err == nil || err.Code != code {
		t.Fatalf("%s error=%v, want %s", action, err, code)
	}
}

type catalogNativeObservation struct {
	Label, Service, Operation string
	Input                     json.RawMessage
	Result                    struct {
		Code   string
		Output json.RawMessage
	}
}
type catalogStableTable struct {
	Name, Database, Description, Version, Location string
	Parameters                                     api.ParametersMap
	Columns, PartitionKeys                         api.ColumnList
}
type catalogStablePartition struct {
	Values     api.ValueStringList
	Parameters api.ParametersMap
	Location   string
}
type catalogStableError struct {
	Table  string
	Values api.ValueStringList
	Code   string
}
type catalogStableResponse struct {
	DatabaseName, DatabaseDescription string
	DatabaseParameters                api.ParametersMap
	Table                             *catalogStableTable
	Tables, Versions                  []catalogStableTable
	Partition                         *catalogStablePartition
	Partitions                        []catalogStablePartition
	Errors                            []catalogStableError
}

func catalogTestValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}
func stableCatalogTable(v api.Table) catalogStableTable {
	out := catalogStableTable{Name: catalogTestValue(v.Name), Database: catalogTestValue(v.DatabaseName), Description: catalogTestValue(v.Description), Version: catalogTestValue(v.VersionId), Parameters: v.Parameters, PartitionKeys: v.PartitionKeys}
	if v.StorageDescriptor != nil {
		out.Location = catalogTestValue(v.StorageDescriptor.Location)
		out.Columns = v.StorageDescriptor.Columns
	}
	return out
}
func stableCatalogPartition(v api.Partition) catalogStablePartition {
	out := catalogStablePartition{Values: v.Values, Parameters: v.Parameters}
	if v.StorageDescriptor != nil {
		out.Location = catalogTestValue(v.StorageDescriptor.Location)
	}
	return out
}
func catalogStable(data []byte) (catalogStableResponse, error) {
	var raw struct {
		Database      *api.Database
		Table         *api.Table
		TableList     api.TableList
		TableVersion  *api.TableVersion
		TableVersions api.GetTableVersionsList
		Partition     *api.Partition
		Partitions    api.PartitionList
		Errors        []struct {
			TableName                           *api.NameString
			PartitionValues, PartitionValueList api.ValueStringList
			ErrorDetail                         *api.ErrorDetail
		}
	}
	var out catalogStableResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return out, err
	}
	if raw.Database != nil {
		out.DatabaseName = catalogTestValue(raw.Database.Name)
		out.DatabaseDescription = catalogTestValue(raw.Database.Description)
		out.DatabaseParameters = raw.Database.Parameters
	}
	if raw.Table != nil {
		out.Table = new(stableCatalogTable(*raw.Table))
	}
	if raw.TableVersion != nil && raw.TableVersion.Table != nil {
		out.Table = new(stableCatalogTable(*raw.TableVersion.Table))
	}
	for _, v := range raw.TableList {
		out.Tables = append(out.Tables, stableCatalogTable(v))
	}
	for _, v := range raw.TableVersions {
		if v.Table != nil {
			out.Versions = append(out.Versions, stableCatalogTable(*v.Table))
		}
	}
	if raw.Partition != nil {
		out.Partition = new(stableCatalogPartition(*raw.Partition))
	}
	for _, v := range raw.Partitions {
		out.Partitions = append(out.Partitions, stableCatalogPartition(v))
	}
	slices.SortFunc(out.Partitions, func(a, b catalogStablePartition) int {
		return strings.Compare(strings.Join(partitionTestStrings(a.Values), "\x00"), strings.Join(partitionTestStrings(b.Values), "\x00"))
	})
	for _, v := range raw.Errors {
		values := v.PartitionValues
		if values == nil {
			values = v.PartitionValueList
		}
		code := ""
		if v.ErrorDetail != nil {
			code = catalogTestValue(v.ErrorDetail.ErrorCode)
		}
		out.Errors = append(out.Errors, catalogStableError{Table: catalogTestValue(v.TableName), Values: values, Code: code})
	}
	return out, nil
}
func partitionTestStrings(values api.ValueStringList) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

// The fixture is an owned native capture, not a copy of local expectations.
// Compare consumer state/errors, not AWS timestamps, opaque tokens or wording.
func TestCatalogNativeTransitionsAndRestart(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "aws", "glue", "catalog_verified.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Observations []catalogNativeObservation }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := catalogTestContext("123456789012", "us-east-1")
			c := clock.NewManual(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC))
			var repository glue.Repository
			closeDB := func() {}
			var reopen func() glue.Repository
			if backend == "memory" {
				repository = glue.NewMemoryRepository(nil)
				reopen = func() glue.Repository { return repository }
			} else {
				path := filepath.Join(t.TempDir(), "catalog.sqlite")
				open := func() glue.Repository {
					db, err := sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					closeDB = func() {
						if err := db.Close(); err != nil {
							t.Error(err)
						}
					}
					return gluesqlite.New(db)
				}
				repository = open()
				reopen = open
			}
			s := glue.New(glue.Config{Repository: repository, Clock: c})
			defer func() { _ = s.Close(); closeDB() }()
			var pageToken *api.Token
			for _, observation := range fixture.Observations {
				if observation.Service != "glue" {
					continue
				}
				t.Run(observation.Label, func(t *testing.T) {
					action := ""
					for _, word := range strings.Split(observation.Operation, "-") {
						action += strings.ToUpper(word[:1]) + word[1:]
					}
					input, err := api.NewInput(action)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(observation.Input, input); err != nil {
						t.Fatal(err)
					}
					if in, ok := input.(*api.GetTablesInput); ok && in.NextToken != nil {
						in.NextToken = pageToken
					}
					callCtx := ctx
					if observation.Label == "get-database-other-region" {
						callCtx = catalogTestContext("123456789012", "us-west-2")
					}
					output, rejected := catalogTestExecute(s, callCtx, action, input)
					code := "Success"
					if rejected != nil {
						code = rejected.Code
					}
					if code != observation.Result.Code {
						t.Fatalf("native code=%s, local=%s (%v)", observation.Result.Code, code, rejected)
					}
					if rejected != nil {
						return
					}
					encoded, err := json.Marshal(output)
					if err != nil {
						t.Fatal(err)
					}
					actual, err := catalogStable(encoded)
					if err != nil {
						t.Fatal(err)
					}
					expected, err := catalogStable(observation.Result.Output)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(actual, expected) {
						t.Fatalf("native state mismatch\nactual %#v\nnative %#v", actual, expected)
					}
					if out, ok := output.(*api.GetTablesOutput); ok && observation.Label == "tables-page-one" {
						pageToken = out.NextToken
						if pageToken == nil {
							t.Fatal("first page lost continuation")
						}
					}
				})
				if observation.Label == "versions-after-skip" {
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					closeDB()
					repository = reopen()
					s = glue.New(glue.Config{Repository: repository, Clock: c})
				}
				c.Advance(time.Second)
			}
		})
	}
}

func TestCatalogPolicyConditionsAndPartitionExpression(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	defer s.Close()
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("policy"))}})
	catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: new(api.NameString("policy")), TableInput: &api.TableInput{Name: new(api.NameString("events")), PartitionKeys: api.ColumnList{{Name: new(api.NameString("year")), Type: new(api.ColumnTypeString("int"))}, {Name: new(api.NameString("zone")), Type: new(api.ColumnTypeString("string"))}}}})
	for _, values := range []api.ValueStringList{{"9", "west"}, {"10", "east"}, {"11", "north"}} {
		catalogTestCall[api.CreatePartitionOutput](t, s, ctx, "CreatePartition", &api.CreatePartitionInput{DatabaseName: new(api.NameString("policy")), TableName: new(api.NameString("events")), PartitionInput: &api.PartitionInput{Values: values}})
	}
	selected := catalogTestCall[api.GetPartitionsOutput](t, s, ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: new(api.NameString("policy")), TableName: new(api.NameString("events")), Expression: new(api.PredicateString("year BETWEEN 10 AND 20 AND (zone IN ('east', 'west') OR zone LIKE 'no%')"))})
	if len(selected.Partitions) != 2 || selected.Partitions[0].Values[0] != "10" || selected.Partitions[1].Values[0] != "11" {
		t.Fatalf("numeric expression selected %v", selected.Partitions)
	}
	catalogTestError(t, s, ctx, "GetPartitions", &api.GetPartitionsInput{DatabaseName: new(api.NameString("policy")), TableName: new(api.NameString("events")), Expression: new(api.PredicateString("missing = 'x'"))}, "InvalidInputException")
	policy := api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"glue:DeleteTable","Resource":"*"}]}`)
	installed := catalogTestCall[api.PutResourcePolicyOutput](t, s, ctx, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &policy, PolicyExistsCondition: new(api.ExistCondition("NOT_EXIST"))})
	catalogTestError(t, s, ctx, "DeleteTable", &api.DeleteTableInput{DatabaseName: new(api.NameString("policy")), Name: new(api.NameString("events"))}, "AccessDeniedException")
	catalogTestError(t, s, ctx, "DeleteResourcePolicy", &api.DeleteResourcePolicyInput{PolicyHashCondition: new(api.HashString("stale"))}, "ConditionCheckFailureException")
	catalogTestCall[api.DeleteResourcePolicyOutput](t, s, ctx, "DeleteResourcePolicy", &api.DeleteResourcePolicyInput{PolicyHashCondition: installed.PolicyHash})
	catalogTestCall[api.DeleteDatabaseOutput](t, s, ctx, "DeleteDatabase", &api.DeleteDatabaseInput{Name: new(api.NameString("policy"))})
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("policy"))}})
	catalogTestError(t, s, ctx, "GetPartition", &api.GetPartitionInput{DatabaseName: new(api.NameString("policy")), TableName: new(api.NameString("events")), PartitionValues: api.ValueStringList{"10", "east"}}, "EntityNotFoundException")
}

func TestCatalogAncestorAndCreateTagAuthorization(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	defer s.Close()
	catalogTestCall[api.CreateCatalogOutput](t, s, ctx, "CreateCatalog", &api.CreateCatalogInput{Name: new(api.CatalogNameString("analytics")), CatalogInput: &api.CatalogInput{}})
	catalog := api.CatalogIdString("123456789012:analytics")
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: &catalog, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("events"))}})
	policy := api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"glue:GetDatabase","Resource":"arn:aws:glue:us-east-1:123456789012:catalog"}]}`)
	catalogTestCall[api.PutResourcePolicyOutput](t, s, ctx, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &policy})
	catalogTestError(t, s, ctx, "GetDatabase", &api.GetDatabaseInput{CatalogId: &catalog, Name: new(api.NameString("events"))}, "AccessDeniedException")
	policy = api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"glue:CreateDatabase","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestTag/team":"analytics"}}}]}`)
	catalogTestCall[api.PutResourcePolicyOutput](t, s, ctx, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &policy})
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: &catalog, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("tagged"))}, Tags: api.TagsMap{"team": "analytics"}})
	policy = api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"glue:TagResource","Resource":"*"}]}`)
	catalogTestCall[api.PutResourcePolicyOutput](t, s, ctx, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &policy})
	catalogTestError(t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{CatalogId: &catalog, DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("denied"))}, Tags: api.TagsMap{"team": "analytics"}}, "AccessDeniedException")
	catalogTestError(t, s, ctx, "GetDatabase", &api.GetDatabaseInput{CatalogId: &catalog, Name: new(api.NameString("denied"))}, "EntityNotFoundException")
}

func TestForeignDatabaseListingUsesCurrentResourcePolicy(t *testing.T) {
	own := catalogTestContext("123456789012", "us-east-1")
	foreign := catalogTestContext("210987654321", "us-east-1")
	s := glue.New(glue.Config{})
	defer s.Close()
	catalogTestCall[api.CreateDatabaseOutput](t, s, foreign, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: new(api.NameString("shared"))}})
	input := &api.GetDatabasesInput{ResourceShareType: new(api.ResourceShareType("FOREIGN"))}
	before := catalogTestCall[api.GetDatabasesOutput](t, s, own, "GetDatabases", input)
	if len(before.DatabaseList) != 0 {
		t.Fatalf("unshared foreign databases leaked: %v", before.DatabaseList)
	}
	policy := api.PolicyJsonString(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"glue:GetDatabases","Resource":["arn:aws:glue:us-east-1:210987654321:catalog","arn:aws:glue:us-east-1:210987654321:database/shared"]}]}`)
	catalogTestCall[api.PutResourcePolicyOutput](t, s, foreign, "PutResourcePolicy", &api.PutResourcePolicyInput{PolicyInJson: &policy})
	shared := catalogTestCall[api.GetDatabasesOutput](t, s, own, "GetDatabases", input)
	if len(shared.DatabaseList) != 1 || catalogTestValue(shared.DatabaseList[0].Name) != "shared" || catalogTestValue(shared.DatabaseList[0].CatalogId) != "210987654321" {
		t.Fatalf("shared database result: %v", shared.DatabaseList)
	}
	catalogTestCall[api.DeleteResourcePolicyOutput](t, s, foreign, "DeleteResourcePolicy", &api.DeleteResourcePolicyInput{})
	after := catalogTestCall[api.GetDatabasesOutput](t, s, own, "GetDatabases", input)
	if len(after.DatabaseList) != 0 {
		t.Fatalf("revoked foreign database leaked: %v", after.DatabaseList)
	}
}

type catalogEventCapture struct {
	events []glue.CatalogEvent
}

func (c *catalogEventCapture) PublishCatalog(_ context.Context, event glue.CatalogEvent) error {
	c.events = append(c.events, event)
	return nil
}

func TestCatalogEventsDescribeSuccessfulBatchMutations(t *testing.T) {
	ctx := catalogTestContext("123456789012", "us-east-1")
	capture := &catalogEventCapture{}
	s := glue.New(glue.Config{CatalogEvents: capture})
	defer s.Close()
	expect := func(action, table string, changedTables []string, changedPartitions [][]string) {
		t.Helper()
		if len(capture.events) != 1 {
			t.Fatalf("%s published events: %v", action, capture.events)
		}
		event := capture.events[0]
		if event.Operation != action || event.DatabaseName != "events" || event.TableName != table || event.CatalogID != "123456789012" || event.Scope != (glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}) {
			t.Fatalf("%s event identity: %+v", action, event)
		}
		if !slices.Equal(event.ChangedTables, changedTables) || !slices.EqualFunc(event.ChangedPartitions, changedPartitions, func(a, b []string) bool { return slices.Equal(a, b) }) {
			t.Fatalf("%s changes: tables=%v partitions=%v; want tables=%v partitions=%v", action, event.ChangedTables, event.ChangedPartitions, changedTables, changedPartitions)
		}
		capture.events = nil
	}
	database, table := api.NameString("EVENTS"), api.NameString("SESSIONS")
	catalogTestCall[api.CreateDatabaseOutput](t, s, ctx, "CreateDatabase", &api.CreateDatabaseInput{DatabaseInput: &api.DatabaseInput{Name: &database}})
	expect("CreateDatabase", "", nil, nil)
	catalogTestCall[api.CreateTableOutput](t, s, ctx, "CreateTable", &api.CreateTableInput{DatabaseName: &database, TableInput: &api.TableInput{Name: &table, PartitionKeys: api.ColumnList{{Name: new(api.NameString("region")), Type: new(api.ColumnTypeString("string"))}}}})
	expect("CreateTable", "", []string{"sessions"}, nil)

	created := catalogTestCall[api.BatchCreatePartitionOutput](t, s, ctx, "BatchCreatePartition", &api.BatchCreatePartitionInput{
		DatabaseName: &database, TableName: &table,
		PartitionInputList: api.PartitionInputList{{Values: api.ValueStringList{"West"}}, {Values: api.ValueStringList{"West"}}, {Values: api.ValueStringList{"East"}}},
	})
	if len(created.Errors) != 1 || catalogTestValue(created.Errors[0].ErrorDetail.ErrorCode) != "AlreadyExistsException" {
		t.Fatalf("duplicate creation errors: %v", created.Errors)
	}
	expect("BatchCreatePartition", "sessions", nil, [][]string{{"West"}, {"East"}})

	updated := catalogTestCall[api.BatchUpdatePartitionOutput](t, s, ctx, "BatchUpdatePartition", &api.BatchUpdatePartitionInput{
		DatabaseName: &database, TableName: &table,
		Entries: api.BatchUpdatePartitionRequestEntryList{
			{PartitionValueList: api.BoundedPartitionValueList{"West"}, PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"North"}}},
			{PartitionValueList: api.BoundedPartitionValueList{"West"}, PartitionInput: &api.PartitionInput{Values: api.ValueStringList{"South"}}},
		},
	})
	if len(updated.Errors) != 1 || catalogTestValue(updated.Errors[0].ErrorDetail.ErrorCode) != "EntityNotFoundException" {
		t.Fatalf("duplicate update errors: %v", updated.Errors)
	}
	expect("BatchUpdatePartition", "sessions", nil, [][]string{{"North"}})
	north := catalogTestCall[api.GetPartitionOutput](t, s, ctx, "GetPartition", &api.GetPartitionInput{DatabaseName: &database, TableName: &table, PartitionValues: api.ValueStringList{"North"}})
	if north.Partition == nil || !slices.Equal(north.Partition.Values, api.ValueStringList{"North"}) {
		t.Fatalf("successful move state: %v", north.Partition)
	}
	catalogTestError(t, s, ctx, "GetPartition", &api.GetPartitionInput{DatabaseName: &database, TableName: &table, PartitionValues: api.ValueStringList{"South"}}, "EntityNotFoundException")

	deleteInput := &api.BatchDeletePartitionInput{DatabaseName: &database, TableName: &table, PartitionsToDelete: api.BatchDeletePartitionValueList{{Values: api.ValueStringList{"North"}}, {Values: api.ValueStringList{"North"}}}}
	deleted := catalogTestCall[api.BatchDeletePartitionOutput](t, s, ctx, "BatchDeletePartition", deleteInput)
	if len(deleted.Errors) != 1 || catalogTestValue(deleted.Errors[0].ErrorDetail.ErrorCode) != "EntityNotFoundException" {
		t.Fatalf("duplicate deletion errors: %v", deleted.Errors)
	}
	expect("BatchDeletePartition", "sessions", nil, [][]string{{"North"}})
	missing := catalogTestCall[api.BatchDeletePartitionOutput](t, s, ctx, "BatchDeletePartition", deleteInput)
	if len(missing.Errors) != 2 || len(capture.events) != 0 {
		t.Fatalf("failed batch emitted changes: errors=%v events=%v", missing.Errors, capture.events)
	}

	tables := catalogTestCall[api.BatchDeleteTableOutput](t, s, ctx, "BatchDeleteTable", &api.BatchDeleteTableInput{DatabaseName: &database, TablesToDelete: api.BatchDeleteTableNameList{"SESSIONS", "SESSIONS"}})
	if len(tables.Errors) != 1 || catalogTestValue(tables.Errors[0].ErrorDetail.ErrorCode) != "EntityNotFoundException" {
		t.Fatalf("duplicate table deletion errors: %v", tables.Errors)
	}
	expect("BatchDeleteTable", "", []string{"sessions"}, nil)
}
