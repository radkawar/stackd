package glue_test

import (
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
	"stackd/storage/sqlite"
	gluesqlite "stackd/storage/sqlite/glue"
)

// Primary contracts: https://docs.aws.amazon.com/glue/latest/dg/about-triggers.html
// and https://docs.aws.amazon.com/glue/latest/dg/workflows_overview.html.
func TestWorkflowPropertiesFailureAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := registryContext("123456789012", "us-east-1")
			c := clock.NewManual(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
			var repo glue.Repository
			closeDB := func() {}
			reopen := func() glue.Repository { return repo }
			if backend == "memory" {
				repo = glue.NewMemoryRepository(nil)
			} else {
				path := filepath.Join(t.TempDir(), "workflow.sqlite")
				reopen = func() glue.Repository {
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
				repo = reopen()
			}
			s := glue.New(glue.Config{Repository: repo, Clock: c})
			t.Cleanup(func() { _ = s.Close(); closeDB() })
			name := new(api.NameString("chain"))
			registryCall[api.CreateWorkflowOutput](t, s, ctx, "CreateWorkflow", &api.CreateWorkflowInput{Name: name, MaxConcurrentRuns: new(api.NullableInteger(1)), DefaultRunProperties: api.WorkflowRunProperties{"shared": "default", "untouched": "initial"}})
			registryCall[api.CreateTriggerOutput](t, s, ctx, "CreateTrigger", &api.CreateTriggerInput{Name: new(api.NameString("start")), WorkflowName: name, Type: new(api.TriggerTypeON_DEMAND), Actions: api.ActionList{{JobName: new(api.NameString("missing-job"))}}})
			first := registryCall[api.StartWorkflowRunOutput](t, s, ctx, "StartWorkflowRun", &api.StartWorkflowRunInput{Name: name, RunProperties: api.WorkflowRunProperties{"shared": "override"}})
			registryError(t, s, ctx, "StartWorkflowRun", &api.StartWorkflowRunInput{Name: name}, "ConcurrentRunsExceededException")
			registryCall[api.PutWorkflowRunPropertiesOutput](t, s, ctx, "PutWorkflowRunProperties", &api.PutWorkflowRunPropertiesInput{Name: name, RunId: first.RunId, RunProperties: api.WorkflowRunProperties{"shared": "changed", "later": "visible"}})
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			closeDB()
			closeDB = func() {}
			repo = reopen()
			s = glue.New(glue.Config{Repository: repo, Clock: c})
			props := registryCall[api.GetWorkflowRunPropertiesOutput](t, s, ctx, "GetWorkflowRunProperties", &api.GetWorkflowRunPropertiesInput{Name: name, RunId: first.RunId})
			if props.RunProperties["shared"] != "changed" || props.RunProperties["untouched"] != "initial" || props.RunProperties["later"] != "visible" {
				t.Fatalf("run properties lost across restart: %v", props.RunProperties)
			}
			if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
				t.Fatal(err)
			}
			result := registryCall[api.GetWorkflowRunOutput](t, s, ctx, "GetWorkflowRun", &api.GetWorkflowRunInput{Name: name, RunId: first.RunId, IncludeGraph: new(api.NullableBoolean(true))})
			// COMPLETED means orchestration ended, not that the child actions succeeded.
			// https://docs.aws.amazon.com/glue/latest/dg/resuming-workflow.html
			if result.Run.Status == nil || *result.Run.Status != api.WorkflowRunStatusCOMPLETED || result.Run.Statistics.ErroredActions == nil || *result.Run.Statistics.ErroredActions != 1 {
				t.Fatalf("missing child action outcome lost: %+v", result.Run)
			}
			static := registryCall[api.GetWorkflowOutput](t, s, ctx, "GetWorkflow", &api.GetWorkflowInput{Name: name, IncludeGraph: new(api.NullableBoolean(true))})
			if static.Workflow.DefaultRunProperties["shared"] != "default" || static.Workflow.DefaultRunProperties["later"] != "" {
				t.Fatalf("run mutation changed defaults: %+v", static.Workflow.DefaultRunProperties)
			}
			for _, node := range static.Workflow.Graph.Nodes {
				if node.TriggerDetails != nil && (*node.TriggerDetails.Trigger.Type != api.TriggerTypeON_DEMAND || *node.TriggerDetails.Trigger.WorkflowName != *name) {
					t.Fatalf("static trigger metadata lost: %+v", node.TriggerDetails.Trigger)
				}
			}
			second := registryCall[api.StartWorkflowRunOutput](t, s, ctx, "StartWorkflowRun", &api.StartWorkflowRunInput{Name: name})
			registryCall[api.StopWorkflowRunOutput](t, s, ctx, "StopWorkflowRun", &api.StopWorkflowRunInput{Name: name, RunId: second.RunId})
			if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
				t.Fatal(err)
			}
			stopped := registryCall[api.GetWorkflowRunOutput](t, s, ctx, "GetWorkflowRun", &api.GetWorkflowRunInput{Name: name, RunId: second.RunId})
			if stopped.Run.Status == nil || *stopped.Run.Status != api.WorkflowRunStatusSTOPPED {
				t.Fatalf("queued stop launched a child: %+v", stopped.Run)
			}
		})
	}
}

func TestTriggerActivationScheduleAndTagAuthority(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	scope := glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	c := clock.NewManual(time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC))
	repo := glue.NewMemoryRepository(nil)
	s := glue.New(glue.Config{Repository: repo, Clock: c})
	t.Cleanup(func() { _ = s.Close() })
	action := api.ActionList{{JobName: new(api.NameString("missing"))}}
	registryError(t, s, ctx, "CreateTrigger", &api.CreateTriggerInput{Name: new(api.NameString("invalid")), Type: new(api.TriggerTypeON_DEMAND), Actions: action, StartOnCreation: new(api.BooleanValue(true))}, "InvalidInputException")
	registryCall[api.CreateWorkflowOutput](t, s, ctx, "CreateWorkflow", &api.CreateWorkflowInput{Name: new(api.NameString("scheduled"))})
	registryCall[api.CreateTriggerOutput](t, s, ctx, "CreateTrigger", &api.CreateTriggerInput{Name: new(api.NameString("timer")), WorkflowName: new(api.NameString("scheduled")), Type: new(api.TriggerTypeSCHEDULED), Schedule: new(api.GenericString("cron(0/5 * * * ? *)")), StartOnCreation: new(api.BooleanValue(true)), Actions: action, Tags: api.TagsMap{"owner": "original"}})
	registryCall[api.StopTriggerOutput](t, s, ctx, "StopTrigger", &api.StopTriggerInput{Name: new(api.NameString("timer"))})
	c.Advance(10 * time.Minute)
	if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
		t.Fatal(err)
	}
	runs := registryCall[api.GetWorkflowRunsOutput](t, s, ctx, "GetWorkflowRuns", &api.GetWorkflowRunsInput{Name: new(api.NameString("scheduled"))})
	if len(runs.Runs) != 0 {
		t.Fatal("deactivated trigger fired")
	}
	arn := api.GlueResourceArn("arn:aws:glue:us-east-1:123456789012:trigger/timer")
	registryCall[api.TagResourceOutput](t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: &arn, TagsToAdd: api.TagsMap{"owner": "changed", "extra": "retained"}})
	foreign := api.GlueResourceArn("arn:aws:glue:us-west-2:123456789012:trigger/timer")
	foreignTags := registryCall[api.GetTagsOutput](t, s, ctx, "GetTags", &api.GetTagsInput{ResourceArn: &foreign})
	if len(foreignTags.Tags) != 0 {
		t.Fatalf("foreign ARN aliased local resource: %v", foreignTags.Tags)
	}
	registryError(t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: &foreign, TagsToAdd: api.TagsMap{"owner": "foreign"}}, "InvalidInputException")
	if err := repo.Update(ctx, func(tx glue.Transaction) error {
		return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: scope, Policy: authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:TagResource","Resource":"*"}}`}})
	}); err != nil {
		t.Fatal(err)
	}
	registryError(t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: &arn, TagsToAdd: api.TagsMap{"owner": "forbidden"}}, "AccessDeniedException")
	tags := registryCall[api.GetTagsOutput](t, s, ctx, "GetTags", &api.GetTagsInput{ResourceArn: &arn})
	if tags.Tags["owner"] != "changed" || tags.Tags["extra"] != "retained" {
		t.Fatalf("denied tag mutation committed: %v", tags.Tags)
	}
	registryCall[api.StartTriggerOutput](t, s, ctx, "StartTrigger", &api.StartTriggerInput{Name: new(api.NameString("timer"))})
	c.Advance(5 * time.Minute)
	if _, err := s.JobDriver().RunDue(ctx, 20); err != nil {
		t.Fatal(err)
	}
	runs = registryCall[api.GetWorkflowRunsOutput](t, s, ctx, "GetWorkflowRuns", &api.GetWorkflowRunsInput{Name: new(api.NameString("scheduled"))})
	if len(runs.Runs) != 1 || runs.Runs[0].Status == nil || *runs.Runs[0].Status != api.WorkflowRunStatusCOMPLETED || *runs.Runs[0].Statistics.ErroredActions != 1 {
		t.Fatalf("scheduled actual command failure missing: %+v", runs.Runs)
	}
	if err := repo.Update(ctx, func(tx glue.Transaction) error {
		return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: scope, Policy: authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:GetTags","Resource":"*"}}`}})
	}); err != nil {
		t.Fatal(err)
	}
	registryError(t, s, ctx, "GetTags", &api.GetTagsInput{ResourceArn: &foreign}, "AccessDeniedException")
}

func TestSecurityConfigurationScopeAndMissingKeys(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	s := glue.New(glue.Config{})
	t.Cleanup(func() { _ = s.Close() })
	name := new(api.NameString("encrypted"))
	registryError(t, s, ctx, "CreateSecurityConfiguration", &api.CreateSecurityConfigurationInput{Name: name, EncryptionConfiguration: &api.EncryptionConfiguration{S3Encryption: api.S3EncryptionList{{S3EncryptionMode: new(api.S3EncryptionModeSSEKMS)}}}}, "InvalidInputException")
	key := new(api.KmsKeyArn("arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001"))
	registryCall[api.CreateSecurityConfigurationOutput](t, s, ctx, "CreateSecurityConfiguration", &api.CreateSecurityConfigurationInput{Name: name, EncryptionConfiguration: &api.EncryptionConfiguration{S3Encryption: api.S3EncryptionList{{S3EncryptionMode: new(api.S3EncryptionModeSSEKMS), KmsKeyArn: key}}, CloudWatchEncryption: &api.CloudWatchEncryption{CloudWatchEncryptionMode: new(api.CloudWatchEncryptionModeSSEKMS), KmsKeyArn: key}}})
	registryError(t, s, registryContext("999999999999", "us-east-1"), "GetSecurityConfiguration", &api.GetSecurityConfigurationInput{Name: name}, "EntityNotFoundException")
	registryCall[api.DeleteSecurityConfigurationOutput](t, s, ctx, "DeleteSecurityConfiguration", &api.DeleteSecurityConfigurationInput{Name: name})
	registryError(t, s, ctx, "GetSecurityConfiguration", &api.GetSecurityConfigurationInput{Name: name}, "EntityNotFoundException")
}

// Official service-reference APIs authorize TagResource for tagged creation:
// https://servicereference.us-east-1.amazonaws.com/v1/glue/glue.json
func TestWorkflowAndTriggerCreationRequireTagAuthority(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	scope := glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	repo := glue.NewMemoryRepository(nil)
	s := glue.New(glue.Config{Repository: repo})
	t.Cleanup(func() { _ = s.Close() })
	if err := repo.Update(ctx, func(tx glue.Transaction) error {
		return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: scope, Policy: authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:TagResource","Resource":"*"}}`}})
	}); err != nil {
		t.Fatal(err)
	}
	name := new(api.NameString("tag-authority"))
	registryError(t, s, ctx, "CreateWorkflow", &api.CreateWorkflowInput{Name: name, Tags: api.TagsMap{"team": "analytics"}}, "AccessDeniedException")
	registryError(t, s, ctx, "GetWorkflow", &api.GetWorkflowInput{Name: name}, "EntityNotFoundException")
	registryCall[api.CreateWorkflowOutput](t, s, ctx, "CreateWorkflow", &api.CreateWorkflowInput{Name: name})
	trigger := new(api.NameString("tagged-trigger"))
	registryError(t, s, ctx, "CreateTrigger", &api.CreateTriggerInput{Name: trigger, Type: new(api.TriggerTypeON_DEMAND), WorkflowName: name, Actions: api.ActionList{{JobName: new(api.NameString("missing"))}}, Tags: api.TagsMap{"team": "analytics"}}, "AccessDeniedException")
	registryError(t, s, ctx, "GetTrigger", &api.GetTriggerInput{Name: trigger}, "EntityNotFoundException")
}

func TestNamedCatalogTagsKeepExactHierarchyAndCurrentAuthority(t *testing.T) {
	ctx := registryContext("123456789012", "us-east-1")
	scope := glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	repo := glue.NewMemoryRepository(nil)
	s := glue.New(glue.Config{Repository: repo})
	t.Cleanup(func() { _ = s.Close() })
	if err := repo.Update(ctx, func(tx glue.Transaction) error {
		for _, catalog := range []string{"123456789012:analytics", "123456789012:analytics:child"} {
			if err := tx.PutCatalog(glue.CatalogRecord{Key: glue.CatalogKey{Scope: scope, CatalogID: catalog}, Tags: map[string]string{"locked": "false"}}); err != nil {
				return err
			}
		}
		return tx.PutResourcePolicy(glue.ResourcePolicyRecord{Scope: scope, Policy: authorization.BoundPolicy{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"glue:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/locked":"true"}}}}`}})
	}); err != nil {
		t.Fatal(err)
	}
	parent := new(api.GlueResourceArn("arn:aws:glue:us-east-1:123456789012:catalog/analytics"))
	child := new(api.GlueResourceArn("arn:aws:glue:us-east-1:123456789012:catalog/analytics/child"))
	registryCall[api.TagResourceOutput](t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: child, TagsToAdd: api.TagsMap{"locked": "true", "team": "analytics"}})
	registryError(t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: child, TagsToAdd: api.TagsMap{"team": "forbidden"}}, "AccessDeniedException")
	childTags := registryCall[api.GetTagsOutput](t, s, ctx, "GetTags", &api.GetTagsInput{ResourceArn: child})
	parentTags := registryCall[api.GetTagsOutput](t, s, ctx, "GetTags", &api.GetTagsInput{ResourceArn: parent})
	if childTags.Tags["team"] != "analytics" || parentTags.Tags["team"] != "" || parentTags.Tags["locked"] != "false" {
		t.Fatalf("catalog tag hierarchy or denial changed: parent=%v child=%v", parentTags.Tags, childTags.Tags)
	}
	registryCall[api.UntagResourceOutput](t, s, ctx, "UntagResource", &api.UntagResourceInput{ResourceArn: child, TagsToRemove: api.TagKeysList{"locked"}})
	registryCall[api.TagResourceOutput](t, s, ctx, "TagResource", &api.TagResourceInput{ResourceArn: child, TagsToAdd: api.TagsMap{"team": "unlocked"}})
	for _, arn := range []string{"arn:aws:glue:us-east-1:123456789012:catalog", "arn:aws:glue:us-east-1:123456789012:table/db/table"} {
		registryError(t, s, ctx, "GetTags", &api.GetTagsInput{ResourceArn: new(api.GlueResourceArn(arn))}, "InvalidInputException")
	}
}
