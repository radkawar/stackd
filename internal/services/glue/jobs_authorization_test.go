package glue_test

import (
	"fmt"
	"testing"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
	"stackd/internal/services/glue"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
)

func TestJobRunAuthorizationUsesCurrentJobTags(t *testing.T) {
	for _, prefix := range []string{"aws", "glue"} {
		t.Run(prefix, func(t *testing.T) {
			root := catalogTestContext("123456789012", "us-east-1")
			domain := memory.NewDomain()
			identities := iam.NewMemoryRepository(domain)
			identityService := iam.NewWithConfig(iam.Config{Repository: identities})
			repository := glue.NewMemoryRepository(domain)
			service := glue.New(glue.Config{Repository: repository, Authorizer: authorization.NewWithClock(identityService, nil, nil)})
			defer service.Close()
			// This fixture covers command authorization, not native execution.
			service.JobDriver().Close()
			scope := glue.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
			key := glue.ResourceKey{Scope: scope, Name: "tagged"}
			user := iam.User{UserName: "reader", UserId: "AIDAREADER", Arn: "arn:aws:iam::123456789012:user/reader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
			caller := awsctx.WithMetadata(root, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: user.Arn, PrincipalID: user.UserId})
			setPolicy := func(policy string) {
				t.Helper()
				user.IdentityPolicies.Inline["runs"] = policy
				if err := identities.Update(root, func(tx iam.WriteTx) error {
					return tx.PutUser(iam.Scope{Partition: scope.Partition, AccountID: scope.AccountID}, user)
				}); err != nil {
					t.Fatal(err)
				}
			}
			catalogTestCall[api.CreateJobOutput](t, service, root, "CreateJob", &api.CreateJobInput{Name: new(api.NameString(key.Name)), Role: new(api.RoleString("arn:aws:iam::123456789012:role/job")), Command: &api.JobCommand{Name: new(api.GenericString("pythonshell")), PythonVersion: new(api.PythonVersionString("3")), ScriptLocation: new(api.ScriptLocationString("s3://owned/job.py"))}, MaxCapacity: new(api.NullableDouble(0.0625)), Tags: api.TagsMap{"access": "locked"}})
			// Seed an admitted execution without requiring Docker. Authorization is
			// exercised through public commands and the current shared IAM owner.
			resetRun := func() {
				t.Helper()
				if err := repository.Update(root, func(tx glue.Transaction) error {
					return tx.PutJobRun(glue.JobRunRecord{Key: key, ID: "jr-retained", State: "RUNNING", StartedAt: time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC), Version: 1})
				}); err != nil {
					t.Fatal(err)
				}
			}
			resetRun()
			requests := []struct {
				action string
				input  any
			}{
				{"GetJobRun", &api.GetJobRunInput{JobName: new(api.NameString(key.Name)), RunId: new(api.IdString("jr-retained"))}},
				{"GetJobRuns", &api.GetJobRunsInput{JobName: new(api.NameString(key.Name))}},
				{"BatchStopJobRun", &api.BatchStopJobRunInput{JobName: new(api.NameString(key.Name)), JobRunIds: api.BatchStopJobRunJobRunIdList{"jr-retained"}}},
			}
			allow := fmt.Sprintf(`{"Effect":"Allow","Action":["glue:GetJobRun","glue:GetJobRuns","glue:BatchStopJobRun"],"Resource":%q}`, key.ARN("job"))
			conditional := func(effect string) string {
				return fmt.Sprintf(`{"Effect":%q,"Action":["glue:GetJobRun","glue:GetJobRuns","glue:BatchStopJobRun"],"Resource":%q,"Condition":{"StringEquals":{%q:"locked"}}}`, effect, key.ARN("job"), prefix+":ResourceTag/access")
			}
			setPolicy(`{"Statement":[` + allow + `,` + conditional("Deny") + `]}`)
			for _, request := range requests {
				catalogTestError(t, service, caller, request.action, request.input, "AccessDeniedException")
			}
			rootRun := catalogTestCall[api.GetJobRunOutput](t, service, root, requests[0].action, requests[0].input)
			if *rootRun.JobRun.JobRunState != "RUNNING" {
				t.Fatal("denied stop changed execution state")
			}
			setPolicy(`{"Statement":[` + conditional("Allow") + `]}`)
			checkAllowed := func() {
				t.Helper()
				got := catalogTestCall[api.GetJobRunOutput](t, service, caller, requests[0].action, requests[0].input)
				if string(*got.JobRun.Id) != "jr-retained" {
					t.Fatal("wrong retained run")
				}
				list := catalogTestCall[api.GetJobRunsOutput](t, service, caller, requests[1].action, requests[1].input)
				if len(list.JobRuns) != 1 || string(*list.JobRuns[0].Id) != "jr-retained" {
					t.Fatal("wrong retained run list")
				}
				stop := catalogTestCall[api.BatchStopJobRunOutput](t, service, caller, requests[2].action, requests[2].input)
				if len(stop.SuccessfulSubmissions) != 1 || len(stop.Errors) != 0 {
					t.Fatalf("stop result: %+v", stop)
				}
			}
			checkAllowed()
			resetRun()
			catalogTestCall[api.TagResourceOutput](t, service, root, "TagResource", &api.TagResourceInput{ResourceArn: new(api.GlueResourceArn(key.ARN("job"))), TagsToAdd: api.TagsMap{"access": "changed"}})
			for _, request := range requests {
				catalogTestError(t, service, caller, request.action, request.input, "AccessDeniedException")
			}
			catalogTestCall[api.DeleteJobOutput](t, service, root, "DeleteJob", &api.DeleteJobInput{JobName: new(api.NameString(key.Name))})
			for _, request := range requests {
				catalogTestError(t, service, caller, request.action, request.input, "AccessDeniedException")
			}
			setPolicy(`{"Statement":[` + allow + `]}`)
			checkAllowed()
		})
	}
}
