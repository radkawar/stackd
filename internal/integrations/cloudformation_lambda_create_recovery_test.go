package integrations

import (
	"testing"

	"stackd/internal/services/cloudformation"
	service "stackd/internal/services/lambda"
)

func TestCFNLambdaVersionCreateRetainsPublicationOnScalingFailure(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			_, key := cfnLambdaSeedDeployment(t, f)
			h := cfnLambdaVersion{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::Version", cloudformation.Properties{"FunctionName": key.Name, "FunctionScalingConfig": map[string]any{"MinExecutionEnvironments": 3}})
			f.authority.denied = "lambda:PutFunctionScalingConfig"
			result, err := h.Create(f.ctx, r)
			if !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != key.ARN()+":1" {
				t.Fatalf("post-publication scaling failure lost admitted version: %+v %v", result, err)
			}
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.Create(f.ctx, r)
			if !cfnMessagingMissing(err, "AccessDeniedException") || recovered.PhysicalID != result.PhysicalID {
				t.Fatalf("same-token replay lost publication: %+v %v", recovered, err)
			}
			if err := f.repo.View(f.ctx, func(reader service.Reader) error {
				versions, err := reader.FunctionVersions(key)
				if err != nil {
					return err
				}
				if len(versions) != 1 || versions[0].Version != 1 {
					t.Fatalf("failed scaling replay created another immutable version: %+v", versions)
				}
				owner, err := reader.FunctionVersionOwner(service.FunctionVersionKey{FunctionKey: key, Version: 1})
				if err != nil {
					return err
				}
				if owner != (service.VersionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}) {
					t.Fatalf("failed scaling replay lost the private publication claim: %+v", owner)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			f.authority.denied = ""
			r.PhysicalID = result.PhysicalID
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := f.repo.View(f.ctx, func(reader service.Reader) error {
				versions, err := reader.FunctionVersions(key)
				if err != nil {
					return err
				}
				if len(versions) != 0 {
					t.Fatalf("rollback did not delete exact admitted publication: %+v", versions)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
