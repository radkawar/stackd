package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	cfnapi "stackd/internal/awsapi/cloudformation"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	service "stackd/internal/services/lambda"
	cfnsqlite "stackd/storage/sqlite/cloudformation"
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

func cfnLambdaRecoveryController(t *testing.T, f *cfnLambdaAdditionalFixture) (*cloudformation.Service, cloudformation.Repository, StepFunctionsCommands) {
	t.Helper()
	var repository cloudformation.Repository = cloudformation.NewMemoryRepository(nil)
	if f.db != nil {
		repository = cfnsqlite.New(f.db)
	}
	controller := cloudformation.New(cloudformation.Config{Repository: repository, Clock: f.manual, Authorizer: f.authority, Handlers: CloudFormationComputeHandlers(f.commands)})
	t.Cleanup(func() { _ = controller.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"cloudformation": controller})
	return controller, repository, commands
}

func cfnLambdaRecoveryDrain(t *testing.T, f *cfnLambdaAdditionalFixture, controller *cloudformation.Service, commands StepFunctionsCommands, stackID string) {
	t.Helper()
	for range 30 {
		if _, err := f.service.JobDriver().RunDue(f.ctx, 100); err != nil {
			t.Fatal(err)
		}
		if _, err := controller.JobDriver().RunDue(f.ctx, 100); err != nil {
			t.Fatal(err)
		}
		out, err := cfnComputeCall[cfnapi.DescribeStacksOutput](f.ctx, commands, "cloudformation", "DescribeStacks", map[string]any{"StackName": stackID})
		if err != nil || len(out.Stacks) != 1 {
			t.Fatalf("describe recovery stack: %+v %v", out, err)
		}
		status := cfnComputeValue(out.Stacks[0].StackStatus)
		if status == "ROLLBACK_COMPLETE" {
			return
		}
		if status == "ROLLBACK_FAILED" || status == "CREATE_COMPLETE" {
			t.Fatalf("unexpected recovery status: %+v", out.Stacks[0])
		}
		if err := f.manual.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("rollback did not complete")
}

func TestCFNLambdaRejectedCreationRollsBackThroughPublicController(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"Function", "EventSourceMapping"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				var f *cfnLambdaAdditionalFixture
				properties := cloudformation.Properties{"FunctionName": "rejected-function", "Runtime": "python3.12", "Handler": "index.handler", "Role": "arn:aws:iam::111111111111:role/execution", "Code": map[string]any{"ZipFile": "def handler(event, context): return event"}, "Environment": map[string]any{"Variables": map[string]any{"AWS_REGION": "reserved"}}}
				if kind == "EventSourceMapping" {
					var sources []string
					f, sources, _ = cfnLambdaMappingNativeFixture(t, backend)
					properties = cloudformation.Properties{"FunctionName": "missing-function", "EventSourceArn": sources[0], "Enabled": false}
				} else {
					f = newCFNLambdaAdditionalFixture(t, backend)
				}
				controller, _, commands := cfnLambdaRecoveryController(t, f)
				body, err := json.Marshal(map[string]any{"Resources": map[string]any{"Rejected": map[string]any{"Type": "AWS::Lambda::" + kind, "Properties": properties}}})
				if err != nil {
					t.Fatal(err)
				}
				out, err := cfnComputeCall[cfnapi.CreateStackOutput](f.ctx, commands, "cloudformation", "CreateStack", map[string]any{"StackName": "rejected-lambda", "TemplateBody": string(body)})
				if err != nil {
					t.Fatalf("valid template was rejected before native admission: %v", err)
				}
				cfnLambdaRecoveryDrain(t, f, controller, commands, cfnComputeValue(out.StackId))
				if err := f.repo.View(f.ctx, func(reader service.Reader) error {
					if kind == "Function" {
						_, err := reader.Function(service.FunctionKey{Scope: service.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "rejected-function"})
						if !errors.Is(err, service.ErrNotFound) {
							t.Fatalf("rejected function was admitted during rollback: %v", err)
						}
						return nil
					}
					rows, err := reader.EventSourceMappings(service.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"})
					if err == nil && len(rows) != 0 {
						t.Fatalf("rejected mapping was admitted during rollback: %+v", rows)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCFNLambdaPartialAdmissionRecoveryDeletesExactOwner(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"Function", "EventSourceMapping"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				var f *cfnLambdaAdditionalFixture
				var r cloudformation.ResourceRequest
				var physicalID string
				if kind == "Function" {
					f = newCFNLambdaAdditionalFixture(t, backend)
					var key service.FunctionKey
					r, key = cfnLambdaSeedDeployment(t, f)
					physicalID = key.Name
				} else {
					var sources []string
					f, sources, _ = cfnLambdaMappingNativeFixture(t, backend)
					r = cfnLambdaAdditionalRequest("AWS::Lambda::EventSourceMapping", cloudformation.Properties{"FunctionName": "configured", "EventSourceArn": sources[0], "Enabled": false})
					admitted, err := (cfnLambdaMapping{f.commands}).Create(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					physicalID = admitted.PhysicalID
				}
				f.reopen(t)
				r.PhysicalID = ""
				// Recovery cannot depend on replay validation after native admission.
				r.Properties = cloudformation.Properties{"FunctionName": "configured"}
				controller, repository, commands := cfnLambdaRecoveryController(t, f)
				after := cloudformation.ResourceRecord{StackID: r.StackID, LogicalID: r.LogicalID, Type: r.Type, Token: r.Token, Generation: 1, Current: true, Properties: r.Properties}
				stack := cloudformation.StackRecord{Scope: r.Scope, ID: r.StackID, Name: r.StackName, Status: "ROLLBACK_IN_PROGRESS", OperationID: "lost-admission", Created: f.manual.Now()}
				op := cloudformation.OperationRecord{ID: stack.OperationID, StackID: stack.ID, Kind: "CREATE", Phase: "ROLLBACK", Reason: "lost native admission reply", Revision: 1, Due: f.manual.Now(), Caller: awsctx.FromContext(f.ctx), Steps: []cloudformation.StepRecord{{LogicalID: r.LogicalID, Action: "CREATE", State: "FAILED_CREATE_RECOVERING", After: after}}}
				if err := repository.Update(f.ctx, func(tx cloudformation.Transaction) error {
					if err := tx.PutStack(stack); err != nil {
						return err
					}
					if err := tx.PutResource(after); err != nil {
						return err
					}
					return tx.PutOperation(op)
				}); err != nil {
					t.Fatal(err)
				}
				cfnLambdaRecoveryDrain(t, f, controller, commands, stack.Name)
				if err := f.repo.View(f.ctx, func(reader service.Reader) error {
					scope := service.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
					var err error
					if kind == "Function" {
						_, err = reader.Function(service.FunctionKey{Scope: scope, Name: physicalID})
					} else {
						_, err = reader.EventSourceMapping(service.EventSourceMappingKey{Scope: scope, UUID: physicalID})
					}
					if !errors.Is(err, service.ErrNotFound) {
						t.Fatalf("exact recovered native owner survived rollback: %v", err)
					}
					if _, err := reader.Function(service.FunctionKey{Scope: scope, Name: "configured"}); kind == "EventSourceMapping" && err != nil {
						t.Fatalf("mapping rollback deleted its unrelated native function: %v", err)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := repository.View(f.ctx, func(reader cloudformation.Reader) error {
					retained, err := reader.Operation(op.ID)
					if err == nil && retained.Steps[0].After.PhysicalID != physicalID {
						t.Fatalf("rollback lost recovered exact identity: %+v", retained.Steps[0])
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCFNLambdaFunctionRecoveryRejectsForeignRecreationAndCurrentIAMDeny(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			r, key := cfnLambdaSeedDeployment(t, f)
			r.PhysicalID, r.CloudControl = "", true
			f.reopen(t)
			h := cfnLambdaFunction{f.commands}
			f.authority.denied = "lambda:GetFunctionConfiguration"
			if result, err := h.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("recovery bypassed current read IAM: %+v %v", result, err)
			}
			absent := r
			absent.Token = "never-admitted-incarnation"
			absent.Properties = cloudformation.Properties{"FunctionName": "never-admitted"}
			if result, err := h.RecoverCreation(f.ctx, absent); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("unauthorized observation certified absence: %+v %v", result, err)
			}
			f.authority.denied = ""
			if result, err := h.RecoverCreation(f.ctx, absent); !cfnComputeMissing(err) || result.PhysicalID != "" {
				t.Fatalf("authoritative absence was not modeled: %+v %v", result, err)
			}
			absent.Properties = cloudformation.Properties{"FunctionName": "invalid name"}
			if result, err := h.RecoverCreation(f.ctx, absent); !cfnComputeMissing(err) || result.PhysicalID != "" {
				t.Fatalf("recovery revalidated a rejected function name: %+v %v", result, err)
			}
			if err := f.repo.Update(f.ctx, func(tx service.Transaction) error {
				record, err := tx.Function(key)
				if err != nil {
					return err
				}
				if err := tx.DeleteFunction(key); err != nil {
					return err
				}
				record.Owner = service.FunctionOwner{}
				record.Revision = "foreign-recreation"
				record.Tags = maps.Clone(cfnComputeOwnedTags(r))
				return tx.PutFunction(record)
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h.commands = f.commands
			if result, err := h.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("same-name native recreation or copied tags were adopted: %+v %v", result, err)
			}
			r.CloudControl = false
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("foreign recreation was deleted: %v", err)
			}
			if current := cfnLambdaDeploymentRecord(t, f, key); current.Revision != "foreign-recreation" || current.Owner != (service.FunctionOwner{}) {
				t.Fatalf("foreign native object was changed: %+v", current)
			}
		})
	}
}

type cfnLambdaRecoveryUnavailableRepository struct{ service.Repository }

func (cfnLambdaRecoveryUnavailableRepository) View(context.Context, func(service.Reader) error) error {
	return errors.New("native observation unavailable")
}

func TestCFNLambdaCreationRecoveryPreservesUnknownObservationErrors(t *testing.T) {
	f := newCFNLambdaAdditionalFixture(t, "memory")
	native := service.New(service.Config{Repository: cfnLambdaRecoveryUnavailableRepository{f.repo}, Clock: f.manual, Authorizer: f.authority})
	t.Cleanup(func() { _ = native.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"lambda": native})
	for _, h := range []cloudformation.ResourceCreationRecoverer{cfnLambdaFunction{commands}, cfnLambdaMapping{commands}} {
		r := cfnLambdaAdditionalRequest("AWS::Lambda::Function", cloudformation.Properties{"FunctionName": "configured"})
		if result, err := h.RecoverCreation(f.ctx, r); err == nil || cfnComputeMissing(err) || result.PhysicalID != "" {
			t.Fatalf("unknown native failure was suppressed or certified absent: %+v %v", result, err)
		}
	}
}

func TestCFNLambdaMappingRecoveryRejectsCopiedTagsAndCurrentIAMDeny(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, sources, deny := cfnLambdaMappingNativeFixture(t, backend)
			r := cfnLambdaAdditionalRequest("AWS::Lambda::EventSourceMapping", cloudformation.Properties{"FunctionName": "configured", "EventSourceArn": sources[0], "Enabled": false})
			h := cfnLambdaMapping{f.commands}
			admitted, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.CloudControl = true
			r.Properties = cloudformation.Properties{}
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.RecoverCreation(f.ctx, r)
			if err != nil || recovered.PhysicalID != admitted.PhysicalID {
				t.Fatalf("lost UUID recovery revalidated properties or lost private claim: %+v %v", recovered, err)
			}
			deny("lambda:ListEventSourceMappings")
			if result, err := h.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("private lookup bypassed current IAM: %+v %v", result, err)
			}
			deny()
			foreign := cfnLambdaMappingNativeRecord(t, f, admitted.PhysicalID)
			if err := cfnMessagingExec(f.ctx, f.commands, "lambda", "TagResource", &api.TagResourceInput{Resource: new(api.TaggableResource(foreign.Key.ARN())), Tags: api.Tags{api.TagKey(cfnComputeTagPrefix + "stack-id"): api.TagValue(r.StackID), api.TagKey(cfnComputeTagPrefix + "logical-id"): api.TagValue(r.LogicalID), api.TagKey(cfnComputeTagPrefix + "incarnation"): api.TagValue(r.Token)}}); err != nil {
				t.Fatal(err)
			}
			foreign = cfnLambdaMappingNativeRecord(t, f, admitted.PhysicalID)
			if err := f.repo.Update(f.ctx, func(tx service.Transaction) error {
				if err := tx.DeleteEventSourceMapping(foreign.Key); err != nil {
					return err
				}
				foreign.Owner = service.MappingOwner{}
				return tx.PutEventSourceMapping(foreign)
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h.commands = f.commands
			if result, err := h.RecoverCreation(f.ctx, r); !cfnComputeMissing(err) || result.PhysicalID != "" {
				t.Fatalf("copied public tags recovered an unclaimed native mapping: %+v %v", result, err)
			}
			r.CloudControl = false
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = admitted.PhysicalID
			if result, err := h.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("same-UUID foreign recreation was adopted: %+v %v", result, err)
			}
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("foreign mapping was deleted: %v", err)
			}
			current := cfnLambdaMappingNativeRecord(t, f, admitted.PhysicalID)
			if current.Owner != (service.MappingOwner{}) || current.State != foreign.State {
				t.Fatalf("foreign mapping changed during recovery: %+v", current)
			}
		})
	}
}
