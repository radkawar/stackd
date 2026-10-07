package integrations

import (
	"encoding/json"
	"maps"
	"reflect"
	"testing"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/iam"
	"stackd/internal/services/lambda"
	"stackd/internal/services/sqs"
)

// Disabled mappings admit real configuration through IAM and the native SQS
// owner without claiming customer execution or supplying a synthetic runtime.
func cfnLambdaMappingNativeFixture(t *testing.T, backend string) (*cfnLambdaAdditionalFixture, []string, func(...string)) {
	t.Helper()
	f := newCFNLambdaAdditionalFixture(t, backend)
	root := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	scope := iam.Scope{Partition: "aws", AccountID: "111111111111"}
	repository := iam.NewMemoryRepository(nil)
	role := iam.Role{Arn: "arn:aws:iam::111111111111:role/execution", RoleName: "execution", RoleId: "AROAMAPPINGEXECUTION", MaxSessionDuration: 3600, AssumeRolePolicyDocument: `{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`, IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"consume": `{"Statement":{"Effect":"Allow","Action":["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes"],"Resource":"arn:aws:sqs:us-east-1:111111111111:mapping-*"}}`}}}
	user := iam.User{Arn: "arn:aws:iam::111111111111:user/mapping-deployer", UserName: "mapping-deployer", UserId: "AIDAMAPPINGDEPLOYER", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"lambda": `{"Statement":{"Effect":"Allow","Action":"lambda:*","Resource":"*"}}`}}}
	if err := repository.Update(root, func(tx iam.WriteTx) error {
		if err := tx.PutRole(scope, role); err != nil {
			return err
		}
		return tx.PutUser(scope, user)
	}); err != nil {
		t.Fatal(err)
	}
	credentials := identity.NewWithConfig(identity.Config{AccountID: scope.AccountID, Repository: iam.NewCredentialRepository(repository, nil), Clock: f.manual})
	iamOwner := iam.NewWithConfig(iam.Config{Repository: repository, Credentials: credentials, Clock: f.manual})
	authority := authorization.NewWithClock(iamOwner, nil, f.manual)
	queues := sqs.NewWithConfig(sqs.Config{Authorizer: authority, Clock: f.manual})
	t.Cleanup(func() {
		if err := queues.Close(); err != nil {
			t.Error(err)
		}
	})
	queueCommands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"sqs": queues})
	sources := make([]string, 3)
	for i, name := range []string{"mapping-stack", "mapping-cloudcontrol", "mapping-foreign"} {
		if _, err := cfnMessagingCall[sqsapi.CreateQueueOutput](root, queueCommands, "sqs", "CreateQueue", &sqsapi.CreateQueueInput{QueueName: new(sqsapi.String(name))}); err != nil {
			t.Fatal(err)
		}
		sources[i] = "arn:aws:sqs:us-east-1:111111111111:" + name
	}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: scope.AccountID, Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId, UserName: user.UserName})
	f.authorizer = authority
	f.source = LambdaSQS{Roles: ServiceRoles{IAM: iamOwner, Credentials: credentials, Authorizer: authority}, Queues: queues}
	if err := f.service.Close(); err != nil {
		t.Fatal(err)
	}
	f.open()
	deny := func(actions ...string) {
		delete(user.IdentityPolicies.Inline, "deny")
		if len(actions) > 0 {
			body, err := json.Marshal(map[string]any{"Statement": map[string]any{"Effect": "Deny", "Action": actions, "Resource": "*"}})
			if err != nil {
				t.Fatal(err)
			}
			user.IdentityPolicies.Inline["deny"] = string(body)
		}
		if err := repository.Update(root, func(tx iam.WriteTx) error { return tx.PutUser(scope, user) }); err != nil {
			t.Fatal(err)
		}
	}
	return f, sources, deny
}

func cfnLambdaMappingNativeRecord(t *testing.T, f *cfnLambdaAdditionalFixture, id string) lambda.EventSourceMappingRecord {
	t.Helper()
	key := lambda.EventSourceMappingKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, UUID: id}
	var record lambda.EventSourceMappingRecord
	if err := f.repo.View(f.ctx, func(reader lambda.Reader) error {
		var err error
		record, err = reader.EventSourceMapping(key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestCFNLambdaMappingPrivateAdmissionRecoveryAndNativeMutation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, sources, deny := cfnLambdaMappingNativeFixture(t, backend)
			h := cfnLambdaMapping{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::EventSourceMapping", cloudformation.Properties{"FunctionName": "configured", "EventSourceArn": sources[0], "Enabled": false, "BatchSize": 10, "Tags": []any{map[string]any{"Key": "customer", "Value": "visible"}}})
			admitted, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			cc := r
			cc.CloudControl = true
			cc.StackID, cc.Token = "cloudcontrol-admission", "cloudcontrol-token"
			cc.Properties = maps.Clone(r.Properties)
			cc.Properties["EventSourceArn"] = sources[1]
			ccAdmitted, err := h.Create(f.ctx, cc)
			if err != nil {
				t.Fatal(err)
			}
			// Neither caller retained the admission reply's UUID before reopening.
			f.reopen(t)
			h.commands = f.commands
			recovered, err := h.Create(f.ctx, r)
			if err != nil || recovered.PhysicalID != admitted.PhysicalID {
				t.Fatalf("lost stack reply did not recover exact private admission: %+v %v", recovered, err)
			}
			ccRecovered, err := h.Create(f.ctx, cc)
			if err != nil || ccRecovered.PhysicalID != ccAdmitted.PhysicalID {
				t.Fatalf("lost Cloud Control reply did not recover exact private admission: %+v %v", ccRecovered, err)
			}
			r.PhysicalID = admitted.PhysicalID
			cc.PhysicalID = ccAdmitted.PhysicalID
			original := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID)
			if original.Owner != (lambda.MappingOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}) {
				t.Fatalf("mapping admission did not retain its typed private claim: %+v", original.Owner)
			}
			for _, suffix := range []string{"stack-id", "logical-id", "incarnation"} {
				if _, present := original.Tags[cfnComputeTagPrefix+suffix]; present {
					t.Fatal("mapping creation emitted obsolete public owner markers")
				}
			}
			deny("lambda:CreateEventSourceMapping")
			if _, err := h.Create(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("private replay bypassed current create IAM: %v", err)
			}
			deny()
			public := api.Tags{api.TagKey(cfnComputeTagPrefix + "stack-id"): "forged", api.TagKey(cfnComputeTagPrefix + "logical-id"): "forged", api.TagKey(cfnComputeTagPrefix + "incarnation"): "forged"}
			if err := cfnMessagingExec(f.ctx, f.commands, "lambda", "TagResource", &api.TagResourceInput{Resource: new(api.TaggableResource(original.Key.ARN())), Tags: public}); err != nil {
				t.Fatal(err)
			}
			if result, err := h.Create(f.ctx, r); err != nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("public tag replacement revoked private admission: %+v %v", result, err)
			}
			if err := cfnMessagingExec(f.ctx, f.commands, "lambda", "UntagResource", &api.UntagResourceInput{Resource: new(api.TaggableResource(original.Key.ARN())), TagKeys: api.TagKeyList{api.TagKey(cfnComputeTagPrefix + "stack-id"), api.TagKey(cfnComputeTagPrefix + "logical-id"), api.TagKey(cfnComputeTagPrefix + "incarnation")}}); err != nil {
				t.Fatal(err)
			}
			if result, err := h.Create(f.ctx, r); err != nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("removing public tags revoked private admission: %+v %v", result, err)
			}
			foreign, err := cfnMessagingCall[api.CreateEventSourceMappingOutput](f.ctx, f.commands, "lambda", "CreateEventSourceMapping", &api.CreateEventSourceMappingInput{FunctionName: new(api.NamespacedFunctionName("configured")), EventSourceArn: new(api.Arn(sources[2])), Enabled: new(api.Enabled(false))})
			if err != nil {
				t.Fatal(err)
			}
			foreignID := cfnComputeValue(foreign.UUID)
			counterfeit := r
			counterfeit.CloudControl = true
			counterfeit.StackID, counterfeit.Token = "counterfeit-request", "counterfeit-token"
			counterfeit.PhysicalID = foreignID
			counterfeit.Properties = maps.Clone(r.Properties)
			counterfeit.Properties["EventSourceArn"] = sources[2]
			for key, value := range cfnComputeOwnedTags(counterfeit) {
				public[api.TagKey(key)] = api.TagValue(value)
			}
			foreignRecord := cfnLambdaMappingNativeRecord(t, f, foreignID)
			if err := cfnMessagingExec(f.ctx, f.commands, "lambda", "TagResource", &api.TagResourceInput{Resource: new(api.TaggableResource(foreignRecord.Key.ARN())), Tags: public}); err != nil {
				t.Fatal(err)
			}
			if result, err := h.Create(f.ctx, counterfeit); !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != "" {
				t.Fatalf("public tags claimed foreign UUID: %+v %v", result, err)
			}
			counterfeit.PhysicalID = ""
			if result, err := h.Create(f.ctx, counterfeit); !cfnMessagingMissing(err, "ResourceConflictException") || result.PhysicalID != "" {
				t.Fatalf("public tags recovered an unclaimed native row: %+v %v", result, err)
			}
			if record := cfnLambdaMappingNativeRecord(t, f, foreignID); record.Owner != (lambda.MappingOwner{}) {
				t.Fatalf("failed private create adopted foreign native mapping: %+v", record.Owner)
			}
			if err := f.repo.Update(f.ctx, func(tx lambda.Transaction) error {
				record, err := tx.EventSourceMapping(original.Key)
				if err != nil {
					return err
				}
				if err := tx.DeleteEventSourceMapping(original.Key); err != nil {
					return err
				}
				record.Owner = lambda.MappingOwner{}
				for key, value := range cfnComputeOwnedTags(r) {
					record.Tags[key] = value
				}
				return tx.PutEventSourceMapping(record)
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h.commands = f.commands
			recreated := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID)
			stale := r
			stale.Properties = maps.Clone(r.Properties)
			stale.Properties["BatchSize"] = 5
			if _, err := h.Update(f.ctx, stale); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("stale stack update reached foreign recreation: %v", err)
			}
			if ready, err := h.Stabilize(f.ctx, stale); ready || !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("stale stack convergence reached foreign recreation: %v %v", ready, err)
			}
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("stale stack deletion reached foreign recreation: %v", err)
			}
			lostID := r
			lostID.PhysicalID = ""
			if err := h.Delete(f.ctx, lostID); err != nil {
				t.Fatal(err)
			}
			if after := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID); !reflect.DeepEqual(after, recreated) {
				t.Fatal("stale stack commands changed recreated native mapping")
			}
			beforeCC := cfnLambdaMappingNativeRecord(t, f, cc.PhysicalID)
			mutation := cc
			mutation.StackID, mutation.Token = "ordinary-update", "ordinary-update-token"
			mutation.Properties = maps.Clone(cc.Properties)
			mutation.Properties["BatchSize"] = 6
			deny("lambda:UpdateEventSourceMapping")
			if ready, err := h.Stabilize(f.ctx, mutation); ready || !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("ordinary Cloud Control update bypassed native IAM: %v %v", ready, err)
			}
			deny()
			if _, err := h.Update(f.ctx, mutation); err != nil {
				t.Fatal(err)
			}
			if ready, err := h.Stabilize(f.ctx, mutation); ready || err != nil {
				t.Fatalf("native mapping update admission: %v %v", ready, err)
			}
			if ready, err := h.Stabilize(f.ctx, mutation); !ready || err != nil {
				t.Fatalf("disabled native mapping did not converge: %v %v", ready, err)
			}
			afterCC := cfnLambdaMappingNativeRecord(t, f, cc.PhysicalID)
			if afterCC.Settings.BatchSize != 6 || afterCC.Owner != beforeCC.Owner {
				t.Fatalf("ordinary mutation lost native configuration or adopted its claim: %+v", afterCC)
			}
			deny("lambda:DeleteEventSourceMapping")
			if err := h.Delete(f.ctx, mutation); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("ordinary Cloud Control delete bypassed native IAM: %v", err)
			}
			deny()
			if err := h.Delete(f.ctx, mutation); err != nil {
				t.Fatal(err)
			}
			if err := f.manual.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.JobDriver().RunDue(f.ctx, 20); err != nil {
				t.Fatal(err)
			}
			if ready, err := h.StabilizeDeletion(f.ctx, mutation); !ready || err != nil {
				t.Fatalf("native mapping deletion did not complete: %v %v", ready, err)
			}
			if after := cfnLambdaMappingNativeRecord(t, f, r.PhysicalID); !reflect.DeepEqual(after, recreated) {
				t.Fatal("ordinary Cloud Control deletion touched the foreign recreation")
			}
		})
	}
}
