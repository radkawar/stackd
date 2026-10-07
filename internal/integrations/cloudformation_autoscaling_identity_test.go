package integrations

import (
	"context"
	"errors"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	asg "stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudformation"
)

func cfnScalingIdentityFixture(t *testing.T, backend string) (*cfnComputeOwnerFixture, cloudformation.ResourceRequest, string) {
	t.Helper()
	f := newCFNComputeOwnerFixture(t, backend, nil)
	group := f.base.group
	group.Data.AutoScalingGroupName = new(api.XmlStringMaxLen255("workers"))
	group.Data.MinSize = new(api.AutoScalingGroupMinSize(0))
	group.Data.MaxSize = new(api.AutoScalingGroupMaxSize(2))
	group.Data.DesiredCapacity = new(api.AutoScalingGroupDesiredCapacity(0))
	group.Data.DefaultCooldown = new(api.Cooldown(300))
	if err := f.asgRepo.Update(f.base.root, func(tx asg.Transaction) error { return tx.PutGroup(group) }); err != nil {
		t.Fatal(err)
	}
	r := f.request(cfnASGPolicyType, "Policy", cloudformation.Properties{"AutoScalingGroupName": "workers", "PolicyType": "SimpleScaling", "AdjustmentType": "ChangeInCapacity", "ScalingAdjustment": 1, "Cooldown": 0})
	f.create(t, &r)
	read := r
	read.Properties = nil
	model, err := f.handlers[r.Type].(cloudformation.ResourceReader).Read(f.base.root, read)
	if err != nil {
		t.Fatal(err)
	}
	name := cfnComputeString(model, "PolicyName")
	if name == "" || model["Arn"] != r.PhysicalID || model["AutoScalingGroupName"] != "workers" {
		t.Fatalf("full policy ARN did not recover native identity: %+v", model)
	}
	return f, r, name
}

func cfnScalingIdentityPolicies(t *testing.T, f *cfnComputeOwnerFixture) api.ScalingPolicies {
	t.Helper()
	return f.native(t, "autoscaling", "DescribePolicies", map[string]any{"AutoScalingGroupName": "workers"}).(*api.DescribePoliciesOutput).ScalingPolicies
}

func cfnScalingIdentityUnchanged(t *testing.T, f *cfnComputeOwnerFixture, arn string, adjustment int) {
	t.Helper()
	policies := cfnScalingIdentityPolicies(t, f)
	if len(policies) != 1 || cfnComputeValue(policies[0].PolicyARN) != arn || int(*policies[0].ScalingAdjustment) != adjustment {
		t.Fatalf("consumer identifier changed the native policy: %+v", policies)
	}
}

func TestComputeScalingPolicyForeignFullIdentityCannotReachLocalPolicy(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, owned, _ := cfnScalingIdentityFixture(t, backend)
			f.reopen(t)
			for _, component := range []struct {
				name  string
				index int
				value string
			}{
				{"partition", 1, "aws-cn"},
				{"region", 3, "us-west-2"},
				{"account", 4, "999999999999"},
				{"policy-uuid", 6, "00000000-0000-4000-8000-000000000099"},
			} {
				t.Run(component.name, func(t *testing.T) {
					parts := strings.Split(owned.PhysicalID, ":")
					parts[component.index] = component.value
					foreign := owned
					foreign.CloudControl = true
					foreign.PhysicalID = strings.Join(parts, ":")
					foreign.Properties = nil
					if _, err := f.handlers[foreign.Type].(cloudformation.ResourceReader).Read(f.base.root, foreign); !cfnCSMissing(err) {
						t.Fatalf("foreign full ARN read local policy: %v", err)
					}
					foreign.Previous = owned.Properties
					foreign.Properties = cfnComputeCopy(owned.Properties, "AutoScalingGroupName", "PolicyType", "AdjustmentType", "Cooldown")
					foreign.Properties["ScalingAdjustment"] = 9
					if _, err := f.handlers[foreign.Type].Update(f.base.root, foreign); !cfnCSMissing(err) {
						t.Fatalf("foreign full ARN updated local policy: %v", err)
					}
					cfnScalingIdentityUnchanged(t, f, owned.PhysicalID, 1)
					if err := f.handlers[foreign.Type].Delete(f.base.root, foreign); err != nil {
						t.Fatalf("absent foreign policy delete: %v", err)
					}
					cfnScalingIdentityUnchanged(t, f, owned.PhysicalID, 1)
				})
			}
		})
	}
}

func TestComputeScalingPolicyDeletedARNCannotReachNativeSameNameReplacement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, stale, name := cfnScalingIdentityFixture(t, backend)
			f.native(t, "autoscaling", "DeletePolicy", map[string]any{"PolicyName": stale.PhysicalID})
			replacement := f.native(t, "autoscaling", "PutScalingPolicy", map[string]any{"AutoScalingGroupName": "workers", "PolicyName": name, "AdjustmentType": "ChangeInCapacity", "ScalingAdjustment": 2, "Cooldown": 0}).(*api.PutScalingPolicyOutput)
			arn := cfnComputeValue(replacement.PolicyARN)
			if arn == stale.PhysicalID {
				t.Fatal("native recreation reused immutable policy identity")
			}
			f.reopen(t)
			stale.CloudControl = true
			if _, err := f.handlers[stale.Type].(cloudformation.ResourceReader).Read(f.base.root, stale); !cfnCSMissing(err) {
				t.Fatalf("stale ARN read native replacement: %v", err)
			}
			stale.Previous = stale.Properties
			stale.Properties = cfnComputeCopy(stale.Properties, "AutoScalingGroupName", "PolicyType", "AdjustmentType", "Cooldown")
			stale.Properties["ScalingAdjustment"] = 9
			if _, err := f.handlers[stale.Type].Update(f.base.root, stale); !cfnCSMissing(err) {
				t.Fatalf("stale ARN updated native replacement: %v", err)
			}
			cfnScalingIdentityUnchanged(t, f, arn, 2)
			if err := f.handlers[stale.Type].Delete(f.base.root, stale); err != nil {
				t.Fatal(err)
			}
			cfnScalingIdentityUnchanged(t, f, arn, 2)
			// An ordinary native upsert still updates the replacement in place.
			out := f.native(t, "autoscaling", "PutScalingPolicy", map[string]any{"AutoScalingGroupName": "workers", "PolicyName": name, "ScalingAdjustment": 3}).(*api.PutScalingPolicyOutput)
			if cfnComputeValue(out.PolicyARN) != arn {
				t.Fatal("ordinary native upsert changed immutable identity")
			}
			cfnScalingIdentityUnchanged(t, f, arn, 3)
		})
	}
}

// This barrier is after the adapter's successful native read, before the real
// mutation enters its native transaction. No engine or repository is simulated.
type cfnScalingMutationBarrier struct {
	owner     awscommands.CommandExecutor
	operation string
	before    func()
}

func (b *cfnScalingMutationBarrier) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if string(r.Operation.Name) == b.operation && b.before != nil {
		before := b.before
		b.before = nil
		before()
	}
	return b.owner.ExecuteCommand(ctx, r)
}

func TestComputeScalingPolicyMutationFencesReadMutationRace(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, operation := range []string{"PutScalingPolicy", "DeletePolicy"} {
			for _, recreate := range []bool{false, true} {
				name := backend + "/" + operation + "/absent"
				if recreate {
					name = backend + "/" + operation + "/replacement"
				}
				t.Run(name, func(t *testing.T) {
					f, r, name := cfnScalingIdentityFixture(t, backend)
					f.reopen(t)
					r.CloudControl = true
					r.Previous = r.Properties
					r.Properties = cfnComputeCopy(r.Properties, "AutoScalingGroupName", "PolicyType", "AdjustmentType", "Cooldown")
					r.Properties["ScalingAdjustment"] = 9
					replacementARN := ""
					barrier := &cfnScalingMutationBarrier{owner: f.groups, operation: operation, before: func() {
						f.native(t, "autoscaling", "DeletePolicy", map[string]any{"PolicyName": r.PhysicalID})
						if recreate {
							out := f.native(t, "autoscaling", "PutScalingPolicy", map[string]any{"AutoScalingGroupName": "workers", "PolicyName": name, "AdjustmentType": "ChangeInCapacity", "ScalingAdjustment": 2, "Cooldown": 0}).(*api.PutScalingPolicyOutput)
							replacementARN = cfnComputeValue(out.PolicyARN)
						}
					}}
					handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"autoscaling": barrier}))
					var err error
					if operation == "PutScalingPolicy" {
						_, err = handlers[r.Type].Update(f.base.root, r)
					} else {
						err = handlers[r.Type].Delete(f.base.root, r)
					}
					var native *awswire.Error
					if !errors.As(err, &native) || native.Code != "ValidationError" {
						t.Fatalf("read-mutation race did not retain the native policy error: %v", err)
					}
					if barrier.before != nil {
						t.Fatal("mutation barrier was not reached")
					}
					if recreate {
						cfnScalingIdentityUnchanged(t, f, replacementARN, 2)
					} else if policies := cfnScalingIdentityPolicies(t, f); len(policies) != 0 {
						t.Fatalf("stale mutation resurrected a deleted policy: %+v", policies)
					}
				})
			}
		}
	}
}

func TestComputeScalingPolicyARNFenceRetainsCurrentNativeIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, r, _ := cfnScalingIdentityFixture(t, backend)
			f.reopen(t)
			identity := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"iam": f.identity})
			putPolicy := func(document string) {
				t.Helper()
				if err := cfnComputeRun(f.base.root, identity, "iam", "PutUserPolicy", map[string]any{"UserName": f.base.user.UserName, "PolicyName": "policy-identity", "PolicyDocument": document}); err != nil {
					t.Fatal(err)
				}
			}
			putPolicy(`{"Statement":{"Effect":"Allow","Action":"autoscaling:*","Resource":"*"}}`)
			r.CloudControl = true
			r.Previous = r.Properties
			r.Properties = cfnComputeCopy(r.Properties, "AutoScalingGroupName", "PolicyType", "AdjustmentType", "Cooldown")
			r.Properties["ScalingAdjustment"] = 9
			barrier := &cfnScalingMutationBarrier{owner: f.groups, operation: "PutScalingPolicy", before: func() {
				putPolicy(`{"Statement":[{"Effect":"Allow","Action":"autoscaling:Describe*","Resource":"*"},{"Effect":"Deny","Action":"autoscaling:PutScalingPolicy","Resource":"*"}]}`)
			}}
			handlers := CloudFormationComputeServiceHandlers(NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"autoscaling": barrier}))
			_, err := handlers[r.Type].Update(f.base.caller, r)
			var denied *awswire.Error
			if barrier.before != nil || !errors.As(err, &denied) || denied.Code != "AccessDenied" {
				t.Fatalf("immutable identity fence bypassed current native IAM: %v", err)
			}
			cfnScalingIdentityUnchanged(t, f, r.PhysicalID, 1)
		})
	}
}
