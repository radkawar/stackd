package cloudformation

import (
	"reflect"
	"strings"
	"testing"

	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awsctx"
)

const conditionalLifecycleTemplate = `
Parameters:
  Mode: {Type: String, Default: dev}
Conditions:
  Production: !Equals [!Ref Mode, prod]
Mappings:
  Policies:
    aws: {Production: Retain}
Resources:
  Association:
    Type: AWS::EC2::SubnetRouteTableAssociation
    DeletionPolicy: !If [Production, !FindInMap [Policies, !Ref 'AWS::Partition', Production], Delete]
    UpdateReplacePolicy: !If [Production, Retain, Delete]
    Properties: {SubnetId: subnet, RouteTableId: original}
`

func TestLifecyclePolicyExpressionsResolveWithoutTransform(t *testing.T) {
	template, err := ParseTemplate(conditionalLifecycleTemplate)
	if err != nil {
		t.Fatal(err)
	}
	raw := template.Resources["Association"].DeletionPolicy
	for _, mode := range []string{"dev", "prod"} {
		policies, err := template.ResolvePolicies(Evaluation{Scope: Scope{Partition: "aws"}, Parameters: map[string]string{"Mode": mode}})
		if err != nil {
			t.Fatal(err)
		}
		want := "Delete"
		if mode == "prod" {
			want = "Retain"
		}
		if policies["Association"] != (ResourcePolicies{want, want}) {
			t.Fatalf("%s: %#v", mode, policies)
		}
	}
	if !reflect.DeepEqual(raw, template.Resources["Association"].DeletionPolicy) {
		t.Fatal("resolution mutated customer expression")
	}
}

func TestLifecyclePoliciesRejectForbiddenExpressionsBeforeProvisioning(t *testing.T) {
	for _, expression := range []string{
		"!Ref Association", "!Ref 'AWS::StackId'", "!Ref 'AWS::StackName'", "!Ref 'AWS::NotificationARNs'", "!Ref 'AWS::URLSuffix'", "!Ref 'AWS::NoValue'",
		"!GetAtt Association.Id", "!Sub Retain", "!Join ['', [Re, tain]]", "!ImportValue Policy", "!Select [0, [Retain]]", "!GetAZs ''", "{Fn::Length: [Retain]}",
		"!If [Production, Retain, !Ref Association]", "!If [Production, Retain, Typo]", "[Retain]", "null",
	} {
		t.Run(expression, func(t *testing.T) {
			body := strings.Replace(conditionalLifecycleTemplate, "!If [Production, !FindInMap [Policies, !Ref 'AWS::Partition', Production], Delete]", expression, 1)
			if _, err := ParseTemplate(body); err == nil {
				t.Fatal("forbidden expression admitted")
			}
		})
	}
	body := strings.Replace(conditionalLifecycleTemplate, "!Equals [!Ref Mode, prod]", "!Equals [!Ref 'AWS::StackName', prod]", 1)
	if _, err := ParseTemplate(body); err == nil {
		t.Fatal("forbidden pseudo parameter hidden in condition admitted")
	}
	template, err := ParseTemplate(strings.Replace(conditionalLifecycleTemplate, "!If [Production, Retain, Delete]", "!Ref Mode", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := template.ResolvePolicies(Evaluation{Scope: Scope{Partition: "aws"}, Parameters: map[string]string{"Mode": "Typo"}}); err == nil {
		t.Fatal("invalid bound policy admitted")
	}
}

func TestConditionalLifecyclePolicyCreateUpdateRestartDelete(t *testing.T) {
	for _, modes := range [][2]string{{"dev", "prod"}, {"prod", "dev"}} {
		t.Run(modes[0]+"-to-"+modes[1], func(t *testing.T) {
			s, repository, owner, _ := lifecycleFixture(t, "CREATE", "APPLY")
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
			var stack StackRecord
			if err := repository.Update(ctx, func(tx Transaction) error {
				var err error
				stack, err = tx.Stack("stack")
				if err != nil {
					return err
				}
				stack.Template, stack.OperationID = "", ""
				stack.Outputs = nil
				return tx.PutStack(stack)
			}); err != nil {
				t.Fatal(err)
			}
			deploy := func(kind, mode, token string) string {
				t.Helper()
				var id string
				err := repository.Update(ctx, func(tx Transaction) error {
					var err error
					stack, err = tx.Stack("stack")
					if err != nil {
						return err
					}
					params := map[string]string(nil)
					if kind != "DELETE" {
						_, params, _, err = s.prepare(tx, stack, conditionalLifecycleTemplate, api.Parameters{{ParameterKey: new(api.ParameterKey("Mode")), ParameterValue: new(api.ParameterValue(mode))}}, nil)
						if err != nil {
							return err
						}
						if kind == "UPDATE" {
							template, err := ParseTemplate(conditionalLifecycleTemplate)
							if err != nil {
								return err
							}
							changes, err := s.changes(tx, stack, template, params, nil, nil)
							if err != nil {
								return err
							}
							if len(changes) != 1 {
								t.Fatalf("policy-only update disappeared: %#v", changes)
							}
						}
					}
					err = s.begin(tx, stack, kind, conditionalLifecycleTemplate, params, nil, nil, nil, "", token, token, "", false)
					id = operationID(stack.ID, kind, token)
					return err
				})
				if err != nil {
					t.Fatal(err)
				}
				for range 40 {
					op := lifecycleRun(t, s, repository, id)
					if op.Phase == "DONE" {
						if op.Reason != "" {
							t.Fatalf("deployment failed: %s", op.Reason)
						}
						return id
					}
				}
				t.Fatal("operation did not finish")
				return ""
			}
			deploy("CREATE", modes[0], "create")
			deploy("UPDATE", modes[1], "update")
			var resource ResourceRecord
			if err := repository.View(ctx, func(r Reader) error {
				current, err := currentResources(r, "stack")
				resource = current["Association"]
				return err
			}); err != nil {
				t.Fatal(err)
			}
			want := "Delete"
			if modes[1] == "prod" {
				want = "Retain"
			}
			if resource.DeletionPolicy != want || resource.UpdateReplacePolicy != want {
				t.Fatalf("policy update not frozen: %+v", resource)
			}
			// A fresh controller sees only retained records, not prior parsed templates.
			restarted := New(Config{Repository: repository, Clock: s.clock, Handlers: s.handlers})
			t.Cleanup(func() { _ = restarted.Close() })
			s = restarted
			deploy("DELETE", "", "delete")
			_, live := owner.live[resource.PhysicalID]
			if live != (want == "Retain") {
				t.Fatalf("%s deletion retained native resource=%v", want, live)
			}
		})
	}
}

func TestConditionalLifecycleRollbackUsesFrozenPolicy(t *testing.T) {
	for _, mode := range []string{"dev", "prod"} {
		t.Run(mode, func(t *testing.T) {
			s, repository, owner, op := lifecycleFixture(t, "CREATE", "ROLLBACK")
			template, err := ParseTemplate(conditionalLifecycleTemplate)
			if err != nil {
				t.Fatal(err)
			}
			policies, err := template.ResolvePolicies(Evaluation{Scope: Scope{Partition: "aws"}, Parameters: map[string]string{"Mode": mode}})
			if err != nil {
				t.Fatal(err)
			}
			op.Kind, op.Template, op.Parameters = "CREATE", conditionalLifecycleTemplate, map[string]string{"Mode": mode}
			op.Steps[0].After.DeletionPolicy = policies["Association"].DeletionPolicy
			op.Steps[0].After.UpdateReplacePolicy = policies["Association"].UpdateReplacePolicy
			if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
				t.Fatal(err)
			}
			restarted := New(Config{Repository: repository, Clock: s.clock, Handlers: s.handlers})
			t.Cleanup(func() { _ = restarted.Close() })
			for range 40 {
				op = lifecycleRun(t, restarted, repository, op.ID)
				if op.Phase == "DONE" {
					break
				}
			}
			if op.Phase != "DONE" {
				t.Fatal("rollback did not finish")
			}
			_, live := owner.live["assoc-created"]
			if live != (mode == "prod") {
				t.Fatalf("rollback mode=%s live=%v", mode, live)
			}
		})
	}
}

func TestLifecyclePolicyResolvesBeforeSnapshotOwnerValidation(t *testing.T) {
	s, _, _, _ := lifecycleFixture(t, "CREATE", "APPLY")
	template, err := ParseTemplate(strings.Replace(conditionalLifecycleTemplate, "!If [Production, !FindInMap [Policies, !Ref 'AWS::Partition', Production], Delete]", "!Ref Mode", 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"Delete", "Retain", "RetainExceptOnCreate", "Snapshot", "Typo"} {
		err := template.validateResolvedPolicies(Evaluation{Scope: Scope{Partition: "aws"}, Parameters: map[string]string{"Mode": value}}, s.handlers)
		if (err == nil) != (value == "Delete" || value == "Retain" || value == "RetainExceptOnCreate") {
			t.Fatalf("bound policy=%s validation=%v", value, err)
		}
	}
}

func TestLifecyclePolicyIntentChangesRemainVisible(t *testing.T) {
	for _, replacement := range []struct{ old, next string }{
		{"!Equals [!Ref Mode, prod]", "!Equals [!Ref Mode, never]"},
		{"aws: {Production: Retain}", "aws: {Production: Delete}"},
		{"!If [Production, !FindInMap [Policies, !Ref 'AWS::Partition', Production], Delete]", "Retain"},
	} {
		s, repository, _, _ := lifecycleFixture(t, "UPSERT", "APPLY")
		var stack StackRecord
		if err := repository.Update(t.Context(), func(tx Transaction) error {
			var err error
			stack, err = tx.Stack("stack")
			if err != nil {
				return err
			}
			stack.Template, stack.Parameters = conditionalLifecycleTemplate, map[string]string{"Mode": "prod"}
			resources, err := currentResources(tx, stack.ID)
			if err != nil {
				return err
			}
			resource := resources["Association"]
			resource.DeletionPolicy, resource.UpdateReplacePolicy = "Retain", "Retain"
			if err := tx.PutResource(resource); err != nil {
				return err
			}
			return tx.PutStack(stack)
		}); err != nil {
			t.Fatal(err)
		}
		template, err := ParseTemplate(strings.Replace(conditionalLifecycleTemplate, replacement.old, replacement.next, 1))
		if err != nil {
			t.Fatal(err)
		}
		if err := repository.View(t.Context(), func(r Reader) error {
			changes, err := s.changes(r, stack, template, stack.Parameters, nil, nil)
			if err != nil {
				return err
			}
			if len(changes) != 1 || changes[0].Action != "Modify" || changes[0].Replacement != "False" {
				t.Fatalf("policy intent update disappeared: %#v", changes)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
