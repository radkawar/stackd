package cloudformation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ssm"
)

type dynamicSSMOwner struct {
	t          *testing.T
	service    *ssm.Service
	repository *lifecycleRepository
	calls      []string
}

func (s *dynamicSSMOwner) command(ctx context.Context, name string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("ssm")
	op, _ := model.Operation(name)
	return s.service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}
func (s *dynamicSSMOwner) ResolveParameter(ctx context.Context, name string) (string, error) {
	value, _, err := s.ResolveParameterVersion(ctx, name)
	return value, err
}
func (s *dynamicSSMOwner) ResolveParameterVersion(ctx context.Context, name string) (string, int64, error) {
	if s.repository.inside {
		s.t.Fatal("SSM lookup ran in a CloudFormation transaction")
	}
	s.calls = append(s.calls, name)
	out, err := s.command(ctx, "GetParameters", &api.GetParametersRequest{Names: api.ParameterNameList{api.PSParameterName(name)}})
	if err != nil {
		return "", 0, err
	}
	result := out.(*api.GetParametersResult)
	if len(result.Parameters) != 1 {
		return "", 0, &awswire.Error{Code: "ParameterNotFound", Message: "parameter not found"}
	}
	p := result.Parameters[0]
	if string(*p.Type) != "String" {
		return "", 0, &awswire.Error{Code: "ValidationError", Message: "SecureString is unsupported"}
	}
	return string(*p.Value), int64(*p.Version), nil
}
func (s *dynamicSSMOwner) put(ctx context.Context, name, value string) {
	s.t.Helper()
	_, err := s.command(ctx, "PutParameter", &api.PutParameterRequest{Name: new(api.PSParameterName(name)), Value: new(api.PSParameterValue(value)), Type: new(api.ParameterType("String")), Overwrite: new(api.Boolean(true))})
	if err != nil {
		s.t.Fatal(err)
	}
}

func TestDynamicSSMOperationPinsVersionWithoutPlaintextPersistence(t *testing.T) {
	s, repository, owner, op := lifecycleFixture(t, "UPSERT", "APPLY")
	parameterOwner := ssm.New(ssm.Config{Repository: ssm.NewMemoryRepository(nil)})
	t.Cleanup(func() { _ = parameterOwner.Close() })
	source := &dynamicSSMOwner{t: t, service: parameterOwner, repository: repository}
	s.parameters = source
	ctx := awsctx.WithMetadata(t.Context(), op.Caller)
	source.put(ctx, "/guard/subnet", "subnet-selected-first")
	op.Template = `{"Resources":{"Association":{"Type":"AWS::EC2::SubnetRouteTableAssociation","Properties":{"SubnetId":{"Fn::Sub":"{{resolve:ssm:/guard/${Name}}}"},"RouteTableId":"original"}}},"Parameters":{"Name":{"Type":"String","Default":"subnet"}}}`
	op.Parameters = map[string]string{"Name": "subnet"}
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
		t.Fatal(err)
	}
	template, err := ParseTemplate(op.Template)
	if err != nil {
		t.Fatal(err)
	}
	props, err := template.ResolveResource("Association", Evaluation{Parameters: op.Parameters})
	if err != nil || props["SubnetId"] != "{{resolve:ssm:/guard/subnet}}" || len(source.calls) != 0 {
		t.Fatalf("read-only evaluation fetched or replaced SSM: %#v %v %v", props, err, source.calls)
	}
	op = lifecycleRun(t, s, repository, op.ID)
	if op.Steps[0].After.DynamicReferences["{{resolve:ssm:/guard/subnet}}"] != 1 || op.Steps[0].State != "PENDING" || len(owner.calls) != 0 {
		t.Fatalf("resolution did not retain a selector before the effect: %+v calls=%v", op.Steps[0], owner.calls)
	}
	source.put(ctx, "/guard/subnet", "subnet-selected-second")
	op = lifecycleRun(t, s, repository, op.ID)
	if owner.live["assoc-original"]["SubnetId"] != "subnet-selected-first" {
		t.Fatalf("effect drifted from retained version: %v", owner.live)
	}
	if source.calls[len(source.calls)-1] != "/guard/subnet:1" {
		t.Fatalf("retry did not authorize pinned owner read: %v", source.calls)
	}
	if err := repository.View(t.Context(), func(reader Reader) error {
		op, err := reader.Operation(op.ID)
		if err != nil {
			return err
		}
		events, err := reader.Events(op.StackID)
		if err != nil {
			return err
		}
		resources, err := reader.Resources(op.StackID)
		if err != nil {
			return err
		}
		body, err := json.Marshal([]any{op, events, resources})
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "subnet-selected-first") || strings.Contains(string(body), "subnet-selected-second") {
			t.Fatalf("resolved plaintext persisted in CFN state: %s", body)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	resolved, pins, _, err := s.resolveDynamicProperties(ctx, props, nil)
	if err != nil || resolved["SubnetId"] != "subnet-selected-second" || pins["{{resolve:ssm:/guard/subnet}}"] != 2 {
		t.Fatalf("new operation did not select latest: %#v %v %v", resolved, pins, err)
	}
}

func TestDynamicSSMExecutionRoleDenialAndScopedMissingParameter(t *testing.T) {
	for _, role := range []bool{false, true} {
		t.Run(map[bool]string{false: "scope", true: "role"}[role], func(t *testing.T) {
			s, repository, owner, op := lifecycleFixture(t, "UPSERT", "APPLY")
			parameterOwner := ssm.New(ssm.Config{Repository: ssm.NewMemoryRepository(nil)})
			t.Cleanup(func() { _ = parameterOwner.Close() })
			source := &dynamicSSMOwner{t: t, service: parameterOwner, repository: repository}
			s.parameters = source
			ctx := awsctx.WithMetadata(t.Context(), op.Caller)
			source.put(ctx, "isolated", "not-for-other-scope")
			op.Template = `{"Resources":{"Association":{"Type":"AWS::EC2::SubnetRouteTableAssociation","Properties":{"SubnetId":"{{resolve:ssm:isolated}}","RouteTableId":"original"}}}}`
			op.DisableRollback = true
			if role {
				op.RoleARN = "arn:aws:iam::123456789012:role/no-ssm"
				s.roles = lifecycleExecutionRoles{t: t, repository: repository}
			} else {
				op.Caller.Region = "us-west-2"
			}
			if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutOperation(op) }); err != nil {
				t.Fatal(err)
			}
			op = lifecycleRun(t, s, repository, op.ID)
			if op.Phase != "DONE" || len(owner.calls) != 0 || len(source.calls) != 1 {
				t.Fatalf("lookup denial admitted resource effect: %+v %v", op, owner.calls)
			}
			if !role && !strings.Contains(op.Reason, "not found") {
				t.Fatalf("cross-region lookup did not fail missing: %s", op.Reason)
			}
			if role && !strings.Contains(op.Reason, "AccessDenied") {
				t.Fatalf("execution role did not control SSM authorization: %s", op.Reason)
			}
		})
	}
}

func TestDynamicSSMCompositionVersionsAndRedactedErrors(t *testing.T) {
	s, repository, _, op := lifecycleFixture(t, "UPSERT", "APPLY")
	parameterOwner := ssm.New(ssm.Config{})
	t.Cleanup(func() { _ = parameterOwner.Close() })
	source := &dynamicSSMOwner{t: t, service: parameterOwner, repository: repository}
	s.parameters = source
	ctx := awsctx.WithMetadata(t.Context(), op.Caller)
	source.put(ctx, "/guard/key", "client-secret-v1")
	source.put(ctx, "/guard/key", "client-secret-v2")
	template, err := ParseTemplate(`{"Resources":{"Association":{"Type":"AWS::EC2::SubnetRouteTableAssociation","Properties":{"SubnetId":{"Fn::Join":["",["prefix-{{resolve:","ssm:/guard/key:1}}-suffix"]]},"RouteTableId":"original"}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	props, err := template.ResolveResource("Association", Evaluation{})
	if err != nil {
		t.Fatal(err)
	}
	resolved, _, secrets, err := s.resolveDynamicProperties(ctx, props, nil)
	if err != nil || resolved["SubnetId"] != "prefix-client-secret-v1-suffix" {
		t.Fatalf("composed pinned reference: %v %v", resolved, err)
	}
	redacted := redactDynamicError(&awswire.Error{Code: "ValidationError", Message: "invalid client-secret-v1"}, secrets)
	if strings.Contains(redacted.Error(), "client-secret-v1") {
		t.Fatal("owner failure leaked dynamic value")
	}
	for _, text := range []string{"{{resolve:ssm:/guard/key:99}}", "{{resolve:ssm:/guard/key:0}}", "{{resolve:ssm:/guard/key:stable}}", "{{resolve:ssm-secure:/guard/key}}", "{{resolve:secretsmanager:key}}", "{{resolve:ssm:/guard/key"} {
		if _, _, _, err := s.resolveDynamicProperties(ctx, Properties{"Value": text}, nil); err == nil {
			t.Fatalf("unsupported/missing version accepted: %s", text)
		}
	}
}
