package cloudformation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudformation"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type registryAuthorizer struct {
	denied bool
	last   authorization.Request
}

func (a *registryAuthorizer) Authorize(_ context.Context, request authorization.Request) *awswire.Error {
	a.last = request
	if a.denied {
		return failure("AccessDenied", "Current policy denies registry reads.", 403)
	}
	return nil
}

func registryRead(t *testing.T, service *Service, scope Scope, input *api.DescribeTypeInput) (*api.DescribeTypeOutput, error) {
	t.Helper()
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region})
	var output *api.DescribeTypeOutput
	err := service.repository.Update(ctx, func(tx Transaction) error {
		var err error
		output, err = service.describeType(tx, input)
		return err
	})
	return output, err
}

func TestDescribeTypeReturnsCapturedSchemaAndNativeOptionalMetadata(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/cloudformation/resource_schemas_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		Types map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"types"`
	}
	if err := json.Unmarshal(data, &captured); err != nil {
		t.Fatal(err)
	}
	authorizer := &registryAuthorizer{}
	service := New(Config{Authorizer: authorizer})
	defer service.Close()
	scope := Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
	for _, name := range []string{"AWS::SSM::Parameter", "AWS::SQS::Queue", "AWS::Lambda::Function"} {
		output, err := registryRead(t, service, scope, &api.DescribeTypeInput{Type: new(api.RegistryTypeRESOURCE), TypeName: new(api.TypeName(name))})
		if err != nil {
			t.Fatal(err)
		}
		var expected, actual any
		if err := json.Unmarshal(captured.Types[name].Schema, &expected); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(text(output.Schema)), &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s did not return the exact captured registry schema", name)
		}
		if text(output.Arn) != registryTypeARN(scope, name) || text(output.Visibility) != "PUBLIC" || !truth(output.IsDefaultVersion) || text(output.DeprecatedStatus) != "LIVE" || text(output.ProvisioningType) != "FULLY_MUTABLE" {
			t.Fatalf("native metadata differs: %#v", output)
		}
		if output.DefaultVersionId != nil || output.PublicVersionNumber != nil || output.PublisherId != nil || output.ExecutionRoleArn != nil || output.LoggingConfig != nil || output.TypeTestsStatus != nil {
			t.Fatalf("public AWS type acquired private/third-party metadata: %#v", output)
		}
		if output.TimeCreated == nil {
			t.Fatal("captured native creation time was omitted")
		}
		if authorizer.last.Action != "cloudformation:DescribeType" || authorizer.last.ResourceARN != text(output.Arn) || authorizer.last.ResourceAccountID != scope.Account || authorizer.last.EvaluationTime == nil {
			t.Fatalf("registry read did not use current scoped authority: %#v", authorizer.last)
		}
	}
}

func TestDescribeTypeSelectorAndCurrentAuthorityBoundaries(t *testing.T) {
	authorizer := &registryAuthorizer{}
	service := New(Config{Authorizer: authorizer})
	defer service.Close()
	scope := Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}
	arn := registryTypeARN(scope, "AWS::SSM::Parameter")
	output, err := registryRead(t, service, scope, &api.DescribeTypeInput{Arn: new(api.TypeArn(arn))})
	if err != nil || text(output.TypeName) != "AWS::SSM::Parameter" {
		t.Fatalf("ARN selector = %#v, %v", output, err)
	}
	authorizer.denied = true
	_, err = registryRead(t, service, scope, &api.DescribeTypeInput{Arn: new(api.TypeArn(arn))})
	assertRegistryError(t, err, "AccessDenied", 403)
	authorizer.denied = false
	cases := []struct {
		name   string
		input  api.DescribeTypeInput
		code   string
		status int
	}{
		{"missing selector", api.DescribeTypeInput{}, "ValidationError", 400},
		{"incomplete selector", api.DescribeTypeInput{TypeName: new(api.TypeName("AWS::SSM::Parameter"))}, "ValidationError", 400},
		{"ambiguous selector", api.DescribeTypeInput{Arn: new(api.TypeArn(arn)), Type: new(api.RegistryTypeRESOURCE)}, "ValidationError", 400},
		{"unknown type", api.DescribeTypeInput{Type: new(api.RegistryTypeRESOURCE), TypeName: new(api.TypeName("Example::Unknown::Resource"))}, "TypeNotFoundException", 404},
		{"unknown hook", api.DescribeTypeInput{Type: new(api.RegistryTypeHOOK), TypeName: new(api.TypeName("Example::Unknown::Hook"))}, "TypeNotFoundException", 404},
		{"uncaptured version", api.DescribeTypeInput{Arn: new(api.TypeArn(arn)), VersionId: new(api.TypeVersionId("00000001"))}, "TypeNotFoundException", 404},
		{"private registration", api.DescribeTypeInput{Arn: new(api.TypeArn("arn:aws:cloudformation:us-east-1:123456789012:type/resource/AWS-SSM-Parameter"))}, "TypeNotFoundException", 404},
		{"other region", api.DescribeTypeInput{Arn: new(api.TypeArn("arn:aws:cloudformation:us-west-2::type/resource/AWS-SSM-Parameter"))}, "TypeNotFoundException", 404},
		{"other partition", api.DescribeTypeInput{Arn: new(api.TypeArn("arn:aws-cn:cloudformation:us-east-1::type/resource/AWS-SSM-Parameter"))}, "TypeNotFoundException", 404},
		{"publisher selector", api.DescribeTypeInput{Arn: new(api.TypeArn(arn)), PublisherId: new(api.PublisherId("123456789012"))}, "CFNRegistryException", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := registryRead(t, service, scope, &tc.input)
			assertRegistryError(t, err, tc.code, tc.status)
		})
	}
}

func assertRegistryError(t *testing.T, err error, code string, status int) {
	t.Helper()
	var failure *awswire.Error
	if !errors.As(err, &failure) || failure.Code != code || failure.StatusCode != status {
		t.Fatalf("registry error = %v; expected %s/%d", err, code, status)
	}
}
