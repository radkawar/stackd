package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroups"
	rgtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroups/types"

	"stackd"
	"stackd/clock"
)

const (
	cloudFormationLambdaAliasAccount = "000000000000"
	cloudFormationLambdaAliasRegion  = "us-east-1"
	cloudFormationLambdaFunctionName = "cfn-alias-function"
	cloudFormationLambdaFunctionARN  = "arn:aws:lambda:us-east-1:000000000000:function:cfn-alias-function"
	cloudFormationLambdaAliasName    = "live"
	cloudFormationLambdaAliasARN     = cloudFormationLambdaFunctionARN + ":" + cloudFormationLambdaAliasName
)

// The function and published versions belong to Lambda, not CloudFormation.
// These local lifecycle regressions execute real Python runtimes, including the
// provisioned environment; they are not a replay of a native AWS capture.
func TestCloudFormationLambdaAliasLifecycle(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCloudFormationLambdaAliasStack(t, backend)
			aliasQuery := f.stackQuery(t, "AWS::Lambda::Alias")
			allQuery := f.stackQuery(t, "AWS::AllSupported")
			owned := map[string]string{cloudFormationLambdaAliasARN: "AWS::Lambda::Alias"}
			f.assertMembers(t, aliasQuery, owned)
			f.assertMembers(t, allQuery, owned)
			f.assertAlias(t, f.primary, "weighted deployment", map[string]float64{f.secondary: 1})
			f.invoke(t, f.secondary, "secondary", "")

			// Matching function and key tags remain attached to those resources;
			// they must neither select the alias nor imply stack membership.
			key, err := f.clients.kms("test", "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{
				Tags: []kmstypes.Tag{{TagKey: aws.String("owner-test"), TagValue: aws.String("lambda-alias")}},
			})
			if err != nil {
				t.Fatal(err)
			}
			f.assertMembers(t, &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10,
				Query: aws.String(`{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"owner-test","Values":["lambda-alias"]}]}`)},
				map[string]string{cloudFormationLambdaFunctionARN: "AWS::Lambda::Function", aws.ToString(key.KeyMetadata.Arn): "AWS::KMS::Key"})
			_, err = f.groups(cloudFormationLambdaAliasRegion, "test").SearchResources(t.Context(), &resourcegroups.SearchResourcesInput{
				ResourceQuery: &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeTagFilters10,
					Query: aws.String(`{"ResourceTypeFilters":["AWS::Lambda::Alias"],"TagFilters":[{"Key":"owner-test","Values":["lambda-alias"]}]}`)},
			})
			assertAPIError(t, err, "BadRequestException")
			for _, scope := range []struct{ account, region string }{
				{"111111111111", cloudFormationLambdaAliasRegion},
				{cloudFormationLambdaAliasAccount, "us-west-2"},
			} {
				out, err := f.groups(scope.region, scope.account).SearchResources(t.Context(), &resourcegroups.SearchResourcesInput{ResourceQuery: aliasQuery})
				if err != nil {
					t.Fatal(err)
				}
				if len(out.ResourceIdentifiers) != 0 || len(out.QueryErrors) != 1 || out.QueryErrors[0].ErrorCode != rgtypes.QueryErrorCodeCloudformationStackNotExisting {
					t.Fatalf("stack alias escaped account/region scope: %+v", out)
				}
				_, err = f.lambda(scope.region, scope.account, "test").GetAlias(t.Context(), &awslambda.GetAliasInput{
					FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName),
				})
				assertAPIError(t, err, "ResourceNotFoundException")
			}

			f.update(t, f.template(t, f.primary, "changed deployment", &cloudFormationAliasRouting{f.secondary, .25}, 0), cfntypes.StackStatusUpdateComplete)
			f.assertAlias(t, f.primary, "changed deployment", map[string]float64{f.secondary: .25})
			f.update(t, f.template(t, f.primary, "", nil, 0), cfntypes.StackStatusUpdateComplete)
			// Native CloudFormation retains an omitted Description, whereas
			// omitting RoutingConfig removes its additional version weights.
			f.assertAlias(t, f.primary, "changed deployment", nil)
			f.invoke(t, f.primary, "primary", "")

			f.update(t, f.template(t, f.primary, "", nil, 1), cfntypes.StackStatusUpdateComplete)
			pool, err := f.native().GetProvisionedConcurrencyConfig(t.Context(), &awslambda.GetProvisionedConcurrencyConfigInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(cloudFormationLambdaAliasName),
			})
			if err != nil {
				t.Fatal(err)
			}
			if string(pool.Status) != "READY" || aws.ToInt32(pool.RequestedProvisionedConcurrentExecutions) != 1 || aws.ToInt32(pool.AvailableProvisionedConcurrentExecutions) != 1 {
				t.Fatalf("stack completed without its provisioned environment: %+v", pool)
			}
			f.invoke(t, f.primary, "primary", "provisioned-concurrency")
			f.update(t, f.template(t, f.primary, "", nil, 0), cfntypes.StackStatusUpdateComplete)
			_, err = f.native().GetProvisionedConcurrencyConfig(t.Context(), &awslambda.GetProvisionedConcurrencyConfigInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(cloudFormationLambdaAliasName),
			})
			assertAPIError(t, err, "ProvisionedConcurrencyConfigNotFoundException")

			// A retained ownership token must not turn an earlier IAM grant into
			// permanent permission to mutate the alias on a later stack operation.
			putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-alias-operator",
				`{"Statement":[{"Effect":"Allow","Action":["cloudformation:*","lambda:GetAlias","lambda:GetProvisionedConcurrencyConfig"],"Resource":"*"}]}`)
			f.update(t, f.template(t, f.secondary, "denied update", nil, 0), cfntypes.StackStatusUpdateFailed)
			f.assertResourceStatus(t, cfntypes.ResourceStatusUpdateFailed)
			f.assertAlias(t, f.primary, "changed deployment", nil)
			_, err = f.lambda(cloudFormationLambdaAliasRegion, f.access, f.secret).DeleteAlias(t.Context(), &awslambda.DeleteAliasInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName),
			})
			assertAPIError(t, err, "AccessDeniedException")
			f.grant(t)
			f.update(t, f.template(t, f.primary, "recovered", nil, 0), cfntypes.StackStatusUpdateComplete)

			// Native retargeting preserves the incarnation and stack membership,
			// including after reconstructing all services over the retained store.
			_, err = f.native().UpdateAlias(t.Context(), &awslambda.UpdateAliasInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName), FunctionVersion: aws.String(f.secondary),
			})
			if err != nil {
				t.Fatal(err)
			}
			f.assertAlias(t, f.secondary, "recovered", nil)
			f.assertMembers(t, aliasQuery, owned)
			f.clients = f.reopen()
			f.assertAlias(t, f.secondary, "recovered", nil)
			f.assertMembers(t, allQuery, owned)

			// Deleting and recreating the same name and target is a new native
			// resource. Neither stack discovery nor later work may adopt it.
			_, err = f.native().CreateAlias(t.Context(), &awslambda.CreateAliasInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName), FunctionVersion: aws.String(f.primary),
			})
			assertAPIError(t, err, "ResourceConflictException")
			if _, err := f.native().DeleteAlias(t.Context(), &awslambda.DeleteAliasInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName),
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.native().CreateAlias(t.Context(), &awslambda.CreateAliasInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName),
				FunctionVersion: aws.String(f.secondary), Description: aws.String("foreign replacement"),
			}); err != nil {
				t.Fatal(err)
			}
			f.assertMembers(t, aliasQuery, map[string]string{})
			f.clients = f.reopen()
			f.assertMembers(t, allQuery, map[string]string{})
			f.update(t, f.template(t, f.primary, "stack update", nil, 0), cfntypes.StackStatusUpdateFailed)
			f.assertResourceStatus(t, cfntypes.ResourceStatusUpdateFailed)
			f.assertAlias(t, f.secondary, "foreign replacement", nil)
			if _, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)}); err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteFailed)
			f.assertResourceStatus(t, cfntypes.ResourceStatusDeleteFailed)
			f.assertAlias(t, f.secondary, "foreign replacement", nil)
			f.assertMembers(t, aliasQuery, map[string]string{})
		})
	}
}

type cloudFormationAliasRouting struct {
	version string
	weight  float64
}

type cloudFormationLambdaAliasStack struct {
	clients                     cloudClients
	reopen                      func() cloudClients
	source                      *clock.Manual
	stackID, primary, secondary string
	access, secret              string
}

func newCloudFormationLambdaAliasStack(t *testing.T, backend string) *cloudFormationLambdaAliasStack {
	t.Helper()
	f := &cloudFormationLambdaAliasStack{source: clock.NewManual(time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC))}
	f.clients, f.reopen = retainedCloud(t, backend, stackd.Config{Clock: f.source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	root := f.clients.iam("test", "test", "")
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("cfn-alias-execution"),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	code := func(marker string) []byte {
		return lambdaZIP(t, map[string]string{"handler.py": "import os\ndef handler(event, context):\n    return {\"marker\": \"" + marker + "\", \"version\": os.environ[\"AWS_LAMBDA_FUNCTION_VERSION\"], \"initialization\": os.environ.get(\"AWS_LAMBDA_INITIALIZATION_TYPE\")}\n"})
	}
	_, err = f.native().CreateFunction(t.Context(), &awslambda.CreateFunctionInput{
		FunctionName: aws.String(cloudFormationLambdaFunctionName), Role: role.Role.Arn,
		Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handler"),
		Code: &lambdatypes.FunctionCode{ZipFile: code("primary")},
		Tags: map[string]string{"owner-test": "lambda-alias"},
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration := &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)}
	if err := awslambda.NewFunctionActiveWaiter(f.native(), fastLambdaActiveWaiter).Wait(t.Context(), configuration, time.Minute); err != nil {
		t.Fatal(err)
	}
	first, err := f.native().PublishVersion(t.Context(), &awslambda.PublishVersionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)})
	if err != nil {
		t.Fatal(err)
	}
	f.primary = aws.ToString(first.Version)
	if _, err := f.native().UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), ZipFile: code("secondary")}); err != nil {
		t.Fatal(err)
	}
	if err := awslambda.NewFunctionUpdatedWaiter(f.native(), fastLambdaUpdatedWaiter).Wait(t.Context(), configuration, time.Minute); err != nil {
		t.Fatal(err)
	}
	second, err := f.native().PublishVersion(t.Context(), &awslambda.PublishVersionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)})
	if err != nil {
		t.Fatal(err)
	}
	f.secondary = aws.ToString(second.Version)
	_, f.access, f.secret = f.clients.user(t, "test", "cfn-alias-operator")
	// The captured create handler requires CreateAlias, not GetAlias or List.
	putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-alias-operator",
		`{"Statement":[{"Effect":"Allow","Action":["cloudformation:*","lambda:CreateAlias"],"Resource":"*"}]}`)
	created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
		StackName: aws.String("lambda-alias-owner"), TemplateBody: aws.String(f.template(t, f.primary, "weighted deployment", &cloudFormationAliasRouting{f.secondary, 1}, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.stackID = aws.ToString(created.StackId)
	stack := f.wait(t, cfntypes.StackStatusCreateComplete)
	outputs := map[string]string{}
	for _, output := range stack.Outputs {
		outputs[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}
	if !reflect.DeepEqual(outputs, map[string]string{"AliasRef": cloudFormationLambdaAliasARN, "AliasARN": cloudFormationLambdaAliasARN}) {
		t.Fatalf("Ref and AliasArn must expose the qualified alias ARN: %v", outputs)
	}
	f.grant(t)
	return f
}

func (f *cloudFormationLambdaAliasStack) template(t *testing.T, version, description string, routing *cloudFormationAliasRouting, provisioned int) string {
	t.Helper()
	properties := map[string]any{"FunctionName": cloudFormationLambdaFunctionName, "FunctionVersion": version, "Name": cloudFormationLambdaAliasName}
	if description != "" {
		properties["Description"] = description
	}
	if routing != nil {
		properties["RoutingConfig"] = map[string]any{"AdditionalVersionWeights": []map[string]any{{"FunctionVersion": routing.version, "FunctionWeight": routing.weight}}}
	}
	if provisioned != 0 {
		properties["ProvisionedConcurrencyConfig"] = map[string]any{"ProvisionedConcurrentExecutions": provisioned}
	}
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{"Alias": map[string]any{"Type": "AWS::Lambda::Alias", "Properties": properties}},
		"Outputs": map[string]any{
			"AliasRef": map[string]any{"Value": map[string]string{"Ref": "Alias"}},
			"AliasARN": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Alias", "AliasArn"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func (f *cloudFormationLambdaAliasStack) grant(t *testing.T) {
	t.Helper()
	putUserPolicy(t, f.clients.iam("test", "test", ""), "cfn-alias-operator",
		`{"Statement":[{"Effect":"Allow","Action":["cloudformation:*","lambda:*"],"Resource":"*"}]}`)
}

func (f *cloudFormationLambdaAliasStack) cfn() *cloudformation.Client {
	return cloudFormationClient(f.clients, cloudFormationLambdaAliasRegion, f.access, f.secret)
}

func (f *cloudFormationLambdaAliasStack) lambda(region, access, secret string) *awslambda.Client {
	return awslambda.New(awslambda.Options{Region: region, BaseEndpoint: aws.String(f.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(access, secret, ""), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1})
}

func (f *cloudFormationLambdaAliasStack) native() *awslambda.Client {
	return f.lambda(cloudFormationLambdaAliasRegion, "test", "test")
}

func (f *cloudFormationLambdaAliasStack) groups(region, account string) *resourcegroups.Client {
	return resourcegroups.New(resourcegroups.Options{Region: region, BaseEndpoint: aws.String(f.clients.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1})
}

func (f *cloudFormationLambdaAliasStack) wait(t *testing.T, wanted cfntypes.StackStatus) cfntypes.Stack {
	t.Helper()
	return cloudFormationWait(t, f.clients, f.source, f.cfn(), f.stackID, wanted)
}

func (f *cloudFormationLambdaAliasStack) update(t *testing.T, template string, wanted cfntypes.StackStatus) {
	t.Helper()
	_, err := f.cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{
		StackName: aws.String(f.stackID), TemplateBody: aws.String(template), DisableRollback: aws.Bool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.wait(t, wanted)
}

func (f *cloudFormationLambdaAliasStack) assertAlias(t *testing.T, version, description string, weights map[string]float64) {
	t.Helper()
	out, err := f.native().GetAlias(t.Context(), &awslambda.GetAliasInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String(cloudFormationLambdaAliasName)})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]float64
	if out.RoutingConfig != nil {
		got = out.RoutingConfig.AdditionalVersionWeights
	}
	if aws.ToString(out.AliasArn) != cloudFormationLambdaAliasARN || aws.ToString(out.FunctionVersion) != version || aws.ToString(out.Description) != description || len(got) != len(weights) {
		t.Fatalf("unexpected alias: %+v; weights=%v", out, got)
	}
	for version, weight := range weights {
		if actual, ok := got[version]; !ok || actual != weight {
			t.Fatalf("routing weights=%v, want %v", got, weights)
		}
	}
}

func (f *cloudFormationLambdaAliasStack) invoke(t *testing.T, version, marker, initialization string) {
	t.Helper()
	out, err := f.native().Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(cloudFormationLambdaAliasName), Payload: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct{ Marker, Version, Initialization string }
	if err := json.Unmarshal(out.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if out.FunctionError != nil || aws.ToString(out.ExecutedVersion) != version || payload.Version != version || payload.Marker != marker || (initialization != "" && payload.Initialization != initialization) {
		t.Fatalf("alias executed wrong deployment/environment: output=%+v payload=%s", out, out.Payload)
	}
}

func (f *cloudFormationLambdaAliasStack) assertResourceStatus(t *testing.T, wanted cfntypes.ResourceStatus) {
	t.Helper()
	out, err := f.cfn().DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: aws.String(f.stackID), LogicalResourceId: aws.String("Alias")})
	if err != nil {
		t.Fatal(err)
	}
	if out.StackResourceDetail == nil || out.StackResourceDetail.ResourceStatus != wanted {
		t.Fatalf("expected alias resource status %s, got %+v", wanted, out.StackResourceDetail)
	}
}

func (f *cloudFormationLambdaAliasStack) stackQuery(t *testing.T, kind string) *rgtypes.ResourceQuery {
	t.Helper()
	body, err := json.Marshal(map[string]any{"ResourceTypeFilters": []string{kind}, "StackIdentifier": f.stackID})
	if err != nil {
		t.Fatal(err)
	}
	return &rgtypes.ResourceQuery{Type: rgtypes.QueryTypeCloudformationStack10, Query: aws.String(string(body))}
}

func (f *cloudFormationLambdaAliasStack) assertMembers(t *testing.T, query *rgtypes.ResourceQuery, wanted map[string]string) {
	t.Helper()
	input := &resourcegroups.SearchResourcesInput{ResourceQuery: query}
	got := map[string]string{}
	for range 100 {
		out, err := f.groups(cloudFormationLambdaAliasRegion, "test").SearchResources(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.QueryErrors) != 0 {
			t.Fatalf("resource query failed: %+v", out.QueryErrors)
		}
		for _, resource := range out.ResourceIdentifiers {
			arn := aws.ToString(resource.ResourceArn)
			if _, duplicate := got[arn]; duplicate {
				t.Fatalf("resource query returned duplicate ARN %s", arn)
			}
			got[arn] = aws.ToString(resource.ResourceType)
		}
		if out.NextToken == nil {
			if !reflect.DeepEqual(got, wanted) {
				t.Fatalf("wanted resources %v, got %v", wanted, got)
			}
			return
		}
		input.NextToken = out.NextToken
	}
	t.Fatal("resource query pagination did not terminate")
}
