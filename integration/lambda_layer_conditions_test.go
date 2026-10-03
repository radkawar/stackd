package stackd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type lambdaLayerConditionFixture struct {
	Artifacts map[string]map[string]string
	Policies  map[string]json.RawMessage
	Cases     []struct {
		Name, Operation, Function, Policy, Result, Native string
		Layers                                            []string
		Get                                               map[string]string
		ExpectedLayers                                    []string `json:"expected_layers"`
	}
}

// Owned native controls establish that omitted and empty Layers supply no IAM
// values even when retained attachments would change the authorization result.
// Every decision goes through real IAM/STS and the signed Lambda SDK surface;
// accepted deployments and rejected updates execute real /opt layer contents.
func TestLambdaLayerDeploymentConditionsSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[lambdaLayerConditionFixture](t, "layer_conditions")
	nativeResults := map[string]string{}
	for _, row := range lambdaFixture[lambdaLayerFixture](t, "layer_conditions_native").Observations {
		nativeResults[row.Label] = row.Result.Code
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newLambdaQualifiedReplay(t, backend)
			admin := r.c.lambda
			clients := cloudClients{r.c.server}
			root := clients.iam("test", "test", "")
			execution, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 aws.String("condition-execution"),
				AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			deployer, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 aws.String("condition-deployer"),
				AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			session, err := clients.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: deployer.Role.Arn, RoleSessionName: aws.String("condition-session")})
			if err != nil {
				t.Fatal(err)
			}
			options := admin.Options()
			options.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
			actor := awslambda.New(options)
			archive := func(name string) []byte {
				files, ok := fixture.Artifacts[name]
				if !ok {
					t.Fatalf("missing artifact %s", name)
				}
				return lambdaZIP(t, files)
			}
			arns := map[string]string{}
			for _, name := range []string{"allowed", "other"} {
				layer, err := admin.PublishLayerVersion(t.Context(), &awslambda.PublishLayerVersionInput{LayerName: aws.String("condition-" + name), Content: &lambdatypes.LayerVersionContentInput{ZipFile: archive(name)}})
				if err != nil {
					t.Fatal(err)
				}
				arns[name] = aws.ToString(layer.LayerVersionArn)
			}
			requested := func(names []string) []string {
				if names == nil {
					return nil
				}
				values := make([]string, len(names))
				for i, name := range names {
					arn, ok := arns[name]
					if !ok {
						t.Fatalf("unknown layer %s", name)
					}
					values[i] = arn
				}
				return values
			}
			configuration := func(t *testing.T, name string) *awslambda.GetFunctionConfigurationOutput {
				t.Helper()
				out, err := admin.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			invoke := func(t *testing.T, name string) []string {
				t.Helper()
				out, err := admin.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: aws.String(name), Payload: []byte(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				if out.FunctionError != nil {
					t.Fatalf("runtime error %s: %s", aws.ToString(out.FunctionError), out.Payload)
				}
				var files []string
				if err := json.Unmarshal(out.Payload, &files); err != nil {
					t.Fatal(err)
				}
				return files
			}
			code := archive("function")
			for _, row := range fixture.Cases {
				if !t.Run(row.Name, func(t *testing.T) {
					document, ok := fixture.Policies[row.Policy]
					if !ok {
						t.Fatalf("unknown policy %s", row.Policy)
					}
					if _, err := root.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: deployer.Role.RoleName, PolicyName: aws.String("deployment"), PolicyDocument: aws.String(string(document))}); err != nil {
						t.Fatal(err)
					}
					for layer, expected := range row.Get {
						_, err := actor.GetLayerVersionByArn(t.Context(), &awslambda.GetLayerVersionByArnInput{Arn: aws.String(arns[layer])})
						if expected == "Success" {
							if err != nil {
								t.Fatal(err)
							}
						} else {
							assertAPIError(t, err, expected)
						}
					}
					var before *awslambda.GetFunctionConfigurationOutput
					var beforeFiles []string
					var callErr error
					switch row.Operation {
					case "create":
						_, callErr = actor.CreateFunction(t.Context(), &awslambda.CreateFunctionInput{
							FunctionName: aws.String(row.Function), Role: execution.Role.Arn, Runtime: lambdatypes.RuntimePython312,
							Handler: aws.String("entry.invoke"), Code: &lambdatypes.FunctionCode{ZipFile: code}, Layers: requested(row.Layers),
						})
					case "update":
						before = configuration(t, row.Function)
						beforeFiles = invoke(t, row.Function)
						_, callErr = actor.UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{
							FunctionName: aws.String(row.Function), Layers: requested(row.Layers), Description: aws.String(row.Name),
						})
					default:
						t.Fatalf("unknown operation %s", row.Operation)
					}
					expected := row.Result
					if row.Native != "" {
						expected = nativeResults[row.Native]
					}
					if expected == "" {
						t.Fatalf("missing expected result for %s (native %s)", row.Name, row.Native)
					}
					if expected != "Success" {
						assertAPIError(t, callErr, expected)
						if before == nil {
							_, err := admin.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(row.Function)})
							assertAPIError(t, err, "ResourceNotFoundException")
							return
						}
						after := configuration(t, row.Function)
						if !reflect.DeepEqual(before.Layers, after.Layers) || aws.ToString(before.RevisionId) != aws.ToString(after.RevisionId) || aws.ToString(before.Description) != aws.ToString(after.Description) || before.State != after.State || before.LastUpdateStatus != after.LastUpdateStatus {
							t.Fatalf("rejected update changed deployment: before=%+v after=%+v", before, after)
						}
						if actual := invoke(t, row.Function); !slices.Equal(actual, beforeFiles) {
							t.Fatalf("rejected update changed runtime layers: before=%v after=%v", beforeFiles, actual)
						}
						return
					}
					if callErr != nil {
						t.Fatal(callErr)
					}
					r.ready(t, row.Function)
					after := configuration(t, row.Function)
					actualARNs := make([]string, len(after.Layers))
					for i, layer := range after.Layers {
						actualARNs[i] = aws.ToString(layer.Arn)
					}
					if !slices.Equal(actualARNs, requested(row.ExpectedLayers)) {
						t.Fatalf("deployed layers=%v; want=%v", actualARNs, requested(row.ExpectedLayers))
					}
					files := make([]string, len(row.ExpectedLayers))
					for i, name := range row.ExpectedLayers {
						files[i] = name + ".txt"
					}
					slices.Sort(files)
					if actual := invoke(t, row.Function); !slices.Equal(actual, files) {
						t.Fatalf("runtime layers=%v; want=%v", actual, files)
					}
				}) {
					t.FailNow()
				}
			}
		})
	}
}
