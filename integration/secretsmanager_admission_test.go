package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/internal/awstest"
)

type secretAdmissionCapture struct {
	Calls []struct {
		Label   string
		Request json.RawMessage
	}
	Matrix struct {
		Variants     map[string]json.RawMessage
		Observations []struct {
			Variant, Case, Code string
			ReturnedStages      []string `json:"returned_stages"`
			ReadbackCode        string   `json:"readback_code"`
			ReadbackStages      []string `json:"readback_stages"`
		}
	} `json:"condition_matrix"`
}

func TestSecretsManagerNativeWriteAdmission(t *testing.T) {
	var validation secretAdmissionCapture
	awsReadFixture(t, "secretsmanager/write_validation.json", &validation)
	var references struct {
		Stages secretAdmissionCapture `json:"stage_conditions"`
	}
	awsReadFixture(t, "ssm/secret_references.json", &references)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: account})
			root := clients.parameterSecrets("us-east-1", account, "test")
			secret, err := root.CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{Name: new("write-admission"), SecretString: new("initial")})
			if err != nil {
				t.Fatal(err)
			}
			identity := clients.iam(account, "test", "")
			role, err := identity.CreateRole(t.Context(), &iam.CreateRoleInput{
				RoleName:                 new("secret-stage-writer"),
				AssumeRolePolicyDocument: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}`, account)),
			})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, identity, "secret-stage-writer", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:PutSecretValue","Resource":%q}]}`, aws.ToString(secret.ARN)))
			versions := map[string]bool{aws.ToString(secret.VersionId): true}
			for _, source := range []struct {
				name    string
				capture secretAdmissionCapture
			}{{"validation", validation}, {"stage-list", references.Stages}} {
				requests := make(map[string]json.RawMessage, len(source.capture.Calls))
				for _, call := range source.capture.Calls {
					requests[call.Label] = call.Request
				}
				for _, variant := range slices.Sorted(maps.Keys(source.capture.Matrix.Variants)) {
					policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:PutSecretValue","Resource":%q,"Condition":%s}]}`, aws.ToString(secret.ARN), source.capture.Matrix.Variants[variant])
					session, err := clients.sts(account, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: new(variant), Policy: new(policy)})
					if err != nil {
						t.Fatal(err)
					}
					for _, observed := range source.capture.Matrix.Observations {
						if observed.Variant != variant || source.name == "stage-list" && observed.Case != "allowed-forbidden" {
							continue
						}
						t.Run(source.name+"/"+variant+"/"+observed.Case, func(t *testing.T) {
							var input map[string]json.RawMessage
							awsDecodeJSON(t, requests["stage-"+variant+"-"+observed.Case], &input)
							if id, present := input["SecretId"]; present && string(id) != "null" {
								input["SecretId"], _ = json.Marshal(aws.ToString(secret.ARN))
							}
							body, err := json.Marshal(input)
							if err != nil {
								t.Fatal(err)
							}
							var token, value string
							awsDecodeJSON(t, input["ClientRequestToken"], &token)
							awsDecodeJSON(t, input["SecretString"], &value)
							options := root.Options()
							options.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
							options.APIOptions = append(options.APIOptions, awstest.JSONBody(body))
							writer := secretsmanager.New(options)
							out, err := writer.PutSecretValue(t.Context(), &secretsmanager.PutSecretValueInput{SecretId: secret.ARN})
							if observed.Code != "Success" {
								assertAPIError(t, err, observed.Code)
							} else {
								if err != nil {
									t.Fatal(err)
								}
								if aws.ToString(out.ARN) != aws.ToString(secret.ARN) || aws.ToString(out.VersionId) != token || !slices.Equal(slices.Sorted(slices.Values(out.VersionStages)), slices.Sorted(slices.Values(observed.ReturnedStages))) {
									t.Fatalf("native admitted version: %+v", out)
								}
								versions[token] = true
							}
							readback, err := root.GetSecretValue(t.Context(), &secretsmanager.GetSecretValueInput{SecretId: secret.ARN, VersionId: new(token)})
							if observed.ReadbackCode != "Success" {
								assertAPIError(t, err, observed.ReadbackCode)
							} else if err != nil || aws.ToString(readback.SecretString) != value || !slices.Equal(slices.Sorted(slices.Values(readback.VersionStages)), slices.Sorted(slices.Values(observed.ReadbackStages))) {
								t.Fatalf("native retained value: %+v %v", readback, err)
							}
						})
					}
				}
			}
			retained, err := root.ListSecretVersionIds(t.Context(), &secretsmanager.ListSecretVersionIdsInput{SecretId: secret.ARN, IncludeDeprecated: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			var actual []string
			for _, version := range retained.Versions {
				actual = append(actual, aws.ToString(version.VersionId))
			}
			slices.Sort(actual)
			if !slices.Equal(actual, slices.Sorted(maps.Keys(versions))) {
				t.Fatalf("rejected writes changed retained versions: %v; admitted %v", actual, versions)
			}
		})
	}
}
