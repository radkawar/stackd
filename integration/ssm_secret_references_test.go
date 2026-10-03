package stackd_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"stackd"
)

func (c cloudClients) parameterSecrets(region, key, secret string) *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestSSMSecretReferencesRemainStatelessAcrossRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			cl, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account})
			secrets := cl.parameterSecrets("us-east-1", account, "test")
			created, err := secrets.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: new("references/database"), SecretString: new("original-value")})
			if err != nil {
				t.Fatal(err)
			}
			root := cl.ssm("us-east-1", account, "test")
			name := "/aws/reference/secretsmanager/references/database"
			got, err := root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			if got.Parameter.Version != 0 || got.Parameter.Type != ssmtypes.ParameterTypeSecureString || aws.ToString(got.Parameter.Name) != name || aws.ToString(got.Parameter.Value) != "original-value" || aws.ToString(got.Parameter.ARN) != aws.ToString(created.ARN) {
				t.Fatalf("secret reference projection: %+v", got.Parameter)
			}
			var source struct {
				ARN          string
				Name         string
				VersionId    string
				SecretString string
				CreatedDate  string
			}
			if err := json.Unmarshal([]byte(aws.ToString(got.Parameter.SourceResult)), &source); err != nil {
				t.Fatal(err)
			}
			if source.ARN != aws.ToString(created.ARN) || source.Name != "references/database" || source.VersionId != aws.ToString(created.VersionId) || source.SecretString != "original-value" || got.Parameter.LastModifiedDate == nil || source.CreatedDate != got.Parameter.LastModifiedDate.UTC().Format("Jan 2, 2006, 3:04:05 PM") {
				t.Fatalf("source response projection: %+v parameter=%+v", source, got.Parameter)
			}
			_, err = root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(false)})
			assertAPIError(t, err, "ValidationException")
			batch, err := root.GetParameters(ctx, &ssm.GetParametersInput{Names: []string{name, name + "-absent"}, WithDecryption: new(true)})
			if err != nil || len(batch.Parameters) != 1 || aws.ToString(batch.Parameters[0].Value) != "original-value" || len(batch.InvalidParameters) != 1 || batch.InvalidParameters[0] != name+"-absent" {
				t.Fatalf("partial reference batch: %+v %v", batch, err)
			}
			_, readerKey, readerSecret := cl.user(t, account, "reference-reader")
			iam := cl.iam(account, "test", "")
			reader := cl.ssm("us-east-1", readerKey, readerSecret)
			putUserPolicy(t, iam, "reference-reader", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"*"}]}`)
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(true)})
			assertAPIError(t, err, "ValidationException")
			_, err = reader.GetParameters(ctx, &ssm.GetParametersInput{Names: []string{name}, WithDecryption: new(true)})
			assertAPIError(t, err, "ValidationException")
			putUserPolicy(t, iam, "reference-reader", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters","secretsmanager:GetSecretValue"],"Resource":"*"}]}`)
			allowed, err := reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(true)})
			if err != nil || aws.ToString(allowed.Parameter.Value) != "original-value" {
				t.Fatalf("live secret authority: %+v %v", allowed, err)
			}
			putUserPolicy(t, iam, "reference-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"*"},{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":%q}]}`, aws.ToString(created.ARN)))
			_, err = reader.GetParameters(ctx, &ssm.GetParametersInput{Names: []string{name, name + "-absent"}, WithDecryption: new(true)})
			assertAPIError(t, err, "ValidationException")
			putUserPolicy(t, iam, "reference-reader", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:GetParameter","ssm:GetParameters","secretsmanager:GetSecretValue"],"Resource":"*"},{"Effect":"Deny","Action":"kms:Decrypt","Resource":"*"}]}`)
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(true)})
			assertAPIError(t, err, "ValidationException")
			_, err = reader.GetParameters(ctx, &ssm.GetParametersInput{Names: []string{name}, WithDecryption: new(true)})
			assertAPIError(t, err, "ValidationException")
			putUserPolicy(t, iam, "reference-reader", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`)
			_, err = reader.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(false)})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := secrets.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: created.ARN, SecretString: new("replacement-value")}); err != nil {
				t.Fatal(err)
			}
			cl = reopen()
			root = cl.ssm("us-east-1", account, "test")
			current, err := root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(true)})
			if err != nil || current.Parameter.Version != 0 || aws.ToString(current.Parameter.Value) != "replacement-value" {
				t.Fatalf("live secret after reopen: %+v %v", current, err)
			}
			previous, err := root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name + ":AWSPREVIOUS"), WithDecryption: new(true)})
			if err != nil || previous.Parameter.Version != 0 || aws.ToString(previous.Parameter.Value) != "original-value" || aws.ToString(previous.Parameter.Selector) != ":AWSPREVIOUS" {
				t.Fatalf("secret stage after reopen: %+v %v", previous, err)
			}
			selected, err := root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name + ":" + aws.ToString(created.VersionId)), WithDecryption: new(true)})
			if err != nil || aws.ToString(selected.Parameter.Value) != "original-value" {
				t.Fatalf("secret version selection: %+v %v", selected, err)
			}
			metadata, err := root.DescribeParameters(ctx, &ssm.DescribeParametersInput{ParameterFilters: []ssmtypes.ParameterStringFilter{{Key: new("Name"), Option: new("Equals"), Values: []string{name}}}})
			if err != nil || len(metadata.Parameters) != 0 {
				t.Fatalf("reference retained parameter metadata: %+v %v", metadata, err)
			}
			if _, err := cl.parameterSecrets("us-east-1", account, "test").DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: created.ARN, ForceDeleteWithoutRecovery: new(true)}); err != nil {
				t.Fatal(err)
			}
			_, err = root.GetParameter(ctx, &ssm.GetParameterInput{Name: new(name), WithDecryption: new(true)})
			assertAPIError(t, err, "ParameterNotFound")
		})
	}
}

func TestSSMSecretReferenceSelectorsAndBinaryProjection(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			const compact = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			const uuidStage = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
			cl, _ := retainedCloud(t, backend, stackd.Config{AccountID: account})
			ctx := t.Context()
			secrets, parameters := cl.parameterSecrets("us-east-1", account, "test"), cl.ssm("us-east-1", account, "test")
			name := "references/nested+/@/="
			created, err := secrets.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: new(name), ClientRequestToken: new(compact), SecretString: new("initial")})
			if err != nil {
				t.Fatal(err)
			}
			current, err := secrets.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: created.ARN, SecretString: new("current")})
			if err != nil {
				t.Fatal(err)
			}
			for _, stage := range []string{compact, uuidStage, "stage/path", "1"} {
				if _, err := secrets.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{SecretId: created.ARN, VersionStage: new(stage), MoveToVersionId: current.VersionId}); err != nil {
					t.Fatal(err)
				}
			}
			reference := "aws/reference/secretsmanager/" + name
			for _, stage := range []string{compact, "stage/path", "1"} {
				got, err := parameters.GetParameter(ctx, &ssm.GetParameterInput{Name: new(reference + ":" + stage), WithDecryption: new(true)})
				if err != nil || aws.ToString(got.Parameter.Value) != "current" || aws.ToString(got.Parameter.Name) != reference || aws.ToString(got.Parameter.Selector) != ":"+stage {
					t.Fatalf("stage %q: %+v %v", stage, got, err)
				}
			}
			_, err = parameters.GetParameter(ctx, &ssm.GetParameterInput{Name: new(reference + ":" + uuidStage), WithDecryption: new(true)})
			assertAPIError(t, err, "ParameterNotFound")
			_, err = parameters.GetParameter(ctx, &ssm.GetParameterInput{Name: new(reference + ":stage:other"), WithDecryption: new(true)})
			assertAPIError(t, err, "ValidationException")
			if _, err := secrets.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: new(name + "/binary"), SecretBinary: []byte{0, 128, 255}}); err != nil {
				t.Fatal(err)
			}
			binary, err := parameters.GetParameter(ctx, &ssm.GetParameterInput{Name: new(reference + "/binary"), WithDecryption: new(true)})
			if err != nil {
				t.Fatal(err)
			}
			if binary.Parameter.Value != nil || binary.Parameter.DataType != nil || binary.Parameter.Version != 0 {
				t.Fatalf("binary reference projection: %+v", binary.Parameter)
			}
			var source struct {
				SecretBinary struct {
					Bytes []int8 `json:"hb"`
				}
				SecretString *string
			}
			if err := json.Unmarshal([]byte(aws.ToString(binary.Parameter.SourceResult)), &source); err != nil {
				t.Fatal(err)
			}
			if source.SecretString != nil || len(source.SecretBinary.Bytes) != 3 || source.SecretBinary.Bytes[0] != 0 || source.SecretBinary.Bytes[1] != -128 || source.SecretBinary.Bytes[2] != -1 {
				t.Fatalf("binary source bytes: %+v", source)
			}
			undecrypted, err := parameters.GetParameters(ctx, &ssm.GetParametersInput{Names: []string{reference, reference + "/binary"}})
			if err != nil || len(undecrypted.Parameters) != 0 || len(undecrypted.InvalidParameters) != 2 || undecrypted.InvalidParameters[0] != reference || undecrypted.InvalidParameters[1] != reference+"/binary" {
				t.Fatalf("undecrypted references: %+v %v", undecrypted, err)
			}
		})
	}
}

func TestSSMAbsentSecretReferencePreservesSuffixAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			const name = "references/absent"
			cl, _ := retainedCloud(t, backend, stackd.Config{AccountID: account})
			_, access, key := cl.user(t, account, "missing-reference-reader")
			parameters := cl.ssm("us-east-1", access, key)
			for _, policy := range []struct{ suffix, code string }{
				{"-*", "ParameterNotFound"}, {"-??????", "ParameterNotFound"},
				{"-ABC123", "ValidationException"}, {"-A*", "ValidationException"},
				{"", "ValidationException"},
			} {
				resource := "arn:aws:secretsmanager:us-east-1:" + account + ":secret:" + name + policy.suffix
				putUserPolicy(t, cl.iam(account, "test", ""), "missing-reference-reader", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:GetParameter","Resource":"*"},{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":%q}]}`, resource))
				_, err := parameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: new("/aws/reference/secretsmanager/" + name), WithDecryption: new(true)})
				assertAPIError(t, err, policy.code)
			}
		})
	}
}
