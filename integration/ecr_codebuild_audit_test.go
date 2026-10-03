package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type buildAuditCall struct {
	Label      string          `json:"label"`
	Service    string          `json:"service"`
	Operation  string          `json:"operation"`
	Parameters json.RawMessage `json:"parameters"`
	Output     json.RawMessage `json:"output"`
	Code       string          `json:"code"`
	RequestID  string          `json:"request_id"`
}

type buildAuditCapture struct {
	Account     string           `json:"account"`
	Region      string           `json:"region"`
	OwnedPrefix string           `json:"owned_prefix"`
	Calls       []buildAuditCall `json:"calls"`
	Cleanup     []buildAuditCall `json:"cleanup"`
	CloudTrail  struct {
		Events []struct {
			Event map[string]any `json:"event"`
		} `json:"events"`
	} `json:"cloudtrail"`
}

func (f buildAuditCapture) event(t *testing.T, call buildAuditCall) map[string]any {
	t.Helper()
	var result map[string]any
	for _, row := range f.CloudTrail.Events {
		if row.Event["requestID"] == call.RequestID {
			if result != nil {
				t.Fatalf("ambiguous native request %s", call.RequestID)
			}
			result = row.Event
		}
	}
	if result == nil {
		t.Fatalf("missing exact native request %s", call.RequestID)
	}
	return result
}

func buildAuditJSON(t *testing.T, value any, bindings map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return ec2AuditReplace(t, body, bindings)
}

func buildAuditAssert(t *testing.T, c cloudClients, f buildAuditCapture, row buildAuditCall, output any, callErr error, bindings map[string]string, identity map[string]any) {
	t.Helper()
	if row.Code == "Success" {
		if callErr != nil {
			t.Fatal(callErr)
		}
	} else {
		var apiError smithy.APIError
		if !errors.As(callErr, &apiError) || apiError.ErrorCode() != row.Code {
			t.Fatalf("%s: SDK error %v, native %s", row.Label, callErr, row.Code)
		}
	}
	client := cloudtrail.New(cloudtrail.Options{Region: f.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	got := auditLatestRecord(t, client, row.Operation)
	if got["requestID"] != nativeAuditRequestID(t, output, callErr) {
		t.Fatal("audit lost signed SDK request correlation")
	}
	var want map[string]any
	if err := json.Unmarshal(buildAuditJSON(t, f.event(t, row), bindings), &want); err != nil {
		t.Fatal(err)
	}
	// Event time belongs to the local clock. Generated repository/project dates
	// are separately bound below from the SDK output, never erased recursively.
	want["eventTime"] = got["eventTime"]
	assertNativeAuditEvent(t, got, want, "")
	if !reflect.DeepEqual(got["userIdentity"], identity) {
		t.Fatalf("authenticated audit identity: got %v want %v", got["userIdentity"], identity)
	}
	nativeIdentity := want["userIdentity"].(map[string]any)
	for _, field := range []string{"type", "arn", "accountId", "userName"} {
		if !reflect.DeepEqual(identity[field], nativeIdentity[field]) {
			t.Fatalf("native principal %s differs: %v", field, nativeIdentity)
		}
	}
}

func buildAuditActor(t *testing.T, c cloudClients, account string) (string, string, map[string]any) {
	t.Helper()
	arn, key, secret := c.user(t, "test", "Delegated")
	putUserPolicy(t, c.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
	user, err := c.iam("test", "test", "").GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("Delegated")})
	if err != nil {
		t.Fatal(err)
	}
	return key, secret, map[string]any{"type": "IAMUser", "principalId": aws.ToString(user.User.UserId), "arn": arn, "accountId": account, "accessKeyId": key, "userName": "Delegated"}
}

func TestECRNativeManagementAudit(t *testing.T) {
	var fixture buildAuditCapture
	awsReadFixture(t, "cloudtrail/ecr_codebuild_history.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: clock.NewManual(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC))}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			key, secret, identity := buildAuditActor(t, c, fixture.Account)
			client := ecrSDK(c, key, secret)
			kmsKey, err := c.kms("test", "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			bindings := map[string]string{"68ab2c9a-47f0-41e9-b9e5-b715582c7aec": aws.ToString(kmsKey.KeyMetadata.KeyId)}
			selected := map[string]bool{}
			for _, label := range []string{"precreate_absence", "create_images", "create_duplicate", "describe_owned", "tag_merge", "tag_list", "tag_remove", "policy_missing", "lifecycle_missing", "manifest_invalid", "layer_missing", "layer_initiate", "layer_upload", "layer_complete", "foreign_repository_layers", "registry_authorization", "batch_existing_and_missing", "describe_image", "immutable", "basic_scanning_configuration", "batch_scanning_configuration", "list_after_delete", "delete_owned"} {
				selected[label] = true
			}
			isolated := "stackd-buildowner-ecr-2b69d1cf0ec0-isolated"
			if _, err := client.CreateRepository(t.Context(), &ecr.CreateRepositoryInput{RepositoryName: &isolated}); err != nil {
				t.Fatal(err)
			}
			for _, row := range fixture.Calls {
				if row.Service != "ecr" {
					continue
				}
				parts := strings.Split(row.Label, ":")
				if len(parts) != 3 || !selected[parts[1]] {
					continue
				}
				t.Run(parts[1], func(t *testing.T) {
					var parameters any
					if err := json.Unmarshal(row.Parameters, &parameters); err != nil {
						t.Fatal(err)
					}
					body := buildAuditJSON(t, parameters, bindings)
					options := client.Options()
					options.APIOptions = append(options.APIOptions, awstest.JSONBody(body))
					output, callErr := awstest.CallSDK(t.Context(), ecr.New(options), row.Operation, body)
					if callErr == nil {
						switch out := output.(type) {
						case *ecr.CreateRepositoryOutput:
							bindings["000000000000.dkr.ecr.us-east-1.amazonaws.com/"+aws.ToString(out.Repository.RepositoryName)] = aws.ToString(out.Repository.RepositoryUri)
							bindings["2026-09-26T14:42:36Z"] = out.Repository.CreatedAt.UTC().Format(time.RFC3339)
						case *ecr.InitiateLayerUploadOutput:
							bindings["d3e0e170-5de8-4e83-95ae-a7d4fb34b98d"] = aws.ToString(out.UploadId)
						case *ecr.DeleteRepositoryOutput:
							bindings["000000000000.dkr.ecr.us-east-1.amazonaws.com/"+isolated] = aws.ToString(out.Repository.RepositoryUri)
							bindings["2026-09-26T14:42:39Z"] = out.Repository.CreatedAt.UTC().Format(time.RFC3339)
						}
					}
					buildAuditAssert(t, c, fixture, row, output, callErr, bindings, identity)
				})
			}
		})
	}
}

func TestCodeBuildNativeManagementAudit(t *testing.T) {
	var fixture buildAuditCapture
	awsReadFixture(t, "cloudtrail/ecr_codebuild_source_auth.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: clock.NewManual(time.Date(2026, 9, 26, 18, 0, 0, 0, time.UTC))}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			key, secret, identity := buildAuditActor(t, c, fixture.Account)
			_, err := c.iam("test", "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &fixture.OwnedPrefix, AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			bindings := map[string]string{}
			for _, row := range append(fixture.Calls, fixture.Cleanup...) {
				// The runtime deliberately rejects explicit OAUTH resources; native
				// accepts them. Its success is captured, not claimed as local support.
				if strings.Contains(row.Operation, ":") || row.Label == "update_primary_auth" {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					options := codebuild.Options{Region: fixture.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1}
					options.APIOptions = append(options.APIOptions, awstest.JSONBody(row.Parameters))
					output, callErr := awstest.CallSDK(t.Context(), codebuild.New(options), row.Operation, row.Parameters)
					if callErr == nil {
						var created, modified *time.Time
						switch out := output.(type) {
						case *codebuild.CreateProjectOutput:
							created, modified = out.Project.Created, out.Project.LastModified
						case *codebuild.UpdateProjectOutput:
							created, modified = out.Project.Created, out.Project.LastModified
						}
						if created != nil {
							event := fixture.event(t, row)
							project := event["responseElements"].(map[string]any)["project"].(map[string]any)
							bindings[project["created"].(string)] = created.UTC().Format(time.RFC3339)
							bindings[project["lastModified"].(string)] = modified.UTC().Format(time.RFC3339)
						}
					}
					buildAuditAssert(t, c, fixture, row, output, callErr, bindings, identity)
				})
			}
		})
	}
}

func TestCodeBuildNativeMissingResourceAudit(t *testing.T) {
	var fixture buildAuditCapture
	awsReadFixture(t, "cloudtrail/ecr_codebuild_history.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			key, secret, identity := buildAuditActor(t, c, fixture.Account)
			client := codebuild.New(codebuild.Options{Region: fixture.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			for _, row := range fixture.Calls {
				if row.Service != "codebuild" || !strings.HasPrefix(strings.Split(row.Label, ":")[1], "missing_") {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					output, callErr := awstest.CallSDK(t.Context(), client, row.Operation, row.Parameters)
					buildAuditAssert(t, c, fixture, row, output, callErr, nil, identity)
				})
			}
		})
	}
}
