package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	gatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"io"
	"net/http"
	"net/http/httptest"
	"stackd"
	"stackd/clock"
	"strings"
	"testing"
	"time"
)

type ecrNativeFixture struct {
	Account      string `json:"account"`
	Observations []struct {
		Case       string          `json:"case"`
		Operation  string          `json:"operation"`
		Parameters json.RawMessage `json:"parameters"`
		Code       string          `json:"code"`
		Output     json.RawMessage `json:"output"`
	} `json:"observations"`
}

func (f ecrNativeFixture) input(t *testing.T, label string, out any) {
	t.Helper()
	for _, row := range f.Observations {
		if row.Case == label {
			if err := json.Unmarshal(row.Parameters, out); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("missing independent native case %s", label)
}
func ecrSDK(c cloudClients, key, secret string) *ecr.Client {
	return ecr.New(ecr.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func ecrCode(t *testing.T, err error, code string) {
	t.Helper()
	var modeled smithy.APIError
	if !errors.As(err, &modeled) || modeled.ErrorCode() != code {
		t.Fatalf("error=%v, want modeled %s", err, code)
	}
}
func ecrDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ecrHTTP(t *testing.T, c cloudClients, token, method, path string, data []byte, want int) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, c.server.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Basic "+token)
	}
	if strings.Contains(path, "/manifests/") {
		request.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	}
	response, err := c.server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s returned %d: %s, want %d", method, path, response.StatusCode, body, want)
	}
	return body
}

func TestECRNativeBytesCurrentPolicyAndRecovery(t *testing.T) {
	var fixture ecrNativeFixture
	awsReadFixture(t, "ecr/stackd-buildowner-ecr-2b69d1cf0ec0-resume-b913ab.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			root := ecrSDK(clients, "test", "test")
			name := "stackd-buildowner-fixture"
			isolated := name + "-isolated"
			created, err := root.CreateRepository(t.Context(), &ecr.CreateRepositoryInput{RepositoryName: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = root.CreateRepository(t.Context(), &ecr.CreateRepositoryInput{RepositoryName: aws.String(isolated)}); err != nil {
				t.Fatal(err)
			}
			var expectedManifest ecr.PutImageInput
			fixture.input(t, "put_image", &expectedManifest)
			expectedManifest.RepositoryName = aws.String(name)
			var blobs [][]byte
			for _, label := range []string{"layer_upload", "config_upload"} {
				var part ecr.UploadLayerPartInput
				fixture.input(t, label, &part)
				part.RepositoryName = aws.String(name)
				blobs = append(blobs, part.LayerPartBlob)
				init, err := root.InitiateLayerUpload(t.Context(), &ecr.InitiateLayerUploadInput{RepositoryName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				part.UploadId = init.UploadId
				if _, err = root.UploadLayerPart(t.Context(), &part); err != nil {
					t.Fatal(err)
				}
				_, err = root.CompleteLayerUpload(t.Context(), &ecr.CompleteLayerUploadInput{RepositoryName: aws.String(name), UploadId: init.UploadId, LayerDigests: []string{"sha256:" + strings.Repeat("0", 64)}})
				ecrCode(t, err, "InvalidLayerException")
				if _, err = root.CompleteLayerUpload(t.Context(), &ecr.CompleteLayerUploadInput{RepositoryName: aws.String(name), UploadId: init.UploadId, LayerDigests: []string{ecrDigest(part.LayerPartBlob)}}); err != nil {
					t.Fatal(err)
				}
			}
			image, err := root.PutImage(t.Context(), &expectedManifest)
			if err != nil {
				t.Fatal(err)
			}
			digest := ecrDigest([]byte(aws.ToString(expectedManifest.ImageManifest)))
			if aws.ToString(image.Image.ImageId.ImageDigest) != digest {
				t.Fatalf("manifest digest is not derived from independent captured bytes: %v", image.Image.ImageId)
			}
			_, err = root.PutImage(t.Context(), &expectedManifest)
			ecrCode(t, err, "ImageAlreadyExistsException")
			other := expectedManifest
			other.RepositoryName = aws.String(isolated)
			_, err = root.PutImage(t.Context(), &other)
			ecrCode(t, err, "LayersNotFoundException")
			mismatch := expectedManifest
			mismatch.ImageDigest = aws.String("sha256:" + strings.Repeat("0", 64))
			_, err = root.PutImage(t.Context(), &mismatch)
			ecrCode(t, err, "ImageDigestDoesNotMatchException")
			if _, err = root.PutImageTagMutability(t.Context(), &ecr.PutImageTagMutabilityInput{RepositoryName: aws.String(name), ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable}); err != nil {
				t.Fatal(err)
			}
			var changed ecr.PutImageInput
			fixture.input(t, "immutable_retag_changed_bytes", &changed)
			changed.RepositoryName = aws.String(name)
			_, err = root.PutImage(t.Context(), &changed)
			ecrCode(t, err, "ImageTagAlreadyExistsException")
			arn, key, secret := clients.user(t, "test", "ecr-pusher")
			putUserPolicy(t, clients.iam("test", "test", ""), "ecr-pusher", allow(`"ecr:*"`, "*"))
			user := ecrSDK(clients, key, secret)
			authorization, err := user.GetAuthorizationToken(t.Context(), &ecr.GetAuthorizationTokenInput{})
			if err != nil {
				t.Fatal(err)
			}
			token := aws.ToString(authorization.AuthorizationData[0].AuthorizationToken)
			if _, err := base64.StdEncoding.DecodeString(token); err != nil {
				t.Fatal("authorization token is not base64")
			}
			prefix := "/v2/aws/" + fixture.Account + "/us-east-1/" + name
			ecrHTTP(t, clients, "", "GET", prefix+"/manifests/original", nil, 401)
			if got := ecrHTTP(t, clients, token, "GET", prefix+"/manifests/original", nil, 200); !bytes.Equal(got, []byte(aws.ToString(expectedManifest.ImageManifest))) {
				t.Fatal("registry manifest bytes changed")
			}
			for _, blob := range blobs {
				if got := ecrHTTP(t, clients, token, "GET", prefix+"/blobs/"+ecrDigest(blob), nil, 200); !bytes.Equal(got, blob) {
					t.Fatal("registry blob bytes changed")
				}
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":%q},"Action":"ecr:BatchGetImage"}]}`, arn)
			if _, err = root.SetRepositoryPolicy(t.Context(), &ecr.SetRepositoryPolicyInput{RepositoryName: aws.String(name), PolicyText: aws.String(policy), Force: true}); err != nil {
				t.Fatal(err)
			}
			ecrHTTP(t, clients, token, "GET", prefix+"/manifests/original", nil, 403)
			if _, err = root.DeleteRepositoryPolicy(t.Context(), &ecr.DeleteRepositoryPolicyInput{RepositoryName: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			putUserPolicy(t, clients.iam("test", "test", ""), "ecr-pusher", allow(`"ecr:GetAuthorizationToken"`, "*"))
			ecrHTTP(t, clients, token, "GET", prefix+"/manifests/original", nil, 403)
			putUserPolicy(t, clients.iam("test", "test", ""), "ecr-pusher", allow(`"ecr:*"`, "*"))
			clients = reopen()
			root = ecrSDK(clients, "test", "test")
			if got := ecrHTTP(t, clients, token, "GET", prefix+"/manifests/original", nil, 200); !bytes.Equal(got, []byte(aws.ToString(expectedManifest.ImageManifest))) {
				t.Fatal("retained token or manifest failed after reopen")
			}
			ecrHTTP(t, clients, token, "GET", strings.Replace(prefix, "/us-east-1/", "/us-west-2/", 1)+"/manifests/original", nil, 401)
			ecrHTTP(t, clients, token, "GET", strings.Replace(prefix, "/"+fixture.Account+"/", "/111111111111/", 1)+"/manifests/original", nil, 403)
			downloaded, err := root.GetDownloadUrlForLayer(t.Context(), &ecr.GetDownloadUrlForLayerInput{RepositoryName: aws.String(name), LayerDigest: aws.String(ecrDigest(blobs[0]))})
			if err != nil {
				t.Fatal(err)
			}
			response, err := clients.server.Client().Get(aws.ToString(downloaded.DownloadUrl))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || !bytes.Equal(body, blobs[0]) {
				t.Fatalf("actual layer download after reopen: status=%d err=%v", response.StatusCode, err)
			}
			source.Advance(12 * time.Hour)
			ecrHTTP(t, clients, token, "GET", prefix+"/manifests/original", nil, 401)
			described, err := root.DescribeRepositories(t.Context(), &ecr.DescribeRepositoriesInput{RepositoryNames: []string{name}})
			if err != nil || aws.ToString(described.Repositories[0].RepositoryArn) != aws.ToString(created.Repository.RepositoryArn) {
				t.Fatalf("repository identity changed at restart: %v", err)
			}
		})
	}
}

func TestECRReplicationRoleDeletionTracksCurrentConfiguration(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012"}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			registry := ecrSDK(clients, "test", "test")
			identity := clients.iam("test", "test", "")
			_, err := registry.PutReplicationConfiguration(t.Context(), &ecr.PutReplicationConfigurationInput{
				ReplicationConfiguration: &ecrtypes.ReplicationConfiguration{Rules: []ecrtypes.ReplicationRule{{
					Destinations: []ecrtypes.ReplicationDestination{{Region: aws.String("us-west-2"), RegistryId: aws.String("111111111111")}},
				}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			role := aws.String("AWSServiceRoleForECRReplication")
			task, err := identity.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: role})
			if err != nil {
				t.Fatal(err)
			}
			status := waitOrganizationRoleDeletion(t, identity, task.DeletionTaskId)
			if status.Status != iamtypes.DeletionTaskStatusTypeFailed || status.Reason == nil || len(status.Reason.RoleUsageList) != 1 {
				t.Fatalf("configured replication role deletion = %+v", status)
			}
			if _, err = identity.GetRole(t.Context(), &iam.GetRoleInput{RoleName: role}); err != nil {
				t.Fatal(err)
			}
			_, err = registry.PutReplicationConfiguration(t.Context(), &ecr.PutReplicationConfigurationInput{
				ReplicationConfiguration: &ecrtypes.ReplicationConfiguration{Rules: []ecrtypes.ReplicationRule{}},
			})
			if err != nil {
				t.Fatal(err)
			}
			task, err = identity.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: role})
			if err != nil {
				t.Fatal(err)
			}
			if status = waitOrganizationRoleDeletion(t, identity, task.DeletionTaskId); status.Status != iamtypes.DeletionTaskStatusTypeSucceeded {
				t.Fatalf("released replication role deletion = %+v", status)
			}
			_, err = identity.GetRole(t.Context(), &iam.GetRoleInput{RoleName: role})
			ecrCode(t, err, "NoSuchEntity")
		})
	}
}

func TestECRRegistryAndAPIGatewayV2RouteIsolation(t *testing.T) {
	clients, _ := retainedCloud(t, "memory", stackd.Config{}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
	gateway := apigatewayv2.New(apigatewayv2.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	created, err := gateway.CreateApi(t.Context(), &apigatewayv2.CreateApiInput{Name: aws.String("stackd-buildowner-route-proof"), ProtocolType: gatewaytypes.ProtocolTypeHttp})
	if err != nil {
		t.Fatal(err)
	}
	read, err := gateway.GetApi(t.Context(), &apigatewayv2.GetApiInput{ApiId: created.ApiId})
	if err != nil || aws.ToString(read.Name) != "stackd-buildowner-route-proof" || read.ProtocolType != gatewaytypes.ProtocolTypeHttp {
		t.Fatalf("ECR intercepted API Gateway v2: output=%v err=%v", read, err)
	}
	registry := ecrSDK(clients, "test", "test")
	token, err := registry.GetAuthorizationToken(t.Context(), &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	ecrHTTP(t, clients, aws.ToString(token.AuthorizationData[0].AuthorizationToken), "GET", "/v2/", nil, 200)
	if _, err = gateway.DeleteApi(t.Context(), &apigatewayv2.DeleteApiInput{ApiId: created.ApiId}); err != nil {
		t.Fatal(err)
	}
}
