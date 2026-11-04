package stackd_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	"stackd"
	"stackd/clock"
	"stackd/compute/eks/ecrcredentials"
)

func TestECRKubeletProviderTLSCurrentIAMAndRefresh(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	source := clock.NewManual(time.Now().UTC())
	cloud, err := stackd.New(stackd.Config{AccountID: "000000000000", Clock: source, PublicEndpoint: "https://" + server.Listener.Addr().String()})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = cloud
	server.StartTLS()
	t.Cleanup(func() {
		server.Close()
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	})
	clients := cloudClients{server}
	root := ecrSDK(clients, "test", "test")
	for _, name := range []string{"kubelet-allowed", "kubelet-denied"} {
		if _, err := root.CreateRepository(t.Context(), &ecr.CreateRepositoryInput{RepositoryName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	// Use independently retained native OCI bytes, not a fabricated registry.
	var fixture ecrNativeFixture
	awsReadFixture(t, "ecr/stackd-buildowner-ecr-2b69d1cf0ec0-resume-b913ab.json", &fixture)
	var image ecr.PutImageInput
	fixture.input(t, "put_image", &image)
	for _, name := range []string{"kubelet-allowed", "kubelet-denied"} {
		for _, label := range []string{"layer_upload", "config_upload"} {
			var part ecr.UploadLayerPartInput
			fixture.input(t, label, &part)
			part.RepositoryName = aws.String(name)
			init, err := root.InitiateLayerUpload(t.Context(), &ecr.InitiateLayerUploadInput{RepositoryName: aws.String(name)})
			if err != nil {
				t.Fatal(err)
			}
			part.UploadId = init.UploadId
			if _, err = root.UploadLayerPart(t.Context(), &part); err != nil {
				t.Fatal(err)
			}
			if _, err = root.CompleteLayerUpload(t.Context(), &ecr.CompleteLayerUploadInput{RepositoryName: aws.String(name), UploadId: init.UploadId, LayerDigests: []string{ecrDigest(part.LayerPartBlob)}}); err != nil {
				t.Fatal(err)
			}
		}
		image.RepositoryName = aws.String(name)
		if _, err := root.PutImage(t.Context(), &image); err != nil {
			t.Fatal(err)
		}
	}
	_, key, secret := clients.user(t, "test", "kubelet-node")
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"},{"Effect":"Allow","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:BatchCheckLayerAvailability"],"Resource":"arn:aws:ecr:us-east-1:000000000000:repository/kubelet-allowed"}]}`
	putUserPolicy(t, clients.iam("test", "test", ""), "kubelet-node", policy)
	config := ecrcredentials.Config{Endpoint: server.URL, Region: "us-east-1", AccessKeyID: key, SecretAccessKey: secret}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	registry := strings.TrimPrefix(server.URL, "https://")
	request := ecrcredentials.Request{APIVersion: ecrcredentials.APIVersion, Kind: "CredentialProviderRequest", Image: registry + "/aws/000000000000/us-east-1/kubelet-allowed:original"}
	response, err := ecrcredentials.Provide(t.Context(), config, ca, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Kind != "CredentialProviderResponse" || response.APIVersion != request.APIVersion || response.CacheKeyType != "Image" || response.CacheDuration != "0s" || len(response.Auth) != 1 {
		t.Fatalf("unexpected provider protocol: kind=%s version=%s cache=%s/%s auth entries=%d", response.Kind, response.APIVersion, response.CacheKeyType, response.CacheDuration, len(response.Auth))
	}
	auth := response.Auth[registry]
	token := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
	prefix := "/v2/aws/000000000000/us-east-1/"
	ecrHTTP(t, clients, "", "GET", prefix+"kubelet-allowed/manifests/original", nil, http.StatusUnauthorized)
	ecrHTTP(t, clients, token, "GET", prefix+"kubelet-allowed/manifests/original", nil, http.StatusOK)
	ecrHTTP(t, clients, token, "GET", prefix+"kubelet-denied/manifests/original", nil, http.StatusForbidden)
	source.Advance(12 * time.Hour)
	ecrHTTP(t, clients, token, "GET", prefix+"kubelet-allowed/manifests/original", nil, http.StatusUnauthorized)
	response, err = ecrcredentials.Provide(t.Context(), config, ca, request)
	if err != nil {
		t.Fatal(err)
	}
	fresh := response.Auth[registry]
	freshToken := base64.StdEncoding.EncodeToString([]byte(fresh.Username + ":" + fresh.Password))
	if freshToken == token {
		t.Fatal("provider reused expired ECR authorization")
	}
	ecrHTTP(t, clients, freshToken, "GET", prefix+"kubelet-allowed/manifests/original", nil, http.StatusOK)
	putUserPolicy(t, clients.iam("test", "test", ""), "kubelet-node", allow(`"ecr:GetAuthorizationToken"`, "*"))
	ecrHTTP(t, clients, freshToken, "GET", prefix+"kubelet-allowed/manifests/original", nil, http.StatusForbidden)
	putUserPolicy(t, clients.iam("test", "test", ""), "kubelet-node", `{"Statement":{"Effect":"Deny","Action":"ecr:GetAuthorizationToken","Resource":"*"}}`)
	if _, err := ecrcredentials.Provide(t.Context(), config, ca, request); err == nil {
		t.Fatal("provider ignored revoked token authority")
	}
	putUserPolicy(t, clients.iam("test", "test", ""), "kubelet-node", policy)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	wrongCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, err := ecrcredentials.Provide(t.Context(), config, wrongCA, request); err == nil {
		t.Fatal("provider accepted untrusted registry TLS")
	}
	config.Endpoint = strings.Replace(server.URL, "https://", "http://", 1)
	if _, err := ecrcredentials.Provide(t.Context(), config, ca, request); err == nil {
		t.Fatal("provider accepted plaintext registry")
	}
	config.Endpoint = server.URL
	request.Image = "unrelated.example.com/private:latest"
	if result, err := ecrcredentials.Provide(t.Context(), config, ca, request); err != nil || len(result.Auth) != 0 {
		t.Fatal("provider leaked credentials to an unrelated registry")
	}
	request.Image = registry + "/aws/000000000000/us-east-1/kubelet-allowed:original"
	request.APIVersion = "credentialprovider.kubelet.k8s.io/v1beta1"
	if _, err := ecrcredentials.Provide(t.Context(), config, ca, request); err == nil {
		t.Fatal("provider accepted unsupported protocol version")
	}
	request.APIVersion = ecrcredentials.APIVersion
	dir := t.TempDir()
	configPath, caPath := filepath.Join(dir, "credentials.json"), filepath.Join(dir, "ca.pem")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ecrcredentials.Run(t.Context(), configPath, caPath, bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var wire ecrcredentials.Response
	if err := json.Unmarshal(output.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Auth[registry].Username != "AWS" {
		t.Fatal("stdio provider did not return native ECR credentials")
	}
	if err := os.Chmod(configPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ecrcredentials.Load(configPath); err == nil {
		t.Fatal("provider accepted world-readable node credentials")
	}
}
