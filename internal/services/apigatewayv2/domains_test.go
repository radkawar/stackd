package apigatewayv2

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"stackd/clock"
	"stackd/internal/awsapi"
	acmapi "stackd/internal/awsapi/acm"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/acm"
	"stackd/internal/services/apigatewaywebsocket"
	"testing"
	"time"
)

func domainCommand(t *testing.T, svc interface {
	ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
}, ctx context.Context, service, action string, in any) any {
	t.Helper()
	model, _ := awscatalog.LookupService(service)
	op, _ := model.Operation(action)
	out, wire := svc.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: in})
	if wire != nil {
		t.Fatalf("%s: %v", action, wire)
	}
	return out
}
func domainFixtureCertificate(t *testing.T, serial int64) ([]byte, []byte) {
	t.Helper()
	scalar := make([]byte, 32)
	scalar[len(scalar)-1] = 7
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"api.example.test"}, NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
}

type domainTruststoreFixture []byte

func (f domainTruststoreFixture) Truststore(context.Context, Scope, string, string) ([]byte, error) {
	return []byte(f), nil
}
func TestCustomDomainHTTPUsesACMAndRetainedMapping(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	now := clock.NewManual(at)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	certificates := acm.New(acm.Config{Clock: now})
	leaf, key := domainFixtureCertificate(t, 1)
	imported := domainCommand(t, certificates, ctx, "acm", "ImportCertificate", &acmapi.ImportCertificateInput{Certificate: leaf, PrivateKey: key}).(*acmapi.ImportCertificateOutput)
	repo := NewMemoryRepository(nil)
	svc := New(Config{Repository: repo, Clock: now, Certificates: certificates, Truststores: domainTruststoreFixture(leaf), Endpoint: "https://127.0.0.1:9443"})
	owner := ResourceOwner{StackID: "stack", LogicalID: "domain", Token: "one"}
	owned := WithResourceOwner(ctx, owner)
	request := &api.CreateDomainNameInput{DomainName: new(api.StringWithLengthBetween1And512("api.example.test")), DomainNameConfigurations: api.DomainNameConfigurations{{CertificateArn: new(api.Arn(*imported.CertificateArn))}}}
	mtlsRequest := *request
	mtlsRequest.MutualTlsAuthentication = &api.MutualTlsAuthenticationInput{}
	text(&mtlsRequest.MutualTlsAuthentication.TruststoreUri, "s3://trust/pem")
	domainModel, _ := awscatalog.LookupService("apigatewayv2")
	createDomainOperation, _ := domainModel.Operation("CreateDomainName")
	if _, wire := svc.ExecuteCommand(owned, awsapi.DecodedRequest{Operation: createDomainOperation, Input: &mtlsRequest}); wire == nil || wire.Code != "BadRequestException" {
		t.Fatalf("imported mTLS certificate admitted without public ownership proof: %v", wire)
	}
	domainCommand(t, svc, owned, "apigatewayv2", "CreateDomainName", request)
	domainCommand(t, svc, owned, "apigatewayv2", "CreateDomainName", request)
	sc := scopeFor(ctx)
	gateway := APIKey{sc, "http-api"}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutAPI(APIRecord{Key: gateway, Name: "mapped", ProtocolType: "HTTP", Disabled: true}); err != nil {
			return err
		}
		stage := ResourceKey{gateway, "live"}
		if err := tx.PutStage(StageRecord{Key: stage, DeploymentID: "deployment"}); err != nil {
			return err
		}
		return tx.PutDeployment(DeploymentRecord{Key: ResourceKey{gateway, "deployment"}})
	}); err != nil {
		t.Fatal(err)
	}
	mappingInput := &api.CreateApiMappingInput{ApiId: new(api.Id(gateway.ID)), Stage: new(api.StringWithLengthBetween1And128("live")), ApiMappingKey: new(api.SelectionKey("orders/v1"))}
	text(&mappingInput.DomainName, "api.example.test")
	mapping := domainCommand(t, svc, WithResourceOwner(ctx, ResourceOwner{StackID: "stack", LogicalID: "mapping", Token: "one"}), "apigatewayv2", "CreateApiMapping", mappingInput).(*api.CreateApiMappingOutput)
	server := httptest.NewUnstartedServer(svc.DomainDispatcher(http.NotFoundHandler(), nil, http.NotFoundHandler()))
	server.TLS = svc.DomainTLSConfig(nil)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(leaf)
	initial, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "api.example.test", Time: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	firstCertificate := initial.ConnectionState().PeerCertificates[0]
	initial.Close()
	if firstCertificate.SerialNumber.Int64() != 1 {
		t.Fatal("wrong ACM certificate selected")
	}
	// Reimport renews live key material but must not change the retained identity.
	renewed, _ := domainFixtureCertificate(t, 2)
	domainCommand(t, certificates, ctx, "acm", "ImportCertificate", &acmapi.ImportCertificateInput{CertificateArn: imported.CertificateArn, Certificate: renewed, PrivateKey: key})
	renewedRoots := x509.NewCertPool()
	renewedRoots.AppendCertsFromPEM(renewed)
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: renewedRoots, ServerName: "api.example.test", Time: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	parsed := connection.ConnectionState().PeerCertificates[0]
	connection.Close()
	if parsed.SerialNumber.Int64() != 2 {
		t.Fatal("stale ACM material")
	}
	wrong := WithResourceOwner(ctx, ResourceOwner{StackID: "other", LogicalID: "domain", Token: "two"})
	model, _ := awscatalog.LookupService("apigatewayv2")
	op, _ := model.Operation("DeleteDomainName")
	deleteInput := &api.DeleteDomainNameInput{}
	text(&deleteInput.DomainName, "api.example.test")
	mappingDeleteOperation, _ := model.Operation("DeleteApiMapping")
	mappingDeleteInput := &api.DeleteApiMappingInput{}
	text(&mappingDeleteInput.ApiMappingId, value(mapping.ApiMappingId))
	text(&mappingDeleteInput.DomainName, "api.example.test")
	if _, wire := svc.ExecuteCommand(WithResourceOwner(ctx, ResourceOwner{StackID: "other", LogicalID: "mapping", Token: "two"}), awsapi.DecodedRequest{Operation: mappingDeleteOperation, Input: mappingDeleteInput}); wire == nil || wire.Code != "ConflictException" {
		t.Fatalf("foreign mapping deletion: %v", wire)
	}
	if _, wire := svc.ExecuteCommand(wrong, awsapi.DecodedRequest{Operation: op, Input: deleteInput}); wire == nil || wire.Code != "ConflictException" {
		t.Fatalf("foreign owner deletion: %v", wire)
	}
}

func TestCustomDomainWebSocketUsesMappedStage(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	now := clock.NewManual(at)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	certificates := acm.New(acm.Config{Clock: now})
	leaf, key := domainFixtureCertificate(t, 1)
	imported := domainCommand(t, certificates, ctx, "acm", "ImportCertificate", &acmapi.ImportCertificateInput{Certificate: leaf, PrivateKey: key}).(*acmapi.ImportCertificateOutput)
	repo := NewMemoryRepository(nil)
	svc := New(Config{Repository: repo, Clock: now, Certificates: certificates})
	request := &api.CreateDomainNameInput{DomainName: new(api.StringWithLengthBetween1And512("api.example.test")), DomainNameConfigurations: api.DomainNameConfigurations{{CertificateArn: new(api.Arn(*imported.CertificateArn))}}}
	domainCommand(t, svc, ctx, "apigatewayv2", "CreateDomainName", request)
	gateway := APIKey{scopeFor(ctx), "socket"}
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutAPI(APIRecord{Key: gateway, ProtocolType: "WEBSOCKET", Disabled: true, RouteSelectionExpression: "$request.body.action"}); err != nil {
			return err
		}
		if err := tx.PutStage(StageRecord{Key: ResourceKey{gateway, "live"}, DeploymentID: "deployment"}); err != nil {
			return err
		}
		return tx.PutDeployment(DeploymentRecord{Key: ResourceKey{gateway, "deployment"}, RouteSelectionExpression: "$request.body.action"})
	}); err != nil {
		t.Fatal(err)
	}
	mapping := &api.CreateApiMappingInput{ApiId: new(api.Id(gateway.ID)), Stage: new(api.StringWithLengthBetween1And128("live")), ApiMappingKey: new(api.SelectionKey("chat"))}
	text(&mapping.DomainName, "api.example.test")
	domainCommand(t, svc, ctx, "apigatewayv2", "CreateApiMapping", mapping)
	sockets := apigatewaywebsocket.New(apigatewaywebsocket.Config{Resolver: svc, Clock: now})
	defer sockets.Close()
	handler := apigatewaywebsocket.NewHandler(sockets, nil)
	server := httptest.NewUnstartedServer(svc.DomainDispatcher(http.NotFoundHandler(), handler, http.NotFoundHandler()))
	server.TLS = svc.DomainTLSConfig(nil)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(leaf)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "api.example.test", Time: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.WriteString(conn, "GET /chat HTTP/1.1\r\nHost: api.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("mapped WebSocket handshake: %d", response.StatusCode)
	}
}
