package identitycenter

import (
	"context"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	portal "stackd/internal/awsapi/sso"
	oidc "stackd/internal/awsapi/ssooidc"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/identitystore"
	"stackd/storage/memory"
)

type oidcFixture struct {
	service    *Service
	repository *MemoryRepository
	directory  *identitystore.MemoryRepository
	source     *clock.Manual
	ctx        context.Context
	instance   Instance
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	domain := memory.NewDomain()
	source := clock.NewManual(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	repository := NewMemoryRepository(domain)
	directory := identitystore.NewMemoryRepository(domain)
	instance := Instance{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ARN: "arn:aws:sso:::instance/ssoins-0123456789abcdef", StoreID: "d-0123456789", Created: source.Now(), Tags: map[string]string{}}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", Region: "us-east-1"})
	if e := repository.Update(ctx, func(tx Transaction) error {
		if e := tx.PutInstance(instance); e != nil {
			return e
		}
		if e := tx.PutClient(Client{ID: "client", SecretHash: tokenHash("secret"), Name: "test", Partition: "aws", Region: "us-east-1", Created: source.Now(), Expires: source.Now().Add(24 * time.Hour), GrantTypes: []string{deviceGrant, "refresh_token"}, Scopes: []string{"sso:account:access"}}); e != nil {
			return e
		}
		return directory.Update(tx.Context(), func(tx identitystore.Transaction) error {
			if e := tx.PutStore(identitystore.Store{ID: instance.StoreID, Scope: directoryScope(instance)}); e != nil {
				return e
			}
			return tx.PutUser(identitystore.User{StoreID: instance.StoreID, ID: "user", UserName: "alice"})
		})
	}); e != nil {
		t.Fatal(e)
	}
	s := New(Config{Repository: repository, Directory: identitystore.NewWithConfig(identitystore.Config{Repository: directory, Clock: source}), Clock: source, PublicEndpoint: "http://127.0.0.1:4566"})
	return &oidcFixture{service: s, repository: repository, directory: directory, source: source, ctx: ctx, instance: instance}
}
func (f *oidcFixture) call(service, action string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService(service)
	op, _ := model.Operation(action)
	return f.service.Frontend(service).ExecuteCommand(f.ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}
func (f *oidcFixture) device(t *testing.T, state string) {
	t.Helper()
	if e := f.repository.Update(f.ctx, func(tx Transaction) error {
		return tx.PutDevice(Device{CodeHash: tokenHash("device"), UserCode: "ABCD-EFGH", ClientID: "client", InstanceARN: f.instance.ARN, UserID: "user", State: state, Created: f.source.Now(), Expires: f.source.Now().Add(10 * time.Minute), Interval: 5})
	}); e != nil {
		t.Fatal(e)
	}
}
func tokenInput() *oidc.CreateTokenInput {
	return &oidc.CreateTokenInput{ClientId: new(oidc.ClientId("client")), ClientSecret: new(oidc.ClientSecret("secret")), GrantType: new(oidc.GrantType(deviceGrant)), DeviceCode: new(oidc.DeviceCode("device"))}
}
func requireOIDCError(t *testing.T, e *awswire.Error, code string) {
	t.Helper()
	if e == nil || e.Code != code {
		t.Fatalf("error=%v; want %s", e, code)
	}
}

func TestOIDCPollingRetainsAdmissionAndExpiry(t *testing.T) {
	f := newOIDCFixture(t)
	f.device(t, "PENDING")
	_, e := f.call("ssooidc", "CreateToken", tokenInput())
	requireOIDCError(t, e, "AuthorizationPendingException")
	_, e = f.call("ssooidc", "CreateToken", tokenInput())
	requireOIDCError(t, e, "SlowDownException")
	f.source.Advance(6 * time.Second)
	_, e = f.call("ssooidc", "CreateToken", tokenInput())
	requireOIDCError(t, e, "SlowDownException")
	f.source.Advance(15 * time.Second)
	_, e = f.call("ssooidc", "CreateToken", tokenInput())
	requireOIDCError(t, e, "AuthorizationPendingException")
	f.source.Advance(10 * time.Minute)
	_, e = f.call("ssooidc", "CreateToken", tokenInput())
	requireOIDCError(t, e, "ExpiredTokenException")
}

func TestOIDCConcurrentRedemptionAndRefreshLogoutFamily(t *testing.T) {
	f := newOIDCFixture(t)
	f.device(t, "AUTHORIZED")
	var wg sync.WaitGroup
	outputs := make(chan *oidc.CreateTokenOutput, 8)
	failures := make(chan *awswire.Error, 8)
	for range 8 {
		wg.Go(func() {
			out, e := f.call("ssooidc", "CreateToken", tokenInput())
			if e != nil {
				failures <- e
				return
			}
			outputs <- out.(*oidc.CreateTokenOutput)
		})
	}
	wg.Wait()
	close(outputs)
	close(failures)
	if len(outputs) != 1 {
		t.Fatalf("device produced %d sessions; want one", len(outputs))
	}
	for e := range failures {
		requireOIDCError(t, e, "InvalidGrantException")
	}
	first := <-outputs
	f.source.Advance(30 * time.Minute)
	in := &oidc.CreateTokenInput{ClientId: new(oidc.ClientId("client")), ClientSecret: new(oidc.ClientSecret("secret")), GrantType: new(oidc.GrantType("refresh_token")), RefreshToken: first.RefreshToken}
	result, e := f.call("ssooidc", "CreateToken", in)
	if e != nil {
		t.Fatal(e)
	}
	second := result.(*oidc.CreateTokenOutput)
	for _, access := range []*oidc.AccessToken{first.AccessToken, second.AccessToken} {
		if _, e = f.call("sso", "ListAccounts", &portal.ListAccountsInput{AccessToken: new(portal.AccessTokenType(*access))}); e != nil {
			t.Fatalf("live family access rejected: %v", e)
		}
	}
	// Refresh does not extend the prior access token's deadline.
	f.source.Advance(30 * time.Minute)
	_, e = f.call("sso", "ListAccounts", &portal.ListAccountsInput{AccessToken: new(portal.AccessTokenType(*first.AccessToken))})
	requireOIDCError(t, e, "UnauthorizedException")
	if _, e = f.call("sso", "Logout", &portal.LogoutInput{AccessToken: new(portal.AccessTokenType(*second.AccessToken))}); e != nil {
		t.Fatal(e)
	}
	_, e = f.call("sso", "ListAccounts", &portal.ListAccountsInput{AccessToken: new(portal.AccessTokenType(*second.AccessToken))})
	requireOIDCError(t, e, "UnauthorizedException")
	_, e = f.call("ssooidc", "CreateToken", in)
	requireOIDCError(t, e, "InvalidGrantException")
}

func TestOIDCClientScopeAndCurrentDirectoryRevocation(t *testing.T) {
	f := newOIDCFixture(t)
	f.device(t, "AUTHORIZED")
	original := f.ctx
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", Region: "us-west-2"})
	_, e := f.call("ssooidc", "CreateToken", tokenInput())
	requireOIDCError(t, e, "InvalidClientException")
	f.ctx = original
	out, e := f.call("ssooidc", "CreateToken", tokenInput())
	if e != nil {
		t.Fatal(e)
	}
	token := out.(*oidc.CreateTokenOutput)
	if err := f.directory.Update(f.ctx, func(tx identitystore.Transaction) error {
		return tx.DeleteUser(identitystore.Key{StoreID: f.instance.StoreID, ID: "user"})
	}); err != nil {
		t.Fatal(err)
	}
	_, e = f.call("sso", "ListAccounts", &portal.ListAccountsInput{AccessToken: new(portal.AccessTokenType(*token.AccessToken))})
	requireOIDCError(t, e, "UnauthorizedException")
	_, e = f.call("ssooidc", "CreateToken", &oidc.CreateTokenInput{ClientId: new(oidc.ClientId("client")), ClientSecret: new(oidc.ClientSecret("secret")), GrantType: new(oidc.GrantType("refresh_token")), RefreshToken: token.RefreshToken})
	requireOIDCError(t, e, "InvalidGrantException")
}

func TestOIDCIssuerIdentifierIsIndependentOfTransport(t *testing.T) {
	f := newOIDCFixture(t)
	input := &oidc.StartDeviceAuthorizationInput{ClientId: new(oidc.ClientId("client")), ClientSecret: new(oidc.ClientSecret("secret")), StartUrl: new(oidc.URI("https://identitycenter.amazonaws.com/ssoins-0123456789abcdef"))}
	result, e := f.call("ssooidc", "StartDeviceAuthorization", input)
	if e != nil {
		t.Fatal(e)
	}
	device := result.(*oidc.StartDeviceAuthorizationOutput)
	if value(device.VerificationUri) != "http://127.0.0.1:4566/_stackd/sso/device" {
		t.Fatalf("browser verification URI=%q", value(device.VerificationUri))
	}
	for _, invalid := range []string{"http://identitycenter.amazonaws.com/ssoins-0123456789abcdef", "https://identitycenter.amazonaws.com.attacker.invalid/ssoins-0123456789abcdef", "https://identitycenter.amazonaws.com.cn/ssoins-0123456789abcdef", "https://identitycenter.amazonaws.com/ssoins-0000000000000000"} {
		input.StartUrl = new(oidc.URI(invalid))
		_, e = f.call("ssooidc", "StartDeviceAuthorization", input)
		requireOIDCError(t, e, "InvalidRequestException")
	}
}
