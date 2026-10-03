package iam_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/internal/services/iam"
)

func federationFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/federation/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type oidcDiscoveryFunc func(context.Context, iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error)

func (f oidcDiscoveryFunc) Discover(ctx context.Context, r iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error) {
	return f(ctx, r)
}

func TestFederationProviderSDKTagsIsolationAndQuotas(t *testing.T) {
	ctx := context.Background()
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithRepository(nil, repository)
	c := clientFor(t, service, "123456789012", "us-east-1")
	saml, err := c.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String("Provider"), SAMLMetadataDocument: aws.String(federationFixture(t, "metadata.xml"))})
	if err != nil {
		t.Fatal(err)
	}
	oidc, err := c.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://idp.example.com/path/"), ThumbprintList: []string{strings.Repeat("a", 40)}})
	if err != nil {
		t.Fatal(err)
	}
	tags := []types.Tag{{Key: aws.String("team"), Value: aws.String("aws:eng")}, {Key: aws.String("Team"), Value: aws.String("capital")}, {Key: aws.String("z"), Value: aws.String("")}}
	if _, err := c.TagSAMLProvider(ctx, &sdkiam.TagSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn, Tags: tags}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TagOpenIDConnectProvider(ctx, &sdkiam.TagOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, Tags: tags}); err != nil {
		t.Fatal(err)
	}
	sp, err := c.ListSAMLProviderTags(ctx, &sdkiam.ListSAMLProviderTagsInput{SAMLProviderArn: saml.SAMLProviderArn, MaxItems: aws.Int32(1)})
	if err != nil || !sp.IsTruncated || aws.ToString(sp.Tags[0].Key) != "Team" {
		t.Fatalf("SAML first page=%+v %v", sp, err)
	}
	sn, err := c.ListSAMLProviderTags(ctx, &sdkiam.ListSAMLProviderTagsInput{SAMLProviderArn: saml.SAMLProviderArn, Marker: sp.Marker})
	if err != nil || len(sn.Tags) != 2 || sn.IsTruncated {
		t.Fatalf("SAML next page=%+v %v", sn, err)
	}
	op, err := c.ListOpenIDConnectProviderTags(ctx, &sdkiam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, MaxItems: aws.Int32(1)})
	if err != nil || !op.IsTruncated || aws.ToString(op.Tags[0].Key) != "Team" {
		t.Fatalf("OIDC first page=%+v %v", op, err)
	}
	on, err := c.ListOpenIDConnectProviderTags(ctx, &sdkiam.ListOpenIDConnectProviderTagsInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, Marker: op.Marker})
	if err != nil || len(on.Tags) != 2 || on.IsTruncated {
		t.Fatalf("OIDC next page=%+v %v", on, err)
	}
	if _, err := c.UntagSAMLProvider(ctx, &sdkiam.UntagSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn, TagKeys: []string{"team", "absent"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UntagOpenIDConnectProvider(ctx, &sdkiam.UntagOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, TagKeys: []string{"team", "absent"}}); err != nil {
		t.Fatal(err)
	}
	many := make([]types.Tag, 49)
	for i := range many {
		many[i] = types.Tag{Key: aws.String(fmt.Sprintf("new%02d", i)), Value: aws.String("v")}
	}
	_, err = c.TagSAMLProvider(ctx, &sdkiam.TagSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn, Tags: many})
	requireCode(t, err, "LimitExceeded")
	_, err = c.TagOpenIDConnectProvider(ctx, &sdkiam.TagOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn, Tags: many})
	requireCode(t, err, "LimitExceeded")
	restarted := clientFor(t, iam.NewWithRepository(nil, repository), "123456789012", "eu-west-2")
	s, err := restarted.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn})
	if err != nil || len(s.Tags) != 2 {
		t.Fatalf("SAML rollback/restart=%+v %v", s, err)
	}
	o, err := restarted.GetOpenIDConnectProvider(ctx, &sdkiam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn})
	if err != nil || len(o.Tags) != 2 {
		t.Fatalf("OIDC rollback/restart=%+v %v", o, err)
	}
	other := clientFor(t, service, "210987654321", "us-east-1")
	_, err = other.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: saml.SAMLProviderArn})
	requireCode(t, err, "AccessDenied")
	_, err = other.GetOpenIDConnectProvider(ctx, &sdkiam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: oidc.OpenIDConnectProviderArn})
	requireCode(t, err, "AccessDenied")
	for _, client := range []*sdkiam.Client{other, clientForPartition(t, service, "123456789012", "cn-north-1", "aws-cn")} {
		out, err := client.ListSAMLProviders(ctx, &sdkiam.ListSAMLProvidersInput{})
		if err != nil || len(out.SAMLProviderList) != 0 {
			t.Fatalf("SAML isolation=%+v %v", out, err)
		}
		oidcs, err := client.ListOpenIDConnectProviders(ctx, &sdkiam.ListOpenIDConnectProvidersInput{})
		if err != nil || len(oidcs.OpenIDConnectProviderList) != 0 {
			t.Fatalf("OIDC isolation=%+v %v", oidcs, err)
		}
	}
	clients := make([]string, 100)
	for i := range clients {
		clients[i] = fmt.Sprintf("client%d", i)
	}
	quota, err := c.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://quota.example.com"), ClientIDList: clients, ThumbprintList: []string{strings.Repeat("b", 40)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AddClientIDToOpenIDConnectProvider(ctx, &sdkiam.AddClientIDToOpenIDConnectProviderInput{OpenIDConnectProviderArn: quota.OpenIDConnectProviderArn, ClientID: aws.String("overflow")})
	requireCode(t, err, "LimitExceeded")
	if _, err = c.AddClientIDToOpenIDConnectProvider(ctx, &sdkiam.AddClientIDToOpenIDConnectProviderInput{OpenIDConnectProviderArn: quota.OpenIDConnectProviderArn, ClientID: aws.String(clients[0])}); err != nil {
		t.Fatal(err)
	}
}

func TestFederationPreparationAuthorizationCancellationAndStaleness(t *testing.T) {
	ctx := context.Background()
	service := iam.New()
	c := clientFor(t, service, "123456789012", "us-east-1")
	user, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("federation-manager")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, user.User)
	var calls atomic.Int32
	source := oidcDiscoveryFunc(func(ctx context.Context, r iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error) {
		calls.Add(1)
		return iam.OIDCDiscoveryResult{IssuerURL: r.IssuerURL, Thumbprints: []string{strings.Repeat("a", 40)}, SigningKeys: []iam.OIDCSigningKey{{ID: "key", Type: "RSA", Operations: []string{"verify"}}}}, nil
	})
	service.SetOIDCDiscovery(source)
	_, err = caller.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://not-authorized.example.com")})
	requireCode(t, err, "AccessDenied")
	if calls.Load() != 0 {
		t.Fatal("unauthorized request reached discovery")
	}
	made, err := c.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://discovery.example.com/path")})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("automatic discovery=%+v %v calls=%d", made, err, calls.Load())
	}
	arn := aws.ToString(made.OpenIDConnectProviderArn)
	record, err := service.OIDCProviderForFederation(authRootContext("aws"), arn)
	if err != nil {
		t.Fatal(err)
	}
	record.Thumbprints[0] = "mutated"
	_, err = c.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://explicit.example.com"), ThumbprintList: []string{strings.Repeat("b", 40)}})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("explicit thumbprints triggered discovery: %v", err)
	}
	keys, err := service.ResolveOIDCSigningKeys(authRootContext("aws"), arn)
	if err != nil || len(keys.SigningKeys) != 1 {
		t.Fatalf("keys=%+v %v", keys, err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	service.SetOIDCDiscovery(oidcDiscoveryFunc(func(ctx context.Context, r iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error) {
		close(entered)
		select {
		case <-release:
			return source.Discover(ctx, r)
		case <-ctx.Done():
			return iam.OIDCDiscoveryResult{}, ctx.Err()
		}
	}))
	done := make(chan error, 1)
	go func() { _, err := service.ResolveOIDCSigningKeys(authRootContext("aws"), arn); done <- err }()
	<-entered
	if _, err := c.UpdateOpenIDConnectProviderThumbprint(ctx, &sdkiam.UpdateOpenIDConnectProviderThumbprintInput{OpenIDConnectProviderArn: made.OpenIDConnectProviderArn, ThumbprintList: []string{strings.Repeat("c", 40)}}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("trust change during discovery accepted")
	}
	service.SetOIDCDiscovery(oidcDiscoveryFunc(func(ctx context.Context, r iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error) {
		<-ctx.Done()
		return iam.OIDCDiscoveryResult{}, ctx.Err()
	}))
	cancelCtx, cancel := context.WithCancel(authRootContext("aws"))
	cancel()
	_, err = service.ResolveOIDCSigningKeys(cancelCtx, arn)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
	service.SetOIDCDiscovery(nil)
	_, err = c.CreateOpenIDConnectProvider(ctx, &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://offline.example.com")})
	requireCode(t, err, "OpenIdIdpCommunicationError")
}

func TestSAMLMetadataRotationSnapshotsAndConcurrency(t *testing.T) {
	ctx := context.Background()
	service := iam.New()
	c := clientFor(t, service, "123456789012", "us-east-1")
	metadata := federationFixture(t, "metadata.xml")
	key := federationFixture(t, "private-key-1.pem")
	created, err := c.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String("rotate"), SAMLMetadataDocument: aws.String(metadata), AddPrivateKey: aws.String(key), AssertionEncryptionMode: types.AssertionEncryptionModeTypeRequired})
	if err != nil {
		t.Fatal(err)
	}
	before, err := c.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn})
	if err != nil {
		t.Fatal(err)
	}
	if before.ValidUntil.Sub(before.CreateDate.AddDate(100, 0, 0)) > time.Second {
		t.Fatal("ValidUntil follows metadata expiry")
	}
	arn := aws.ToString(created.SAMLProviderArn)
	snapshot, err := service.SAMLProviderForFederation(authRootContext("aws"), arn)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.PrivateKeys[0].PKCS8DER[0] = 0
	snapshot.Issuers[0].SigningCertificates[0][0] = 0
	again, err := service.SAMLProviderForFederation(authRootContext("aws"), arn)
	if err != nil || again.PrivateKeys[0].PKCS8DER[0] == 0 || again.Issuers[0].SigningCertificates[0][0] == 0 {
		t.Fatal("snapshot aliases repository")
	}
	_, err = c.UpdateSAMLProvider(ctx, &sdkiam.UpdateSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn, SAMLMetadataDocument: aws.String(strings.ReplaceAll(metadata, "stackd-idp", "replaced")), RemovePrivateKey: aws.String("SAMLPK0000000000000000")})
	requireCode(t, err, "InvalidInput")
	state, err := c.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn})
	if err != nil || aws.ToString(state.SAMLMetadataDocument) != metadata || !state.ValidUntil.Equal(*before.ValidUntil) {
		t.Fatal("failed rotation partially committed metadata")
	}
	var wg sync.WaitGroup
	failures := make(chan error, 20)
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, err := c.TagSAMLProvider(ctx, &sdkiam.TagSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn, Tags: []types.Tag{{Key: aws.String(fmt.Sprintf("k%d", i)), Value: aws.String("v")}}})
			if err != nil {
				failures <- err
			}
		}(i)
		go func() {
			defer wg.Done()
			_, err := c.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn})
			if err != nil {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	state, err = c.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn})
	if err != nil || len(state.Tags) != 10 {
		t.Fatalf("lost concurrent tags %+v %v", state, err)
	}
	collection := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + metadata + strings.ReplaceAll(strings.ReplaceAll(metadata, "stackd-idp", "second-idp"), `use="signing"`, `use="encryption"`) + `</EntitiesDescriptor>`
	if _, err = c.UpdateSAMLProvider(ctx, &sdkiam.UpdateSAMLProviderInput{SAMLProviderArn: created.SAMLProviderArn, SAMLMetadataDocument: aws.String(collection)}); err != nil {
		t.Fatal(err)
	}
	final, err := service.SAMLProviderForFederation(authRootContext("aws"), arn)
	if err != nil || len(final.Issuers) != 2 || len(final.Issuers[0].SigningCertificates) != 1 || len(final.Issuers[1].SigningCertificates) != 0 || !slices.Equal(final.PrivateKeys[0].PKCS8DER, again.PrivateKeys[0].PKCS8DER) {
		t.Fatalf("issuer trust or keys changed: %+v %v", final.Issuers, err)
	}
}
