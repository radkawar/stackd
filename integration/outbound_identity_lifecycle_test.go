package stackd_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd"
	"stackd/clock"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

func TestOutboundIdentityOrderedPropagationSurvivesReconstruction(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0).UTC())
	backends := storage.NewMemory()
	var active atomic.Pointer[stackd.Stack]
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { active.Load().ServeHTTP(w, r) }))
	config := stackd.Config{Clock: source, Storage: backends, PublicEndpoint: "http://" + server.Listener.Addr().String()}
	instance, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(instance)
	server.Start()
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if err := active.Load().Close(); err != nil {
			t.Error(err)
		}
	})
	c := cloudClients{server}
	root := c.iam("test", "test", "")
	ctx := t.Context()
	enabled, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := root.GetOutboundWebIdentityFederationInfo(ctx, &iam.GetOutboundWebIdentityFederationInfoInput{})
	if err != nil || !info.JwtVendingEnabled {
		t.Fatalf("IAM configuration should be immediately enabled: %+v %v", info, err)
	}
	_, key, secret := c.user(t, "test", "propagation")
	putUserPolicy(t, root, "propagation", allow(`"sts:GetWebIdentityToken"`, "*"))
	caller := c.sts(key, secret, "")
	check := func(code string) {
		t.Helper()
		out, err := caller.GetWebIdentityToken(ctx, outboundInput())
		if code != "" {
			assertAPIError(t, err, code)
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		verifyOutboundJWT(t, aws.ToString(enabled.IssuerIdentifier), aws.ToString(out.WebIdentityToken), source.Now())
	}
	advanceClock(t, source, 10*time.Second-time.Nanosecond)
	check("OutboundWebIdentityFederationDisabledException")
	advanceClock(t, source, time.Nanosecond)
	check("")
	if _, err := root.DisableOutboundWebIdentityFederation(ctx, &iam.DisableOutboundWebIdentityFederationInput{}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 2*time.Second)
	again, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil || aws.ToString(again.IssuerIdentifier) != aws.ToString(enabled.IssuerIdentifier) {
		t.Fatalf("issuer changed: %+v %v", again, err)
	}
	// Both delayed changes must survive provider reconstruction. The backend,
	// clock and public listener remain owned by the embedding application.
	if err := instance.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(restored)
	check("")
	advanceClock(t, source, 8*time.Second-time.Nanosecond)
	check("")
	advanceClock(t, source, time.Nanosecond)
	check("OutboundWebIdentityFederationDisabledException")
	info, err = root.GetOutboundWebIdentityFederationInfo(ctx, &iam.GetOutboundWebIdentityFederationInfoInput{})
	if err != nil || !info.JwtVendingEnabled {
		t.Fatal("STS propagation changed the newer IAM configuration")
	}
	advanceClock(t, source, 2*time.Second-time.Nanosecond)
	check("OutboundWebIdentityFederationDisabledException")
	advanceClock(t, source, time.Nanosecond)
	check("")
	advanceClock(t, source, 6*time.Hour)
	check("")
}

type accountSettingsRepository struct {
	iamstore.Repository
	reject atomic.Bool
}
type accountSettingsTx struct {
	iamstore.WriteTx
	reject bool
}

func (r *accountSettingsRepository) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iamstore.WriteTx) error { return fn(accountSettingsTx{tx, r.reject.Load()}) })
}
func (tx accountSettingsTx) PutAccountSettings(scope iamstore.Scope, record iamstore.AccountSettingsRecord) error {
	if err := tx.WriteTx.PutAccountSettings(scope, record); err != nil {
		return err
	}
	if tx.reject {
		return errors.New("injected IAM account configuration commit failure")
	}
	return nil
}

func TestOutboundIdentityFailedConfigurationDoesNotPropagate(t *testing.T) {
	backends := storage.NewMemory()
	repository := &accountSettingsRepository{Repository: backends.IAM}
	backends.IAM = repository
	c, source := outboundCloud(t, stackd.Config{Storage: backends})
	ctx := t.Context()
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "rollback")
	putUserPolicy(t, root, "rollback", allow(`"sts:GetWebIdentityToken"`, "*"))
	caller := c.sts(key, secret, "")
	repository.reject.Store(true)
	out, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err == nil || out != nil {
		t.Fatalf("failed enable published result: %+v %v", out, err)
	}
	repository.reject.Store(false)
	advanceClock(t, source, 20*time.Second)
	_, err = caller.GetWebIdentityToken(ctx, outboundInput())
	assertAPIError(t, err, "OutboundWebIdentityFederationDisabledException")
	enabled, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
	if err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 10*time.Second)
	repository.reject.Store(true)
	disabled, err := root.DisableOutboundWebIdentityFederation(ctx, &iam.DisableOutboundWebIdentityFederationInput{})
	if err == nil || disabled != nil {
		t.Fatalf("failed disable published result: %+v %v", disabled, err)
	}
	repository.reject.Store(false)
	advanceClock(t, source, 20*time.Second)
	token, err := caller.GetWebIdentityToken(ctx, outboundInput())
	if err != nil {
		t.Fatal(err)
	}
	verifyOutboundJWT(t, aws.ToString(enabled.IssuerIdentifier), aws.ToString(token.WebIdentityToken), source.Now())
}

func TestOutboundIdentityPartitionIsolation(t *testing.T) {
	c, source := outboundCloud(t, stackd.Config{})
	ctx := t.Context()
	type partitionClient struct {
		partition, issuer string
		iam               *iam.Client
		sts               *sts.Client
	}
	var clients []partitionClient
	for _, location := range []struct{ partition, region string }{
		{"aws", "us-east-1"}, {"aws-cn", "cn-north-1"}, {"aws-us-gov", "us-gov-west-1"},
	} {
		root := iam.New(c.iam("test", "test", "").Options(), func(o *iam.Options) { o.Region = location.region })
		_, err := root.GetOutboundWebIdentityFederationInfo(ctx, &iam.GetOutboundWebIdentityFederationInfoInput{})
		assertAPIError(t, err, "FeatureDisabled")
		if _, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("outbound-partition")}); err != nil {
			t.Fatal(err)
		}
		putUserPolicy(t, root, "outbound-partition", allow(`"sts:GetWebIdentityToken"`, "*"))
		keys, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("outbound-partition")})
		if err != nil {
			t.Fatal(err)
		}
		caller := sts.New(c.sts(aws.ToString(keys.AccessKey.AccessKeyId), aws.ToString(keys.AccessKey.SecretAccessKey), "").Options(), func(o *sts.Options) { o.Region = location.region })
		enabled, err := root.EnableOutboundWebIdentityFederation(ctx, &iam.EnableOutboundWebIdentityFederationInput{})
		if err != nil {
			t.Fatal(err)
		}
		issuer := aws.ToString(enabled.IssuerIdentifier)
		if !strings.Contains(issuer, "/oidc/"+location.partition+"/000000000000/") {
			t.Fatalf("issuer has wrong partition: %s", issuer)
		}
		clients = append(clients, partitionClient{location.partition, issuer, root, caller})
	}
	advanceClock(t, source, 10*time.Second)
	for _, client := range clients {
		out, err := client.sts.GetWebIdentityToken(ctx, outboundInput())
		if err != nil {
			t.Fatal(err)
		}
		claims := verifyOutboundJWT(t, client.issuer, aws.ToString(out.WebIdentityToken), source.Now())
		if claims["sub"] != "arn:"+client.partition+":iam::000000000000:user/outbound-partition" {
			t.Fatalf("partition subject: %v", claims["sub"])
		}
	}
	if _, err := clients[0].iam.DisableOutboundWebIdentityFederation(ctx, &iam.DisableOutboundWebIdentityFederationInput{}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 10*time.Second)
	for i, client := range clients {
		out, err := client.sts.GetWebIdentityToken(ctx, outboundInput())
		if i == 0 {
			assertAPIError(t, err, "OutboundWebIdentityFederationDisabledException")
		} else if err != nil {
			t.Fatalf("commercial disable reached %s: %v", client.partition, err)
		} else {
			verifyOutboundJWT(t, client.issuer, aws.ToString(out.WebIdentityToken), source.Now())
		}
	}
}
