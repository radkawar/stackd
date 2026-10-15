package route53

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/route53"
	"stackd/internal/awsctx"
)

func TestUnsignedDNSSECScopedExistenceAndCurrentIAM(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "unsigned.test", "unsigned")
	read := &api.GetDNSSECRequest{HostedZoneId: z.HostedZone.Id}
	check := func(ctx context.Context) {
		t.Helper()
		out := invoke[api.GetDNSSECResponse](t, s, ctx, "GetDNSSEC", read)
		if out.Status == nil || value(out.Status.ServeSignature) != "NOT_SIGNING" || len(out.KeySigningKeys) != 0 || out.Status.StatusMessage != nil {
			t.Fatalf("unsigned zone DNSSEC state: %#v", out)
		}
	}
	check(ctx)
	read.HostedZoneId = new(api.ResourceId(cleanID(value(z.HostedZone.Id))))
	check(ctx)
	reject(t, s, rootContext("222222222222"), "GetDNSSEC", read, "NoSuchHostedZone")
	foreignPartition := awsctx.FromContext(ctx)
	foreignPartition.Partition = "aws-cn"
	reject(t, s, awsctx.WithMetadata(context.Background(), foreignPartition), "GetDNSSEC", read, "NoSuchHostedZone")
	source := &currentPolicies{set: authorization.PolicySet{Identity: []policy.Policy{{Document: fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"route53:GetDNSSEC","Resource":"arn:aws:route53:::hostedzone/%s"}]}`, cleanID(value(z.HostedZone.Id)))}}}}
	s.authorizer = authorization.New(source, nil)
	m := awsctx.FromContext(ctx)
	m.PrincipalARN, m.PrincipalID = "arn:aws:iam::111111111111:user/reader", "AIDAREADER"
	user := awsctx.WithMetadata(context.Background(), m)
	check(user)
	other := createZone(t, s, ctx, "other.test", "other")
	reject(t, s, user, "GetDNSSEC", &api.GetDNSSECRequest{HostedZoneId: other.HostedZone.Id}, "AccessDenied")
	source.set.Identity = nil
	reject(t, s, user, "GetDNSSEC", read, "AccessDenied")
	check(ctx)
	invoke[api.DeleteHostedZoneResponse](t, s, ctx, "DeleteHostedZone", &api.DeleteHostedZoneRequest{Id: z.HostedZone.Id})
	reject(t, s, ctx, "GetDNSSEC", read, "NoSuchHostedZone")
	reject(t, s, ctx, "GetDNSSEC", &api.GetDNSSECRequest{HostedZoneId: new(api.ResourceId("ZUNKNOWN"))}, "NoSuchHostedZone")
}

func TestSDKUnsignedDNSSECAndUnsupportedSigning(t *testing.T) {
	s, _ := testService(t)
	client := sdkClient(t, s)
	ctx := t.Context()
	z, err := client.CreateHostedZone(ctx, &sdk.CreateHostedZoneInput{Name: new("dnssec-sdk.test"), CallerReference: new("dnssec-sdk")})
	if err != nil {
		t.Fatal(err)
	}
	read := &sdk.GetDNSSECInput{HostedZoneId: z.HostedZone.Id}
	got, err := client.GetDNSSEC(ctx, read)
	if err != nil || got == nil || got.Status == nil || aws.ToString(got.Status.ServeSignature) != "NOT_SIGNING" || len(got.KeySigningKeys) != 0 {
		t.Fatalf("GetDNSSEC=%#v err=%v", got, err)
	}
	reject(t, s, rootContext("111111111111"), "EnableHostedZoneDNSSEC", &api.EnableHostedZoneDNSSECRequest{HostedZoneId: new(api.ResourceId(aws.ToString(z.HostedZone.Id)))}, "NotImplemented")
	if _, err := client.DeleteHostedZone(ctx, &sdk.DeleteHostedZoneInput{Id: z.HostedZone.Id}); err != nil {
		t.Fatal(err)
	}
	_, err = client.GetDNSSEC(ctx, read)
	var missing *types.NoSuchHostedZone
	if !errors.As(err, &missing) {
		t.Fatalf("modeled NoSuchHostedZone not decoded: %T %v", err, err)
	}
}
