package route53

import (
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"io"
	"net/http"
	"net/http/httptest"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/route53"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
)

func sdkClient(t *testing.T, s *Service) *sdk.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		model, _ := awscatalog.LookupService("route53")
		op, labels, ok := model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header)
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		decoded, e := api.DecodeRequest(string(op.Name), awsapi.Request{Body: body, Labels: labels, Query: r.URL.Query(), Header: r.Header})
		if e != nil {
			awswire.RESTXMLError(w, r, &model, s.RequestError(string(op.Name), e))
			return
		}
		ctx := awsctx.WithMetadata(r.Context(), awsctx.FromContext(rootContext("111111111111")))
		s.ServeHTTP(w, r.WithContext(awsapi.WithDecodedRequest(ctx, decoded)))
	}))
	t.Cleanup(server.Close)
	return sdk.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1, HTTPClient: server.Client()}, func(o *sdk.Options) { o.BaseEndpoint = new(server.URL) })
}
func TestSDKHostedZoneAndTransactionalModeledError(t *testing.T) {
	s, _ := testService(t)
	client := sdkClient(t, s)
	ctx := t.Context()
	z, e := client.CreateHostedZone(ctx, &sdk.CreateHostedZoneInput{Name: new("sdk.test"), CallerReference: new("sdk-contract")})
	if e != nil {
		t.Fatal(e)
	}
	if aws.ToString(z.HostedZone.Name) != "sdk.test." || aws.ToString(z.HostedZone.Id) == "" || z.ChangeInfo.Status != types.ChangeStatusPending || len(z.DelegationSet.NameServers) != 4 {
		t.Fatalf("invalid created zone: %#v", z)
	}
	got, e := client.GetHostedZone(ctx, &sdk.GetHostedZoneInput{Id: z.HostedZone.Id})
	if e != nil || aws.ToInt64(got.HostedZone.ResourceRecordSetCount) != 2 {
		t.Fatalf("GetHostedZone=%#v err=%v", got, e)
	}
	listed, e := client.ListHostedZones(ctx, &sdk.ListHostedZonesInput{MaxItems: new(int32(1))})
	if e != nil || len(listed.HostedZones) != 1 || aws.ToString(listed.HostedZones[0].Id) != aws.ToString(z.HostedZone.Id) {
		t.Fatalf("ListHostedZones=%#v err=%v", listed, e)
	}
	record := types.ResourceRecordSet{Name: new("app.sdk.test"), Type: types.RRTypeA, TTL: new(int64(60)), ResourceRecords: []types.ResourceRecord{{Value: new("192.0.2.9")}}}
	_, e = client.ChangeResourceRecordSets(ctx, &sdk.ChangeResourceRecordSetsInput{HostedZoneId: z.HostedZone.Id, ChangeBatch: &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionCreate, ResourceRecordSet: &record}}}})
	if e != nil {
		t.Fatal(e)
	}
	bad := types.ResourceRecordSet{Name: new("outside.test"), Type: types.RRTypeA, TTL: new(int64(60)), ResourceRecords: []types.ResourceRecord{{Value: new("192.0.2.10")}}}
	_, e = client.ChangeResourceRecordSets(ctx, &sdk.ChangeResourceRecordSetsInput{HostedZoneId: z.HostedZone.Id, ChangeBatch: &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionDelete, ResourceRecordSet: &record}, {Action: types.ChangeActionCreate, ResourceRecordSet: &bad}}}})
	var rejected *types.InvalidChangeBatch
	if !errors.As(e, &rejected) {
		t.Fatalf("modeled InvalidChangeBatch not decoded: %T %v", e, e)
	}
	requireA(t, s, "app.sdk.test.", [4]byte{192, 0, 2, 9})
	page, e := client.ListResourceRecordSets(ctx, &sdk.ListResourceRecordSetsInput{HostedZoneId: z.HostedZone.Id, StartRecordName: new("app.sdk.test"), StartRecordType: types.RRTypeA, MaxItems: new(int32(1))})
	if e != nil || len(page.ResourceRecordSets) != 1 || aws.ToString(page.ResourceRecordSets[0].ResourceRecords[0].Value) != "192.0.2.9" {
		t.Fatalf("list record result=%#v err=%v", page, e)
	}
	_, e = client.UpdateHostedZoneComment(ctx, &sdk.UpdateHostedZoneCommentInput{Id: z.HostedZone.Id, Comment: new("retained comment")})
	if e != nil {
		t.Fatal(e)
	}
	got, e = client.GetHostedZone(ctx, &sdk.GetHostedZoneInput{Id: z.HostedZone.Id})
	if e != nil || aws.ToString(got.HostedZone.Config.Comment) != "retained comment" {
		t.Fatalf("comment result=%#v err=%v", got, e)
	}
	_, e = client.ChangeResourceRecordSets(ctx, &sdk.ChangeResourceRecordSetsInput{HostedZoneId: z.HostedZone.Id, ChangeBatch: &types.ChangeBatch{Changes: []types.Change{{Action: types.ChangeActionDelete, ResourceRecordSet: &record}}}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = client.DeleteHostedZone(ctx, &sdk.DeleteHostedZoneInput{Id: z.HostedZone.Id})
	if e != nil {
		t.Fatal(e)
	}
	_, e = client.GetHostedZone(ctx, &sdk.GetHostedZoneInput{Id: z.HostedZone.Id})
	var missing *types.NoSuchHostedZone
	if !errors.As(e, &missing) {
		t.Fatalf("modeled NoSuchHostedZone not decoded: %v", e)
	}
}
