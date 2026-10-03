package appsync

import (
	"context"
	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
	"time"
)

func controlCall(s *Service, ctx context.Context, action string, input any) (any, *awswire.Error) {
	m, _ := awscatalog.LookupService("appsync")
	op, _ := m.Operation(action)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}
func TestExpiredAPIKeyRenewalAndDeletionBoundary(t *testing.T) {
	now := time.Date(2031, 2, 3, 4, 17, 21, 0, time.UTC)
	timer := clock.NewManual(now)
	repository := NewMemoryRepository(nil)
	s := NewWithConfig(Config{Repository: repository, Clock: timer})
	k := Key{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", ID: "api"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	if e := repository.Update(ctx, func(tx Transaction) error { return tx.PutAPI(APIRecord{Key: k}) }); e != nil {
		t.Fatal(e)
	}
	input := &api.CreateApiKeyRequest{ApiId: new(api.String(k.ID)), Expires: new(api.Long(now.Add(24*time.Hour - time.Second).Unix()))}
	if _, e := controlCall(s, ctx, "CreateApiKey", input); e == nil || e.Code != "ApiKeyValidityOutOfBoundsException" {
		t.Fatalf("short key validity: %v", e)
	}
	input.Expires = new(api.Long(now.Add(24 * time.Hour).Unix()))
	out, e := controlCall(s, ctx, "CreateApiKey", input)
	if e != nil {
		t.Fatal(e)
	}
	key := out.(*api.CreateApiKeyResponse).ApiKey
	expected := now.Add(24 * time.Hour).Truncate(time.Hour).Unix()
	if int64(*key.Expires) != expected || int64(*key.Deletes) != expected+60*86400 {
		t.Fatalf("hour rounding or deletion interval: %#v", key)
	}
	out, e = controlCall(s, ctx, "UpdateApiKey", &api.UpdateApiKeyRequest{ApiId: input.ApiId, Id: key.Id, Description: new(api.String("renamed")), Expires: new(api.Long(0))})
	if e != nil {
		t.Fatal(e)
	}
	unchanged := out.(*api.UpdateApiKeyResponse).ApiKey
	if int64(*unchanged.Expires) != expected || value(unchanged.Description) != "renamed" {
		t.Fatalf("zero expiry must retain validity while updating description: %#v", unchanged)
	}
	if e := timer.Advance(2 * 24 * time.Hour); e != nil {
		t.Fatal(e)
	}
	renewal := &api.UpdateApiKeyRequest{ApiId: input.ApiId, Id: key.Id, Expires: new(api.Long(timer.Now().Add(7 * 24 * time.Hour).Unix()))}
	out, e = controlCall(s, ctx, "UpdateApiKey", renewal)
	if e != nil {
		t.Fatal(e)
	}
	renewed := out.(*api.UpdateApiKeyResponse).ApiKey
	if *renewed.Expires <= *key.Expires || value(renewed.Id) != value(key.Id) {
		t.Fatal("expired retained key was not reinstated with the same identity")
	}
	if e := timer.Advance(time.Unix(int64(*renewed.Deletes), 0).Sub(timer.Now())); e != nil {
		t.Fatal(e)
	}
	renewal.Expires = new(api.Long(timer.Now().Add(7 * 24 * time.Hour).Unix()))
	if _, e = controlCall(s, ctx, "UpdateApiKey", renewal); e == nil || e.Code != "NotFoundException" {
		t.Fatalf("deleted key was renewed: %v", e)
	}
	out, e = controlCall(s, ctx, "ListApiKeys", &api.ListApiKeysRequest{ApiId: input.ApiId})
	if e != nil {
		t.Fatal(e)
	}
	if len(out.(*api.ListApiKeysResponse).ApiKeys) != 0 {
		t.Fatal("deleted key remained visible")
	}
}

func TestPaginationCursorSurvivesDeletionAndRejectsDifferentScope(t *testing.T) {
	max := new(api.MaxResults(2))
	items := []string{"a", "b", "c", "d"}
	id := func(v string) string { return v }
	first, next, e := page(items, nil, max, "api/one/functions", id)
	if e != nil {
		t.Fatal(e)
	}
	if len(first) != 2 || first[0] != "a" || first[1] != "b" {
		t.Fatalf("first page: %v", first)
	}
	second, token, e := page([]string{"c", "d"}, next, max, "api/one/functions", id)
	if e != nil {
		t.Fatal(e)
	}
	if len(second) != 2 || second[0] != "c" || second[1] != "d" || token != nil {
		t.Fatalf("cursor after deletion: %v %v", second, token)
	}
	if _, _, e = page(items, next, max, "api/two/functions", id); e == nil {
		t.Fatal("cross-API token accepted")
	}
}
