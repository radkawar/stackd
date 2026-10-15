package apigateway

import (
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awsctx"
	"testing"
)

func TestCreateAPIKeyEmptyOptionalValueGeneratesIndependentKeys(t *testing.T) {
	s := New(Config{})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	var keys []*api.ApiKey
	for _, requested := range []*api.String{nil, ptr("")} {
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			key, err := s.createAPIKey(tx, &api.CreateApiKeyRequest{Value: requested, Enabled: new(api.Boolean(true))})
			if err != nil {
				return err
			}
			if err := validClientKeyValue(value(key.Value)); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, key)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if value(keys[0].Id) == value(keys[1].Id) || value(keys[0].Value) == value(keys[1].Value) {
		t.Fatal("independent key creations reused identity or bearer value")
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.createAPIKey(tx, &api.CreateApiKeyRequest{Value: ptr("not-a-valid-api-key")})
		if err == nil {
			t.Fatal("nonempty invalid value was accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
