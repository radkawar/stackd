package glue_test

import (
	"testing"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/glue"
)

func TestEmptyCatalogEncryptionSettingsRestoreDefaults(t *testing.T) {
	s := glue.New(glue.Config{})
	defer s.Close()
	ctx := catalogTestContext("123456789012", "us-east-1")
	put := func(settings *api.DataCatalogEncryptionSettings) {
		t.Helper()
		catalogTestCall[api.PutDataCatalogEncryptionSettingsOutput](t, s, ctx, "PutDataCatalogEncryptionSettings", &api.PutDataCatalogEncryptionSettingsInput{DataCatalogEncryptionSettings: settings})
	}
	get := func() *api.ConnectionPasswordEncryption {
		t.Helper()
		return catalogTestCall[api.GetDataCatalogEncryptionSettingsOutput](t, s, ctx, "GetDataCatalogEncryptionSettings", &api.GetDataCatalogEncryptionSettingsInput{}).DataCatalogEncryptionSettings.ConnectionPasswordEncryption
	}
	enabled := &api.DataCatalogEncryptionSettings{ConnectionPasswordEncryption: &api.ConnectionPasswordEncryption{ReturnConnectionPasswordEncrypted: new(api.Boolean(true)), AwsKmsKeyId: new(api.NameString("arn:aws:kms:us-east-1:123456789012:key/owned"))}, EncryptionAtRest: &api.EncryptionAtRest{CatalogEncryptionMode: new(api.CatalogEncryptionMode("DISABLED"))}}
	put(enabled)
	if got := get(); !bool(*got.ReturnConnectionPasswordEncrypted) || got.AwsKmsKeyId == nil {
		t.Fatal("explicit password settings did not persist")
	}
	put(&api.DataCatalogEncryptionSettings{})
	if got := get(); bool(*got.ReturnConnectionPasswordEncrypted) || got.AwsKmsKeyId != nil {
		t.Fatalf("provider destroy retained encryption settings: %+v", got)
	}
	put(enabled)
	put(&api.DataCatalogEncryptionSettings{EncryptionAtRest: &api.EncryptionAtRest{CatalogEncryptionMode: new(api.CatalogEncryptionMode("DISABLED"))}})
	if got := get(); bool(*got.ReturnConnectionPasswordEncrypted) || got.AwsKmsKeyId != nil {
		t.Fatalf("omitted password configuration was patched instead of replaced: %+v", got)
	}
	// A rejected replacement must not change the previous valid settings.
	put(enabled)
	catalogTestError(t, s, ctx, "PutDataCatalogEncryptionSettings", &api.PutDataCatalogEncryptionSettingsInput{DataCatalogEncryptionSettings: &api.DataCatalogEncryptionSettings{EncryptionAtRest: &api.EncryptionAtRest{CatalogEncryptionMode: new(api.CatalogEncryptionMode("SSE-KMS"))}}}, "InvalidInputException")
	if got := get(); !bool(*got.ReturnConnectionPasswordEncrypted) || got.AwsKmsKeyId == nil {
		t.Fatal("unavailable catalog encryption changed valid password settings")
	}
}
