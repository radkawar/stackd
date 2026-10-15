package athena_test

import (
	"context"
	"maps"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/athena"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
)

func TestUpdateDataCatalogPreservesOmittedFieldsAndCurrentAuthority(t *testing.T) {
	root := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	domain := memory.NewDomain()
	identities := iam.NewMemoryRepository(domain)
	identityService := iam.NewWithConfig(iam.Config{Repository: identities})
	service := athena.New(athena.Config{Repository: athena.NewMemoryRepository(domain), Authorizer: authorization.New(identityService, nil)})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	name := new(api.CatalogNameString("lake"))
	kind := new(api.DataCatalogType("GLUE"))
	parameters := api.ParametersMap{"catalog-id": "123456789012", "kept": "original"}
	namedQueryCall[api.CreateDataCatalogOutput](t, service, root, "CreateDataCatalog", &api.CreateDataCatalogInput{Name: name, Type: kind, Description: new(api.DescriptionString("initial")), Parameters: parameters, Tags: api.TagList{{Key: new(api.TagKey("access")), Value: new(api.TagValue("allowed"))}}})
	read := func() *api.DataCatalog {
		t.Helper()
		return namedQueryCall[api.GetDataCatalogOutput](t, service, root, "GetDataCatalog", &api.GetDataCatalogInput{Name: name}).DataCatalog
	}
	check := func(description string, expected api.ParametersMap) {
		t.Helper()
		catalog := read()
		if catalog.Description == nil || string(*catalog.Description) != description || !maps.Equal(catalog.Parameters, expected) || catalog.Type == nil || *catalog.Type != *kind {
			t.Fatalf("catalog changed unexpectedly: %+v", catalog)
		}
	}
	// The pinned provider omits unchanged Parameters on description updates.
	namedQueryCall[api.UpdateDataCatalogOutput](t, service, root, "UpdateDataCatalog", &api.UpdateDataCatalogInput{Name: name, Type: kind, Description: new(api.DescriptionString("updated"))})
	check("updated", parameters)
	parameters = api.ParametersMap{"catalog-id": "210987654321"}
	namedQueryCall[api.UpdateDataCatalogOutput](t, service, root, "UpdateDataCatalog", &api.UpdateDataCatalogInput{Name: name, Type: kind, Parameters: parameters})
	check("updated", parameters)

	model, _ := awscatalog.LookupService("athena")
	operation, _ := model.Operation("UpdateDataCatalog")
	reject := func(ctx context.Context, input *api.UpdateDataCatalogInput, code string) {
		t.Helper()
		_, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: awscatalog.AWSJSON11, Input: input})
		if rejected == nil || rejected.Code != code {
			t.Fatalf("update rejection = %v; want %s", rejected, code)
		}
		check("updated", parameters)
	}
	reject(root, &api.UpdateDataCatalogInput{Name: name, Type: kind, Parameters: api.ParametersMap{}, Description: new(api.DescriptionString("not admitted"))}, "InvalidRequestException")
	reject(root, &api.UpdateDataCatalogInput{Name: name, Type: new(api.DataCatalogType("HIVE"))}, "InvalidRequestException")

	user := iam.User{UserName: "catalog-reader", UserId: "AIDACATALOG", Arn: "arn:aws:iam::123456789012:user/catalog-reader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	caller := awsctx.WithMetadata(root, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	setPolicy := func(document string) {
		t.Helper()
		user.IdentityPolicies.Inline["catalog"] = document
		if err := identities.Update(root, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	setPolicy(`{"Statement":[{"Effect":"Allow","Action":"athena:UpdateDataCatalog","Resource":"arn:aws:athena:us-east-1:123456789012:datacatalog/lake","Condition":{"StringEquals":{"aws:ResourceTag/access":"allowed"}}}]}`)
	namedQueryCall[api.UpdateDataCatalogOutput](t, service, caller, "UpdateDataCatalog", &api.UpdateDataCatalogInput{Name: name, Type: kind})
	arn := new(api.AmazonResourceName("arn:aws:athena:us-east-1:123456789012:datacatalog/lake"))
	namedQueryCall[api.TagResourceOutput](t, service, root, "TagResource", &api.TagResourceInput{ResourceARN: arn, Tags: api.TagList{{Key: new(api.TagKey("access")), Value: new(api.TagValue("revoked"))}}})
	reject(caller, &api.UpdateDataCatalogInput{Name: name, Type: kind, Description: new(api.DescriptionString("denied by current tag"))}, "AccessDeniedException")
	namedQueryCall[api.TagResourceOutput](t, service, root, "TagResource", &api.TagResourceInput{ResourceARN: arn, Tags: api.TagList{{Key: new(api.TagKey("access")), Value: new(api.TagValue("allowed"))}}})
	setPolicy(`{"Statement":[{"Effect":"Deny","Action":"athena:UpdateDataCatalog","Resource":"*"}]}`)
	reject(caller, &api.UpdateDataCatalogInput{Name: name, Type: kind, Parameters: api.ParametersMap{"catalog-id": "999999999999"}}, "AccessDeniedException")
}
