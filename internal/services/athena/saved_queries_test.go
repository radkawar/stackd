package athena_test

import (
	"context"
	"fmt"
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

func namedQueryCall[O any](t *testing.T, service *athena.Service, ctx context.Context, action string, input any) *O {
	t.Helper()
	model, _ := awscatalog.LookupService("athena")
	operation, ok := model.Operation(action)
	if !ok {
		t.Fatalf("missing generated operation %s", action)
	}
	output, rejected := service.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: awscatalog.AWSJSON11, Input: input})
	if rejected != nil {
		t.Fatal(rejected)
	}
	return output.(*O)
}

// The current provider's named-query data source uses this batch API. Exercise
// real typed catalog and IAM owners, not a provider-specific response fixture.
func TestBatchGetNamedQueryUsesCurrentWorkgroupAuthority(t *testing.T) {
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
	user := iam.User{UserName: "reader", UserId: "AIDAREADER", Arn: "arn:aws:iam::123456789012:user/reader", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{}}}
	caller := awsctx.WithMetadata(root, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: user.Arn, PrincipalID: user.UserId})
	setPolicy := func(document string) {
		t.Helper()
		user.IdentityPolicies.Inline["named"] = document
		if err := identities.Update(root, func(tx iam.WriteTx) error {
			return tx.PutUser(iam.Scope{Partition: "aws", AccountID: "123456789012"}, user)
		}); err != nil {
			t.Fatal(err)
		}
	}
	ids := api.NamedQueryIdList{}
	for _, group := range []string{"allowed", "other"} {
		namedQueryCall[api.CreateWorkGroupOutput](t, service, root, "CreateWorkGroup", &api.CreateWorkGroupInput{Name: new(api.WorkGroupName(group)), Tags: api.TagList{{Key: new(api.TagKey("access")), Value: new(api.TagValue(group))}}})
		created := namedQueryCall[api.CreateNamedQueryOutput](t, service, root, "CreateNamedQuery", &api.CreateNamedQueryInput{WorkGroup: new(api.WorkGroupName(group)), Name: new(api.NameString(group)), Database: new(api.DatabaseString("database")), QueryString: new(api.QueryString("SELECT 1"))})
		ids = append(ids, *created.NamedQueryId)
	}
	ids = append(ids, "missing-query-id")
	setPolicy(`{"Statement":[{"Effect":"Allow","Action":"athena:BatchGetNamedQuery","Resource":"arn:aws:athena:us-east-1:123456789012:workgroup/*","Condition":{"StringEquals":{"aws:ResourceTag/access":"allowed"}}}]}`)
	read := func() *api.BatchGetNamedQueryOutput {
		return namedQueryCall[api.BatchGetNamedQueryOutput](t, service, caller, "BatchGetNamedQuery", &api.BatchGetNamedQueryInput{NamedQueryIds: ids})
	}
	result := read()
	if len(result.NamedQueries) != 1 || *result.NamedQueries[0].NamedQueryId != ids[0] || len(result.UnprocessedNamedQueryIds) != 2 {
		t.Fatalf("wrong partial batch: %+v", result)
	}
	if string(*result.UnprocessedNamedQueryIds[0].ErrorCode) != "AccessDeniedException" || *result.UnprocessedNamedQueryIds[0].NamedQueryId != ids[1] || string(*result.UnprocessedNamedQueryIds[1].ErrorCode) != "InvalidRequestException" {
		t.Fatalf("wrong unprocessed identities/errors: %+v", result.UnprocessedNamedQueryIds)
	}
	arn := "arn:aws:athena:us-east-1:123456789012:workgroup/allowed"
	namedQueryCall[api.TagResourceOutput](t, service, root, "TagResource", &api.TagResourceInput{ResourceARN: new(api.AmazonResourceName(arn)), Tags: api.TagList{{Key: new(api.TagKey("access")), Value: new(api.TagValue("revoked"))}}})
	if revoked := read(); len(revoked.NamedQueries) != 0 || len(revoked.UnprocessedNamedQueryIds) != 3 {
		t.Fatalf("changed current tags did not revoke access: %+v", revoked)
	}
	setPolicy(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"athena:BatchGetNamedQuery","Resource":%q}]}`, arn))
	if restored := read(); len(restored.NamedQueries) != 1 || *restored.NamedQueries[0].NamedQueryId != ids[0] {
		t.Fatalf("changed current IAM policy did not restore access: %+v", restored)
	}
	otherRegion := awsctx.WithMetadata(root, awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-west-2", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	regional := namedQueryCall[api.BatchGetNamedQueryOutput](t, service, otherRegion, "BatchGetNamedQuery", &api.BatchGetNamedQueryInput{NamedQueryIds: ids[:2]})
	if len(regional.NamedQueries) != 0 || len(regional.UnprocessedNamedQueryIds) != 2 {
		t.Fatalf("batch crossed regional ownership: %+v", regional)
	}
}

func TestBatchGetNamedQueryRejectsInvalidBatchSize(t *testing.T) {
	service := athena.New(athena.Config{})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	model, _ := awscatalog.LookupService("athena")
	operation, _ := model.Operation("BatchGetNamedQuery")
	for _, count := range []int{0, 51} {
		input := &api.BatchGetNamedQueryInput{NamedQueryIds: make(api.NamedQueryIdList, count)}
		_, rejected := service.ExecuteCommand(context.Background(), awsapi.DecodedRequest{Operation: operation, Protocol: awscatalog.AWSJSON11, Input: input})
		if rejected == nil || rejected.Code != "InvalidRequestException" {
			t.Fatalf("batch size %d: %v", count, rejected)
		}
	}
}
