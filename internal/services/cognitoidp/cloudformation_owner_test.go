package cognitoidp

import (
	"context"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func TestResourceOwnerRecoversAndFencesPoolChildren(t *testing.T) {
	s := New(Config{Repository: NewMemoryRepository(nil)})
	base := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-2", PrincipalARN: "arn:aws:iam::123456789012:root"})
	model, _ := awscatalog.LookupService("cognitoidp")
	call := func(ctx context.Context, action string, in any) (any, *awswire.Error) {
		op, _ := model.Operation(action)
		return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	}
	out, e := call(base, "CreateUserPool", &api.CreateUserPoolInput{PoolName: new(api.UserPoolNameType("owned"))})
	if e != nil {
		t.Fatal(e)
	}
	pool := out.(*api.CreateUserPoolOutput).UserPool.Id
	first := WithResourceOwner(base, ResourceOwner{StackID: "stack-a", LogicalID: "Client", Token: "one"})
	second := WithResourceOwner(base, ResourceOwner{StackID: "stack-b", LogicalID: "Client", Token: "one"})
	create := &api.CreateUserPoolClientInput{UserPoolId: pool, ClientName: new(api.ClientNameType("app"))}

	// A retried create of the same incarnation returns the persisted client.
	created, e := call(first, "CreateUserPoolClient", create)
	if e != nil {
		t.Fatal(e)
	}
	retried, e := call(first, "CreateUserPoolClient", create)
	if e != nil {
		t.Fatal(e)
	}
	id := created.(*api.CreateUserPoolClientOutput).UserPoolClient.ClientId
	if *retried.(*api.CreateUserPoolClientOutput).UserPoolClient.ClientId != *id {
		t.Fatalf("recovered create allocated another client: %s != %s", *retried.(*api.CreateUserPoolClientOutput).UserPoolClient.ClientId, *id)
	}
	listed, e := call(base, "ListUserPoolClients", &api.ListUserPoolClientsInput{UserPoolId: pool})
	if e != nil || len(listed.(*api.ListUserPoolClientsOutput).UserPoolClients) != 1 {
		t.Fatalf("recovered create duplicated the client: %+v, %v", listed, e)
	}

	// Another incarnation can neither mutate nor delete the claimed client.
	_, e = call(second, "UpdateUserPoolClient", &api.UpdateUserPoolClientInput{UserPoolId: pool, ClientId: id})
	if e == nil || e.Code != "InvalidParameterException" {
		t.Fatalf("another incarnation updated a claimed client: %v", e)
	}
	_, e = call(second, "DeleteUserPoolClient", &api.DeleteUserPoolClientInput{UserPoolId: pool, ClientId: id})
	if e == nil {
		t.Fatal("unclaimed incarnation deleted a client")
	}

	// A group created outside CloudFormation is not adopted, and deleting a
	// claimed group through the API releases its claim for a later stack.
	if _, e = call(base, "CreateGroup", &api.CreateGroupInput{UserPoolId: pool, GroupName: new(api.GroupNameType("api"))}); e != nil {
		t.Fatal(e)
	}
	_, e = call(first, "CreateGroup", &api.CreateGroupInput{UserPoolId: pool, GroupName: new(api.GroupNameType("api"))})
	if e == nil || e.Code != "GroupExistsException" {
		t.Fatalf("stack adopted an API-created group: %v", e)
	}
	if _, e = call(first, "CreateGroup", &api.CreateGroupInput{UserPoolId: pool, GroupName: new(api.GroupNameType("stack"))}); e != nil {
		t.Fatal(e)
	}
	_, e = call(second, "CreateGroup", &api.CreateGroupInput{UserPoolId: pool, GroupName: new(api.GroupNameType("stack"))})
	if e == nil || e.Code != "InvalidParameterException" {
		t.Fatalf("another incarnation adopted a claimed group: %v", e)
	}
	if _, e = call(base, "DeleteGroup", &api.DeleteGroupInput{UserPoolId: pool, GroupName: new(api.GroupNameType("stack"))}); e != nil {
		t.Fatal(e)
	}
	if _, e = call(second, "CreateGroup", &api.CreateGroupInput{UserPoolId: pool, GroupName: new(api.GroupNameType("stack"))}); e != nil {
		t.Fatalf("deleted group's claim outlived it: %v", e)
	}

	// The claimed client is deleted by its own incarnation and its claim with it.
	if _, e = call(first, "DeleteUserPoolClient", &api.DeleteUserPoolClientInput{UserPoolId: pool, ClientId: id}); e != nil {
		t.Fatal(e)
	}
	if err := s.repository.View(t.Context(), func(r Reader) error {
		key := PoolKey{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-2"}, ID: string(*pool)}
		for _, claim := range []OwnershipKey{{PoolKey: key, Kind: OwnerKindClient, Name: string(*id)}, {PoolKey: key, Kind: OwnerKindClientToken, Name: tokenName(ResourceOwner{StackID: "stack-a", LogicalID: "Client", Token: "one"})}} {
			if _, err := r.Ownership(claim); err == nil {
				t.Fatalf("client deletion retained claim %+v", claim)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
