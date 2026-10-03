// Command identitystore_smoke exercises signed SDK requests through the production
// gateway and directory owner, using a disposable SQLite database and real restart.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/identitystore/document"
	"github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	api "stackd/internal/awsapi/identitystore"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
	service "stackd/internal/services/identitystore"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/identitystore"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	ctx := context.Background()
	dir, e := os.MkdirTemp("", "stackd-identitystore-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	scope := service.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}
	store := "d-1234567890"
	var db *sql.DB
	var server *httptest.Server
	var owner *service.Service
	close := func() error {
		if server != nil {
			server.Close()
			server = nil
		}
		if db != nil {
			e := db.Close()
			db = nil
			return e
		}
		return nil
	}
	defer close()
	open := func() (*sdk.Client, error) {
		var e error
		db, e = sqlite.Open(ctx, filepath.Join(dir, "identity.db"))
		if e != nil {
			return nil, e
		}
		owner = service.NewWithConfig(service.Config{Repository: backend.New(db)})
		model, _ := awscatalog.LookupService("identitystore")
		registry := &gateway.Registry{}
		if e := registry.Register(gateway.Service{Name: model.Name, SigningName: model.SigningName, Protocol: gateway.JSON11, TargetPrefix: model.TargetPrefix, Provider: owner, Model: &model, Decode: api.DecodeRequest}); e != nil {
			return nil, e
		}
		g, e := gateway.New(registry, gateway.Config{AccountID: scope.AccountID})
		if e != nil {
			return nil, e
		}
		server = httptest.NewServer(g)
		return sdk.New(sdk.Options{Region: scope.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(scope.AccountID, "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1}), nil
	}
	client, e := open()
	if e != nil {
		return e
	}
	if e := owner.EnsureStore(ctx, scope, store); e != nil {
		return e
	}
	user, e := client.CreateUser(ctx, &sdk.CreateUserInput{IdentityStoreId: &store, UserName: aws.String("alice"), DisplayName: aws.String("Alice Example"), Name: &types.Name{GivenName: aws.String("Alice"), FamilyName: aws.String("Example")}, Emails: []types.Email{{Value: aws.String("alice@example.com"), Type: aws.String("work"), Primary: true}}})
	if e != nil {
		return e
	}
	group, e := client.CreateGroup(ctx, &sdk.CreateGroupInput{IdentityStoreId: &store, DisplayName: aws.String("Operators")})
	if e != nil {
		return e
	}
	member := &types.MemberIdMemberUserId{Value: aws.ToString(user.UserId)}
	membership, e := client.CreateGroupMembership(ctx, &sdk.CreateGroupMembershipInput{IdentityStoreId: &store, GroupId: group.GroupId, MemberId: member})
	if e != nil {
		return e
	}
	_, e = client.CreateGroupMembership(ctx, &sdk.CreateGroupMembershipInput{IdentityStoreId: &store, GroupId: group.GroupId, MemberId: member})
	var conflict *types.ConflictException
	if !errors.As(e, &conflict) {
		return fmt.Errorf("duplicate membership must be modeled ConflictException: %w", e)
	}
	_, e = client.UpdateUser(ctx, &sdk.UpdateUserInput{IdentityStoreId: &store, UserId: user.UserId, Operations: []types.AttributeOperation{{AttributePath: aws.String("displayName"), AttributeValue: document.NewLazyDocument("Alice Updated")}}})
	if e != nil {
		return e
	}
	lookup, e := client.GetUserId(ctx, &sdk.GetUserIdInput{IdentityStoreId: &store, AlternateIdentifier: &types.AlternateIdentifierMemberUniqueAttribute{Value: types.UniqueAttribute{AttributePath: aws.String("UserName"), AttributeValue: document.NewLazyDocument("alice")}}})
	if e != nil {
		return e
	}
	if aws.ToString(lookup.UserId) != aws.ToString(user.UserId) {
		return errors.New("username lookup changed identity")
	}
	check := func(want bool) error {
		out, e := client.IsMemberInGroups(ctx, &sdk.IsMemberInGroupsInput{IdentityStoreId: &store, MemberId: member, GroupIds: []string{aws.ToString(group.GroupId)}})
		if e != nil {
			return e
		}
		if len(out.Results) != 1 || out.Results[0].MembershipExists != want {
			return fmt.Errorf("membership result does not match %v: %+v", want, out.Results)
		}
		trusted, e := owner.IsMember(ctx, scope, store, aws.ToString(user.UserId), aws.ToString(group.GroupId))
		if e != nil {
			return e
		}
		if trusted != want {
			return errors.New("consumer membership disagrees with public API")
		}
		return nil
	}
	if e := check(true); e != nil {
		return e
	}
	fmt.Println("signed SDK create user/group/membership, duplicate conflict, update and lookup: passed")
	if e := close(); e != nil {
		return e
	}
	client, e = open()
	if e != nil {
		return e
	}
	if e := check(true); e != nil {
		return e
	}
	described, e := client.DescribeUser(ctx, &sdk.DescribeUserInput{IdentityStoreId: &store, UserId: user.UserId})
	if e != nil {
		return e
	}
	if aws.ToString(described.DisplayName) != "Alice Updated" || len(described.Emails) != 1 || aws.ToString(described.Emails[0].Value) != "alice@example.com" {
		return errors.New("profile did not survive SQLite restart")
	}
	listed, e := client.ListGroupMemberships(ctx, &sdk.ListGroupMembershipsInput{IdentityStoreId: &store, GroupId: group.GroupId})
	if e != nil {
		return e
	}
	if len(listed.GroupMemberships) != 1 || aws.ToString(listed.GroupMemberships[0].MembershipId) != aws.ToString(membership.MembershipId) {
		return errors.New("membership list lost identity across restart")
	}
	foreign := sdk.New(sdk.Options{Region: scope.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("444455556666", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	_, e = foreign.DescribeUser(ctx, &sdk.DescribeUserInput{IdentityStoreId: &store, UserId: user.UserId})
	var missing *types.ResourceNotFoundException
	if !errors.As(e, &missing) {
		return fmt.Errorf("foreign store lookup must be modeled ResourceNotFoundException: %w", e)
	}
	fmt.Println("SQLite restart retained profile/membership; signed cross-account isolation: passed")
	_, e = client.DeleteGroupMembership(ctx, &sdk.DeleteGroupMembershipInput{IdentityStoreId: &store, MembershipId: membership.MembershipId})
	if e != nil {
		return e
	}
	if e := check(false); e != nil {
		return e
	}
	_, e = client.CreateGroupMembership(ctx, &sdk.CreateGroupMembershipInput{IdentityStoreId: &store, GroupId: group.GroupId, MemberId: member})
	if e != nil {
		return e
	}
	_, e = client.DeleteUser(ctx, &sdk.DeleteUserInput{IdentityStoreId: &store, UserId: user.UserId})
	if e != nil {
		return e
	}
	if e := check(false); e != nil {
		return e
	}
	if e := owner.DeleteStore(ctx, scope, store); e != nil {
		return e
	}
	if e := close(); e != nil {
		return e
	}
	client, e = open()
	if e != nil {
		return e
	}
	_, e = client.DescribeGroup(ctx, &sdk.DescribeGroupInput{IdentityStoreId: &store, GroupId: group.GroupId})
	if !errors.As(e, &missing) {
		return fmt.Errorf("retired store still accessible: %w", e)
	}
	fmt.Println("membership deletion, user cascade, trusted store retirement and restart: passed")
	return close()
}
