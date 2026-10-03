package identitystore_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/identitystore"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/identitystore"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/identitystore"
)

var owner = service.Scope{Partition: "aws", AccountID: "111122223333", Region: "us-east-1"}

const storeID = "d-1234567890"

func ownerContext(ctx context.Context, scope service.Scope) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root"})
}
func command(t *testing.T, ctx context.Context, s *service.Service, action string, input any) (any, *awswire.Error) {
	t.Helper()
	raw, e := json.Marshal(input)
	if e != nil {
		t.Fatal(e)
	}
	request, e := api.DecodeRequest(action, awsapi.Request{JSON: raw})
	if e != nil {
		t.Fatal(e)
	}
	return s.ExecuteCommand(ctx, request)
}
func success(t *testing.T, ctx context.Context, s *service.Service, action string, input any) any {
	t.Helper()
	out, e := command(t, ctx, s, action, input)
	if e != nil {
		t.Fatalf("%s: %v", action, e)
	}
	return out
}
func createUser(t *testing.T, ctx context.Context, s *service.Service, name string) string {
	t.Helper()
	out := success(t, ctx, s, "CreateUser", map[string]any{"IdentityStoreId": storeID, "UserName": name, "DisplayName": name, "Name": map[string]string{"GivenName": name, "FamilyName": "Example"}, "Emails": []map[string]any{{"Value": name + "@example.com", "Primary": true}}}).(*api.CreateUserOutput)
	return string(*out.UserId)
}
func createGroup(t *testing.T, ctx context.Context, s *service.Service, name string) string {
	t.Helper()
	out := success(t, ctx, s, "CreateGroup", map[string]any{"IdentityStoreId": storeID, "DisplayName": name}).(*api.CreateGroupOutput)
	return string(*out.GroupId)
}
func createMembership(t *testing.T, ctx context.Context, s *service.Service, user, group string) string {
	t.Helper()
	out := success(t, ctx, s, "CreateGroupMembership", map[string]any{"IdentityStoreId": storeID, "GroupId": group, "MemberId": map[string]string{"UserId": user}}).(*api.CreateGroupMembershipOutput)
	return string(*out.MembershipId)
}

func TestMembershipAuthoritySurvivesRestartAndDeletion(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var db *sql.DB
			var repo service.Repository
			var s *service.Service
			path := filepath.Join(t.TempDir(), "identity.db")
			reopen := func() {
				if kind == "memory" {
					if repo == nil {
						repo = service.NewMemoryRepository(memory.NewDomain())
					}
				} else {
					if db != nil {
						if e := db.Close(); e != nil {
							t.Fatal(e)
						}
					}
					var e error
					db, e = sqlite.Open(t.Context(), path)
					if e != nil {
						t.Fatal(e)
					}
					repo = backend.New(db)
				}
				s = service.NewWithConfig(service.Config{Repository: repo})
			}
			reopen()
			defer func() {
				if db != nil {
					db.Close()
				}
			}()
			ctx := ownerContext(t.Context(), owner)
			if e := s.EnsureStore(ctx, owner, storeID); e != nil {
				t.Fatal(e)
			}
			user := createUser(t, ctx, s, "alice")
			group := createGroup(t, ctx, s, "operators")
			membership := createMembership(t, ctx, s, user, group)
			reopen()
			u, e := s.UserByName(ctx, owner, storeID, "alice")
			if e != nil || u.ID != user || len(u.Emails) != 1 || u.Emails[0].Value != "alice@example.com" {
				t.Fatalf("retained user: %+v %v", u, e)
			}
			if exists, e := s.IsMember(ctx, owner, storeID, user, group); e != nil || !exists {
				t.Fatalf("retained membership: %v %v", exists, e)
			}
			for _, foreign := range []service.Scope{
				{Partition: "aws", AccountID: "444455556666", Region: "us-east-1"},
				{Partition: "aws", AccountID: "111122223333", Region: "us-west-2"},
				{Partition: "aws-us-gov", AccountID: "111122223333", Region: "us-east-1"},
			} {
				if _, e := s.FindUser(ctx, foreign, storeID, user); !errors.Is(e, service.ErrNotFound) {
					t.Fatalf("foreign lookup: %v", e)
				}
				if e := s.EnsureStore(ctx, foreign, storeID); !errors.Is(e, service.ErrNotFound) {
					t.Fatalf("store takeover: %v", e)
				}
				if _, e := command(t, ownerContext(t.Context(), foreign), s, "DescribeUser", map[string]string{"IdentityStoreId": storeID, "UserId": user}); e == nil || e.Code != "ResourceNotFoundException" {
					t.Fatalf("foreign API lookup: %v", e)
				}
			}
			rollback := errors.New("abort enclosing command")
			if e := repo.Update(ctx, func(tx service.Transaction) error {
				success(t, tx.Context(), s, "DeleteGroupMembership", map[string]string{"IdentityStoreId": storeID, "MembershipId": membership})
				if exists, e := s.IsMember(tx.Context(), owner, storeID, user, group); e != nil || exists {
					t.Fatalf("staged deletion not authoritative: %v %v", exists, e)
				}
				return rollback
			}); !errors.Is(e, rollback) {
				t.Fatal(e)
			}
			if exists, e := s.IsMember(ctx, owner, storeID, user, group); e != nil || !exists {
				t.Fatalf("rollback lost membership: %v %v", exists, e)
			}
			success(t, ctx, s, "DeleteGroupMembership", map[string]string{"IdentityStoreId": storeID, "MembershipId": membership})
			if exists, e := s.IsMember(ctx, owner, storeID, user, group); e != nil || exists {
				t.Fatalf("deleted membership still authoritative: %v %v", exists, e)
			}
			createMembership(t, ctx, s, user, group)
			success(t, ctx, s, "DeleteUser", map[string]string{"IdentityStoreId": storeID, "UserId": user})
			recreated := createUser(t, ctx, s, "alice")
			if recreated == user {
				t.Fatal("recreation reused user identity")
			}
			if exists, e := s.IsMember(ctx, owner, storeID, recreated, group); e != nil || exists {
				t.Fatalf("recreation inherited membership: %v %v", exists, e)
			}
			createMembership(t, ctx, s, recreated, group)
			success(t, ctx, s, "DeleteGroup", map[string]string{"IdentityStoreId": storeID, "GroupId": group})
			reopen()
			if exists, e := s.IsMember(ctx, owner, storeID, recreated, group); e != nil || exists {
				t.Fatalf("group deletion retained membership after restart: %v %v", exists, e)
			}
		})
	}
}

func TestRejectedPatchIsAtomicAndPaginationCannotChangeSelection(t *testing.T) {
	s := service.NewWithConfig(service.Config{})
	ctx := ownerContext(t.Context(), owner)
	if e := s.EnsureStore(ctx, owner, storeID); e != nil {
		t.Fatal(e)
	}
	alice := createUser(t, ctx, s, "alice")
	createUser(t, ctx, s, "bob")
	_, e := command(t, ctx, s, "UpdateUser", map[string]any{"IdentityStoreId": storeID, "UserId": alice, "Operations": []map[string]any{{"AttributePath": "DisplayName", "AttributeValue": "Changed"}, {"AttributePath": "UserName", "AttributeValue": "bob"}}})
	if e == nil || e.Code != "ConflictException" {
		t.Fatalf("duplicate name patch: %v", e)
	}
	u, err := s.FindUser(ctx, owner, storeID, alice)
	if err != nil || u.DisplayName != "alice" || u.UserName != "alice" {
		t.Fatalf("failed patch leaked: %+v %v", u, err)
	}
	first := success(t, ctx, s, "ListUsers", map[string]any{"IdentityStoreId": storeID, "MaxResults": 1}).(*api.ListUsersOutput)
	if len(first.Users) != 1 || first.NextToken == nil {
		t.Fatalf("first page: %+v", first)
	}
	second := success(t, ctx, s, "ListUsers", map[string]any{"IdentityStoreId": storeID, "MaxResults": 1, "NextToken": *first.NextToken}).(*api.ListUsersOutput)
	if len(second.Users) != 1 || second.NextToken != nil || *second.Users[0].UserId == *first.Users[0].UserId {
		t.Fatalf("second page: %+v", second)
	}
	_, e = command(t, ctx, s, "ListUsers", map[string]any{"IdentityStoreId": storeID, "NextToken": *first.NextToken, "Filters": []map[string]string{{"AttributePath": "UserName", "AttributeValue": "alice"}}})
	if e == nil || e.Code != "ValidationException" {
		t.Fatalf("token changed filter: %v", e)
	}
}
