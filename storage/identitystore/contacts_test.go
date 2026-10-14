package identitystore_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	api "stackd/internal/awsapi/identitystore"
	service "stackd/internal/services/identitystore"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/identitystore"
)

func TestUserContactsPersistReplaceClearAndRollback(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var db *sql.DB
			var repo service.Repository
			var s *service.Service
			path := filepath.Join(t.TempDir(), "contacts.db")
			reopen := func() {
				if kind == "memory" {
					if repo == nil {
						repo = service.NewMemoryRepository(memory.NewDomain())
					}
				} else {
					if db != nil {
						if err := db.Close(); err != nil {
							t.Fatal(err)
						}
					}
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
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
			if err := s.EnsureStore(ctx, owner, storeID); err != nil {
				t.Fatal(err)
			}
			out := success(t, ctx, s, "CreateUser", map[string]any{
				"IdentityStoreId": storeID, "UserName": "contacts", "DisplayName": "Local contacts",
				"Addresses":    []map[string]any{{"StreetAddress": "1 Local Street", "Country": "US", "Primary": true}},
				"PhoneNumbers": []map[string]any{{"Value": "+12065550101", "Type": "work", "Primary": true}},
			}).(*api.CreateUserOutput)
			id := string(*out.UserId)
			reopen()
			read := func() *api.DescribeUserOutput {
				return success(t, ctx, s, "DescribeUser", map[string]string{"IdentityStoreId": storeID, "UserId": id}).(*api.DescribeUserOutput)
			}
			if u := read(); len(u.Addresses) != 1 || string(*u.Addresses[0].StreetAddress) != "1 Local Street" || len(u.PhoneNumbers) != 1 || string(*u.PhoneNumbers[0].Value) != "+12065550101" {
				t.Fatalf("contacts not retained: %+v", u)
			}
			// Reader and writer slices must never alias retained memory state.
			if err := repo.View(ctx, func(r service.Reader) error {
				u, err := r.User(service.Key{StoreID: storeID, ID: id})
				if err != nil {
					return err
				}
				u.Addresses[0].StreetAddress = "not a write"
				u.PhoneNumbers[0].Value = "not a write"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if u := read(); string(*u.Addresses[0].StreetAddress) != "1 Local Street" || string(*u.PhoneNumbers[0].Value) != "+12065550101" {
				t.Fatal("reader mutated retained contacts")
			}
			patch := func(operations []map[string]any) any {
				return map[string]any{"IdentityStoreId": storeID, "UserId": id, "Operations": operations}
			}
			replacement := []map[string]any{
				{"AttributePath": "addresses", "AttributeValue": []map[string]any{{"streetAddress": "2 Local Street", "primary": false}}},
				{"AttributePath": "phoneNumbers", "AttributeValue": []map[string]any{{"value": "+12065550102", "primary": false}}},
			}
			abort := errors.New("abort enclosing transaction")
			if err := repo.Update(ctx, func(tx service.Transaction) error {
				success(t, tx.Context(), s, "UpdateUser", patch(replacement))
				return abort
			}); !errors.Is(err, abort) {
				t.Fatalf("rollback: %v", err)
			}
			if u := read(); string(*u.Addresses[0].StreetAddress) != "1 Local Street" || string(*u.PhoneNumbers[0].Value) != "+12065550101" {
				t.Fatal("aborted patch changed contacts")
			}
			for _, invalid := range []any{
				[]map[string]any{},
				[]map[string]any{{"value": "a"}, {"value": "b"}},
				[]map[string]any{{"value": ""}},
				[]map[string]any{{"value": strings.Repeat("x", 1025)}},
				[]map[string]any{{"unsupported": "attribute"}},
			} {
				_, err := command(t, ctx, s, "UpdateUser", patch([]map[string]any{
					replacement[0], {"AttributePath": "phoneNumbers", "AttributeValue": invalid},
				}))
				if err == nil || err.Code != "ValidationException" {
					t.Fatalf("invalid contact accepted: %+v, %v", invalid, err)
				}
				if u := read(); string(*u.Addresses[0].StreetAddress) != "1 Local Street" {
					t.Fatal("rejected patch leaked its address update")
				}
			}
			success(t, ctx, s, "UpdateUser", patch(replacement))
			reopen()
			if u := read(); string(*u.Addresses[0].StreetAddress) != "2 Local Street" || u.Addresses[0].Country != nil || bool(*u.Addresses[0].Primary) || string(*u.PhoneNumbers[0].Value) != "+12065550102" || u.PhoneNumbers[0].Type != nil || bool(*u.PhoneNumbers[0].Primary) {
				t.Fatalf("whole-list replacement lost semantics: %+v", u)
			}
			foreign := owner
			foreign.AccountID = "444455556666"
			if _, err := command(t, ownerContext(t.Context(), foreign), s, "UpdateUser", patch(replacement)); err == nil || err.Code != "ResourceNotFoundException" {
				t.Fatalf("foreign contact patch: %v", err)
			}
			success(t, ctx, s, "UpdateUser", patch([]map[string]any{{"AttributePath": "addresses"}, {"AttributePath": "phoneNumbers", "AttributeValue": nil}}))
			reopen()
			if u := read(); len(u.Addresses) != 0 || len(u.PhoneNumbers) != 0 {
				t.Fatalf("cleared contacts returned after reopen: %+v", u)
			}
			success(t, ctx, s, "UpdateUser", patch(replacement))
			success(t, ctx, s, "DeleteUser", map[string]string{"IdentityStoreId": storeID, "UserId": id})
			reopen()
			if _, err := s.FindUser(ctx, owner, storeID, id); !errors.Is(err, service.ErrNotFound) {
				t.Fatalf("deleted contact owner returned after reopen: %v", err)
			}
		})
	}
}
