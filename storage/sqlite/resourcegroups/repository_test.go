package resourcegroups_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/resourcegroups"
	domain "stackd/storage/resourcegroups"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/resourcegroups"
)

func groupFixture(scope domain.Scope, name string) domain.Group {
	return domain.Group{
		Scope: scope, ARN: fmt.Sprintf("arn:%s:resource-groups:%s:%s:group/%s", scope.Partition, scope.Region, scope.AccountID, name), Name: name,
		Description: "retained description",
		Query:       &api.ResourceQuery{Type: new(api.QueryType("TAG_FILTERS_1_0")), Query: new(api.Query(`{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"team","Values":["blue"]}]}`))},
		Tags:        map[string]string{"team": "blue", "environment": "test"}, Created: time.Unix(0, 0).UTC(),
	}
}

func TestGroupsRemainAtomicScopedAndDetached(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var repo domain.Repository
			restart := func() {}
			checkDeletedTags := func(string) {}
			if kind == "memory" {
				repo = domain.NewMemory(nil)
			} else {
				path := filepath.Join(t.TempDir(), "groups.sqlite")
				db, err := sqlite.Open(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = backend.New(db)
				restart = func() {
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repo = backend.New(db)
				}
				checkDeletedTags = func(arn string) {
					var count int
					if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM resourcegroups_group_tags WHERE group_arn = ?", arn).Scan(&count); err != nil {
						t.Fatal(err)
					}
					if count != 0 {
						t.Fatalf("deleted group retained %d tag rows", count)
					}
				}
			}
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			group := groupFixture(scope, "z-group")
			expected := groupFixture(scope, "z-group")
			other := groupFixture(scope, "a-group")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				for _, g := range []domain.Group{group, other} {
					if err := tx.PutGroup(g); err != nil {
						return err
					}
					if g.ARN == expected.ARN {
						retained, _, err := tx.Group(scope, g.ARN)
						if err != nil {
							return err
						}
						expected.Incarnation = retained.Incarnation
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Mutating accepted request memory must not rewrite retained state.
			group.Tags["team"] = "caller mutation"
			*group.Query.Type = "changed"
			*group.Query.Query = "changed"

			assertSnapshot := func(r domain.Reader) error {
				got, ok, err := r.Group(scope, expected.Name)
				if err != nil {
					return err
				}
				if !ok || !reflect.DeepEqual(got, expected) {
					t.Fatalf("group snapshot changed: got %#v, want %#v", got, expected)
				}
				got.Tags["team"] = "reader mutation"
				*got.Query.Type = "reader mutation"
				*got.Query.Query = "reader mutation"
				again, _, err := r.Group(scope, expected.ARN)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(again, expected) {
					t.Fatal("read result aliases retained group state")
				}
				rows, err := r.Groups(scope)
				if err != nil {
					return err
				}
				if len(rows) != 2 || rows[0].ARN != other.ARN || rows[1].ARN != expected.ARN {
					t.Fatalf("unstable group order: %#v", rows)
				}
				rows[1].Tags["team"] = "list mutation"
				*rows[1].Query.Query = "list mutation"
				return nil
			}
			if err := repo.View(t.Context(), assertSnapshot); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("reject command")
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				changed := groupFixture(scope, expected.Name)
				changed.Tags = map[string]string{"replacement": "staged"}
				changed.Query.Query = new(api.Query(`{"ResourceTypeFilters":["AWS::S3::Bucket"]}`))
				if err := tx.PutGroup(changed); err != nil {
					return err
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatalf("rollback result: %v", err)
			}

			if err := repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
					if err := child.DeleteGroup(scope, expected.ARN); err != nil {
						return err
					}
					return abort
				}); !errors.Is(err, abort) {
					return fmt.Errorf("savepoint rejection: %v", err)
				}
				if err := assertSnapshot(tx); err != nil {
					return err
				}
				if err := repo.Attempt(tx.Context(), func(child domain.Transaction) error {
					g := groupFixture(scope, expected.Name)
					g.Description = "accepted child"
					return child.PutGroup(g)
				}); err != nil {
					return err
				}
				g, _, err := tx.Group(scope, expected.ARN)
				if err != nil {
					return err
				}
				if g.Description != "accepted child" {
					t.Fatal("outer reader lost accepted child writes")
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatalf("outer rollback result: %v", err)
			}

			for _, foreign := range []domain.Scope{
				{Partition: "aws-cn", AccountID: scope.AccountID, Region: scope.Region},
				{Partition: scope.Partition, AccountID: "222222222222", Region: scope.Region},
				{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-west-2"},
			} {
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					for _, id := range []string{expected.Name, expected.ARN} {
						if _, ok, err := r.Group(foreign, id); err != nil || ok {
							t.Fatalf("foreign group visible: %v %v", ok, err)
						}
					}
					rows, err := r.Groups(foreign)
					if err != nil {
						return err
					}
					if len(rows) != 0 {
						t.Fatal("foreign scope listed groups")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteGroup(foreign, expected.ARN) }); err != nil {
					t.Fatal(err)
				}
				misScoped := groupFixture(foreign, expected.Name)
				misScoped.ARN = expected.ARN
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutGroup(misScoped) }); err == nil {
					t.Fatal("foreign scope rewrote existing ARN")
				}
				foreignGroup := groupFixture(foreign, expected.Name)
				if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutGroup(foreignGroup) }); err != nil {
					t.Fatal(err)
				}
				if err := repo.View(t.Context(), func(r domain.Reader) error {
					got, ok, err := r.Group(foreign, expected.Name)
					if err != nil {
						return err
					}
					if !ok || got.ARN != foreignGroup.ARN {
						t.Fatal("same-name groups did not remain independently scoped")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			restart()
			if err := repo.View(t.Context(), assertSnapshot); err != nil {
				t.Fatal(err)
			}
			if err := repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteGroup(scope, expected.Name) }); err != nil {
				t.Fatal(err)
			}
			restart()
			if err := repo.View(t.Context(), func(r domain.Reader) error {
				if _, ok, err := r.Group(scope, expected.ARN); err != nil || ok {
					t.Fatalf("deleted group: %v %v", ok, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			checkDeletedTags(expected.ARN)
		})
	}
}
