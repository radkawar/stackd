package servicecatalogappregistry_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/storage/memory"
	rg "stackd/storage/resourcegroups"
	domain "stackd/storage/servicecatalogappregistry"
	"stackd/storage/sqlite"
	rgsql "stackd/storage/sqlite/resourcegroups"
	backend "stackd/storage/sqlite/servicecatalogappregistry"
)

type repositories struct {
	apps    domain.Repository
	groups  rg.Repository
	restart func()
}

func openRepositories(t *testing.T, kind string) *repositories {
	t.Helper()
	r := &repositories{restart: func() {}}
	if kind == "memory" {
		d := memory.NewDomain()
		r.apps, r.groups = domain.NewMemory(d), rg.NewMemory(d)
		return r
	}
	path := filepath.Join(t.TempDir(), "appregistry.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r.apps, r.groups = backend.New(db), rgsql.New(db)
	r.restart = func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		r.apps, r.groups = backend.New(db), rgsql.New(db)
	}
	return r
}

func applicationFixture(scope domain.Scope, id, name string) domain.Application {
	return domain.Application{
		Scope: scope, ID: id, ARN: fmt.Sprintf("arn:%s:servicecatalog:%s:%s:/applications/%s", scope.Partition, scope.Region, scope.AccountID, id),
		Name: name, Description: "retained application", ClientToken: "application-token",
		CreateFingerprint:   "original-application-fingerprint",
		CloudFormationClaim: "trusted-application-claim",
		GroupARN:            "arn:aws:resource-groups:us-east-1:111111111111:group/application",
		TagGroupARN:         "arn:aws:resource-groups:us-east-1:111111111111:group/application-tags",
		Created:             time.Unix(0, 0).UTC(), Modified: time.Unix(1700000000, 123456789).UTC(),
		Tags: map[string]string{"team": "blue"},
	}
}
func attributeFixture(scope domain.Scope, id, name string) domain.AttributeGroup {
	return domain.AttributeGroup{
		Scope: scope, ID: id, ARN: fmt.Sprintf("arn:%s:servicecatalog:%s:%s:/attribute-groups/%s", scope.Partition, scope.Region, scope.AccountID, id),
		Name: name, Description: "retained attributes", Attributes: "{\n  \"team\": [\"blue\", \"green\"]\n}", ClientToken: "attribute-token",
		CreateFingerprint:   "original-attribute-fingerprint",
		CloudFormationClaim: "trusted-attribute-claim",
		Created:             time.Unix(0, 0).UTC(), Modified: time.Unix(1700000000, 123456789).UTC(),
		Tags: map[string]string{"owner": "platform"},
	}
}

func TestScopedDetachedSnapshotsSurviveReopen(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			a := applicationFixture(scope, "app-id", "app-name")
			g := attributeFixture(scope, "attribute-id", "attribute-name")
			wantApp, wantGroup := applicationFixture(scope, a.ID, a.Name), attributeFixture(scope, g.ID, g.Name)
			configuration := domain.Configuration{Scope: scope, TagKey: "application"}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutApplication(a); err != nil {
					return err
				}
				if err := tx.PutAttributeGroup(g); err != nil {
					return err
				}
				return tx.PutConfiguration(configuration)
			}); err != nil {
				t.Fatal(err)
			}
			a.Tags["team"], g.Tags["owner"] = "caller mutation", "caller mutation"
			assertSnapshots := func(reader domain.Reader) error {
				for _, id := range []string{a.ARN, a.ID, a.Name} {
					got, ok, err := reader.Application(scope, id)
					if err != nil {
						return err
					}
					if !ok || !reflect.DeepEqual(got, wantApp) {
						t.Fatalf("application %q: got %#v, want %#v", id, got, wantApp)
					}
					got.Tags["team"] = "reader mutation"
				}
				for _, id := range []string{g.ARN, g.ID, g.Name} {
					got, ok, err := reader.AttributeGroup(scope, id)
					if err != nil {
						return err
					}
					if !ok || !reflect.DeepEqual(got, wantGroup) {
						t.Fatalf("attribute group %q: got %#v, want %#v", id, got, wantGroup)
					}
					got.Tags["owner"] = "reader mutation"
				}
				apps, err := reader.Applications(scope)
				if err != nil {
					return err
				}
				groups, err := reader.AttributeGroups(scope)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(apps, []domain.Application{wantApp}) || !reflect.DeepEqual(groups, []domain.AttributeGroup{wantGroup}) {
					t.Fatal("list snapshots changed")
				}
				apps[0].Tags["team"], groups[0].Tags["owner"] = "list mutation", "list mutation"
				gotConfig, err := reader.Configuration(scope)
				if err != nil {
					return err
				}
				if gotConfig != configuration {
					t.Fatalf("configuration = %#v", gotConfig)
				}
				return nil
			}
			if err := r.apps.View(t.Context(), assertSnapshots); err != nil {
				t.Fatal(err)
			}
			for _, foreign := range []domain.Scope{
				{Partition: "aws-cn", AccountID: scope.AccountID, Region: scope.Region},
				{Partition: scope.Partition, AccountID: "222222222222", Region: scope.Region},
				{Partition: scope.Partition, AccountID: scope.AccountID, Region: "us-west-2"},
			} {
				if err := r.apps.View(t.Context(), func(reader domain.Reader) error {
					for _, id := range []string{a.ARN, a.ID, a.Name} {
						if _, ok, err := reader.Application(foreign, id); err != nil || ok {
							t.Fatalf("foreign application visible: %v, %v", ok, err)
						}
					}
					for _, id := range []string{g.ARN, g.ID, g.Name} {
						if _, ok, err := reader.AttributeGroup(foreign, id); err != nil || ok {
							t.Fatalf("foreign attributes visible: %v, %v", ok, err)
						}
					}
					got, err := reader.Configuration(foreign)
					if err != nil {
						return err
					}
					if got != (domain.Configuration{Scope: foreign}) {
						t.Fatal("configuration crossed scope")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
					if err := tx.DeleteApplication(foreign, a.ARN); err != nil {
						return err
					}
					return tx.DeleteAttributeGroup(foreign, g.ARN)
				}); err != nil {
					t.Fatal(err)
				}
				misScoped := wantApp
				misScoped.Scope = foreign
				if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error { return tx.PutApplication(misScoped) }); err == nil {
					t.Fatal("foreign scope overwrote application ARN")
				}
				if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
					if err := tx.PutApplication(applicationFixture(foreign, a.ID, a.Name)); err != nil {
						return err
					}
					return tx.PutAttributeGroup(attributeFixture(foreign, g.ID, g.Name))
				}); err != nil {
					t.Fatal(err)
				}
			}
			r.restart()
			if err := r.apps.View(t.Context(), assertSnapshots); err != nil {
				t.Fatal(err)
			}
			if err := r.apps.View(t.Context(), func(reader domain.Reader) error {
				west := scope
				west.Region = "us-west-2"
				want := []domain.Application{wantApp, applicationFixture(west, a.ID, a.Name)}
				got, err := reader.AccountApplications(scope.Partition, scope.AccountID)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("account-wide applications crossed account/partition or missed region: %#v", got)
				}
				got[0].Tags["team"] = "account-list mutation"
				return assertSnapshots(reader)
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAttemptCoordinatesRelatedOwnersAndOuterRollback(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			a := applicationFixture(scope, "app-id", "app-name")
			group := rg.Group{Scope: rg.Scope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, ARN: a.GroupARN, Name: "application", Description: "original"}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.PutApplication(a); err != nil {
					return err
				}
				return r.groups.Update(tx.Context(), func(other rg.Transaction) error { return other.PutGroup(group) })
			}); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("reject command")
			assertOriginal := func(reader domain.Reader) error {
				got, ok, err := reader.Application(scope, a.ID)
				if err != nil {
					return err
				}
				if !ok || got.Description != a.Description {
					t.Fatal("application escaped rollback")
				}
				return r.groups.View(reader.Context(), func(other rg.Reader) error {
					got, ok, err := other.Group(group.Scope, group.ARN)
					if err != nil {
						return err
					}
					if !ok || got.Description != group.Description {
						t.Fatal("related group escaped rollback")
					}
					return nil
				})
			}
			changeBoth := func(tx domain.Transaction) error {
				changed := a
				changed.Description = "staged application"
				if err := tx.PutApplication(changed); err != nil {
					return err
				}
				staged, err := tx.AccountApplications(scope.Partition, scope.AccountID)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(staged, []domain.Application{changed}) {
					t.Fatal("account-wide usage missed staged application mutation")
				}
				return r.groups.Update(tx.Context(), func(other rg.Transaction) error {
					changed := group
					changed.Description = "staged group"
					return other.PutGroup(changed)
				})
			}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				if err := r.apps.Attempt(tx.Context(), func(child domain.Transaction) error {
					if err := changeBoth(child); err != nil {
						return err
					}
					return abort
				}); !errors.Is(err, abort) {
					return fmt.Errorf("rejected attempt: %w", err)
				}
				if err := assertOriginal(tx); err != nil {
					return err
				}
				return tx.PutConfiguration(domain.Configuration{Scope: scope, TagKey: "committed-after-rejection"})
			}); err != nil {
				t.Fatal(err)
			}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				if err := r.apps.Attempt(tx.Context(), changeBoth); err != nil {
					return err
				}
				got, _, err := tx.Application(scope, a.ID)
				if err != nil {
					return err
				}
				if got.Description != "staged application" {
					t.Fatal("outer reader lost accepted child write")
				}
				return abort
			}); !errors.Is(err, abort) {
				t.Fatalf("outer rollback: %v", err)
			}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				_ = r.apps.Update(tx.Context(), func(child domain.Transaction) error {
					if err := changeBoth(child); err != nil {
						return err
					}
					return abort
				})
				return nil
			}); !errors.Is(err, abort) {
				t.Fatalf("caught nested Update must poison outer transaction: %v", err)
			}
			r.restart()
			if err := r.apps.View(t.Context(), func(reader domain.Reader) error {
				if err := assertOriginal(reader); err != nil {
					return err
				}
				configuration, err := reader.Configuration(scope)
				if err != nil {
					return err
				}
				if configuration.TagKey != "committed-after-rejection" {
					t.Fatal("failed Attempt poisoned outer commit")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUniqueNamesAndCascadesRetainIndependentResources(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			scope := domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
			a, b := applicationFixture(scope, "a", "first"), applicationFixture(scope, "b", "second")
			g, h := attributeFixture(scope, "g", "shared"), attributeFixture(scope, "h", "retained")
			association := domain.Association{ApplicationARN: a.ARN, ResourceARN: "arn:aws:s3:::bucket", ResourceName: "bucket", ResourceType: "AWS::S3::Bucket", Incarnation: "first-incarnation", CloudFormationClaim: "first-resource-claim", ApplyTag: true, Created: time.Unix(1700000000, 0).UTC()}
			edgeClaim := func(app domain.Application, attributes domain.AttributeGroup) string {
				return "claim:" + app.ID + "/" + attributes.ID
			}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				for _, app := range []domain.Application{a, b} {
					if err := tx.PutApplication(app); err != nil {
						return err
					}
				}
				for _, attributes := range []domain.AttributeGroup{g, h} {
					if err := tx.PutAttributeGroup(attributes); err != nil {
						return err
					}
				}
				for _, app := range []domain.Application{a, b} {
					for _, attributes := range []domain.AttributeGroup{g, h} {
						if err := tx.AssociateAttributeGroup(domain.AttributeGroupAssociation{ApplicationARN: app.ARN, AttributeGroupARN: attributes.ARN, CloudFormationClaim: edgeClaim(app, attributes)}); err != nil {
							return err
						}
					}
					row := association
					row.ApplicationARN = app.ARN
					if err := tx.PutAssociation(row); err != nil {
						return err
					}
				}
				if err := tx.AssociateAttributeGroup(domain.AttributeGroupAssociation{ApplicationARN: a.ARN, AttributeGroupARN: g.ARN}); err != nil {
					return err
				}
				association.Incarnation, association.CloudFormationClaim, association.ApplyTag = "replacement-incarnation", "", false
				return tx.PutAssociation(association)
			}); err != nil {
				t.Fatal(err)
			}
			for _, put := range []func(domain.Transaction) error{
				func(tx domain.Transaction) error {
					return tx.PutApplication(applicationFixture(scope, "duplicate", a.Name))
				},
				func(tx domain.Transaction) error {
					return tx.PutAttributeGroup(attributeFixture(scope, "duplicate", g.Name))
				},
				func(tx domain.Transaction) error {
					return tx.AssociateAttributeGroup(domain.AttributeGroupAssociation{ApplicationARN: a.ARN, AttributeGroupARN: "missing"})
				},
				func(tx domain.Transaction) error {
					row := association
					row.ApplicationARN = "missing"
					return tx.PutAssociation(row)
				},
			} {
				if err := r.apps.Update(t.Context(), put); err == nil {
					t.Fatal("repository admitted duplicate name or missing association parent")
				}
			}
			if err := r.apps.Update(t.Context(), func(tx domain.Transaction) error {
				rows, err := tx.Associations(a.ARN)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(rows, []domain.Association{association}) {
					t.Fatalf("association replacement: %#v", rows)
				}
				links, err := tx.AttributeGroupAssociations(a.ARN)
				if err != nil {
					return err
				}
				// Replacing a link replaces its private claim; it never survives a direct edge.
				if want := []domain.AttributeGroupAssociation{{ApplicationARN: a.ARN, AttributeGroupARN: g.ARN}, {ApplicationARN: a.ARN, AttributeGroupARN: h.ARN, CloudFormationClaim: edgeClaim(a, h)}}; !reflect.DeepEqual(links, want) {
					t.Fatalf("attribute link claims: %#v", links)
				}
				if err := tx.DisassociateAttributeGroup(a.ARN, g.ARN); err != nil {
					return err
				}
				if _, ok, err := tx.AttributeGroup(scope, g.ID); err != nil || !ok {
					t.Fatalf("disassociation deleted attributes: %v %v", ok, err)
				}
				if err := tx.DeleteAttributeGroup(scope, g.Name); err != nil {
					return err
				}
				for _, app := range []domain.Application{a, b} {
					links, err := tx.AttributeGroupAssociations(app.ARN)
					if err != nil {
						return err
					}
					if want := []domain.AttributeGroupAssociation{{ApplicationARN: app.ARN, AttributeGroupARN: h.ARN, CloudFormationClaim: edgeClaim(app, h)}}; !reflect.DeepEqual(links, want) {
						t.Fatalf("attribute deletion left links: %#v", links)
					}
				}
				return tx.DeleteApplication(scope, a.ID)
			}); err != nil {
				t.Fatal(err)
			}
			r.restart()
			if err := r.apps.View(t.Context(), func(reader domain.Reader) error {
				if _, ok, err := reader.Application(scope, a.ARN); err != nil || ok {
					t.Fatalf("deleted application: %v %v", ok, err)
				}
				if _, ok, err := reader.AttributeGroup(scope, g.ARN); err != nil || ok {
					t.Fatalf("deleted attributes: %v %v", ok, err)
				}
				if got, ok, err := reader.AttributeGroup(scope, h.ARN); err != nil || !ok || !reflect.DeepEqual(got, h) {
					t.Fatalf("application deletion damaged retained attributes: %#v %v", got, err)
				}
				links, err := reader.AttributeGroupAssociations(a.ARN)
				if err != nil {
					return err
				}
				rows, err := reader.Associations(a.ARN)
				if err != nil {
					return err
				}
				if len(links) != 0 || len(rows) != 0 {
					t.Fatal("deleted application retained associations")
				}
				links, err = reader.AttributeGroupAssociations(b.ARN)
				if err != nil {
					return err
				}
				rows, err = reader.Associations(b.ARN)
				if err != nil {
					return err
				}
				retained := association
				retained.ApplicationARN, retained.Incarnation, retained.CloudFormationClaim, retained.ApplyTag = b.ARN, "first-incarnation", "first-resource-claim", true
				if want := []domain.AttributeGroupAssociation{{ApplicationARN: b.ARN, AttributeGroupARN: h.ARN, CloudFormationClaim: edgeClaim(b, h)}}; !reflect.DeepEqual(links, want) || !reflect.DeepEqual(rows, []domain.Association{retained}) {
					t.Fatal("application deletion damaged independent associations")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
