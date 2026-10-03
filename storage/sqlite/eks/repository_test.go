package eks_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	domain "stackd/internal/services/eks"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/eks"
	journaldb "stackd/storage/sqlite/journal"
)

type repositories struct {
	repo    domain.Repository
	events  journal.Storage
	restart func()
}

func openRepositories(t *testing.T, kind string) *repositories {
	t.Helper()
	if kind == "memory" {
		d := memory.NewDomain()
		return &repositories{repo: domain.NewMemoryRepository(d), events: journal.NewMemory(d)}
	}
	path := filepath.Join(t.TempDir(), "eks.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r := &repositories{repo: backend.New(db), events: journaldb.New(db)}
	r.restart = func() {
		t.Helper()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		r.repo, r.events = backend.New(db), journaldb.New(db)
	}
	return r
}

func clusterKey() domain.Key {
	return domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "owned"}
}
func records(k domain.Key) (domain.Cluster, domain.AccessEntry, domain.AccessPolicy, domain.Update) {
	created := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	modified := created.Add(time.Second + 7*time.Nanosecond)
	protection := false
	c := domain.Cluster{
		Key: k, ID: "cluster-incarnation", RoleARN: "arn:aws:iam::111111111111:role/control", KubernetesVersion: "1.33",
		Status: "UPDATING", Operation: "config", Error: "retained-observation",
		Endpoint: "https://127.0.0.1:18443", CertificateAuthority: "Y2E=", VPCID: "vpc-owned",
		Subnets: []string{"subnet-b", "subnet-a"}, SecurityGroups: []string{"sg-owned"}, Tags: map[string]string{"owner": "team"},
		Created: created, Due: time.Unix(0, 0).UTC(), Generation: 7,
		ClientToken: "create-token", RequestHash: "create-hash", CreatorARN: "arn:aws:iam::111111111111:user/creator", CreatorID: "creator-incarnation",
		AuthenticationMode: "API", BootstrapAdmin: true, DeletionProtection: true,
	}
	e := domain.AccessEntry{
		Key: k, PrincipalARN: "arn:aws:iam::111111111111:role/operator", PrincipalID: "role-incarnation", Username: "operator", Type: "STANDARD",
		ID: "entry-incarnation", ClientToken: "access-token", RequestHash: "access-hash",
		Groups: []string{"operators", "viewers"}, Tags: map[string]string{"owner": "security"}, Created: created, Modified: modified,
	}
	p := domain.AccessPolicy{Key: k, PrincipalARN: e.PrincipalARN, PolicyARN: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy", ScopeType: "namespace", Namespaces: []string{"production", "shared-*"}, Associated: created, Modified: modified}
	u := domain.Update{Key: k, ID: "update-a", Type: "ConfigUpdate", Status: "InProgress", ErrorCode: "retained-code", ErrorMessage: "retained-message", ClientToken: "update-token", RequestHash: "update-hash", Created: modified, DeletionProtection: &protection, AuthenticationMode: "API", KubernetesVersion: "1.33"}
	return c, e, p, u
}
func putRecords(tx domain.Transaction, c domain.Cluster, e domain.AccessEntry, p domain.AccessPolicy, u domain.Update) error {
	if err := tx.PutCluster(c); err != nil {
		return err
	}
	if err := tx.PutAccessEntry(e); err != nil {
		return err
	}
	for _, token := range []string{"older-token", "mutation-token"} {
		if err := tx.PutAccessMutation(domain.AccessMutation{Key: e.Key, PrincipalARN: e.PrincipalARN, Token: token, RequestHash: token + "-hash"}); err != nil {
			return err
		}
	}
	if err := tx.PutAccessPolicy(p); err != nil {
		return err
	}
	return tx.PutClusterUpdate(u)
}
func appendEvent(ctx context.Context, events journal.Storage, id string) error {
	k := clusterKey()
	return events.AppendAPICallCompleted(ctx, journal.Envelope{At: time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC), Partition: k.Partition, AccountID: k.AccountID, Region: k.Region}, journal.APICallCompleted{EventID: id, EventSource: "eks.amazonaws.com", EventName: "UpdateClusterConfig", Category: journal.CategoryManagement})
}
func checkRecords(t *testing.T, r domain.Reader, k domain.Key) error {
	t.Helper()
	c, e, p, u := records(k)
	gotC, err := r.Cluster(k)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(gotC, c) {
		t.Fatalf("retained cluster = %#v, want %#v", gotC, c)
	}
	gotE, err := r.AccessEntry(k, e.PrincipalARN)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(gotE, e) {
		t.Fatalf("retained entry = %#v, want %#v", gotE, e)
	}
	for _, token := range []string{"older-token", "mutation-token"} {
		mutation, err := r.AccessMutation(k, e.PrincipalARN, token)
		if err != nil {
			return err
		}
		if mutation != (domain.AccessMutation{Key: k, PrincipalARN: e.PrincipalARN, Token: token, RequestHash: token + "-hash"}) {
			t.Fatalf("retained access mutation = %#v", mutation)
		}
	}
	gotP, err := r.AccessPolicies(k, e.PrincipalARN)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(gotP, []domain.AccessPolicy{p}) {
		t.Fatalf("retained policies = %#v, want %#v", gotP, p)
	}
	gotU, err := r.ClusterUpdate(k, u.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(gotU, u) {
		t.Fatalf("retained update = %#v, want %#v", gotU, u)
	}
	return nil
}

func TestRepositoryRollbackAndSharedAttempt(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			k := clusterKey()
			c, e, p, u := records(k)
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := putRecords(tx, c, e, p, u); err != nil {
					return err
				}
				return appendEvent(tx.Context(), r.events, "seed")
			}); err != nil {
				t.Fatal(err)
			}
			rejected := errors.New("rejected transition")
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteCluster(k); err != nil {
					return err
				}
				if err := appendEvent(tx.Context(), r.events, "rolled-back"); err != nil {
					return err
				}
				return rejected
			}); !errors.Is(err, rejected) {
				t.Fatalf("rollback = %v", err)
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error { return checkRecords(t, reader, k) }); err != nil {
				t.Fatal(err)
			}
			// An ordinary borrowed write failure aborts its owner, even when caught.
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				err := r.repo.Update(tx.Context(), func(child domain.Transaction) error {
					if err := child.DeleteCluster(k); err != nil {
						return err
					}
					if err := appendEvent(child.Context(), r.events, "caught-write"); err != nil {
						return err
					}
					return rejected
				})
				if !errors.Is(err, rejected) {
					t.Fatalf("nested failure = %v", err)
				}
				return nil
			}); !errors.Is(err, rejected) {
				t.Fatalf("caught nested write committed: %v", err)
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error { return checkRecords(t, reader, k) }); err != nil {
				t.Fatal(err)
			}
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				err := r.repo.Attempt(tx.Context(), func(child domain.Transaction) error {
					if err := child.DeleteCluster(k); err != nil {
						return err
					}
					if err := appendEvent(child.Context(), r.events, "rejected-command"); err != nil {
						return err
					}
					return rejected
				})
				if !errors.Is(err, rejected) {
					t.Fatalf("attempt failure = %v", err)
				}
				if err := checkRecords(t, tx, k); err != nil {
					return err
				}
				if err := r.repo.Attempt(tx.Context(), func(child domain.Transaction) error {
					changed, err := child.Cluster(k)
					if err != nil {
						return err
					}
					changed.Generation++
					changed.Due = changed.Created.Add(5 * time.Second)
					if err := child.PutCluster(changed); err != nil {
						return err
					}
					return appendEvent(child.Context(), r.events, "accepted-command")
				}); err != nil {
					return err
				}
				changed, err := tx.Cluster(k)
				if err != nil {
					return err
				}
				if changed.Generation != 8 || !changed.Due.Equal(c.Created.Add(5*time.Second)) {
					t.Fatalf("owner missed successful savepoint: %#v", changed)
				}
				changed.Status = "ACTIVE"
				return tx.PutCluster(changed)
			}); err != nil {
				t.Fatal(err)
			}
			if r.restart != nil {
				r.restart()
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				got, err := reader.Cluster(k)
				if err != nil {
					return err
				}
				if got.Generation != 8 || got.Status != "ACTIVE" || !got.Due.Equal(c.Created.Add(5*time.Second)) {
					t.Fatalf("accepted command lost: %#v", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			events, err := r.events.Read(t.Context(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, 0, len(events))
			for _, event := range events {
				ids = append(ids, event.APICallCompleted.EventID)
			}
			if !slices.Equal(ids, []string{"seed", "accepted-command"}) {
				t.Fatalf("journal did not share command/owner rollback: %v", ids)
			}
		})
	}
}

func TestRepositoryMutableOwnershipAndRestart(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			k := clusterKey()
			c, e, p, u := records(k)
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := putRecords(tx, c, e, p, u); err != nil {
					return err
				}
				c.Subnets[0], c.SecurityGroups[0], c.Tags["owner"] = "changed", "changed", "changed"
				e.Groups[0], e.Tags["owner"] = "changed", "changed"
				p.Namespaces[0] = "changed"
				*u.DeletionProtection = true
				return checkRecords(t, tx, k)
			}); err != nil {
				t.Fatal(err)
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				c, err := reader.Cluster(k)
				if err != nil {
					return err
				}
				c.Subnets[0], c.SecurityGroups[0], c.Tags["owner"] = "read-change", "read-change", "read-change"
				e, err := reader.AccessEntry(k, e.PrincipalARN)
				if err != nil {
					return err
				}
				e.Groups[0], e.Tags["owner"] = "read-change", "read-change"
				policies, err := reader.AccessPolicies(k, e.PrincipalARN)
				if err != nil {
					return err
				}
				policies[0].Namespaces[0] = "read-change"
				u, err := reader.ClusterUpdate(k, u.ID)
				if err != nil {
					return err
				}
				*u.DeletionProtection = true
				all, err := reader.AllClusters()
				if err != nil {
					return err
				}
				all[0].Tags["owner"] = "list-change"
				clusters, err := reader.Clusters(k.Scope)
				if err != nil {
					return err
				}
				clusters[0].Subnets[0] = "list-change"
				entries, err := reader.AccessEntries(k)
				if err != nil {
					return err
				}
				entries[0].Groups[0] = "list-change"
				updates, err := reader.ClusterUpdates(k)
				if err != nil {
					return err
				}
				*updates[0].DeletionProtection = true
				return checkRecords(t, reader, k)
			}); err != nil {
				t.Fatal(err)
			}
			if r.restart != nil {
				r.restart()
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error { return checkRecords(t, reader, k) }); err != nil {
				t.Fatal(err)
			}
			// Unset deadlines and tri-state update intent remain distinct from epoch/false.
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				c, err := tx.Cluster(k)
				if err != nil {
					return err
				}
				c.Due, c.Tags, c.Subnets, c.SecurityGroups = time.Time{}, nil, nil, []string{}
				if err := tx.PutCluster(c); err != nil {
					return err
				}
				for _, id := range []string{"nil", "true"} {
					v := domain.Update{Key: k, ID: id}
					if id == "true" {
						b := true
						v.DeletionProtection = &b
					}
					if err := tx.PutClusterUpdate(v); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if r.restart != nil {
				r.restart()
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				c, err := reader.Cluster(k)
				if err != nil {
					return err
				}
				if !c.Due.IsZero() || c.Tags != nil || c.Subnets != nil || !reflect.DeepEqual(c.SecurityGroups, []string{}) {
					t.Fatalf("unset/empty intent changed: %#v", c)
				}
				for _, id := range []string{"nil", "true"} {
					u, err := reader.ClusterUpdate(k, id)
					if err != nil {
						return err
					}
					if !u.Created.IsZero() || (id == "nil" && u.DeletionProtection != nil) || (id == "true" && (u.DeletionProtection == nil || !*u.DeletionProtection)) {
						t.Fatalf("tri-state intent changed: %#v", u)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryExactScopeCascadeAndOrdering(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			k := clusterKey()
			partition, account, region, name := k, k, k, k
			partition.Partition, account.AccountID, region.Region, name.Name = "aws-cn", "222222222222", "us-west-2", "another"
			keys := []domain.Key{partition, region, k, name, account}
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				for _, key := range keys {
					c, e, p, u := records(key)
					if err := putRecords(tx, c, e, p, u); err != nil {
						return err
					}
				}
				_, e, p, u := records(k)
				e.PrincipalARN += "/z"
				if err := tx.PutAccessEntry(e); err != nil {
					return err
				}
				if err := tx.PutAccessMutation(domain.AccessMutation{Key: k, PrincipalARN: e.PrincipalARN, Token: "mutation-token", RequestHash: "other-principal-hash"}); err != nil {
					return err
				}
				p.PrincipalARN = e.PrincipalARN
				if err := tx.PutAccessPolicy(p); err != nil {
					return err
				}
				p.PolicyARN += "Z"
				if err := tx.PutAccessPolicy(p); err != nil {
					return err
				}
				u.ID = "update-z"
				return tx.PutClusterUpdate(u)
			}); err != nil {
				t.Fatal(err)
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				all, err := reader.AllClusters()
				if err != nil {
					return err
				}
				got := make([]domain.Key, 0, len(all))
				for _, c := range all {
					got = append(got, c.Key)
				}
				if !slices.Equal(got, []domain.Key{name, k, region, account, partition}) {
					t.Fatalf("all cluster ordering/scope = %v", got)
				}
				local, err := reader.Clusters(k.Scope)
				if err != nil {
					return err
				}
				if len(local) != 2 || local[0].Key != name || local[1].Key != k {
					t.Fatalf("scoped cluster ordering = %#v", local)
				}
				entries, err := reader.AccessEntries(k)
				if err != nil {
					return err
				}
				_, e, p, _ := records(k)
				if len(entries) != 2 || entries[0].PrincipalARN != e.PrincipalARN || entries[1].PrincipalARN != e.PrincipalARN+"/z" {
					t.Fatalf("entry ordering = %#v", entries)
				}
				policies, err := reader.AccessPolicies(k, e.PrincipalARN+"/z")
				if err != nil {
					return err
				}
				if len(policies) != 2 || policies[0].PolicyARN != p.PolicyARN || policies[1].PolicyARN != p.PolicyARN+"Z" {
					t.Fatalf("policy ordering = %#v", policies)
				}
				updates, err := reader.ClusterUpdates(k)
				if err != nil {
					return err
				}
				if len(updates) != 2 || updates[0].ID != "update-a" || updates[1].ID != "update-z" {
					t.Fatalf("update ordering = %#v", updates)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				_, e, p, _ := records(k)
				if err := tx.DeleteAccessPolicy(k, e.PrincipalARN+"/z", p.PolicyARN+"Z"); err != nil {
					return err
				}
				if err := tx.DeleteAccessEntry(k, e.PrincipalARN); err != nil {
					return err
				}
				for _, token := range []string{"older-token", "mutation-token"} {
					if _, err := tx.AccessMutation(k, e.PrincipalARN, token); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("entry deletion retained mutation %q: %v", token, err)
					}
				}
				mutation, err := tx.AccessMutation(k, e.PrincipalARN+"/z", "mutation-token")
				if err != nil {
					return err
				}
				if mutation.RequestHash != "other-principal-hash" {
					t.Fatalf("entry deletion crossed mutation principal: %#v", mutation)
				}
				policies, err := tx.AccessPolicies(k, e.PrincipalARN)
				if err != nil {
					return err
				}
				if len(policies) != 0 {
					t.Fatalf("entry deletion retained policies: %#v", policies)
				}
				policies, err = tx.AccessPolicies(k, e.PrincipalARN+"/z")
				if err != nil {
					return err
				}
				if len(policies) != 1 || policies[0].PolicyARN != p.PolicyARN {
					t.Fatalf("entry/policy deletion crossed principal: %#v", policies)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := tx.DeleteCluster(k); err != nil {
					return err
				}
				if _, err := tx.Cluster(k); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted cluster lookup = %v", err)
				}
				return tx.PutCluster(domain.Cluster{Key: k, ID: "new-incarnation"})
			}); err != nil {
				t.Fatal(err)
			}
			if r.restart != nil {
				r.restart()
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				for _, key := range []domain.Key{partition, account, region, name} {
					if err := checkRecords(t, reader, key); err != nil {
						return err
					}
				}
				c, err := reader.Cluster(k)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(c, domain.Cluster{Key: k, ID: "new-incarnation"}) {
					t.Fatalf("recreated name inherited intent: %#v", c)
				}
				entries, err := reader.AccessEntries(k)
				if err != nil {
					return err
				}
				updates, err := reader.ClusterUpdates(k)
				if err != nil {
					return err
				}
				_, e, _, u := records(k)
				for _, principal := range []string{e.PrincipalARN, e.PrincipalARN + "/z"} {
					policies, err := reader.AccessPolicies(k, principal)
					if err != nil {
						return err
					}
					if len(policies) != 0 {
						t.Fatalf("cluster deletion retained policies: %#v", policies)
					}
					if _, err := reader.AccessEntry(k, principal); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("deleted entry lookup = %v", err)
					}
					for _, token := range []string{"older-token", "mutation-token"} {
						if _, err := reader.AccessMutation(k, principal, token); !errors.Is(err, domain.ErrNotFound) {
							t.Fatalf("cluster deletion retained mutation %q: %v", token, err)
						}
					}
				}
				if len(entries) != 0 || len(updates) != 0 {
					t.Fatalf("cluster deletion retained children: entries=%#v updates=%#v", entries, updates)
				}
				if _, err := reader.ClusterUpdate(k, u.ID); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("deleted update lookup = %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryCallbackLifetimeAndReadOnlyBoundary(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			k := clusterKey()
			var expired domain.Transaction
			if err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				expired = tx
				return tx.PutCluster(domain.Cluster{Key: k, ID: "retained"})
			}); err != nil {
				t.Fatal(err)
			}
			if err := expired.DeleteCluster(k); err == nil {
				t.Fatal("expired writer accepted deletion")
			}
			if _, err := expired.Cluster(k); err == nil {
				t.Fatal("expired reader exposed state")
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				if err := r.repo.Update(reader.Context(), func(tx domain.Transaction) error { return tx.DeleteCluster(k) }); err == nil {
					t.Fatal("view allowed borrowed write")
				}
				if err := r.repo.Attempt(reader.Context(), func(tx domain.Transaction) error { return tx.DeleteCluster(k) }); err == nil {
					t.Fatal("view allowed command savepoint")
				}
				got, err := reader.Cluster(k)
				if err != nil {
					return err
				}
				if got.ID != "retained" {
					t.Fatalf("read-only boundary lost cluster: %#v", got)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositorySuccessfulAttemptStillBelongsToOwner(t *testing.T) {
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			r := openRepositories(t, kind)
			k := clusterKey()
			rejected := errors.New("outer command rejected")
			err := r.repo.Update(t.Context(), func(tx domain.Transaction) error {
				if err := r.repo.Attempt(tx.Context(), func(child domain.Transaction) error {
					c, e, p, u := records(k)
					if err := putRecords(child, c, e, p, u); err != nil {
						return err
					}
					return appendEvent(child.Context(), r.events, "uncommitted-command")
				}); err != nil {
					return err
				}
				if err := checkRecords(t, tx, k); err != nil {
					return err
				}
				return rejected
			})
			if !errors.Is(err, rejected) {
				t.Fatalf("outer rollback = %v", err)
			}
			if err := r.repo.View(t.Context(), func(reader domain.Reader) error {
				if _, err := reader.Cluster(k); !errors.Is(err, domain.ErrNotFound) {
					t.Fatalf("savepoint committed beyond owner: %v", err)
				}
				entries, err := reader.AccessEntries(k)
				if err != nil {
					return err
				}
				updates, err := reader.ClusterUpdates(k)
				if err != nil {
					return err
				}
				_, e, _, _ := records(k)
				for _, token := range []string{"older-token", "mutation-token"} {
					if _, err := reader.AccessMutation(k, e.PrincipalARN, token); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("savepoint retained uncommitted mutation %q: %v", token, err)
					}
				}
				policies, err := reader.AccessPolicies(k, e.PrincipalARN)
				if err != nil {
					return err
				}
				if len(entries) != 0 || len(updates) != 0 || len(policies) != 0 {
					t.Fatalf("savepoint retained uncommitted children: %v %v %v", entries, updates, policies)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			events, err := r.events.Read(t.Context(), 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatalf("savepoint retained uncommitted journal: %#v", events)
			}
		})
	}
}
