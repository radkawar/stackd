package elasticache_test

import (
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"

	engine "stackd/engine/valkey"
	domain "stackd/storage/elasticache"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/elasticache"
)

func TestPlacementRoundTripRestartScopeAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "placement.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster", Name: "placed"}
	// These are retained reservation values, not values inferred by persistence.
	original := domain.Cluster{Key: key, RuntimeID: "immutable-incarnation", SubnetGroup: "private-cache", ClientPort: 6379, ClientSubnets: []string{"subnet-b", "subnet-a"}, SecurityGroups: []string{"sg-b", "sg-a"}, NodePlacements: []domain.CacheNodePlacement{
		{NodeIndex: 2, InterfaceID: "eni-second", SubnetID: "subnet-b", AvailabilityZone: "us-east-1b", NetworkID: "vpc-private", Address: netip.MustParseAddr("10.20.2.17"), Gateway: netip.MustParseAddr("10.20.2.1"), Pool: netip.MustParsePrefix("10.20.2.0/24"), MAC: "02:00:00:00:02:17"},
		{NodeIndex: 1, InterfaceID: "eni-first", SubnetID: "subnet-a", AvailabilityZone: "us-east-1a", NetworkID: "vpc-private", Address: netip.MustParseAddr("10.20.1.19"), Gateway: netip.MustParseAddr("10.20.1.1"), Pool: netip.MustParsePrefix("10.20.1.0/24"), MAC: "02:00:00:00:01:19"},
	}, Nodes: []engine.Node{{ID: "primary", Endpoint: engine.Endpoint{Address: "10.20.1.19", Port: 6379}}, {ID: "replica", Endpoint: engine.Endpoint{Address: "10.20.2.17", Port: 6379}}}}
	keys := []domain.Key{key}
	for _, scope := range []domain.Scope{{Partition: "aws-cn", AccountID: key.AccountID, Region: key.Region}, {Partition: key.Partition, AccountID: "222222222222", Region: key.Region}, {Partition: key.Partition, AccountID: key.AccountID, Region: "us-west-2"}} {
		other := key
		other.Scope = scope
		keys = append(keys, other)
	}
	otherKind := key
	otherKind.Kind = "replication-group"
	keys = append(keys, otherKind)
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
		for _, k := range keys {
			v := original
			v.Key = k
			if e := tx.PutCluster(v); e != nil {
				return e
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("abort placement transition")
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
		changed := original
		changed.SubnetGroup = "uncommitted"
		changed.ClientPort = 0
		changed.ClientSubnets = nil
		changed.SecurityGroups = nil
		changed.NodePlacements = nil
		if e := tx.PutCluster(changed); e != nil {
			return e
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repo = backend.New(db)
	assertPlacement := func(k domain.Key) {
		t.Helper()
		if e := repo.View(t.Context(), func(r domain.Reader) error {
			got, e := r.Cluster(k)
			if e != nil {
				return e
			}
			if got.SubnetGroup != original.SubnetGroup || got.ClientPort != original.ClientPort || got.RuntimeID != original.RuntimeID || !reflect.DeepEqual(got.ClientSubnets, original.ClientSubnets) || !reflect.DeepEqual(got.SecurityGroups, original.SecurityGroups) || !reflect.DeepEqual(got.NodePlacements, original.NodePlacements) || !reflect.DeepEqual(got.Nodes, original.Nodes) {
				t.Fatalf("placement changed: %#v", got)
			}
			got.ClientSubnets[0] = "mutated"
			got.SecurityGroups[0] = "mutated"
			got.NodePlacements[0].InterfaceID = "mutated"
			again, e := r.Cluster(k)
			if e != nil {
				return e
			}
			if !reflect.DeepEqual(again.ClientSubnets, original.ClientSubnets) || !reflect.DeepEqual(again.SecurityGroups, original.SecurityGroups) || !reflect.DeepEqual(again.NodePlacements, original.NodePlacements) {
				t.Fatal("read slices share mutable storage")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	for _, k := range keys {
		assertPlacement(k)
	}
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteCluster(key) }); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"elasticache_client_subnet", "elasticache_security_group", "elasticache_node_placement"} {
		var count int
		if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table+" WHERE partition = ? AND account_id = ? AND region = ? AND kind = ? AND name = ?", key.Partition, key.AccountID, key.Region, key.Kind, key.Name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained deleted ownership: %d", table, count)
		}
	}
	for _, k := range keys[1:] {
		assertPlacement(k)
	}
	if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
		return tx.PutCluster(domain.Cluster{Key: key, RuntimeID: "replacement"})
	}); err != nil {
		t.Fatal(err)
	}
	if err = repo.View(t.Context(), func(r domain.Reader) error {
		got, e := r.Cluster(key)
		if e != nil {
			return e
		}
		if got.SubnetGroup != "" || got.ClientPort != 0 || len(got.ClientSubnets) != 0 || len(got.SecurityGroups) != 0 || len(got.NodePlacements) != 0 || len(got.Nodes) != 0 {
			t.Fatalf("replacement inherited placement: %#v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPlacementConstraintsRollbackWholeCluster(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "constraints.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := backend.New(db)
	key := domain.Key{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster", Name: "invalid"}
	placement := domain.CacheNodePlacement{NodeIndex: 1, InterfaceID: "eni-owned", Address: netip.MustParseAddr("10.0.0.2"), Gateway: netip.MustParseAddr("10.0.0.1"), Pool: netip.MustParsePrefix("10.0.0.0/24")}
	for _, placements := range [][]domain.CacheNodePlacement{{{NodeIndex: 0}}, {placement, placement}} {
		if err = repo.Update(t.Context(), func(tx domain.Transaction) error {
			return tx.PutCluster(domain.Cluster{Key: key, NodePlacements: placements})
		}); err == nil {
			t.Fatal("invalid placement identity accepted")
		}
		if err = repo.View(t.Context(), func(r domain.Reader) error { _, e := r.Cluster(key); return e }); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("partial cluster committed: %v", err)
		}
	}
}
