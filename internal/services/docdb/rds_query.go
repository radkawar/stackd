package docdb

import (
	"context"
	"errors"
	rdsengine "stackd/engine/rds"
	"stackd/internal/services/rds"
	"strings"
)

// NameOwner reserves the existing RDS identifier namespace through the other
// authoritative repository in the same command transaction.
type NameOwner interface {
	Owns(context.Context, string, string) (bool, error)
}

func (s *Service) checkName(ctx context.Context, k Key) error {
	if s.names == nil {
		return nil
	}
	exists, e := s.names.Owns(ctx, k.Kind, k.Name)
	if e != nil {
		return e
	}
	if exists {
		return duplicate(k.Kind)
	}
	return nil
}

// Owns performs a routing lookup, not authorization or a public existence API.
// Execution remains responsible for current IAM and native readiness checks.
func (s *Service) Owns(ctx context.Context, kind, reference string) (bool, error) {
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 7)
		if len(parts) != 7 {
			return false, nil
		}
		kind = parts[5]
	}
	if kind != "cluster" && kind != "db" && kind != "cluster-snapshot" {
		return false, nil
	}
	k, e := resourceKey(ctx, kind, reference)
	if e != nil {
		return false, nil
	}
	found := false
	e = s.repository.View(ctx, func(r Reader) error {
		var e error
		switch kind {
		case "cluster":
			_, e = r.Cluster(k)
		case "db":
			_, e = r.Instance(k)
		case "cluster-snapshot":
			_, e = r.Snapshot(k)
		}
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e == nil {
			found = true
		}
		return e
	})
	return found, e
}
func rdsKey(k Key) rds.Key {
	return rds.Key{Scope: rds.Scope{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region}, Kind: k.Kind, Name: k.Name}
}

// RDSDatabases supplies ephemeral list projections for the shared RDS Query
// namespace. Native passwords, TLS keys and document data never cross this edge.
func (s *Service) RDSDatabases(ctx context.Context) ([]rds.Database, error) {
	out := []rds.Database{}
	e := s.repository.View(ctx, func(r Reader) error {
		clusters, e := r.Clusters()
		if e != nil {
			return e
		}
		byName := map[Key]Cluster{}
		for _, v := range clusters {
			if v.Key.Scope != scopeFor(ctx) {
				continue
			}
			byName[v.Key] = v
			out = append(out, rds.Database{Key: rdsKey(v.Key), Engine: "docdb", EngineVersion: v.EngineVersion, Username: v.Username, RuntimeID: v.RuntimeID, Status: v.Status, Created: v.Created, DeletionProtection: v.DeletionProtection, Tags: v.Tags, Endpoint: rdsengine.Endpoint{Address: v.Endpoint.Address, Port: v.Endpoint.Port}})
		}
		instances, e := r.Instances()
		if e != nil {
			return e
		}
		for _, m := range instances {
			if m.Key.Scope != scopeFor(ctx) {
				continue
			}
			v, ok := byName[Key{Scope: m.Key.Scope, Kind: "cluster", Name: m.Cluster}]
			if !ok {
				return errors.New("DocumentDB member has no owning cluster")
			}
			out = append(out, rds.Database{Key: rdsKey(m.Key), Engine: "docdb", EngineVersion: v.EngineVersion, Username: v.Username, Class: m.Class, RuntimeID: m.RuntimeID, Status: m.Status, Cluster: m.Cluster, Created: m.Created, Tags: m.Tags, Endpoint: rdsengine.Endpoint{Address: v.Endpoint.Address, Port: v.Endpoint.Port}})
		}
		return nil
	})
	return out, e
}
func (s *Service) RDSSnapshots(ctx context.Context) ([]rds.Snapshot, error) {
	out := []rds.Snapshot{}
	e := s.repository.View(ctx, func(r Reader) error {
		all, e := r.Snapshots()
		if e != nil {
			return e
		}
		for _, v := range all {
			if v.Key.Scope == scopeFor(ctx) {
				out = append(out, rds.Snapshot{Key: rdsKey(v.Key), Source: v.Source, RuntimeID: v.RuntimeID, Engine: "docdb", EngineVersion: v.EngineVersion, Username: v.Username, Status: v.Status, Created: v.Created, Tags: v.Tags})
			}
		}
		return nil
	})
	return out, e
}
