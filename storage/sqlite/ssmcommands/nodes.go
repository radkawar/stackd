package ssmcommands

import (
	"stackd/storage/sqlite/ssmcommands/internal/sqlcgen"
	domain "stackd/storage/ssmcommands"
)

func (r reader) Node(k domain.Key) (domain.Node, error) {
	row, err := r.q.GetNode(r.ctx, sqlcgen.GetNodeParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, NodeID: k.ID})
	if err != nil {
		return domain.Node{}, missing(err)
	}
	return node(row), nil
}
func (r reader) Nodes(scope domain.Scope) ([]domain.Node, error) {
	rows, err := r.q.ListNodes(r.ctx, sqlcgen.ListNodesParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Node, 0, len(rows))
	for _, row := range rows {
		out = append(out, node(row))
	}
	return out, nil
}
func node(row sqlcgen.SsmNode) domain.Node {
	return domain.Node{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.NodeID}, AgentVersion: row.AgentVersion, AgentName: row.AgentName, PlatformType: row.PlatformType, PlatformName: row.PlatformName, PlatformVersion: row.PlatformVersion, ComputerName: row.ComputerName, RegisteredAt: row.RegisteredAt, LastPing: row.LastPing}
}
func (w writer) PutNode(v domain.Node) error {
	return w.q.PutNode(w.ctx, sqlcgen.PutNodeParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, NodeID: v.Key.ID, AgentVersion: v.AgentVersion, AgentName: v.AgentName, PlatformType: v.PlatformType, PlatformName: v.PlatformName, PlatformVersion: v.PlatformVersion, ComputerName: v.ComputerName, RegisteredAt: v.RegisteredAt.UTC(), LastPing: v.LastPing.UTC()})
}
