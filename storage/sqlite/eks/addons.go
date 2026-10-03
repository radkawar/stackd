package eks

import (
	"encoding/json"
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) Addon(k domain.Key, name string) (domain.Addon, error) {
	row, err := r.q.GetAddon(r.ctx, sqlcgen.GetAddonParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, AddonName: name})
	if err != nil {
		return domain.Addon{}, missing(err)
	}
	return readAddon(row)
}
func (r reader) Addons(k domain.Key) ([]domain.Addon, error) {
	rows, err := r.q.ListAddons(r.ctx, sqlcgen.ListAddonsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Addon, 0, len(rows))
	for _, row := range rows {
		a, err := readAddon(row)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}
func readAddon(row sqlcgen.EksAddon) (domain.Addon, error) {
	a := domain.Addon{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}, Name: row.AddonName, ID: row.ID, Version: row.Version, AppliedVersion: row.AppliedVersion, Configuration: row.Configuration, AppliedConfiguration: row.AppliedConfiguration, Status: row.Status, Operation: row.Operation, Error: row.Error, ErrorCode: row.ErrorCode, ResolveConflicts: row.ResolveConflicts, UpdateID: row.UpdateID, ClientToken: row.ClientToken, RequestHash: row.RequestHash, Created: readTime(row.Created), Modified: readTime(row.Modified), Due: readTime(row.Due), Generation: row.Generation, Preserve: row.Preserve != 0}
	err := json.Unmarshal([]byte(row.Tags), &a.Tags)
	return a, err
}
func (w writer) PutAddon(a domain.Addon) error {
	tags, err := encodeTags(a.Tags)
	if err != nil {
		return err
	}
	k := a.Key
	return w.q.PutAddon(w.ctx, sqlcgen.PutAddonParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, AddonName: a.Name, ID: a.ID, Version: a.Version, AppliedVersion: a.AppliedVersion, Configuration: a.Configuration, AppliedConfiguration: a.AppliedConfiguration, Status: a.Status, Operation: a.Operation, Error: a.Error, ErrorCode: a.ErrorCode, ResolveConflicts: a.ResolveConflicts, UpdateID: a.UpdateID, ClientToken: a.ClientToken, RequestHash: a.RequestHash, Tags: tags, Created: timeValue(a.Created), Modified: timeValue(a.Modified), Due: timeValue(a.Due), Generation: a.Generation, Preserve: bit(a.Preserve)})
}
func (w writer) DeleteAddon(k domain.Key, name string) error {
	return w.q.DeleteAddon(w.ctx, sqlcgen.DeleteAddonParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, AddonName: name})
}
