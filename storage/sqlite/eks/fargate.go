package eks

import (
	"encoding/json"
	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) FargateProfile(k domain.Key, name string) (domain.FargateProfile, error) {
	row, err := r.q.GetFargateProfile(r.ctx, sqlcgen.GetFargateProfileParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ProfileName: name})
	if err != nil {
		return domain.FargateProfile{}, missing(err)
	}
	return readFargateProfile(row)
}
func (r reader) FargateProfiles(k domain.Key) ([]domain.FargateProfile, error) {
	rows, err := r.q.ListFargateProfiles(r.ctx, sqlcgen.ListFargateProfilesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FargateProfile, 0, len(rows))
	for _, row := range rows {
		p, err := readFargateProfile(row)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func readFargateProfile(row sqlcgen.EksFargateProfile) (domain.FargateProfile, error) {
	p := domain.FargateProfile{Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}, Name: row.ProfileName, ID: row.ID, RoleARN: row.RoleArn, RoleID: row.RoleID, Status: row.Status, Operation: row.Operation, Error: row.Error, ClientToken: row.ClientToken, RequestHash: row.RequestHash, Created: readTime(row.Created), Due: readTime(row.Due), Generation: row.Generation}
	for _, v := range []struct {
		raw string
		out any
	}{{row.Selectors, &p.Selectors}, {row.Subnets, &p.Subnets}, {row.Tags, &p.Tags}} {
		if err := json.Unmarshal([]byte(v.raw), v.out); err != nil {
			return p, err
		}
	}
	return p, nil
}
func (w writer) PutFargateProfile(p domain.FargateProfile) error {
	selectors, err := json.Marshal(p.Selectors)
	if err != nil {
		return err
	}
	subnets, err := encodeStrings(p.Subnets)
	if err != nil {
		return err
	}
	tags, err := encodeTags(p.Tags)
	if err != nil {
		return err
	}
	k := p.Key
	return w.q.PutFargateProfile(w.ctx, sqlcgen.PutFargateProfileParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ProfileName: p.Name, ID: p.ID, RoleArn: p.RoleARN, RoleID: p.RoleID, Status: p.Status, Operation: p.Operation, Error: p.Error, ClientToken: p.ClientToken, RequestHash: p.RequestHash, Selectors: string(selectors), Subnets: subnets, Tags: tags, Created: timeValue(p.Created), Due: timeValue(p.Due), Generation: p.Generation})
}
func (w writer) DeleteFargateProfile(k domain.Key, name string) error {
	return w.q.DeleteFargateProfile(w.ctx, sqlcgen.DeleteFargateProfileParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ProfileName: name})
}
