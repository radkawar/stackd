package guardduty

import (
	domain "stackd/storage/guardduty"
	"stackd/storage/sqlite/guardduty/internal/sqlcgen"
)

func (r reader) IPList(sc domain.Scope, detector string, kind domain.IPListKind, id string) (domain.IPList, error) {
	row, err := r.q.GetIPList(r.ctx, sqlcgen.GetIPListParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Kind: string(kind), ID: id})
	if err != nil {
		return domain.IPList{}, notFound(err)
	}
	return r.ipList(row)
}

func (r reader) IPLists(sc domain.Scope, detector string) ([]domain.IPList, error) {
	rows, err := r.q.ListIPLists(r.ctx, sqlcgen.ListIPListsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector})
	if err != nil {
		return nil, err
	}
	return r.ipLists(rows)
}

func (r reader) MatchingIPLists(sc domain.Scope, detector string, ip uint32) ([]domain.IPList, error) {
	rows, err := r.q.MatchingIPLists(r.ctx, sqlcgen.MatchingIPListsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Ip: int64(ip)})
	if err != nil {
		return nil, err
	}
	return r.ipLists(rows)
}

func (r reader) ipLists(rows []sqlcgen.GuarddutyIpList) ([]domain.IPList, error) {
	var out []domain.IPList
	if len(rows) > 0 {
		out = make([]domain.IPList, 0, len(rows))
	}
	for _, row := range rows {
		v, err := r.ipList(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) ipList(row sqlcgen.GuarddutyIpList) (domain.IPList, error) {
	v := domain.IPList{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DetectorID: row.DetectorID, Kind: domain.IPListKind(row.Kind), ID: row.ID, ARN: row.Arn, Name: row.Name, Format: row.Format, Location: row.Location, ExpectedBucketOwner: row.ExpectedBucketOwner, ClientToken: row.ClientToken, Status: row.Status, Version: row.Version, Due: row.Due}
	if row.TagsPresent {
		v.Tags = map[string]string{}
	}
	tags, err := r.q.ListIPListTags(r.ctx, row.Arn)
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.TagKey] = tag.TagValue
	}
	return v, nil
}

func (w writer) PutIPList(v domain.IPList) error {
	if _, err := w.q.GetDetector(w.ctx, sqlcgen.GetDetectorParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.DetectorID}); err != nil {
		return notFound(err)
	}
	if err := w.q.PutIPList(w.ctx, sqlcgen.PutIPListParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, Kind: string(v.Kind), ID: v.ID, Arn: v.ARN, Name: v.Name, Format: v.Format, Location: v.Location, ExpectedBucketOwner: v.ExpectedBucketOwner, ClientToken: v.ClientToken, Status: v.Status, Version: v.Version, Due: v.Due, TagsPresent: v.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteIPListTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutIPListTag(w.ctx, sqlcgen.PutIPListTagParams{Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteIPList(sc domain.Scope, detector string, kind domain.IPListKind, id string) error {
	return w.q.DeleteIPList(w.ctx, sqlcgen.DeleteIPListParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Kind: string(kind), ID: id})
}

func (w writer) ReplaceIPRanges(sc domain.Scope, detector string, kind domain.IPListKind, id string, ranges []domain.IPRange) error {
	if _, err := w.q.GetIPList(w.ctx, sqlcgen.GetIPListParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Kind: string(kind), ID: id}); err != nil {
		return notFound(err)
	}
	if err := w.q.DeleteIPRanges(w.ctx, sqlcgen.DeleteIPRangesParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Kind: string(kind), ID: id}); err != nil {
		return err
	}
	for _, interval := range ranges {
		if err := w.q.PutIPRange(w.ctx, sqlcgen.PutIPRangeParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, Kind: string(kind), ID: id, FirstIp: int64(interval.First), LastIp: int64(interval.Last)}); err != nil {
			return err
		}
	}
	return nil
}
