package configservice

import (
	"maps"
	"slices"
	domain "stackd/storage/configservice"
	"stackd/storage/sqlite/configservice/internal/sqlcgen"
)

func (r reader) loadItem(v sqlcgen.ConfigItem) (domain.Item, error) {
	out := domain.Item{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Sequence: v.Sequence, ResourceType: v.ResourceType, ResourceID: v.ResourceID, ResourceName: v.ResourceName, ARN: v.ARN, AvailabilityZone: v.AvailabilityZone, CaptureTime: v.CaptureTime, CreationTime: v.CreationTime, Status: v.Status, Configuration: v.Configuration}
	tags, err := r.q.ListItemTags(r.ctx, v.Sequence)
	if err != nil {
		return out, err
	}
	for _, t := range tags {
		if out.Tags == nil {
			out.Tags = make(map[string]string, len(tags))
		}
		out.Tags[t.TagKey] = t.Value
	}
	supplements, err := r.q.ListItemSupplements(r.ctx, v.Sequence)
	if err != nil {
		return out, err
	}
	for _, s := range supplements {
		if out.Supplementary == nil {
			out.Supplementary = make(map[string]string, len(supplements))
		}
		out.Supplementary[s.Name] = s.Document
	}
	relationships, err := r.q.ListItemRelationships(r.ctx, v.Sequence)
	if err != nil {
		return out, err
	}
	for _, rel := range relationships {
		out.Relationships = append(out.Relationships, domain.Relationship{ResourceType: rel.ResourceType, ResourceID: rel.ResourceID, ResourceName: rel.ResourceName, Name: rel.Name})
	}
	return out, nil
}

func (r reader) Items(s domain.Scope) ([]domain.Item, error) {
	rows, err := r.q.ListItems(r.ctx, sqlcgen.ListItemsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Item, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadItem(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) AppendItem(v domain.Item) (domain.Item, error) {
	id, err := w.q.AppendItem(w.ctx, sqlcgen.AppendItemParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, ResourceType: v.ResourceType, ResourceID: v.ResourceID, ResourceName: v.ResourceName, ARN: v.ARN, AvailabilityZone: v.AvailabilityZone, CaptureTime: v.CaptureTime, CreationTime: v.CreationTime, Status: v.Status, Configuration: v.Configuration})
	if err != nil {
		return domain.Item{}, err
	}
	for key, value := range v.Tags {
		if err = w.q.InsertItemTag(w.ctx, sqlcgen.InsertItemTagParams{ParentID: id, TagKey: key, Value: value}); err != nil {
			return domain.Item{}, err
		}
	}
	for name, document := range v.Supplementary {
		if err = w.q.InsertItemSupplement(w.ctx, sqlcgen.InsertItemSupplementParams{ParentID: id, Name: name, Document: document}); err != nil {
			return domain.Item{}, err
		}
	}
	for ordinal, rel := range v.Relationships {
		if err = w.q.InsertItemRelationship(w.ctx, sqlcgen.InsertItemRelationshipParams{ParentID: id, Ordinal: int64(ordinal), ResourceType: rel.ResourceType, ResourceID: rel.ResourceID, ResourceName: rel.ResourceName, Name: rel.Name}); err != nil {
			return domain.Item{}, err
		}
	}
	v.Sequence = id
	v.Tags = maps.Clone(v.Tags)
	v.Supplementary = maps.Clone(v.Supplementary)
	v.Relationships = slices.Clone(v.Relationships)
	return v, nil
}

func (r reader) loadDelivery(v sqlcgen.ConfigDelivery) (domain.Delivery, error) {
	out := domain.Delivery{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, ChannelName: v.ChannelName, Kind: v.Kind, ObjectKey: v.ObjectKey, Due: v.Due, CreatedAt: v.CreatedAt, CompletedAt: v.CompletedAt, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage, Attempts: int(v.Attempts), FirstSequence: v.FirstSequence, LastSequence: v.LastSequence}
	return out, nil
}

func (r reader) Deliveries() ([]domain.Delivery, error) {
	rows, err := r.q.ListDeliveries(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Delivery, 0, len(rows))
	for _, v := range rows {
		record, err := r.loadDelivery(v)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutDelivery(v domain.Delivery) error {
	return w.q.PutDelivery(w.ctx, sqlcgen.PutDeliveryParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, ID: v.ID, ChannelName: v.ChannelName, Kind: v.Kind, ObjectKey: v.ObjectKey, Due: v.Due, CreatedAt: v.CreatedAt, CompletedAt: v.CompletedAt, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage, Attempts: int64(v.Attempts), FirstSequence: v.FirstSequence, LastSequence: v.LastSequence})
}
