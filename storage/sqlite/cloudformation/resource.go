package cloudformation

import (
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func (r reader) Resources(stack string) ([]domain.ResourceRecord, error) {
	rows, err := r.q.Resources(r.ctx, stack)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ResourceRecord, 0, len(rows))
	for _, row := range rows {
		v, err := decodeResource(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func decodeResource(row sqlcgen.CloudformationResource) (domain.ResourceRecord, error) {
	var out domain.ResourceRecord
	out.StackID = row.StackID
	out.LogicalID = row.LogicalID
	out.Type = row.Type
	out.PhysicalID = row.PhysicalID
	out.Ref = row.Ref
	out.Token = row.Token
	out.Generation = uint64(row.Generation)
	out.Current = row.Current
	out.Status = row.Status
	out.StatusReason = row.StatusReason
	out.DeletionPolicy = row.DeletionPolicy
	out.UpdateReplacePolicy = row.UpdateReplacePolicy
	if err := decodeDocument(row.Properties, &out.Properties); err != nil {
		return out, err
	}
	if err := decodeDocument(row.EventProperties, &out.EventProperties); err != nil {
		return out, err
	}
	if err := decodeDocument(row.DynamicReferences, &out.DynamicReferences); err != nil {
		return out, err
	}
	if err := decodeDocument(row.Attributes, &out.Attributes); err != nil {
		return out, err
	}
	out.Updated = row.Updated.UTC()
	return out, nil
}

func encodeResource(v domain.ResourceRecord) (sqlcgen.PutResourceParams, error) {
	var p sqlcgen.PutResourceParams
	var err error
	p.StackID = v.StackID
	p.LogicalID = v.LogicalID
	p.Type = v.Type
	p.PhysicalID = v.PhysicalID
	p.Ref = v.Ref
	p.Token = v.Token
	p.Generation, err = signed(v.Generation)
	if err != nil {
		return p, err
	}
	p.Current = v.Current
	p.Status = v.Status
	p.StatusReason = v.StatusReason
	p.DeletionPolicy = v.DeletionPolicy
	p.UpdateReplacePolicy = v.UpdateReplacePolicy
	p.Properties, err = encodeDocument(v.Properties)
	if err != nil {
		return p, err
	}
	p.EventProperties, err = encodeDocument(v.EventProperties)
	if err != nil {
		return p, err
	}
	p.DynamicReferences, err = encodeDocument(v.DynamicReferences)
	if err != nil {
		return p, err
	}
	p.Attributes, err = encodeDocument(v.Attributes)
	if err != nil {
		return p, err
	}
	p.Updated = v.Updated.UTC()
	return p, nil
}

func (w writer) PutResource(v domain.ResourceRecord) error {
	p, err := encodeResource(v)
	if err != nil {
		return err
	}
	if err := w.q.PutResource(w.ctx, p); err != nil {
		return err
	}
	return nil
}
