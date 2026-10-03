package cloudformation

import (
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func (r reader) Events(stack string) ([]domain.EventRecord, error) {
	rows, err := r.q.Events(r.ctx, stack)
	if err != nil {
		return nil, err
	}
	out := make([]domain.EventRecord, 0, len(rows))
	for _, row := range rows {
		v, err := decodeEvent(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func decodeEvent(row sqlcgen.CloudformationEvent) (domain.EventRecord, error) {
	var out domain.EventRecord
	out.StackID = row.StackID
	out.ID = row.ID
	out.LogicalID = row.LogicalID
	out.Type = row.Type
	out.PhysicalID = row.PhysicalID
	out.Status = row.Status
	out.Reason = row.Reason
	out.Token = row.Token
	out.Sequence = uint64(row.Sequence)
	out.Timestamp = row.Timestamp.UTC()
	if err := decodeDocument(row.Properties, &out.Properties); err != nil {
		return out, err
	}
	return out, nil
}

func encodeEvent(v domain.EventRecord) (sqlcgen.PutEventParams, error) {
	var p sqlcgen.PutEventParams
	var err error
	p.StackID = v.StackID
	p.ID = v.ID
	p.LogicalID = v.LogicalID
	p.Type = v.Type
	p.PhysicalID = v.PhysicalID
	p.Status = v.Status
	p.Reason = v.Reason
	p.Token = v.Token
	p.Sequence, err = signed(v.Sequence)
	if err != nil {
		return p, err
	}
	p.Timestamp = v.Timestamp.UTC()
	p.Properties, err = encodeDocument(v.Properties)
	if err != nil {
		return p, err
	}
	return p, nil
}

func (w writer) PutEvent(v domain.EventRecord) error {
	p, err := encodeEvent(v)
	if err != nil {
		return err
	}
	if err := w.q.PutEvent(w.ctx, p); err != nil {
		return err
	}
	return nil
}
