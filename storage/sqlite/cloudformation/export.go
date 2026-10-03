package cloudformation

import (
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func (r reader) Exports(scope domain.Scope) ([]domain.ExportRecord, error) {
	rows, err := r.q.Exports(r.ctx, sqlcgen.ExportsParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ExportRecord, 0, len(rows))
	for _, row := range rows {
		v, err := decodeExport(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func decodeExport(row sqlcgen.CloudformationExport) (domain.ExportRecord, error) {
	var out domain.ExportRecord
	out.Scope.Partition = row.Partition
	out.Scope.Account = row.Account
	out.Scope.Region = row.Region
	out.Name = row.Name
	out.Value = row.Value
	out.StackID = row.StackID
	return out, nil
}

func encodeExport(v domain.ExportRecord) (sqlcgen.PutExportParams, error) {
	var p sqlcgen.PutExportParams
	p.Partition = v.Scope.Partition
	p.Account = v.Scope.Account
	p.Region = v.Scope.Region
	p.Name = v.Name
	p.Value = v.Value
	p.StackID = v.StackID
	return p, nil
}

func (w writer) PutExport(v domain.ExportRecord) error {
	p, err := encodeExport(v)
	if err != nil {
		return err
	}
	if err := w.q.PutExport(w.ctx, p); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteExport(scope domain.Scope, name string) error {
	return w.q.DeleteExport(w.ctx, sqlcgen.DeleteExportParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region, Name: name})
}
