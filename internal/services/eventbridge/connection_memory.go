package eventbridge

import "slices"

func cloneConnection(v ConnectionRecord) ConnectionRecord {
	v.Parameters = slices.Clone(v.Parameters)
	return v
}
func (r memoryReader) Connection(k ConnectionKey) (ConnectionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ConnectionRecord{}, err
	}
	v, ok := r.s.connections[k]
	if !ok {
		return v, ErrNotFound
	}
	return cloneConnection(v), nil
}
func (r memoryReader) ConnectionByID(id string) (ConnectionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ConnectionRecord{}, err
	}
	for _, v := range r.s.connections {
		if v.ID == id {
			return cloneConnection(v), nil
		}
	}
	return ConnectionRecord{}, ErrNotFound
}
func (r memoryReader) Connections(scope Scope) ([]ConnectionRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ConnectionRecord{}
	for k, v := range r.s.connections {
		if k.Scope == scope {
			out = append(out, cloneConnection(v))
		}
	}
	slices.SortFunc(out, func(a, b ConnectionRecord) int { return compare(a.Key.Name, b.Key.Name) })
	return out, nil
}
func (r memoryReader) ConnectionARNs(partition, account string) ([]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []string{}
	for k, v := range r.s.connections {
		if k.Partition == partition && k.Account == account {
			out = append(out, v.ARN())
		}
	}
	slices.Sort(out)
	return out, nil
}
func (r memoryReader) NextConnectionJob() (ConnectionRecord, bool, error) {
	if err := r.tx.Check(false); err != nil {
		return ConnectionRecord{}, false, err
	}
	var next ConnectionRecord
	found := false
	for _, v := range r.s.connections {
		if !v.Due.IsZero() && (!found || v.Due.Before(next.Due) || v.Due.Equal(next.Due) && v.ID < next.ID) {
			next, found = v, true
		}
	}
	return cloneConnection(next), found, nil
}
func (w memoryWriter) PutConnection(v ConnectionRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.connections[v.Key] = cloneConnection(v)
	return nil
}
func (w memoryWriter) DeleteConnection(k ConnectionKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.connections, k)
	return nil
}
