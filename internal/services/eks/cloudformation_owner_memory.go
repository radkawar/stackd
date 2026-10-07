package eks

import "slices"

func (r memoryReader) CloudFormationCreation(key CloudFormationCreationKey) (CloudFormationCreation, error) {
	if err := r.tx.Check(false); err != nil {
		return CloudFormationCreation{}, err
	}
	row, ok := r.s.cloudFormationCreations[key]
	if !ok {
		return CloudFormationCreation{}, ErrNotFound
	}
	return row, nil
}
func (r memoryReader) CloudFormationCreations(scope Scope) ([]CloudFormationCreation, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	var rows []CloudFormationCreation
	for key, row := range r.s.cloudFormationCreations {
		if key.Scope == scope {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b CloudFormationCreation) int {
		if a.Key.ResourceType < b.Key.ResourceType {
			return -1
		}
		if a.Key.ResourceType > b.Key.ResourceType {
			return 1
		}
		if a.Key.Owner < b.Key.Owner {
			return -1
		}
		if a.Key.Owner > b.Key.Owner {
			return 1
		}
		return 0
	})
	return rows, nil
}
func (w memoryWriter) PutCloudFormationCreation(row CloudFormationCreation) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.cloudFormationCreations[row.Key]; ok {
		return cloudFormationMismatch()
	}
	for key, old := range w.s.cloudFormationCreations {
		if key.Scope == row.Key.Scope && key.ResourceType == row.Key.ResourceType && old.NativeID == row.NativeID {
			return cloudFormationMismatch()
		}
	}
	w.s.cloudFormationCreations[row.Key] = row
	return nil
}
