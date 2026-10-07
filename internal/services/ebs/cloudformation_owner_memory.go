package ebs

func (r memoryReader) CloudFormationCreation(k CloudFormationCreationKey) (string, error) {
	if err := r.tx.Check(false); err != nil {
		return "", err
	}
	id, ok := r.s.creations[k]
	if !ok {
		return "", ErrNotFound
	}
	return id, nil
}
func (w memoryWriter) PutCloudFormationCreation(k CloudFormationCreationKey, id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if prior, ok := w.s.creations[k]; ok && prior != id {
		return ownershipFailure()
	}
	w.s.creations[k] = id
	return nil
}
