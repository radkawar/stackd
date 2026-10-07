package apigateway

import "fmt"

// NextStageIncarnation allocates inside the same owner transaction as stage
// creation. The scoped counter is retained after stage and API deletion.
func (w memoryWriter) NextStageIncarnation(scope Scope) (uint64, error) {
	if err := w.tx.Check(true); err != nil {
		return 0, err
	}
	current := w.s.stageSequence[scope]
	if current >= uint64(1<<63-1) {
		return 0, fmt.Errorf("API Gateway stage incarnation sequence exhausted")
	}
	next := current + 1
	w.s.stageSequence[scope] = next
	return next, nil
}
