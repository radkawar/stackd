package stepfunctions

import (
	"cmp"
	"fmt"
)

// Key orders equal-deadline work consistently in every repository. Frame IDs are
// nonnegative sequence numbers; fixed-width encoding preserves numeric order.
func (w WorkRecord) Key() string {
	scope := w.Execution.Scope
	if w.Kind == WorkMachineDelete {
		scope = w.Machine.Scope
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%020d|%s", w.Kind, scope.Partition, scope.AccountID, scope.Region, w.Machine.Name, w.Execution.ARN, w.FrameID, w.TaskID)
}

func CompareWork(a, b WorkRecord) int {
	if order := a.Due.Compare(b.Due); order != 0 {
		return order
	}
	return cmp.Compare(a.Key(), b.Key())
}
