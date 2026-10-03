package resourcegroups

import "context"

// Resource is a current owner snapshot, never retained as a resource catalog.
// Type is the CloudFormation resource type. Global resources are included only
// when Resource Groups supports them in the caller's regional query.
type Resource struct {
	ARN, Type string
	Tags      map[string]string
	StackOnly bool
	Pending   bool
}

// Stack is the current CloudFormation selection over live owner resources.
// An empty ARN means the stack is absent in the caller's scope; a known deleted
// stack retains its ARN and status, so the query reports the native inactive error.
type Stack struct {
	ARN, Status string
	Resources   []Resource
}

// Resources consumes live typed owner state in the caller's transaction domain.
// The adapter must not apply Tagging API historical membership exclusions.
type Resources interface {
	List(context.Context) ([]Resource, error)
	Stack(context.Context, string) (Stack, error)
}
