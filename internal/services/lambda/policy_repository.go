package lambda

// FunctionPolicy is independently revisioned state.
// IAM principals in Document use immutable IDs; PrincipalIDs retains their
// bindings for current-ARN rendering without rebinding surviving statements.
type FunctionPolicy struct {
	Key          FunctionReference
	Document     string
	Revision     string
	PrincipalIDs map[string]string
	Owner        FunctionPolicyOwner
}

type PolicyReader interface {
	FunctionPolicy(FunctionReference) (FunctionPolicy, error)
}

type PolicyWriter interface {
	PutFunctionPolicy(FunctionPolicy) error
	DeleteFunctionPolicy(FunctionReference) error
}
