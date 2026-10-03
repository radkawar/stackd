package jsonata

import "github.com/tiaanduplessis/jsonata-go/internal/syntax"

// This local bridge is based on github.com/tiaanduplessis/jsonata-go v0.1.0.
// It exposes the canonical compiled syntax for ASL admission checks, avoiding a
// second parser with different syntax support. The evaluator and parser are
// unchanged. Callers must treat the returned tree and its slices as immutable.
func (e *Expr) Syntax() SyntaxNode {
	if e == nil {
		return nil
	}
	return e.node
}

type SyntaxNode = syntax.Node
type SyntaxLiteral = syntax.Literal
type SyntaxName = syntax.Name
type SyntaxVariable = syntax.Variable
type SyntaxPath = syntax.Path
type SyntaxArray = syntax.Array
type SyntaxBlock = syntax.Block
type SyntaxObject = syntax.Object
type SyntaxBinary = syntax.Binary
type SyntaxBind = syntax.Bind
type SyntaxApply = syntax.Apply
type SyntaxUnary = syntax.Unary
type SyntaxSelector = syntax.Selector
type SyntaxWildcard = syntax.Wildcard
type SyntaxParent = syntax.Parent
type SyntaxTransform = syntax.Transform
type SyntaxCall = syntax.Call
type SyntaxPlaceholder = syntax.Placeholder
type SyntaxLambda = syntax.Lambda

const (
	SyntaxVariableNamed = syntax.VariableNamed
	SyntaxVariableFocus = syntax.VariableFocus
	SyntaxVariableRoot  = syntax.VariableRoot
)
