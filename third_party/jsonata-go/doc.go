// Package jsonata provides a pure-Go implementation of the JSONata 2.2
// expression language, compatible with jsonata-js v2.2.2.
//
// Compile creates an immutable expression that can be evaluated repeatedly.
// The compatibility API is designed around Compile, MustCompile, Expr.Eval,
// Expr.EvalBytes, RegisterExts, RegisterVars, and Extension. EvalWithOptions,
// EvalContext, and Engine provide context-aware and instance-scoped evaluation
// with per-call bindings and resource limits.
//
// Evaluation accepts ordinary Go JSON values and returns ordinary Go JSON
// values. Inputs, bindings, and extension results are normalized and copied
// for evaluation; cyclic or unsupported values return an error. Compiled
// expressions and engines are safe for concurrent use, but extension code must
// provide its own synchronization for shared state.
//
// The package follows semantic versioning. The JSONata language baseline is
// jsonata-js v2.2.2; the exact reference revision used for conformance is
// recorded by the conformance report.
package jsonata
