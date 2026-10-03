// Package jtypes contains the small reflection-facing compatibility surface
// used by JSONata extension functions.
package jtypes

import (
	"errors"
	"reflect"
)

var (
	TypeOptional    = reflect.TypeOf((*Optional)(nil)).Elem()
	TypeCallable    = reflect.TypeOf((*Callable)(nil)).Elem()
	TypeConvertible = reflect.TypeOf((*Convertible)(nil)).Elem()
	TypeVariant     = reflect.TypeOf((*Variant)(nil)).Elem()
	TypeValue       = reflect.TypeOf((*reflect.Value)(nil)).Elem()
	TypeInterface   = reflect.TypeOf((*interface{})(nil)).Elem()
)

// ErrUndefined identifies an omitted or empty JSONata value.
var ErrUndefined = errors.New("undefined")

// Variant describes a value that can be represented by one of several Go
// types.
type Variant interface {
	ValidTypes() []reflect.Type
}

// Callable is the function shape exposed to extension implementations.
type Callable interface {
	Name() string
	ParamCount() int
	Call([]reflect.Value) (reflect.Value, error)
}

// Convertible allows an extension value to provide a requested reflection
// representation.
type Convertible interface {
	ConvertTo(reflect.Type) (reflect.Value, bool)
}

// Optional is implemented by optional extension-function arguments.
type Optional interface {
	IsSet() bool
	Set(reflect.Value)
	Type() reflect.Type
}

type optionalState bool

func (state *optionalState) IsSet() bool { return bool(*state) }

// OptionalBool is an optional bool argument.
type OptionalBool struct {
	optionalState
	Bool bool
}

func NewOptionalBool(value bool) OptionalBool {
	var option OptionalBool
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalBool) Set(value reflect.Value) {
	option.optionalState = true
	option.Bool = value.Bool()
}

func (*OptionalBool) Type() reflect.Type { return reflect.TypeOf(false) }

// OptionalInt is an optional int argument.
type OptionalInt struct {
	optionalState
	Int int
}

func NewOptionalInt(value int) OptionalInt {
	var option OptionalInt
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalInt) Set(value reflect.Value) {
	option.optionalState = true
	option.Int = int(value.Int())
}

func (*OptionalInt) Type() reflect.Type { return reflect.TypeOf(0) }

// OptionalFloat64 is an optional float64 argument.
type OptionalFloat64 struct {
	optionalState
	Float64 float64
}

func NewOptionalFloat64(value float64) OptionalFloat64 {
	var option OptionalFloat64
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalFloat64) Set(value reflect.Value) {
	option.optionalState = true
	option.Float64 = value.Float()
}

func (*OptionalFloat64) Type() reflect.Type { return reflect.TypeOf(float64(0)) }

// OptionalString is an optional string argument.
type OptionalString struct {
	optionalState
	String string
}

func NewOptionalString(value string) OptionalString {
	var option OptionalString
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalString) Set(value reflect.Value) {
	option.optionalState = true
	if !value.IsValid() || value.Kind() != reflect.String {
		panic("optional string requires a string value")
	}
	option.String = value.String()
}

func (*OptionalString) Type() reflect.Type { return reflect.TypeOf("") }

// OptionalInterface is an optional interface{} argument.
type OptionalInterface struct {
	optionalState
	Interface interface{}
}

func NewOptionalInterface(value interface{}) OptionalInterface {
	var option OptionalInterface
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalInterface) Set(value reflect.Value) {
	option.optionalState = true
	option.Interface = value.Interface()
}

func (*OptionalInterface) Type() reflect.Type { return TypeInterface }

// OptionalValue is an optional reflect.Value argument.
type OptionalValue struct {
	optionalState
	Value reflect.Value
}

func NewOptionalValue(value reflect.Value) OptionalValue {
	var option OptionalValue
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalValue) Set(value reflect.Value) {
	option.optionalState = true
	option.Value = value.Interface().(reflect.Value)
}

func (*OptionalValue) Type() reflect.Type { return TypeValue }

// OptionalCallable is an optional Callable argument.
type OptionalCallable struct {
	optionalState
	Callable Callable
}

func NewOptionalCallable(value Callable) OptionalCallable {
	var option OptionalCallable
	option.Set(reflect.ValueOf(value))
	return option
}

func (option *OptionalCallable) Set(value reflect.Value) {
	option.optionalState = true
	option.Callable = nil
	option.Callable = value.Interface().(Callable)
}

func (*OptionalCallable) Type() reflect.Type { return TypeCallable }

// ArgHandler is a predicate over evaluated function arguments.
type ArgHandler func([]reflect.Value) bool

func ArgCountEquals(count int) ArgHandler {
	return func(arguments []reflect.Value) bool {
		return len(arguments) == count
	}
}

func ArgUndefined(index int) ArgHandler {
	return func(arguments []reflect.Value) bool {
		return index >= 0 && index < len(arguments) && !arguments[index].IsValid()
	}
}

func isSignedInteger(kind reflect.Kind) bool {
	return kind >= reflect.Int && kind <= reflect.Int64
}
