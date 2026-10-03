package jtypes

import "reflect"

// Resolve removes non-nil interface and pointer layers from a value. A nil
// pointer remains a typed, nil pointer so callers can still inspect its type.
func Resolve(value reflect.Value) reflect.Value {
	for value.IsValid() {
		switch value.Kind() {
		case reflect.Interface, reflect.Pointer:
			if value.IsNil() {
				return value
			}
			value = value.Elem()
		default:
			return value
		}
	}
	return value
}

func IsBool(value reflect.Value) bool {
	return kindOf(value) == reflect.Bool
}

func IsString(value reflect.Value) bool {
	return kindOf(value) == reflect.String
}

func IsNumber(value reflect.Value) bool {
	kind := kindOf(value)
	return isFloatKind(kind) || isSignedInteger(kind) || isUnsignedInteger(kind)
}

func IsCallable(value reflect.Value) bool {
	value = Resolve(value)
	if !value.IsValid() {
		return false
	}
	if value.Type().Implements(TypeCallable) {
		return true
	}
	return reflect.PointerTo(value.Type()).Implements(TypeCallable)
}

func IsArray(value reflect.Value) bool {
	kind := value.Kind()
	return isArrayKind(kind) || isArrayKind(kindOf(value))
}

func IsArrayOf(value reflect.Value, predicate func(reflect.Value) bool) bool {
	if !IsArray(value) {
		return false
	}
	value = Resolve(value)
	for index := 0; index < value.Len(); index++ {
		if !predicate(value.Index(index)) {
			return false
		}
	}
	return true
}

func IsMap(value reflect.Value) bool {
	return kindOf(value) == reflect.Map
}

func IsStruct(value reflect.Value) bool {
	return kindOf(value) == reflect.Struct
}

func AsBool(value reflect.Value) (bool, bool) {
	value = Resolve(value)
	if !value.IsValid() || value.Kind() != reflect.Bool {
		return false, false
	}
	return value.Bool(), true
}

func AsString(value reflect.Value) (string, bool) {
	value = Resolve(value)
	if value.IsValid() && value.Kind() == reflect.String {
		return value.String(), true
	}
	return "", false
}

func AsNumber(value reflect.Value) (float64, bool) {
	value = Resolve(value)
	if !value.IsValid() {
		return 0, false
	}
	switch {
	case isFloatKind(value.Kind()):
		return value.Float(), true
	case isSignedInteger(value.Kind()), isUnsignedInteger(value.Kind()):
		converted := value.Convert(reflect.TypeOf(float64(0)))
		return converted.Float(), true
	default:
		return 0, false
	}
}

func AsCallable(value reflect.Value) (Callable, bool) {
	value = Resolve(value)
	if !value.IsValid() {
		return nil, false
	}
	if value.Type().Implements(TypeCallable) && value.CanInterface() {
		return value.Interface().(Callable), true
	}
	if value.CanAddr() && reflect.PointerTo(value.Type()).Implements(TypeCallable) && value.Addr().CanInterface() {
		return value.Addr().Interface().(Callable), true
	}
	return nil, false
}

func kindOf(value reflect.Value) reflect.Kind {
	return Resolve(value).Kind()
}

func isArrayKind(kind reflect.Kind) bool {
	return kind == reflect.Array || kind == reflect.Slice
}

func isFloatKind(kind reflect.Kind) bool {
	return kind == reflect.Float32 || kind == reflect.Float64
}

func isUnsignedInteger(kind reflect.Kind) bool {
	switch kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}
