package appsync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/evanw/esbuild/pkg/api"
	"github.com/google/uuid"
)

const mappingDeadline = time.Second

var mappingUtilityProgram = goja.MustCompile("appsync-utils.js", mappingUtilities, true)

// Programs contain no VM state. Bound the cache so customer code churn cannot
// retain an unbounded catalog, while request/response phases reuse compilation.
var mappingPrograms = struct {
	sync.Mutex
	programs map[string]*goja.Program
	order    [128]string
	next     int
}{programs: make(map[string]*goja.Program, 128)}

func compileMapping(code string) (*goja.Program, error) {
	mappingPrograms.Lock()
	program := mappingPrograms.programs[code]
	mappingPrograms.Unlock()
	if program != nil {
		return program, nil
	}
	compiled := api.Transform(code, api.TransformOptions{
		Loader: api.LoaderJS, Format: api.FormatCommonJS, Target: api.ES2020,
		Sourcefile: "resolver.js", LogLevel: api.LogLevelSilent,
	})
	if len(compiled.Errors) != 0 {
		return nil, mappingFailure(compiled.Errors[0].Text)
	}
	program, err := goja.Compile("resolver.js", string(compiled.Code), true)
	if err != nil {
		return nil, mappingFailure(err.Error())
	}
	mappingPrograms.Lock()
	defer mappingPrograms.Unlock()
	if existing := mappingPrograms.programs[code]; existing != nil {
		return existing, nil
	}
	delete(mappingPrograms.programs, mappingPrograms.order[mappingPrograms.next])
	mappingPrograms.order[mappingPrograms.next] = code
	mappingPrograms.next = (mappingPrograms.next + 1) % len(mappingPrograms.order)
	mappingPrograms.programs[code] = program
	return program, nil
}

// TODO: Comeback: enforce AppSync's narrower JavaScript syntax/builtin restrictions;
// the sandbox currently executes a broader ECMAScript subset through goja.
// ValidateMapping checks the actual module and its two executable entry points.
// VTL is deliberately not translated: the repository has no Velocity engine.
func ValidateMapping(code string) error {
	_, err := runMapping(context.Background(), code, "validate", map[string]any{})
	return err
}

func runMapping(ctx context.Context, code, phase string, state map[string]any) (out any, err error) {
	// Accessors on module exports and stash are customer code too. goja's Go-side
	// object access may raise an exception rather than returning one.
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(error); ok {
				out, err = nil, mappingException(failure)
			} else {
				panic(recovered)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(code) > 32768 {
		return nil, mappingFailure("Resolver code exceeds 32768 bytes")
	}
	program, err := compileMapping(code)
	if err != nil {
		return nil, err
	}
	vm := goja.New()
	vm.SetMaxCallStackSize(256)
	ctx, cancel := context.WithTimeout(ctx, mappingDeadline)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { vm.Interrupt(ctx.Err()) })
	defer stop()

	throw := func(err error) { panic(vm.NewGoError(err)) }
	set := func(name string, v any) {
		if err := vm.Set(name, v); err != nil {
			panic(err)
		}
	}
	set("__fail", func(message, kind string, data goja.Value) {
		throw(&MappingError{Message: message, Type: kind, Data: data.Export()})
	})
	set("__appendError", func(message, kind string, data goja.Value) {
		errors, _ := state["__errors"].([]MappingError)
		state["__errors"] = append(errors, MappingError{Message: message, Type: kind, Data: data.Export()})
	})
	set("__earlyReturn", func(v goja.Value, skipTo string) { throw(&EarlyReturn{Value: v.Export(), SkipTo: skipTo}) })
	set("__uuid", uuid.NewString)
	set("__base64Encode", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) })
	set("__base64Decode", func(s string) string {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			throw(mappingFailure("Invalid base64 value"))
		}
		return string(b)
	})
	set("__urlEncode", url.QueryEscape)
	set("__urlDecode", func(s string) string {
		v, err := url.QueryUnescape(s)
		if err != nil {
			throw(mappingFailure(err.Error()))
		}
		return v
	})
	set("__now", func(format string) any {
		now, ok := state["__now"].(time.Time)
		if !ok {
			throw(mappingFailure("Resolver clock is unavailable"))
		}
		switch format {
		case "seconds":
			return now.Unix()
		case "milliseconds":
			return now.UnixMilli()
		default:
			return now.UTC().Format(time.RFC3339Nano)
		}
	})
	if _, err := vm.RunProgram(mappingUtilityProgram); err != nil {
		return nil, mappingException(err)
	}
	set("require", func(name string) goja.Value {
		switch name {
		case "@aws-appsync/utils":
			return vm.Get("__utils")
		case "@aws-appsync/utils/dynamodb":
			return vm.Get("__dynamodb")
		default:
			throw(&MappingError{Message: "Unsupported AppSync module: " + name, Type: "UnsupportedOperation"})
			return goja.Undefined()
		}
	})
	module := vm.NewObject()
	if err := module.Set("exports", vm.NewObject()); err != nil {
		return nil, err
	}
	set("module", module)
	set("exports", module.Get("exports"))
	if _, err = vm.RunProgram(program); err != nil {
		return nil, mappingException(err)
	}
	exports := module.Get("exports").ToObject(vm)
	for _, name := range []string{"request", "response"} {
		if _, ok := goja.AssertFunction(exports.Get(name)); !ok {
			return nil, mappingFailure("Resolver must export function " + name)
		}
	}
	if phase == "validate" {
		return nil, nil
	}
	if phase != "request" && phase != "response" {
		return nil, mappingFailure("Unknown resolver phase: " + phase)
	}

	// JSON creates native JavaScript objects and arrays, not reflected Go slices.
	// Only public context is visible; stash is exported even on a raised error.
	public := make(map[string]any, len(state))
	for k, v := range state {
		if !strings.HasPrefix(k, "__") {
			public[k] = v
		}
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		return nil, mappingFailure("Unable to encode resolver context: " + err.Error())
	}
	parse, _ := goja.AssertFunction(vm.Get("JSON").ToObject(vm).Get("parse"))
	contextValue, err := parse(goja.Undefined(), vm.ToValue(string(encoded)))
	if err != nil {
		return nil, mappingException(err)
	}
	object := contextValue.ToObject(vm)
	if v := object.Get("arguments"); v != nil && !goja.IsUndefined(v) {
		_ = object.Set("args", v)
	}
	if v := object.Get("stash"); v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		_ = object.Set("stash", vm.NewObject())
	}
	fn, _ := goja.AssertFunction(exports.Get(phase))
	result, callErr := fn(goja.Undefined(), contextValue)
	// Export may invoke user-defined getters. Keep the interrupt armed throughout.
	export, exportErr := vm.RunString("(function(value) { return JSON.stringify(value); })")
	if exportErr != nil {
		return nil, mappingException(exportErr)
	}
	stringify, _ := goja.AssertFunction(export)
	stash, stashErr := stringify(goja.Undefined(), object.Get("stash"))
	if stashErr == nil && !goja.IsUndefined(stash) {
		var retained map[string]any
		if err := json.Unmarshal([]byte(stash.String()), &retained); err == nil {
			state["stash"] = retained
		} else {
			stashErr = err
		}
	}
	if callErr != nil {
		return nil, mappingException(callErr)
	}
	if stashErr != nil {
		return nil, mappingFailure("Invalid resolver stash: " + stashErr.Error())
	}
	if result == nil || goja.IsUndefined(result) || goja.IsNull(result) {
		return nil, nil
	}
	if result.ExportType() == reflect.TypeFor[*goja.Promise]() {
		return nil, &MappingError{Message: "Asynchronous resolver results are not supported", Type: "UnsupportedOperation"}
	}
	serialized, err := stringify(goja.Undefined(), result)
	if err != nil {
		return nil, mappingException(err)
	}
	if goja.IsUndefined(serialized) {
		return nil, mappingFailure("Resolver returned a non-JSON value")
	}
	if err := json.Unmarshal([]byte(serialized.String()), &out); err != nil {
		return nil, mappingFailure(err.Error())
	}
	return out, nil
}

func mappingFailure(message string) *MappingError {
	return &MappingError{Message: message, Type: "MappingTemplate"}
}

func mappingException(err error) error {
	var mapped *MappingError
	var early *EarlyReturn
	if errors.As(err, &mapped) {
		return mapped
	}
	if errors.As(err, &early) {
		return early
	}
	var interrupted *goja.InterruptedError
	if errors.As(err, &interrupted) {
		return &MappingError{Message: "Resolver execution cancelled or exceeded its time limit", Type: "ExecutionTimeout"}
	}
	return mappingFailure(fmt.Sprint(err))
}
