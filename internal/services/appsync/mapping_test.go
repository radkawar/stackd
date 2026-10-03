package appsync

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMappingPipelineStashAndRealResponse(t *testing.T) {
	code := `import {util} from '@aws-appsync/utils';
export function request(ctx) {
  ctx.stash.names = [ctx.arguments.name];
  ctx.stash.names.push(ctx.args.name.toUpperCase());
  return {payload: {name: ctx.args.name, previous: ctx.prev.result}};
}
export function response(ctx) {
  if (ctx.error) util.error(ctx.error.message, ctx.error.type);
  return {name: ctx.result.name + '!', names: ctx.stash.names, when: util.time.nowEpochSeconds()};
}`
	state := map[string]any{"arguments": map[string]any{"name": "Ada"}, "stash": map[string]any{}, "prev": map[string]any{"result": "before"}, "__now": time.Unix(12345, 0)}
	request, err := runMapping(t.Context(), code, "request", state)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"payload": map[string]any{"name": "Ada", "previous": "before"}}; !reflect.DeepEqual(request, want) {
		t.Fatalf("request = %#v, want %#v", request, want)
	}
	state["result"] = map[string]any{"name": "stored"}
	result, err := runMapping(t.Context(), code, "response", state)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"name": "stored!", "names": []any{"Ada", "ADA"}, "when": float64(12345)}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("response = %#v, want %#v", result, want)
	}
}

func TestMappingErrorsAndEarlyReturnRetainStash(t *testing.T) {
	for _, test := range []struct {
		name, request string
		early         bool
	}{
		{"error", `ctx.stash.wrote = true; util.error('denied', 'Denied', {id: 7});`, false},
		{"early", `ctx.stash.wrote = true; runtime.earlyReturn({id: 7}, {skipTo: 'NEXT'});`, true},
		{"early-default", `ctx.stash.wrote = true; runtime.earlyReturn({id: 7});`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := map[string]any{"stash": map[string]any{}}
			_, err := runMapping(t.Context(), `export function request(ctx){`+test.request+`} export function response(ctx){return ctx.result;}`, "request", state)
			if test.early {
				var early *EarlyReturn
				if !errors.As(err, &early) || early.SkipTo != "NEXT" {
					t.Fatalf("early return = %#v, error = %v", early, err)
				}
				data, marshalErr := json.Marshal(early.Value)
				if marshalErr != nil || string(data) != `{"id":7}` {
					t.Fatalf("early return data = %s, error = %v", data, marshalErr)
				}
			} else {
				var failure *MappingError
				if !errors.As(err, &failure) || failure.Message != "denied" || failure.Type != "Denied" {
					t.Fatalf("mapping error = %#v, error = %v", failure, err)
				}
				data, marshalErr := json.Marshal(failure.Data)
				if marshalErr != nil || string(data) != `{"id":7}` {
					t.Fatalf("error data = %s, error = %v", data, marshalErr)
				}
			}
			if !reflect.DeepEqual(state["stash"], map[string]any{"wrote": true}) {
				t.Fatalf("stash lost on control transfer: %#v", state["stash"])
			}
		})
	}
}

func TestMappingAppendedErrorDoesNotDiscardResult(t *testing.T) {
	state := map[string]any{"result": "partial"}
	result, err := runMapping(t.Context(), `import {util} from '@aws-appsync/utils'; export function request(ctx){return {}} export function response(ctx){util.appendError('one failed','Partial',{key:'one'});return ctx.result;}`, "response", state)
	if err != nil || result != "partial" {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	failures, ok := state["__errors"].([]MappingError)
	if !ok || len(failures) != 1 || failures[0].Type != "Partial" || failures[0].Message != "one failed" {
		t.Fatalf("appended errors = %#v", state["__errors"])
	}
}

func TestMappingUnsupportedModulesHelpersAndAsync(t *testing.T) {
	for _, code := range []string{
		`import fs from 'node:fs'; export function request(){return fs.readFileSync('/etc/passwd')} export function response(ctx){return ctx.result}`,
		`import {util} from '@aws-appsync/utils'; export function request(){return util.someMissingUtility()} export function response(ctx){return ctx.result}`,
		`export async function request(){return {payload:'not synchronous'}} export function response(ctx){return ctx.result}`,
	} {
		_, err := runMapping(t.Context(), code, "request", map[string]any{})
		var failure *MappingError
		if !errors.As(err, &failure) || failure.Type != "UnsupportedOperation" {
			t.Fatalf("unsupported resolver error = %#v (%v)", failure, err)
		}
	}
}

func TestMappingCancellationInterruptsCustomerLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := runMapping(ctx, `export function request(){while(true){}} export function response(ctx){return ctx.result}`, "request", map[string]any{})
	var failure *MappingError
	if !errors.As(err, &failure) || failure.Type != "ExecutionTimeout" {
		t.Fatalf("loop cancellation = %v", err)
	}
}

func TestMappingDynamoDBNativeTypeBoundary(t *testing.T) {
	result, err := runMapping(t.Context(), `import {put} from '@aws-appsync/utils/dynamodb'; export function request(ctx){return put({key:{id:'one'},item:{count:2,active:true,list:[null,'x']},condition:{id:{attributeExists:false}}})} export function response(ctx){return ctx.result}`, "request", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	request := result.(map[string]any)
	if request["operation"] != "PutItem" {
		t.Fatalf("operation = %#v", request)
	}
	want := map[string]any{"count": map[string]any{"N": "2"}, "active": map[string]any{"BOOL": true}, "list": map[string]any{"L": []any{map[string]any{"NULL": true}, map[string]any{"S": "x"}}}}
	if !reflect.DeepEqual(request["attributeValues"], want) {
		t.Fatalf("DynamoDB values = %#v", request["attributeValues"])
	}
	state := map[string]any{"result": map[string]any{"count": float64(2)}}
	response, err := runMapping(t.Context(), `export function request(ctx){return {}} export function response(ctx){return ctx.result.count+1}`, "response", state)
	if err != nil || response != float64(3) {
		t.Fatalf("native response arithmetic = %#v, %v", response, err)
	}
}
