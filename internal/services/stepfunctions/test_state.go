package stepfunctions

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awscatalog"
	"stackd/internal/services/stepfunctions/asl"
)

// compileTestState wraps a single state without rewriting its definition. The
// ordinary ASL compiler still owns schema validation, paths and expressions.
// Synthetic terminal targets allow inspection of Next without executing it.
func compileTestState(in *api.TestStateInput) (*asl.State, string, []*asl.State, error) {
	if err := definitionInput(in.Definition); err != nil {
		return nil, "", nil, err
	}
	source, name := value(in.Definition), value(in.StateName)
	if in.StateName != nil {
		definition, err := admitDefinition(in.Definition, "STANDARD")
		if err != nil {
			return nil, "", nil, err
		}
		state, parents := findTestState(definition, name)
		if state == nil {
			return nil, "", nil, invalid("stateName must identify a state in the supplied definition.")
		}
		return state, source, parents, nil
	}
	name = "StateName"
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(source), &object); err != nil || object == nil {
		return nil, "", nil, failure("InvalidDefinition", "Invalid State Machine Definition: state must be a JSON object.", 400)
	}
	if _, isMachine := object["States"]; isMachine {
		return nil, "", nil, invalid("stateName is required when definition is a state machine.")
	}
	targets := map[string]json.RawMessage{}
	var collectTargets func(map[string]json.RawMessage)
	collectTargets = func(node map[string]json.RawMessage) {
		for _, field := range []string{"Next", "Default"} {
			var target string
			if json.Unmarshal(node[field], &target) == nil && target != "" && target != name {
				targets[target] = json.RawMessage(`{"Type":"Succeed"}`)
			}
		}
		for _, field := range []string{"Choices", "Catch"} {
			var rules []map[string]json.RawMessage
			if json.Unmarshal(node[field], &rules) == nil {
				for _, rule := range rules {
					collectTargets(rule)
				}
			}
		}
	}
	collectTargets(object)
	targets[name] = json.RawMessage(source)
	states, err := json.Marshal(targets)
	if err != nil {
		return nil, "", nil, err
	}
	source = `{"StartAt":"StateName","States":` + string(states) + `}`
	definition, err := admitDefinition(new(api.Definition(source)), "STANDARD")
	if err != nil {
		return nil, "", nil, err
	}
	return definition.States[name], source, nil, nil
}

func findTestState(definition *asl.Definition, name string) (*asl.State, []*asl.State) {
	if state := definition.States[name]; state != nil {
		return state, nil
	}
	for _, parent := range definition.States {
		if parent.Map != nil {
			if state, parents := findTestState(parent.Map.Processor, name); state != nil {
				return state, append([]*asl.State{parent}, parents...)
			}
		}
		if parent.Parallel != nil {
			for _, scope := range parent.Parallel.Branches {
				if state, parents := findTestState(scope, name); state != nil {
					return state, append([]*asl.State{parent}, parents...)
				}
			}
		}
	}
	return nil, nil
}

func (s *Service) testState(ctx context.Context, in *api.TestStateInput) (*api.TestStateOutput, error) {
	state, source, parents, err := compileTestState(in)
	if err != nil {
		return nil, err
	}
	level := value(in.InspectionLevel)
	if in.InspectionLevel == nil {
		level = "INFO"
	}
	if level != "INFO" && level != "DEBUG" && level != "TRACE" {
		return nil, invalid("inspectionLevel must be INFO, DEBUG, or TRACE.")
	}
	if in.Context != nil && in.Mock == nil {
		return nil, invalid("context can only be specified with a mock.")
	}
	if in.Mock == nil && (state.Type == asl.Map || state.Type == asl.Parallel) {
		return nil, invalid("Map and Parallel states require a mock in TestState.")
	}
	var mockResult any
	if in.Mock != nil {
		if state.Type != asl.Task && state.Type != asl.Map && state.Type != asl.Parallel {
			return nil, invalid("A mock can only be specified for Task, Map, or Parallel states.")
		}
		if in.RevealSecrets != nil && bool(*in.RevealSecrets) {
			return nil, invalid("revealSecrets cannot be enabled with a mock.")
		}
		mockResult, err = validateStateMock(state, in.Mock)
		if err != nil {
			return nil, err
		}
	}
	if state.Task != nil {
		resource := state.Task.Resource
		if in.Mock == nil && strings.Contains(resource, ":activity:") {
			return nil, invalid("Activity tasks require a mock in TestState.")
		}
		if in.Mock == nil && (strings.HasSuffix(resource, ".sync") || strings.HasSuffix(resource, ".sync:2") || strings.HasSuffix(resource, ".waitForTaskToken")) {
			return nil, failure("InvalidDefinition", "TestState API does not support '.sync' or '.waitForTaskToken' integration patterns.", 400)
		}
		if in.Mock == nil && in.RoleArn == nil {
			return nil, invalid("roleArn is required when testing a Task state.")
		}
	}
	input, err := executionInput(in.Input)
	if err != nil {
		return nil, err
	}
	variables := "{}"
	if in.Variables != nil {
		variables = string(*in.Variables)
		var bindings map[string]json.RawMessage
		if len(variables) > executionDataLimit || !utf8.ValidString(variables) || json.Unmarshal([]byte(variables), &bindings) != nil || bindings == nil {
			return nil, invalid("variables must be a JSON object no larger than 262144 bytes.")
		}
	}
	if in.StateConfiguration != nil {
		config := in.StateConfiguration
		if config.RetrierRetryCount != nil && *config.RetrierRetryCount < 0 {
			return nil, invalid("retrierRetryCount must not be negative.")
		}
		if config.MapIterationFailureCount != nil && *config.MapIterationFailureCount < 0 {
			return nil, invalid("mapIterationFailureCount must not be negative.")
		}
		if (config.MapItemReaderData != nil || config.MapIterationFailureCount != nil) && state.Map == nil {
			return nil, invalid("Map configuration requires a Map state.")
		}
		if config.ErrorCausedByState != nil && (in.Mock == nil || in.Mock.ErrorOutput == nil || state.Map == nil && state.Parallel == nil) {
			return nil, invalid("errorCausedByState requires a mocked error for a Map or Parallel state.")
		}
	}
	failureState, failureParents := state, parents
	if in.StateConfiguration != nil && in.StateConfiguration.ErrorCausedByState != nil {
		var nestedParents []*asl.State
		failureState, nestedParents = findTestState(&asl.Definition{States: map[string]*asl.State{state.Name: state}}, string(*in.StateConfiguration.ErrorCausedByState))
		if failureState == nil || failureState == state {
			return nil, invalid("errorCausedByState must identify a child state of the tested Map or Parallel.")
		}
		failureParents = append(append([]*asl.State(nil), parents...), nestedParents...)
	}
	scope, id := scopeFor(ctx), uuid.NewString()
	machine := MachineKey{Scope: scope, Name: uuid.NewString()}
	err = s.repository.View(ctx, func(r Reader) error {
		if rejected := s.authorize(r, "TestState", "*", nil, nil); rejected != nil {
			return rejected
		}
		if in.RevealSecrets != nil && bool(*in.RevealSecrets) {
			if rejected := s.authorize(r, "RevealSecrets", "*", nil, nil); rejected != nil {
				return rejected
			}
		}
		if in.RoleArn != nil {
			return s.passRole(r, value(in.RoleArn), machine)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	now := s.clock.Now().UTC()
	execution := ExecutionRecord{
		Key:     ExecutionKey{Scope: scope, ARN: "arn:" + scope.Partition + ":states:" + scope.Region + ":" + scope.AccountID + ":express:" + machine.Name + ":" + id},
		Machine: machine, MachineID: machine.Name, RevisionID: id, Name: id, Type: "EXPRESS", Input: input,
		Started: now, Deadline: now.Add(5 * time.Minute), ParentEventID: apievents.EventID(ctx), Status: "RUNNING",
	}
	revision := RevisionRecord{Key: RevisionKey{Scope: scope, ID: id}, Machine: machine, MachineID: machine.Name, Definition: source, RoleARN: value(in.RoleArn)}
	frame := FrameRecord{Key: FrameKey{Execution: execution.Key, ID: 1}, StateName: "StateName", Input: input, Variables: variables, Entered: now, Phase: FrameReady}
	env, err := evaluationEnvironment(execution, revision, frame, state, now)
	if err != nil {
		return nil, err
	}
	if in.RoleArn == nil {
		env.ContextObject["Execution"].(map[string]any)["RoleArn"] = nil
	}
	if in.Context != nil {
		var configured map[string]any
		if len(*in.Context) > executionDataLimit || !utf8.ValidString(string(*in.Context)) || json.Unmarshal([]byte(*in.Context), &configured) != nil || configured == nil {
			return nil, invalid("context must be a JSON object no larger than 262144 bytes.")
		}
		env.ContextObject = configured
	}
	out := &api.TestStateOutput{Status: new(api.TestExecutionStatus("SUCCEEDED"))}
	var inspect stateInspection
	if level != "INFO" {
		out.InspectionData = &api.InspectionData{Input: new(api.SensitiveData(input))}
		inspect = func(stage string, data any) error {
			if state.Map != nil {
				if stage == "afterParameters" || stage == "afterItemSelector" && state.Map.ItemSelector == nil || stage == "afterItemBatcher" && state.Map.ItemBatcher == nil {
					return nil
				}
				if stage == "afterItemBatcher" {
					// Native inspection represents each batch item as JSON text;
					// the shared runtime batch remains an ordinary JSON value.
					batches := data.([]any)
					projected := make([]any, len(batches))
					for i, value := range batches {
						batch := value.(map[string]any)
						copy := make(map[string]any, len(batch))
						for key, value := range batch {
							copy[key] = value
						}
						items := batch["Items"].([]any)
						texts := make([]string, len(items))
						for j, item := range items {
							var err error
							texts[j], err = encodeExecutionData(item)
							if err != nil {
								return err
							}
						}
						copy["Items"], projected[i] = texts, copy
					}
					data = projected
				}
			}
			encoded, err := json.Marshal(data)
			if err != nil {
				return err
			}
			field := new(api.SensitiveData(encoded))
			switch stage {
			case "afterInputPath":
				out.InspectionData.AfterInputPath = field
			case "afterParameters":
				out.InspectionData.AfterParameters = field
			case "afterArguments":
				out.InspectionData.AfterArguments = field
			case "afterResultSelector":
				out.InspectionData.AfterResultSelector = field
			case "afterResultPath":
				out.InspectionData.AfterResultPath = field
			case "result":
				out.InspectionData.Result = field
			case "variables":
				out.InspectionData.Variables = field
			case "afterItemsPath", "afterItems":
				out.InspectionData.AfterItemsPath = field
			case "afterItemsPointer":
				out.InspectionData.AfterItemsPointer = field
			case "afterItemSelector":
				if state.Map != nil && state.Map.ItemSelector != nil {
					out.InspectionData.AfterItemSelector = field
				}
			case "afterItemBatcher":
				if state.Map != nil && state.Map.ItemBatcher != nil {
					out.InspectionData.AfterItemBatcher = field
				}
			}
			return nil
		}
	}
	var evaluated stateEvaluation
	if in.Mock != nil {
		evaluated, err = s.evaluateMockState(ctx, state, env, in, mockResult, out.InspectionData, inspect)
		env.HasResult, env.Result = err == nil && evaluated.Failure == nil, evaluated.Result
	} else if state.Type == asl.Task {
		evaluated = stateEvaluation{Next: state.Next, Assign: state.Assign, Output: state.Output}
		var task TaskRecord
		task, err = prepareTask(ctx, state, env, execution, revision, frame, now, inspect)
		if err == nil {
			var outcome TaskOutcome
			outcome, err = s.runTestTask(ctx, execution, revision, task)
			if err == nil {
				if outcome.Error != "" {
					evaluated.Failure = &asl.EvaluationError{Name: outcome.Error, Cause: outcome.Cause}
				} else {
					err = json.Unmarshal([]byte(outcome.Output), &evaluated.Result)
					if err == nil {
						err = inspectState([]stateInspection{inspect}, "result", evaluated.Result)
					}
					env.HasResult, env.Result = true, evaluated.Result
				}
			}
		}
	} else {
		evaluated, err = evaluateState(ctx, state, env, now, inspect)
		if err == nil && evaluated.Due != nil {
			err = s.waitTestState(ctx, *evaluated.Due, execution.Deadline)
		}
	}
	if err == nil && evaluated.Failure != nil {
		err = evaluated.Failure
	}
	if err == nil {
		var output string
		output, _, err = stateOutput(ctx, state, env, evaluated.Result, evaluated.Assign, evaluated.Output, inspect)
		if err == nil {
			out.Output = new(api.SensitiveData(output))
			if evaluated.Next != "" {
				out.NextState = new(api.StateName(evaluated.Next))
			}
		}
	}
	if err != nil {
		var failed *asl.EvaluationError
		if !errors.As(err, &failed) {
			return nil, err
		}
		out.Status = new(api.TestExecutionStatus("FAILED"))
		if failed.Name != "" {
			out.Error = new(api.SensitiveError(failed.Name))
		}
		if failed.Cause != "" {
			out.Cause = new(api.SensitiveCause(failed.Cause))
		}
		handlers := append(append([]*asl.State(nil), failureParents...), failureState)
		for i := len(handlers) - 1; i >= 0; i-- {
			if catchErr := testStateFailure(ctx, handlers[i], env, in.StateConfiguration, failed, out, inspect); catchErr != nil {
				if !errors.As(catchErr, &failed) {
					return nil, catchErr
				}
				out.Status = new(api.TestExecutionStatus("FAILED"))
				out.Error, out.Cause = new(api.SensitiveError(failed.Name)), new(api.SensitiveCause(failed.Cause))
				out.Output, out.NextState = nil, nil
			}
			if value(out.Status) != "FAILED" {
				break
			}
		}
	}
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	err = s.repository.Attempt(completion, func(tx Transaction) error { return s.recordCall(tx.Context(), "TestState", in, out, nil) })
	return out, err
}

func testStateFailure(ctx context.Context, state *asl.State, env asl.Environment, config *api.TestStateConfiguration, failed *asl.EvaluationError, out *api.TestStateOutput, inspect stateInspection) error {
	var count int64
	if config != nil && config.RetrierRetryCount != nil {
		count = int64(*config.RetrierRetryCount)
	}
	for i, retrier := range state.Retry {
		if !matchesStateError(retrier.ErrorEquals, failed.Name) {
			continue
		}
		if count >= retrier.MaxAttempts {
			break
		}
		due, err := retryDue(retrier, count, env, env.Now, env.Now.Add(time.Duration(1<<31-1)*time.Second))
		if err != nil {
			return err
		}
		out.Status = new(api.TestExecutionStatus("RETRIABLE"))
		if out.InspectionData != nil {
			out.InspectionData.ErrorDetails = &api.InspectionErrorDetails{
				RetryIndex:                  new(api.ExceptionHandlerIndex(i)),
				RetryBackoffIntervalSeconds: new(api.RetryBackoffIntervalSeconds(due.Sub(env.Now) / time.Second)),
			}
		}
		return nil
	}
	for i, catcher := range state.Catch {
		if !matchesStateError(catcher.ErrorEquals, failed.Name) {
			continue
		}
		output, _, err := evaluateCatch(ctx, state, env, catcher, failed.Name, failed.Cause, inspect)
		if err != nil {
			return err
		}
		out.Status = new(api.TestExecutionStatus("CAUGHT_ERROR"))
		out.Output, out.NextState = new(api.SensitiveData(output)), new(api.StateName(catcher.Next))
		if out.InspectionData != nil {
			out.InspectionData.ErrorDetails = &api.InspectionErrorDetails{CatchIndex: new(api.ExceptionHandlerIndex(i))}
		}
		return nil
	}
	return nil
}

func (s *Service) waitTestState(ctx context.Context, due, deadline time.Time) error {
	timeout := !due.Before(deadline)
	if timeout {
		due = deadline
	}
	if due.After(s.clock.Now()) {
		timer := s.clock.NewTimerAt(due)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-timer.C():
		}
	}
	if timeout {
		return &asl.EvaluationError{Name: "States.Timeout", Cause: "The state exceeded its execution timeout."}
	}
	return nil
}

func (s *Service) runTestTask(ctx context.Context, execution ExecutionRecord, revision RevisionRecord, task TaskRecord) (TaskOutcome, error) {
	if s.tasks == nil {
		return TaskOutcome{}, &asl.EvaluationError{Name: "States.TaskFailed", Cause: "No task integration runner is configured."}
	}
	deadline := execution.Deadline
	if task.TimeoutSeconds > 0 {
		if taskDeadline := task.Scheduled.Add(time.Duration(task.TimeoutSeconds) * time.Second); taskDeadline.Before(deadline) {
			deadline = taskDeadline
		}
	}
	runCtx, cancel := context.WithCancel(requestContext(ctx, execution))
	defer cancel()
	timer := s.clock.NewTimerAt(deadline)
	defer timer.Stop()
	finished, monitorDone := make(chan struct{}), make(chan struct{})
	timedOut := false
	go func() {
		defer close(monitorDone)
		select {
		case <-finished:
		case <-runCtx.Done():
		case <-s.ctx.Done():
			cancel()
		case <-timer.C():
			timedOut = true
			cancel()
		}
	}()
	outcome, err := s.tasks.Run(runCtx, task, revision, func(TaskOutcome) error { return errors.New("asynchronous submission is not supported by TestState") })
	close(finished)
	<-monitorDone
	if timedOut || !s.clock.Now().Before(deadline) {
		return TaskOutcome{}, &asl.EvaluationError{Name: "States.Timeout", Cause: "The state exceeded its execution timeout."}
	}
	if ctx.Err() != nil {
		return TaskOutcome{}, ctx.Err()
	}
	if s.ctx.Err() != nil {
		return TaskOutcome{}, s.ctx.Err()
	}
	if err != nil {
		return TaskOutcome{Error: "States.TaskFailed", Cause: err.Error()}, nil
	}
	if outcome.Submitted {
		return TaskOutcome{}, errors.New("TestState task returned an asynchronous outcome")
	}
	return taskOutcomeFailure(outcome, false), nil
}

func validateStateMock(state *asl.State, mock *api.MockInput) (any, error) {
	mode := value(mock.FieldValidationMode)
	if mock.FieldValidationMode == nil {
		mode = "STRICT"
	}
	if mode != "STRICT" && mode != "PRESENT" && mode != "NONE" {
		return nil, invalid("fieldValidationMode must be STRICT, PRESENT, or NONE.")
	}
	if (mock.Result == nil) == (mock.ErrorOutput == nil) {
		return nil, invalid("Exactly one of result or errorOutput is required for a test mock.")
	}
	if mock.ErrorOutput != nil {
		if value(mock.ErrorOutput.Error) == "" {
			return nil, invalid("An error was not specified in the mocked error output.")
		}
		if utf8.RuneCountInString(value(mock.ErrorOutput.Error)) > 256 || utf8.RuneCountInString(value(mock.ErrorOutput.Cause)) > 32768 {
			return nil, invalid("Mock error or cause exceeds its maximum length.")
		}
		return nil, nil
	}
	raw := string(*mock.Result)
	if len(raw) > executionDataLimit || !utf8.ValidString(raw) {
		return nil, invalid("Mocked result must not exceed 262144 UTF-8 bytes.")
	}
	var result any
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, invalid("Mocked result must contain valid JSON.")
	}
	if state.Map != nil || state.Parallel != nil {
		results, array := result.([]any)
		if state.Map != nil && state.Map.ResultWriter != nil {
			if _, ok := result.(map[string]any); !ok {
				return nil, invalid("Mocked ResultWriter result must be an object.")
			}
		} else if !array {
			return nil, invalid("Mocked result must be an array.")
		}
		if state.Parallel != nil && len(results) != len(state.Parallel.Branches) {
			return nil, invalid("Mocked result must contain the same number of items as number of Parallel branches.")
		}
		return result, nil
	}
	if mode == "NONE" {
		return result, nil
	}
	resource := state.Task.Resource
	parts := strings.SplitN(resource, ":", 6)
	if len(parts) != 6 {
		return nil, invalid("Invalid mocked Task resource.")
	}
	if parts[2] == "lambda" || strings.HasPrefix(parts[5], "activity:") {
		return result, nil
	}
	integration := strings.TrimPrefix(parts[5], "aws-sdk:")
	serviceName, action, ok := strings.Cut(integration, ":")
	if !ok {
		return nil, invalid("Invalid mocked Task resource.")
	}
	syncTask := strings.HasSuffix(action, ".sync") || strings.HasSuffix(action, ".sync:2")
	action = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(action, ".waitForTaskToken"), ".sync:2"), ".sync")
	switch serviceName {
	case "http", "apigateway", "eks":
		return result, nil
	case "states", "sfn":
		serviceName = "stepfunctions"
	case "cloudwatchlogs":
		serviceName = "logs"
	}
	if syncTask {
		switch serviceName {
		case "stepfunctions":
			action = "describeExecution"
		case "ecs":
			action = "describeTasks"
		case "batch":
			action = "describeJobs"
		}
	}
	model, ok := awscatalog.LookupService(serviceName)
	if !ok {
		return nil, invalid("The mocked integration has no supported response schema.")
	}
	if action == "" {
		return nil, invalid("Invalid mocked integration operation.")
	}
	operation, ok := model.Operation(strings.ToUpper(action[:1]) + action[1:])
	if !ok || operation.Output == "" {
		return nil, invalid("The mocked integration operation has no supported response schema.")
	}
	if err := awsapi.ValidateSDKMockResult(model, operation.Output, []byte(raw), mode == "STRICT"); err != nil {
		return nil, invalid("Mock result schema validation error: " + err.Error())
	}
	return result, nil
}

type testMapReaderParser interface {
	ParseMapReaderData(context.Context, MapReaderRequest, []byte) (MapReaderOutput, error)
}

func (s *Service) evaluateMockState(ctx context.Context, state *asl.State, env asl.Environment, in *api.TestStateInput, result any, details *api.InspectionData, inspect stateInspection) (stateEvaluation, error) {
	evaluated, err := evaluateState(ctx, state, env, env.Now, inspect)
	if err != nil {
		return evaluated, err
	}
	if state.Map != nil {
		itemEnv := mapInputEnvironment(state, env, evaluated.Arguments)
		var items []any
		var keys, sources []string
		source := ""
		if state.Map.ItemReader != nil {
			if in.StateConfiguration == nil || in.StateConfiguration.MapItemReaderData == nil {
				return evaluated, invalid("ItemReader data must be specified when testing a Map state with ItemReader specified.")
			}
			raw := string(*in.StateConfiguration.MapItemReaderData)
			if len(raw) > executionDataLimit || !utf8.ValidString(raw) {
				return evaluated, invalid("mapItemReaderData must not exceed 262144 UTF-8 bytes.")
			}
			request, err := mapReaderRequest(ctx, state, itemEnv)
			if err != nil {
				return evaluated, err
			}
			parser, ok := s.tasks.(testMapReaderParser)
			if !ok {
				return evaluated, errors.New("the configured task adapter does not provide Map reader parsing")
			}
			read, err := parser.ParseMapReaderData(ctx, request, []byte(raw))
			if err != nil {
				return evaluated, err
			}
			items, keys, sources, source = read.Items, read.Keys, read.Sources, read.Source
			stage := "afterItemsPath"
			if request.ReaderConfig.ItemsPointer != "" {
				stage = "afterItemsPointer"
			}
			if err := inspectState([]stateInspection{inspect}, stage, items); err != nil {
				return evaluated, err
			}
		} else {
			items, keys, err = mapSelectedItems(ctx, state, env, evaluated.Arguments, inspect)
			if err != nil {
				return evaluated, err
			}
		}
		inputs, err := mapItemInputs(ctx, state, itemEnv, items, keys, sources, source, inspect)
		if err != nil {
			return evaluated, err
		}
		maximum, toleratedCount, toleratedPercentage := int64(0), int64(0), float64(0)
		if state.Map.MaxConcurrency != nil {
			maximum, err = state.Map.MaxConcurrency.Evaluate(ctx, itemEnv)
			if err != nil {
				return evaluated, err
			}
		}
		if state.Map.ToleratedFailureCount != nil {
			toleratedCount, err = state.Map.ToleratedFailureCount.Evaluate(ctx, itemEnv)
			if err != nil {
				return evaluated, err
			}
		}
		if state.Map.ToleratedFailurePercentage != nil {
			toleratedPercentage, err = state.Map.ToleratedFailurePercentage.Evaluate(ctx, itemEnv)
			if err != nil {
				return evaluated, err
			}
		}
		if details != nil {
			details.MaxConcurrency = new(api.InspectionMaxConcurrency(maximum))
			if state.Map.ToleratedFailureCount != nil {
				details.ToleratedFailureCount = new(api.InspectionToleratedFailureCount(toleratedCount))
			}
			if state.Map.ToleratedFailurePercentage != nil {
				details.ToleratedFailurePercentage = new(api.InspectionToleratedFailurePercentage(toleratedPercentage))
			}
		}
		var failed int64
		if in.StateConfiguration != nil && in.StateConfiguration.MapIterationFailureCount != nil {
			failed = int64(*in.StateConfiguration.MapIterationFailureCount)
		}
		if failed > int64(len(inputs)) {
			return evaluated, invalid("Map iteration failure count must be less than or equal to the number of Map iterations.")
		}
		if state.Map.ProcessorConfig.Mode == "DISTRIBUTED" && failureThresholdExceeded(state.Map, failed, int64(len(inputs)), toleratedCount, toleratedPercentage) {
			evaluated.Failure = &asl.EvaluationError{Name: "States.ExceedToleratedFailureThreshold", Cause: "The specified tolerated failure threshold was exceeded"}
			return evaluated, nil
		}
		if in.Mock.ErrorOutput == nil && state.Map.ResultWriter == nil && int64(len(result.([]any))) != int64(len(inputs))-failed {
			return evaluated, invalid("Input array does not equal the mocked result array's size.")
		}
	}
	if in.Mock.ErrorOutput != nil {
		evaluated.Failure = &asl.EvaluationError{Name: value(in.Mock.ErrorOutput.Error), Cause: value(in.Mock.ErrorOutput.Cause)}
		return evaluated, nil
	}
	evaluated.Result = result
	if state.Task != nil {
		if err := inspectState([]stateInspection{inspect}, "result", result); err != nil {
			return evaluated, err
		}
	}
	return evaluated, nil
}
