package stepfunctions

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

// MapResultExecution describes an actual retained child execution.
// Type, ItemCount and Generation are adapter bookkeeping, not S3 output.
type MapResultExecution struct {
	ExecutionARN    string     `json:"ExecutionArn"`
	StateMachineARN string     `json:"StateMachineArn"`
	Type            string     `json:"ExecutionType"`
	Name            string     `json:"Name"`
	Status          string     `json:"Status"`
	Input           string     `json:"Input"`
	Output          string     `json:"Output,omitempty"`
	Error           string     `json:"Error,omitempty"`
	Cause           string     `json:"Cause,omitempty"`
	Started         time.Time  `json:"StartDate"`
	Stopped         *time.Time `json:"StopDate,omitempty"`
	ItemCount       int64      `json:"ItemCount"`
	Generation      int64      `json:"Generation"`
	RedriveCount    int64      `json:"RedriveCount"`
	Redriven        *time.Time `json:"RedriveDate,omitempty"`
}

type MapWriterConfig struct {
	Transformation string `json:"Transformation"`
	OutputType     string `json:"OutputType"`
}

type MapWriterRequest struct {
	Parameters   map[string]any       `json:"Parameters"`
	MapRunARN    string               `json:"MapRunArn"`
	WriterConfig MapWriterConfig      `json:"WriterConfig"`
	Executions   []MapResultExecution `json:"Executions"`
	Generation   int64                `json:"Generation"`
	PriorFiles   []MapResultFile      `json:"PriorFiles"`
}

type MapWriterOutput struct {
	Result                   any             `json:"Result"`
	ResultsWrittenItems      int64           `json:"ResultsWrittenItems"`
	ResultsWrittenExecutions int64           `json:"ResultsWrittenExecutions"`
	Files                    []MapResultFile `json:"Files"`
}

func mapWriterConfig(writer *asl.ResultWriter) MapWriterConfig {
	config := MapWriterConfig{Transformation: "COMPACT", OutputType: "JSON"}
	if writer != nil {
		if writer.Resource != "" {
			config.Transformation = "NONE"
		}
		if writer.WriterConfig != nil {
			config.Transformation, config.OutputType = writer.WriterConfig.Transformation, writer.WriterConfig.OutputType
		}
	}
	return config
}

// TransformMapResults implements the transformation independently of where the
// results are delivered. Failed executions retain their diagnostic metadata.
func TransformMapResults(executions []MapResultExecution, config MapWriterConfig) ([]any, error) {
	out := make([]any, 0, len(executions))
	for _, execution := range executions {
		if execution.Status == "PENDING" {
			out = append(out, map[string]any{"Input": execution.Input, "InputDetails": map[string]any{"Included": true}, "Status": "PENDING"})
			continue
		}
		if config.Transformation == "NONE" || execution.Status != "SUCCEEDED" {
			entry := map[string]any{"ExecutionArn": execution.ExecutionARN, "StateMachineArn": execution.StateMachineARN, "Name": execution.Name, "Status": execution.Status, "Input": execution.Input, "StartDate": execution.Started, "InputDetails": map[string]any{"Included": true}, "OutputDetails": map[string]any{"Included": true}, "RedriveCount": execution.RedriveCount}
			if execution.Type != "EXPRESS" {
				entry["RedriveStatus"] = "REDRIVABLE_BY_MAP_RUN"
				if execution.Status == "SUCCEEDED" {
					entry["RedriveStatus"], entry["RedriveStatusReason"] = "NOT_REDRIVABLE", "Execution is SUCCEEDED and cannot be redriven"
				}
			}
			if execution.Stopped != nil {
				entry["StopDate"] = *execution.Stopped
			}
			if execution.Redriven != nil {
				entry["RedriveDate"] = *execution.Redriven
			}
			if execution.Output != "" {
				entry["Output"] = execution.Output
			}
			if execution.Error != "" {
				entry["Error"] = execution.Error
			}
			if execution.Cause != "" {
				entry["Cause"] = execution.Cause
			}
			out = append(out, entry)
			continue
		}
		var output any
		if err := json.Unmarshal([]byte(execution.Output), &output); err != nil {
			return nil, err
		}
		switch config.Transformation {
		case "COMPACT":
			out = append(out, output)
		case "FLATTEN":
			if array, ok := output.([]any); ok {
				out = append(out, array...)
			} else {
				out = append(out, output)
			}
		default:
			return nil, fmt.Errorf("invalid map result transformation %q", config.Transformation)
		}
	}
	return out, nil
}

// EncodeMapResults is shared by the real ResultWriter adapter and uses Go's
// JSON encoder for both supported output formats.
func EncodeMapResults(executions []MapResultExecution, config MapWriterConfig) ([]byte, error) {
	results, err := TransformMapResults(executions, config)
	if err != nil {
		return nil, err
	}
	if config.OutputType == "JSON" {
		return json.Marshal(results)
	}
	if config.OutputType != "JSONL" {
		return nil, fmt.Errorf("invalid map result output type %q", config.OutputType)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func mapResultExecutions(children []ExecutionRecord, label string) []MapResultExecution {
	results := make([]MapResultExecution, len(children))
	for index, child := range children {
		results[index] = MapResultExecution{ExecutionARN: child.Key.ARN, StateMachineARN: child.Machine.ARN() + "/" + label, Type: child.Type, Name: child.Name, Status: child.Status, Input: child.Input, Output: child.Output, Error: child.Error, Cause: child.Cause, Started: child.Started, Stopped: child.Stopped, ItemCount: child.MapItemCount, Generation: child.MapGeneration, RedriveCount: child.RedriveCount}
		if child.Type == "STANDARD" {
			results[index].Redriven = child.Redriven
		}
	}
	return results
}

func (s *Service) finishMapChildren(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, children []ExecutionRecord, at time.Time, effects *transitionEffects) error {
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	results := mapResultExecutions(children, run.Label)
	writer := state.Map.ResultWriter
	config := mapWriterConfig(writer)
	if writer != nil && writer.Resource != "" {
		arguments, err := stateArguments(tx.Context(), state, env)
		if err != nil {
			return err
		}
		parameters, err := mapParameters(tx.Context(), writer.Parameters, writer.Arguments, mapInputEnvironment(state, env, arguments))
		if err != nil {
			return err
		}
		files, err := tx.MapResultFiles(run.Key)
		if err != nil {
			return err
		}
		request := MapWriterRequest{Parameters: parameters, MapRunARN: frame.MapRunARN, WriterConfig: config, Executions: results, Generation: run.RedriveCount, PriorFiles: files}
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		return s.scheduleMapEffect(tx, execution, revision, frame, "MAP_WRITER", writer.Resource, string(encoded), at)
	}
	output, err := TransformMapResults(results, config)
	if err != nil {
		return err
	}
	return s.finishMapRun(tx, execution, revision, frame, state, env, output, at, effects)
}

func (s *Service) completeMapWriter(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, task TaskRecord, at time.Time, effects *transitionEffects) error {
	output, err := s.acknowledgeMapWriter(tx, execution, frame, task)
	if err != nil {
		return err
	}
	if frame.Error != "" {
		return s.failMapState(tx, execution, revision, frame, state, env, frame.Error, frame.Cause, at, effects)
	}
	return s.finishMapRun(tx, execution, revision, frame, state, env, output.Result, at, effects)
}

func (s *Service) failMapResults(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, run MapRunRecord, name, cause string, at time.Time, effects *transitionEffects) error {
	writer := state.Map.ResultWriter
	if writer == nil || writer.Resource == "" {
		run.ResultsWrittenItems, run.ResultsWrittenExecutions = run.TotalItems, frame.ItemCount
		if err := tx.PutMapRun(run); err != nil {
			return err
		}
		return s.failMapState(tx, execution, revision, frame, state, env, name, cause, at, effects)
	}
	// The writer must see failed and never-started inputs as well as successes.
	// Retain the original failure while the existing effect lifecycle exports.
	frame.Error, frame.Cause = name, cause
	if err := s.abortMapExecutions(tx, execution, run, at, effects); err != nil {
		return err
	}
	children, err := tx.Executions(ExecutionSelection{Scope: execution.Key.Scope, MapRunARN: run.Key.ARN})
	if err != nil {
		return err
	}
	slices.SortFunc(children, func(a, b ExecutionRecord) int { return cmp.Compare(a.Name, b.Name) })
	return s.finishMapChildren(tx, execution, revision, frame, state, env, children, at, effects)
}

func (s *Service) failMapState(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, name, cause string, at time.Time, effects *transitionEffects) error {
	if name == "States.Runtime" {
		// Map child-admission failures still close and export the Map Run;
		// the generic runtime-error path then terminates the parent globally.
		if err := s.failMapRun(tx, execution, revision, frame, name, cause, at); err != nil {
			return err
		}
		record := frameHistory(frame, historyEvent("MapStateFailed", frame.PreviousHistoryID))
		record.Error, record.Cause = name, cause
		id, err := s.appendHistory(tx, execution, revision, at, record)
		if err != nil {
			return err
		}
		frame.PreviousHistoryID = id
	}
	return s.failState(tx, execution, revision, frame, state, env, name, cause, at, effects)
}

func (s *Service) acknowledgeMapWriter(tx Transaction, execution *ExecutionRecord, frame *FrameRecord, task TaskRecord) (MapWriterOutput, error) {
	var output MapWriterOutput
	if err := json.Unmarshal([]byte(task.Output), &output); err != nil {
		return output, &asl.EvaluationError{Name: "States.ResultWriterFailed", Cause: "The ResultWriter returned an invalid write acknowledgement."}
	}
	var request MapWriterRequest
	if err := json.Unmarshal([]byte(task.Parameters), &request); err != nil {
		return output, err
	}
	var items int64
	for _, child := range request.Executions {
		items += child.ItemCount
	}
	if output.ResultsWrittenItems < 0 || output.ResultsWrittenItems > items || output.ResultsWrittenExecutions < 0 || output.ResultsWrittenExecutions > int64(len(request.Executions)) {
		return output, &asl.EvaluationError{Name: "States.ResultWriterFailed", Cause: "The ResultWriter acknowledged results outside this Map Run."}
	}
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return output, err
	}
	run.ResultsWrittenItems, run.ResultsWrittenExecutions = output.ResultsWrittenItems, output.ResultsWrittenExecutions
	if err := tx.PutMapRun(run); err != nil {
		return output, err
	}
	for _, file := range output.Files {
		if err := tx.PutMapResultFile(run.Key, file); err != nil {
			return output, err
		}
	}
	if task.Status == TaskSucceeded && (output.ResultsWrittenItems != items || output.ResultsWrittenExecutions != int64(len(request.Executions)) || output.Result == nil) {
		return output, &asl.EvaluationError{Name: "States.ResultWriterFailed", Cause: "The ResultWriter did not acknowledge all execution results."}
	}
	return output, nil
}

func (s *Service) finishMapRun(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, output any, at time.Time, effects *transitionEffects) error {
	// A large unexported aggregate is a state-data failure, not a successful run.
	if _, err := encodeExecutionData(output); err != nil {
		return err
	}
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	if state.Map.ResultWriter == nil || state.Map.ResultWriter.Resource == "" {
		// Returning the aggregate to the parent also writes the child results,
		// even when no S3 ResultWriter is configured.
		run.ResultsWrittenItems, run.ResultsWrittenExecutions = run.TotalItems, frame.ItemCount
	}
	run.Status, run.Stopped = "SUCCEEDED", new(at)
	if err := tx.PutMapRun(run); err != nil {
		return err
	}
	id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, historyEvent("MapRunSucceeded", frame.PreviousHistoryID)))
	if err != nil {
		return err
	}
	if _, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, historyEvent("MapStateSucceeded", id))); err != nil {
		return err
	}
	return s.finishState(tx, execution, revision, frame, state, env, output, state.Next, state.Assign, state.Output, at, effects)
}

func (s *Service) failMapRun(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, name, cause string, at time.Time) error {
	if frame.MapRunARN == "" {
		return nil
	}
	run, err := tx.MapRun(MapRunKey{Scope: execution.Key.Scope, ARN: frame.MapRunARN})
	if err != nil {
		return err
	}
	if run.Status != "RUNNING" {
		return nil
	}
	run.Status, run.Stopped = "FAILED", new(at)
	if err := tx.PutMapRun(run); err != nil {
		return err
	}
	event := historyEvent("MapRunFailed", frame.PreviousHistoryID)
	event.MapRunFailedEventDetails = &api.MapRunFailedEventDetails{Error: new(api.SensitiveError(name)), Cause: new(api.SensitiveCause(cause))}
	id, err := s.appendHistory(tx, execution, revision, at, frameHistory(frame, event))
	frame.PreviousHistoryID = id
	return err
}
