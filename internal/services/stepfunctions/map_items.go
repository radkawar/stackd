package stepfunctions

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"time"

	"stackd/internal/services/stepfunctions/asl"
)

// MapReaderRequest is the resolved request passed to the destination adapter.
// The adapter performs resource access and parsing outside the state transaction.
type MapReaderRequest struct {
	Parameters   map[string]any  `json:"Parameters"`
	ReaderConfig MapReaderConfig `json:"ReaderConfig"`
}

type MapReaderConfig struct {
	InputType         string   `json:"InputType,omitempty"`
	CSVHeaderLocation string   `json:"CSVHeaderLocation,omitempty"`
	CSVHeaders        []string `json:"CSVHeaders,omitempty"`
	CSVDelimiter      string   `json:"CSVDelimiter,omitempty"`
	MaxItems          int64    `json:"MaxItems,omitempty"`
	ManifestType      string   `json:"ManifestType,omitempty"`
	ItemsPointer      string   `json:"ItemsPointer,omitempty"`
	Transformation    string   `json:"Transformation,omitempty"`
}

type MapReaderOutput struct {
	Items   []any    `json:"Items"`
	Source  string   `json:"Source,omitempty"`
	Sources []string `json:"Sources,omitempty"`
	Keys    []string `json:"Keys,omitempty"`
}

func mapInputEnvironment(state *asl.State, env asl.Environment, arguments any) asl.Environment {
	if state.Language == asl.JSONPath {
		env.Input = arguments
	}
	return env
}

func mapParameters(ctx context.Context, parameters, arguments *asl.Template, env asl.Environment) (map[string]any, error) {
	template := parameters
	if arguments != nil {
		template = arguments
	}
	if template == nil {
		return map[string]any{}, nil
	}
	value, err := template.Evaluate(ctx, env)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, &asl.EvaluationError{Name: "States.Runtime", Cause: "Map resource parameters must evaluate to an object."}
	}
	return object, nil
}

func mapReaderRequest(ctx context.Context, state *asl.State, env asl.Environment) (MapReaderRequest, error) {
	reader := state.Map.ItemReader
	parameters, err := mapParameters(ctx, reader.Parameters, reader.Arguments, env)
	if err != nil {
		return MapReaderRequest{}, err
	}
	request := MapReaderRequest{Parameters: parameters}
	if config := reader.ReaderConfig; config != nil {
		request.ReaderConfig = MapReaderConfig{InputType: config.InputType, CSVHeaderLocation: config.CSVHeaderLocation, CSVHeaders: config.CSVHeaders, CSVDelimiter: config.CSVDelimiter, ManifestType: config.ManifestType, ItemsPointer: config.ItemsPointer, Transformation: config.Transformation}
		if config.MaxItems != nil {
			request.ReaderConfig.MaxItems, err = config.MaxItems.Evaluate(ctx, env)
			if err != nil {
				return MapReaderRequest{}, err
			}
		}
	}
	return request, nil
}

func (s *Service) startMapReader(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, at time.Time) error {
	request, err := mapReaderRequest(tx.Context(), state, env)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	return s.scheduleMapEffect(tx, execution, revision, frame, "MAP_READER", state.Map.ItemReader.Resource, string(encoded), at)
}

func mapSelectedItems(ctx context.Context, state *asl.State, env asl.Environment, arguments any, inspect ...stateInspection) ([]any, []string, error) {
	var items any
	var err error
	if state.Language == asl.JSONPath {
		selection := env
		selection.Input = arguments
		items, err = selectedInput(state.Map.ItemsPath, selection)
	} else if state.Map.Items != nil {
		items, err = state.Map.Items.Evaluate(ctx, env)
	} else {
		items = arguments
	}
	if err != nil {
		return nil, nil, err
	}
	stage := "afterItemsPath"
	if state.Language == asl.JSONata {
		stage = "afterItems"
	}
	if err := inspectState(inspect, stage, items); err != nil {
		return nil, nil, err
	}
	if array, ok := items.([]any); ok {
		return array, nil, nil
	}
	if object, ok := items.(map[string]any); ok && state.Language == asl.JSONata {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		values := make([]any, len(keys))
		for i, key := range keys {
			values[i] = object[key]
		}
		return values, keys, nil
	}
	return nil, nil, &asl.EvaluationError{Name: "States.Runtime", Cause: "The Map items value must be an array (or an object for JSONata)."}
}

// mapItemInputs applies the selector once, before batching. Arguments retains
// only customer JSON, not a second serialized model of the workflow resources.
func mapItemInputs(ctx context.Context, state *asl.State, env asl.Environment, items []any, keys, sources []string, source string, inspect ...stateInspection) ([]any, error) {
	if state.Map.ProcessorConfig.Mode == "DISTRIBUTED" && state.Map.ItemReader == nil {
		source = "STATE_DATA"
	}
	selected := make([]any, len(items))
	for index, item := range items {
		result := item
		if state.Map.ItemSelector != nil {
			itemEnv := env
			itemEnv.ContextObject = maps.Clone(env.ContextObject)
			contextItem := map[string]any{"Index": index, "Value": item}
			if keys != nil {
				contextItem["Key"] = keys[index]
			}
			itemSource := source
			if sources != nil {
				itemSource = sources[index]
			}
			if itemSource != "" {
				contextItem["Source"] = itemSource
			}
			itemEnv.ContextObject["Map"] = map[string]any{"Item": contextItem}
			var err error
			result, err = state.Map.ItemSelector.Evaluate(ctx, itemEnv)
			if err != nil {
				return nil, err
			}
		}
		if _, err := encodeExecutionData(result); err != nil {
			return nil, err
		}
		selected[index] = result
	}
	if err := inspectState(inspect, "afterItemSelector", selected); err != nil {
		return nil, err
	}
	batcher := state.Map.ItemBatcher
	if batcher == nil {
		return selected, inspectState(inspect, "afterItemBatcher", selected)
	}
	maxItems, maxBytes := int64(len(selected)), int64(executionDataLimit)
	var err error
	if batcher.MaxItemsPerBatch != nil {
		maxItems, err = batcher.MaxItemsPerBatch.Evaluate(ctx, env)
		if err != nil {
			return nil, err
		}
	}
	if batcher.MaxInputBytesPerBatch != nil {
		maxBytes, err = batcher.MaxInputBytesPerBatch.Evaluate(ctx, env)
		if err != nil {
			return nil, err
		}
	}
	var batchInput any
	if batcher.BatchInput != nil {
		batchInput, err = batcher.BatchInput.Evaluate(ctx, env)
		if err != nil {
			return nil, err
		}
	}
	batches := make([]any, 0)
	for offset := 0; offset < len(selected); {
		batch := map[string]any{"Items": []any{}}
		if batcher.BatchInput != nil {
			batch["BatchInput"] = batchInput
		}
		overhead, err := json.Marshal(batch)
		if err != nil {
			return nil, err
		}
		size, end := int64(len(overhead)), offset
		for end < len(selected) && int64(end-offset) < maxItems {
			encoded, err := json.Marshal(selected[end])
			if err != nil {
				return nil, err
			}
			addition := int64(len(encoded))
			if end != offset {
				addition++
			}
			if size+addition > maxBytes {
				break
			}
			size += addition
			end++
		}
		if end == offset {
			return nil, &asl.EvaluationError{Name: "States.DataLimitExceeded", Cause: fmt.Sprintf("Map item %d cannot fit within MaxInputBytesPerBatch.", offset)}
		}
		batch["Items"] = selected[offset:end]
		batches = append(batches, batch)
		offset = end
	}
	return batches, inspectState(inspect, "afterItemBatcher", batches)
}

func mapBatchCardinality(state *asl.State, input any) int64 {
	if state.Map.ItemBatcher == nil {
		return 1
	}
	return int64(len(input.(map[string]any)["Items"].([]any)))
}

func (s *Service) resumeMapEffect(tx Transaction, execution *ExecutionRecord, revision RevisionRecord, frame *FrameRecord, state *asl.State, env asl.Environment, task TaskRecord, at time.Time, effects *transitionEffects) error {
	if task.Kind == "MAP_EXECUTIONS" || task.Kind == "MAP_REDRIVE" {
		return s.resumeMapExecutions(tx, execution, revision, frame, state, env, task, at, effects)
	}
	if task.Status != TaskSucceeded {
		if task.Kind == "MAP_WRITER" && task.Output != "" {
			if _, err := s.acknowledgeMapWriter(tx, execution, frame, task); err != nil {
				return err
			}
		}
		name := "States.ItemReaderFailed"
		if task.Kind == "MAP_WRITER" {
			name = "States.ResultWriterFailed"
		}
		cause := task.Cause
		if cause == "" {
			cause = task.Error
		}
		return s.failState(tx, execution, revision, frame, state, env, name, cause, at, effects)
	}
	frame.TaskID = ""
	if task.Kind == "MAP_WRITER" {
		return s.completeMapWriter(tx, execution, revision, frame, state, env, task, at, effects)
	}
	var output MapReaderOutput
	if err := json.Unmarshal([]byte(task.Output), &output); err != nil {
		return &asl.EvaluationError{Name: "States.ItemReaderFailed", Cause: "The ItemReader returned invalid item data: " + err.Error()}
	}
	if output.Items == nil {
		return &asl.EvaluationError{Name: "States.ItemReaderFailed", Cause: "The ItemReader did not return an item array."}
	}
	if output.Sources != nil && len(output.Sources) != len(output.Items) || output.Keys != nil && len(output.Keys) != len(output.Items) {
		return &asl.EvaluationError{Name: "States.ItemReaderFailed", Cause: "The ItemReader item metadata does not match the returned items."}
	}
	var arguments any
	if err := json.Unmarshal([]byte(frame.Arguments), &arguments); err != nil {
		return err
	}
	return s.beginMapItems(tx, execution, revision, frame, state, env, arguments, output.Items, output.Keys, output.Sources, output.Source, at, effects)
}
