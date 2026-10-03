package lambda

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func (s *Service) registerDurable() {
	register(s, "CheckpointDurableExecution", s.checkpointDurableExecution)
	register(s, "GetDurableExecution", s.getDurableExecution)
	register(s, "GetDurableExecutionHistory", s.getDurableExecutionHistory)
	register(s, "GetDurableExecutionState", s.getDurableExecutionState)
	register(s, "ListDurableExecutionsByFunction", s.listDurableExecutions)
	register(s, "StopDurableExecution", s.stopDurableExecution)
	register(s, "SendDurableExecutionCallbackSuccess", s.durableCallbackSuccess)
	register(s, "SendDurableExecutionCallbackFailure", s.durableCallbackFailure)
	register(s, "SendDurableExecutionCallbackHeartbeat", s.durableCallbackHeartbeat)
}

func (s *Service) authorizedDurable(r Reader, arn, action string) (DurableExecutionRecord, error) {
	var zero DurableExecutionRecord
	prefix, _, ok := strings.Cut(arn, "/durable-execution/")
	if !ok {
		return zero, durableParameter("Invalid durable execution ARN.")
	}
	ref, wire := parseFunctionReference(r.Context(), prefix, "")
	if wire != nil {
		return zero, wire
	}
	function, err := r.Function(ref.FunctionKey)
	if err != nil {
		return zero, err
	}
	if wire := s.authorize(r.Context(), action, arn, function.Tags, nil, nil); wire != nil {
		return zero, wire
	}
	v, err := r.DurableExecution(arn)
	if err != nil {
		return zero, err
	}
	if !v.ExpiresAt.IsZero() && !s.clock.Now().Before(v.ExpiresAt) {
		return zero, ErrNotFound
	}
	if data, _ := r.Context().Value(durableDataAccessKey{}).(bool); data {
		return cryptDurableRecord(r.Context(), v, true)
	}
	return v, nil
}

func durableConfiguration(v DurableExecutionRecord) *api.DurableConfig {
	return &api.DurableConfig{ExecutionTimeout: new(api.ExecutionTimeout(v.ExecutionTimeout)), RetentionPeriodInDays: new(api.RetentionPeriodInDays(v.RetentionDays)), KMSKeyArn: durableOptional[api.KMSKeyArn](v.KeyARN)}
}

func (s *Service) getDurableExecution(ctx context.Context, in *api.GetDurableExecutionInput) (*api.GetDurableExecutionOutput, *awswire.Error) {
	include := in.IncludeExecutionData == nil || bool(*in.IncludeExecutionData)
	if include {
		prepared, rejected := s.prepareDurableContext(ctx, value(in.DurableExecutionArn), "GetDurableExecution", false)
		if rejected != nil {
			return nil, rejected
		}
		ctx = prepared
		defer clearDurableMaterial(ctx)
	}
	var v DurableExecutionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = s.authorizedDurable(r, value(in.DurableExecutionArn), "GetDurableExecution")
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	out := &api.GetDurableExecutionOutput{DurableExecutionArn: new(api.DurableExecutionArn(v.ARN)), DurableExecutionName: new(api.DurableExecutionName(v.Name)), FunctionArn: new(api.NameSpacedFunctionArn(v.Function.ARN())), Status: new(api.ExecutionStatus(v.Status)), StartTimestamp: new(v.StartedAt), EndTimestamp: durableTime(v.EndedAt), Version: new(api.VersionWithLatestPublished(versionName(v.Function.Version))), DurableConfig: durableConfiguration(v), ExecutionDataIncluded: new(api.ExecutionDataIncluded(include))}
	if v.TraceID != "" {
		out.TraceHeader = &api.TraceHeader{XAmznTraceId: new(api.XAmznTraceId(v.TraceID))}
	}
	if include {
		if v.Input != nil {
			out.InputPayload = new(api.InputPayload(*v.Input))
		}
		if v.Result != nil {
			out.Result = new(api.OutputPayload(*v.Result))
		}
		out.Error = cloneDurableError(v.Error)
	}
	return out, nil
}

type durableMarker struct {
	Scope    string
	Position int
	Expires  int64
}

func (s *Service) durablePage(marker, scope string, maximum *api.ItemCount, count int) (int, int, *api.String, *awswire.Error) {
	limit := 100
	if maximum != nil && *maximum != 0 {
		limit = int(*maximum)
	}
	if limit < 1 || limit > 1000 {
		return 0, 0, nil, durableParameter("MaxItems must be between 1 and 1000.")
	}
	position := 0
	if marker != "" {
		encoded, err := base64.RawURLEncoding.DecodeString(marker)
		var decoded durableMarker
		if err != nil || json.Unmarshal(encoded, &decoded) != nil || decoded.Scope != scope || decoded.Position < 0 || decoded.Position > count || s.clock.Now().Unix() >= decoded.Expires {
			return 0, 0, nil, durableParameter("Invalid or expired pagination marker.")
		}
		position = decoded.Position
	}
	end := min(count, position+limit)
	var next *api.String
	if end < count {
		encoded, _ := json.Marshal(durableMarker{Scope: scope, Position: end, Expires: s.clock.Now().Add(24 * time.Hour).Unix()})
		next = new(api.String(base64.RawURLEncoding.EncodeToString(encoded)))
	}
	return position, end, next, nil
}

func (s *Service) getDurableExecutionState(ctx context.Context, in *api.GetDurableExecutionStateInput) (*api.GetDurableExecutionStateOutput, *awswire.Error) {
	prepared, rejected := s.prepareDurableContext(ctx, value(in.DurableExecutionArn), "GetDurableExecutionState", false)
	if rejected != nil {
		return nil, rejected
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	var v DurableExecutionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = s.authorizedDurable(r, value(in.DurableExecutionArn), "GetDurableExecutionState")
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	if v.Token != value(in.CheckpointToken) || v.Status != "RUNNING" {
		return nil, durableParameter("The checkpoint token is invalid or the durable execution is no longer running.")
	}
	operations := durableOperations(v.Operations)
	start, end, next, wire := s.durablePage(value(in.Marker), v.ARN+"/state/"+v.Token, in.MaxItems, len(operations))
	if wire != nil {
		return nil, wire
	}
	return &api.GetDurableExecutionStateOutput{Operations: operations[start:end], NextMarker: next}, nil
}

func (s *Service) getDurableExecutionHistory(ctx context.Context, in *api.GetDurableExecutionHistoryInput) (*api.GetDurableExecutionHistoryOutput, *awswire.Error) {
	data := in.IncludeExecutionData != nil && bool(*in.IncludeExecutionData)
	if data {
		prepared, rejected := s.prepareDurableContext(ctx, value(in.DurableExecutionArn), "GetDurableExecutionHistory", false)
		if rejected != nil {
			return nil, rejected
		}
		ctx = prepared
		defer clearDurableMaterial(ctx)
	}
	var v DurableExecutionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = s.authorizedDurable(r, value(in.DurableExecutionArn), "GetDurableExecutionHistory")
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	reverse := in.ReverseOrder != nil && bool(*in.ReverseOrder)
	if reverse {
		slices.Reverse(v.History)
	}
	scope := v.ARN + "/history"
	if reverse {
		scope += "/reverse"
	}
	start, end, next, wire := s.durablePage(value(in.Marker), scope, in.MaxItems, len(v.History))
	if wire != nil {
		return nil, wire
	}
	out := &api.GetDurableExecutionHistoryOutput{Events: make(api.Events, 0, end-start), NextMarker: next}
	for _, event := range v.History[start:end] {
		out.Events = append(out.Events, durableHistoryEvent(event, v, data))
	}
	return out, nil
}

func (s *Service) listDurableExecutions(ctx context.Context, in *api.ListDurableExecutionsByFunctionInput) (*api.ListDurableExecutionsByFunctionOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	var rows []DurableExecutionRecord
	var version uint64
	err := s.repository.View(ctx, func(r Reader) error {
		function, err := loadFunction(r, ref)
		if err != nil {
			return err
		}
		version = function.Version
		if wire := s.authorizeFunction(r, "ListDurableExecutionsByFunction", ref, function, nil); wire != nil {
			return wire
		}
		rows, err = r.DurableExecutions()
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	rows = slices.DeleteFunc(rows, func(v DurableExecutionRecord) bool {
		return v.Function.FunctionKey != ref.FunctionKey || (ref.Qualifier != "" && v.Function.Version != version) || (!v.ExpiresAt.IsZero() && !s.clock.Now().Before(v.ExpiresAt)) || (value(in.DurableExecutionName) != "" && v.Name != value(in.DurableExecutionName)) || (len(in.Statuses) > 0 && !slices.Contains(in.Statuses, api.ExecutionStatus(v.Status))) || (in.StartedAfter != nil && !v.StartedAt.After(*in.StartedAfter)) || (in.StartedBefore != nil && !v.StartedAt.Before(*in.StartedBefore))
	})
	slices.SortFunc(rows, func(a, b DurableExecutionRecord) int {
		return cmp.Or(b.StartedAt.Compare(a.StartedAt), cmp.Compare(a.ARN, b.ARN))
	})
	if in.ReverseOrder != nil && bool(*in.ReverseOrder) {
		slices.Reverse(rows)
	}
	filter := *in
	filter.Marker, filter.MaxItems = nil, nil
	encoded, _ := json.Marshal(filter)
	start, end, next, wire := s.durablePage(value(in.Marker), ref.ARN()+"/list/"+string(encoded), in.MaxItems, len(rows))
	if wire != nil {
		return nil, wire
	}
	out := &api.ListDurableExecutionsByFunctionOutput{DurableExecutions: make(api.DurableExecutions, 0, end-start), NextMarker: next}
	for _, v := range rows[start:end] {
		out.DurableExecutions = append(out.DurableExecutions, api.Execution{DurableExecutionArn: new(api.DurableExecutionArn(v.ARN)), DurableExecutionName: new(api.DurableExecutionName(v.Name)), FunctionArn: new(api.NameSpacedFunctionArn(v.Function.ARN())), Status: new(api.ExecutionStatus(v.Status)), StartTimestamp: new(v.StartedAt), EndTimestamp: durableTime(v.EndedAt), KMSKeyArn: durableOptional[api.KMSKeyArn](v.KeyARN)})
	}
	return out, nil
}

func (s *Service) stopDurableExecution(ctx context.Context, in *api.StopDurableExecutionInput) (*api.StopDurableExecutionOutput, *awswire.Error) {
	prepared, rejected := s.prepareDurableContext(ctx, value(in.DurableExecutionArn), "StopDurableExecution", false)
	if rejected != nil {
		return nil, rejected
	}
	ctx = prepared
	defer clearDurableMaterial(ctx)
	var out *api.StopDurableExecutionOutput
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.authorizedDurable(tx, value(in.DurableExecutionArn), "StopDurableExecution")
		if err != nil {
			return err
		}
		completeDurable(&v, "STOPPED", nil, in.Error, s.clock.Now())
		if err := putPreparedDurable(tx, v); err != nil {
			return err
		}
		out = &api.StopDurableExecutionOutput{StopTimestamp: new(v.EndedAt)}
		return s.recordCall(tx.Context(), "StopDurableExecution", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.durable.stop(value(in.DurableExecutionArn))
	s.durable.changed()
	s.jobs.Wake()
	return out, nil
}
