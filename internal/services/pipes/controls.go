package pipes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"maps"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/pipes"
	"strings"
)

func registerControls(s *Service) {
	register(s, "CreatePipe", s.create)
	register(s, "UpdatePipe", s.update)
	register(s, "DescribePipe", func(ctx context.Context, t Transaction, in *api.DescribePipeInput) (*api.DescribePipeOutput, error) {
		p, e := s.load(ctx, t, value(in.Name), "DescribePipe")
		if e != nil {
			return nil, e
		}
		return describe(p), nil
	})
	register(s, "DeletePipe", func(ctx context.Context, t Transaction, in *api.DeletePipeInput) (*api.DeletePipeOutput, error) {
		p, err := s.load(ctx, t, value(in.Name), "DeletePipe")
		if err != nil {
			return nil, err
		}
		p.State = "DELETING"
		p.Modified = s.clock.Now()
		p.Due = p.Modified
		p.Version++
		if err = t.PutPipe(p); err != nil {
			return nil, err
		}
		return &api.DeletePipeOutput{
			Arn:              new(api.PipeArn(p.Key.ARN())),
			Name:             new(api.PipeName(p.Key.Name)),
			CurrentState:     new(api.PipeState(p.State)),
			DesiredState:     new(api.RequestedPipeStateDescribeResponse(p.Desired)),
			CreationTime:     new(p.Created),
			LastModifiedTime: new(p.Modified),
		}, nil
	})
	register(s, "StartPipe", func(ctx context.Context, t Transaction, in *api.StartPipeInput) (*api.StartPipeOutput, error) {
		p, e := s.state(ctx, t, value(in.Name), "StartPipe", "RUNNING")
		if e != nil {
			return nil, e
		}
		return &api.StartPipeOutput{
			Arn:              new(api.PipeArn(p.Key.ARN())),
			Name:             new(api.PipeName(p.Key.Name)),
			CurrentState:     new(api.PipeState(p.State)),
			DesiredState:     new(api.RequestedPipeState(p.Desired)),
			CreationTime:     new(p.Created),
			LastModifiedTime: new(p.Modified),
		}, nil
	})
	register(s, "StopPipe", func(ctx context.Context, t Transaction, in *api.StopPipeInput) (*api.StopPipeOutput, error) {
		p, e := s.state(ctx, t, value(in.Name), "StopPipe", "STOPPED")
		if e != nil {
			return nil, e
		}
		return &api.StopPipeOutput{
			Arn:              new(api.PipeArn(p.Key.ARN())),
			Name:             new(api.PipeName(p.Key.Name)),
			CurrentState:     new(api.PipeState(p.State)),
			DesiredState:     new(api.RequestedPipeState(p.Desired)),
			CreationTime:     new(p.Created),
			LastModifiedTime: new(p.Modified),
		}, nil
	})
	register(s, "ListPipes", s.list)
	register(s, "TagResource", func(ctx context.Context, t Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
		p, e := s.byARN(ctx, t, value(in.ResourceArn), "TagResource")
		if e != nil {
			return nil, e
		}
		if e = validateTags(in.Tags); e != nil {
			return nil, e
		}
		conditions := tagConditions(in.Tags)
		if e = s.authorize(ctx, p, "TagResource", conditions); e != nil {
			return nil, e
		}
		if p.Tags == nil {
			p.Tags = api.TagMap{}
		}
		maps.Copy(p.Tags, in.Tags)
		if len(p.Tags) > 50 {
			return nil, invalid("A pipe supports at most 50 tags.")
		}
		return &api.TagResourceOutput{}, t.PutPipe(p)
	})
	register(s, "UntagResource", func(ctx context.Context, t Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
		p, e := s.byARN(ctx, t, value(in.ResourceArn), "UntagResource")
		if e != nil {
			return nil, e
		}
		var keys []string
		for _, k := range in.TagKeys {
			keys = append(keys, string(k))
		}
		if e = s.authorize(ctx, p, "UntagResource", map[string][]string{"aws:TagKeys": keys}); e != nil {
			return nil, e
		}
		for _, k := range in.TagKeys {
			delete(p.Tags, k)
		}
		return &api.UntagResourceOutput{}, t.PutPipe(p)
	})
	register(s, "ListTagsForResource", func(ctx context.Context, t Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
		p, e := s.byARN(ctx, t, value(in.ResourceArn), "ListTagsForResource")
		if e != nil {
			return nil, e
		}
		return &api.ListTagsForResourceOutput{Tags: p.Tags}, nil
	})
}
func (s *Service) create(ctx context.Context, t Transaction, in *api.CreatePipeInput) (*api.CreatePipeOutput, error) {
	p := PipeRecord{
		Key:           Key{scopeFor(ctx), value(in.Name)},
		ID:            uuid.NewString(),
		Version:       1,
		Description:   value(in.Description),
		RoleARN:       value(in.RoleArn),
		SourceARN:     value(in.Source),
		TargetARN:     value(in.Target),
		EnrichmentARN: value(in.Enrichment),
		Tags:          maps.Clone(in.Tags),
		State:         "CREATING",
		Desired:       "RUNNING",
		Created:       s.clock.Now(),
		Modified:      s.clock.Now(),
		Due:           s.clock.Now(),
		ParentEventID: apievents.EventID(ctx),
	}
	if in.DesiredState != nil {
		p.Desired = value(in.DesiredState)
	}
	if in.TargetParameters != nil {
		p.Target = api.ClonePipeTargetParameters(*in.TargetParameters)
	}
	if in.EnrichmentParameters != nil {
		p.EnrichmentTemplate = value(in.EnrichmentParameters.InputTemplate)
		p.EnrichmentHTTP = cloneEnrichmentHTTP(in.EnrichmentParameters.HttpParameters)
	}
	if err := s.authorize(ctx, p, "CreatePipe", tagConditions(in.Tags)); err != nil {
		return nil, err
	}
	if _, err := t.Pipe(p.Key); err == nil {
		conflict := failure("ConflictException", "Pipe "+p.Key.Name+" already exists.", 409)
		resourceID, _ := json.Marshal(p.Key.Name)
		conflict.Details = map[string]json.RawMessage{"resourceId": resourceID, "resourceType": json.RawMessage(`"Pipe"`)}
		return nil, conflict
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if e := validateTags(p.Tags); e != nil {
		return nil, e
	}
	source, e := sourceSettings(p.SourceARN, in.SourceParameters)
	if e != nil {
		return nil, e
	}
	p.Source = source
	if isKafka(source.Kind) && source.Kafka.ConsumerGroupID != "" {
		all, err := t.Pipes()
		if err != nil {
			return nil, err
		}
		for _, other := range all {
			if other.Key.Scope == p.Key.Scope && isKafka(other.Source.Kind) && KafkaGroup(other) == KafkaGroup(p) {
				return nil, invalid("ConsumerGroupID must be unique among Kafka pipe sources in this account and region.")
			}
		}
	}
	if e = s.prepare(ctx, &p, in.KmsKeyIdentifier, in.LogConfiguration); e != nil {
		return nil, e
	}
	if e = t.PutPipe(p); e != nil {
		return nil, e
	}
	return &api.CreatePipeOutput{
		Arn:              new(api.PipeArn(p.Key.ARN())),
		Name:             new(api.PipeName(p.Key.Name)),
		CurrentState:     new(api.PipeState(p.State)),
		DesiredState:     new(api.RequestedPipeState(p.Desired)),
		CreationTime:     new(p.Created),
		LastModifiedTime: new(p.Modified),
	}, nil
}
func (s *Service) update(ctx context.Context, t Transaction, in *api.UpdatePipeInput) (*api.UpdatePipeOutput, error) {
	p, e := s.load(ctx, t, value(in.Name), "UpdatePipe")
	if e != nil {
		return nil, e
	}
	if p.State == "DELETING" {
		return nil, failure("ConflictException", "Pipe is deleting.", 409)
	}
	if in.Description != nil {
		p.Description = value(in.Description)
	}
	p.RoleARN = value(in.RoleArn)
	if in.Target != nil {
		p.TargetARN = value(in.Target)
	}
	if in.Enrichment != nil {
		p.EnrichmentARN = value(in.Enrichment)
	}
	if in.EnrichmentParameters != nil {
		p.EnrichmentTemplate = value(in.EnrichmentParameters.InputTemplate)
		if in.EnrichmentParameters.HttpParameters != nil {
			p.EnrichmentHTTP = cloneEnrichmentHTTP(in.EnrichmentParameters.HttpParameters)
		}
	}
	if in.TargetParameters != nil {
		p.Target = api.ClonePipeTargetParameters(*in.TargetParameters)
	}
	if in.DesiredState != nil {
		p.Desired = value(in.DesiredState)
	}
	if in.SourceParameters != nil {
		old := sourceParameters(p.Source)
		if q := in.SourceParameters.ManagedStreamingKafkaParameters; q != nil && q.Credentials != nil && old.ManagedStreamingKafkaParameters != nil {
			old.ManagedStreamingKafkaParameters.Credentials = nil
		}
		if q := in.SourceParameters.SelfManagedKafkaParameters; q != nil && q.Credentials != nil && old.SelfManagedKafkaParameters != nil {
			old.SelfManagedKafkaParameters.Credentials = nil
		}
		b, e := json.Marshal(in.SourceParameters)
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, old); e != nil {
			return nil, e
		}
		p.Source, e = sourceSettings(p.SourceARN, old)
		if e != nil {
			return nil, e
		}
	}
	if e = s.prepare(ctx, &p, in.KmsKeyIdentifier, in.LogConfiguration); e != nil {
		return nil, e
	}
	p.State = "UPDATING"
	p.Reason = ""
	p.Version++
	p.Modified = s.clock.Now()
	p.Due = p.Modified
	if e = t.PutPipe(p); e != nil {
		return nil, e
	}
	return &api.UpdatePipeOutput{
		Arn:              new(api.PipeArn(p.Key.ARN())),
		Name:             new(api.PipeName(p.Key.Name)),
		CurrentState:     new(api.PipeState(p.State)),
		DesiredState:     new(api.RequestedPipeState(p.Desired)),
		CreationTime:     new(p.Created),
		LastModifiedTime: new(p.Modified),
	}, nil
}
func (s *Service) state(ctx context.Context, t Transaction, name, action, desired string) (PipeRecord, error) {
	p, e := s.load(ctx, t, name, action)
	if e != nil {
		return p, e
	}
	if p.State == "DELETING" {
		return p, failure("ConflictException", "Pipe is deleting.", 409)
	}
	if p.Desired == desired && p.State == desired {
		return p, nil
	}
	p.Desired = desired
	p.State = "STARTING"
	if desired == "STOPPED" {
		p.State = "STOPPING"
	}
	p.Reason = ""
	p.Version++
	p.Modified = s.clock.Now()
	p.Due = p.Modified
	return p, t.PutPipe(p)
}
func describe(p PipeRecord) *api.DescribePipeOutput {
	out := &api.DescribePipeOutput{
		Arn:              new(api.PipeArn(p.Key.ARN())),
		Name:             new(api.PipeName(p.Key.Name)),
		Description:      new(api.PipeDescription(p.Description)),
		CurrentState:     new(api.PipeState(p.State)),
		DesiredState:     new(api.RequestedPipeStateDescribeResponse(p.Desired)),
		CreationTime:     new(p.Created),
		LastModifiedTime: new(p.Modified),
		RoleArn:          new(api.RoleArn(p.RoleARN)),
		Source:           new(api.ArnOrUrl(p.SourceARN)),
		Target:           new(api.Arn(p.TargetARN)),
		SourceParameters: sourceParameters(p.Source),
		TargetParameters: new(api.ClonePipeTargetParameters(p.Target)),
		Tags:             maps.Clone(p.Tags),
		LogConfiguration: loggingOutput(p.Logging),
	}
	if p.KMSKeyARN != "" {
		out.KmsKeyIdentifier = new(api.KmsKeyIdentifier(p.KMSKeyARN))
	}
	if p.EnrichmentARN != "" {
		out.Enrichment = new(api.OptionalArn(p.EnrichmentARN))
	}
	if p.EnrichmentTemplate != "" || p.EnrichmentHTTP != nil {
		out.EnrichmentParameters = &api.PipeEnrichmentParameters{HttpParameters: cloneEnrichmentHTTP(p.EnrichmentHTTP)}
		if p.EnrichmentTemplate != "" {
			out.EnrichmentParameters.InputTemplate = new(api.InputTemplate(p.EnrichmentTemplate))
		}
	}
	if p.Reason != "" {
		out.StateReason = new(api.PipeStateReason(p.Reason))
	}
	return out
}
func (s *Service) byARN(ctx context.Context, t Reader, arn, action string) (PipeRecord, error) {
	prefix := Key{Scope: scopeFor(ctx)}.ARN()
	if !strings.HasPrefix(arn, prefix) {
		return PipeRecord{}, failure("NotFoundException", "Pipe does not exist.", 404)
	}
	return s.load(ctx, t, strings.TrimPrefix(arn, prefix), action)
}
func (s *Service) list(ctx context.Context, t Transaction, in *api.ListPipesInput) (*api.ListPipesOutput, error) {
	if e := s.authorize(ctx, PipeRecord{Key: Key{Scope: scopeFor(ctx)}}, "ListPipes", nil); e != nil {
		return nil, e
	}
	after := ""
	if in.NextToken != nil {
		b, e := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		if e != nil {
			return nil, invalid("Invalid NextToken.")
		}
		var token struct {
			Scope Scope
			After string
			Query string
		}
		if json.Unmarshal(b, &token) != nil || token.Scope != scopeFor(ctx) || token.Query != listQuery(in) {
			return nil, invalid("Invalid NextToken.")
		}
		after = token.After
	}
	limit := 100
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	if limit < 1 || limit > 100 {
		return nil, invalid("Limit must be between 1 and 100.")
	}
	all, e := t.Pipes()
	if e != nil {
		return nil, e
	}
	out := &api.ListPipesOutput{Pipes: api.PipeList{}}
	for _, p := range all {
		if p.Key.Scope != scopeFor(ctx) || p.Key.Name <= after || !strings.HasPrefix(p.Key.Name, value(in.NamePrefix)) || !strings.HasPrefix(p.SourceARN, value(in.SourcePrefix)) || !strings.HasPrefix(p.TargetARN, value(in.TargetPrefix)) || (in.CurrentState != nil && p.State != value(in.CurrentState)) || (in.DesiredState != nil && p.Desired != value(in.DesiredState)) {
			continue
		}
		if len(out.Pipes) == limit {
			b, _ := json.Marshal(struct {
				Scope Scope
				After string
				Query string
			}{scopeFor(ctx), value(out.Pipes[len(out.Pipes)-1].Name), listQuery(in)})
			out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString(b)))
			break
		}
		out.Pipes = append(out.Pipes, api.Pipe{
			Arn:              new(api.PipeArn(p.Key.ARN())),
			Name:             new(api.PipeName(p.Key.Name)),
			CurrentState:     new(api.PipeState(p.State)),
			DesiredState:     new(api.RequestedPipeState(p.Desired)),
			CreationTime:     new(p.Created),
			LastModifiedTime: new(p.Modified),
			Source:           new(api.ArnOrUrl(p.SourceARN)),
			Target:           new(api.Arn(p.TargetARN)),
			Enrichment:       new(api.OptionalArn(p.EnrichmentARN)),
		})
	}
	return out, nil
}
func listQuery(in *api.ListPipesInput) string {
	return strings.Join([]string{value(in.NamePrefix), value(in.SourcePrefix), value(in.TargetPrefix), value(in.CurrentState), value(in.DesiredState)}, "\x00")
}
func validateTags(tags api.TagMap) error {
	if len(tags) > 50 {
		return invalid("A pipe supports at most 50 tags.")
	}
	for k := range tags {
		if k == "" || strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return invalid("Invalid tag key.")
		}
	}
	return nil
}
func tagConditions(tags api.TagMap) map[string][]string {
	c := map[string][]string{}
	for k, v := range tags {
		c["aws:RequestTag/"+string(k)] = []string{string(v)}
		c["aws:TagKeys"] = append(c["aws:TagKeys"], string(k))
	}
	return c
}
