package ssm

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"stackd/internal/scheduler"
)

// Event is a native Parameter Store event admitted in the parameter transaction.
type Event struct {
	Scope          Scope
	ID, DetailType string
	Detail         []byte
	Resources      []string
	At             time.Time
}

// Events joins EventBridge publication to the repository's active transaction.
type Events interface {
	PublishEvent(context.Context, Event) error
}

func (s *Service) emitChange(tx Transaction, p ParameterRecord, operation string) error {
	detail, err := json.Marshal(struct {
		Operation   string `json:"operation"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description,omitempty"`
	}{operation, p.Key.Name, p.Type, p.Description})
	if err != nil {
		return err
	}
	return s.emitParameterEvent(tx, p, "Parameter Store Change", detail)
}

func (s *Service) emitLabelChange(tx Transaction, p ParameterRecord, label string, from, to int64) error {
	previous := ""
	if from != 0 {
		previous = strconv.FormatInt(from, 10)
	}
	detail, err := json.Marshal(struct {
		Operation   string `json:"operation"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description,omitempty"`
		Label       string `json:"label"`
		From        string `json:"fromVersion"`
		To          string `json:"toVersion"`
	}{"LabelParameterVersion", p.Key.Name, p.Type, p.Description, label, previous, strconv.FormatInt(to, 10)})
	if err != nil {
		return err
	}
	return s.emitParameterEvent(tx, p, "Parameter Store Change", detail)
}

func (s *Service) emitPolicy(tx Transaction, p ParameterRecord, policy ParameterPolicy) error {
	content, err := json.Marshal(policyDocument{Type: policy.Type, Version: policy.Version, Attributes: policy.Attributes})
	if err != nil {
		return err
	}
	reason := ""
	if policy.Type == "Expiration" {
		reason = "Parameter expired and was deleted"
	}
	detail, err := json.Marshal(struct {
		Name          string `json:"parameter-name"`
		ParameterType string `json:"parameter-type"`
		Type          string `json:"policy-type"`
		Content       string `json:"policy-content"`
		Status        string `json:"action-status"`
		Reason        string `json:"action-reason,omitempty"`
	}{p.Key.Name, p.Type, policy.Type, string(content), "SUCCESS", reason})
	if err != nil {
		return err
	}
	return s.emitParameterEvent(tx, p, "Parameter Store Policy Action", detail)
}

func (s *Service) emitParameterEvent(tx Transaction, p ParameterRecord, kind string, detail []byte) error {
	if s.events == nil {
		return nil
	}
	return s.events.PublishEvent(tx.Context(), Event{Scope: p.Key.Scope, ID: identifier(), DetailType: kind, Detail: detail, Resources: []string{parameterARN(p.Key)}, At: s.clock.Now().UTC()})
}

type policyJobs struct{ s *Service }
type policyJobKey struct {
	Parameter ParameterKey
	Index     int
}

func (source policyJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	found := false
	err := source.s.repository.View(ctx, func(r Reader) error {
		p, err := r.NextPolicy()
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		index := -1
		for i, policy := range p.Policies {
			if policy.Fired || policy.Due.IsZero() {
				continue
			}
			if index < 0 || policy.Due.Before(p.Policies[index].Due) {
				index = i
			}
		}
		if index < 0 {
			return nil
		}
		key, err := json.Marshal(policyJobKey{p.Key, index})
		if err != nil {
			return err
		}
		job = scheduler.Job{Key: string(key), Version: uint64(p.CurrentVersion), Due: p.Policies[index].Due}
		found = true
		return nil
	})
	return job, found, err
}

func (source policyJobs) Run(ctx context.Context, selected scheduler.Job) error {
	var key policyJobKey
	if err := json.Unmarshal([]byte(selected.Key), &key); err != nil {
		return err
	}
	s := source.s
	return s.repository.Update(ctx, func(tx Transaction) error {
		p, err := tx.Parameter(key.Parameter)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if uint64(p.CurrentVersion) != selected.Version || key.Index < 0 || key.Index >= len(p.Policies) {
			return nil
		}
		policy := &p.Policies[key.Index]
		if policy.Fired || !policy.Due.Equal(selected.Due) || policy.Due.After(s.clock.Now()) {
			return nil
		}
		if err := s.emitPolicy(tx, p, *policy); err != nil {
			return err
		}
		if policy.Type == "Expiration" {
			return s.removeParameter(tx, p)
		}
		policy.Fired = true
		if err := tx.PutParameter(p); err != nil {
			return err
		}
		version, err := tx.Version(VersionKey{Parameter: p.Key, Version: p.CurrentVersion})
		if err != nil {
			return err
		}
		version.Policies = p.Policies
		return tx.PutVersion(version)
	})
}
