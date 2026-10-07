package cloudformation

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ssmDynamicReference = regexp.MustCompile(`\{\{resolve:ssm:([a-zA-Z0-9_./-]+)(?::([0-9]+))?\}\}`)

func hasDynamicReferences(value any) bool {
	switch v := value.(type) {
	case Properties:
		return hasDynamicReferences(map[string]any(v))
	case map[string]any:
		for _, item := range v {
			if hasDynamicReferences(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if hasDynamicReferences(item) {
				return true
			}
		}
	case string:
		return strings.Contains(v, "{{resolve:")
	}
	return false
}

// resolveDynamicProperties runs only outside repository transactions. It replaces
// complete references after intrinsic evaluation, never scans substituted values
// recursively, and keeps only selected versions in durable deployment state.
func (s *Service) resolveDynamicProperties(ctx context.Context, properties Properties, versions map[string]int64) (Properties, map[string]int64, []string, error) {
	if !hasDynamicReferences(properties) {
		return properties, versions, nil, nil
	}
	pins := make(map[string]int64, len(versions))
	for key, version := range versions {
		pins[key] = version
	}
	values := map[string]string{}
	var secrets []string
	var resolve func(any) (any, error)
	resolve = func(value any) (any, error) {
		switch v := value.(type) {
		case map[string]any:
			out := make(map[string]any, len(v))
			for _, key := range templateKeys(v) {
				item, err := resolve(v[key])
				if err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				out[key] = item
			}
			return out, nil
		case []any:
			out := make([]any, len(v))
			for i, item := range v {
				resolved, err := resolve(item)
				if err != nil {
					return nil, err
				}
				out[i] = resolved
			}
			return out, nil
		case string:
			if !strings.Contains(v, "{{resolve:") {
				return v, nil
			}
			if err := templateDynamicReference(v); err != nil {
				return nil, err
			}
			matches := ssmDynamicReference.FindAllStringSubmatchIndex(v, -1)
			if strings.Contains(ssmDynamicReference.ReplaceAllString(v, ""), "{{resolve:") {
				return nil, invalid("Invalid SSM dynamic reference; use a parameter name and optional positive numeric version")
			}
			source, ok := s.parameters.(ParameterVersionSource)
			if !ok {
				return nil, invalid("Version-aware SSM parameter source is unavailable")
			}
			var out strings.Builder
			end := 0
			for _, match := range matches {
				reference := v[match[0]:match[1]]
				value, found := values[reference]
				if !found {
					name := v[match[2]:match[3]]
					version := pins[reference]
					if match[4] >= 0 {
						var err error
						version, err = strconv.ParseInt(v[match[4]:match[5]], 10, 64)
						if err != nil || version < 1 {
							return nil, invalid("SSM dynamic reference version must be a positive integer")
						}
					}
					if version > 0 {
						name += ":" + strconv.FormatInt(version, 10)
					}
					var selected int64
					var err error
					value, selected, err = source.ResolveParameterVersion(ctx, name)
					if err != nil {
						return nil, err
					}
					if selected < 1 || (version > 0 && selected != version) {
						return nil, invalid("SSM returned a different parameter version")
					}
					pins[reference], values[reference] = selected, value
					if value != "" {
						secrets = append(secrets, value)
					}
				}
				out.WriteString(v[end:match[0]])
				out.WriteString(value)
				end = match[1]
			}
			out.WriteString(v[end:])
			return out.String(), nil
		default:
			return value, nil
		}
	}
	out, err := resolve(map[string]any(properties))
	if err != nil {
		return nil, pins, secrets, redactDynamicError(err, secrets)
	}
	return Properties(out.(map[string]any)), pins, secrets, nil
}

type dynamicReferenceError struct {
	cause   error
	message string
}

func (e *dynamicReferenceError) Error() string { return e.message }
func (e *dynamicReferenceError) Unwrap() error { return e.cause }
func redactDynamicError(err error, secrets []string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, value := range secrets {
		message = strings.ReplaceAll(message, value, "****")
	}
	return &dynamicReferenceError{cause: err, message: message}
}

func (s *Service) resolveDynamicIntent(ctx, commandCtx context.Context, stack StackRecord, op OperationRecord, step StepRecord, cause error) error {
	var props, before Properties
	var secrets []string
	if cause == nil {
		props, step.After.DynamicReferences, secrets, cause = s.resolveDynamicProperties(commandCtx, step.After.Properties, step.After.DynamicReferences)
	}
	if cause == nil {
		var prior []string
		before, _, prior, cause = s.resolveDynamicProperties(commandCtx, step.Before.Properties, step.Before.DynamicReferences)
		secrets = append(secrets, prior...)
	}
	if cause == nil {
		h := s.handlers[step.After.Type]
		if h == nil {
			cause = invalid("Resource handler is unavailable: " + step.After.Type)
		} else {
			if validator, ok := h.(ResourceUpdateValidator); ok && step.Before.PhysicalID != "" && step.Before.Type == step.After.Type {
				cause = validator.ValidateUpdate(before, props)
			} else {
				cause = h.Validate(props)
			}
			if cause == nil {
				replace := step.Before.PhysicalID != "" && step.Before.Type != step.After.Type
				if step.Before.PhysicalID != "" && !replace {
					if planner, ok := h.(ResourceContextualReplacementPlanner); ok {
						request := resourceRequest(stack, op, step.After, before)
						request.Properties = props
						request.PhysicalID, request.Token = step.Before.PhysicalID, step.Before.Token
						replace, cause = planner.ReplacementForResource(commandCtx, request)
					} else {
						replace, cause = RequiresReplacement(h, stack.Scope, before, props)
					}
				}
				if cause == nil {
					cause = resolveStepAction(&step, replace)
				}
				if cause == nil && step.Action == "REPLACE" {
					cause = h.Validate(props)
				}
			}
		}
	}
	cause = redactDynamicError(cause, secrets)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Operation(op.ID)
		if err != nil {
			return err
		}
		if current.Phase != op.Phase || current.Revision != op.Revision || current.Cursor != op.Cursor || current.Steps[op.Cursor].State != "RESOLVING" {
			return nil
		}
		stack, err = tx.Stack(op.StackID)
		if err != nil {
			return err
		}
		if stack.OperationID != op.ID {
			return nil
		}
		op.Cancel = current.Cancel
		if op.Cancel {
			return s.startRollback(tx, &stack, &op, "Update cancelled by user")
		}
		var pending *ResourcePendingError
		if errors.As(cause, &pending) {
			op.Steps[op.Cursor] = step
			op.Revision++
			op.Due = s.clock.Now().Add(time.Second)
			return tx.PutOperation(op)
		}
		if cause != nil {
			return s.failResourceAdmission(tx, &stack, &op, step, cause)
		}
		step.State = "PENDING"
		op.Steps[op.Cursor] = step
		op.Revision++
		op.Due = s.clock.Now()
		return tx.PutOperation(op)
	})
}

// dynamicRequest resolves only ephemeral handler inputs; retained resource and
// event properties remain intrinsic-evaluated dynamic reference expressions.
func (s *Service) dynamicRequest(ctx context.Context, request ResourceRequest, resource, previous ResourceRecord) (ResourceRequest, []string, error) {
	props, _, secrets, err := s.resolveDynamicProperties(ctx, resource.Properties, resource.DynamicReferences)
	if err != nil {
		return request, secrets, err
	}
	prior, _, oldSecrets, err := s.resolveDynamicProperties(ctx, previous.Properties, previous.DynamicReferences)
	secrets = append(secrets, oldSecrets...)
	request.Properties, request.Previous = props, prior
	return request, secrets, redactDynamicError(err, secrets)
}
