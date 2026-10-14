package cloudformation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"stackd/internal/awswire"
)

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
func (s *Service) resolveDynamicProperties(ctx context.Context, properties Properties, versions map[string]DynamicReferencePin) (Properties, map[string]DynamicReferencePin, []string, error) {
	if !hasDynamicReferences(properties) {
		return properties, versions, nil, nil
	}
	pins := make(map[string]DynamicReferencePin, len(versions))
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
			var out strings.Builder
			for rest := v; ; {
				start := strings.Index(rest, "{{resolve:")
				if start < 0 {
					out.WriteString(rest)
					break
				}
				out.WriteString(rest[:start])
				rest = rest[start:]
				end := strings.Index(rest, "}}")
				if end < 0 {
					return nil, invalid("Unterminated dynamic reference")
				}
				reference := rest[:end+2]
				ref, err := parseDynamicReference(reference[len("{{resolve:") : len(reference)-2])
				if err != nil {
					return nil, err
				}
				selectedValue, found := values[reference]
				if !found {
					selectedValue, pins[reference], err = s.readDynamicReference(ctx, ref, pins[reference], &secrets)
					if err != nil {
						return nil, err
					}
					values[reference] = selectedValue
					if selectedValue != "" {
						secrets = append(secrets, selectedValue)
					}
				}
				out.WriteString(selectedValue)
				rest = rest[end+2:]
			}
			resolved := out.String()
			if resolved != "" {
				secrets = append(secrets, resolved)
			}
			return resolved, nil
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

func (s *Service) readDynamicReference(ctx context.Context, ref dynamicReference, pin DynamicReferencePin, secrets *[]string) (string, DynamicReferencePin, error) {
	if pin.Service != "" && pin.Service != ref.service {
		return "", pin, invalid("Retained dynamic reference selector has a different service")
	}
	if ref.service == "secretsmanager" {
		if s.secrets == nil {
			return "", pin, invalid("Secrets Manager dynamic reference source is unavailable")
		}
		selector := SecretVersionSelector{SecretID: ref.name, VersionStage: ref.stage, VersionID: ref.versionID}
		if pin.SecretVersionID != "" {
			if ref.versionID != "" && ref.versionID != pin.SecretVersionID {
				return "", pin, invalid("Retained Secrets Manager selector differs from the template version")
			}
			selector.VersionID, selector.VersionStage = pin.SecretVersionID, ""
		}
		raw, selected, err := s.secrets.ResolveSecretVersion(ctx, selector)
		if err != nil {
			return "", pin, err
		}
		if raw != "" {
			*secrets = append(*secrets, raw)
		}
		if selected == "" || selector.VersionID != "" && selected != selector.VersionID {
			return "", pin, invalid("Secrets Manager returned a different secret version")
		}
		pin = DynamicReferencePin{Service: ref.service, SecretVersionID: selected}
		if ref.jsonKey != "" {
			var document map[string]json.RawMessage
			if json.Unmarshal([]byte(raw), &document) != nil || document == nil {
				return "", pin, invalid("Secrets Manager JSON-key reference requires a JSON object SecretString")
			}
			item, exists := document[ref.jsonKey]
			if !exists {
				return "", pin, invalid("Could not find a value associated with JSONKey in SecretString")
			}
			value, err := dynamicSecretJSONValue(item)
			return value, pin, err
		}
		return raw, pin, nil
	}
	version := ref.version
	if version == 0 {
		version = pin.ParameterVersion
	}
	if pin.ParameterVersion > 0 && ref.version > 0 && pin.ParameterVersion != ref.version {
		return "", pin, invalid("Retained SSM selector differs from the template version")
	}
	name := ref.name
	if version > 0 {
		name += ":" + strconv.FormatInt(version, 10)
	}
	var value string
	var selected int64
	var err error
	if ref.service == "ssm-secure" {
		source, ok := s.parameters.(SecureParameterVersionSource)
		if !ok {
			return "", pin, invalid("Secure SSM parameter source is unavailable")
		}
		value, selected, err = source.ResolveSecureParameterVersion(ctx, name)
	} else {
		source, ok := s.parameters.(ParameterVersionSource)
		if !ok {
			return "", pin, invalid("Version-aware SSM parameter source is unavailable")
		}
		value, selected, err = source.ResolveParameterVersion(ctx, name)
	}
	if err != nil {
		return "", pin, err
	}
	if value != "" {
		*secrets = append(*secrets, value)
	}
	if selected < 1 || version > 0 && selected != version {
		return "", pin, invalid("SSM returned a different parameter version")
	}
	return value, DynamicReferencePin{Service: ref.service, ParameterVersion: selected}, nil
}

func dynamicSecretJSONValue(item json.RawMessage) (string, error) {
	item = bytes.TrimSpace(item)
	if len(item) > 0 && item[0] == '"' {
		var value string
		if json.Unmarshal(item, &value) != nil {
			return "", invalid("Invalid Secrets Manager JSON-key value")
		}
		return value, nil
	}
	// Native AWS calibration: numbers, booleans, objects, arrays and null are
	// stringified; containers use compact JSON, not Go's fmt representation.
	var compact bytes.Buffer
	compact.Grow(len(item))
	if json.Compact(&compact, item) != nil {
		return "", invalid("Invalid Secrets Manager JSON-key value")
	}
	return compact.String(), nil
}

func redactDynamicError(err error, secrets []string) error {
	if err == nil {
		return nil
	}
	if len(secrets) == 0 {
		return err
	}
	var pending *ResourcePendingError
	if errors.As(err, &pending) {
		return &ResourcePendingError{Reason: redactDynamicMessage(pending.Reason, secrets)}
	}
	var wire *awswire.Error
	if errors.As(err, &wire) {
		safe := *wire
		safe.Message, safe.Cause = redactDynamicMessage(wire.Message, secrets), nil
		return &safe
	}
	message := redactDynamicMessage(err.Error(), secrets)
	return errors.New(message)
}

func redactDynamicMessage(message string, secrets []string) string {
	for _, value := range secrets {
		if value == "" {
			continue
		}
		message = strings.ReplaceAll(message, value, "****")
		quoted, _ := json.Marshal(value)
		if len(quoted) > 2 {
			message = strings.ReplaceAll(message, string(quoted[1:len(quoted)-1]), "****")
		}
		goQuoted := strconv.Quote(value)
		message = strings.ReplaceAll(message, goQuoted[1:len(goQuoted)-1], "****")
	}
	return message
}

func (s *Service) resolveDynamicIntent(ctx, commandCtx context.Context, stack StackRecord, op OperationRecord, step StepRecord, cause error) error {
	var props, before Properties
	var secrets []string
	if cause == nil {
		cause = validateDynamicResourceProperties(step.After.Type, step.After.Properties)
	}
	if cause == nil && hasDynamicReferences(step.Before.Properties) {
		cause = validateDynamicResourceProperties(step.Before.Type, step.Before.Properties)
	}
	if cause == nil {
		props, step.After.DynamicReferences, secrets, cause = s.resolveDynamicProperties(commandCtx, step.After.Properties, step.After.DynamicReferences)
	}
	if cause == nil {
		var prior []string
		before, step.Before.DynamicReferences, prior, cause = s.resolveDynamicProperties(commandCtx, step.Before.Properties, step.Before.DynamicReferences)
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

// Secret version selections belong to one accepted operation, not a published
// deployment. AWS rollback re-evaluates the old template's stage/current/ID.
func withoutSecretVersionPins(pins map[string]DynamicReferencePin) map[string]DynamicReferencePin {
	secretCount := 0
	for _, pin := range pins {
		if pin.Service == "secretsmanager" {
			secretCount++
		}
	}
	if secretCount == 0 {
		return pins
	}
	if secretCount == len(pins) {
		return nil
	}
	out := make(map[string]DynamicReferencePin, len(pins)-secretCount)
	for reference, pin := range pins {
		if pin.Service != "secretsmanager" {
			out[reference] = pin
		}
	}
	return out
}

func publishedDynamicResource(resource ResourceRecord) ResourceRecord {
	resource.DynamicReferences = withoutSecretVersionPins(resource.DynamicReferences)
	return resource
}

func forgetOperationSecretVersions(op *OperationRecord) {
	for i := range op.Steps {
		step := &op.Steps[i]
		step.Before.DynamicReferences = withoutSecretVersionPins(step.Before.DynamicReferences)
		step.After.DynamicReferences = withoutSecretVersionPins(step.After.DynamicReferences)
		step.Restore.DynamicReferences = withoutSecretVersionPins(step.Restore.DynamicReferences)
	}
}

func rollbackDynamicResource(step *StepRecord) *ResourceRecord {
	if step.BeforeDeleted && (step.State == "RESTORE_RUNNING" || step.State == "RESTORE_STABILIZING") {
		return &step.Restore
	}
	if !step.BeforeDeleted && step.Action == "UPDATE" {
		return &step.Before
	}
	return nil
}

func needsRollbackSecretResolution(step *StepRecord) bool {
	resource := rollbackDynamicResource(step)
	if resource == nil {
		return false
	}
	missing := false
	_ = walkDynamicProperty(resource.Properties, "", func(text, _ string) error {
		for rest := text; ; {
			start := strings.Index(rest, "{{resolve:secretsmanager:")
			if start < 0 {
				return nil
			}
			rest = rest[start:]
			end := strings.Index(rest, "}}")
			if end < 0 {
				missing = true
				return nil
			}
			if resource.DynamicReferences[rest[:end+2]].SecretVersionID == "" {
				missing = true
				return nil
			}
			rest = rest[end+2:]
		}
	})
	return missing
}

func (s *Service) resolveRollbackSecretIntent(ctx, commandCtx context.Context, stack StackRecord, op OperationRecord, step StepRecord, cause error) error {
	resource := rollbackDynamicResource(&step)
	if resource == nil {
		return invalid("Rollback dynamic reference intent has no resource")
	}
	var secrets []string
	if cause == nil {
		cause = validateDynamicResourceProperties(resource.Type, resource.Properties)
	}
	if cause == nil {
		_, resource.DynamicReferences, secrets, cause = s.resolveDynamicProperties(commandCtx, resource.Properties, resource.DynamicReferences)
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
		if current.Phase != "ROLLBACK" || current.Revision != op.Revision || current.Cursor != op.Cursor {
			return nil
		}
		stack, err = tx.Stack(op.StackID)
		if err != nil {
			return err
		}
		if stack.OperationID != op.ID {
			return nil
		}
		op.Steps[op.Cursor] = step
		var pending *ResourcePendingError
		if cause != nil && !errors.As(cause, &pending) {
			return s.failRollback(tx, &stack, &op, cause)
		}
		op.Revision++
		op.Due = s.clock.Now()
		if pending != nil {
			op.Due = op.Due.Add(time.Second)
		}
		return tx.PutOperation(op)
	})
}

// dynamicRequest resolves only ephemeral handler inputs; retained resource and
// event properties remain intrinsic-evaluated dynamic reference expressions.
func (s *Service) dynamicRequest(ctx context.Context, request ResourceRequest, resource, previous ResourceRecord) (ResourceRequest, []string, error) {
	if err := validateDynamicResourceProperties(resource.Type, resource.Properties); err != nil {
		return request, nil, err
	}
	if hasDynamicReferences(previous.Properties) {
		if err := validateDynamicResourceProperties(previous.Type, previous.Properties); err != nil {
			return request, nil, err
		}
	}
	props, _, secrets, err := s.resolveDynamicProperties(ctx, resource.Properties, resource.DynamicReferences)
	if err != nil {
		return request, secrets, err
	}
	prior, _, oldSecrets, err := s.resolveDynamicProperties(ctx, previous.Properties, previous.DynamicReferences)
	secrets = append(secrets, oldSecrets...)
	request.Properties, request.Previous = props, prior
	return request, secrets, redactDynamicError(err, secrets)
}

// protectDynamicResult keeps write-only inputs from being echoed into durable
// CFN results by a destination. Identity echoes cannot be masked without
// breaking lifecycle addressing, so they are an explicit emulator safety limit.
func protectDynamicResult(result ResourceResult, secrets []string, properties ...Properties) (ResourceResult, error) {
	secure := false
	for _, property := range properties {
		secure = secure || hasSecureDynamicReferences(property)
	}
	if !secure {
		return result, nil
	}
	if containsResolvedValue(result.PhysicalID, secrets) || containsResolvedValue(result.Ref, secrets) {
		// TODO: Comeback support secure identifier consumption without retaining its plaintext identity.
		return ResourceResult{}, failure("NotImplementedException", "stackd cannot retain a resource identity containing a resolved secure dynamic value")
	}
	if !documentContainsResolvedValue(result.Attributes, secrets) {
		return result, nil
	}
	var redact func(any) any
	redact = func(value any) any {
		switch v := value.(type) {
		case string:
			for _, secret := range secrets {
				if secret != "" {
					v = strings.ReplaceAll(v, secret, "****")
				}
			}
			return v
		case Properties:
			return redact(map[string]any(v))
		case map[string]any:
			out := make(map[string]any, len(v))
			for key, item := range v {
				out[key] = redact(item)
			}
			return out
		case map[string]string:
			out := make(map[string]string, len(v))
			for key, item := range v {
				out[key] = redact(item).(string)
			}
			return out
		case []any:
			out := make([]any, len(v))
			for i, item := range v {
				out[i] = redact(item)
			}
			return out
		case []string:
			out := make([]string, len(v))
			for i, item := range v {
				out[i] = redact(item).(string)
			}
			return out
		default:
			return value
		}
	}
	attributes := make(map[string]any, len(result.Attributes))
	marked := maps.Clone(result.RedactedAttributes)
	if marked == nil {
		marked = make(map[string]bool)
	}
	for name, value := range result.Attributes {
		attributes[name] = redact(value)
		if documentContainsResolvedValue(value, secrets) {
			marked[name] = true
		}
	}
	result.Attributes, result.RedactedAttributes = attributes, marked
	return result, nil
}

func hasSecureDynamicReferences(value any) bool {
	switch v := value.(type) {
	case Properties:
		return hasSecureDynamicReferences(map[string]any(v))
	case map[string]any:
		for _, item := range v {
			if hasSecureDynamicReferences(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if hasSecureDynamicReferences(item) {
				return true
			}
		}
	case string:
		return strings.Contains(v, "{{resolve:ssm-secure:") || strings.Contains(v, "{{resolve:secretsmanager:")
	}
	return false
}

func containsResolvedValue(text string, values []string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(text, value) {
			return true
		}
	}
	return false
}

func documentContainsResolvedValue(value any, values []string) bool {
	switch v := value.(type) {
	case Properties:
		return documentContainsResolvedValue(map[string]any(v), values)
	case map[string]any:
		for _, item := range v {
			if documentContainsResolvedValue(item, values) {
				return true
			}
		}
	case map[string]string:
		for _, item := range v {
			if containsResolvedValue(item, values) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if documentContainsResolvedValue(item, values) {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if containsResolvedValue(item, values) {
				return true
			}
		}
	case string:
		return containsResolvedValue(v, values)
	}
	return false
}
