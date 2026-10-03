package policy

import "fmt"

func (r *AuthorizationResult) identityLayer(kind Layer, policies []Policy, request Request, context evaluationContext) (Decision, error) {
	layer := LayerEvaluation{Layer: kind, Decision: ImplicitDeny}
	defer func() { r.Layers = append(r.Layers, layer) }()
	documents := make([]*Document, 0, len(policies))
	parse := Parse
	if kind == SessionLayer {
		parse = ParseSession
	}
	for _, p := range policies {
		doc, err := parse([]byte(p.Document))
		layer.Policies = append(layer.Policies, PolicyEvaluation{Source: p.Source, Version: p.Version, Decision: ImplicitDeny, Failed: err != nil})
		if err != nil {
			return ImplicitDeny, fmt.Errorf("%s policy %q: %w", kind, p.Source, err)
		}
		documents = append(documents, doc)
	}
	trace := evaluationTrace{explain: true}
	decision, err := evaluate(documents, request, context, &trace, false)
	trace.policies(layer.Policies)
	layer.Decision = decision
	return decision, err
}

func (l *LayerEvaluation) resourcePolicy(p Policy, request Request, context evaluationContext, principal Principal) (ResourceDecision, error) {
	entry := PolicyEvaluation{Source: p.Source, Version: p.Version, Decision: ImplicitDeny}
	doc, err := ParseResource([]byte(p.Document))
	if err != nil {
		entry.Failed = true
		l.Policies = append(l.Policies, entry)
		return ResourceDecision{Decision: ImplicitDeny}, fmt.Errorf("%s policy %q: %w", l.Layer, p.Source, err)
	}
	trace := evaluationTrace{explain: true}
	decision, err := evaluateResource(doc, request, context, principal, &trace, false)
	entries := []PolicyEvaluation{entry}
	trace.policies(entries)
	l.Policies = append(l.Policies, entries[0])
	return decision, err
}

func (r *AuthorizationResult) controls(kind Layer, levels []PolicyLevel, request Request, context evaluationContext) (bool, error) {
	for _, level := range levels {
		decision := ImplicitDeny
		var err error
		if kind == ServiceControlLayer {
			decision, err = r.identityLayer(kind, level.Documents, request, context)
			r.Layers[len(r.Layers)-1].TargetID = level.TargetID
		} else {
			layer := LayerEvaluation{Layer: kind, TargetID: level.TargetID}
			for _, p := range level.Documents {
				var resource ResourceDecision
				// Organizations RCP validation accepts only a wildcard principal.
				// Principal restrictions use authenticated request condition keys.
				resource, err = layer.resourcePolicy(p, request, context, Principal{})
				if err != nil || resource.Decision == ExplicitDeny {
					decision = resource.Decision
					break
				}
				if resource.Decision == Allow {
					decision = Allow
				}
			}
			layer.Decision = decision
			r.Layers = append(r.Layers, layer)
		}
		if err != nil {
			return false, err
		}
		if decision != Allow {
			reason := "A service control policy does not permit this operation."
			if kind == ResourceControlLayer {
				reason = "A resource control policy does not permit this operation."
				if decision == ExplicitDeny {
					reason = "A resource control policy explicitly denies this operation."
				}
			}
			*r = r.finish(decision, reason)
			return false, nil
		}
	}
	return true, nil
}

// AuthorizeResourceControls evaluates only resource-owner RCP levels, including
// for a verified external federation identity. The caller selects the applicable
// hierarchy and authenticates Context. Allow here satisfies only RCP restrictions;
// it grants no identity, resource or trust permissions. Errors deny access.
func AuthorizeResourceControls(request Request, levels []PolicyLevel) (AuthorizationResult, error) {
	result := AuthorizationResult{Decision: ImplicitDeny}
	context, err := requestContext(request)
	if err != nil {
		return result, err
	}
	if allowed, err := result.controls(ResourceControlLayer, levels, request, context); err != nil || !allowed {
		return result, err
	}
	return result.finish(Allow, "Resource control policy levels permit this operation."), nil
}
