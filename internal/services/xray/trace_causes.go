package xray

import api "stackd/internal/awsapi/xray"

func traceExceptions(e *traceEntity) api.RootCauseExceptions { return e.exceptions }

func traceResolveExceptions(v *traceView) {
	owners := map[string]*traceEntity{}
	for _, e := range v.entities {
		e.exceptions = api.RootCauseExceptions{}
		values, _ := tracePath(e.doc, "cause", "exceptions").([]any)
		for _, value := range values {
			exception, _ := value.(map[string]any)
			e.exceptions = append(e.exceptions, api.RootCauseException{Name: traceString(traceText(exception, "type")), Message: traceString(traceText(exception, "message"))})
			if id := traceText(exception, "id"); id != "" {
				owners[id] = e
			}
		}
	}
	// A string cause references an exception ID, not a segment ID. It directs the
	// causal path to the exception owner without copying its exception onto the
	// referencing entity. Unresolved references produce no exception path.
	for _, e := range v.entities {
		if reference, ok := e.doc["cause"].(string); ok {
			e.causeReference = owners[reference]
		}
	}
}

type traceCausePart struct {
	node     *traceNode
	entities []*traceEntity
	// Inferred service entries represent the receiving side of a remote call:
	// exceptions belong to the caller, and Remote is false on the receiver.
	inferred bool
}

func traceCauseCopy(path []traceCausePart) []traceCausePart {
	out := make([]traceCausePart, len(path))
	copy(out, path)
	if len(out) > 0 {
		last := len(out) - 1
		out[last].entities = append([]*traceEntity(nil), out[last].entities...)
	}
	return out
}
func traceCauseAppend(path []traceCausePart, node *traceNode, e *traceEntity, inferred bool) []traceCausePart {
	path = traceCauseCopy(path)
	if len(path) == 0 || path[len(path)-1].node != node || inferred {
		return append(path, traceCausePart{node: node, entities: []*traceEntity{e}, inferred: inferred})
	}
	path[len(path)-1].entities = append(path[len(path)-1].entities, e)
	return path
}
func traceCauseOwner(e *traceEntity) *traceNode {
	if e.row.Subsegment && e.remote() {
		for p := e.parent; p != nil; p = p.parent {
			if p.node != nil {
				return p.node
			}
		}
	}
	return e.node
}

// Flag-only leaf segments do not create exception root causes. An exception
// path or an inferred downstream failure is required; root outcome flags still
// appear independently on the summary. This distinction is native, not a
// reduction of the status codes across a trace.
func traceProjectCauses(v *traceView) {
	for _, category := range []string{"error", "fault"} {
		for _, e := range v.entities {
			if e.node == nil || !traceFlag(e.doc, category) {
				continue
			}
			// Local subsegments are evidence within their service's causal path,
			// not independent services. Only real segments and remote receivers
			// can start a cause when no flagged ancestor claims them.
			if e.row.Subsegment && !e.remote() {
				continue
			}
			// A flagged ancestor already owns this causal path. A resolved remote
			// caller without a flagged ancestor is represented by its real callee.
			if parent := e.parent; parent != nil && traceFlag(parent.doc, category) {
				detachedCaller := parent.row.Subsegment && parent.remote() && (parent.parent == nil || !traceFlag(parent.parent.doc, category))
				// A reference to another branch does not claim this inferred failure.
				// Native retains that receiver as a separate non-impacting root cause.
				detachedReference := false
				if _, referenced := parent.doc["cause"].(string); referenced && e.row.Subsegment && e.remote() && e.node.inferred {
					detachedReference = true
					for target := parent.causeReference; target != nil; target = target.parent {
						if target == e {
							detachedReference = false
							break
						}
					}
				}
				if !detachedCaller && !detachedReference {
					continue
				}
			}
			if e.row.Subsegment && e.remote() {
				resolved := false
				for _, child := range e.children {
					if !child.row.Subsegment {
						resolved = true
						break
					}
				}
				if resolved {
					continue
				}
			}
			owner := traceCauseOwner(e)
			if owner == nil {
				owner = e.node
			}
			if e.row.Subsegment && e.remote() && e.node.inferred {
				traceEmitCause(v, category, []traceCausePart{{node: e.node, entities: []*traceEntity{e}, inferred: true}}, false)
				continue
			}
			traceWalkCause(v, category, e, owner, nil, e == v.root, nil)
		}
	}
	traceResponseCause(v)
}
func traceWalkCause(v *traceView, category string, e *traceEntity, owner *traceNode, path []traceCausePart, impacting bool, target *traceEntity) {
	if _, referenced := e.doc["cause"].(string); referenced {
		target = e.causeReference
		if target == nil {
			return
		}
	}
	if target == e {
		target = nil
	}
	var selected *traceEntity
	if target != nil {
		for child := target; child != nil; child = child.parent {
			if child.parent == e {
				selected = child
				break
			}
		}
		if selected == nil {
			return
		}
	}
	path = traceCauseAppend(path, owner, e, false)
	if e.row.Subsegment && e.remote() && e.node != owner && e.node.inferred {
		path = traceCauseAppend(path, e.node, e, true)
		traceEmitCause(v, category, path, impacting)
		return
	}
	// Native selects one evidence-bearing path, preferring an inferred downstream
	// failure over a local exception. References above constrain that selection.
	// Equal-priority ordering is undocumented: use the existing stable child
	// order locally, not a claimed reproduction of AWS's ID-dependent ordering.
	before := len(v.causes[category])
	for _, inferred := range []bool{true, false} {
		for _, child := range e.children {
			if !traceFlag(child.doc, category) || (selected != nil && child != selected) {
				continue
			}
			remote := child.row.Subsegment && child.remote() && child.node != nil && child.node != owner && child.node.inferred
			if remote != inferred {
				continue
			}
			nextOwner := owner
			if !child.row.Subsegment {
				nextOwner = child.node
			}
			if nextOwner == nil {
				continue
			}
			traceWalkCause(v, category, child, nextOwner, path, impacting, target)
			if len(v.causes[category]) != before {
				return
			}
		}
	}
	// Flag-only tails are not causes. Stop at the deepest actual exception owner;
	// keep empty intermediary entities only when a descendant emits a cause.
	if len(traceExceptions(e)) > 0 {
		traceEmitCause(v, category, path, impacting)
	}
}
func traceEmitCause(v *traceView, category string, path []traceCausePart, impacting bool) {
	traceCacheCause(v, category, path, impacting)
	if category == "error" {
		services := api.ErrorRootCauseServices{}
		for _, part := range path {
			id := part.node.identity.serviceID()
			entities := api.ErrorRootCauseEntityPath{}
			for _, entity := range part.entities {
				exceptions := traceExceptions(entity)
				if part.inferred {
					exceptions = api.RootCauseExceptions{}
				}
				entities = append(entities, api.ErrorRootCauseEntity{Name: traceString(traceText(entity.doc, "name")), Remote: traceBool(entity.remote() && !part.inferred), Exceptions: exceptions})
			}
			services = append(services, api.ErrorRootCauseService{Name: id.Name, Names: id.Names, Type: id.Type, Inferred: traceBool(part.inferred || part.node.inferred), EntityPath: entities})
		}
		v.Summary.ErrorRootCauses = append(v.Summary.ErrorRootCauses, api.ErrorRootCause{ClientImpacting: traceBool(impacting), Services: services})
	} else {
		services := api.FaultRootCauseServices{}
		for _, part := range path {
			id := part.node.identity.serviceID()
			entities := api.FaultRootCauseEntityPath{}
			for _, entity := range part.entities {
				exceptions := traceExceptions(entity)
				if part.inferred {
					exceptions = api.RootCauseExceptions{}
				}
				entities = append(entities, api.FaultRootCauseEntity{Name: traceString(traceText(entity.doc, "name")), Remote: traceBool(entity.remote() && !part.inferred), Exceptions: exceptions})
			}
			services = append(services, api.FaultRootCauseService{Name: id.Name, Names: id.Names, Type: id.Type, Inferred: traceBool(part.inferred || part.node.inferred), EntityPath: entities})
		}
		v.Summary.FaultRootCauses = append(v.Summary.FaultRootCauses, api.FaultRootCause{ClientImpacting: traceBool(impacting), Services: services})
	}
}
func traceResponseCause(v *traceView) {
	if v.root == nil {
		return
	}
	rootDuration, ok := v.root.duration()
	if !ok || rootDuration <= 0 {
		return
	}
	path := []traceCausePart{{node: v.root.node, entities: []*traceEntity{v.root}}}
	current, owner := v.root, v.root.node
	for {
		var next *traceEntity
		// Native discriminators reject coverage .25 and .5, accepting .75.
		longest := rootDuration / 2
		for _, child := range current.children {
			d, complete := child.duration()
			if complete && d > longest && d <= rootDuration {
				longest = d
				next = child
			}
		}
		if next == nil {
			break
		}
		if !next.row.Subsegment {
			owner = next.node
		}
		if owner == nil {
			break
		}
		path = traceCauseAppend(path, owner, next, false)
		if next.row.Subsegment && next.remote() && next.node != owner && next.node.inferred {
			path = traceCauseAppend(path, next.node, next, true)
			break
		}
		current = next
	}
	if len(path) == 1 && len(path[0].entities) == 1 {
		return
	}
	services := api.ResponseTimeRootCauseServices{}
	for _, part := range path {
		id := part.node.identity.serviceID()
		entities := api.ResponseTimeRootCauseEntityPath{}
		for _, entity := range part.entities {
			duration, _ := entity.duration()
			entities = append(entities, api.ResponseTimeRootCauseEntity{Name: traceString(traceText(entity.doc, "name")), Coverage: traceDouble(duration / rootDuration), Remote: traceBool(entity.remote() && !part.inferred)})
		}
		services = append(services, api.ResponseTimeRootCauseService{Name: id.Name, Names: id.Names, Type: id.Type, Inferred: traceBool(part.inferred || part.node.inferred), EntityPath: entities})
	}
	v.Summary.ResponseTimeRootCauses = append(v.Summary.ResponseTimeRootCauses, api.ResponseTimeRootCause{ClientImpacting: traceBool(true), Services: services})
	traceCacheCause(v, "responsetime", path, true)
}

// Build selector values from the same decoded path as the public projection,
// without serializing and parsing the generated response model.
func traceCacheCause(v *traceView, category string, path []traceCausePart, impacting bool) {
	services := make([]any, 0, len(path))
	rootDuration := 0.0
	if v.root != nil {
		rootDuration, _ = v.root.duration()
	}
	for _, part := range path {
		id := part.node.identity
		service := map[string]any{"Names": []any{id.name}, "Inferred": part.inferred || part.node.inferred}
		if id.name != "" {
			service["Name"] = id.name
		}
		if id.kind != "" {
			service["Type"] = id.kind
		}
		entities := make([]any, 0, len(part.entities))
		for _, e := range part.entities {
			entity := map[string]any{"Remote": e.remote() && !part.inferred}
			if name := traceText(e.doc, "name"); name != "" {
				entity["Name"] = name
			}
			if category == "responsetime" {
				duration, _ := e.duration()
				entity["Coverage"] = duration / rootDuration
			} else {
				exceptions := []any{}
				if !part.inferred {
					for _, exception := range e.exceptions {
						value := map[string]any{}
						if exception.Name != nil {
							value["Name"] = string(*exception.Name)
						}
						if exception.Message != nil {
							value["Message"] = string(*exception.Message)
						}
						exceptions = append(exceptions, value)
					}
				}
				entity["Exceptions"] = exceptions
			}
			entities = append(entities, entity)
		}
		service["EntityPath"] = entities
		services = append(services, service)
	}
	v.causes[category] = append(v.causes[category], map[string]any{"ClientImpacting": impacting, "Services": services})
}
