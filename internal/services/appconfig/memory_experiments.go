package appconfig

import (
	"cmp"
	"maps"
	"slices"
)

type experimentDefinitionKey struct {
	Scope
	ApplicationID, ID string
}
type experimentRunKey struct {
	experimentDefinitionKey
	Number int32
}
type experimentState struct {
	definitions map[experimentDefinitionKey]ExperimentDefinition
	runs        map[experimentRunKey]ExperimentRun
}

func newExperimentState() experimentState {
	return experimentState{map[experimentDefinitionKey]ExperimentDefinition{}, map[experimentRunKey]ExperimentRun{}}
}
func cloneExperimentState(s experimentState) experimentState {
	s.definitions = maps.Clone(s.definitions)
	s.runs = maps.Clone(s.runs)
	return s
}
func cloneExperimentTreatment(v ExperimentTreatment) ExperimentTreatment {
	v.Attributes = maps.Clone(v.Attributes)
	for k, a := range v.Attributes {
		a.Numbers = slices.Clone(a.Numbers)
		a.Strings = slices.Clone(a.Strings)
		v.Attributes[k] = a
	}
	return v
}
func cloneExperimentDefinition(v ExperimentDefinition) ExperimentDefinition {
	v.Control = cloneExperimentTreatment(v.Control)
	v.Treatments = slices.Clone(v.Treatments)
	for i := range v.Treatments {
		v.Treatments[i] = cloneExperimentTreatment(v.Treatments[i])
	}
	return v
}
func cloneExperimentRun(v ExperimentRun) ExperimentRun {
	v.Snapshot = cloneExperimentDefinition(v.Snapshot)
	v.Overrides = maps.Clone(v.Overrides)
	if v.Result != nil {
		r := *v.Result
		v.Result = &r
	}
	v.Events = slices.Clone(v.Events)
	for i := range v.Events {
		v.Events[i].Overrides = maps.Clone(v.Events[i].Overrides)
		if v.Events[i].Exposure != nil {
			e := *v.Events[i].Exposure
			v.Events[i].Exposure = &e
		}
	}
	return v
}
func (r memoryReader) ExperimentDefinitions(sc Scope, app string) ([]ExperimentDefinition, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []ExperimentDefinition{}
	for _, v := range r.s.definitions {
		if v.Scope == sc && (app == "" || v.ApplicationID == app) {
			out = append(out, cloneExperimentDefinition(v))
		}
	}
	slices.SortFunc(out, func(a, b ExperimentDefinition) int {
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (r memoryReader) ExperimentRuns(sc Scope, app, definition string) ([]ExperimentRun, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	out := []ExperimentRun{}
	for _, v := range r.s.runs {
		if v.Scope == sc && v.ApplicationID == app && v.DefinitionID == definition {
			out = append(out, cloneExperimentRun(v))
		}
	}
	slices.SortFunc(out, func(a, b ExperimentRun) int { return cmp.Compare(a.Number, b.Number) })
	return out, nil
}
func (w memoryWriter) PutExperimentDefinition(v ExperimentDefinition) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.definitions[experimentDefinitionKey{v.Scope, v.ApplicationID, v.ID}] = cloneExperimentDefinition(v)
	return nil
}
func (w memoryWriter) DeleteExperimentDefinition(sc Scope, app, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := experimentDefinitionKey{sc, app, id}
	delete(w.s.definitions, key)
	for k := range w.s.runs {
		if k.experimentDefinitionKey == key {
			delete(w.s.runs, k)
		}
	}
	return nil
}
func (w memoryWriter) PutExperimentRun(v ExperimentRun) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	w.s.runs[experimentRunKey{experimentDefinitionKey{v.Scope, v.ApplicationID, v.DefinitionID}, v.Number}] = cloneExperimentRun(v)
	return nil
}
