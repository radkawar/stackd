package appconfig

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"

	api "stackd/internal/awsapi/appconfig"
)

func registerExperiments(s *Service) {
	register(s, "CreateExperimentDefinition", s.createExperimentDefinition)
	register(s, "GetExperimentDefinition", func(tx Transaction, in *api.GetExperimentDefinitionInput) (*api.ExperimentDefinition, error) {
		d, e := s.experimentDefinition(tx, "GetExperimentDefinition", value(in.ApplicationIdentifier), value(in.ExperimentDefinitionIdentifier))
		if e != nil {
			return nil, e
		}
		o := experimentDefinitionOutput(d)
		return &o, nil
	})
	register(s, "UpdateExperimentDefinition", s.updateExperimentDefinition)
	register(s, "DeleteExperimentDefinition", s.deleteExperimentDefinition)
	register(s, "ListExperimentDefinitions", s.listExperimentDefinitions)
	register(s, "GetExperimentRun", func(tx Transaction, in *api.GetExperimentRunInput) (*api.ExperimentRun, error) {
		_, r, e := s.experimentRun(tx, "GetExperimentRun", value(in.ApplicationIdentifier), value(in.ExperimentDefinitionIdentifier), number(in.Run))
		if e != nil {
			return nil, e
		}
		o := experimentRunOutput(r)
		return &o, nil
	})
	register(s, "ListExperimentRuns", s.listExperimentRuns)
	register(s, "ListExperimentRunEvents", s.listExperimentRunEvents)
	registerExternal(s, "StartExperimentRun", s.startExperimentRun)
	registerExternal(s, "UpdateExperimentRun", s.updateExperimentRun)
	registerExternal(s, "StopExperimentRun", s.stopExperimentRun)
}
func experimentDefinitionARN(sc Scope, app, id string) string {
	return arn(sc, "application/"+app+"/experimentdefinition/"+id)
}
func experimentRunARN(sc Scope, app, id string, n int32) string {
	return experimentDefinitionARN(sc, app, id) + "/experimentrun/" + strconv.Itoa(int(n))
}
func findExperimentDefinition(r Reader, sc Scope, app, id string) (ExperimentDefinition, error) {
	rows, e := r.ExperimentDefinitions(sc, app)
	if e != nil {
		return ExperimentDefinition{}, e
	}
	for _, d := range rows {
		if d.ID == id || d.Name == id {
			return d, nil
		}
	}
	return ExperimentDefinition{}, failure("ResourceNotFoundException", "Experiment definition not found: "+id)
}
func (s *Service) experimentDefinition(r Reader, action, appID, id string) (ExperimentDefinition, error) {
	sc := scopeFor(r.Context())
	a, e := s.controlApplication(r, sc, action, appID)
	if e != nil {
		return ExperimentDefinition{}, e
	}
	d, e := findExperimentDefinition(r, sc, a.ID, id)
	if e != nil {
		return d, e
	}
	tags, e := r.Tags(sc, experimentDefinitionARN(sc, a.ID, d.ID))
	if e != nil {
		return d, e
	}
	return d, s.authorizePrivate(r.Context(), action, experimentDefinitionARN(sc, a.ID, d.ID), tags, d.Ownership)
}
func (s *Service) experimentRun(r Reader, action, app, id string, n int32) (ExperimentDefinition, ExperimentRun, error) {
	d, e := s.experimentDefinition(r, action, app, id)
	if e != nil {
		return d, ExperimentRun{}, e
	}
	rows, e := r.ExperimentRuns(d.Scope, d.ApplicationID, d.ID)
	if e != nil {
		return d, ExperimentRun{}, e
	}
	for _, run := range rows {
		if run.Number == n {
			resource := experimentRunARN(d.Scope, d.ApplicationID, d.ID, n)
			tags, e := r.Tags(d.Scope, resource)
			if e != nil {
				return d, run, e
			}
			return d, run, s.authorizePrivate(r.Context(), action, resource, tags, run.Ownership)
		}
	}
	return d, ExperimentRun{}, failure("ResourceNotFoundException", fmt.Sprintf("Experiment run %d not found", n))
}
func (s *Service) createExperimentDefinition(tx Transaction, in *api.CreateExperimentDefinitionInput) (*api.ExperimentDefinition, error) {
	sc := scopeFor(tx.Context())
	app, e := s.controlApplication(tx, sc, "CreateExperimentDefinition", value(in.ApplicationIdentifier))
	if e != nil {
		return nil, e
	}
	env, e := findEnvironment(tx, sc, app.ID, value(in.EnvironmentIdentifier))
	if e != nil {
		return nil, e
	}
	p, e := findProfile(tx, sc, app.ID, value(in.ConfigurationProfileIdentifier))
	if e != nil {
		return nil, e
	}
	if p.Type != "AWS.AppConfig.FeatureFlags" || p.LocationURI != "hosted" {
		return nil, failure("BadRequestException", "Experiments require a hosted AWS.AppConfig.FeatureFlags configuration profile.")
	}
	tags, e := createTags(in.Tags)
	if e != nil {
		return nil, e
	}
	rows, e := tx.ExperimentDefinitions(sc, app.ID)
	if e != nil {
		return nil, e
	}
	for _, d := range rows {
		if d.Name == value(in.Name) {
			return nil, failure("ConflictException", "An experiment definition with that name already exists.")
		}
	}
	control, e := experimentTreatmentInput(in.Control, "c")
	if e != nil {
		return nil, e
	}
	treatments, e := experimentTreatmentInputs(in.Treatments)
	if e != nil {
		return nil, e
	}
	now := s.clock.Now().UTC()
	d := ExperimentDefinition{Scope: sc, ApplicationID: app.ID, EnvironmentID: env.ID, ProfileID: p.ID, Name: value(in.Name), FlagKey: value(in.FlagKey), AudienceRule: value(in.AudienceRule), AudienceDescription: value(in.AudienceDescription), Hypothesis: value(in.Hypothesis), LaunchCriteria: value(in.LaunchCriteria), KMSKeyIdentifier: p.KMSKeyIdentifier, Status: "IDLE", CreatedAt: now, UpdatedAt: now, Control: control, Treatments: treatments, Ownership: cloudFormationClaim(tx.Context(), "experimentdefinition")}
	d.ID = uniqueID(func(id string) bool {
		for _, d := range rows {
			if d.ID == id {
				return true
			}
		}
		return false
	})
	if e = s.authorizeTagsOnCreate(tx.Context(), experimentDefinitionARN(sc, app.ID, d.ID), tags); e != nil {
		return nil, e
	}
	if e = tx.PutExperimentDefinition(d); e != nil {
		return nil, e
	}
	if e = tx.PutTags(sc, experimentDefinitionARN(sc, app.ID, d.ID), tags); e != nil {
		return nil, e
	}
	o := experimentDefinitionOutput(d)
	return &o, nil
}
func (s *Service) updateExperimentDefinition(tx Transaction, in *api.UpdateExperimentDefinitionInput) (*api.ExperimentDefinition, error) {
	d, e := s.experimentDefinition(tx, "UpdateExperimentDefinition", value(in.ApplicationIdentifier), value(in.ExperimentDefinitionIdentifier))
	if e != nil {
		return nil, e
	}
	if d.Status != "IDLE" {
		message := fmt.Sprintf("Cannot update experiment definition %s with status %s.", d.ID, d.Status)
		if d.Status == "ACTIVE" {
			message += " Stop the current experiment run before updating the experiment definition."
		}
		return nil, failure("ConflictException", message)
	}
	if in.AudienceRule != nil {
		d.AudienceRule = value(in.AudienceRule)
	}
	if in.AudienceDescription != nil {
		d.AudienceDescription = value(in.AudienceDescription)
	}
	if in.Hypothesis != nil {
		d.Hypothesis = value(in.Hypothesis)
	}
	if in.LaunchCriteria != nil {
		d.LaunchCriteria = value(in.LaunchCriteria)
	}
	if in.Control != nil {
		d.Control, e = experimentTreatmentInput(in.Control, "c")
		if e != nil {
			return nil, e
		}
	}
	if in.Treatments != nil {
		d.Treatments, e = experimentTreatmentInputs(in.Treatments)
		if e != nil {
			return nil, e
		}
	}
	d.UpdatedAt = s.clock.Now().UTC()
	if e = tx.PutExperimentDefinition(d); e != nil {
		return nil, e
	}
	o := experimentDefinitionOutput(d)
	return &o, nil
}
func (s *Service) deleteExperimentDefinition(tx Transaction, in *api.DeleteExperimentDefinitionInput) (*api.Unit, error) {
	d, e := s.experimentDefinition(tx, "DeleteExperimentDefinition", value(in.ApplicationIdentifier), value(in.ExperimentDefinitionIdentifier))
	if e != nil {
		return nil, e
	}
	if d.Status == "ACTIVE" {
		return nil, failure("BadRequestException", fmt.Sprintf("Experiment definition %s cannot be deleted while an experiment is running.", d.ID))
	}
	switch value(in.DeleteType) {
	case "", "ARCHIVE":
		d.Status = "ARCHIVED"
		d.UpdatedAt = s.clock.Now().UTC()
		e = tx.PutExperimentDefinition(d)
	case "DESTROY":
		runs, err := tx.ExperimentRuns(d.Scope, d.ApplicationID, d.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range runs {
			if err = tx.PutTags(d.Scope, experimentRunARN(d.Scope, d.ApplicationID, d.ID, r.Number), nil); err != nil {
				return nil, err
			}
		}
		if e = tx.PutTags(d.Scope, experimentDefinitionARN(d.Scope, d.ApplicationID, d.ID), nil); e != nil {
			return nil, e
		}
		e = tx.DeleteExperimentDefinition(d.Scope, d.ApplicationID, d.ID)
	default:
		return nil, failure("BadRequestException", "DeleteType must be ARCHIVE or DESTROY.")
	}
	return &api.Unit{}, e
}
func (s *Service) listExperimentDefinitions(tx Transaction, in *api.ListExperimentDefinitionsInput) (*api.ExperimentDefinitions, error) {
	sc := scopeFor(tx.Context())
	if e := s.authorize(tx.Context(), "ListExperimentDefinitions", "*", nil); e != nil {
		return nil, e
	}
	appID := ""
	if in.ApplicationIdentifier != nil {
		a, e := findApplication(tx, sc, value(in.ApplicationIdentifier))
		if e != nil {
			return nil, e
		}
		appID = a.ID
	}
	rows, e := tx.ExperimentDefinitions(sc, appID)
	if e != nil {
		return nil, e
	}
	profileFilter, environmentFilter := value(in.ConfigurationProfileIdentifier), value(in.EnvironmentIdentifier)
	// With an application selected, names and IDs denote the same filters.
	// Without one, a name can select resources in multiple applications.
	if appID != "" {
		if in.ConfigurationProfileIdentifier != nil {
			p, err := findProfile(tx, sc, appID, profileFilter)
			if err == nil {
				profileFilter = p.ID
			} else if wireError(err).Code != "ResourceNotFoundException" {
				return nil, err
			}
		}
		if in.EnvironmentIdentifier != nil {
			env, err := findEnvironment(tx, sc, appID, environmentFilter)
			if err == nil {
				environmentFilter = env.ID
			} else if wireError(err).Code != "ResourceNotFoundException" {
				return nil, err
			}
		}
	}
	filtered := rows[:0]
	for _, d := range rows {
		if in.Status != nil && d.Status != value(in.Status) {
			continue
		}
		if in.ConfigurationProfileIdentifier != nil && profileFilter != d.ProfileID {
			p, e := findProfile(tx, sc, d.ApplicationID, profileFilter)
			if e != nil {
				if wireError(e).Code == "ResourceNotFoundException" {
					continue
				}
				return nil, e
			}
			if p.ID != d.ProfileID {
				continue
			}
		}
		if in.EnvironmentIdentifier != nil && environmentFilter != d.EnvironmentID {
			env, e := findEnvironment(tx, sc, d.ApplicationID, environmentFilter)
			if e != nil {
				if wireError(e).Code == "ResourceNotFoundException" {
					continue
				}
				return nil, e
			}
			if env.ID != d.EnvironmentID {
				continue
			}
		}
		filtered = append(filtered, d)
	}
	slices.SortFunc(filtered, func(a, b ExperimentDefinition) int {
		if n := b.CreatedAt.Compare(a.CreatedAt); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ApplicationID, b.ApplicationID); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	rows, next, e := page(filtered, in.NextToken, in.MaxResults, pageBinding(sc, "ListExperimentDefinitions", appID, profileFilter, environmentFilter, value(in.Status)), func(i int) pageKey {
		return pageKey{CreatedAt: filtered[i].CreatedAt, ID: filtered[i].ApplicationID + "/" + filtered[i].ID}
	})
	if e != nil {
		return nil, e
	}
	out := &api.ExperimentDefinitions{Items: api.ExperimentDefinitionList{}, NextToken: next}
	for _, d := range rows {
		p := experimentDefinitionOutput(d)
		out.Items = append(out.Items, api.ExperimentDefinitionSummary{ApplicationId: p.ApplicationId, ConfigurationProfileId: p.ConfigurationProfileId, CreatedAt: p.CreatedAt, EnvironmentId: p.EnvironmentId, FlagKey: p.FlagKey, Hypothesis: p.Hypothesis, Id: p.Id, Name: p.Name, Status: p.Status, UpdatedAt: p.UpdatedAt})
	}
	return out, nil
}
func (s *Service) listExperimentRuns(tx Transaction, in *api.ListExperimentRunsInput) (*api.ExperimentRuns, error) {
	d, e := s.experimentDefinition(tx, "ListExperimentRuns", value(in.ApplicationIdentifier), value(in.ExperimentDefinitionIdentifier))
	if e != nil {
		return nil, e
	}
	rows, e := tx.ExperimentRuns(d.Scope, d.ApplicationID, d.ID)
	if e != nil {
		return nil, e
	}
	filtered := rows[:0]
	for _, r := range rows {
		if in.Status == nil || r.Status == value(in.Status) {
			filtered = append(filtered, r)
		}
	}
	slices.Reverse(filtered)
	rows, next, e := page(filtered, in.NextToken, in.MaxResults, pageBinding(d.Scope, "ListExperimentRuns", d.ApplicationID, d.ID, value(in.Status)), func(i int) pageKey { return pageKey{Number: -int64(filtered[i].Number)} })
	if e != nil {
		return nil, e
	}
	out := &api.ExperimentRuns{Items: api.ExperimentRunSummaryList{}, NextToken: next}
	for _, r := range rows {
		p := experimentRunOutput(r)
		out.Items = append(out.Items, api.ExperimentRunSummary{Description: p.Description, EndedAt: p.EndedAt, ExperimentDefinitionId: p.ExperimentDefinitionId, Run: p.Run, StartedAt: p.StartedAt, Status: p.Status, UpdatedAt: p.UpdatedAt})
	}
	return out, nil
}
func (s *Service) listExperimentRunEvents(tx Transaction, in *api.ListExperimentRunEventsInput) (*api.ExperimentRunEvents, error) {
	_, r, e := s.experimentRun(tx, "ListExperimentRunEvents", value(in.ApplicationIdentifier), value(in.ExperimentDefinitionIdentifier), number(in.Run))
	if e != nil {
		return nil, e
	}
	rows, next, e := page(r.Events, in.NextToken, in.MaxResults, pageBinding(r.Scope, "ListExperimentRunEvents", r.ApplicationID, r.DefinitionID, strconv.FormatInt(int64(r.Number), 10)), func(i int) pageKey { return pageKey{Number: int64(i - len(r.Events))} })
	if e != nil {
		return nil, e
	}
	out := &api.ExperimentRunEvents{Items: api.ExperimentRunEventList{}, NextToken: next}
	for _, ev := range rows {
		v := api.ExperimentRunEvent{AssociatedDeployment: deployOptional[api.Arn](ev.DeploymentARN), Description: new(api.Description(ev.Description)), EventType: new(api.ExperimentRunEventType(ev.Type)), OccurredAt: new(ev.At), TriggeredBy: new(api.TriggeredBy(ev.TriggeredBy)), TreatmentOverrides: experimentOverridesOutput(ev.Overrides)}
		if ev.Exposure != nil {
			v.ExposurePercentage = new(api.NullablePercentage(*ev.Exposure))
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}
