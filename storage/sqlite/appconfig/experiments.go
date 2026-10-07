package appconfig

import (
	"database/sql"
	"errors"

	domain "stackd/storage/appconfig"
	"stackd/storage/sqlite/appconfig/internal/sqlcgen"
)

func experimentBool(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func (r reader) ExperimentDefinitions(sc domain.Scope, app string) ([]domain.ExperimentDefinition, error) {
	rows, e := r.q.ListExperimentDefinitions(r.ctx, sqlcgen.ListExperimentDefinitionsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ApplicationID: app})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ExperimentDefinition, 0, len(rows))
	for _, row := range rows {
		v, e := r.loadExperimentDefinition(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) loadExperimentDefinition(v sqlcgen.AppconfigExperimentDefinition) (domain.ExperimentDefinition, error) {
	out := domain.ExperimentDefinition{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ApplicationID: v.ApplicationID, ID: v.ID, Name: v.Name, EnvironmentID: v.EnvironmentID, ProfileID: v.ProfileID, FlagKey: v.FlagKey, AudienceRule: v.AudienceRule, AudienceDescription: v.AudienceDescription, Hypothesis: v.Hypothesis, LaunchCriteria: v.LaunchCriteria, KMSKeyIdentifier: v.KmsKeyIdentifier, Status: v.Status, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	rows, e := r.q.ListExperimentTreatments(r.ctx, v.RowID)
	if e != nil {
		return out, e
	}
	for _, row := range rows {
		t := domain.ExperimentTreatment{Key: row.TreatmentKey, Description: row.Description, Weight: row.Weight, Enabled: row.Enabled != 0, Attributes: map[string]domain.ExperimentAttribute{}}
		attrs, e := r.q.ListExperimentAttributes(r.ctx, row.RowID)
		if e != nil {
			return out, e
		}
		for _, attr := range attrs {
			a := domain.ExperimentAttribute{Kind: attr.Kind, Boolean: attr.BooleanValue != 0, Number: attr.NumberValue, String: attr.StringValue}
			if a.Kind == "numbers" {
				a.Numbers = []float64{}
			} else if a.Kind == "strings" {
				a.Strings = []string{}
			}
			items, e := r.q.ListExperimentAttributeItems(r.ctx, attr.RowID)
			if e != nil {
				return out, e
			}
			for _, item := range items {
				if a.Kind == "numbers" {
					a.Numbers = append(a.Numbers, item.NumberValue)
				} else {
					a.Strings = append(a.Strings, item.StringValue)
				}
			}
			t.Attributes[attr.Name] = a
		}
		if row.Ordinal == 0 {
			out.Control = t
		} else {
			out.Treatments = append(out.Treatments, t)
		}
	}
	return out, nil
}
func (w writer) PutExperimentDefinition(v domain.ExperimentDefinition) error {
	_, e := w.putExperimentDefinition(v, 0)
	return e
}
func (w writer) putExperimentDefinition(v domain.ExperimentDefinition, snapshot int32) (int64, error) {
	id, e := w.q.PutExperimentDefinition(w.ctx, sqlcgen.PutExperimentDefinitionParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApplicationID: v.ApplicationID, ID: v.ID, SnapshotNumber: int64(snapshot), Name: v.Name, EnvironmentID: v.EnvironmentID, ProfileID: v.ProfileID, FlagKey: v.FlagKey, AudienceRule: v.AudienceRule, AudienceDescription: v.AudienceDescription, Hypothesis: v.Hypothesis, LaunchCriteria: v.LaunchCriteria, KmsKeyIdentifier: v.KMSKeyIdentifier, Status: v.Status, CreatedAt: v.CreatedAt.UTC(), UpdatedAt: v.UpdatedAt.UTC(), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
	if e != nil {
		return 0, e
	}
	if e = w.q.DeleteExperimentTreatments(w.ctx, id); e != nil {
		return 0, e
	}
	for ordinal := -1; ordinal < len(v.Treatments); ordinal++ {
		t := v.Control
		if ordinal >= 0 {
			t = v.Treatments[ordinal]
		}
		row, e := w.q.PutExperimentTreatment(w.ctx, sqlcgen.PutExperimentTreatmentParams{DefinitionRow: id, Ordinal: int64(ordinal + 1), TreatmentKey: t.Key, Description: t.Description, Weight: t.Weight, Enabled: experimentBool(t.Enabled)})
		if e != nil {
			return 0, e
		}
		for key, a := range t.Attributes {
			attr, e := w.q.PutExperimentAttribute(w.ctx, sqlcgen.PutExperimentAttributeParams{TreatmentRow: row, Name: key, Kind: a.Kind, BooleanValue: experimentBool(a.Boolean), NumberValue: a.Number, StringValue: a.String})
			if e != nil {
				return 0, e
			}
			for i, n := range a.Numbers {
				if e = w.q.PutExperimentAttributeItem(w.ctx, sqlcgen.PutExperimentAttributeItemParams{AttributeRow: attr, Ordinal: int64(i), NumberValue: n}); e != nil {
					return 0, e
				}
			}
			for i, s := range a.Strings {
				if e = w.q.PutExperimentAttributeItem(w.ctx, sqlcgen.PutExperimentAttributeItemParams{AttributeRow: attr, Ordinal: int64(i), StringValue: s}); e != nil {
					return 0, e
				}
			}
		}
	}
	return id, nil
}
func (w writer) DeleteExperimentDefinition(sc domain.Scope, app, id string) error {
	return w.q.DeleteExperimentDefinition(w.ctx, sqlcgen.DeleteExperimentDefinitionParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ApplicationID: app, ID: id})
}
func (r reader) ExperimentRuns(sc domain.Scope, app, id string) ([]domain.ExperimentRun, error) {
	definition, e := r.q.GetExperimentDefinitionRow(r.ctx, sqlcgen.GetExperimentDefinitionRowParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ApplicationID: app, ID: id})
	if errors.Is(e, sql.ErrNoRows) {
		return []domain.ExperimentRun{}, nil
	}
	if e != nil {
		return nil, e
	}
	rows, e := r.q.ListExperimentRuns(r.ctx, definition.RowID)
	if e != nil {
		return nil, e
	}
	out := make([]domain.ExperimentRun, 0, len(rows))
	for _, row := range rows {
		v := domain.ExperimentRun{Scope: sc, ApplicationID: app, DefinitionID: id, Number: int32(row.Number), Description: row.Description, Status: row.Status, Exposure: row.Exposure, StartedAt: row.StartedAt, UpdatedAt: row.UpdatedAt, EndedAt: row.EndedAt, Ownership: domain.CloudFormationOwnership{Owner: row.CfnOwner, Token: row.CfnToken}}
		snapshot, e := r.q.GetExperimentDefinitionRow(r.ctx, sqlcgen.GetExperimentDefinitionRowParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ApplicationID: app, ID: id, SnapshotNumber: row.Number})
		if e != nil {
			return nil, e
		}
		v.Snapshot, e = r.loadExperimentDefinition(snapshot)
		if e != nil {
			return nil, e
		}
		if row.HasResult != 0 {
			v.Result = &domain.ExperimentResult{ExecutiveSummary: row.ExecutiveSummary, ReasonsToLaunch: row.ReasonsToLaunch, ReasonsNotToLaunch: row.ReasonsNotToLaunch}
		}
		if row.HasOverrides != 0 {
			v.Overrides = map[string]string{}
		}
		overrides, e := r.q.ListExperimentOverrides(r.ctx, row.RowID)
		if e != nil {
			return nil, e
		}
		for _, o := range overrides {
			v.Overrides[o.EntityID] = o.TreatmentKey
		}
		events, e := r.q.ListExperimentEvents(r.ctx, row.RowID)
		if e != nil {
			return nil, e
		}
		for _, event := range events {
			ev := domain.ExperimentEvent{Type: event.Type, Description: event.Description, TriggeredBy: event.TriggeredBy, DeploymentARN: event.DeploymentArn, At: event.OccurredAt}
			if event.Exposure.Valid {
				ev.Exposure = new(event.Exposure.Float64)
			}
			if event.HasOverrides != 0 {
				ev.Overrides = map[string]string{}
			}
			overrides, e := r.q.ListExperimentEventOverrides(r.ctx, event.RowID)
			if e != nil {
				return nil, e
			}
			for _, o := range overrides {
				ev.Overrides[o.EntityID] = o.TreatmentKey
			}
			v.Events = append(v.Events, ev)
		}
		out = append(out, v)
	}
	return out, nil
}
func (w writer) PutExperimentRun(v domain.ExperimentRun) error {
	definition, e := w.q.GetExperimentDefinitionRow(w.ctx, sqlcgen.GetExperimentDefinitionRowParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApplicationID: v.ApplicationID, ID: v.DefinitionID})
	if e != nil {
		return e
	}
	if _, e = w.putExperimentDefinition(v.Snapshot, v.Number); e != nil {
		return e
	}
	p := sqlcgen.PutExperimentRunParams{DefinitionRow: definition.RowID, Number: int64(v.Number), Description: v.Description, Status: v.Status, Exposure: v.Exposure, HasOverrides: experimentBool(v.Overrides != nil), HasResult: experimentBool(v.Result != nil), StartedAt: v.StartedAt.UTC(), UpdatedAt: v.UpdatedAt.UTC(), EndedAt: v.EndedAt.UTC(), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token}
	if v.Result != nil {
		p.ExecutiveSummary = v.Result.ExecutiveSummary
		p.ReasonsToLaunch = v.Result.ReasonsToLaunch
		p.ReasonsNotToLaunch = v.Result.ReasonsNotToLaunch
	}
	row, e := w.q.PutExperimentRun(w.ctx, p)
	if e != nil {
		return e
	}
	if e = w.q.DeleteExperimentOverrides(w.ctx, row); e != nil {
		return e
	}
	for entity, treatment := range v.Overrides {
		if e = w.q.PutExperimentOverride(w.ctx, sqlcgen.PutExperimentOverrideParams{RunRow: row, EntityID: entity, TreatmentKey: treatment}); e != nil {
			return e
		}
	}
	if e = w.q.DeleteExperimentEvents(w.ctx, row); e != nil {
		return e
	}
	for ordinal, event := range v.Events {
		p := sqlcgen.PutExperimentEventParams{RunRow: row, Ordinal: int64(ordinal), Type: event.Type, Description: event.Description, TriggeredBy: event.TriggeredBy, DeploymentArn: event.DeploymentARN, OccurredAt: event.At.UTC(), HasOverrides: experimentBool(event.Overrides != nil)}
		if event.Exposure != nil {
			p.Exposure = sql.NullFloat64{Float64: *event.Exposure, Valid: true}
		}
		eventRow, e := w.q.PutExperimentEvent(w.ctx, p)
		if e != nil {
			return e
		}
		for entity, treatment := range event.Overrides {
			if e = w.q.PutExperimentEventOverride(w.ctx, sqlcgen.PutExperimentEventOverrideParams{EventRow: eventRow, EntityID: entity, TreatmentKey: treatment}); e != nil {
				return e
			}
		}
	}
	return nil
}
