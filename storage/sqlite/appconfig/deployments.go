package appconfig

import (
	"database/sql"
	"errors"
	domain "stackd/storage/appconfig"
	"stackd/storage/sqlite/appconfig/internal/sqlcgen"
	"time"
)

func (r reader) loadDeployment(v sqlcgen.AppconfigDeployment) (domain.Deployment, error) {
	out := domain.Deployment{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ApplicationID: v.ApplicationID, EnvironmentID: v.EnvironmentID, ProfileID: v.ProfileID, StrategyID: v.StrategyID, Number: int32(v.Number), PreviousDeployment: int32(v.PreviousDeployment), ConfigurationName: v.ConfigurationName, ConfigurationVersion: v.ConfigurationVersion, VersionLabel: v.VersionLabel, LocationURI: v.LocationUri, Description: v.Description, ContentType: v.ContentType, State: v.State, Type: v.Type, ExperimentFlags: v.ExperimentFlags, GrowthType: v.GrowthType, KMSKeyIdentifier: v.KmsKeyIdentifier, KMSKeyARN: v.KmsKeyArn, Content: v.Content, DurationMinutes: int32(v.DurationMinutes), FinalBakeMinutes: int32(v.FinalBakeMinutes), GrowthFactor: v.GrowthFactor, Percentage: v.Percentage, StartedAt: v.StartedAt, CompletedAt: v.CompletedAt, Due: v.Due, Generation: v.Generation}
	out.PipelineActionID = v.PipelineActionID
	events, err := r.q.ListDeploymentEvents(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, child := range events {
		item := domain.DeploymentEvent{Type: child.Type, Description: child.Description, TriggeredBy: child.TriggeredBy, At: child.At}
		invocations, err := r.q.ListActionInvocations(r.ctx, child.RowID)
		if err != nil {
			return out, err
		}
		for _, inv := range invocations {
			item.Invocations = append(item.Invocations, domain.ActionInvocation{ID: inv.ID, ExtensionID: inv.ExtensionID, ActionName: inv.ActionName, URI: inv.Uri, RoleARN: inv.RoleArn, ErrorCode: inv.ErrorCode, ErrorMessage: inv.ErrorMessage})
		}
		out.Events = append(out.Events, item)
	}
	extensions, err := r.q.ListAppliedExtensions(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, child := range extensions {
		item := domain.AppliedExtension{AssociationID: child.AssociationID, ExtensionID: child.ExtensionID, Version: int32(child.Version)}
		parameters, err := r.q.ListAppliedExtensionParameters(r.ctx, child.RowID)
		if err != nil {
			return out, err
		}
		if len(parameters) > 0 {
			item.Parameters = make(map[string]string, len(parameters))
		}
		for _, p := range parameters {
			item.Parameters[p.Name] = p.Value
		}
		actions, err := r.q.ListAppliedExtensionActions(r.ctx, child.RowID)
		if err != nil {
			return out, err
		}
		for _, a := range actions {
			item.Actions = append(item.Actions, domain.ExtensionAction{Point: a.Point, Name: a.Name, Description: a.Description, URI: a.Uri, RoleARN: a.RoleArn})
		}
		out.Extensions = append(out.Extensions, item)
	}
	parameters, err := r.q.ListDynamicParameters(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	if len(parameters) > 0 {
		out.DynamicParameters = make(map[string][]string, len(parameters))
	}
	for _, p := range parameters {
		values, err := r.q.ListDynamicValues(r.ctx, p.RowID)
		if err != nil {
			return out, err
		}
		out.DynamicParameters[p.Name] = values
	}
	return out, nil
}
func (r reader) Deployments(s domain.Scope, applicationID string, environmentID string) ([]domain.Deployment, error) {
	rows, err := r.q.ListDeployments(r.ctx, sqlcgen.ListDeploymentsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID, EnvironmentID: environmentID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Deployment, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadDeployment(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutDeployment(v domain.Deployment) error {
	id, err := w.q.PutDeployment(w.ctx, sqlcgen.PutDeploymentParams{PipelineActionID: v.PipelineActionID, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApplicationID: v.ApplicationID, EnvironmentID: v.EnvironmentID, ProfileID: v.ProfileID, StrategyID: v.StrategyID, Number: int64(v.Number), PreviousDeployment: int64(v.PreviousDeployment), ConfigurationName: v.ConfigurationName, ConfigurationVersion: v.ConfigurationVersion, VersionLabel: v.VersionLabel, LocationUri: v.LocationURI, Description: v.Description, ContentType: v.ContentType, State: v.State, Type: v.Type, ExperimentFlags: v.ExperimentFlags, GrowthType: v.GrowthType, KmsKeyIdentifier: v.KMSKeyIdentifier, KmsKeyArn: v.KMSKeyARN, Content: contentBytes(v.Content), DurationMinutes: int64(v.DurationMinutes), FinalBakeMinutes: int64(v.FinalBakeMinutes), GrowthFactor: v.GrowthFactor, Percentage: v.Percentage, StartedAt: v.StartedAt.UTC(), CompletedAt: v.CompletedAt.UTC(), Due: v.Due.UTC(), Generation: v.Generation})
	if err != nil {
		return err
	}
	if err = w.q.ClearDeploymentEvents(w.ctx, id); err != nil {
		return err
	}
	for ordinal, child := range v.Events {
		childID, err := w.q.InsertDeploymentEvent(w.ctx, sqlcgen.InsertDeploymentEventParams{ParentID: id, Ordinal: int64(ordinal), Type: child.Type, Description: child.Description, TriggeredBy: child.TriggeredBy, At: child.At.UTC()})
		if err != nil {
			return err
		}
		for i, inv := range child.Invocations {
			if err = w.q.InsertActionInvocation(w.ctx, sqlcgen.InsertActionInvocationParams{ParentID: childID, Ordinal: int64(i), ID: inv.ID, ExtensionID: inv.ExtensionID, ActionName: inv.ActionName, Uri: inv.URI, RoleArn: inv.RoleARN, ErrorCode: inv.ErrorCode, ErrorMessage: inv.ErrorMessage}); err != nil {
				return err
			}
		}
	}
	if err = w.q.ClearAppliedExtensions(w.ctx, id); err != nil {
		return err
	}
	for ordinal, child := range v.Extensions {
		childID, err := w.q.InsertAppliedExtension(w.ctx, sqlcgen.InsertAppliedExtensionParams{ParentID: id, Ordinal: int64(ordinal), AssociationID: child.AssociationID, ExtensionID: child.ExtensionID, Version: int64(child.Version)})
		if err != nil {
			return err
		}
		for name, value := range child.Parameters {
			if err = w.q.InsertAppliedExtensionParameter(w.ctx, sqlcgen.InsertAppliedExtensionParameterParams{ParentID: childID, Name: name, Value: value}); err != nil {
				return err
			}
		}
		for i, a := range child.Actions {
			if err = w.q.InsertAppliedExtensionAction(w.ctx, sqlcgen.InsertAppliedExtensionActionParams{ParentID: childID, Ordinal: int64(i), Point: a.Point, Name: a.Name, Description: a.Description, Uri: a.URI, RoleArn: a.RoleARN}); err != nil {
				return err
			}
		}
	}
	if err = w.q.ClearDynamicParameters(w.ctx, id); err != nil {
		return err
	}
	for name, values := range v.DynamicParameters {
		parameterID, err := w.q.InsertDynamicParameter(w.ctx, sqlcgen.InsertDynamicParameterParams{ParentID: id, Name: name})
		if err != nil {
			return err
		}
		for i, value := range values {
			if err = w.q.InsertDynamicValue(w.ctx, sqlcgen.InsertDynamicValueParams{ParentID: parameterID, Ordinal: int64(i), Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteDeployment(s domain.Scope, applicationID string, environmentID string, number int32) error {
	return w.q.DeleteDeployment(w.ctx, sqlcgen.DeleteDeploymentParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID, EnvironmentID: environmentID, Number: int64(number)})
}

func (r reader) loadSession(v sqlcgen.AppconfigSession) (domain.Session, error) {
	out := domain.Session{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Token: v.Token, ClientID: v.ClientID, ApplicationID: v.ApplicationID, EnvironmentID: v.EnvironmentID, ProfileID: v.ProfileID, LastDeployment: int32(v.LastDeployment), PollSeconds: int32(v.PollSeconds), CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, NextPoll: v.NextPoll}
	return out, nil
}
func (r reader) Session(s domain.Scope, token string) (domain.Session, bool, error) {
	v, err := r.q.GetSession(r.ctx, sqlcgen.GetSessionParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: token})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Session{}, false, nil
	}
	if err != nil {
		return domain.Session{}, false, err
	}
	out, err := r.loadSession(v)
	return out, err == nil, err
}

func (r reader) Sessions(s domain.Scope) ([]domain.Session, error) {
	rows, err := r.q.ListSessions(r.ctx, sqlcgen.ListSessionsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadSession(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutSession(v domain.Session) error {
	return w.q.PutSession(w.ctx, sqlcgen.PutSessionParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Token: v.Token, ClientID: v.ClientID, ApplicationID: v.ApplicationID, EnvironmentID: v.EnvironmentID, ProfileID: v.ProfileID, LastDeployment: int64(v.LastDeployment), PollSeconds: int64(v.PollSeconds), CreatedAt: v.CreatedAt.UTC(), ExpiresAt: v.ExpiresAt.UTC(), NextPoll: v.NextPoll.UTC()})
}
func (w writer) DeleteSession(s domain.Scope, token string) error {
	return w.q.DeleteSession(w.ctx, sqlcgen.DeleteSessionParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, Token: token})
}

// PendingDeployments includes every retained deadline, regardless of lifecycle state.
func (r reader) PendingDeployments() ([]domain.Deployment, error) {
	rows, err := r.q.ListPendingDeployments(r.ctx, time.Time{})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Deployment, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadDeployment(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
