package appconfig

import (
	domain "stackd/storage/appconfig"
	"stackd/storage/sqlite/appconfig/internal/sqlcgen"
)

func (r reader) loadApplication(v sqlcgen.AppconfigApplication) (domain.Application, error) {
	out := domain.Application{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, Name: v.Name, Description: v.Description, Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	return out, nil
}
func (r reader) Applications(s domain.Scope) ([]domain.Application, error) {
	rows, err := r.q.ListApplications(r.ctx, sqlcgen.ListApplicationsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Application, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadApplication(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutApplication(v domain.Application) error {
	return w.q.PutApplication(w.ctx, sqlcgen.PutApplicationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Name: v.Name, Description: v.Description, CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
}
func (w writer) DeleteApplication(s domain.Scope, iD string) error {
	return w.q.DeleteApplication(w.ctx, sqlcgen.DeleteApplicationParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ID: iD})
}

func (r reader) loadEnvironment(v sqlcgen.AppconfigEnvironment) (domain.Environment, error) {
	out := domain.Environment{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ApplicationID: v.ApplicationID, ID: v.ID, Name: v.Name, Description: v.Description, State: v.State, LastPoll: v.LastPoll, CreatedAt: v.CreatedAt, Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	monitors, err := r.q.ListMonitors(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, child := range monitors {
		item := domain.Monitor{AlarmARN: child.AlarmArn, RoleARN: child.RoleArn}
		out.Monitors = append(out.Monitors, item)
	}
	return out, nil
}
func (r reader) Environments(s domain.Scope, applicationID string) ([]domain.Environment, error) {
	rows, err := r.q.ListEnvironments(r.ctx, sqlcgen.ListEnvironmentsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Environment, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadEnvironment(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutEnvironment(v domain.Environment) error {
	id, err := w.q.PutEnvironment(w.ctx, sqlcgen.PutEnvironmentParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApplicationID: v.ApplicationID, ID: v.ID, Name: v.Name, Description: v.Description, State: v.State, LastPoll: v.LastPoll.UTC(), CreatedAt: v.CreatedAt.UTC(), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
	if err != nil {
		return err
	}
	if err = w.q.ClearMonitors(w.ctx, id); err != nil {
		return err
	}
	for ordinal, child := range v.Monitors {
		err = w.q.InsertMonitor(w.ctx, sqlcgen.InsertMonitorParams{ParentID: id, Ordinal: int64(ordinal), AlarmArn: child.AlarmARN, RoleArn: child.RoleARN})
		if err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteEnvironment(s domain.Scope, applicationID string, iD string) error {
	return w.q.DeleteEnvironment(w.ctx, sqlcgen.DeleteEnvironmentParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID, ID: iD})
}

func (r reader) loadProfile(v sqlcgen.AppconfigProfile) (domain.Profile, error) {
	out := domain.Profile{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ApplicationID: v.ApplicationID, ID: v.ID, Name: v.Name, Description: v.Description, LocationURI: v.LocationUri, RetrievalRoleARN: v.RetrievalRoleArn, Type: v.Type, KMSKeyIdentifier: v.KmsKeyIdentifier, KMSKeyARN: v.KmsKeyArn, LastPoll: v.LastPoll, NextVersion: int32(v.NextVersion), CreatedAt: v.CreatedAt, Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	validators, err := r.q.ListValidators(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, child := range validators {
		item := domain.Validator{Type: child.Type, Content: child.Content}
		out.Validators = append(out.Validators, item)
	}
	return out, nil
}
func (r reader) Profiles(s domain.Scope, applicationID string) ([]domain.Profile, error) {
	rows, err := r.q.ListProfiles(r.ctx, sqlcgen.ListProfilesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Profile, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadProfile(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutProfile(v domain.Profile) error {
	id, err := w.q.PutProfile(w.ctx, sqlcgen.PutProfileParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApplicationID: v.ApplicationID, ID: v.ID, Name: v.Name, Description: v.Description, LocationUri: v.LocationURI, RetrievalRoleArn: v.RetrievalRoleARN, Type: v.Type, KmsKeyIdentifier: v.KMSKeyIdentifier, KmsKeyArn: v.KMSKeyARN, LastPoll: v.LastPoll.UTC(), NextVersion: int64(v.NextVersion), CreatedAt: v.CreatedAt.UTC(), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
	if err != nil {
		return err
	}
	if err = w.q.ClearValidators(w.ctx, id); err != nil {
		return err
	}
	for ordinal, child := range v.Validators {
		err = w.q.InsertValidator(w.ctx, sqlcgen.InsertValidatorParams{ParentID: id, Ordinal: int64(ordinal), Type: child.Type, Content: child.Content})
		if err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteProfile(s domain.Scope, applicationID string, iD string) error {
	return w.q.DeleteProfile(w.ctx, sqlcgen.DeleteProfileParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID, ID: iD})
}

func (r reader) loadHostedVersion(v sqlcgen.AppconfigHostedVersion) (domain.HostedVersion, error) {
	out := domain.HostedVersion{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ApplicationID: v.ApplicationID, ProfileID: v.ProfileID, Number: int32(v.Number), Description: v.Description, ContentType: v.ContentType, VersionLabel: v.VersionLabel, KMSKeyARN: v.KmsKeyArn, Content: v.Content, Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	return out, nil
}
func (r reader) HostedVersions(s domain.Scope, applicationID string, profileID string) ([]domain.HostedVersion, error) {
	rows, err := r.q.ListHostedVersions(r.ctx, sqlcgen.ListHostedVersionsParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID, ProfileID: profileID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.HostedVersion, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadHostedVersion(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutHostedVersion(v domain.HostedVersion) error {
	return w.q.PutHostedVersion(w.ctx, sqlcgen.PutHostedVersionParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ApplicationID: v.ApplicationID, ProfileID: v.ProfileID, Number: int64(v.Number), Description: v.Description, ContentType: v.ContentType, VersionLabel: v.VersionLabel, KmsKeyArn: v.KMSKeyARN, Content: contentBytes(v.Content), CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
}
func (w writer) DeleteHostedVersion(s domain.Scope, applicationID string, profileID string, number int32) error {
	return w.q.DeleteHostedVersion(w.ctx, sqlcgen.DeleteHostedVersionParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ApplicationID: applicationID, ProfileID: profileID, Number: int64(number)})
}

func (r reader) loadStrategy(v sqlcgen.AppconfigStrategy) (domain.Strategy, error) {
	out := domain.Strategy{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, ID: v.ID, Name: v.Name, Description: v.Description, GrowthType: v.GrowthType, ReplicateTo: v.ReplicateTo, DurationMinutes: int32(v.DurationMinutes), FinalBakeMinutes: int32(v.FinalBakeMinutes), GrowthFactor: v.GrowthFactor, Ownership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}}
	return out, nil
}
func (r reader) Strategies(s domain.Scope) ([]domain.Strategy, error) {
	rows, err := r.q.ListStrategies(r.ctx, sqlcgen.ListStrategiesParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Strategy, 0, len(rows))
	for _, v := range rows {
		item, err := r.loadStrategy(v)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (w writer) PutStrategy(v domain.Strategy) error {
	return w.q.PutStrategy(w.ctx, sqlcgen.PutStrategyParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Name: v.Name, Description: v.Description, GrowthType: v.GrowthType, ReplicateTo: v.ReplicateTo, DurationMinutes: int64(v.DurationMinutes), FinalBakeMinutes: int64(v.FinalBakeMinutes), GrowthFactor: v.GrowthFactor, CfnOwner: v.Ownership.Owner, CfnToken: v.Ownership.Token})
}
func (w writer) DeleteStrategy(s domain.Scope, iD string) error {
	return w.q.DeleteStrategy(w.ctx, sqlcgen.DeleteStrategyParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region, ID: iD})
}
