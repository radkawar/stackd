package appconfig

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"time"

	api "stackd/internal/awsapi/appconfig"
)

func registerDeployments(s *Service) {
	registerExternal(s, "StartDeployment", s.startDeployment)
	registerExternal(s, "ValidateConfiguration", s.validateConfiguration)
	register(s, "GetDeployment", func(tx Transaction, in *api.GetDeploymentInput) (*api.GetDeploymentOutput, error) {
		app, env, err := s.deploymentEnvironment(tx, "GetDeployment", value(in.ApplicationId), value(in.EnvironmentId))
		if err != nil {
			return nil, err
		}
		d, err := findDeployment(tx, app.Scope, app.ID, env.ID, number(in.DeploymentNumber))
		if err != nil {
			return nil, err
		}
		if err = s.authorizeDeployment(tx, "GetDeployment", d); err != nil {
			return nil, err
		}
		out := deploymentOutput(d)
		return &out, nil
	})
	register(s, "ListDeployments", func(tx Transaction, in *api.ListDeploymentsInput) (*api.ListDeploymentsOutput, error) {
		app, env, err := s.deploymentEnvironment(tx, "ListDeployments", value(in.ApplicationId), value(in.EnvironmentId))
		if err != nil {
			return nil, err
		}
		rows, err := tx.Deployments(app.Scope, app.ID, env.ID)
		if err != nil {
			return nil, err
		}
		slices.SortFunc(rows, func(a, b Deployment) int {
			if a.Number > b.Number {
				return -1
			}
			if a.Number < b.Number {
				return 1
			}
			return 0
		})
		rows, next, err := page(rows, in.NextToken, in.MaxResults, pageBinding(app.Scope, "ListDeployments", app.ID, env.ID), func(i int) pageKey { return pageKey{Number: -int64(rows[i].Number)} })
		if err != nil {
			return nil, err
		}
		out := &api.ListDeploymentsOutput{NextToken: next, Items: api.DeploymentList{}}
		for _, d := range rows {
			p := deploymentOutput(d)
			out.Items = append(out.Items, api.DeploymentSummary{CompletedAt: p.CompletedAt, ConfigurationName: p.ConfigurationName, ConfigurationProfileId: p.ConfigurationProfileId, ConfigurationVersion: p.ConfigurationVersion, DeploymentDurationInMinutes: p.DeploymentDurationInMinutes, DeploymentNumber: p.DeploymentNumber, FinalBakeTimeInMinutes: p.FinalBakeTimeInMinutes, GrowthFactor: p.GrowthFactor, GrowthType: p.GrowthType, PercentageComplete: p.PercentageComplete, StartedAt: p.StartedAt, State: p.State, Type: new(api.DeploymentType(d.Type)), VersionLabel: p.VersionLabel})
		}
		return out, nil
	})
	register(s, "StopDeployment", s.stopDeployment)
}

func deployOptional[T ~string](v string) *T {
	if v == "" {
		return nil
	}
	return new(T(v))
}
func deploymentActive(d Deployment) bool {
	return d.State == "VALIDATING" || d.State == "DEPLOYING" || d.State == "BAKING" || d.State == "ROLLING_BACK"
}
func findDeployment(r Reader, scope Scope, app, env string, n int32) (Deployment, error) {
	rows, err := r.Deployments(scope, app, env)
	if err != nil {
		return Deployment{}, err
	}
	for _, d := range rows {
		if d.Number == n {
			return d, nil
		}
	}
	return Deployment{}, failure("ResourceNotFoundException", "Deployment not found")
}
func (s *Service) deploymentEnvironment(r Reader, action, application, environment string) (Application, Environment, error) {
	scope := scopeFor(r.Context())
	app, err := findApplication(r, scope, application)
	if err != nil {
		return app, Environment{}, err
	}
	env, err := findEnvironment(r, scope, app.ID, environment)
	if err != nil {
		return app, env, err
	}
	for _, resource := range []string{appARN(scope, app.ID), envARN(scope, app.ID, env.ID)} {
		tags, e := r.Tags(scope, resource)
		if e != nil {
			return app, env, e
		}
		if e = s.authorize(r.Context(), action, resource, tags); e != nil {
			return app, env, e
		}
	}
	return app, env, nil
}
func (s *Service) authorizeDeployment(r Reader, action string, d Deployment) error {
	resource := deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number)
	tags, err := r.Tags(d.Scope, resource)
	if err != nil {
		return err
	}
	return s.authorize(r.Context(), action, resource, tags)
}
func deploymentOutput(d Deployment) api.Deployment {
	out := api.Deployment{ApplicationId: new(api.Id(d.ApplicationID)), EnvironmentId: new(api.Id(d.EnvironmentID)), ConfigurationProfileId: new(api.Id(d.ProfileID)), DeploymentStrategyId: deployOptional[api.Id](d.StrategyID), DeploymentNumber: new(api.Integer(d.Number)), ConfigurationName: new(api.Name(d.ConfigurationName)), ConfigurationLocationUri: new(api.Uri(d.LocationURI)), ConfigurationVersion: new(api.Version(d.ConfigurationVersion)), Description: deployOptional[api.Description](d.Description)}
	// The deployed bytes are only returned through the data APIs.
	out.DeploymentDurationInMinutes = new(api.MinutesBetween0And24Hours(d.DurationMinutes))
	out.FinalBakeTimeInMinutes = new(api.MinutesBetween0And24Hours(d.FinalBakeMinutes))
	out.GrowthFactor = new(api.Percentage(d.GrowthFactor))
	out.GrowthType = new(api.GrowthType(d.GrowthType))
	out.PercentageComplete = new(api.Percentage(d.Percentage))
	out.StartedAt = new(d.StartedAt)
	out.State = new(api.DeploymentState(d.State))
	out.VersionLabel = deployOptional[api.VersionLabel](d.VersionLabel)
	out.KmsKeyIdentifier = deployOptional[api.KmsKeyIdentifier](d.KMSKeyIdentifier)
	out.KmsKeyArn = deployOptional[api.Arn](d.KMSKeyARN)
	if !d.CompletedAt.IsZero() {
		out.CompletedAt = new(d.CompletedAt)
	}
	for _, e := range d.Events {
		event := api.DeploymentEvent{EventType: new(api.DeploymentEventType(e.Type)), Description: new(api.Description(e.Description)), TriggeredBy: new(api.TriggeredBy(e.TriggeredBy)), OccurredAt: new(e.At)}
		for _, a := range e.Invocations {
			event.ActionInvocations = append(event.ActionInvocations, api.ActionInvocation{ActionName: new(api.Name(a.ActionName)), ErrorCode: deployOptional[api.String](a.ErrorCode), ErrorMessage: deployOptional[api.String](a.ErrorMessage), ExtensionIdentifier: new(api.Identifier(a.ExtensionID)), InvocationId: new(api.Id(a.ID)), RoleArn: deployOptional[api.Arn](a.RoleARN), Uri: new(api.Uri(a.URI))})
		}
		out.EventLog = append(out.EventLog, event)
	}
	for _, e := range d.Extensions {
		p := api.ParameterValueMap{}
		for k, v := range e.Parameters {
			p[api.ExtensionOrParameterName(k)] = api.StringWithLengthBetween1And2048(v)
		}
		out.AppliedExtensions = append(out.AppliedExtensions, api.AppliedExtension{ExtensionAssociationId: new(api.Id(e.AssociationID)), ExtensionId: new(api.Id(e.ExtensionID)), VersionNumber: new(api.Integer(e.Version)), Parameters: p})
	}
	return out
}

type deploymentAdmission struct {
	app          Application
	env          Environment
	profile      Profile
	strategy     Strategy
	hosted       *HostedVersion
	associations []Association
	extensions   []Extension
	latest       int32
	previous     int32
	recovered    *Deployment
}

func (s *Service) admission(r Reader, in *api.StartDeploymentInput) (deploymentAdmission, error) {
	var a deploymentAdmission
	var err error
	a.app, a.env, err = s.deploymentEnvironment(r, "StartDeployment", value(in.ApplicationId), value(in.EnvironmentId))
	if err != nil {
		return a, err
	}
	a.profile, err = findProfile(r, a.app.Scope, a.app.ID, value(in.ConfigurationProfileId))
	if err != nil {
		return a, err
	}
	a.strategy, err = findStrategy(r, a.app.Scope, value(in.DeploymentStrategyId))
	if err != nil {
		return a, err
	}
	for _, resource := range []string{profileARN(a.app.Scope, a.app.ID, a.profile.ID), strategyARN(a.app.Scope, a.strategy.ID)} {
		tags, e := r.Tags(a.app.Scope, resource)
		if e != nil {
			return a, e
		}
		if e = s.authorize(r.Context(), "StartDeployment", resource, tags); e != nil {
			return a, e
		}
	}
	rows, err := r.Deployments(a.app.Scope, a.app.ID, a.env.ID)
	if err != nil {
		return a, err
	}
	if actionID := pipelineActionID(r.Context()); actionID != "" {
		for _, d := range rows {
			if d.PipelineActionID == actionID {
				a.recovered = &d
				return a, nil
			}
		}
	}
	for _, d := range rows {
		if d.Number > a.latest {
			a.latest = d.Number
		}
		if deploymentActive(d) {
			return a, failure("ConflictException", "A deployment is already in progress for this environment")
		}
		if d.ProfileID == a.profile.ID && d.State == "COMPLETE" && d.Number > a.previous {
			a.previous = d.Number
		}
	}
	if len(in.Tags) > 0 {
		if err := s.authorize(r.Context(), "TagResource", deploymentARN(a.app.Scope, a.app.ID, a.env.ID, a.latest+1), nil); err != nil {
			return a, err
		}
	}
	if a.profile.LocationURI == "hosted" {
		v, e := findHostedVersion(r, a.app.Scope, a.app.ID, a.profile.ID, value(in.ConfigurationVersion))
		if e != nil {
			return a, e
		}
		a.hosted = &v
	}
	associations, err := r.Associations(a.app.Scope)
	if err != nil {
		return a, err
	}
	for _, association := range associations {
		if association.ResourceARN != appARN(a.app.Scope, a.app.ID) && association.ResourceARN != envARN(a.app.Scope, a.app.ID, a.env.ID) && association.ResourceARN != profileARN(a.app.Scope, a.app.ID, a.profile.ID) {
			continue
		}
		extension, e := findExtension(r, a.app.Scope, association.ExtensionID, association.ExtensionVersion)
		if e != nil {
			return a, e
		}
		a.associations = append(a.associations, association)
		a.extensions = append(a.extensions, extension)
	}
	return a, nil
}
func (s *Service) sourceContent(ctx context.Context, p Profile, version string, hosted *HostedVersion) (ConfigurationContent, error) {
	if hosted == nil {
		if s.effects == nil {
			return ConfigurationContent{}, failure("BadRequestException", "Configuration retrieval is not configured")
		}
		return s.effects.Retrieve(ctx, p, version)
	}
	content := hosted.Content
	if hosted.KMSKeyARN != "" {
		if s.effects == nil {
			return ConfigurationContent{}, failure("BadRequestException", "KMS decryption is not configured")
		}
		var err error
		resource := profileARN(p.Scope, p.ApplicationID, p.ID) + "/hostedconfigurationversion/" + strconv.Itoa(int(hosted.Number))
		content, err = s.effects.Unprotect(ctx, p.Scope, hosted.KMSKeyARN, resource, content)
		if err != nil {
			return ConfigurationContent{}, err
		}
	}
	return ConfigurationContent{Content: content, ContentType: hosted.ContentType, Version: strconv.Itoa(int(hosted.Number)), VersionLabel: hosted.VersionLabel, Description: hosted.Description}, nil
}
func (s *Service) startDeployment(ctx context.Context, in *api.StartDeploymentInput) (*api.StartDeploymentOutput, error) {
	var a deploymentAdmission
	tags, err := createTags(in.Tags)
	if err != nil {
		return nil, err
	}
	err = s.repository.View(ctx, func(r Reader) error { var e error; a, e = s.admission(r, in); return e })
	if err != nil {
		return nil, err
	}
	if a.recovered != nil {
		out := deploymentOutput(*a.recovered)
		if err := s.recordCall(ctx, "StartDeployment", in, &out, nil); err != nil {
			return nil, err
		}
		return &out, nil
	}
	content, err := s.sourceContent(ctx, a.profile, value(in.ConfigurationVersion), a.hosted)
	if err != nil {
		return nil, err
	}
	d := Deployment{Scope: a.app.Scope, Type: "USER", ApplicationID: a.app.ID, EnvironmentID: a.env.ID, ProfileID: a.profile.ID, StrategyID: a.strategy.ID, LocationURI: a.profile.LocationURI, Number: a.latest + 1, PreviousDeployment: a.previous, ConfigurationName: a.profile.Name, Description: value(in.Description), DurationMinutes: a.strategy.DurationMinutes, FinalBakeMinutes: a.strategy.FinalBakeMinutes, GrowthFactor: a.strategy.GrowthFactor, GrowthType: a.strategy.GrowthType, DynamicParameters: map[string][]string{}, KMSKeyIdentifier: value(in.KmsKeyIdentifier)}
	d.PipelineActionID = pipelineActionID(ctx)
	for k, v := range in.DynamicExtensionParameters {
		d.DynamicParameters[string(k)] = []string{string(v)}
	}
	content, extensions, invocations, err := s.runExtensions(ctx, "PRE_START_DEPLOYMENT", a.app, &a.env, &a.profile, content, &d)
	if err != nil {
		return nil, err
	}
	d.Extensions = extensions
	if err = s.validateContent(ctx, a.profile, content.Version, content.Content); err != nil {
		return nil, err
	}
	d.ConfigurationVersion = content.Version
	d.VersionLabel = content.VersionLabel
	d.ContentType = content.ContentType
	d.Content = content.Content
	if d.KMSKeyIdentifier != "" {
		if s.effects == nil {
			return nil, failure("BadRequestException", "KMS encryption is not configured")
		}
		d.Content, d.KMSKeyARN, err = s.effects.Protect(ctx, d.Scope, d.KMSKeyIdentifier, deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number), d.Content)
		if err != nil {
			return nil, err
		}
	}
	var out api.StartDeploymentOutput
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, e := s.admission(tx, in)
		if e != nil {
			return e
		}
		if current.recovered != nil {
			out = deploymentOutput(*current.recovered)
			return s.recordCall(tx.Context(), "StartDeployment", in, &out, nil)
		}
		if !reflect.DeepEqual(a, current) {
			return failure("ConflictException", "Deployment resources changed during validation; retry the request")
		}
		now := s.clock.Now().UTC()
		d.StartedAt = now
		d.Generation = 1
		d.State = "VALIDATING"
		d.Due = now
		addDeploymentEvent(&d, "DEPLOYMENT_STARTED", "USER", "Deployment started", now, invocations)
		if len(d.Extensions) == 0 {
			d.State = "DEPLOYING"
			d.Due = nextDeploymentDue(d, now)
			if d.DurationMinutes == 0 {
				d.Percentage = 100
				d.State = "BAKING"
				if d.FinalBakeMinutes == 0 && len(a.env.Monitors) == 0 {
					d.State = "COMPLETE"
					d.CompletedAt = now
					d.Due = time.Time{}
					addDeploymentEvent(&d, "DEPLOYMENT_COMPLETED", "APPCONFIG", "Deployment completed instantly", now, nil)
				}
			}
		}
		if e = tx.PutDeployment(d); e != nil {
			return e
		}
		a.env.State = "Deploying"
		if d.State == "COMPLETE" {
			a.env.State = "ReadyForDeployment"
		}
		if e = tx.PutEnvironment(a.env); e != nil {
			return e
		}
		if e = tx.PutTags(d.Scope, deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number), tags); e != nil {
			return e
		}
		out = deploymentOutput(d)
		return s.recordCall(tx.Context(), "StartDeployment", in, &out, nil)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func addDeploymentEvent(d *Deployment, kind, by, description string, at time.Time, invocations []ActionInvocation) {
	d.Events = append([]DeploymentEvent{{Type: kind, TriggeredBy: by, Description: description, At: at, Invocations: invocations}}, d.Events...)
}
func (s *Service) stopDeployment(tx Transaction, in *api.StopDeploymentInput) (*api.StopDeploymentOutput, error) {
	app, env, err := s.deploymentEnvironment(tx, "StopDeployment", value(in.ApplicationId), value(in.EnvironmentId))
	if err != nil {
		return nil, err
	}
	d, err := findDeployment(tx, app.Scope, app.ID, env.ID, number(in.DeploymentNumber))
	if err != nil {
		return nil, err
	}
	if err = s.authorizeDeployment(tx, "StopDeployment", d); err != nil {
		return nil, err
	}
	rows, err := tx.Deployments(app.Scope, app.ID, env.ID)
	if err != nil {
		return nil, err
	}
	for _, other := range rows {
		if other.Number > d.Number {
			return nil, failure("BadRequestException", "Only the latest deployment can be stopped or reverted")
		}
	}
	now := s.clock.Now().UTC()
	revert := d.State == "COMPLETE" && boolean(in.AllowRevert)
	if revert {
		if now.After(d.CompletedAt.Add(72 * time.Hour)) {
			return nil, failure("BadRequestException", "Completed deployments can only be reverted within 72 hours")
		}
	} else if !deploymentActive(d) || d.State == "ROLLING_BACK" {
		return nil, failure("BadRequestException", fmt.Sprintf("Deployment %d cannot be stopped, it has a status of %s", d.Number, d.State))
	}
	d.Generation++
	d.State = "ROLLED_BACK"
	kind := "ROLLBACK_COMPLETED"
	description := "Deployment rolled back by user request"
	if revert {
		d.State = "REVERTED"
		kind = "REVERT_COMPLETED"
		description = "Deployment reverted by user request"
	}
	d.Due = time.Time{}
	if !revert && len(d.Extensions) == 0 {
		d.CompletedAt = now
	}
	if len(d.Extensions) > 0 {
		d.State = "ROLLING_BACK"
		d.Due = now
		kind = "ROLLBACK_STARTED"
		description = "Deployment rollback requested by user"
	}
	addDeploymentEvent(&d, kind, "USER", description, now, nil)
	if err = tx.PutDeployment(d); err != nil {
		return nil, err
	}
	env.State = deploymentEnvironmentState(d.State)
	if err = tx.PutEnvironment(env); err != nil {
		return nil, err
	}
	out := deploymentOutput(d)
	return &out, nil
}
func (s *Service) validateConfiguration(ctx context.Context, in *api.ValidateConfigurationInput) (*api.ValidateConfigurationOutput, error) {
	var app Application
	var p Profile
	var hosted *HostedVersion
	read := func(r Reader) error {
		var err error
		app, err = findApplication(r, scopeFor(ctx), value(in.ApplicationId))
		if err != nil {
			return err
		}
		p, err = findProfile(r, app.Scope, app.ID, value(in.ConfigurationProfileId))
		if err != nil {
			return err
		}
		for _, resource := range []string{appARN(app.Scope, app.ID), profileARN(app.Scope, app.ID, p.ID)} {
			tags, e := r.Tags(app.Scope, resource)
			if e != nil {
				return e
			}
			if e = s.authorize(r.Context(), "ValidateConfiguration", resource, tags); e != nil {
				return e
			}
		}
		if p.LocationURI == "hosted" {
			v, e := findHostedVersion(r, app.Scope, app.ID, p.ID, value(in.ConfigurationVersion))
			if e != nil {
				return e
			}
			hosted = &v
		}
		return nil
	}
	if err := s.repository.View(ctx, read); err != nil {
		return nil, err
	}
	before := p
	beforeHosted := hosted
	content, err := s.sourceContent(ctx, p, value(in.ConfigurationVersion), hosted)
	if err != nil {
		return nil, err
	}
	if err = s.validateContent(ctx, p, content.Version, content.Content); err != nil {
		return nil, err
	}
	out := &api.ValidateConfigurationOutput{}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		if e := read(tx); e != nil {
			return e
		}
		if !reflect.DeepEqual(before, p) || !reflect.DeepEqual(beforeHosted, hosted) {
			return failure("ConflictException", "Configuration changed during validation")
		}
		return s.recordCall(tx.Context(), "ValidateConfiguration", in, out, nil)
	})
	return out, err
}
