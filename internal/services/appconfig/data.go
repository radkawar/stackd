package appconfig

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"time"

	api "stackd/internal/awsapi/appconfig"
	dataapi "stackd/internal/awsapi/appconfigdata"
	"stackd/internal/awswire"
)

func registerDataOperations(s *Service) {
	registerData(s, "StartConfigurationSession", s.startConfigurationSession)
	registerExternalData(s, "GetLatestConfiguration", s.getLatestConfiguration)
	registerExternal(s, "GetConfiguration", s.getConfiguration)
}
func configurationARN(scope Scope, app, env, profile string) string {
	return arn(scope, "application/"+app+"/environment/"+env+"/configuration/"+profile)
}
func dataTokenError(message, problem string) *awswire.Error {
	e := failure("BadRequestException", message)
	e.Reason = "InvalidParameters"
	detail, _ := json.Marshal(map[string]any{"InvalidParameters": map[string]any{"ConfigurationToken": map[string]string{"Problem": problem}}})
	e.Details = map[string]json.RawMessage{"Details": detail}
	return e
}
func dataResourceNotFound(kind string, refs map[string]string) *awswire.Error {
	e := failure("ResourceNotFoundException", kind+" not found")
	reference, _ := json.Marshal(refs)
	resourceType, _ := json.Marshal(kind)
	e.Details = map[string]json.RawMessage{"ResourceType": resourceType, "ReferencedBy": reference}
	return e
}
func dataDeploymentNotFound(env, profile string) *awswire.Error {
	return dataResourceNotFound("Deployment", map[string]string{"EnvironmentIdentifier": env, "ConfigurationProfileIdentifier": profile})
}
func configurationMissing(err error) bool {
	var e *awswire.Error
	return errors.As(err, &e) && e.Code == "ResourceNotFoundException"
}
func configurationID(v string) bool {
	if len(v) < 4 || len(v) > 7 {
		return false
	}
	for _, c := range v {
		if c < 'a' || c > 'z' {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
func (s *Service) dataResources(r Reader, action, application, environment, configuration string) (Application, Environment, Profile, error) {
	scope := scopeFor(r.Context())
	missing := func(err error, kind, parameter, identifier string) error {
		if !configurationMissing(err) || action == "GetConfiguration" {
			return err
		}
		if action == "StartConfigurationSession" && configurationID(application) && configurationID(environment) && configurationID(configuration) {
			return dataDeploymentNotFound(environment, configuration)
		}
		return dataResourceNotFound(kind, map[string]string{parameter: identifier})
	}
	app, err := findApplication(r, scope, application)
	if err != nil {
		// Native name resolution skips the application lookup when an ID was
		// supplied, then resolves the profile before the environment.
		if action == "StartConfigurationSession" && configurationMissing(err) && configurationID(application) {
			if configurationID(environment) && configurationID(configuration) {
				return app, Environment{}, Profile{}, dataDeploymentNotFound(environment, configuration)
			}
			if _, e := findProfile(r, scope, application, configuration); e != nil {
				return app, Environment{}, Profile{}, missing(e, "ConfigurationProfile", "ConfigurationProfileIdentifier", configuration)
			}
			if _, e := findEnvironment(r, scope, application, environment); e != nil {
				return app, Environment{}, Profile{}, missing(e, "Environment", "EnvironmentIdentifier", environment)
			}
			return app, Environment{}, Profile{}, dataDeploymentNotFound(environment, configuration)
		}
		return app, Environment{}, Profile{}, missing(err, "Application", "ApplicationIdentifier", application)
	}
	p, err := findProfile(r, scope, app.ID, configuration)
	if err != nil {
		return app, Environment{}, p, missing(err, "ConfigurationProfile", "ConfigurationProfileIdentifier", configuration)
	}
	env, err := findEnvironment(r, scope, app.ID, environment)
	if err != nil {
		return app, env, p, missing(err, "Environment", "EnvironmentIdentifier", environment)
	}
	if action != "GetConfiguration" {
		setDataResource(r.Context(), app.ID, env.ID, p.ID)
	}
	resources := []string{configurationARN(scope, app.ID, env.ID, p.ID)}
	if action == "GetConfiguration" {
		resources = []string{appARN(scope, app.ID), envARN(scope, app.ID, env.ID), profileARN(scope, app.ID, p.ID)}
	}
	for _, resource := range resources {
		tags, e := r.Tags(scope, resource)
		if e != nil {
			return app, env, p, e
		}
		if e = s.authorize(r.Context(), action, resource, tags); e != nil {
			return app, env, p, e
		}
	}
	return app, env, p, nil
}
func (s *Service) startConfigurationSession(tx Transaction, in *dataapi.StartConfigurationSessionInput) (*dataapi.StartConfigurationSessionOutput, error) {
	app, env, p, err := s.dataResources(tx, "StartConfigurationSession", value(in.ApplicationIdentifier), value(in.EnvironmentIdentifier), value(in.ConfigurationProfileIdentifier))
	if err != nil {
		return nil, err
	}
	poll := int32(60)
	if in.RequiredMinimumPollIntervalInSeconds != nil {
		poll = int32(*in.RequiredMinimumPollIntervalInSeconds)
	}
	if poll < 15 || poll > 86400 {
		return nil, failure("BadRequestException", "RequiredMinimumPollIntervalInSeconds must be between 15 and 86400")
	}
	rows, err := tx.Deployments(app.Scope, app.ID, env.ID)
	if err != nil {
		return nil, err
	}
	available := false
	for _, d := range rows {
		if d.ProfileID == p.ID && (d.State == "COMPLETE" || d.State == "BAKING" || d.State == "DEPLOYING") {
			available = true
			break
		}
	}
	if !available {
		return nil, dataDeploymentNotFound(env.ID, p.ID)
	}
	token := rand.Text()
	now := s.clock.Now().UTC()
	session := Session{Scope: app.Scope, Token: token, ClientID: token, ApplicationID: app.ID, EnvironmentID: env.ID, ProfileID: p.ID, PollSeconds: poll, CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	if err = tx.PutSession(session); err != nil {
		return nil, err
	}
	return &dataapi.StartConfigurationSessionOutput{InitialConfigurationToken: new(dataapi.Token(token))}, nil
}
func findSession(r Reader, scope Scope, token string, now time.Time) (Session, error) {
	session, found, err := r.Session(scope, token)
	if err != nil {
		return Session{}, err
	}
	if !found {
		return Session{}, dataTokenError("Token not valid", "Corrupted")
	}
	if !now.Before(session.ExpiresAt) {
		return Session{}, dataTokenError("Configuration token has expired", "Expired")
	}
	if now.Before(session.NextPoll) {
		return Session{}, dataTokenError("Request too early", "PollIntervalNotSatisfied")
	}
	return session, nil
}

// Each session has a stable cohort for each deployment; increasing percentage
// only adds clients. A rollback selects the prior immutable deployment bytes.
func selectedDeployment(rows []Deployment, profile, client string) (Deployment, bool) {
	slices.SortFunc(rows, func(a, b Deployment) int {
		if a.Number > b.Number {
			return -1
		}
		if a.Number < b.Number {
			return 1
		}
		return 0
	})
	for _, d := range rows {
		if d.ProfileID != profile {
			continue
		}
		switch d.State {
		case "COMPLETE", "BAKING":
			return d, true
		case "DEPLOYING":
			sum := sha256.Sum256([]byte(client + "\x00" + deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number)))
			cohort := float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53) * 100
			if cohort < d.Percentage {
				return d, true
			}
		}
	}
	return Deployment{}, false
}
func (s *Service) deployedContent(ctx context.Context, d Deployment, profileType string) ([]byte, error) {
	content := d.Content
	if d.KMSKeyARN != "" {
		if s.effects == nil {
			return nil, failure("BadRequestException", "KMS decryption is not configured")
		}
		var err error
		content, err = s.effects.Unprotect(ctx, d.Scope, d.KMSKeyARN, deploymentARN(d.Scope, d.ApplicationID, d.EnvironmentID, d.Number), content)
		if err != nil {
			return nil, err
		}
	}
	if profileType == "AWS.AppConfig.FeatureFlags" && isAgentRequest(ctx) {
		return s.agentContent(profileType, content)
	}
	return s.servedContent(profileType, content)
}
func (s *Service) markConfigurationPoll(tx Transaction, env Environment, p Profile) error {
	now := s.clock.Now().UTC()
	env.LastPoll = now
	p.LastPoll = now
	if err := tx.PutEnvironment(env); err != nil {
		return err
	}
	return tx.PutProfile(p)
}
func (s *Service) getLatestConfiguration(ctx context.Context, in *dataapi.GetLatestConfigurationInput) (*dataapi.GetLatestConfigurationOutput, error) {
	var session Session
	var selected Deployment
	var profile Profile
	read := func(r Reader) (Environment, Profile, Deployment, Session, error) {
		current, err := findSession(r, scopeFor(ctx), value(in.ConfigurationToken), s.clock.Now().UTC())
		if err != nil {
			return Environment{}, Profile{}, Deployment{}, current, err
		}
		missing := func() error {
			return dataResourceNotFound("Configuration", map[string]string{"ConfigurationToken": current.Token})
		}
		_, env, p, err := s.dataResources(r, "GetLatestConfiguration", current.ApplicationID, current.EnvironmentID, current.ProfileID)
		if err != nil {
			if configurationMissing(err) {
				err = missing()
			}
			return env, p, Deployment{}, current, err
		}
		rows, err := r.Deployments(current.Scope, current.ApplicationID, current.EnvironmentID)
		if err != nil {
			return env, p, Deployment{}, current, err
		}
		d, ok := selectedDeployment(rows, p.ID, current.ClientID)
		if !ok {
			return env, p, d, current, missing()
		}
		return env, p, d, current, nil
	}
	err := s.repository.View(ctx, func(r Reader) error {
		_, p, d, current, e := read(r)
		profile = p
		selected = d
		session = current
		return e
	})
	if err != nil {
		return nil, err
	}
	out := &dataapi.GetLatestConfigurationOutput{NextPollIntervalInSeconds: new(dataapi.Integer(session.PollSeconds)), ContentType: new(dataapi.String(selected.ContentType))}
	if profile.Type == "AWS.AppConfig.FeatureFlags" && isAgentRequest(ctx) {
		out.ContentType = new(dataapi.String("application/ion;type=AWS.AppConfig.FeatureFlags"))
	}
	if selected.Number != session.LastDeployment {
		out.Configuration, err = s.deployedContent(ctx, selected, profile.Type)
		if err != nil {
			return nil, err
		}
		out.VersionLabel = deployOptional[dataapi.String](selected.VersionLabel)
	}
	nextToken := rand.Text()
	out.NextPollConfigurationToken = new(dataapi.Token(nextToken))
	err = s.repository.Update(ctx, func(tx Transaction) error {
		env, p, d, current, e := read(tx)
		if e != nil {
			return e
		}
		if current != session {
			return dataTokenError("Invalid configuration token", "Invalid")
		}
		if d.Number != selected.Number || p.Type != profile.Type {
			return failure("BadRequestException", "Configuration changed during retrieval; retry with the same token")
		}
		if e = tx.DeleteSession(session.Scope, session.Token); e != nil {
			return e
		}
		current.Token = nextToken
		current.LastDeployment = d.Number
		now := s.clock.Now().UTC()
		current.ExpiresAt = now.Add(24 * time.Hour)
		current.NextPoll = now.Add(time.Duration(current.PollSeconds) * time.Second)
		if e = tx.PutSession(current); e != nil {
			return e
		}
		if e = s.markConfigurationPoll(tx, env, p); e != nil {
			return e
		}
		return s.recordCall(tx.Context(), "GetLatestConfiguration", in, out, nil)
	})
	if err != nil {
		return nil, err
	}
	if isAgentRequest(ctx) && selected.ExperimentFlags != "" {
		setConfigurationHeader(ctx, "Experiment-Flags", selected.ExperimentFlags)
	}
	return out, nil
}
func (s *Service) getConfiguration(ctx context.Context, in *api.GetConfigurationInput) (*api.GetConfigurationOutput, error) {
	var selected Deployment
	var profile Profile
	read := func(r Reader) (Environment, Profile, Deployment, error) {
		app, env, p, err := s.dataResources(r, "GetConfiguration", value(in.Application), value(in.Environment), value(in.Configuration))
		if err != nil {
			return env, p, Deployment{}, err
		}
		if value(in.ClientId) == "" {
			return env, p, Deployment{}, failure("BadRequestException", "ClientId is required")
		}
		rows, err := r.Deployments(app.Scope, app.ID, env.ID)
		if err != nil {
			return env, p, Deployment{}, err
		}
		d, ok := selectedDeployment(rows, p.ID, value(in.ClientId))
		if !ok {
			return env, p, d, failure("ResourceNotFoundException", "Deployment not found")
		}
		return env, p, d, nil
	}
	err := s.repository.View(ctx, func(r Reader) error { _, p, d, e := read(r); profile = p; selected = d; return e })
	if err != nil {
		return nil, err
	}
	if profile.Type == "AWS.AppConfig.FeatureFlags" {
		return nil, failure("BadRequestException", "Feature flag configurations must be accessed via AWS AppConfig Data's GetLatestConfiguration API")
	}
	out := &api.GetConfigurationOutput{ConfigurationVersion: new(api.Version(selected.ConfigurationVersion)), ContentType: new(api.String(selected.ContentType))}
	if value(in.ClientConfigurationVersion) != selected.ConfigurationVersion {
		out.Content, err = s.deployedContent(ctx, selected, profile.Type)
		if err != nil {
			return nil, err
		}
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		env, p, d, e := read(tx)
		if e != nil {
			return e
		}
		if d.Number != selected.Number || p.Type != profile.Type {
			return failure("BadRequestException", "Configuration changed during retrieval; retry the request")
		}
		if e = s.markConfigurationPoll(tx, env, p); e != nil {
			return e
		}
		return s.recordCall(tx.Context(), "GetConfiguration", in, out, nil)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
