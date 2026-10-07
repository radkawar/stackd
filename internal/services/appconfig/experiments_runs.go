package appconfig

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"slices"
	"time"

	api "stackd/internal/awsapi/appconfig"
)

type experimentChange struct {
	action, application, definition string
	number                          int32
	description                     *api.Description
	exposure                        *api.NullablePercentage
	overrides                       *api.TreatmentOverrides
	result                          *api.ExperimentRunResult
	tags                            api.TagMap
	deployment                      *api.DeploymentParameters
	request                         any
}
type experimentAdmission struct {
	definition ExperimentDefinition
	run        ExperimentRun
	runs       []ExperimentRun
	app        Application
	env        Environment
	profile    Profile
	baseline   Deployment
	latest     int32
}

func (s *Service) startExperimentRun(ctx context.Context, in *api.StartExperimentRunInput) (*api.ExperimentRun, error) {
	return s.changeExperimentRun(ctx, experimentChange{action: "StartExperimentRun", application: value(in.ApplicationIdentifier), definition: value(in.ExperimentDefinitionIdentifier), description: in.Description, exposure: in.ExposurePercentage, overrides: in.TreatmentOverrides, tags: in.Tags, deployment: in.DeploymentParameters, request: in})
}
func (s *Service) updateExperimentRun(ctx context.Context, in *api.UpdateExperimentRunInput) (*api.ExperimentRun, error) {
	return s.changeExperimentRun(ctx, experimentChange{action: "UpdateExperimentRun", application: value(in.ApplicationIdentifier), definition: value(in.ExperimentDefinitionIdentifier), number: number(in.Run), description: in.Description, exposure: in.ExposurePercentage, overrides: in.TreatmentOverrides, deployment: in.DeploymentParameters, request: in})
}
func (s *Service) stopExperimentRun(ctx context.Context, in *api.StopExperimentRunInput) (*api.ExperimentRun, error) {
	return s.changeExperimentRun(ctx, experimentChange{action: "StopExperimentRun", application: value(in.ApplicationIdentifier), definition: value(in.ExperimentDefinitionIdentifier), number: number(in.Run), result: in.Result, deployment: in.DeploymentParameters, request: in})
}
func (s *Service) experimentAdmission(r Reader, c experimentChange) (experimentAdmission, error) {
	var a experimentAdmission
	var err error
	if c.action == "StartExperimentRun" {
		a.definition, err = s.experimentDefinition(r, c.action, c.application, c.definition)
	} else {
		a.definition, a.run, err = s.experimentRun(r, c.action, c.application, c.definition, c.number)
	}
	if err != nil {
		return a, err
	}
	d := a.definition
	if c.action == "StartExperimentRun" {
		if d.Status != "IDLE" {
			return a, failure("ConflictException", fmt.Sprintf("Cannot start experiment definition %s with status %s.", d.ID, d.Status))
		}
	} else if a.run.Status != "RUNNING" {
		if c.action == "UpdateExperimentRun" {
			return a, failure("BadRequestException", fmt.Sprintf("Cannot update experiment run %d for experiment definition %s because it is already terminal.", a.run.Number, d.ID))
		}
		return a, failure("BadRequestException", fmt.Sprintf("Experiment run %d for experiment definition %s is not running.", a.run.Number, d.ID))
	}
	a.app, err = findApplication(r, d.Scope, d.ApplicationID)
	if err != nil {
		return a, err
	}
	a.env, err = findEnvironment(r, d.Scope, d.ApplicationID, d.EnvironmentID)
	if err != nil {
		return a, err
	}
	a.profile, err = findProfile(r, d.Scope, d.ApplicationID, d.ProfileID)
	if err != nil {
		return a, err
	}
	deployments, err := r.Deployments(d.Scope, d.ApplicationID, d.EnvironmentID)
	if err != nil {
		return a, err
	}
	for _, deployment := range deployments {
		if deployment.Number > a.latest {
			a.latest = deployment.Number
		}
		if deploymentActive(deployment) {
			return a, failure("ConflictException", "A deployment is already in progress for this environment")
		}
		if deployment.ProfileID == d.ProfileID && deployment.State == "COMPLETE" && deployment.Type != "MANAGED" && deployment.Number > a.baseline.Number {
			a.baseline = deployment
		}
	}
	if a.baseline.Number == 0 {
		return a, failure("BadRequestException", "The experiment feature flag must be deployed to the target environment before starting a run.")
	}
	definitions, err := r.ExperimentDefinitions(d.Scope, d.ApplicationID)
	if err != nil {
		return a, err
	}
	for _, definition := range definitions {
		if definition.EnvironmentID != d.EnvironmentID || definition.ProfileID != d.ProfileID {
			continue
		}
		runs, e := r.ExperimentRuns(d.Scope, d.ApplicationID, definition.ID)
		if e != nil {
			return a, e
		}
		for _, run := range runs {
			if run.Status == "RUNNING" {
				if c.action == "StartExperimentRun" && run.Snapshot.FlagKey == d.FlagKey {
					return a, failure("ConflictException", "An experiment is already running on this feature flag in the environment.")
				}
				a.runs = append(a.runs, run)
			}
		}
	}
	if c.action == "StartExperimentRun" {
		runs, e := r.ExperimentRuns(d.Scope, d.ApplicationID, d.ID)
		if e != nil {
			return a, e
		}
		a.run = ExperimentRun{Scope: d.Scope, ApplicationID: d.ApplicationID, DefinitionID: d.ID, Number: 1, Snapshot: cloneExperimentDefinition(d), Status: "RUNNING", Ownership: cloudFormationClaim(r.Context(), "experimentrun")}
		for _, run := range runs {
			if run.Number >= a.run.Number {
				a.run.Number = run.Number + 1
			}
		}
	}
	return a, nil
}
func (s *Service) changeExperimentRun(ctx context.Context, c experimentChange) (*api.ExperimentRun, error) {
	if c.action == "UpdateExperimentRun" && c.exposure != nil && c.overrides != nil {
		return nil, failure("BadRequestException", "Only one deployment attribute can be updated per request")
	}
	if c.exposure != nil {
		v := float64(*c.exposure)
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 100 {
			return nil, failure("BadRequestException", "Exposure percentage must be between 0 and 100.")
		}
	}
	var a experimentAdmission
	if err := s.repository.View(ctx, func(r Reader) error { var e error; a, e = s.experimentAdmission(r, c); return e }); err != nil {
		return nil, err
	}
	next := cloneExperimentRun(a.run)
	definition := a.definition
	now := s.clock.Now().UTC()
	event := ExperimentEvent{TriggeredBy: "USER", At: now}
	if c.description != nil {
		next.Description = value(c.description)
	}
	if c.exposure != nil {
		exposure := float64(*c.exposure)
		if exposure < next.Exposure {
			return nil, failure("BadRequestException", fmt.Sprintf("Exposure percentage can only be increased. Current: %.1f%%, Requested: %.1f%%.", next.Exposure, exposure))
		}
		next.Exposure = exposure
	}
	if c.overrides != nil {
		overrides, e := experimentOverridesInput(c.overrides, next.Snapshot)
		if e != nil {
			return nil, e
		}
		next.Overrides = overrides
	}
	deploy := c.action != "UpdateExperimentRun" || c.exposure != nil || c.overrides != nil
	switch c.action {
	case "StartExperimentRun":
		next.StartedAt = now
		definition.Status = "ACTIVE"
		event.Type = "RUN_STARTED"
		event.Description = "Experiment run started"
		event.Exposure = new(next.Exposure)
		event.Overrides = next.Overrides
	case "StopExperimentRun":
		next.Status = "DONE"
		next.EndedAt = now
		definition.Status = "IDLE"
		event.Type = "RUN_STOPPED"
		event.Description = "Experiment run stopped"
		if c.result != nil {
			next.Result = &ExperimentResult{ExecutiveSummary: value(c.result.ExecutiveSummary), ReasonsToLaunch: value(c.result.ReasonsToLaunch), ReasonsNotToLaunch: value(c.result.ReasonsNotToLaunch)}
		}
	case "UpdateExperimentRun":
		if c.exposure != nil {
			event.Type = "EXPOSURE_UPDATED"
			event.Description = "Experiment exposure updated"
			event.Exposure = new(next.Exposure)
		} else if c.overrides != nil {
			event.Type = "OVERRIDES_UPDATED"
			event.Description = "Experiment treatment overrides updated"
			event.Overrides = next.Overrides
		}
	}
	next.UpdatedAt = now
	definition.UpdatedAt = now
	if event.Type != "" {
		next.Events = append([]ExperimentEvent{event}, next.Events...)
	}
	runTags, err := createTags(c.tags)
	if err != nil {
		return nil, err
	}
	if c.action == "StartExperimentRun" {
		if err = s.authorizeTagsOnCreate(ctx, experimentRunARN(next.Scope, next.ApplicationID, next.DefinitionID, next.Number), runTags); err != nil {
			return nil, err
		}
	}
	deploymentTags := map[string]string{}
	if c.deployment != nil {
		deploymentTags, err = createTags(c.deployment.Tags)
		if err != nil {
			return nil, err
		}
	}
	var managed Deployment
	if deploy {
		content := a.baseline.Content
		if a.baseline.KMSKeyARN != "" {
			if s.effects == nil {
				return nil, failure("BadRequestException", "KMS decryption is not configured")
			}
			content, err = s.effects.Unprotect(ctx, a.baseline.Scope, a.baseline.KMSKeyARN, deploymentARN(a.baseline.Scope, a.baseline.ApplicationID, a.baseline.EnvironmentID, a.baseline.Number), content)
			if err != nil {
				return nil, err
			}
		}
		runs := slices.DeleteFunc(slices.Clone(a.runs), func(r ExperimentRun) bool { return r.DefinitionID == next.DefinitionID })
		if next.Status == "RUNNING" {
			runs = append(runs, next)
		}
		transformed, flags, e := applyExperimentRuns(content, runs)
		if e != nil {
			return nil, e
		}
		managed = Deployment{Scope: a.definition.Scope, ApplicationID: a.app.ID, EnvironmentID: a.env.ID, ProfileID: a.profile.ID, Number: a.latest + 1, PreviousDeployment: a.latest, ConfigurationName: a.profile.Name, ConfigurationVersion: a.baseline.ConfigurationVersion, VersionLabel: a.baseline.VersionLabel, LocationURI: a.profile.LocationURI, Description: "For " + experimentRunARN(next.Scope, next.ApplicationID, next.DefinitionID, next.Number), ContentType: a.baseline.ContentType, Content: transformed, Type: "MANAGED", GrowthType: "LINEAR", GrowthFactor: 100, ExperimentFlags: flags, DynamicParameters: map[string][]string{}, KMSKeyIdentifier: a.baseline.KMSKeyIdentifier}
		if c.deployment != nil {
			for k, v := range c.deployment.DynamicExtensionParameters {
				managed.DynamicParameters[string(k)] = []string{string(v)}
			}
		}
		configuration := ConfigurationContent{Content: managed.Content, ContentType: managed.ContentType, Version: managed.ConfigurationVersion, VersionLabel: managed.VersionLabel}
		configuration, extensions, invocations, e := s.runExtensions(ctx, "PRE_START_DEPLOYMENT", a.app, &a.env, &a.profile, configuration, &managed)
		if e != nil {
			return nil, e
		}
		managed.Extensions = extensions
		managed.Content = configuration.Content
		managed.ContentType = configuration.ContentType
		if e = s.validateContent(ctx, a.profile, managed.ConfigurationVersion, managed.Content); e != nil {
			return nil, e
		}
		if managed.KMSKeyIdentifier != "" {
			if s.effects == nil {
				return nil, failure("BadRequestException", "KMS encryption is not configured")
			}
			managed.Content, managed.KMSKeyARN, e = s.effects.Protect(ctx, managed.Scope, managed.KMSKeyIdentifier, deploymentARN(managed.Scope, managed.ApplicationID, managed.EnvironmentID, managed.Number), managed.Content)
			if e != nil {
				return nil, e
			}
		}
		managed.StartedAt = now
		managed.Generation = 1
		managed.State = "VALIDATING"
		managed.Due = now
		addDeploymentEvent(&managed, "DEPLOYMENT_STARTED", "USER", "Deployment started", now, invocations)
		if len(managed.Extensions) == 0 {
			managed.State = "COMPLETE"
			managed.Percentage = 100
			managed.CompletedAt = now
			managed.Due = time.Time{}
			addDeploymentEvent(&managed, "DEPLOYMENT_COMPLETED", "APPCONFIG", "Deployment completed instantly", now, nil)
		}
	}
	out := experimentRunOutput(next)
	err = s.repository.Update(ctx, func(tx Transaction) error {
		current, e := s.experimentAdmission(tx, c)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(a, current) {
			return failure("ConflictException", "Experiment resources changed during validation; retry the request")
		}
		if c.action == "StartExperimentRun" {
			resource := experimentRunARN(next.Scope, next.ApplicationID, next.DefinitionID, next.Number)
			if e = s.authorizeTagsOnCreate(tx.Context(), resource, runTags); e != nil {
				return e
			}
			if e = tx.PutTags(next.Scope, resource, runTags); e != nil {
				return e
			}
		}
		if deploy {
			if e = tx.PutDeployment(managed); e != nil {
				return e
			}
			a.env.State = deploymentEnvironmentState(managed.State)
			if e = tx.PutEnvironment(a.env); e != nil {
				return e
			}
			if e = tx.PutTags(managed.Scope, deploymentARN(managed.Scope, managed.ApplicationID, managed.EnvironmentID, managed.Number), deploymentTags); e != nil {
				return e
			}
		}
		if e = tx.PutExperimentDefinition(definition); e != nil {
			return e
		}
		if e = tx.PutExperimentRun(next); e != nil {
			return e
		}
		return s.recordCall(tx.Context(), c.action, c.request, &out, nil)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
