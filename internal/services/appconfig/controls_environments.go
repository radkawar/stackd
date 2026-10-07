package appconfig

import (
	"fmt"
	"slices"

	api "stackd/internal/awsapi/appconfig"
)

// environmentReady is the native wire state of an idle environment; AWS
// returns this value rather than the model enum spelling READY_FOR_DEPLOYMENT.
const environmentReady = "ReadyForDeployment"

func registerEnvironments(s *Service) {
	register(s, "CreateEnvironment", s.createEnvironment)
	register(s, "GetEnvironment", s.getEnvironment)
	register(s, "UpdateEnvironment", s.updateEnvironment)
	register(s, "DeleteEnvironment", s.deleteEnvironment)
	register(s, "ListEnvironments", s.listEnvironments)
}

func environmentOutput(e Environment) api.Environment {
	out := api.Environment{ApplicationId: textOf[api.Id](e.ApplicationID), Id: textOf[api.Id](e.ID), Name: textOf[api.Name](e.Name), Description: textOf[api.Description](e.Description), State: textOf[api.EnvironmentState](e.State)}
	if e.Monitors != nil {
		out.Monitors = make(api.MonitorList, 0, len(e.Monitors))
		for _, m := range e.Monitors {
			out.Monitors = append(out.Monitors, api.Monitor{AlarmArn: textOf[api.StringWithLengthBetween1And2048](m.AlarmARN), AlarmRoleArn: textOf[api.RoleArn](m.RoleARN)})
		}
	}
	return out
}

// environmentMonitors admits monitors and the caller's iam:PassRole for each
// alarm role. Native AppConfig requires AlarmRoleArn although the model marks
// it optional; alarm existence is checked by deployments, not here.
func (s *Service) environmentMonitors(r Reader, in api.MonitorList) ([]Monitor, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]Monitor, 0, len(in))
	for _, m := range in {
		if m.AlarmRoleArn == nil {
			return nil, failure("BadRequestException", "1 validation error detected: Value null at 'alarmRoleArn' failed to satisfy constraint: Member must not be null.")
		}
		out = append(out, Monitor{AlarmARN: value(m.AlarmArn), RoleARN: value(m.AlarmRoleArn)})
	}
	for _, m := range out {
		if err := s.passRole(r.Context(), m.RoleARN); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func environmentNameTaken(r Reader, sc Scope, app, name, self string) error {
	rows, err := r.Environments(sc, app)
	if err != nil {
		return err
	}
	for _, e := range rows {
		if e.Name == name && e.ID != self {
			return failure("BadRequestException", fmt.Sprintf("Environment with name %s already exists with id %s in application %s and account %s", name, e.ID, app, sc.AccountID))
		}
	}
	return nil
}

func (s *Service) createEnvironment(tx Transaction, in *api.CreateEnvironmentInput) (*api.Environment, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "CreateEnvironment", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	tags, err := createTags(in.Tags)
	if err != nil {
		return nil, err
	}
	monitors, err := s.environmentMonitors(tx, in.Monitors)
	if err != nil {
		return nil, err
	}
	name := value(in.Name)
	if err := environmentNameTaken(tx, sc, app.ID, name, ""); err != nil {
		return nil, err
	}
	rows, err := tx.Environments(sc, app.ID)
	if err != nil {
		return nil, err
	}
	env := Environment{Scope: sc, ApplicationID: app.ID, Name: name, Description: value(in.Description), State: environmentReady, Monitors: monitors, CreatedAt: s.clock.Now().UTC(), Ownership: cloudFormationClaim(tx.Context(), "environment")}
	env.ID = uniqueID(func(id string) bool {
		return slices.ContainsFunc(rows, func(e Environment) bool { return e.ID == id })
	})
	if err := s.authorizeTagsOnCreate(tx.Context(), envARN(sc, app.ID, env.ID), tags); err != nil {
		return nil, err
	}
	if err := tx.PutEnvironment(env); err != nil {
		return nil, err
	}
	if err := tx.PutTags(sc, envARN(sc, app.ID, env.ID), tags); err != nil {
		return nil, err
	}
	out := environmentOutput(env)
	out.Description = in.Description
	return &out, nil
}

func (s *Service) getEnvironment(tx Transaction, in *api.GetEnvironmentInput) (*api.Environment, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "GetEnvironment", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	env, err := s.controlEnvironment(tx, sc, "GetEnvironment", app, value(in.EnvironmentId))
	if err != nil {
		return nil, err
	}
	out := environmentOutput(env)
	return &out, nil
}

func (s *Service) updateEnvironment(tx Transaction, in *api.UpdateEnvironmentInput) (*api.Environment, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "UpdateEnvironment", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	env, err := s.controlEnvironment(tx, sc, "UpdateEnvironment", app, value(in.EnvironmentId))
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if err := environmentNameTaken(tx, sc, app.ID, value(in.Name), env.ID); err != nil {
			return nil, err
		}
		env.Name = value(in.Name)
	}
	if in.Description != nil {
		env.Description = value(in.Description)
	}
	if in.Monitors != nil {
		// An explicit empty list clears monitors and is returned as [].
		if env.Monitors, err = s.environmentMonitors(tx, in.Monitors); err != nil {
			return nil, err
		}
	}
	if err := tx.PutEnvironment(env); err != nil {
		return nil, err
	}
	out := environmentOutput(env)
	if in.Description != nil {
		out.Description = in.Description
	}
	return &out, nil
}

// deleteEnvironment removes the environment and its retained deployment
// history. In-progress deployments and non-archived experiment definitions
// block deletion before the account deletion-protection window is evaluated.
func (s *Service) deleteEnvironment(tx Transaction, in *api.DeleteEnvironmentInput) (*api.Unit, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "DeleteEnvironment", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	env, err := s.controlEnvironment(tx, sc, "DeleteEnvironment", app, value(in.EnvironmentId))
	if err != nil {
		return nil, err
	}
	if err := checkControlAssociations(tx, sc, envARN(sc, app.ID, env.ID), "environment"); err != nil {
		return nil, err
	}
	deployments, err := tx.Deployments(sc, app.ID, env.ID)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(deployments, deploymentActive) {
		// Native message for this conflict has not been captured.
		return nil, failure("ConflictException", fmt.Sprintf("Cannot delete environment %s because a deployment is in progress.", env.ID))
	}
	live, err := liveExperiments(tx, sc, app.ID, func(d ExperimentDefinition) bool { return d.EnvironmentID == env.ID })
	if err != nil {
		return nil, err
	}
	if live {
		return nil, failure("BadRequestException", fmt.Sprintf("Cannot delete environment %s, because there are non-archived experiment definitions associated with it.", env.ID))
	}
	if err := s.checkDeletionProtection(tx, sc, env.CreatedAt, env.LastPoll, value(in.DeletionProtectionCheck)); err != nil {
		return nil, err
	}
	for _, d := range deployments {
		if err := tx.DeleteDeployment(sc, app.ID, env.ID, d.Number); err != nil {
			return nil, err
		}
		if err := tx.PutTags(sc, deploymentARN(sc, app.ID, env.ID, d.Number), nil); err != nil {
			return nil, err
		}
	}
	if err := tx.DeleteEnvironment(sc, app.ID, env.ID); err != nil {
		return nil, err
	}
	if err := tx.PutTags(sc, envARN(sc, app.ID, env.ID), nil); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

func (s *Service) listEnvironments(tx Transaction, in *api.ListEnvironmentsInput) (*api.Environments, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "ListEnvironments", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	rows, err := tx.Environments(sc, app.ID)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, in.NextToken, in.MaxResults, pageBinding(sc, "ListEnvironments", app.ID), func(i int) pageKey { return pageKey{ID: rows[i].ID} })
	if err != nil {
		return nil, err
	}
	out := &api.Environments{Items: make(api.EnvironmentList, 0, len(rows)), NextToken: next}
	for _, e := range rows {
		out.Items = append(out.Items, environmentOutput(e))
	}
	return out, nil
}
