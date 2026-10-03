package appconfig

import (
	"fmt"

	api "stackd/internal/awsapi/appconfig"
)

func registerApplications(s *Service) {
	register(s, "CreateApplication", s.createApplication)
	register(s, "GetApplication", s.getApplication)
	register(s, "UpdateApplication", s.updateApplication)
	register(s, "DeleteApplication", s.deleteApplication)
	register(s, "ListApplications", s.listApplications)
}

func applicationOutput(a Application) api.Application {
	return api.Application{Id: textOf[api.Id](a.ID), Name: textOf[api.Name](a.Name), Description: textOf[api.Description](a.Description)}
}

// Application names are unique within an account and Region.
func applicationNameTaken(r Reader, sc Scope, name, self string) error {
	rows, err := r.Applications(sc)
	if err != nil {
		return err
	}
	for _, a := range rows {
		if a.Name == name && a.ID != self {
			return failure("BadRequestException", fmt.Sprintf("Application with name %s already exists with id %s in account %s", name, a.ID, sc.AccountID))
		}
	}
	return nil
}

func (s *Service) createApplication(tx Transaction, in *api.CreateApplicationInput) (*api.Application, error) {
	sc := scopeFor(tx.Context())
	if err := s.authorize(tx.Context(), "CreateApplication", "*", nil); err != nil {
		return nil, err
	}
	tags, err := createTags(in.Tags)
	if err != nil {
		return nil, err
	}
	name := value(in.Name)
	if err := applicationNameTaken(tx, sc, name, ""); err != nil {
		return nil, err
	}
	rows, err := tx.Applications(sc)
	if err != nil {
		return nil, err
	}
	// Default regional quota: https://docs.aws.amazon.com/general/latest/gr/appconfig.html
	if len(rows) >= 100 {
		return nil, failure("ServiceQuotaExceededException", "The maximum number of applications is 100.")
	}
	app := Application{Scope: sc, Name: name, Description: value(in.Description)}
	app.ID = uniqueID(func(id string) bool {
		for _, a := range rows {
			if a.ID == id {
				return true
			}
		}
		return false
	})
	if err := s.authorizeTagsOnCreate(tx.Context(), appARN(sc, app.ID), tags); err != nil {
		return nil, err
	}
	if err := tx.PutApplication(app); err != nil {
		return nil, err
	}
	if err := tx.PutTags(sc, appARN(sc, app.ID), tags); err != nil {
		return nil, err
	}
	out := applicationOutput(app)
	out.Description = in.Description
	return &out, nil
}

func (s *Service) getApplication(tx Transaction, in *api.GetApplicationInput) (*api.Application, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "GetApplication", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	out := applicationOutput(app)
	return &out, nil
}

func (s *Service) updateApplication(tx Transaction, in *api.UpdateApplicationInput) (*api.Application, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "UpdateApplication", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if err := applicationNameTaken(tx, sc, value(in.Name), app.ID); err != nil {
			return nil, err
		}
		app.Name = value(in.Name)
	}
	if in.Description != nil {
		app.Description = value(in.Description)
	}
	if err := tx.PutApplication(app); err != nil {
		return nil, err
	}
	out := applicationOutput(app)
	if in.Description != nil {
		out.Description = in.Description
	}
	return &out, nil
}

// deleteApplication checks extension associations first, then child
// environments, configuration profiles and experiment definitions.
func (s *Service) deleteApplication(tx Transaction, in *api.DeleteApplicationInput) (*api.Unit, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "DeleteApplication", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	if err := checkControlAssociations(tx, sc, appARN(sc, app.ID), "application"); err != nil {
		return nil, err
	}
	envs, err := tx.Environments(sc, app.ID)
	if err != nil {
		return nil, err
	}
	if len(envs) > 0 {
		return nil, failure("BadRequestException", fmt.Sprintf("Cannot delete application %s, because there are still environments existing under it.", app.ID))
	}
	profiles, err := tx.Profiles(sc, app.ID)
	if err != nil {
		return nil, err
	}
	if len(profiles) > 0 {
		return nil, failure("BadRequestException", fmt.Sprintf("Cannot delete application %s, because there are still configuration profiles existing under it.", app.ID))
	}
	// Archived definitions still block application deletion natively.
	definitions, err := tx.ExperimentDefinitions(sc, app.ID)
	if err != nil {
		return nil, err
	}
	if len(definitions) > 0 {
		return nil, failure("BadRequestException", fmt.Sprintf("Cannot delete application %s, because there are still experiment definitions existing under it.", app.ID))
	}
	if err := tx.DeleteApplication(sc, app.ID); err != nil {
		return nil, err
	}
	if err := tx.PutTags(sc, appARN(sc, app.ID), nil); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

func (s *Service) listApplications(tx Transaction, in *api.ListApplicationsInput) (*api.Applications, error) {
	sc := scopeFor(tx.Context())
	if err := s.authorize(tx.Context(), "ListApplications", "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Applications(sc)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, in.NextToken, in.MaxResults, pageBinding(sc, "ListApplications"), func(i int) pageKey { return pageKey{ID: rows[i].ID} })
	if err != nil {
		return nil, err
	}
	out := &api.Applications{Items: make(api.ApplicationList, 0, len(rows)), NextToken: next}
	for _, a := range rows {
		out.Items = append(out.Items, applicationOutput(a))
	}
	return out, nil
}
