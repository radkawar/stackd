package appconfig

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/awswire"
)

// registerControls installs the application, environment, configuration
// profile, hosted configuration version and deployment strategy APIs.
func registerControls(s *Service) {
	registerApplications(s)
	registerEnvironments(s)
	registerProfiles(s)
	registerHostedVersions(s)
	registerStrategies(s)
}

// Associated extensions must be explicitly detached before their target is
// deleted; native AppConfig never leaves associations pointing at a missing target.
func checkControlAssociations(r Reader, sc Scope, resource, kind string) error {
	rows, err := r.Associations(sc)
	if err != nil {
		return err
	}
	for _, association := range rows {
		if association.ResourceARN == resource {
			return failure("BadRequestException", fmt.Sprintf("Cannot delete %s %s because there are extensions associated with it. Please remove the extension associations to this %s first.", kind, resource, kind))
		}
	}
	return nil
}

// Native AppConfig resolves application, environment and profile identifiers
// by ID or name; the returned messages always echo the caller's identifier.
func applicationMissing(sc Scope, id string) error {
	return failure("ResourceNotFoundException", fmt.Sprintf("Application with Id %s could not be found for account %s.", id, sc.AccountID))
}

func environmentMissing(sc Scope, app, id string) error {
	return failure("ResourceNotFoundException", fmt.Sprintf("Environment with Application Id %s and Environment Id %s could not be found for account %s.", app, id, sc.AccountID))
}

func profileMissing(sc Scope, app, id string) error {
	return failure("ResourceNotFoundException", fmt.Sprintf("Configuration Profile with Application Id %s and Configuration Profile Id %s could not be found for account %s.", app, id, sc.AccountID))
}

func hostedVersionMissing(sc Scope, app, profile string, number int32) error {
	return failure("ResourceNotFoundException", fmt.Sprintf("Hosted Configuration Version with Application Id %s, Configuration Profile Id %s, and Version %d could not be found for account %s", app, profile, number, sc.AccountID))
}

func notFound(err error) bool {
	var e *awswire.Error
	return errors.As(err, &e) && e.Code == "ResourceNotFoundException"
}

// authorizeResource evaluates current IAM for one resource element of an
// action, including that resource's current aws:ResourceTag values.
func (s *Service) authorizeResource(r Reader, sc Scope, action, resource string) error {
	tags, err := r.Tags(sc, resource)
	if err != nil {
		return err
	}
	return s.authorize(r.Context(), action, resource, tags)
}

// controlApplication resolves an application and authorizes the application
// resource element. Missing resources are authorized against the requested
// identifier first, so callers without permission never learn existence.
func (s *Service) controlApplication(r Reader, sc Scope, action, id string) (Application, error) {
	app, err := findApplication(r, sc, id)
	if notFound(err) {
		if denied := s.authorize(r.Context(), action, appARN(sc, id), nil); denied != nil {
			return Application{}, denied
		}
		return Application{}, applicationMissing(sc, id)
	}
	if err != nil {
		return Application{}, err
	}
	return app, s.authorizeResource(r, sc, action, appARN(sc, app.ID))
}

func (s *Service) controlEnvironment(r Reader, sc Scope, action string, app Application, id string) (Environment, error) {
	env, err := findEnvironment(r, sc, app.ID, id)
	if notFound(err) {
		if denied := s.authorize(r.Context(), action, envARN(sc, app.ID, id), nil); denied != nil {
			return Environment{}, denied
		}
		return Environment{}, environmentMissing(sc, app.ID, id)
	}
	if err != nil {
		return Environment{}, err
	}
	return env, s.authorizeResource(r, sc, action, envARN(sc, app.ID, env.ID))
}

func (s *Service) controlProfile(r Reader, sc Scope, action string, app Application, id string) (Profile, error) {
	profile, err := findProfile(r, sc, app.ID, id)
	if notFound(err) {
		if denied := s.authorize(r.Context(), action, profileARN(sc, app.ID, id), nil); denied != nil {
			return Profile{}, denied
		}
		return Profile{}, profileMissing(sc, app.ID, id)
	}
	if err != nil {
		return Profile{}, err
	}
	return profile, s.authorizeResource(r, sc, action, profileARN(sc, app.ID, profile.ID))
}

// uniqueID allocates a native-shaped identifier absent from taken.
func uniqueID(taken func(string) bool) string {
	for {
		if id := newID(); !taken(id) {
			return id
		}
	}
}

func tagValues[K, V ~string](in map[K]V) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}

// createTags admits request tags on a new resource with the same reserved-key
// and count rules as TagResource.
func createTags[K, V ~string](in map[K]V) (map[string]string, error) {
	tags := tagValues(in)
	for k := range tags {
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, failure("BadRequestException", "Tag keys cannot begin with aws:.")
		}
	}
	if len(tags) > 50 {
		return nil, failure("BadRequestException", "A resource may have at most 50 tags.")
	}
	return tags, nil
}

func textOf[T ~string](v string) *T {
	if v == "" {
		return nil
	}
	return new(T(v))
}

// activeDeployments reports whether any environment deployment in the
// application is still validating, deploying, baking or rolling back and
// matches keep.
func activeDeployments(r Reader, sc Scope, app string, envs []Environment, keep func(Deployment) bool) (bool, error) {
	for _, env := range envs {
		rows, err := r.Deployments(sc, app, env.ID)
		if err != nil {
			return false, err
		}
		if slices.ContainsFunc(rows, func(d Deployment) bool { return deploymentActive(d) && keep(d) }) {
			return true, nil
		}
	}
	return false, nil
}

// liveExperiments reports non-archived experiment definitions matching keep.
// Archived definitions remain retained history and do not block deletion.
func liveExperiments(r Reader, sc Scope, app string, keep func(ExperimentDefinition) bool) (bool, error) {
	rows, err := r.ExperimentDefinitions(sc, app)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(rows, func(d ExperimentDefinition) bool { return d.Status != "ARCHIVED" && keep(d) }), nil
}

func formatVersion(n int32) string { return strconv.FormatInt(int64(n), 10) }
