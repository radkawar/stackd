package appconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const (
	profileFreeform = "AWS.Freeform"
	profileFlags    = "AWS.AppConfig.FeatureFlags"
	hostedLocation  = "hosted"
)

func registerProfiles(s *Service) {
	registerExternal(s, "CreateConfigurationProfile", s.createProfile)
	register(s, "GetConfigurationProfile", s.getProfile)
	register(s, "UpdateConfigurationProfile", s.updateProfile)
	register(s, "DeleteConfigurationProfile", s.deleteProfile)
	register(s, "ListConfigurationProfiles", s.listProfiles)
}

func validatorsOutput(in []Validator) api.ValidatorList {
	if in == nil {
		return nil
	}
	out := make(api.ValidatorList, 0, len(in))
	for _, v := range in {
		out = append(out, api.Validator{Type: new(api.ValidatorType(v.Type)), Content: new(api.StringWithLengthBetween0And32768(v.Content))})
	}
	return out
}

func profileOutput(p Profile) api.ConfigurationProfile {
	return api.ConfigurationProfile{
		ApplicationId:    textOf[api.Id](p.ApplicationID),
		Id:               textOf[api.Id](p.ID),
		Name:             textOf[api.LongName](p.Name),
		Description:      textOf[api.Description](p.Description),
		LocationUri:      textOf[api.Uri](p.LocationURI),
		RetrievalRoleArn: textOf[api.RoleArn](p.RetrievalRoleARN),
		Type:             textOf[api.ConfigurationProfileType](p.Type),
		KmsKeyIdentifier: textOf[api.KmsKeyIdentifier](p.KMSKeyIdentifier),
		KmsKeyArn:        textOf[api.Arn](p.KMSKeyARN),
		Validators:       validatorsOutput(p.Validators),
	}
}

// profileType admits the two native profile types. AWS reports an unknown
// type as a missing ConfigurationProfileType resource.
func profileType(v string) (string, error) {
	switch v {
	case "":
		return profileFreeform, nil
	case profileFreeform, profileFlags:
		return v, nil
	}
	e := failure("ResourceNotFoundException", "Invalid type, must be one of: AWS.Freeform, AWS.AppConfig.FeatureFlags")
	e.Details = map[string]json.RawMessage{"ResourceName": json.RawMessage(`"ConfigurationProfileType"`)}
	return "", e
}

// locationNeedsRole classifies a configuration source URI. Hosted and
// CodePipeline sources need no retrieval role; S3, Parameter Store, SSM
// documents and Secrets Manager require one.
func locationNeedsRole(uri string) (bool, error) {
	if uri == hostedLocation {
		return false, nil
	}
	for _, prefix := range []string{"ssm-parameter://", "ssm-document://", "secretsmanager://"} {
		if rest, ok := strings.CutPrefix(uri, prefix); ok && rest != "" {
			return true, nil
		}
	}
	if rest, ok := strings.CutPrefix(uri, "codepipeline://"); ok && rest != "" {
		return false, nil
	}
	if rest, ok := strings.CutPrefix(uri, "s3://"); ok {
		bucket, key, found := strings.Cut(rest, "/")
		if !found || bucket == "" || key == "" {
			return false, failure("BadRequestException", "Invalid locationUri "+uri)
		}
		return true, nil
	}
	if parts := strings.SplitN(uri, ":", 6); len(parts) == 6 && parts[0] == "arn" && parts[2] == "ssm" && (strings.HasPrefix(parts[5], "parameter/") || strings.HasPrefix(parts[5], "document/")) {
		return true, nil
	}
	return false, failure("BadRequestException", fmt.Sprintf("The Uri: %s is of an unsupported type", uri))
}

// profileValidators admits validators. JSON Schema documents are retained
// verbatim; native AWS does not parse them until validation. Lambda
// validators must name an ARN with an account.
func profileValidators(in api.ValidatorList) ([]Validator, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]Validator, 0, len(in))
	for _, v := range in {
		kind, content := value(v.Type), value(v.Content)
		if kind == string(api.ValidatorTypeLAMBDA) {
			if parts := strings.Split(content, ":"); len(parts) < 6 || parts[0] != "arn" || parts[4] == "" {
				return nil, failure("BadRequestException", fmt.Sprintf("ARN %s is invalid due to not containing an account ID.", content))
			}
		}
		out = append(out, Validator{Type: kind, Content: content})
	}
	return out, nil
}

// kmsKeyARN mirrors AppConfig's unverified resolution of a key identifier:
// ARNs are retained, aliases become alias ARNs and other values key ARNs.
// Key existence and caller authority are checked by KMS when content is protected.
func kmsKeyARN(sc Scope, id string) string {
	switch {
	case strings.HasPrefix(id, "arn:"):
		return id
	case strings.HasPrefix(id, "alias/"):
		return "arn:" + sc.Partition + ":kms:" + sc.Region + ":" + sc.AccountID + ":" + id
	}
	return "arn:" + sc.Partition + ":kms:" + sc.Region + ":" + sc.AccountID + ":key/" + id
}

func kmsHostedOnly() error {
	return failure("BadRequestException", "KmsKeyIdentifier applies only to AppConfig hosted configuration data. For non-hosted configuration sources, configure encryption in the corresponding service.")
}

func profileNameTaken(r Reader, sc Scope, app, name, self string) error {
	rows, err := r.Profiles(sc, app)
	if err != nil {
		return err
	}
	for _, p := range rows {
		if p.Name == name && p.ID != self {
			return failure("BadRequestException", fmt.Sprintf("ConfigurationProfile with name %s already exists with id %s in application %s account %s", name, p.ID, app, sc.AccountID))
		}
	}
	return nil
}

// admitProfile validates a new profile inside a transaction snapshot and
// returns it with a fresh identifier, or with id when it is still unused.
func (s *Service) admitProfile(r Reader, in *api.CreateConfigurationProfileInput, id string) (Profile, map[string]string, bool, error) {
	sc := scopeFor(r.Context())
	app, err := s.controlApplication(r, sc, "CreateConfigurationProfile", value(in.ApplicationId))
	if err != nil {
		return Profile{}, nil, false, err
	}
	kind, err := profileType(value(in.Type))
	if err != nil {
		return Profile{}, nil, false, err
	}
	p := Profile{Scope: sc, ApplicationID: app.ID, Name: value(in.Name), Description: value(in.Description), LocationURI: value(in.LocationUri), RetrievalRoleARN: value(in.RetrievalRoleArn), Type: kind, KMSKeyIdentifier: value(in.KmsKeyIdentifier), CreatedAt: s.clock.Now().UTC(), NextVersion: 1, Ownership: cloudFormationClaim(r.Context(), "configurationprofile")}
	if kind == profileFlags && p.LocationURI != hostedLocation {
		return Profile{}, nil, false, failure("BadRequestException", "ConfigurationProfiles of type 'AWS.AppConfig.FeatureFlags' can only have a locationUri of 'hosted'")
	}
	needsRole, err := locationNeedsRole(p.LocationURI)
	if err != nil {
		return Profile{}, nil, false, err
	}
	switch {
	case p.LocationURI == hostedLocation && p.RetrievalRoleARN != "":
		return Profile{}, nil, false, failure("BadRequestException", fmt.Sprintf("1 validation error detected: Value %s at 'retrievalRoleArn' failed to satisfy constraint: Member must be null if the request has the following uri: hosted", p.RetrievalRoleARN))
	case needsRole && p.RetrievalRoleARN == "":
		return Profile{}, nil, false, failure("BadRequestException", "1 validation error detected: Value null at 'retrievalRoleArn' failed to satisfy constraint: Member must not be null if the request has the following uri: "+p.LocationURI)
	}
	if p.KMSKeyIdentifier != "" {
		if p.LocationURI != hostedLocation {
			return Profile{}, nil, false, kmsHostedOnly()
		}
		p.KMSKeyARN = kmsKeyARN(sc, p.KMSKeyIdentifier)
	}
	if p.Validators, err = profileValidators(in.Validators); err != nil {
		return Profile{}, nil, false, err
	}
	tags, err := createTags(in.Tags)
	if err != nil {
		return Profile{}, nil, false, err
	}
	if err := profileNameTaken(r, sc, app.ID, p.Name, ""); err != nil {
		return Profile{}, nil, false, err
	}
	if err := s.passRole(r.Context(), p.RetrievalRoleARN); err != nil {
		return Profile{}, nil, false, err
	}
	rows, err := r.Profiles(sc, app.ID)
	if err != nil {
		return Profile{}, nil, false, err
	}
	taken := func(v string) bool { return slices.ContainsFunc(rows, func(p Profile) bool { return p.ID == v }) }
	p.ID = id
	if id == "" || taken(id) {
		p.ID = uniqueID(taken)
	}
	if err := s.authorizeTagsOnCreate(r.Context(), profileARN(sc, app.ID, p.ID), tags); err != nil {
		return Profile{}, nil, false, err
	}
	return p, tags, needsRole, nil
}

// createProfile assumes the retrieval role outside repository transactions,
// as AWS does at creation for role-backed sources, then commits the profile
// after re-evaluating current state and IAM.
func (s *Service) createProfile(ctx context.Context, in *api.CreateConfigurationProfileInput) (*api.ConfigurationProfile, error) {
	var draft Profile
	var needsRole bool
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		draft, _, needsRole, err = s.admitProfile(r, in, "")
		return err
	}); err != nil {
		return nil, err
	}
	if needsRole {
		if s.effects == nil {
			return nil, failure("BadRequestException", "Configuration retrieval roles are not configured.")
		}
		source := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "appconfig.amazonaws.com", SourceARN: profileARN(draft.Scope, draft.ApplicationID, draft.ID)})
		if err := s.effects.AssumeRetrievalRole(source, draft.Scope, draft.RetrievalRoleARN); err != nil {
			var e *awswire.Error
			if errors.As(err, &e) {
				return nil, failure("BadRequestException", "Error trying to assume role "+draft.RetrievalRoleARN)
			}
			return nil, err
		}
	}
	var out api.ConfigurationProfile
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		p, tags, _, err := s.admitProfile(tx, in, draft.ID)
		if err != nil {
			return err
		}
		if p.ID != draft.ID || p.ApplicationID != draft.ApplicationID || p.RetrievalRoleARN != draft.RetrievalRoleARN {
			return failure("ConflictException", "The application changed while the configuration profile was being created.")
		}
		if err := tx.PutProfile(p); err != nil {
			return err
		}
		if err := tx.PutTags(p.Scope, profileARN(p.Scope, p.ApplicationID, p.ID), tags); err != nil {
			return err
		}
		out = profileOutput(p)
		out.Description = in.Description
		return s.recordCall(tx.Context(), "CreateConfigurationProfile", in, &out, nil)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Service) getProfile(tx Transaction, in *api.GetConfigurationProfileInput) (*api.ConfigurationProfile, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "GetConfigurationProfile", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	p, err := s.controlProfile(tx, sc, "GetConfigurationProfile", app, value(in.ConfigurationProfileId))
	if err != nil {
		return nil, err
	}
	out := profileOutput(p)
	return &out, nil
}

// updateProfile follows native update admission: an empty KMS identifier
// clears encryption for new versions, an explicit empty validator list clears
// validators, and a retrieval role may be set on any source without an
// immediate role assumption.
func (s *Service) updateProfile(tx Transaction, in *api.UpdateConfigurationProfileInput) (*api.ConfigurationProfile, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "UpdateConfigurationProfile", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	p, err := s.controlProfile(tx, sc, "UpdateConfigurationProfile", app, value(in.ConfigurationProfileId))
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if err := profileNameTaken(tx, sc, app.ID, value(in.Name), p.ID); err != nil {
			return nil, err
		}
		p.Name = value(in.Name)
	}
	if in.Description != nil {
		p.Description = value(in.Description)
	}
	if in.KmsKeyIdentifier != nil {
		id := value(in.KmsKeyIdentifier)
		switch {
		case id == "":
			p.KMSKeyIdentifier, p.KMSKeyARN = "", ""
		case p.LocationURI != hostedLocation:
			return nil, kmsHostedOnly()
		default:
			p.KMSKeyIdentifier, p.KMSKeyARN = id, kmsKeyARN(sc, id)
		}
	}
	if in.RetrievalRoleArn != nil {
		if err := s.passRole(tx.Context(), value(in.RetrievalRoleArn)); err != nil {
			return nil, err
		}
		p.RetrievalRoleARN = value(in.RetrievalRoleArn)
	}
	if in.Validators != nil {
		if p.Validators, err = profileValidators(in.Validators); err != nil {
			return nil, err
		}
	}
	if err := tx.PutProfile(p); err != nil {
		return nil, err
	}
	out := profileOutput(p)
	if in.Description != nil {
		out.Description = in.Description
	}
	return &out, nil
}

// deleteProfile requires the hosted versions to be deleted first, as AWS
// does, and rejects in-progress deployments and live experiment definitions
// before evaluating the deletion-protection window.
func (s *Service) deleteProfile(tx Transaction, in *api.DeleteConfigurationProfileInput) (*api.Unit, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "DeleteConfigurationProfile", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	p, err := s.controlProfile(tx, sc, "DeleteConfigurationProfile", app, value(in.ConfigurationProfileId))
	if err != nil {
		return nil, err
	}
	if err := checkControlAssociations(tx, sc, profileARN(sc, app.ID, p.ID), "configuration profile"); err != nil {
		return nil, err
	}
	versions, err := tx.HostedVersions(sc, app.ID, p.ID)
	if err != nil {
		return nil, err
	}
	if len(versions) > 0 {
		return nil, failure("BadRequestException", fmt.Sprintf("Cannot delete configuration profile %s because there are still hosted configuration versions existing under it.", p.ID))
	}
	envs, err := tx.Environments(sc, app.ID)
	if err != nil {
		return nil, err
	}
	active, err := activeDeployments(tx, sc, app.ID, envs, func(d Deployment) bool { return d.ProfileID == p.ID })
	if err != nil {
		return nil, err
	}
	if active {
		// Native message for this conflict has not been captured.
		return nil, failure("ConflictException", fmt.Sprintf("Cannot delete configuration profile %s because a deployment is in progress.", p.ID))
	}
	live, err := liveExperiments(tx, sc, app.ID, func(d ExperimentDefinition) bool { return d.ProfileID == p.ID })
	if err != nil {
		return nil, err
	}
	if live {
		// Native text follows the captured environment message.
		return nil, failure("BadRequestException", fmt.Sprintf("Cannot delete configuration profile %s, because there are non-archived experiment definitions associated with it.", p.ID))
	}
	if err := s.checkDeletionProtection(tx, sc, p.CreatedAt, p.LastPoll, value(in.DeletionProtectionCheck)); err != nil {
		return nil, err
	}
	if err := tx.DeleteProfile(sc, app.ID, p.ID); err != nil {
		return nil, err
	}
	if err := tx.PutTags(sc, profileARN(sc, app.ID, p.ID), nil); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

func (s *Service) listProfiles(tx Transaction, in *api.ListConfigurationProfilesInput) (*api.ConfigurationProfiles, error) {
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, "ListConfigurationProfiles", value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	rows, err := tx.Profiles(sc, app.ID)
	if err != nil {
		return nil, err
	}
	if kind := value(in.Type); kind != "" {
		rows = slices.DeleteFunc(rows, func(p Profile) bool { return p.Type != kind })
	}
	rows, next, err := page(rows, in.NextToken, in.MaxResults, pageBinding(sc, "ListConfigurationProfiles", app.ID, value(in.Type)), func(i int) pageKey { return pageKey{ID: rows[i].ID} })
	if err != nil {
		return nil, err
	}
	out := &api.ConfigurationProfiles{Items: make(api.ConfigurationProfileSummaryList, 0, len(rows)), NextToken: next}
	for _, p := range rows {
		item := api.ConfigurationProfileSummary{ApplicationId: textOf[api.Id](p.ApplicationID), Id: textOf[api.Id](p.ID), Name: textOf[api.LongName](p.Name), LocationUri: textOf[api.Uri](p.LocationURI), Type: textOf[api.ConfigurationProfileType](p.Type)}
		for _, v := range p.Validators {
			item.ValidatorTypes = append(item.ValidatorTypes, api.ValidatorType(v.Type))
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}
