package appconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/appconfig"
	"stackd/internal/awswire"
)

// hostedContentLimit is the native 2 MiB hosted configuration size quota.
const hostedContentLimit = 2 << 20

func registerHostedVersions(s *Service) {
	registerExternal(s, "CreateHostedConfigurationVersion", s.createHostedVersion)
	registerExternal(s, "GetHostedConfigurationVersion", s.getHostedVersion)
	register(s, "DeleteHostedConfigurationVersion", s.deleteHostedVersion)
	register(s, "ListHostedConfigurationVersions", s.listHostedVersions)
}

func hostedSummary(v HostedVersion) api.HostedConfigurationVersionSummary {
	return api.HostedConfigurationVersionSummary{
		ApplicationId:          textOf[api.Id](v.ApplicationID),
		ConfigurationProfileId: textOf[api.Id](v.ProfileID),
		VersionNumber:          new(api.Integer(v.Number)),
		Description:            textOf[api.Description](v.Description),
		ContentType:            textOf[api.StringWithLengthBetween1And255](v.ContentType),
		VersionLabel:           textOf[api.VersionLabel](v.VersionLabel),
		KmsKeyArn:              textOf[api.Arn](v.KMSKeyARN),
	}
}

// hostedOutput returns the version with its plaintext content; stored
// content is ciphertext whenever KMSKeyARN is set.
func hostedOutput(v HostedVersion, plaintext []byte) *api.HostedConfigurationVersion {
	return &api.HostedConfigurationVersion{
		ApplicationId:          textOf[api.Id](v.ApplicationID),
		ConfigurationProfileId: textOf[api.Id](v.ProfileID),
		VersionNumber:          new(api.Integer(v.Number)),
		Description:            textOf[api.Description](v.Description),
		ContentType:            textOf[api.StringWithLengthBetween1And255](v.ContentType),
		VersionLabel:           textOf[api.VersionLabel](v.VersionLabel),
		KmsKeyArn:              textOf[api.Arn](v.KMSKeyARN),
		Content:                api.Blob(plaintext),
	}
}

func hostedContentTooLarge(size int) error {
	e := failure("PayloadTooLargeException", "Content size limit exceeded.")
	e.Details = map[string]json.RawMessage{
		"Measure": json.RawMessage(`"KILOBYTES"`),
		"Limit":   json.RawMessage(`2048.0`),
		"Size":    json.RawMessage(strconv.Itoa((size+1023)/1024) + ".0"),
	}
	return e
}

// kmsFailure reports a KMS owner rejection the way AppConfig wraps
// KMS client errors in a BadRequestException.
func kmsFailure(err error) error {
	var e *awswire.Error
	if errors.As(err, &e) {
		return failure("BadRequestException", fmt.Sprintf("%s (Service: AWSKMS; Status Code: %d; Error Code: %s)", e.Message, e.StatusCode, e.Code))
	}
	return err
}

func latestHosted(rows []HostedVersion) (HostedVersion, bool) {
	var latest HostedVersion
	for _, v := range rows {
		if v.Number > latest.Number {
			latest = v
		}
	}
	return latest, latest.Number > 0
}

type hostedDraft struct {
	app      Application
	profile  Profile
	latest   int32
	number   int32
	previous *HostedVersion
}

// admitHosted evaluates current IAM and all state-dependent admission for a
// new hosted version. Hosted versions are accepted for any profile source,
// matching native CodePipeline-profile behavior. Freeform validators are not
// run at creation; ValidateConfiguration and StartDeployment own them.
func (s *Service) admitHosted(r Reader, in *api.CreateHostedConfigurationVersionInput) (hostedDraft, error) {
	const action = "CreateHostedConfigurationVersion"
	sc := scopeFor(r.Context())
	app, err := s.controlApplication(r, sc, action, value(in.ApplicationId))
	if err != nil {
		return hostedDraft{}, err
	}
	profile, err := s.controlProfile(r, sc, action, app, value(in.ConfigurationProfileId))
	if err != nil {
		return hostedDraft{}, err
	}
	if len(in.Content) == 0 {
		return hostedDraft{}, failure("BadRequestException", "1 validation error detected: Value at 'content' failed to satisfy constraint: Member must not be null")
	}
	if len(in.Content) > hostedContentLimit {
		return hostedDraft{}, hostedContentTooLarge(len(in.Content))
	}
	label := value(in.VersionLabel)
	if label != "" && strings.Trim(label, "0123456789") == "" {
		return hostedDraft{}, failure("BadRequestException", fmt.Sprintf("1 validation error detected: Value '%s' at 'versionLabel' failed to satisfy constraint: Member must satisfy regular expression pattern: .*[^0-9].*", label))
	}
	rows, err := r.HostedVersions(sc, app.ID, profile.ID)
	if err != nil {
		return hostedDraft{}, err
	}
	d := hostedDraft{app: app, profile: profile}
	if latest, ok := latestHosted(rows); ok {
		d.latest, d.previous = latest.Number, &latest
	}
	if label != "" {
		if i := slices.IndexFunc(rows, func(v HostedVersion) bool { return v.VersionLabel == label }); i >= 0 {
			return hostedDraft{}, failure("BadRequestException", fmt.Sprintf("The version label '%s' has already been assigned to hosted configuration version %d. Please provide a different version label to create your hosted configuration version.", label, rows[i].Number))
		}
	}
	if in.LatestVersionNumber != nil && number(in.LatestVersionNumber) != d.latest {
		return hostedDraft{}, failure("ConflictException", fmt.Sprintf("Expected latest version %d does not match actual latest version %d", number(in.LatestVersionNumber), d.latest))
	}
	// Numbers are never reused after deletion.
	d.number = max(profile.NextVersion, d.latest+1, 1)
	return d, nil
}

// createHostedVersion runs feature-flag normalization, PRE_CREATE extensions
// and KMS protection outside repository transactions, then commits only if
// the profile's version sequence and encryption settings are unchanged.
func (s *Service) createHostedVersion(ctx context.Context, in *api.CreateHostedConfigurationVersionInput) (*api.HostedConfigurationVersion, error) {
	var d hostedDraft
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		d, err = s.admitHosted(r, in)
		return err
	}); err != nil {
		return nil, err
	}
	sc := d.profile.Scope
	content := ConfigurationContent{Content: slices.Clone([]byte(in.Content)), ContentType: value(in.ContentType), Version: formatVersion(d.number), VersionLabel: value(in.VersionLabel), Description: value(in.Description)}
	if d.profile.Type == profileFlags {
		var previous []byte
		if d.previous != nil {
			previous = d.previous.Content
			if d.previous.KMSKeyARN != "" {
				if s.effects == nil {
					return nil, failure("BadRequestException", "KMS decryption is not configured")
				}
				var err error
				if previous, err = s.effects.Unprotect(ctx, sc, d.previous.KMSKeyARN, hostedVersionARN(sc, d.app.ID, d.profile.ID, d.previous.Number), previous); err != nil {
					return nil, kmsFailure(err)
				}
			}
		}
		normalized, err := normalizeFeatureFlags(content.Content, previous, s.clock.Now().UTC())
		if err != nil {
			return nil, err
		}
		content.Content = normalized
	}
	content, _, _, err := s.runExtensions(ctx, "PRE_CREATE_HOSTED_CONFIGURATION_VERSION", d.app, nil, &d.profile, content, nil)
	if err != nil {
		return nil, err
	}
	// Extensions and feature-flag normalization can enlarge an admitted input.
	// Apply the hosted quota to the final plaintext before encryption or commit.
	if len(content.Content) > hostedContentLimit {
		return nil, hostedContentTooLarge(len(content.Content))
	}
	version := HostedVersion{Scope: sc, ApplicationID: d.app.ID, ProfileID: d.profile.ID, Number: d.number, Description: value(in.Description), ContentType: content.ContentType, VersionLabel: value(in.VersionLabel), Content: content.Content}
	if d.profile.KMSKeyIdentifier != "" {
		if s.effects == nil {
			return nil, failure("BadRequestException", "KMS encryption is not configured")
		}
		if version.Content, version.KMSKeyARN, err = s.effects.Protect(ctx, sc, d.profile.KMSKeyIdentifier, hostedVersionARN(sc, d.app.ID, d.profile.ID, d.number), content.Content); err != nil {
			return nil, kmsFailure(err)
		}
	}
	var out *api.HostedConfigurationVersion
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		current, err := s.admitHosted(tx, in)
		if err != nil {
			return err
		}
		if current.number != d.number || current.latest != d.latest {
			return failure("ConflictException", fmt.Sprintf("Expected latest version %d does not match actual latest version %d", d.latest, current.latest))
		}
		if current.profile.KMSKeyIdentifier != d.profile.KMSKeyIdentifier || current.profile.Type != d.profile.Type {
			return failure("ConflictException", "The configuration profile changed while the hosted configuration version was being created.")
		}
		if err := tx.PutHostedVersion(version); err != nil {
			return err
		}
		current.profile.NextVersion = version.Number + 1
		if err := tx.PutProfile(current.profile); err != nil {
			return err
		}
		out = hostedOutput(version, content.Content)
		out.Description = in.Description
		return s.recordCall(tx.Context(), "CreateHostedConfigurationVersion", in, out, nil)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// hostedVersionARN identifies a hosted version for IAM and, as observed in
// native KMS events, the aws:appconfig:hostedconfigurationversion:arn
// encryption context of its protected content.
func hostedVersionARN(sc Scope, app, profile string, n int32) string {
	return profileARN(sc, app, profile) + "/hostedconfigurationversion/" + formatVersion(n)
}

// controlHostedVersion resolves a version by number and authorizes the
// application, profile and hosted-version resource elements.
func (s *Service) controlHostedVersion(r Reader, action string, app, profile string, n int32) (HostedVersion, error) {
	sc := scopeFor(r.Context())
	a, err := s.controlApplication(r, sc, action, app)
	if err != nil {
		return HostedVersion{}, err
	}
	p, err := s.controlProfile(r, sc, action, a, profile)
	if err != nil {
		return HostedVersion{}, err
	}
	resource := hostedVersionARN(sc, a.ID, p.ID, n)
	if err := s.authorize(r.Context(), action, resource, nil); err != nil {
		return HostedVersion{}, err
	}
	rows, err := r.HostedVersions(sc, a.ID, p.ID)
	if err != nil {
		return HostedVersion{}, err
	}
	i := slices.IndexFunc(rows, func(v HostedVersion) bool { return v.Number == n })
	if i < 0 {
		return HostedVersion{}, hostedVersionMissing(sc, a.ID, p.ID, n)
	}
	return rows[i], nil
}

// getHostedVersion decrypts KMS-protected content through the KMS owner
// outside repository transactions and records the read after re-resolving it.
func (s *Service) getHostedVersion(ctx context.Context, in *api.GetHostedConfigurationVersionInput) (*api.HostedConfigurationVersion, error) {
	const action = "GetHostedConfigurationVersion"
	var v HostedVersion
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = s.controlHostedVersion(r, action, value(in.ApplicationId), value(in.ConfigurationProfileId), number(in.VersionNumber))
		return err
	}); err != nil {
		return nil, err
	}
	plaintext := v.Content
	if v.KMSKeyARN != "" {
		if s.effects == nil {
			return nil, failure("BadRequestException", "KMS decryption is not configured")
		}
		var err error
		if plaintext, err = s.effects.Unprotect(ctx, v.Scope, v.KMSKeyARN, hostedVersionARN(v.Scope, v.ApplicationID, v.ProfileID, v.Number), v.Content); err != nil {
			return nil, kmsFailure(err)
		}
	}
	var out *api.HostedConfigurationVersion
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		if _, err := s.controlHostedVersion(tx, action, value(in.ApplicationId), value(in.ConfigurationProfileId), number(in.VersionNumber)); err != nil {
			return err
		}
		out = hostedOutput(v, plaintext)
		return s.recordCall(tx.Context(), action, in, out, nil)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) deleteHostedVersion(tx Transaction, in *api.DeleteHostedConfigurationVersionInput) (*api.Unit, error) {
	v, err := s.controlHostedVersion(tx, "DeleteHostedConfigurationVersion", value(in.ApplicationId), value(in.ConfigurationProfileId), number(in.VersionNumber))
	if err != nil {
		return nil, err
	}
	if err := tx.DeleteHostedVersion(v.Scope, v.ApplicationID, v.ProfileID, v.Number); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

// listHostedVersions returns newest versions first. A VersionLabel filter
// ending in '*' matches label prefixes; otherwise it matches exactly.
func (s *Service) listHostedVersions(tx Transaction, in *api.ListHostedConfigurationVersionsInput) (*api.HostedConfigurationVersions, error) {
	const action = "ListHostedConfigurationVersions"
	sc := scopeFor(tx.Context())
	app, err := s.controlApplication(tx, sc, action, value(in.ApplicationId))
	if err != nil {
		return nil, err
	}
	p, err := s.controlProfile(tx, sc, action, app, value(in.ConfigurationProfileId))
	if err != nil {
		return nil, err
	}
	rows, err := tx.HostedVersions(sc, app.ID, p.ID)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b HostedVersion) int { return int(b.Number) - int(a.Number) })
	if filter := value(in.VersionLabel); filter != "" {
		prefix, wildcard := strings.CutSuffix(filter, "*")
		rows = slices.DeleteFunc(rows, func(v HostedVersion) bool {
			if wildcard {
				return v.VersionLabel == "" || !strings.HasPrefix(v.VersionLabel, prefix)
			}
			return v.VersionLabel != filter
		})
	}
	rows, next, err := page(rows, in.NextToken, in.MaxResults, pageBinding(sc, action, app.ID, p.ID, value(in.VersionLabel)), func(i int) pageKey { return pageKey{Number: -int64(rows[i].Number)} })
	if err != nil {
		return nil, err
	}
	out := &api.HostedConfigurationVersions{Items: make(api.HostedConfigurationVersionSummaryList, 0, len(rows)), NextToken: next}
	for _, v := range rows {
		out.Items = append(out.Items, hostedSummary(v))
	}
	return out, nil
}
