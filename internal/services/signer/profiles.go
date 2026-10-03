package signer

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"regexp"
	"slices"
	api "stackd/internal/awsapi/signer"
	"strings"
	"time"
)

var profileName = regexp.MustCompile(`^[A-Za-z0-9_]{2,64}$`)

func registerProfiles(s *Service) {
	register(s, "PutSigningProfile", s.putProfile)
	register(s, "GetSigningProfile", s.getProfile)
	register(s, "CancelSigningProfile", s.cancelProfile)
	register(s, "ListSigningProfiles", s.listProfiles)
	register(s, "GetSigningPlatform", s.getPlatform)
	register(s, "ListSigningPlatforms", s.listPlatforms)
	register(s, "ListTagsForResource", s.listTags)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
}
func profileARN(sc Scope, name string) string {
	return "arn:" + sc.Partition + ":signer:" + sc.Region + ":" + sc.AccountID + ":/signing-profiles/" + name
}
func (s *Service) loadProfile(ctx context.Context, r Reader, name, version, owner, action string) (Profile, error) {
	sc := scopeFor(ctx)
	if owner != "" && owner != sc.AccountID {
		return Profile{}, invalid("Cross-account signing profile permissions are not implemented")
	}
	v, e := r.Profile(sc, name, version)
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, v.ARN, v.Tags, nil)
}
func (s *Service) putProfile(ctx context.Context, t Transaction, in *api.PutSigningProfileInput) (*api.PutSigningProfileOutput, error) {
	name := value(in.ProfileName)
	if !profileName.MatchString(name) {
		return nil, invalid("Profile name must contain 2-64 letters, numbers or underscores")
	}
	if value(in.PlatformId) != LambdaPlatform {
		return nil, invalid("Only AWSLambda-SHA384-ECDSA signing is implemented")
	}
	if in.SigningMaterial != nil || in.Overrides != nil || len(in.SigningParameters) > 0 {
		return nil, invalid("Custom signing material, overrides and parameters are not supported for this platform")
	}
	sc := scopeFor(ctx)
	v := Profile{Scope: sc, Name: name, ARN: profileARN(sc, name), Version: strings.ReplaceAll(uuid.NewString(), "-", "")[:10], Status: "Active", Current: true, Created: s.clock.Now().UTC().Truncate(time.Second), ValidityValue: 135, ValidityType: "MONTHS", Tags: map[string]string{}}
	v.VersionARN = v.ARN + "/" + v.Version
	if in.SignatureValidityPeriod != nil {
		p := in.SignatureValidityPeriod
		if p.Value == nil || p.Type == nil {
			return nil, invalid("A signature validity value and type are required")
		}
		v.ValidityValue = int64(*p.Value)
		v.ValidityType = value(p.Type)
	}
	if v.ValidityValue < 1 || v.ValidityType != "DAYS" && v.ValidityType != "MONTHS" && v.ValidityType != "YEARS" || signatureExpiry(v.Created, v).After(v.Created.AddDate(0, 135, 0)) {
		return nil, invalid("Signature validity must be between 1 day and 135 months")
	}
	conditions := map[string][]string{}
	for k, x := range in.Tags {
		v.Tags[string(k)] = string(x)
		conditions["aws:RequestTag/"+string(k)] = []string{string(x)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	if e := validTags(v.Tags); e != nil {
		return nil, e
	}
	if e := s.authorize(ctx, "PutSigningProfile", v.ARN, nil, conditions); e != nil {
		return nil, e
	}
	_, e := t.Profile(sc, name, "")
	if e == nil {
		return nil, invalid("Profile with name " + name + " already exists")
	}
	if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if e = s.issueProfile(t, &v); e != nil {
		return nil, e
	}
	if e = t.PutProfile(v); e != nil {
		return nil, e
	}
	o := &api.PutSigningProfileOutput{}
	text(&o.Arn, v.ARN)
	text(&o.ProfileVersion, v.Version)
	text(&o.ProfileVersionArn, v.VersionARN)
	return o, nil
}
func signatureExpiry(now time.Time, v Profile) time.Time {
	switch v.ValidityType {
	case "DAYS":
		return now.AddDate(0, 0, int(v.ValidityValue))
	case "YEARS":
		return now.AddDate(int(v.ValidityValue), 0, 0)
	default:
		return now.AddDate(0, int(v.ValidityValue), 0)
	}
}
func validity(v Profile) *api.SignatureValidityPeriod {
	return &api.SignatureValidityPeriod{Value: new(api.Integer(v.ValidityValue)), Type: new(api.ValidityType(v.ValidityType))}
}
func (s *Service) getProfile(ctx context.Context, t Transaction, in *api.GetSigningProfileInput) (*api.GetSigningProfileOutput, error) {
	v, e := s.loadProfile(ctx, t, value(in.ProfileName), "", value(in.ProfileOwner), "GetSigningProfile")
	if e != nil {
		return nil, e
	}
	o := &api.GetSigningProfileOutput{SignatureValidityPeriod: validity(v)}
	text(&o.Arn, v.ARN)
	text(&o.ProfileName, v.Name)
	text(&o.ProfileVersion, v.Version)
	text(&o.ProfileVersionArn, v.VersionARN)
	text(&o.PlatformId, LambdaPlatform)
	text(&o.PlatformDisplayName, "AWS Lambda")
	text(&o.Status, v.Status)
	tags(&o.Tags, v.Tags)
	if !v.RevokedAt.IsZero() {
		o.RevocationRecord = &api.SigningProfileRevocationRecord{RevocationEffectiveFrom: &v.EffectiveTime, RevokedAt: &v.RevokedAt, RevokedBy: new(api.String(v.RevokedBy))}
		text(&o.StatusReason, v.RevocationReason)
	}
	return o, nil
}
func (s *Service) cancelProfile(ctx context.Context, t Transaction, in *api.CancelSigningProfileInput) (*api.CancelSigningProfileOutput, error) {
	v, e := s.loadProfile(ctx, t, value(in.ProfileName), "", "", "CancelSigningProfile")
	if e != nil {
		return nil, e
	}
	if v.Status == "Revoked" {
		return nil, invalid("A revoked signing profile cannot be canceled")
	}
	v.Status = "Canceled"
	return &api.CancelSigningProfileOutput{}, t.PutProfile(v)
}
func page(max *api.MaxResults, token string) (int, string, error) {
	limit := 25
	if max != nil {
		limit = int(*max)
	}
	if limit < 1 || limit > 1000 {
		return 0, "", invalid("Invalid maxResults")
	}
	if token == "" {
		return limit, "", nil
	}
	b, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil {
		return 0, "", invalid("Invalid nextToken")
	}
	return limit, string(b), nil
}
func (s *Service) listProfiles(ctx context.Context, t Transaction, in *api.ListSigningProfilesInput) (*api.ListSigningProfilesOutput, error) {
	if e := s.authorize(ctx, "ListSigningProfiles", "", nil, nil); e != nil {
		return nil, e
	}
	limit, after, e := page(in.MaxResults, value(in.NextToken))
	if e != nil {
		return nil, e
	}
	rows, e := t.Profiles(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	o := &api.ListSigningProfilesOutput{Profiles: api.SigningProfiles{}}
	for _, v := range rows {
		if !v.Current || v.VersionARN <= after || value(in.PlatformId) != "" && value(in.PlatformId) != LambdaPlatform || v.Status == "Canceled" && (in.IncludeCanceled == nil || !bool(*in.IncludeCanceled)) || len(in.Statuses) > 0 && !slices.Contains(in.Statuses, api.SigningProfileStatus(v.Status)) {
			continue
		}
		if len(o.Profiles) == limit {
			text(&o.NextToken, base64.RawURLEncoding.EncodeToString([]byte(value(o.Profiles[len(o.Profiles)-1].ProfileVersionArn))))
			break
		}
		p := api.SigningProfile{SignatureValidityPeriod: validity(v)}
		text(&p.Arn, v.ARN)
		text(&p.ProfileName, v.Name)
		text(&p.ProfileVersion, v.Version)
		text(&p.ProfileVersionArn, v.VersionARN)
		text(&p.Status, v.Status)
		text(&p.PlatformId, LambdaPlatform)
		text(&p.PlatformDisplayName, "AWS Lambda")
		tags(&p.Tags, v.Tags)
		o.Profiles = append(o.Profiles, p)
	}
	return o, nil
}
func validTags(v map[string]string) error {
	if len(v) > 200 {
		return invalid("Too many tags")
	}
	for k, x := range v {
		if k == "" || len(k) > 128 || len(x) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid tag")
		}
	}
	return nil
}
func (s *Service) tagProfile(ctx context.Context, t Transaction, arn string) (Profile, error) {
	prefix := profileARN(scopeFor(ctx), "")
	if !strings.HasPrefix(arn, prefix) {
		return Profile{}, ErrNotFound
	}
	name := strings.TrimPrefix(arn, prefix)
	if strings.Contains(name, "/") {
		return Profile{}, ErrNotFound
	}
	return t.Profile(scopeFor(ctx), name, "")
}
func (s *Service) listTags(ctx context.Context, t Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	v, e := s.tagProfile(ctx, t, value(in.ResourceArn))
	if e != nil {
		return nil, e
	}
	if e = s.authorize(ctx, "ListTagsForResource", v.ARN, v.Tags, nil); e != nil {
		return nil, e
	}
	o := &api.ListTagsForResourceOutput{}
	tags(&o.Tags, v.Tags)
	return o, nil
}
func (s *Service) tagResource(ctx context.Context, t Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	v, e := s.tagProfile(ctx, t, value(in.ResourceArn))
	if e != nil {
		return nil, e
	}
	conditions := map[string][]string{}
	for k, x := range in.Tags {
		conditions["aws:RequestTag/"+string(k)] = []string{string(x)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	if e = s.authorize(ctx, "TagResource", v.ARN, v.Tags, conditions); e != nil {
		return nil, e
	}
	for k, x := range in.Tags {
		v.Tags[string(k)] = string(x)
	}
	if e = validTags(v.Tags); e != nil {
		return nil, e
	}
	return &api.TagResourceOutput{}, t.PutProfile(v)
}
func (s *Service) untagResource(ctx context.Context, t Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	v, e := s.tagProfile(ctx, t, value(in.ResourceArn))
	if e != nil {
		return nil, e
	}
	conditions := map[string][]string{}
	for _, k := range in.TagKeys {
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], string(k))
	}
	if e = s.authorize(ctx, "UntagResource", v.ARN, v.Tags, conditions); e != nil {
		return nil, e
	}
	for _, k := range in.TagKeys {
		delete(v.Tags, string(k))
	}
	return &api.UntagResourceOutput{}, t.PutProfile(v)
}
