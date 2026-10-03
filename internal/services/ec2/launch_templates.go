package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func registerLaunchTemplates(s *Service) {
	register(s, "CreateLaunchTemplate", s.createLaunchTemplate)
	register(s, "CreateLaunchTemplateVersion", s.createLaunchTemplateVersion)
	register(s, "DescribeLaunchTemplates", s.describeLaunchTemplates)
	register(s, "DescribeLaunchTemplateVersions", s.describeLaunchTemplateVersions)
	register(s, "ModifyLaunchTemplate", s.modifyLaunchTemplate)
	register(s, "DeleteLaunchTemplate", s.deleteLaunchTemplate)
	register(s, "DeleteLaunchTemplateVersions", s.deleteLaunchTemplateVersions)
	register(s, "GetLaunchTemplateData", s.getLaunchTemplateData)
}

var launchTemplateNamePattern = regexp.MustCompile(`^[a-zA-Z0-9()./_-]{3,128}$`)
var launchTemplateIDPattern = regexp.MustCompile(`^lt-[0-9a-f]{17}$`)
var launchTemplateImagePattern = regexp.MustCompile(`^ami-([0-9a-f]{8}|[0-9a-f]{17})$`)

func launchTemplateMissing(id, name string) error {
	if id != "" {
		return failure("InvalidLaunchTemplateId.NotFound", "The specified launch template, with template ID "+id+", does not exist.")
	}
	return failure("InvalidLaunchTemplateName.NotFoundException", "The specified launch template, with template name "+name+", does not exist.")
}
func selectLaunchTemplate(ctx context.Context, tx Reader, id, name string) (LaunchTemplateRecord, error) {
	if id != "" && name != "" {
		return LaunchTemplateRecord{}, failure("InvalidParameterCombination", "Either provide launch template ID or launch template name to modify the template.")
	}
	if id == "" && name == "" {
		return LaunchTemplateRecord{}, failure("MissingParameter", "A launch template ID or name must be specified.")
	}
	if id != "" {
		if !launchTemplateIDPattern.MatchString(id) {
			return LaunchTemplateRecord{}, failure("InvalidLaunchTemplateId.Malformed", "The following launch template ids are malformed: "+id)
		}
		v, err := tx.LaunchTemplate(key(ctx, id))
		if errors.Is(err, ErrNotFound) {
			err = launchTemplateMissing(id, name)
		}
		return v, err
	}
	rows, err := tx.LaunchTemplates(scopeFor(ctx))
	if err != nil {
		return LaunchTemplateRecord{}, err
	}
	for _, row := range rows {
		if str(row.Data.LaunchTemplateName) == name {
			return row, nil
		}
	}
	return LaunchTemplateRecord{}, launchTemplateMissing(id, name)
}
func launchTemplateVersionNumber(template LaunchTemplateRecord, raw string) (int64, error) {
	switch raw {
	case "", "$Default":
		return int64(*template.Data.DefaultVersionNumber), nil
	case "$Latest":
		return int64(*template.Data.LatestVersionNumber), nil
	}
	number, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || number < 1 {
		return 0, failure("InvalidParameterValue", "Invalid launch template version: either '$Default', '$Latest', or a numeric version are allowed.")
	}
	return number, nil
}
func selectLaunchTemplateVersion(tx Reader, template LaunchTemplateRecord, raw string) (LaunchTemplateVersionRecord, error) {
	number, err := launchTemplateVersionNumber(template, raw)
	if err != nil {
		return LaunchTemplateVersionRecord{}, err
	}
	v, err := tx.LaunchTemplateVersion(LaunchTemplateVersionKey{template.Key, number})
	if errors.Is(err, ErrNotFound) {
		err = failure("InvalidLaunchTemplateId.VersionNotFound", "Could not find the specified version "+strconv.FormatInt(number, 10)+" for the launch template with ID "+template.Key.ID+".")
	}
	return v, err
}
func launchTemplateVersionResult(template LaunchTemplateRecord, version LaunchTemplateVersionRecord) api.LaunchTemplateVersion {
	data := api.LaunchTemplateConvertRequestLaunchTemplateDataToResponseLaunchTemplateData(version.Data)
	return api.LaunchTemplateVersion{LaunchTemplateId: new(api.String(template.Key.ID)), LaunchTemplateName: copyPointer(template.Data.LaunchTemplateName),
		VersionNumber: new(api.Long(version.Key.Number)), VersionDescription: copyPointer(version.Description), CreateTime: new(api.DateTime(version.CreatedAt)), CreatedBy: new(api.String(version.CreatedBy)),
		DefaultVersion: new(api.Boolean(version.Key.Number == int64(*template.Data.DefaultVersionNumber))), LaunchTemplateData: &data, Operator: &api.OperatorResponse{Managed: new(api.Boolean(false))}}
}

func launchTemplateToken(ctx context.Context, tx Reader, action, token string, input any) (LaunchTemplateTokenRecord, bool, error) {
	v := LaunchTemplateTokenRecord{Key: LaunchTemplateTokenKey{scopeFor(ctx), action, token}}
	if token == "" {
		return v, false, nil
	}
	if len(token) > 128 {
		return v, false, failure("InvalidParameterValue", "Client token must not exceed 128 ASCII characters.")
	}
	for _, c := range token {
		if c > 127 {
			return v, false, failure("InvalidParameterValue", "Client token must contain only ASCII characters.")
		}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return v, false, err
	}
	sum := sha256.Sum256(data)
	v.Fingerprint = hex.EncodeToString(sum[:])
	old, err := tx.LaunchTemplateToken(v.Key)
	if errors.Is(err, ErrNotFound) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	if old.Fingerprint != v.Fingerprint {
		return v, false, failure("IdempotentParameterMismatch", "Client token already used before.")
	}
	return old, true, nil
}
func putLaunchTemplateToken(tx Transaction, token LaunchTemplateTokenRecord, id string, version int64) error {
	if token.Key.Token == "" {
		return nil
	}
	token.TemplateID, token.Version = id, version
	return tx.PutLaunchTemplateToken(token)
}
func validateTemplateData(data *api.RequestLaunchTemplateData, description *api.VersionDescription) error {
	if description != nil && utf8.RuneCountInString(string(*description)) > 255 {
		return failure("InvalidParameterValue", "Version description must not exceed 255 characters.")
	}
	if data == nil {
		return failure("MissingParameter", "No launch template data was provided. Launch template data is required to create a launch template.")
	}
	if data.Operator != nil {
		return unsupported("Managed launch-template operators require a service-owned resource provider.")
	}
	if image := str(data.ImageId); image != "" && !strings.HasPrefix(image, "resolve:ssm:") && !launchTemplateImagePattern.MatchString(image) {
		return failure("InvalidAMIID.Malformed", "The image ID '"+image+"' is not valid. The expected format is ami-xxxxxxxx or ami-xxxxxxxxxxxxxxxxx.")
	}
	if data.UserData != nil {
		decoded, err := base64.StdEncoding.DecodeString(str(data.UserData))
		if err != nil {
			return failure("InvalidUserData.Malformed", "Invalid BASE64 encoding of user data.")
		}
		if len(decoded) > 16*1024 {
			return failure("InvalidParameterValue", "User data exceeds 16384 bytes.")
		}
	}
	if m := data.MetadataOptions; m != nil {
		if m.HttpPutResponseHopLimit != nil && (*m.HttpPutResponseHopLimit < 1 || *m.HttpPutResponseHopLimit > 64) {
			return failure("InvalidParameterValue", "HTTP PUT response hop limit must be between 1 and 64.")
		}
		for _, check := range []struct {
			value string
			valid []string
		}{{str(m.HttpTokens), []string{"optional", "required"}}, {str(m.HttpEndpoint), []string{"enabled", "disabled"}}, {str(m.HttpProtocolIpv6), []string{"enabled", "disabled"}}, {str(m.InstanceMetadataTags), []string{"enabled", "disabled"}}} {
			if check.value != "" && check.value != check.valid[0] && check.value != check.valid[1] {
				return failure("InvalidParameterValue", "Invalid launch template metadata option.")
			}
		}
	}
	for _, spec := range data.TagSpecifications {
		if err := validateTags(spec.Tags); err != nil {
			return err
		}
	}
	return nil
}
func templateDataEmpty(data api.RequestLaunchTemplateData) bool {
	return !api.HasRequestLaunchTemplateData(data)
}

func (s *Service) createLaunchTemplate(ctx context.Context, tx Transaction, in *api.CreateLaunchTemplateRequest) (*api.CreateLaunchTemplateResult, error) {
	tags, err := CreationTags(in.TagSpecifications, "launch-template")
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	for _, tag := range tags {
		conditions["aws:ResourceTag/"+str(tag.Key)] = []string{str(tag.Value)}
		conditions["ec2:ResourceTag/"+str(tag.Key)] = []string{str(tag.Value)}
	}
	if err := s.authorizeCreateWith(ctx, "CreateLaunchTemplate", "launch-template", "*", tags, conditions); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if !launchTemplateNamePattern.MatchString(str(in.LaunchTemplateName)) {
		return nil, failure("InvalidLaunchTemplateName.MalformedException", "A launch template name must be between 3 and 128 characters, and may contain letters, numbers, and the following characters: - ( ) . / _.")
	}
	if in.Operator != nil {
		return nil, unsupported("Managed launch templates require a service-owned resource provider.")
	}
	if err := validateTemplateData(in.LaunchTemplateData, in.VersionDescription); err != nil {
		return nil, err
	}
	if templateDataEmpty(*in.LaunchTemplateData) {
		return nil, failure("MissingParameter", "No launch template data was provided. Launch template data is required to create a launch template.")
	}
	copy := *in
	copy.ClientToken, copy.DryRun = nil, nil
	token, replay, err := launchTemplateToken(ctx, tx, "CreateLaunchTemplate", str(in.ClientToken), copy)
	if err != nil {
		return nil, err
	}
	if replay {
		previous, err := tx.LaunchTemplate(key(ctx, token.TemplateID))
		if errors.Is(err, ErrNotFound) || (err == nil && previous.LastVersion != token.Version) {
			return nil, failure("IdempotentParameterMismatch", "Client token already used before.")
		}
		if err != nil {
			return nil, err
		}
		return &api.CreateLaunchTemplateResult{LaunchTemplate: &previous.Data}, nil
	}
	rows, err := tx.LaunchTemplates(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if str(row.Data.LaunchTemplateName) == str(in.LaunchTemplateName) {
			return nil, failure("InvalidLaunchTemplateName.AlreadyExistsException", "Launch template name already in use.")
		}
	}
	id, err := tx.NextID(scopeFor(ctx), "lt")
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	actor := awsctx.FromContext(ctx).PrincipalARN
	template := LaunchTemplateRecord{Key: key(ctx, id), LastVersion: 1, Data: api.LaunchTemplate{LaunchTemplateId: new(api.String(id)), LaunchTemplateName: new(api.LaunchTemplateName(str(in.LaunchTemplateName))), CreateTime: new(api.DateTime(now)), CreatedBy: new(api.String(actor)), DefaultVersionNumber: new(api.Long(1)), LatestVersionNumber: new(api.Long(1)), Tags: tags, Operator: &api.OperatorResponse{Managed: new(api.Boolean(false))}}}
	version := LaunchTemplateVersionRecord{Key: LaunchTemplateVersionKey{template.Key, 1}, CreatedAt: now, CreatedBy: actor, Description: copyPointer(in.VersionDescription), Data: api.CloneRequestLaunchTemplateData(*in.LaunchTemplateData)}
	if err := tx.PutLaunchTemplate(template); err != nil {
		return nil, err
	}
	if err := tx.PutLaunchTemplateVersion(version); err != nil {
		return nil, err
	}
	if err := putLaunchTemplateToken(tx, token, id, 1); err != nil {
		return nil, err
	}
	warning, err := templateWarnings(ctx, tx, version.Data)
	if err != nil {
		return nil, err
	}
	return &api.CreateLaunchTemplateResult{LaunchTemplate: &template.Data, Warning: warning}, nil
}

func (s *Service) createLaunchTemplateVersion(ctx context.Context, tx Transaction, in *api.CreateLaunchTemplateVersionRequest) (*api.CreateLaunchTemplateVersionResult, error) {
	template, err := selectLaunchTemplate(ctx, tx, str(in.LaunchTemplateId), str(in.LaunchTemplateName))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "CreateLaunchTemplateVersion", "launch-template", template.Key.ID, template.Data.Tags); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	overrides := api.RequestLaunchTemplateData{}
	if in.LaunchTemplateData != nil {
		overrides = api.CloneRequestLaunchTemplateData(*in.LaunchTemplateData)
	}
	if err := validateTemplateData(&overrides, in.VersionDescription); err != nil {
		return nil, err
	}
	copy := *in
	copy.ClientToken, copy.DryRun = nil, nil
	token, replay, err := launchTemplateToken(ctx, tx, "CreateLaunchTemplateVersion", str(in.ClientToken), copy)
	if err != nil {
		return nil, err
	}
	if replay {
		v, err := selectLaunchTemplateVersion(tx, template, strconv.FormatInt(token.Version, 10))
		if err != nil {
			return nil, err
		}
		result := launchTemplateVersionResult(template, v)
		return &api.CreateLaunchTemplateVersionResult{LaunchTemplateVersion: &result}, nil
	}
	data := api.RequestLaunchTemplateData{}
	if in.SourceVersion != nil {
		v, err := selectLaunchTemplateVersion(tx, template, str(in.SourceVersion))
		if err != nil {
			return nil, err
		}
		data = v.Data
	}
	api.OverlayRequestLaunchTemplateData(&data, overrides)
	if templateDataEmpty(data) {
		return nil, failure("MissingParameter", "No launch template data was provided. Launch template data is required to create a launch template.")
	}
	if boolValue(in.ResolveAlias) && strings.HasPrefix(str(data.ImageId), "resolve:ssm:") {
		return nil, unsupported("Resolving SSM image aliases in launch templates is not implemented.")
	}
	template.LastVersion++
	template.Data.LatestVersionNumber = new(api.Long(template.LastVersion))
	v := LaunchTemplateVersionRecord{Key: LaunchTemplateVersionKey{template.Key, template.LastVersion}, CreatedAt: s.clock.Now(), CreatedBy: awsctx.FromContext(ctx).PrincipalARN, Description: copyPointer(in.VersionDescription), Data: data}
	if err := tx.PutLaunchTemplate(template); err != nil {
		return nil, err
	}
	if err := tx.PutLaunchTemplateVersion(v); err != nil {
		return nil, err
	}
	if err := putLaunchTemplateToken(tx, token, template.Key.ID, v.Key.Number); err != nil {
		return nil, err
	}
	result := launchTemplateVersionResult(template, v)
	warning, err := templateWarnings(ctx, tx, data)
	if err != nil {
		return nil, err
	}
	return &api.CreateLaunchTemplateVersionResult{LaunchTemplateVersion: &result, Warning: warning}, nil
}

func (s *Service) modifyLaunchTemplate(ctx context.Context, tx Transaction, in *api.ModifyLaunchTemplateRequest) (*api.ModifyLaunchTemplateResult, error) {
	template, err := selectLaunchTemplate(ctx, tx, str(in.LaunchTemplateId), str(in.LaunchTemplateName))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ModifyLaunchTemplate", "launch-template", template.Key.ID, template.Data.Tags); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(in.DefaultVersion) == "" {
		return nil, failure("MissingParameter", "A launch template version must be specified to set the new default version for the template with ID "+template.Key.ID+".")
	}
	copy := *in
	copy.ClientToken, copy.DryRun = nil, nil
	token, replay, err := launchTemplateToken(ctx, tx, "ModifyLaunchTemplate", str(in.ClientToken), copy)
	if err != nil {
		return nil, err
	}
	if replay {
		template.Data.Tags = nil
		template.Data.CreateTime = new(api.DateTime(time.Unix(0, 0).UTC()))
		return &api.ModifyLaunchTemplateResult{LaunchTemplate: &template.Data}, nil
	}
	version, err := selectLaunchTemplateVersion(tx, template, str(in.DefaultVersion))
	if err != nil {
		return nil, err
	}
	template.Data.DefaultVersionNumber = new(api.Long(version.Key.Number))
	if err := tx.PutLaunchTemplate(template); err != nil {
		return nil, err
	}
	if err := putLaunchTemplateToken(tx, token, template.Key.ID, version.Key.Number); err != nil {
		return nil, err
	}
	template.Data.Tags = nil
	template.Data.CreateTime = new(api.DateTime(time.Unix(0, 0).UTC()))
	return &api.ModifyLaunchTemplateResult{LaunchTemplate: &template.Data}, nil
}

func (s *Service) deleteLaunchTemplate(ctx context.Context, tx Transaction, in *api.DeleteLaunchTemplateRequest) (*api.DeleteLaunchTemplateResult, error) {
	template, err := selectLaunchTemplate(ctx, tx, str(in.LaunchTemplateId), str(in.LaunchTemplateName))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteLaunchTemplate", "launch-template", template.Key.ID, template.Data.Tags); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	// Existing instances retain launch identity; AWS does not block template
	// deletion on instances (or on external consumers such as Auto Scaling).
	if err := tx.DeleteLaunchTemplate(template.Key); err != nil {
		return nil, err
	}
	template.Data.Tags = nil
	return &api.DeleteLaunchTemplateResult{LaunchTemplate: &template.Data}, nil
}

func (s *Service) deleteLaunchTemplateVersions(ctx context.Context, tx Transaction, in *api.DeleteLaunchTemplateVersionsRequest) (*api.DeleteLaunchTemplateVersionsResult, error) {
	template, err := selectLaunchTemplate(ctx, tx, str(in.LaunchTemplateId), str(in.LaunchTemplateName))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DeleteLaunchTemplateVersions", "launch-template", template.Key.ID, template.Data.Tags); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.Versions) == 0 {
		return nil, failure("MissingParameter", "At least one launch template version must be specified.")
	}
	numbers := make([]int64, 0, len(in.Versions))
	seen := map[int64]bool{}
	for _, raw := range in.Versions {
		n, err := launchTemplateVersionNumber(template, string(raw))
		if err != nil {
			return nil, failure("InvalidParameterValue", "Invalid value for version: "+string(raw))
		}
		if !seen[n] {
			numbers = append(numbers, n)
			seen[n] = true
		}
	}
	if seen[int64(*template.Data.DefaultVersionNumber)] {
		return nil, failure("InvalidParameterValue", "The default version cannot be deleted. Either specify another version as default or delete the launch template.")
	}
	out := &api.DeleteLaunchTemplateVersionsResult{SuccessfullyDeletedLaunchTemplateVersions: api.DeleteLaunchTemplateVersionsResponseSuccessSet{}, UnsuccessfullyDeletedLaunchTemplateVersions: api.DeleteLaunchTemplateVersionsResponseErrorSet{}}
	for _, n := range numbers {
		err := tx.DeleteLaunchTemplateVersion(LaunchTemplateVersionKey{template.Key, n})
		if errors.Is(err, ErrNotFound) {
			out.UnsuccessfullyDeletedLaunchTemplateVersions = append(out.UnsuccessfullyDeletedLaunchTemplateVersions, api.DeleteLaunchTemplateVersionsResponseErrorItem{LaunchTemplateId: new(api.String(template.Key.ID)), LaunchTemplateName: new(api.String(str(template.Data.LaunchTemplateName))), VersionNumber: new(api.Long(n)), ResponseError: &api.ResponseError{Code: new(api.LaunchTemplateErrorCode("launchTemplateVersionDoesNotExist")), Message: new(api.String("The launch template version does not exist."))}})
			continue
		}
		if err != nil {
			return nil, err
		}
		out.SuccessfullyDeletedLaunchTemplateVersions = append(out.SuccessfullyDeletedLaunchTemplateVersions, api.DeleteLaunchTemplateVersionsResponseSuccessItem{LaunchTemplateId: new(api.String(template.Key.ID)), LaunchTemplateName: new(api.String(str(template.Data.LaunchTemplateName))), VersionNumber: new(api.Long(n))})
	}
	versions, err := tx.LaunchTemplateVersions(template.Key)
	if err != nil {
		return nil, err
	}
	if len(versions) > 0 {
		template.Data.LatestVersionNumber = new(api.Long(versions[0].Key.Number))
	}
	if err := tx.PutLaunchTemplate(template); err != nil {
		return nil, err
	}
	return out, nil
}

func templateWarnings(ctx context.Context, tx Reader, data api.RequestLaunchTemplateData) (*api.ValidationWarning, error) {
	warning := &api.ValidationWarning{}
	add := func(code, message string) {
		warning.Errors = append(warning.Errors, api.ValidationError{Code: new(api.String(code)), Message: new(api.String(message))})
	}
	if data.InstanceType != nil && instanceTypeRegion(ctx) == nil {
		if _, known := capturedInstanceTypes.Types[*data.InstanceType]; !known {
			add("InvalidInstanceType", "The following supplied instance types do not exist: ["+string(*data.InstanceType)+"]")
		}
	}
	if len(data.NetworkInterfaces) > 0 && (len(data.SecurityGroupIds) > 0 || len(data.SecurityGroups) > 0) {
		add("InvalidParameterCombination", "If you specify a network interface, you must specify all security groups as part of the network interface.")
	}
	for _, network := range data.NetworkInterfaces {
		for _, id := range network.Groups {
			if _, err := tx.SecurityGroup(key(ctx, string(id))); errors.Is(err, ErrNotFound) {
				add("InvalidSecurityGroupID.NotFound", "The security group '"+string(id)+"' does not exist")
			} else if err != nil {
				return nil, err
			}
		}
	}
	if len(warning.Errors) == 0 {
		return nil, nil
	}
	return warning, nil
}
