package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) registerLayers() {
	register(s, "PublishLayerVersion", s.publishLayerVersion)
	register(s, "GetLayerVersion", s.getLayerVersion)
	register(s, "GetLayerVersionByArn", s.getLayerVersionByArn)
	register(s, "DeleteLayerVersion", s.deleteLayerVersion)
	register(s, "ListLayerVersions", s.listLayerVersions)
	register(s, "ListLayers", s.listLayers)
	register(s, "AddLayerVersionPermission", s.addLayerVersionPermission)
	register(s, "GetLayerVersionPolicy", s.getLayerVersionPolicy)
	register(s, "RemoveLayerVersionPermission", s.removeLayerVersionPermission)
}
func layerScope(ctx context.Context) Scope {
	v := awsctx.FromContext(ctx)
	return Scope{Partition: v.Partition, Account: v.AccountID, Region: v.Region}
}
func parseLayerKey(ctx context.Context, name string) (LayerKey, *awswire.Error) {
	key := LayerKey{Scope: layerScope(ctx), Name: name}
	if strings.HasPrefix(name, "arn:") {
		p := strings.Split(name, ":")
		if len(p) != 7 || p[2] != "lambda" || p[5] != "layer" || p[1] != key.Partition || p[3] != key.Region {
			return LayerKey{}, failure("InvalidParameterValueException", "Invalid layer ARN.", 400)
		}
		key.Scope = Scope{Partition: p[1], Region: p[3], Account: p[4]}
		key.Name = p[6]
	}
	return key, nil
}
func layerVersionKey(ctx context.Context, name string, version *api.LayerVersionNumber) (LayerVersionKey, *awswire.Error) {
	key, wire := parseLayerKey(ctx, name)
	if wire != nil {
		return LayerVersionKey{}, wire
	}
	if version == nil || *version < 1 {
		return LayerVersionKey{}, failure("InvalidParameterValueException", "Invalid layer version number.", 400)
	}
	return LayerVersionKey{LayerKey: key, Version: uint64(*version)}, nil
}
func parseLayerVersionARN(ctx context.Context, arn string) (LayerVersionKey, *awswire.Error) {
	p := strings.Split(arn, ":")
	if len(p) != 8 {
		return LayerVersionKey{}, failure("InvalidParameterValueException", "Invalid layer version ARN.", 400)
	}
	version, err := strconv.ParseInt(p[7], 10, 64)
	if err != nil {
		return LayerVersionKey{}, failure("InvalidParameterValueException", "Invalid layer version ARN.", 400)
	}
	return layerVersionKey(ctx, strings.Join(p[:7], ":"), new(api.LayerVersionNumber(version)))
}
func loadLayer(r LayerReader, key LayerVersionKey) (LayerVersionRecord, error) {
	v, err := r.LayerVersion(key)
	if errors.Is(err, ErrNotFound) {
		return v, failure("ResourceNotFoundException", "Layer version "+key.ARN()+" does not exist.", 404)
	}
	return v, err
}
func (s *Service) authorizeLayer(r Reader, action string, key LayerVersionKey, extra map[string][]string) *awswire.Error {
	current, err := r.LayerPolicy(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return wireError(err)
	}
	return s.authorizer.Authorize(r.Context(), authorization.Request{Action: "lambda:" + action, ResourceARN: key.ARN(), ResourceAccountID: key.Account, ResourcePolicies: []authorization.BoundPolicy{{Document: current.Document, PrincipalIDs: current.PrincipalIDs}}, Context: extra})
}
func layerStrings[T ~string](values []T) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}

// lambda:Layer describes layers specified in this request, not retained
// attachments. Omission and clearing both supply no condition values; IAM's
// empty-set rules apply without inventing an ARN for either case.
func layerConditions(layers []api.LayerVersionArn) map[string][]string {
	if len(layers) == 0 {
		return nil
	}
	return map[string][]string{"lambda:Layer": layerStrings(layers)}
}

func layerRuntimes(values []string) api.CompatibleRuntimes {
	if values == nil {
		return nil
	}
	out := make(api.CompatibleRuntimes, len(values))
	for i, v := range values {
		out[i] = api.Runtime(v)
	}
	return out
}
func layerArchitectures(values []string) api.CompatibleArchitectures {
	if values == nil {
		return nil
	}
	out := make(api.CompatibleArchitectures, len(values))
	for i, v := range values {
		out[i] = api.Architecture(v)
	}
	return out
}
func layerVersionOutput(v LayerVersionRecord) *api.GetLayerVersionOutput {
	out := &api.GetLayerVersionOutput{CompatibleRuntimes: layerRuntimes(v.CompatibleRuntimes), CompatibleArchitectures: layerArchitectures(v.CompatibleArchitectures), CreatedDate: new(api.Timestamp(v.Created.UTC().Format("2006-01-02T15:04:05.000-0700"))), Description: new(api.Description(v.Description)), LayerArn: new(api.LayerArn(v.Key.LayerKey.ARN())), LayerVersionArn: new(api.LayerVersionArn(v.Key.ARN())), Version: new(api.LayerVersionNumber(v.Key.Version))}
	if v.LicenseInfo != "" {
		out.LicenseInfo = new(api.LicenseInfo(v.LicenseInfo))
	}
	return out
}
func (s *Service) layerContent(tx Transaction, v LayerVersionRecord) (*api.LayerVersionContentOutput, error) {
	out := &api.LayerVersionContentOutput{CodeSha256: new(api.String(v.CodeSHA256)), CodeSize: new(api.Long(v.CodeSize))}
	if v.SigningProfileVersionARN != "" {
		out.SigningProfileVersionArn = new(api.Arn(v.SigningProfileVersionARN))
		out.SigningJobArn = new(api.Arn(v.SigningJobARN))
	}
	if v.Reference != nil {
		out.ResolvedS3Object = resolvedS3Object(v.Reference)
	} else {
		location, err := s.issueCodeURL(tx, CodeArchiveKey{Scope: v.Key.Scope, SHA256: v.CodeSHA256})
		if err != nil {
			return nil, err
		}
		out.Location = new(api.SensitiveStringOnServerOnly(location))
	}
	return out, nil
}
func (s *Service) publishLayerVersion(ctx context.Context, in *api.PublishLayerVersionInput) (*api.PublishLayerVersionOutput, *awswire.Error) {
	key, wire := parseLayerKey(ctx, value(in.LayerName))
	if wire != nil {
		return nil, wire
	}
	if wire = s.authorize(ctx, "PublishLayerVersion", key.ARN(), nil, nil, nil); wire != nil {
		return nil, wire
	}
	owner, wire := layerVersionOwnerFor(ctx)
	if wire != nil {
		return nil, wire
	}
	var out *api.PublishLayerVersionOutput
	complete := func(tx Transaction, v LayerVersionRecord) error {
		projected := layerVersionOutput(v)
		var err error
		projected.Content, err = s.layerContent(tx, v)
		if err != nil {
			return err
		}
		out = (*api.PublishLayerVersionOutput)(projected)
		return s.recordCall(tx.Context(), "PublishLayerVersion", in, out, nil)
	}
	recover := func(tx Transaction) (bool, error) {
		if wire := s.authorize(tx.Context(), "PublishLayerVersion", key.ARN(), nil, nil, nil); wire != nil {
			return false, wire
		}
		if owner == (LayerVersionOwner{}) {
			return false, nil
		}
		v, err := tx.OwnedLayerVersion(key, owner)
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, complete(tx, v)
	}
	// Recover before any external archive or signature work: the original
	// source can change or disappear without changing the owned publication.
	if owner != (LayerVersionOwner{}) {
		err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := recover(tx)
			return err
		})
		if err != nil {
			return nil, wireError(err)
		}
		if out != nil {
			s.jobs.Wake()
			return out, nil
		}
	}
	content := in.Content
	archive, reference, wire := s.loadCode(ctx, key.Scope, key.ARN(), content.ZipFile, value(content.S3Bucket), value(content.S3Key), value(content.S3ObjectVersion), value(content.S3ObjectStorageMode))
	if wire != nil {
		return nil, wire
	}
	// Publication does not enforce a consumer's code signing policy. Native
	// Lambda retains invalid/unsigned layers but exposes signer metadata only
	// when the ZIP integrity and cryptographic signature are valid.
	signature, signatureErr := s.verifyDeploymentSignature(ctx, archive.Code)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		// Fence parallel recovery and IAM changes while external loading ran.
		if recovered, err := recover(tx); err != nil || recovered {
			return err
		}
		version, err := tx.AllocateLayerVersion(key)
		if err != nil {
			return err
		}
		v := LayerVersionRecord{Key: LayerVersionKey{LayerKey: key, Version: version}, Owner: owner, CodeSHA256: archive.Key.SHA256, CodeSize: int64(len(archive.Code)), Reference: reference, Description: value(in.Description), LicenseInfo: value(in.LicenseInfo), Created: s.clock.Now(), CompatibleRuntimes: layerStrings(in.CompatibleRuntimes), CompatibleArchitectures: layerStrings(in.CompatibleArchitectures)}
		if signatureErr == nil {
			v.SigningProfileVersionARN, v.SigningJobARN = signature.SigningProfileVersionARN, signature.SigningJobARN
		}
		if err := tx.PutCodeArchive(archive); err != nil {
			return err
		}
		if err := tx.PutLayerVersion(v); err != nil {
			return err
		}
		return complete(tx, v)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func (s *Service) readLayerVersion(ctx context.Context, key LayerVersionKey) (*api.GetLayerVersionOutput, *awswire.Error) {
	var out *api.GetLayerVersionOutput
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := loadLayer(tx, key)
		if err != nil {
			return err
		}
		if wire := s.authorizeLayer(tx, "GetLayerVersion", key, nil); wire != nil {
			return wire
		}
		out = layerVersionOutput(v)
		out.Content, err = s.layerContent(tx, v)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}
func (s *Service) getLayerVersion(ctx context.Context, in *api.GetLayerVersionInput) (*api.GetLayerVersionOutput, *awswire.Error) {
	key, wire := layerVersionKey(ctx, value(in.LayerName), in.VersionNumber)
	if wire != nil {
		return nil, wire
	}
	return s.readLayerVersion(ctx, key)
}
func (s *Service) getLayerVersionByArn(ctx context.Context, in *api.GetLayerVersionByArnInput) (*api.GetLayerVersionByArnOutput, *awswire.Error) {
	key, wire := parseLayerVersionARN(ctx, value(in.Arn))
	if wire != nil {
		return nil, wire
	}
	return s.readLayerVersion(ctx, key)
}
func (s *Service) deleteLayerVersion(ctx context.Context, in *api.DeleteLayerVersionInput) (*api.DeleteLayerVersionOutput, *awswire.Error) {
	key, wire := layerVersionKey(ctx, value(in.LayerName), in.VersionNumber)
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if wire := s.authorizeLayer(tx, "DeleteLayerVersion", key, nil); wire != nil {
			return wire
		}
		if err := requireLayerVersionOwner(tx, key); err != nil {
			return err
		}
		if err := tx.DeleteLayerVersion(key); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteLayerVersion", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return &api.DeleteLayerVersionOutput{}, nil
}
func listedLayer(v LayerVersionRecord) api.LayerVersionsListItem {
	full := layerVersionOutput(v)
	out := api.LayerVersionsListItem{CompatibleRuntimes: full.CompatibleRuntimes, CompatibleArchitectures: full.CompatibleArchitectures, CreatedDate: full.CreatedDate, LayerVersionArn: full.LayerVersionArn, LicenseInfo: full.LicenseInfo, Version: full.Version}
	if v.Description != "" {
		out.Description = full.Description
	}
	return out
}
func layerMatches(v LayerVersionRecord, runtime, architecture string) bool {
	return (runtime == "" || slices.Contains(v.CompatibleRuntimes, runtime)) && (architecture == "" || slices.Contains(v.CompatibleArchitectures, architecture))
}

// Scan before filtering: a page can be empty and still carry a continuation.
func layerPage(records []LayerVersionRecord, marker string, max *api.MaxLayerListItems, prefix string, versions bool) ([]LayerVersionRecord, *api.String, *awswire.Error) {
	after := ""
	if marker != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(marker)
		if err != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, nil, failure("InvalidParameterValueException", "Invalid pagination marker.", 400)
		}
		after = strings.TrimPrefix(string(decoded), prefix)
		if after == "" {
			return nil, nil, failure("InvalidParameterValueException", "Invalid pagination marker.", 400)
		}
	}
	limit := 50
	if max != nil {
		limit = int(*max)
	}
	out := make([]LayerVersionRecord, 0, min(limit, len(records)))
	last := ""
	for _, v := range records {
		position := v.Key.Name
		if versions {
			position = fmt.Sprintf("%020d", ^v.Key.Version)
		}
		if position <= after {
			continue
		}
		if len(out) == limit {
			return out, new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + last)))), nil
		}
		out = append(out, v)
		last = position
	}
	return out, nil, nil
}
func (s *Service) listLayerVersions(ctx context.Context, in *api.ListLayerVersionsInput) (*api.ListLayerVersionsOutput, *awswire.Error) {
	key, wire := parseLayerKey(ctx, value(in.LayerName))
	if wire != nil {
		return nil, wire
	}
	var records []LayerVersionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "ListLayerVersions", key.ARN(), nil, nil, nil); wire != nil {
			return wire
		}
		var err error
		records, err = r.LayerVersions(key)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	runtime, arch := value(in.CompatibleRuntime), value(in.CompatibleArchitecture)
	records, next, wire := layerPage(records, value(in.Marker), in.MaxItems, key.ARN()+"/versions/"+runtime+"/"+arch+"/", true)
	if wire != nil {
		return nil, wire
	}
	out := &api.ListLayerVersionsOutput{LayerVersions: api.LayerVersionsList{}, NextMarker: next}
	for _, v := range records {
		if layerMatches(v, runtime, arch) {
			out.LayerVersions = append(out.LayerVersions, listedLayer(v))
		}
	}
	return out, nil
}
func (s *Service) listLayers(ctx context.Context, in *api.ListLayersInput) (*api.ListLayersOutput, *awswire.Error) {
	scope := layerScope(ctx)
	var records []LayerVersionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "ListLayers", "*", nil, nil, nil); wire != nil {
			return wire
		}
		var err error
		records, err = r.Layers(scope)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	runtime, arch := value(in.CompatibleRuntime), value(in.CompatibleArchitecture)
	records, next, wire := layerPage(records, value(in.Marker), in.MaxItems, (LayerKey{Scope: scope}).ARN()+"/layers/"+runtime+"/"+arch+"/", false)
	if wire != nil {
		return nil, wire
	}
	out := &api.ListLayersOutput{Layers: api.LayersList{}, NextMarker: next}
	for _, v := range records {
		if layerMatches(v, runtime, arch) {
			item := listedLayer(v)
			out.Layers = append(out.Layers, api.LayersListItem{LayerName: new(api.LayerName(v.Key.Name)), LayerArn: new(api.LayerArn(v.Key.LayerKey.ARN())), LatestMatchingVersion: &item})
		}
	}
	return out, nil
}
func (s *Service) resolveLayers(tx Reader, function FunctionKey, arns []string) ([]LayerVersionRecord, *awswire.Error) {
	if len(arns) > 5 {
		return nil, failure("InvalidParameterValueException", "Cannot have more than 5 layers.", 400)
	}
	out := make([]LayerVersionRecord, 0, len(arns))
	seen := make(map[LayerKey]struct{}, len(arns))
	for _, arn := range arns {
		key, wire := parseLayerVersionARN(tx.Context(), arn)
		if wire != nil {
			return nil, wire
		}
		if key.Partition != function.Partition || key.Region != function.Region {
			return nil, failure("InvalidParameterValueException", "Layers must be in the same region as the function.", 400)
		}
		if _, ok := seen[key.LayerKey]; ok {
			return nil, failure("InvalidParameterValueException", "Two different versions of the same layer are not allowed to be referenced in the same function.", 400)
		}
		seen[key.LayerKey] = struct{}{}
		v, err := tx.LayerVersion(key)
		if errors.Is(err, ErrNotFound) {
			return nil, unavailableLayer(key)
		}
		if err != nil {
			return nil, wireError(err)
		}
		if wire := s.authorizeLayer(tx, "GetLayerVersion", key, nil); wire != nil {
			return nil, wireError(wire)
		}
		out = append(out, v)
	}
	return out, nil
}
