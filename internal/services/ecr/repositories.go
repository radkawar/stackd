package ecr

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awsctx"
	"strings"
)

var repositoryName = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)

func repositoryARN(k RepositoryKey) string {
	return "arn:" + k.Partition + ":ecr:" + k.Region + ":" + k.AccountID + ":repository/" + k.Name
}
func registryScope(tx Reader, id *api.RegistryId) Scope {
	scope := scopeFor(tx.Context())
	if id != nil {
		scope.AccountID = string(*id)
	}
	return scope
}
func (s *Service) registry(r Reader, scope Scope) (RegistryRecord, error) {
	v, err := r.Registry(scope)
	if errors.Is(err, ErrNotFound) {
		return RegistryRecord{Scope: scope, Scanning: api.RegistryScanningConfiguration{ScanType: new(api.ScanTypeBASIC), Rules: api.RegistryScanningRuleList{}}, Replication: api.ReplicationConfiguration{Rules: api.ReplicationRuleList{}}}, nil
	}
	return v, err
}
func (s *Service) authorize(r Reader, action string, repo RepositoryRecord, conditions map[string][]string) error {
	c := maps.Clone(conditions)
	if c == nil {
		c = map[string][]string{}
	}
	for k, v := range repo.Tags {
		c["aws:ResourceTag/"+k] = []string{v}
		c["ecr:ResourceTag/"+k] = []string{v}
	}
	resource := repo.ARN
	if resource == "" {
		resource = "*"
	}
	now := s.clock.Now()
	request := authorization.Request{Action: "ecr:" + strings.TrimPrefix(action, "ecr:"), ResourceARN: resource, ResourceAccountID: repo.Key.AccountID, Context: c, EvaluationTime: &now}
	if repo.Policy.Document != "" {
		bound := repo.Policy
		document, _, err := repositoryPolicyDocument(bound.Document)
		if err != nil {
			return err
		}
		bound.Document = document
		request.ResourcePolicies = append(request.ResourcePolicies, bound)
	}
	registry, err := s.registry(r, repo.Key.Scope)
	if err != nil {
		return err
	}
	if registry.Policy.Document != "" {
		request.ResourcePolicies = append(request.ResourcePolicies, registry.Policy)
	}
	if e := s.authorizer.Authorize(r.Context(), request); e != nil {
		return wireError(e)
	}
	return nil
}
func (s *Service) resolveRepository(tx Transaction, id *api.RegistryId, name *api.RepositoryName, action string) (RepositoryRecord, error) {
	return s.resolveRepositoryWithConditions(tx, id, name, action, nil)
}
func (s *Service) resolveRepositoryWithConditions(tx Transaction, id *api.RegistryId, name *api.RepositoryName, action string, conditions map[string][]string) (RepositoryRecord, error) {
	key := RepositoryKey{registryScope(tx, id), value(name)}
	repo, err := tx.Repository(key)
	if errors.Is(err, ErrNotFound) {
		repo = RepositoryRecord{Key: key, ARN: repositoryARN(key)}
	}
	if e := s.authorize(tx, action, repo, conditions); e != nil {
		return RepositoryRecord{}, e
	}
	if err != nil {
		return RepositoryRecord{}, err
	}
	// The private incarnation fence observes only rows current IAM authorized.
	if err = fenceRepository(tx, repo); err != nil {
		return RepositoryRecord{}, err
	}
	return repo, nil
}
func tagsConditions(tags api.TagList) map[string][]string {
	c := map[string][]string{}
	var keys []string
	for _, t := range tags {
		key := value(t.Key)
		c["aws:RequestTag/"+key] = []string{value(t.Value)}
		keys = append(keys, key)
	}
	c["aws:TagKeys"] = keys
	return c
}
func tagMap(tags api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range tags {
		key := value(t.Key)
		if key == "" || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, failure("InvalidTagParameterException", "Tag keys cannot be empty or use the reserved aws: prefix.")
		}
		out[key] = value(t.Value)
	}
	if len(out) > 50 {
		return nil, failure("TooManyTagsException", "A repository supports at most 50 tags.")
	}
	return out, nil
}
func validateMutability(mode string, filters api.ImageTagMutabilityExclusionFilters) error {
	switch mode {
	case "MUTABLE", "IMMUTABLE":
		if len(filters) > 0 {
			return failure("InvalidParameterException", "Exclusion filters require an exclusion mutability mode.")
		}
	case "MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION":
		if len(filters) < 1 || len(filters) > 5 {
			return failure("InvalidParameterException", "An exclusion mode requires one to five filters.")
		}
	default:
		return failure("InvalidParameterException", "Invalid image tag mutability.")
	}
	for _, f := range filters {
		if value(f.FilterType) != "WILDCARD" || value(f.Filter) == "" || strings.Count(value(f.Filter), "*") > 4 {
			return failure("InvalidParameterException", "Invalid tag mutability exclusion filter.")
		}
	}
	return nil
}
func (s *Service) describeRepository(repo RepositoryRecord) (api.Repository, error) {
	origin, err := s.origin()
	if err != nil {
		return api.Repository{}, err
	}
	u, _ := url.Parse(origin)
	enc := &api.EncryptionConfiguration{EncryptionType: new(api.EncryptionType(repo.EncryptionType))}
	if repo.KMSKeyID != "" {
		enc.KmsKey = new(api.KmsKey(repo.KMSKeyID))
	}
	return api.Repository{RepositoryArn: new(api.Arn(repo.ARN)), RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: new(api.RepositoryName(repo.Key.Name)), RepositoryUri: new(api.Url(u.Host + "/" + repo.Key.Partition + "/" + repo.Key.AccountID + "/" + repo.Key.Region + "/" + repo.Key.Name)), CreatedAt: new(repo.Created), ImageTagMutability: new(api.ImageTagMutability(repo.Mutability)), ImageTagMutabilityExclusionFilters: api.CloneImageTagMutabilityExclusionFilters(repo.Exclusions), ImageScanningConfiguration: &api.ImageScanningConfiguration{ScanOnPush: new(api.ScanOnPushFlag(repo.ScanOnPush))}, EncryptionConfiguration: enc}, nil
}
func (s *Service) createRepository(tx Transaction, in *api.CreateRepositoryInput) (*api.CreateRepositoryOutput, error) {
	scope := registryScope(tx, in.RegistryId)
	key := RepositoryKey{scope, value(in.RepositoryName)}
	if !repositoryName.MatchString(key.Name) || len(key.Name) > 256 || len(key.Name) < 2 {
		return nil, failure("InvalidParameterException", "Invalid repository name.")
	}
	tags, err := tagMap(in.Tags)
	if err != nil {
		return nil, err
	}
	repo := RepositoryRecord{Key: key, ARN: repositoryARN(key), Created: s.clock.Now(), Mutability: value(in.ImageTagMutability), Exclusions: api.CloneImageTagMutabilityExclusionFilters(in.ImageTagMutabilityExclusionFilters), Tags: tags, EncryptionType: "AES256"}
	if repo.Mutability == "" {
		repo.Mutability = "MUTABLE"
	}
	if err = validateMutability(repo.Mutability, repo.Exclusions); err != nil {
		return nil, err
	}
	if err = s.authorize(tx, "CreateRepository", repo, tagsConditions(in.Tags)); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		if err = s.authorize(tx, "TagResource", repo, tagsConditions(in.Tags)); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Repository(key); err == nil {
		return nil, failure("RepositoryAlreadyExistsException", "The repository already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if in.ImageScanningConfiguration != nil && in.ImageScanningConfiguration.ScanOnPush != nil {
		repo.ScanOnPush = bool(*in.ImageScanningConfiguration.ScanOnPush)
		if repo.ScanOnPush && s.scanner == nil {
			return nil, failure("ValidationException", "Scan on push requires a configured vulnerability scanner and its vulnerability database.")
		}
	}
	keyID := ""
	if in.EncryptionConfiguration != nil {
		repo.EncryptionType = value(in.EncryptionConfiguration.EncryptionType)
		keyID = value(in.EncryptionConfiguration.KmsKey)
	}
	if repo.EncryptionType != "AES256" && repo.EncryptionType != "KMS" {
		return nil, failure("InvalidParameterException", "Only AES256 and KMS encryption are available; KMS_DSSE requires a dual-layer GovCloud encryption implementation.")
	}
	repo, err = s.prepareRepositoryEncryption(tx.Context(), repo, keyID)
	if err != nil {
		return nil, err
	}
	description, err := s.describeRepository(repo)
	if err != nil {
		return nil, err
	}
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	return &api.CreateRepositoryOutput{Repository: &description}, nil
}
func (s *Service) deleteRepository(tx Transaction, in *api.DeleteRepositoryInput) (*api.DeleteRepositoryOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "DeleteRepository")
	if err != nil {
		return nil, err
	}
	images, err := tx.Images(repo.Key)
	if err != nil {
		return nil, err
	}
	if len(images) > 0 && (in.Force == nil || !bool(*in.Force)) {
		return nil, failure("RepositoryNotEmptyException", "The repository contains images; use force to delete it.")
	}
	description, err := s.describeRepository(repo)
	if err != nil {
		return nil, err
	}
	if err = s.retireRepositoryEncryption(tx.Context(), repo); err != nil {
		return nil, err
	}
	if err = tx.DeleteRepository(repo.Key); err != nil {
		return nil, err
	}
	return &api.DeleteRepositoryOutput{Repository: &description}, nil
}
func (s *Service) describeRepositories(tx Transaction, in *api.DescribeRepositoriesInput) (*api.DescribeRepositoriesOutput, error) {
	scope := registryScope(tx, in.RegistryId)
	out := &api.DescribeRepositoriesOutput{Repositories: api.RepositoryList{}}
	if len(in.RepositoryNames) > 0 {
		if in.NextToken != nil || in.MaxResults != nil {
			return nil, failure("InvalidParameterException", "Repository names cannot be combined with pagination.")
		}
		for _, name := range in.RepositoryNames {
			repo, err := s.resolveRepository(tx, in.RegistryId, new(name), "DescribeRepositories")
			if err != nil {
				return nil, err
			}
			v, err := s.describeRepository(repo)
			if err != nil {
				return nil, err
			}
			out.Repositories = append(out.Repositories, v)
		}
		return out, nil
	}
	if err := s.authorize(tx, "DescribeRepositories", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	rows, err := tx.Repositories(scope)
	if err != nil {
		return nil, err
	}
	start, end, next, err := pageBounds("DescribeRepositories", scope, nil, in.MaxResults, in.NextToken, len(rows))
	if err != nil {
		return nil, err
	}
	for _, repo := range rows[start:end] {
		v, err := s.describeRepository(repo)
		if err != nil {
			return nil, err
		}
		out.Repositories = append(out.Repositories, v)
	}
	out.NextToken = next
	return out, nil
}
func (s *Service) describeRegistry(tx Transaction, _ *api.DescribeRegistryInput) (*api.DescribeRegistryOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "DescribeRegistry", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	registry, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	return &api.DescribeRegistryOutput{RegistryId: new(api.RegistryId(scope.AccountID)), ReplicationConfiguration: &registry.Replication}, nil
}
func (s *Service) putImageTagMutability(tx Transaction, in *api.PutImageTagMutabilityInput) (*api.PutImageTagMutabilityOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "PutImageTagMutability")
	if err != nil {
		return nil, err
	}
	if err = validateMutability(value(in.ImageTagMutability), in.ImageTagMutabilityExclusionFilters); err != nil {
		return nil, err
	}
	repo.Mutability = value(in.ImageTagMutability)
	repo.Exclusions = api.CloneImageTagMutabilityExclusionFilters(in.ImageTagMutabilityExclusionFilters)
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	return &api.PutImageTagMutabilityOutput{RegistryId: new(api.RegistryId(repo.Key.AccountID)), RepositoryName: in.RepositoryName, ImageTagMutability: in.ImageTagMutability, ImageTagMutabilityExclusionFilters: repo.Exclusions}, nil
}
func (s *Service) repositoryForARN(tx Transaction, text string, action string, conditions map[string][]string) (RepositoryRecord, error) {
	parts := strings.SplitN(text, ":", 6)
	m := awsctx.FromContext(tx.Context())
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[2] != "ecr" || parts[3] != m.Region || !strings.HasPrefix(parts[5], "repository/") {
		return RepositoryRecord{}, failure("InvalidParameterException", "Invalid repository ARN for this region and partition.")
	}
	return s.resolveRepositoryWithConditions(tx, new(api.RegistryId(parts[4])), new(api.RepositoryName(strings.TrimPrefix(parts[5], "repository/"))), action, conditions)
}
func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	repo, err := s.repositoryForARN(tx, value(in.ResourceArn), "ListTagsForResource", nil)
	if err != nil {
		return nil, err
	}
	out := &api.ListTagsForResourceOutput{Tags: api.TagList{}}
	keys := slices.Sorted(maps.Keys(repo.Tags))
	for _, k := range keys {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(repo.Tags[k]))})
	}
	return out, nil
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	repo, err := s.repositoryForARN(tx, value(in.ResourceArn), "TagResource", tagsConditions(in.Tags))
	if err != nil {
		return nil, err
	}
	tags, err := tagMap(in.Tags)
	if err != nil {
		return nil, err
	}
	if repo.Tags == nil {
		repo.Tags = map[string]string{}
	}
	maps.Copy(repo.Tags, tags)
	if len(repo.Tags) > 50 {
		return nil, failure("TooManyTagsException", "A repository supports at most 50 tags.")
	}
	return &api.TagResourceOutput{}, tx.PutRepository(repo)
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	var keys []string
	if len(in.TagKeys) > 0 {
		keys = make([]string, len(in.TagKeys))
		for i, k := range in.TagKeys {
			keys[i] = string(k)
		}
	}
	repo, err := s.repositoryForARN(tx, value(in.ResourceArn), "UntagResource", map[string][]string{"aws:TagKeys": keys})
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		delete(repo.Tags, k)
	}
	return &api.UntagResourceOutput{}, tx.PutRepository(repo)
}

type pageToken struct {
	Query  string
	Offset int
}

func pageBounds(action string, scope any, filter any, max *api.MaxResults, token *api.NextToken, total int) (int, int, *api.NextToken, error) {
	limit := 100
	if max != nil {
		limit = int(*max)
	}
	if limit < 1 || limit > 1000 {
		return 0, 0, nil, failure("InvalidParameterException", "maxResults must be between 1 and 1000.")
	}
	query, _ := json.Marshal([]any{action, scope, filter})
	cursor := pageToken{Query: string(query)}
	if token != nil {
		data, err := base64.RawURLEncoding.DecodeString(string(*token))
		if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Query != string(query) || cursor.Offset < 0 || cursor.Offset > total {
			return 0, 0, nil, failure("InvalidParameterException", "Invalid pagination token for this request.")
		}
	}
	start := cursor.Offset
	end := min(start+limit, total)
	var next *api.NextToken
	if end < total {
		cursor.Offset = end
		b, _ := json.Marshal(cursor)
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString(b)))
	}
	return start, end, next, nil
}
