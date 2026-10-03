package ecr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/ecr"
	"stackd/internal/scheduler"
)

// Scanner consumes the actual plaintext manifest and content-addressed OCI
// blobs. Implementations must use an explicitly configured local vulnerability
// database; this contract does not imply equivalence to the AWS database.
// Scan is invoked only after the resource transaction has closed.
type Scanner interface {
	Scan(context.Context, ScanInput) (ScanResult, error)
}
type ScanInput struct {
	Manifest  []byte
	MediaType string
	Blobs     map[string][]byte
}
type ScanResult struct {
	Findings             api.ImageScanFindingList
	VulnerabilityUpdated time.Time
}
type ScanError struct {
	Status string
	Err    error
}

func (e *ScanError) Error() string { return e.Err.Error() }
func (e *ScanError) Unwrap() error { return e.Err }

func (s *Service) getRegistryScanningConfiguration(tx Transaction, _ *api.GetRegistryScanningConfigurationInput) (*api.GetRegistryScanningConfigurationOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "ecr:GetRegistryScanningConfiguration", RepositoryRecord{Key: RepositoryKey{Scope: scope}, ARN: "*"}, nil); err != nil {
		return nil, err
	}
	registry, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	return &api.GetRegistryScanningConfigurationOutput{RegistryId: str[api.RegistryId](scope.AccountID), ScanningConfiguration: &registry.Scanning}, nil
}
func (s *Service) putRegistryScanningConfiguration(tx Transaction, in *api.PutRegistryScanningConfigurationInput) (*api.PutRegistryScanningConfigurationOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "ecr:PutRegistryScanningConfiguration", RepositoryRecord{Key: RepositoryKey{Scope: scope}, ARN: "*"}, nil); err != nil {
		return nil, err
	}
	scanType := value(in.ScanType)
	if scanType == "" {
		scanType = "BASIC"
	}
	if scanType != "BASIC" {
		// TODO: Comeback — enhanced/continuous scans require the Inspector owner.
		return nil, failure("InvalidParameterException", "Only BASIC image scanning is supported by the configured scanner")
	}
	if len(in.Rules) > 1 {
		return nil, failure("InvalidParameterException", "BASIC scanning supports at most one SCAN_ON_PUSH rule")
	}
	for _, rule := range in.Rules {
		if value(rule.ScanFrequency) != "SCAN_ON_PUSH" || len(rule.RepositoryFilters) == 0 || len(rule.RepositoryFilters) > 100 {
			return nil, failure("InvalidParameterException", "BASIC rules require SCAN_ON_PUSH and 1 to 100 repository filters")
		}
		for _, filter := range rule.RepositoryFilters {
			if value(filter.FilterType) != "WILDCARD" || len(value(filter.Filter)) == 0 || len(value(filter.Filter)) > 255 {
				return nil, failure("InvalidParameterException", "Invalid repository scanning filter")
			}
		}
	}
	registry, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	registry.Scanning = api.RegistryScanningConfiguration{ScanType: str[api.ScanType](scanType), Rules: api.CloneRegistryScanningRuleList(in.Rules)}
	if err = tx.PutRegistry(registry); err != nil {
		return nil, err
	}
	repos, err := tx.Repositories(scope)
	if err != nil {
		return nil, err
	}
	for _, repo := range repos {
		repo.ScanOnPush = len(matchingScanFilters(registry.Scanning, repo.Key.Name)) > 0
		if err = tx.PutRepository(repo); err != nil {
			return nil, err
		}
	}
	return &api.PutRegistryScanningConfigurationOutput{RegistryScanningConfiguration: &registry.Scanning}, nil
}
func matchingScanFilters(config api.RegistryScanningConfiguration, name string) api.ScanningRepositoryFilterList {
	filters := api.ScanningRepositoryFilterList{}
	for _, rule := range config.Rules {
		if value(rule.ScanFrequency) != "SCAN_ON_PUSH" {
			continue
		}
		for _, filter := range rule.RepositoryFilters {
			pattern := value(filter.Filter)
			// ECR scanning filters without a '*' match every repository containing the
			// supplied text, unlike lifecycle tag prefixes.
			if strings.Contains(pattern, "*") && starMatch(pattern, name) || !strings.Contains(pattern, "*") && strings.Contains(name, pattern) {
				filters = append(filters, filter)
			}
		}
	}
	return filters
}
func (s *Service) batchGetRepositoryScanningConfiguration(tx Transaction, in *api.BatchGetRepositoryScanningConfigurationInput) (*api.BatchGetRepositoryScanningConfigurationOutput, error) {
	scope := scopeFor(tx.Context())
	if len(in.RepositoryNames) < 1 || len(in.RepositoryNames) > 100 {
		return nil, failure("InvalidParameterException", "Between 1 and 100 repository names are required")
	}
	registry, err := s.registry(tx, scope)
	if err != nil {
		return nil, err
	}
	out := &api.BatchGetRepositoryScanningConfigurationOutput{ScanningConfigurations: api.RepositoryScanningConfigurationList{}, Failures: api.RepositoryScanningConfigurationFailureList{}}
	seen := map[string]bool{}
	for _, name := range in.RepositoryNames {
		if seen[string(name)] {
			continue
		}
		seen[string(name)] = true
		repo, err := s.resolveRepository(tx, nil, new(name), "ecr:BatchGetRepositoryScanningConfiguration")
		if err != nil {
			if wireError(err).Code != "RepositoryNotFoundException" {
				return nil, err
			}
			out.Failures = append(out.Failures, api.RepositoryScanningConfigurationFailure{RepositoryName: new(name), FailureCode: str[api.ScanningConfigurationFailureCode]("REPOSITORY_NOT_FOUND"), FailureReason: str[api.ScanningConfigurationFailureReason]("The specified repository does not exist")})
			continue
		}
		filters := matchingScanFilters(registry.Scanning, repo.Key.Name)
		onPush := repo.ScanOnPush || len(filters) > 0
		frequency := "MANUAL"
		if onPush {
			frequency = "SCAN_ON_PUSH"
		}
		out.ScanningConfigurations = append(out.ScanningConfigurations, api.RepositoryScanningConfiguration{RepositoryName: new(name), RepositoryArn: str[api.Arn](repo.ARN), ScanOnPush: new(api.ScanOnPushFlag(onPush)), ScanFrequency: str[api.ScanFrequency](frequency), AppliedScanFilters: filters})
	}
	return out, nil
}
func (s *Service) putImageScanningConfiguration(tx Transaction, in *api.PutImageScanningConfigurationInput) (*api.PutImageScanningConfigurationOutput, error) {
	if in.ImageScanningConfiguration == nil || in.ImageScanningConfiguration.ScanOnPush == nil {
		return nil, failure("InvalidParameterException", "imageScanningConfiguration.scanOnPush is required")
	}
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:PutImageScanningConfiguration")
	if err != nil {
		return nil, err
	}
	repo.ScanOnPush = bool(*in.ImageScanningConfiguration.ScanOnPush)
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	return &api.PutImageScanningConfigurationOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), ImageScanningConfiguration: &api.ImageScanningConfiguration{ScanOnPush: new(api.ScanOnPushFlag(repo.ScanOnPush))}}, nil
}

func resolveScanImage(r Reader, repo RepositoryRecord, id *api.ImageIdentifier) (ImageRecord, error) {
	if id == nil || value(id.ImageDigest) == "" && value(id.ImageTag) == "" {
		return ImageRecord{}, failure("InvalidParameterException", "imageId must contain a digest or tag")
	}
	if id.ImageDigest != nil {
		image, err := r.Image(ImageKey{Repository: repo.Key, Digest: value(id.ImageDigest)})
		if errors.Is(err, ErrNotFound) || err == nil && id.ImageTag != nil && !slices.Contains(image.Tags, value(id.ImageTag)) {
			return ImageRecord{}, failure("ImageNotFoundException", "The specified image does not exist")
		}
		return image, err
	}
	images, err := r.Images(repo.Key)
	if err != nil {
		return ImageRecord{}, err
	}
	for _, image := range images {
		if slices.Contains(image.Tags, value(id.ImageTag)) {
			return image, nil
		}
	}
	return ImageRecord{}, failure("ImageNotFoundException", "The specified image does not exist")
}
func scanStatus(image ImageRecord) *api.ImageScanStatus {
	status := &api.ImageScanStatus{Status: str[api.ScanStatus](image.ScanStatus)}
	if image.ScanDescription != "" {
		status.Description = str[api.ScanStatusDescription](image.ScanDescription)
	}
	return status
}
func scanIdentifier(image ImageRecord, requested *api.ImageIdentifier) *api.ImageIdentifier {
	id := &api.ImageIdentifier{ImageDigest: str[api.ImageDigest](image.Key.Digest)}
	if requested != nil {
		id.ImageTag = requested.ImageTag
	}
	return id
}
func (s *Service) startImageScan(tx Transaction, in *api.StartImageScanInput) (*api.StartImageScanOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:StartImageScan")
	if err != nil {
		return nil, err
	}
	image, err := resolveScanImage(tx, repo, in.ImageId)
	if err != nil {
		return nil, err
	}
	if s.scanner == nil {
		return nil, failure("ServerException", "No native image scanner and offline vulnerability database are configured")
	}
	if image.ScanStatus == "PENDING" || image.ScanStatus == "IN_PROGRESS" || !image.ScanStarted.IsZero() && s.clock.Now().Before(image.ScanStarted.Add(24*time.Hour)) {
		return nil, failure("LimitExceededException", "An image can be scanned only once per 24 hours")
	}
	if len(image.References) > 0 {
		return nil, failure("UnsupportedImageTypeException", "Manifest lists must be scanned through their platform image digests")
	}
	image.ScanStatus = "PENDING"
	image.ScanDescription = ""
	image.ScanStarted = s.clock.Now()
	image.ScanID = identifier()
	if err = tx.PutImage(image); err != nil {
		return nil, err
	}
	return &api.StartImageScanOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), ImageId: scanIdentifier(image, in.ImageId), ImageScanStatus: scanStatus(image)}, nil
}
func (s *Service) scanOnPush(tx Transaction, repo RepositoryRecord, image *ImageRecord) error {
	registry, err := s.registry(tx, repo.Key.Scope)
	if err != nil {
		return err
	}
	if !repo.ScanOnPush && len(matchingScanFilters(registry.Scanning, repo.Key.Name)) == 0 {
		return nil
	}
	if image.ScanStatus == "PENDING" || image.ScanStatus == "IN_PROGRESS" || !image.ScanStarted.IsZero() && s.clock.Now().Before(image.ScanStarted.Add(24*time.Hour)) {
		return nil
	}
	image.ScanStarted = s.clock.Now()
	image.ScanDescription = ""
	image.ScanStatus = "PENDING"
	image.ScanID = identifier()
	if s.scanner == nil {
		image.ScanStatus = "FAILED"
		image.ScanDescription = "No native image scanner and offline vulnerability database are configured"
	}
	if len(image.References) > 0 {
		image.ScanStatus = "UNSUPPORTED_IMAGE"
		image.ScanDescription = "Manifest lists must be scanned through their platform image digests"
	}
	return nil
}
func (s *Service) describeImageScanFindings(tx Transaction, in *api.DescribeImageScanFindingsInput) (*api.DescribeImageScanFindingsOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:DescribeImageScanFindings")
	if err != nil {
		return nil, err
	}
	image, err := resolveScanImage(tx, repo, in.ImageId)
	if err != nil {
		return nil, err
	}
	if image.ScanStatus == "" {
		return nil, failure("ScanNotFoundException", "No image scan exists for this image")
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	fingerprint := fmt.Sprintf("scan:%s:%s:%s:%s", repo.ARN, image.Key.Digest, image.ScanID, image.ScanCompleted.Format(time.RFC3339Nano))
	start, end, next, err := scanPage(value(in.NextToken), fingerprint, len(image.Findings), limit, 1000)
	if err != nil {
		return nil, err
	}
	findings := &api.ImageScanFindings{Findings: image.Findings[start:end], FindingSeverityCounts: api.FindingSeverityCounts{}}
	for _, finding := range image.Findings {
		severity := api.FindingSeverity(value(finding.Severity))
		findings.FindingSeverityCounts[severity]++
	}
	if !image.ScanCompleted.IsZero() {
		findings.ImageScanCompletedAt = new(image.ScanCompleted)
	}
	if !image.VulnerabilityUpdated.IsZero() {
		findings.VulnerabilitySourceUpdatedAt = new(image.VulnerabilityUpdated)
	}
	if image.ScanCompleted.IsZero() {
		findings = nil
	}
	return &api.DescribeImageScanFindingsOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), ImageId: scanIdentifier(image, in.ImageId), ImageScanStatus: scanStatus(image), ImageScanFindings: findings, NextToken: next}, nil
}

type scanningJobs struct{ s *Service }

func scanJobKey(image ImageRecord) string {
	return strings.Join([]string{image.Key.Repository.Partition, image.Key.Repository.AccountID, image.Key.Repository.Region, image.Key.Repository.Name, image.Key.Digest, image.ScanID}, "\x00")
}
func (j scanningJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		repos, err := r.AllRepositories()
		if err != nil {
			return err
		}
		for _, repo := range repos {
			images, err := r.Images(repo.Key)
			if err != nil {
				return err
			}
			for _, image := range images {
				if image.ScanStatus != "PENDING" && image.ScanStatus != "IN_PROGRESS" {
					continue
				}
				key := scanJobKey(image)
				if !found || image.ScanStarted.Before(next.Due) || image.ScanStarted.Equal(next.Due) && key < next.Key {
					next = scheduler.Job{Key: key, Due: image.ScanStarted}
					found = true
				}
			}
		}
		return nil
	})
	return next, found, err
}
func (j scanningJobs) Run(ctx context.Context, job scheduler.Job) error {
	parts := strings.Split(job.Key, "\x00")
	if len(parts) != 6 {
		return errors.New("invalid ECR scan job key")
	}
	key := ImageKey{Repository: RepositoryKey{Scope: Scope{Partition: parts[0], AccountID: parts[1], Region: parts[2]}, Name: parts[3]}, Digest: parts[4]}
	var repo RepositoryRecord
	var image ImageRecord
	var input ScanInput
	eligible := false
	var loadErr error
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		repo, err = tx.Repository(key.Repository)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		image, err = tx.Image(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if image.ScanStatus != "PENDING" && image.ScanStatus != "IN_PROGRESS" || image.ScanID != parts[5] || !image.ScanStarted.Equal(job.Due) || job.Due.After(j.s.clock.Now()) {
			return nil
		}
		eligible = true
		image.ScanStatus = "IN_PROGRESS"
		if err = tx.PutImage(image); err != nil {
			return err
		}
		input, loadErr = j.s.scanInput(tx, repo, image)
		return nil
	})
	if err != nil || !eligible {
		return err
	}
	result := ScanResult{}
	scanErr := loadErr
	if scanErr == nil {
		if j.s.scanner == nil {
			scanErr = errors.New("native image scanner is not configured")
		} else {
			result, scanErr = j.s.scanner.Scan(ctx, input)
		}
	}
	// Shutdown leaves the accepted intent available for recovery. It is not a
	// scanner failure and must not discard the last successful findings.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Image(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		currentRepo, err := tx.Repository(key.Repository)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.ScanStatus != "IN_PROGRESS" || current.ScanID != image.ScanID || !current.ScanStarted.Equal(image.ScanStarted) || !current.Pushed.Equal(image.Pushed) || !currentRepo.Created.Equal(repo.Created) {
			return nil
		}
		current.ScanStatus = "COMPLETE"
		current.ScanDescription = ""
		if scanErr != nil {
			current.ScanStatus = "FAILED"
			current.ScanDescription = scanErr.Error()
			if len(current.ScanDescription) > 1024 {
				current.ScanDescription = current.ScanDescription[:1024]
			}
			var status *ScanError
			if errors.As(scanErr, &status) && status.Status == "UNSUPPORTED_IMAGE" {
				current.ScanStatus = status.Status
			}
		} else {
			current.Findings = result.Findings
			current.VulnerabilityUpdated = result.VulnerabilityUpdated
			current.ScanCompleted = j.s.clock.Now()
		}
		if err = tx.PutImage(current); err != nil {
			return err
		}
		if current.ScanStatus != "COMPLETE" {
			return nil
		}
		counts := api.FindingSeverityCounts{}
		for _, finding := range current.Findings {
			counts[api.FindingSeverity(value(finding.Severity))]++
		}
		tags := current.Tags
		if tags == nil {
			tags = []string{}
		}
		return j.s.publishEvent(tx.Context(), key.Repository.Scope, "ECR Image Scan", []string{currentRepo.ARN}, map[string]any{"repository-name": key.Repository.Name, "image-digest": key.Digest, "image-tags": tags, "scan-status": current.ScanStatus, "finding-severity-counts": counts})
	})
}
func (s *Service) scanInput(r Reader, repo RepositoryRecord, image ImageRecord) (ScanInput, error) {
	manifest, err := s.openPayload(r.Context(), repo, "manifest:"+image.Key.Digest, image.Payload)
	if err != nil {
		return ScanInput{}, err
	}
	var document struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err = json.Unmarshal(manifest, &document); err != nil {
		return ScanInput{}, err
	}
	digests := make([]string, 0, len(document.Layers)+1)
	if document.Config.Digest != "" {
		digests = append(digests, document.Config.Digest)
	}
	for _, layer := range document.Layers {
		digests = append(digests, layer.Digest)
	}
	input := ScanInput{Manifest: manifest, MediaType: image.MediaType, Blobs: make(map[string][]byte, len(digests))}
	for _, digest := range digests {
		if _, ok := input.Blobs[digest]; ok {
			continue
		}
		blob, err := r.Blob(ImageKey{Repository: repo.Key, Digest: digest})
		if err != nil {
			return ScanInput{}, err
		}
		plain, err := s.openPayload(r.Context(), repo, "blob:"+digest, blob.Payload)
		if err != nil {
			return ScanInput{}, err
		}
		input.Blobs[digest] = plain
	}
	return input, nil
}
