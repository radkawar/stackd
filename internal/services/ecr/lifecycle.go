package ecr

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/ecr"
	"stackd/internal/scheduler"
)

const lifecycleInterval = 24 * time.Hour

type lifecyclePolicy struct {
	Rules []lifecycleRule `json:"rules"`
}
type lifecycleRule struct {
	Priority    int32              `json:"rulePriority"`
	Description string             `json:"description,omitempty"`
	Selection   lifecycleSelection `json:"selection"`
	Action      struct {
		Type   string `json:"type"`
		Target string `json:"targetStorageClass,omitempty"`
	} `json:"action"`
}
type lifecycleSelection struct {
	TagStatus    string   `json:"tagStatus"`
	Patterns     []string `json:"tagPatternList,omitempty"`
	Prefixes     []string `json:"tagPrefixList,omitempty"`
	StorageClass string   `json:"storageClass,omitempty"`
	CountType    string   `json:"countType"`
	CountUnit    string   `json:"countUnit,omitempty"`
	CountNumber  int32    `json:"countNumber"`
}

// parseLifecyclePolicy implements the expiry grammar, rather than accepting
// arbitrary JSON. Archive transitions require a separate storage-class owner.
func parseLifecyclePolicy(text string) (lifecyclePolicy, error) {
	var policy lifecyclePolicy
	invalid := func(message string) (lifecyclePolicy, error) {
		return lifecyclePolicy{}, failure("InvalidParameterException", message)
	}
	if len(text) < 100 || len(text) > 30720 {
		return invalid("Lifecycle policy text must contain between 100 and 30720 bytes")
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return invalid("Invalid lifecycle policy: " + err.Error())
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return invalid("Lifecycle policy must contain exactly one JSON document")
	}
	if len(policy.Rules) == 0 || len(policy.Rules) > 50 {
		return invalid("Lifecycle policies require between 1 and 50 rules")
	}
	priorities := map[int32]bool{}
	prefixes := map[string]bool{}
	untagged := false
	sort.Slice(policy.Rules, func(i, j int) bool { return policy.Rules[i].Priority < policy.Rules[j].Priority })
	for i, rule := range policy.Rules {
		if rule.Priority < 1 || priorities[rule.Priority] {
			return invalid("Each rule must have a unique positive rulePriority")
		}
		priorities[rule.Priority] = true
		selection := rule.Selection
		if rule.Action.Type != "expire" || rule.Action.Target != "" || selection.StorageClass != "" && selection.StorageClass != "standard" {
			// TODO: Comeback — implement archive transitions with retained storage classes.
			return invalid("Only expire actions for standard-storage images are supported")
		}
		if selection.CountNumber < 1 {
			return invalid("countNumber must be positive")
		}
		switch selection.CountType {
		case "imageCountMoreThan":
			if selection.CountUnit != "" {
				return invalid("countUnit is not permitted for imageCountMoreThan")
			}
		case "sinceImagePushed":
			if selection.CountUnit != "days" {
				return invalid("sinceImagePushed requires countUnit days")
			}
		default:
			return invalid("Unsupported lifecycle countType")
		}
		switch selection.TagStatus {
		case "any":
			if i != len(policy.Rules)-1 {
				return invalid("The any rule must have the highest rulePriority")
			}
		case "untagged":
			if untagged {
				return invalid("Only one rule may select untagged images")
			}
			untagged = true
		case "tagged":
			if (len(selection.Patterns) == 0) == (len(selection.Prefixes) == 0) {
				return invalid("Tagged rules require exactly one nonempty tagPatternList or tagPrefixList")
			}
		default:
			return invalid("tagStatus must be tagged, untagged, or any")
		}
		if selection.TagStatus != "tagged" && (selection.Patterns != nil || selection.Prefixes != nil) {
			return invalid("Tag selectors are allowed only for tagged images")
		}
		if selection.Patterns != nil && selection.Prefixes != nil {
			return invalid("tagPatternList and tagPrefixList are mutually exclusive")
		}
		for _, list := range [][]string{selection.Patterns, selection.Prefixes} {
			seen := map[string]bool{}
			for _, pattern := range list {
				if pattern == "" || len(pattern) > 128 || strings.Count(pattern, "*") > 4 || seen[pattern] {
					return invalid("Tag selectors must be unique nonempty strings with at most four wildcards")
				}
				seen[pattern] = true
			}
		}
		for _, prefix := range selection.Prefixes {
			if prefixes[prefix] {
				return invalid("Tag prefixes must be unique across rules")
			}
			prefixes[prefix] = true
		}
	}
	return policy, nil
}

// starMatch treats only '*' as a wildcard; '?' and character classes are literal.
func starMatch(pattern, text string) bool {
	p, t, star, retry := 0, 0, -1, 0
	for t < len(text) {
		if p < len(pattern) && pattern[p] == text[t] {
			p++
			t++
			continue
		}
		if p < len(pattern) && pattern[p] == '*' {
			star = p
			p++
			retry = t
			continue
		}
		if star < 0 {
			return false
		}
		retry++
		t = retry
		p = star + 1
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func (selection lifecycleSelection) matches(image ImageRecord) bool {
	if selection.TagStatus == "any" {
		return true
	}
	if selection.TagStatus == "untagged" {
		return len(image.Tags) == 0
	}
	if len(image.Tags) == 0 {
		return false
	}
	selectors := selection.Patterns
	prefix := false
	if len(selection.Prefixes) > 0 {
		selectors = selection.Prefixes
		prefix = true
	}
	for _, selector := range selectors {
		matched := false
		for _, tag := range image.Tags {
			if prefix && strings.HasPrefix(tag, selector) || !prefix && starMatch(selector, tag) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// evaluateLifecycle evaluates every rule against the same image inventory.
// Higher-priority tag selection protects an image even when that rule keeps it.
func evaluateLifecycle(policy lifecyclePolicy, images []ImageRecord, now time.Time) api.LifecyclePolicyPreviewResultList {
	ordered := slices.Clone(images)
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].Pushed.Equal(ordered[j].Pushed) {
			return ordered[i].Pushed.After(ordered[j].Pushed)
		}
		return ordered[i].Key.Digest < ordered[j].Key.Digest
	})
	protected := map[string]bool{}
	selected := map[string]int32{}
	for _, rule := range policy.Rules {
		count := int64(0)
		// Calendar days preserve subsecond boundaries without duration overflow.
		var cutoff time.Time
		if rule.Selection.CountType == "sinceImagePushed" {
			cutoff = now.AddDate(0, 0, -int(rule.Selection.CountNumber))
		}
		for _, image := range ordered {
			if !rule.Selection.matches(image) {
				continue
			}
			count++
			expire := false
			if rule.Selection.CountType == "imageCountMoreThan" {
				expire = count > int64(rule.Selection.CountNumber)
			} else {
				expire = image.Pushed.Before(cutoff)
			}
			if expire && !protected[image.Key.Digest] {
				selected[image.Key.Digest] = rule.Priority
			}
			protected[image.Key.Digest] = true
		}
	}
	// A manifest cannot be removed while a retained index references it. Removing
	// blocked selections to a fixed point also handles nested indexes.
	for changed := true; changed; {
		changed = false
		for _, image := range ordered {
			if _, expires := selected[image.Key.Digest]; expires {
				continue
			}
			for _, digest := range image.References {
				if _, ok := selected[digest]; ok {
					delete(selected, digest)
					changed = true
				}
			}
		}
	}
	results := api.LifecyclePolicyPreviewResultList{}
	for i := len(ordered) - 1; i >= 0; i-- {
		image := ordered[i]
		priority, ok := selected[image.Key.Digest]
		if !ok {
			continue
		}
		tags := make(api.ImageTagList, len(image.Tags))
		for i, tag := range image.Tags {
			tags[i] = api.ImageTag(tag)
		}
		results = append(results, api.LifecyclePolicyPreviewResult{ImageDigest: str[api.ImageDigest](image.Key.Digest), ImageTags: tags, ImagePushedAt: new(image.Pushed), AppliedRulePriority: new(api.LifecyclePolicyRulePriority(priority)), Action: &api.LifecyclePolicyRuleAction{Type: str[api.ImageActionType]("EXPIRE")}, StorageClass: str[api.LifecyclePolicyStorageClass]("STANDARD")})
	}
	return results
}

func (s *Service) putLifecyclePolicy(tx Transaction, in *api.PutLifecyclePolicyInput) (*api.PutLifecyclePolicyOutput, error) {
	text := value(in.LifecyclePolicyText)
	if _, err := parseLifecyclePolicy(text); err != nil {
		return nil, err
	}
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:PutLifecyclePolicy")
	if err != nil {
		return nil, err
	}
	repo.LifecyclePolicy = text
	repo.LifecycleDue = s.clock.Now().Add(lifecycleInterval)
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	return &api.PutLifecyclePolicyOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](text)}, nil
}
func (s *Service) getLifecyclePolicy(tx Transaction, in *api.GetLifecyclePolicyInput) (*api.GetLifecyclePolicyOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:GetLifecyclePolicy")
	if err != nil {
		return nil, err
	}
	if repo.LifecyclePolicy == "" {
		return nil, failure("LifecyclePolicyNotFoundException", "No lifecycle policy exists for this repository")
	}
	out := &api.GetLifecyclePolicyOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](repo.LifecyclePolicy)}
	if !repo.LifecycleEvaluated.IsZero() {
		out.LastEvaluatedAt = new(repo.LifecycleEvaluated)
	}
	return out, nil
}
func (s *Service) deleteLifecyclePolicy(tx Transaction, in *api.DeleteLifecyclePolicyInput) (*api.DeleteLifecyclePolicyOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:DeleteLifecyclePolicy")
	if err != nil {
		return nil, err
	}
	if repo.LifecyclePolicy == "" {
		return nil, failure("LifecyclePolicyNotFoundException", "No lifecycle policy exists for this repository")
	}
	out := &api.DeleteLifecyclePolicyOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](repo.LifecyclePolicy)}
	if !repo.LifecycleEvaluated.IsZero() {
		out.LastEvaluatedAt = new(repo.LifecycleEvaluated)
	}
	repo.LifecyclePolicy = ""
	repo.LifecycleDue = time.Time{}
	repo.LifecycleEvaluated = time.Time{}
	return out, tx.PutRepository(repo)
}
func (s *Service) startLifecyclePolicyPreview(tx Transaction, in *api.StartLifecyclePolicyPreviewInput) (*api.StartLifecyclePolicyPreviewOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:StartLifecyclePolicyPreview")
	if err != nil {
		return nil, err
	}
	if repo.PreviewStatus == "IN_PROGRESS" {
		return nil, failure("LifecyclePolicyPreviewInProgressException", "A lifecycle policy preview is already in progress")
	}
	text := repo.LifecyclePolicy
	if in.LifecyclePolicyText != nil {
		text = string(*in.LifecyclePolicyText)
	}
	if text == "" {
		return nil, failure("LifecyclePolicyNotFoundException", "No lifecycle policy was supplied or configured")
	}
	if _, err = parseLifecyclePolicy(text); err != nil {
		return nil, err
	}
	repo.PreviewPolicy = text
	repo.PreviewStatus = "IN_PROGRESS"
	repo.PreviewResults = nil
	repo.PreviewExpires = s.clock.Now().Add(lifecycleInterval)
	if err = tx.PutRepository(repo); err != nil {
		return nil, err
	}
	return &api.StartLifecyclePolicyPreviewOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](text), Status: str[api.LifecyclePolicyPreviewStatus](repo.PreviewStatus)}, nil
}

func (s *Service) getLifecyclePolicyPreview(tx Transaction, in *api.GetLifecyclePolicyPreviewInput) (*api.GetLifecyclePolicyPreviewOutput, error) {
	repo, err := s.resolveRepository(tx, in.RegistryId, in.RepositoryName, "ecr:GetLifecyclePolicyPreview")
	if err != nil {
		return nil, err
	}
	if repo.PreviewStatus == "" {
		return nil, failure("LifecyclePolicyPreviewNotFoundException", "No lifecycle policy preview exists for this repository")
	}
	if len(in.ImageIds) > 0 && (in.MaxResults != nil || in.NextToken != nil) {
		return nil, failure("InvalidParameterException", "imageIds cannot be combined with pagination")
	}
	tagStatus := "ANY"
	if in.Filter != nil && in.Filter.TagStatus != nil {
		tagStatus = string(*in.Filter.TagStatus)
	}
	if tagStatus != "ANY" && tagStatus != "TAGGED" && tagStatus != "UNTAGGED" {
		return nil, failure("InvalidParameterException", "Invalid tagStatus")
	}
	for _, id := range in.ImageIds {
		if value(id.ImageDigest) == "" && value(id.ImageTag) == "" {
			return nil, failure("InvalidParameterException", "An image identifier requires a digest or tag")
		}
	}
	out := &api.GetLifecyclePolicyPreviewOutput{RegistryId: str[api.RegistryId](repo.Key.AccountID), RepositoryName: str[api.RepositoryName](repo.Key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](repo.PreviewPolicy), Status: str[api.LifecyclePolicyPreviewStatus](repo.PreviewStatus)}
	if !s.clock.Now().Before(repo.PreviewExpires) {
		out.Status = str[api.LifecyclePolicyPreviewStatus]("EXPIRED")
		return out, nil
	}
	if repo.PreviewStatus != "COMPLETE" {
		return out, nil
	}
	out.Summary = &api.LifecyclePolicyPreviewSummary{ExpiringImageTotalCount: new(api.ImageCount(len(repo.PreviewResults)))}
	rows := api.LifecyclePolicyPreviewResultList{}
	for _, row := range repo.PreviewResults {
		if tagStatus == "TAGGED" && len(row.ImageTags) == 0 || tagStatus == "UNTAGGED" && len(row.ImageTags) != 0 {
			continue
		}
		if len(in.ImageIds) > 0 {
			match := false
			for _, id := range in.ImageIds {
				if (id.ImageDigest == nil || value(id.ImageDigest) == value(row.ImageDigest)) && (id.ImageTag == nil || slices.Contains(row.ImageTags, api.ImageTag(value(id.ImageTag)))) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		rows = append(rows, row)
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	fingerprint := fmt.Sprintf("preview:%s:%s:%s:%s", repo.ARN, repo.PreviewExpires.Format(time.RFC3339Nano), repo.PreviewPolicy, tagStatus)
	start, end, next, err := scanPage(value(in.NextToken), fingerprint, len(rows), limit, 100)
	if err != nil {
		return nil, err
	}
	out.PreviewResults = rows[start:end]
	out.NextToken = next
	return out, nil
}

// Pagination is bound to the repository, immutable result generation and filter;
// a token from another scope or replaced preview is not an inventory cursor.
func scanPage(token, scope string, length, limit, maximum int) (int, int, *api.NextToken, error) {
	if limit < 1 || limit > maximum {
		return 0, 0, nil, failure("InvalidParameterException", "Invalid maxResults")
	}
	sum := sha256.Sum256([]byte(scope))
	prefix := fmt.Sprintf("%x:", sum[:16])
	start := 0
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || !strings.HasPrefix(string(raw), prefix) {
			return 0, 0, nil, failure("InvalidParameterException", "Invalid nextToken")
		}
		start, err = strconv.Atoi(strings.TrimPrefix(string(raw), prefix))
		if err != nil || start < 0 || start > length {
			return 0, 0, nil, failure("InvalidParameterException", "Invalid nextToken")
		}
	}
	end := min(start+limit, length)
	var next *api.NextToken
	if end < length {
		next = str[api.NextToken](base64.RawURLEncoding.EncodeToString([]byte(prefix + strconv.Itoa(end))))
	}
	return start, end, next, nil
}

type lifecycleJobs struct{ s *Service }

func lifecycleKey(repo RepositoryRecord, kind string) string {
	return kind + "\x00" + strings.Join([]string{repo.Key.Partition, repo.Key.AccountID, repo.Key.Region, repo.Key.Name}, "\x00")
}
func (j lifecycleJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		repos, err := r.AllRepositories()
		if err != nil {
			return err
		}
		for _, repo := range repos {
			kind := "expire"
			due := repo.LifecycleDue
			if repo.PreviewStatus == "IN_PROGRESS" {
				previewDue := repo.PreviewExpires.Add(-lifecycleInterval)
				if due.IsZero() || previewDue.Before(due) {
					kind = "preview"
					due = previewDue
				}
			}
			if due.IsZero() {
				continue
			}
			key := lifecycleKey(repo, kind)
			if !found || due.Before(next.Due) || due.Equal(next.Due) && key < next.Key {
				next = scheduler.Job{Key: key, Due: due}
				found = true
			}
		}
		return nil
	})
	return next, found, err
}
func (j lifecycleJobs) Run(ctx context.Context, job scheduler.Job) error {
	parts := strings.Split(job.Key, "\x00")
	if len(parts) != 5 {
		return errors.New("invalid ECR lifecycle job key")
	}
	key := RepositoryKey{Scope: Scope{Partition: parts[1], AccountID: parts[2], Region: parts[3]}, Name: parts[4]}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		repo, err := tx.Repository(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		now := j.s.clock.Now()
		text := repo.LifecyclePolicy
		if parts[0] == "preview" {
			if repo.PreviewStatus != "IN_PROGRESS" || !repo.PreviewExpires.Add(-lifecycleInterval).Equal(job.Due) {
				return nil
			}
			text = repo.PreviewPolicy
		} else if repo.LifecyclePolicy == "" || !repo.LifecycleDue.Equal(job.Due) {
			return nil
		}
		if job.Due.After(now) {
			return nil
		}
		policy, err := parseLifecyclePolicy(text)
		if err != nil {
			return err
		}
		images, err := tx.Images(key)
		if err != nil {
			return err
		}
		results := evaluateLifecycle(policy, images, now)
		if parts[0] == "preview" {
			repo.PreviewResults = results
			repo.PreviewStatus = "COMPLETE"
		} else {
			// The transaction removes the complete selected set atomically; retained
			// manifests therefore never refer to a partially expired selected set.
			for _, row := range results {
				if err = tx.DeleteImage(ImageKey{Repository: key, Digest: value(row.ImageDigest)}); err != nil {
					return err
				}
				imageKey := ImageKey{Repository: key, Digest: value(row.ImageDigest)}
				if len(row.ImageTags) == 0 {
					if err = j.s.publishImageAction(tx.Context(), imageKey, "DELETE", ""); err != nil {
						return err
					}
				} else {
					for _, tag := range row.ImageTags {
						if err = j.s.publishImageAction(tx.Context(), imageKey, "DELETE", string(tag)); err != nil {
							return err
						}
					}
				}
			}
			repo.LifecycleEvaluated = now
			repo.LifecycleDue = now.Add(lifecycleInterval)
			if len(results) > 0 {
				if err = j.s.recordServiceEvent(tx.Context(), "PolicyExecutionEvent", repo, map[string]any{"repositoryName": key.Name, "lifecycleEventImageActions": results}); err != nil {
					return err
				}
			}
		}
		return tx.PutRepository(repo)
	})
}
