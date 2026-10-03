package ecr

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awsctx"
)

func lifecycleFixturePolicy(t *testing.T, rules ...string) lifecyclePolicy {
	t.Helper()
	policy, err := parseLifecyclePolicy(`{"rules":[` + strings.Join(rules, ",") + `]}`)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
func lifecycleRuleJSON(priority int32, status string, patterns []string, countType string, count int32) string {
	rule := lifecycleRule{Priority: priority, Selection: lifecycleSelection{TagStatus: status, Patterns: patterns, CountType: countType, CountNumber: count}}
	if countType == "sinceImagePushed" {
		rule.Selection.CountUnit = "days"
	}
	rule.Action.Type = "expire"
	raw, _ := json.Marshal(rule)
	return string(raw)
}

// These fixtures reproduce AWS's documented multiple-rule and multiple-tag
// examples, plus reference and exact-age boundaries:
// https://docs.aws.amazon.com/AmazonECR/latest/userguide/lifecycle_policy_examples.html
func TestLifecycleEvaluationFixtures(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 900000000, time.UTC)
	image := func(digest string, days int, tags ...string) ImageRecord {
		return ImageRecord{Key: ImageKey{Digest: digest}, Pushed: now.AddDate(0, 0, -days), Tags: tags}
	}
	abc := []ImageRecord{image("A", 10, "beta-1", "prod-1"), image("B", 9, "beta-2", "prod-2"), image("C", 8, "beta-3")}
	tests := []struct {
		name       string
		rules      []string
		images     []ImageRecord
		want       []string
		priorities []int32
	}{
		{"AWS priority protection", []string{lifecycleRuleJSON(1, "tagged", []string{"prod*"}, "imageCountMoreThan", 1), lifecycleRuleJSON(2, "tagged", []string{"beta*"}, "imageCountMoreThan", 1)}, abc, []string{"A"}, []int32{1}},
		{"AWS reversed priorities", []string{lifecycleRuleJSON(1, "tagged", []string{"beta*"}, "imageCountMoreThan", 1), lifecycleRuleJSON(2, "tagged", []string{"prod*"}, "imageCountMoreThan", 1)}, abc, []string{"A", "B"}, []int32{1, 1}},
		{"all tag patterns required", []string{lifecycleRuleJSON(1, "tagged", []string{"alpha*", "beta*"}, "sinceImagePushed", 5)}, []ImageRecord{image("A", 12, "alpha-1"), image("B", 11, "beta-1"), image("C", 10, "alpha-2", "beta-2"), image("F", 2, "alpha-4", "beta-4")}, []string{"C"}, []int32{1}},
		{"untagged excludes tags", []string{lifecycleRuleJSON(1, "untagged", nil, "imageCountMoreThan", 1)}, []ImageRecord{image("old", 10), image("new", 1), image("tagged", 30, "keep")}, []string{"old"}, []int32{1}},
		{"age is strictly older", []string{lifecycleRuleJSON(1, "any", nil, "sinceImagePushed", 5)}, []ImageRecord{image("boundary", 5), {Key: ImageKey{Digest: "older"}, Pushed: now.AddDate(0, 0, -5).Add(-time.Nanosecond)}}, []string{"older"}, []int32{1}},
		{"retained index protects child", []string{lifecycleRuleJSON(1, "untagged", nil, "sinceImagePushed", 5)}, []ImageRecord{image("child", 10), {Key: ImageKey{Digest: "index"}, Pushed: now, Tags: []string{"keep"}, References: []string{"child"}}}, nil, nil},
		{"selected index allows child", []string{lifecycleRuleJSON(1, "any", nil, "sinceImagePushed", 5)}, []ImageRecord{image("child", 10), {Key: ImageKey{Digest: "index"}, Pushed: now.AddDate(0, 0, -9), References: []string{"child"}}}, []string{"child", "index"}, []int32{1, 1}},
		{"prefix all selectors", []string{`{"rulePriority":1,"selection":{"tagStatus":"tagged","tagPrefixList":["alpha","beta"],"countType":"sinceImagePushed","countUnit":"days","countNumber":5},"action":{"type":"expire"}}`}, []ImageRecord{image("both", 9, "alpha-one", "beta-one"), image("one", 10, "alpha-beta")}, []string{"both"}, []int32{1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := lifecycleFixturePolicy(t, test.rules...)
			rows := evaluateLifecycle(policy, test.images, now)
			var got []string
			var priorities []int32
			for _, row := range rows {
				got = append(got, value(row.ImageDigest))
				priorities = append(priorities, int32(*row.AppliedRulePriority))
				if value(row.Action.Type) != "EXPIRE" {
					t.Fatalf("action = %v", row.Action)
				}
			}
			if !reflect.DeepEqual(got, test.want) || !reflect.DeepEqual(priorities, test.priorities) {
				t.Fatalf("expired %v with priorities %v, want %v / %v", got, priorities, test.want, test.priorities)
			}
		})
	}
}

func TestLifecyclePolicyValidation(t *testing.T) {
	base := lifecycleRuleJSON(1, "any", nil, "imageCountMoreThan", 1)
	tests := []struct{ name, text string }{
		{"zero count", `{"rules":[` + lifecycleRuleJSON(1, "any", nil, "imageCountMoreThan", 0) + `]}`},
		{"duplicate priority", `{"rules":[` + base + `,` + base + `]}`},
		{"any must be last", `{"rules":[` + base + `,` + lifecycleRuleJSON(2, "untagged", nil, "sinceImagePushed", 1) + `]}`},
		{"tag selectors required", `{"rules":[` + lifecycleRuleJSON(1, "tagged", nil, "imageCountMoreThan", 1) + `]}`},
		{"wildcard bound", `{"rules":[` + lifecycleRuleJSON(1, "tagged", []string{"a*b*c*d*e*f"}, "sinceImagePushed", 1) + `]}`},
		{"no trailing document", `{"rules":[` + base + `]} {}`},
		{"unknown count type", `{"rules":[` + lifecycleRuleJSON(1, "any", nil, "notACountType", 1) + `]}`},
		{"unknown policy field", `{"ignored":true,"rules":[` + base + `]}`},
		{"untagged selectors forbidden", `{"rules":[` + lifecycleRuleJSON(1, "untagged", []string{"prod*"}, "sinceImagePushed", 1) + `]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseLifecyclePolicy(test.text)
			if err == nil || wireError(err).Code != "InvalidParameterException" {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func lifecycleTestContext(scope Scope) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":root", PrincipalID: scope.AccountID})
}
func TestLifecycleScheduledDeletionAndPolicyRemoval(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	repository := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	ctx := lifecycleTestContext(scope)
	key := RepositoryKey{Scope: scope, Name: "owned"}
	other := key
	other.AccountID = "210987654321"
	otherRegion := key
	otherRegion.Region = "us-west-2"
	repo := RepositoryRecord{Key: key, ARN: repositoryARN(key), Created: now}
	policy := `{"rules":[` + lifecycleRuleJSON(1, "any", nil, "imageCountMoreThan", 1) + `]}`
	if err := repository.Update(ctx, func(tx Transaction) error {
		for _, k := range []RepositoryKey{key, other, otherRegion} {
			r := repo
			r.Key = k
			r.ARN = repositoryARN(k)
			if err := tx.PutRepository(r); err != nil {
				return err
			}
			for _, digest := range []string{"old", "new"} {
				pushed := now
				if digest == "old" {
					pushed = now.Add(-time.Hour)
				}
				if err := tx.PutImage(ImageRecord{Key: ImageKey{Repository: k, Digest: digest}, Pushed: pushed}); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	service := New(Config{Repository: repository, Clock: source})
	defer service.Close()
	if err := repository.Update(ctx, func(tx Transaction) error {
		_, err := service.putLifecyclePolicy(tx, &api.PutLifecyclePolicyInput{RepositoryName: str[api.RepositoryName](key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](policy)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	jobs := lifecycleJobs{service}
	job, found, err := jobs.Next(ctx)
	if err != nil || !found || !job.Due.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("job = %v %v %v", job, found, err)
	}
	if err = jobs.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	check := func(k RepositoryKey, digest string, wantPresent bool) {
		t.Helper()
		err := repository.View(ctx, func(r Reader) error { _, err := r.Image(ImageKey{Repository: k, Digest: digest}); return err })
		if wantPresent && err != nil || !wantPresent && !errors.Is(err, ErrNotFound) {
			t.Fatalf("image %v/%s present=%v error=%v", k, digest, wantPresent, err)
		}
	}
	check(key, "old", true)
	if err = source.Advance(24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the source over retained state: expiration is not a goroutine
	// timer attached to the original Service instance.
	reopened := New(Config{Repository: repository, Clock: source})
	defer reopened.Close()
	if err = (lifecycleJobs{reopened}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	check(key, "old", false)
	check(key, "new", true)
	check(other, "old", true)
	check(otherRegion, "old", true)
	if err = repository.Update(ctx, func(tx Transaction) error {
		r, err := tx.Repository(key)
		if err != nil {
			return err
		}
		if !r.LifecycleEvaluated.Equal(source.Now()) {
			t.Fatalf("evaluation timestamp = %s", r.LifecycleEvaluated)
		}
		_, err = reopened.deleteLifecyclePolicy(tx, &api.DeleteLifecyclePolicyInput{RepositoryName: str[api.RepositoryName](key.Name)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = source.Advance(24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if err = (lifecycleJobs{reopened}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	check(key, "new", true)
	if _, found, err = (lifecycleJobs{reopened}).Next(ctx); err != nil || found {
		t.Fatalf("deleted policy retained job: found=%v error=%v", found, err)
	}
}

func TestLifecyclePreviewRetainedAndScopedPagination(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	source := clock.NewManual(now)
	repository := NewMemoryRepository(nil)
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	ctx := lifecycleTestContext(scope)
	key := RepositoryKey{Scope: scope, Name: "preview"}
	service := New(Config{Repository: repository, Clock: source})
	defer service.Close()
	policy := `{"rules":[` + lifecycleRuleJSON(1, "any", nil, "imageCountMoreThan", 1) + `]}`
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutRepository(RepositoryRecord{Key: key, ARN: repositoryARN(key), Created: now}); err != nil {
			return err
		}
		for i, digest := range []string{"old", "middle", "new"} {
			if err := tx.PutImage(ImageRecord{Key: ImageKey{Repository: key, Digest: digest}, Pushed: now.Add(time.Duration(i) * time.Hour)}); err != nil {
				return err
			}
		}
		_, err := service.startLifecyclePolicyPreview(tx, &api.StartLifecyclePolicyPreviewInput{RepositoryName: str[api.RepositoryName](key.Name), LifecyclePolicyText: str[api.LifecyclePolicyText](policy)})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	job, found, err := (lifecycleJobs{service}).Next(ctx)
	if err != nil || !found {
		t.Fatalf("preview job: %v %v", found, err)
	}
	if err = (lifecycleJobs{service}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	reopened := New(Config{Repository: repository, Clock: source})
	defer reopened.Close()
	if err = repository.Update(ctx, func(tx Transaction) error {
		first, err := reopened.getLifecyclePolicyPreview(tx, &api.GetLifecyclePolicyPreviewInput{RepositoryName: str[api.RepositoryName](key.Name), MaxResults: new(api.LifecyclePreviewMaxResults(1))})
		if err != nil {
			return err
		}
		if value(first.Status) != "COMPLETE" || len(first.PreviewResults) != 1 || value(first.PreviewResults[0].ImageDigest) != "old" || int(*first.Summary.ExpiringImageTotalCount) != 2 || first.NextToken == nil {
			t.Fatalf("first preview page = %+v", first)
		}
		second, err := reopened.getLifecyclePolicyPreview(tx, &api.GetLifecyclePolicyPreviewInput{RepositoryName: str[api.RepositoryName](key.Name), MaxResults: new(api.LifecyclePreviewMaxResults(1)), NextToken: first.NextToken})
		if err != nil {
			return err
		}
		if len(second.PreviewResults) != 1 || value(second.PreviewResults[0].ImageDigest) != "middle" || second.NextToken != nil {
			t.Fatalf("second preview page = %+v", second)
		}
		_, _, _, err = scanPage(value(first.NextToken), "other repository", 2, 1, 100)
		if err == nil {
			t.Fatal("cross-repository cursor accepted")
		}
		images, err := tx.Images(key)
		if err != nil {
			return err
		}
		if len(images) != 3 {
			t.Fatalf("preview deleted images: %d retained", len(images))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
