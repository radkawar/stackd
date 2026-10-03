package resourcegroups

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

const scanInterval = time.Second

func lifecycleJobKey(scope Scope) string {
	return "lifecycle/" + scope.Partition + "/" + scope.AccountID + "/" + scope.Region
}
func scopedWorkerContext(ctx context.Context, scope Scope) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
}
func (s *Service) NextJob(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	selectJob := func(key string, version uint64, due time.Time) {
		if due.IsZero() {
			return
		}
		if !found || due.Before(next.Due) || (due.Equal(next.Due) && key < next.Key) {
			next = scheduler.Job{Key: key, Version: version, Due: due}
			found = true
		}
	}
	err := s.repository.View(ctx, func(r Reader) error {
		tasks, err := r.TagSyncTasks()
		if err != nil {
			return err
		}
		for _, t := range tasks {
			selectJob(t.ARN, t.Version, t.NextCheck)
		}
		accounts, err := r.LifecycleAccounts()
		if err != nil {
			return err
		}
		for _, a := range accounts {
			if a.Desired == "ACTIVE" {
				selectJob(lifecycleJobKey(a.Scope), a.Version, a.NextCheck)
			}
		}
		return nil
	})
	return next, found, err
}
func (s *Service) RunDue(ctx context.Context, job scheduler.Job) error {
	if strings.HasPrefix(job.Key, "lifecycle/") {
		return s.runLifecycle(ctx, job)
	}
	return s.runTagSync(ctx, job)
}
func currentTask(r Reader, job scheduler.Job, now time.Time) (TagSyncTask, bool, error) {
	rows, err := r.TagSyncTasks()
	if err != nil {
		return TagSyncTask{}, false, err
	}
	for _, t := range rows {
		if t.ARN == job.Key {
			return t, t.Version == job.Version && t.NextCheck.Equal(job.Due) && !t.NextCheck.After(now), nil
		}
	}
	return TagSyncTask{}, false, nil
}
func matchesTask(q resourceQuery, r ApplicationResource) bool {
	if !slices.Contains(q.ResourceTypeFilters, "AWS::AllSupported") && !slices.Contains(q.ResourceTypeFilters, r.Type) {
		return false
	}
	for _, f := range q.TagFilters {
		v, ok := r.Tags[f.Key]
		if !ok || (len(f.Values) > 0 && !slices.Contains(f.Values, v)) {
			return false
		}
	}
	return true
}
func (s *Service) delegatedTask(tx Transaction, t TagSyncTask) (context.Context, error) {
	if s.roles == nil || s.applicationResources == nil {
		return nil, failure("NotImplementedException", "Tag synchronization requires current owner tagging and delegated IAM role authority.")
	}
	return s.roles.AssumeTagSyncRole(scopedWorkerContext(tx.Context(), t.Scope), t.RoleARN, t.GroupARN)
}
func (s *Service) runTagSync(ctx context.Context, job scheduler.Job) error {
	now := s.clock.Now()
	var task TagSyncTask
	var current bool
	var candidates []ApplicationResource
	var applied []AppliedMembership
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		task, current, err = currentTask(tx, job, now)
		if err != nil || !current {
			return err
		}
		g, ok, err := tx.Group(task.Scope, task.GroupARN)
		if err != nil {
			return err
		}
		if !ok || g.ManagedType != applicationGroupType {
			return tx.DeleteTagSyncTask(task.ARN)
		}
		delegated, err := s.delegatedTask(tx, task)
		if err != nil {
			return err
		}
		if denied := s.authorizer.Authorize(delegated, authorization.Request{Action: "tag:GetResources", ResourceARN: "*", EvaluationTime: &now}); denied != nil {
			return denied
		}
		candidates, err = s.applicationResources.List(delegated)
		if err != nil {
			return err
		}
		applied, err = tx.AppliedMemberships(task.ARN)
		return err
	})
	if err == nil && !current {
		return nil
	}
	if err != nil {
		return s.finishTagSync(ctx, job, err)
	}
	q, err := parseQuery(&task.Query)
	if err != nil {
		return s.finishTagSync(ctx, job, err)
	}
	// Each effect uses its own attempt. A rejected owner command rolls back its
	// tag, task ownership and native API event without undoing another owner.
	byARN := make(map[string]ApplicationResource, len(candidates))
	for _, r := range candidates {
		byARN[r.ARN] = r
	}
	selected := make(map[string]AppliedMembership, len(applied))
	for _, m := range applied {
		selected[m.ResourceARN] = m
	}
	var firstError error
	for _, r := range candidates {
		_, owned := selected[r.ARN]
		if !owned && !matchesTask(q, r) {
			continue
		}
		if err := s.applyTagSyncEffect(ctx, job, r.ARN, r.Incarnation); err != nil {
			if transientWorkerError(err) {
				return err
			}
			if firstError == nil {
				firstError = err
			}
		}
	}
	for _, m := range applied {
		if _, ok := byARN[m.ResourceARN]; !ok {
			if err := s.applyTagSyncEffect(ctx, job, m.ResourceARN, m.Incarnation); err != nil {
				if transientWorkerError(err) {
					return err
				}
				if firstError == nil {
					firstError = err
				}
			}
		}
	}
	return s.finishTagSync(ctx, job, firstError)
}
func transientWorkerError(err error) bool {
	var rejected *awswire.Error
	return !errors.As(err, &rejected) || rejected.StatusCode >= 500
}
func (s *Service) applyTagSyncEffect(ctx context.Context, job scheduler.Job, resourceARN, incarnation string) error {
	return s.repository.Attempt(ctx, func(tx Transaction) error {
		now := s.clock.Now()
		t, ok, err := currentTask(tx, job, now)
		if err != nil || !ok {
			return err
		}
		g, ok, err := tx.Group(t.Scope, t.GroupARN)
		if err != nil {
			return err
		}
		if !ok || g.ManagedType != applicationGroupType {
			return tx.DeleteTagSyncTask(t.ARN)
		}
		delegated, err := s.delegatedTask(tx, t)
		if err != nil {
			return err
		}
		live, found, err := s.applicationResources.Resolve(delegated, resourceARN)
		if err != nil {
			return err
		}
		rows, err := tx.AppliedMemberships(t.ARN)
		if err != nil {
			return err
		}
		var owned AppliedMembership
		for _, row := range rows {
			if row.ResourceARN == resourceARN {
				owned = row
				break
			}
		}
		// Never apply a selection to a replacement owner. Its own next scan must
		// select that new incarnation from current source tags.
		if !found || live.Incarnation != incarnation || owned.TaskARN != "" && owned.Incarnation != live.Incarnation {
			if owned.TaskARN != "" {
				return tx.DeleteAppliedMembership(t.ARN, resourceARN)
			}
			return nil
		}
		if live.TaggingPending {
			return nil
		}
		q, err := parseQuery(&t.Query)
		if err != nil {
			return err
		}
		matches := matchesTask(q, live)
		if owned.TaskARN != "" {
			groupings, err := tx.Groupings(g.ARN)
			if err != nil {
				return err
			}
			taskStillOwns := false
			for _, a := range groupings {
				if a.ResourceARN == resourceARN && a.Incarnation == live.Incarnation && a.TaskARN == t.ARN {
					taskStillOwns = true
					break
				}
			}
			if !taskStillOwns || live.Tags[applicationTagKey] != g.ARN {
				return tx.DeleteAppliedMembership(t.ARN, resourceARN)
			}
			if matches {
				return nil
			}
		} else {
			// Direct membership and membership assigned to another application are
			// never adopted or overwritten by a tag-sync task.
			if !matches || live.Tags[applicationTagKey] != "" {
				return nil
			}
		}
		remove := owned.TaskARN != ""
		action, tagAction := "GroupResources", "tag:TagResources"
		if remove {
			action, tagAction = "UngroupResources", "tag:UntagResources"
		}
		if err := s.authorize(delegated, action, &g, nil, nil); err != nil {
			return err
		}
		for _, a := range []string{"tag:GetResources", tagAction} {
			if denied := s.authorizer.Authorize(delegated, authorization.Request{Action: a, ResourceARN: "*", EvaluationTime: &now}); denied != nil {
				return denied
			}
		}
		if remove {
			err = s.applicationResources.Untag(delegated, live, []string{applicationTagKey})
		} else {
			err = s.applicationResources.Tag(delegated, live, map[string]string{applicationTagKey: g.ARN})
		}
		if err != nil {
			return err
		}
		after, found, err := s.applicationResources.Resolve(delegated, live.ARN)
		if err != nil {
			return err
		}
		if !found || after.Incarnation != live.Incarnation {
			return failure("NotFoundException", "The resource incarnation changed while applying its tag.")
		}
		status := "SUCCESS"
		matchesEffect := after.Tags[applicationTagKey] == g.ARN
		if remove {
			matchesEffect = after.Tags[applicationTagKey] != g.ARN
		}
		if !matchesEffect {
			if after.TaggingPending {
				status = "IN_PROGRESS"
			} else {
				return failure("BadRequestException", "The resource owner did not apply the requested application tag transition.")
			}
		}
		grouping := Grouping{GroupARN: g.ARN, ResourceARN: live.ARN, ResourceType: live.Type, Incarnation: live.Incarnation, Action: "GROUP", Status: status, TaskARN: t.ARN, Updated: now}
		if remove {
			grouping.Action = "UNGROUP"
		}
		if err := tx.PutGrouping(grouping); err != nil {
			return err
		}
		if remove {
			return tx.DeleteAppliedMembership(t.ARN, live.ARN)
		}
		return tx.PutAppliedMembership(AppliedMembership{TaskARN: t.ARN, ResourceARN: live.ARN, ResourceType: live.Type, Incarnation: live.Incarnation, AppliedAt: now})
	})
}
func (s *Service) finishTagSync(ctx context.Context, job scheduler.Job, result error) error {
	if result != nil && transientWorkerError(result) {
		return result
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		now := s.clock.Now()
		t, ok, err := currentTask(tx, job, now)
		if err != nil || !ok {
			return err
		}
		t.Status = "ACTIVE"
		t.ErrorMessage = ""
		if result != nil {
			t.Status = "ERROR"
			t.ErrorMessage = result.Error()
		}
		t.NextCheck = now.Add(scanInterval)
		t.Version++
		return tx.PutTagSyncTask(t)
	})
}
