package resourcegroups

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	"stackd/internal/scheduler"
	"stackd/internal/services/eventbridge"
)

type lifecycleReader struct {
	Reader
	ctx context.Context
}

func (r lifecycleReader) Context() context.Context { return r.ctx }
func currentLifecycle(r Reader, job scheduler.Job, now time.Time) (LifecycleAccount, bool, error) {
	rows, err := r.LifecycleAccounts()
	if err != nil {
		return LifecycleAccount{}, false, err
	}
	for _, a := range rows {
		if lifecycleJobKey(a.Scope) == job.Key {
			return a, a.Desired == "ACTIVE" && a.Version == job.Version && a.NextCheck.Equal(job.Due) && !a.NextCheck.After(now), nil
		}
	}
	return LifecycleAccount{}, false, nil
}
func (s *Service) runLifecycle(ctx context.Context, job scheduler.Job) error {
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		now := s.clock.Now()
		account, ok, err := currentLifecycle(tx, job, now)
		if err != nil || !ok {
			return err
		}
		if s.roles == nil || s.publisher == nil || s.resources == nil || s.applicationResources == nil {
			return failure("NotImplementedException", "Lifecycle owner discovery, current IAM role authority or transactional publisher is unavailable.")
		}
		delegated, err := s.roles.AssumeLifecycleRole(scopedWorkerContext(tx.Context(), account.Scope), account.Scope)
		if err != nil {
			return err
		}
		if denied := s.authorizer.Authorize(delegated, authorization.Request{Action: "tag:GetResources", ResourceARN: "*", EvaluationTime: &now}); denied != nil {
			return denied
		}
		reader := lifecycleReader{Reader: tx, ctx: delegated}
		groups, err := tx.Groups(account.Scope)
		if err != nil {
			return err
		}
		snapshots, err := tx.LifecycleSnapshots(account.Scope)
		if err != nil {
			return err
		}
		prior := make(map[string]LifecycleSnapshot, len(snapshots))
		for _, snapshot := range snapshots {
			prior[snapshot.Group.ARN] = snapshot
		}
		for _, g := range groups {
			old, existed := prior[g.ARN]
			delete(prior, g.ARN)
			if existed && old.Group.Incarnation != g.Incarnation {
				if err := s.publishGroupState(delegated, &old, "delete", nil, nil); err != nil {
					return err
				}
				existed = false
			}
			members, err := s.lifecycleMembers(reader, g)
			if err != nil {
				return err
			}
			next := LifecycleSnapshot{Group: g, Members: members}
			if existed {
				next.Sequence = old.Sequence
			}
			if account.Initialized {
				if !existed {
					if err := s.publishGroupState(delegated, &next, "create", nil, groupState(g)); err != nil {
						return err
					}
				} else {
					before, after := changedGroupState(old.Group, g)
					if len(after) > 0 {
						if err := s.publishGroupState(delegated, &next, "update", before, after); err != nil {
							return err
						}
					}
				}
				before := old.Members
				if !existed {
					before = nil
				}
				if err := s.publishMemberChanges(delegated, &next, before); err != nil {
					return err
				}
			}
			if err := tx.PutLifecycleSnapshot(next); err != nil {
				return err
			}
		}
		missing := slices.Sorted(maps.Keys(prior))
		for _, arn := range missing {
			snapshot := prior[arn]
			if err := s.publishGroupState(delegated, &snapshot, "delete", nil, nil); err != nil {
				return err
			}
			if err := tx.DeleteLifecycleSnapshot(arn); err != nil {
				return err
			}
		}
		account.Initialized = true
		account.Status = "ACTIVE"
		account.Message = ""
		account.Version++
		account.NextCheck = now.Add(scanInterval)
		return tx.PutLifecycleAccount(account)
	})
	if err == nil || transientWorkerError(err) {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		now := s.clock.Now()
		a, ok, e := currentLifecycle(tx, job, now)
		if e != nil || !ok {
			return e
		}
		a.Status = "ERROR"
		a.Message = err.Error()
		a.Version++
		a.NextCheck = now.Add(scanInterval)
		return tx.PutLifecycleAccount(a)
	})
}

func (s *Service) lifecycleMembers(r Reader, g Group) ([]LifecycleMember, error) {
	rows, _, err := s.groupMembers(r, g)
	if err != nil {
		return nil, err
	}
	out := make([]LifecycleMember, 0, len(rows))
	for _, row := range rows {
		if row.Pending && row.Tags[applicationTagKey] != g.ARN {
			continue
		}
		member := LifecycleMember{ARN: row.ARN, Type: row.Type}
		// Real application owners expose a stable identity even when a resource ARN
		// is reused between scans. Ordinary unsupported owners remain ARN-based.
		if g.ManagedType == applicationGroupType {
			current, found, err := s.applicationResources.Resolve(r.Context(), row.ARN)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			member.Incarnation = current.Incarnation
		} else if row.Type == "AWS::ResourceGroups::Group" {
			child, found, err := r.Group(g.Scope, row.ARN)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			member.Incarnation = child.Incarnation
		}
		out = append(out, member)
	}
	slices.SortFunc(out, func(a, b LifecycleMember) int { return strings.Compare(a.ARN, b.ARN) })
	return out, nil
}
func groupState(g Group) map[string]any {
	state := map[string]any{}
	if g.Description != "" {
		state["description"] = g.Description
	}
	if g.Query != nil {
		state["resource-query"] = map[string]string{"type": value(g.Query.Type), "query": value(g.Query.Query)}
	}
	if g.ManagedType != "" {
		state["group-configuration"] = groupConfiguration(g).Configuration
	}
	return state
}
func changedGroupState(a, b Group) (map[string]any, map[string]any) {
	old, new := groupState(a), groupState(b)
	before, after := map[string]any{}, map[string]any{}
	for _, key := range []string{"description", "resource-query", "group-configuration"} {
		if !reflect.DeepEqual(old[key], new[key]) {
			before[key] = old[key]
			after[key] = new[key]
		}
	}
	return before, after
}
func groupIdentity(g Group) map[string]string {
	return map[string]string{"arn": g.ARN, "name": g.Name, "unique-id": g.Incarnation}
}
func (s *Service) publishGroupState(ctx context.Context, snapshot *LifecycleSnapshot, change string, before, after map[string]any) error {
	detail := map[string]any{"state-change": change}
	if len(before) > 0 {
		detail["old-state"] = before
	}
	if len(after) > 0 {
		detail["new-state"] = after
	}
	return s.publishLifecycle(ctx, snapshot, "ResourceGroups Group State Change", detail, []string{snapshot.Group.ARN})
}

type memberChange struct {
	Change string `json:"membership-change"`
	ARN    string `json:"arn"`
	Type   string `json:"resource-type"`
}

func (s *Service) publishMemberChanges(ctx context.Context, snapshot *LifecycleSnapshot, before []LifecycleMember) error {
	previous := make(map[string]LifecycleMember, len(before))
	current := make(map[string]LifecycleMember, len(snapshot.Members))
	for _, m := range before {
		previous[m.ARN] = m
	}
	for _, m := range snapshot.Members {
		current[m.ARN] = m
	}
	changes := []memberChange{}
	for _, m := range before {
		if n, ok := current[m.ARN]; !ok || n != m {
			changes = append(changes, memberChange{"remove", m.ARN, m.Type})
		}
	}
	for _, m := range snapshot.Members {
		if p, ok := previous[m.ARN]; !ok || p != m {
			changes = append(changes, memberChange{"add", m.ARN, m.Type})
		}
	}
	// Bound event documents independently of account/group size. Each committed
	// batch increments the same retained sequence as group-state events.
	for len(changes) > 0 {
		count := min(len(changes), 100)
		batch := changes[:count]
		resources := []string{snapshot.Group.ARN}
		for _, change := range batch {
			resources = append(resources, change.ARN)
		}
		if err := s.publishLifecycle(ctx, snapshot, "ResourceGroups Group Membership Change", map[string]any{"resources": batch}, resources); err != nil {
			return err
		}
		changes = changes[count:]
	}
	return nil
}
func (s *Service) publishLifecycle(ctx context.Context, snapshot *LifecycleSnapshot, detailType string, detail map[string]any, resources []string) error {
	snapshot.Sequence++
	detail["event-sequence"] = snapshot.Sequence
	detail["group"] = groupIdentity(snapshot.Group)
	document, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	g := snapshot.Group
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(g.ARN+"/"+g.Incarnation+"/"+strconv.FormatUint(snapshot.Sequence, 10))).String()
	return s.publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: id, Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: g.Partition, Account: g.AccountID, Region: g.Region}, Name: "default"}, Source: "aws.resource-groups", DetailType: detailType, Detail: string(document), Resources: resources, Time: s.clock.Now(), Account: g.AccountID})
}
