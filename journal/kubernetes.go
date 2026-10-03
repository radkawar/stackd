package journal

import (
	"context"
	"errors"
	"slices"
	"time"

	"stackd/storage/memory"
)

// KubernetesAuditObserved is native audit metadata, not an AWS API outcome.
// Cluster identity is supplied by its EKS owner. UserName is the effective user;
// ActorUserName preserves the original identity when Kubernetes impersonates it.
// Full request/response objects are not retained. Successful native RBAC binding
// creation also retains the admitted role reference and ordered subjects.
type KubernetesAuditObserved struct {
	ClusterARN    string `json:"cluster_arn"`
	ClusterID     string `json:"cluster_id"`
	ClusterName   string `json:"cluster_name"`
	AuditID       string `json:"audit_id"`
	Stage         string `json:"stage"`
	Verb          string `json:"verb"`
	RequestURI    string `json:"request_uri"`
	UserName      string `json:"user_name"`
	UserUID       string `json:"user_uid"`
	ActorUserName string `json:"actor_user_name"`
	SourceIP      string `json:"source_ip"`
	Namespace     string `json:"namespace"`
	Resource      string `json:"resource"`
	Subresource   string `json:"subresource"`
	Name          string `json:"name"`
	UserAgent     string `json:"user_agent"`
	APIVersion    string `json:"api_version"`
	ResponseCode  int32  `json:"response_code"`
	// DeleteOptionsObserved distinguishes effective options from metadata-only
	// events, whose request body may have overridden the query.
	DeleteOptionsObserved bool                `json:"delete_options_observed,omitempty"`
	DryRun                bool                `json:"dry_run,omitempty"`
	NativeAt              time.Time           `json:"native_at"`
	Groups                []string            `json:"groups,omitempty"`
	RoleRefAPIGroup       string              `json:"role_ref_api_group,omitempty"`
	RoleRefKind           string              `json:"role_ref_kind,omitempty"`
	RoleRefName           string              `json:"role_ref_name,omitempty"`
	Subjects              []KubernetesSubject `json:"subjects,omitempty"`
}

// KubernetesSubject is an admitted native RBAC binding subject, not its actor.
type KubernetesSubject struct {
	APIGroup  string `json:"api_group"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// CloneKubernetesAudit detaches mutable evidence from its source owner.
func CloneKubernetesAudit(event KubernetesAuditObserved) KubernetesAuditObserved {
	event.Groups = slices.Clone(event.Groups)
	event.Subjects = slices.Clone(event.Subjects)
	return event
}

// ValidateKubernetesAudit checks source identity, not detection eligibility.
func ValidateKubernetesAudit(e Envelope, event KubernetesAuditObserved) error {
	if e.Partition == "" || e.AccountID == "" || e.Region == "" || event.ClusterID == "" || event.ClusterARN == "" || event.AuditID == "" || event.Stage == "" || event.NativeAt.IsZero() {
		return errors.New("incomplete Kubernetes audit source identity")
	}
	return nil
}

type kubernetesAuditKey struct{ partition, account, region, cluster, audit, stage string }

func (j *memoryJournal) AppendKubernetesAuditObserved(ctx context.Context, e Envelope, event KubernetesAuditObserved) (bool, error) {
	if err := ValidateKubernetesAudit(e, event); err != nil {
		return false, err
	}
	inserted := false
	err := j.store.Update(ctx, func(events *[]Event, tx *memory.Transaction) error {
		return j.kubernetes.Update(tx.Context(), func(seen *map[kubernetesAuditKey]struct{}, _ *memory.Transaction) error {
			key := kubernetesAuditKey{e.Partition, e.AccountID, e.Region, event.ClusterID, event.AuditID, event.Stage}
			if _, ok := (*seen)[key]; ok {
				return nil
			}
			saved := CloneKubernetesAudit(event)
			e.Sequence = int64(len(*events)) + 1
			*events = append(*events, Event{Envelope: e, KubernetesAuditObserved: &saved})
			(*seen)[key] = struct{}{}
			inserted = true
			return nil
		})
	})
	return inserted && err == nil, err
}
