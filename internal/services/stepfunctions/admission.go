package stepfunctions

import (
	"math"
	"sync"
	"time"

	"stackd/internal/ratelimit"
)

// Workflow admission budgets are process-local, replenished by service time,
// and shared by callers in an account and Region. They are not resource state.
// AWS publishes nominal token buckets, not its distributed fleet allocator.
// TODO: Comeback — reconcile nominal admission with measured AWS fleet allocation;
// a native burst can exceed the published bucket without establishing a new limit.
type workflowAdmission struct {
	mu      sync.Mutex
	budgets map[workflowAdmissionKey]workflowBudget
}

type workflowAdmissionKey struct {
	Scope
	bucket string
}

type workflowQuota struct {
	capacity, refill float64
}

type workflowBudget struct {
	bucket    ratelimit.Bucket
	nextRetry time.Time
}

// admit consumes one token or reports when one becomes available. A clock rewind
// cannot refill a bucket twice for the same elapsed service time.
func (a *workflowAdmission) admit(scope Scope, bucket string, at time.Time, quota workflowQuota) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := workflowAdmissionKey{Scope: scope, bucket: bucket}
	budget, exists := a.budgets[key]
	if !exists {
		budget.bucket = ratelimit.NewBucket(at, quota.capacity)
	}
	delay := budget.bucket.Take(at, quota.capacity, quota.refill)
	if delay != 0 && bucket == "StateTransition" {
		// Spread ready branches across refill instants instead of waking
		// every denied branch for each single token. This schedules a
		// retry, not a permit: frames still compete when their Due arrives.
		due := at.Add(delay)
		if budget.nextRetry.After(due) {
			due = budget.nextRetry
		}
		budget.nextRetry = due.Add(time.Duration(math.Ceil(float64(time.Second) / quota.refill)))
		delay = due.Sub(at)
	}
	if a.budgets == nil {
		a.budgets = make(map[workflowAdmissionKey]workflowBudget)
	}
	a.budgets[key] = budget
	return delay
}

// Defaults are captured from the AWS Service Quotas API in
// testdata/aws/stepfunctions/api_throttling.json. The documented large-Region
// group also includes us-east-1 and eu-west-1. The native catalogue, rather than
// the older prose table, owns DescribeActivity, DescribeExecution and Redrive.
func workflowQuotaFor(action, region string) (workflowQuota, bool) {
	large := region == "us-east-1" || region == "us-west-2" || region == "eu-west-1"
	switch action {
	case "CreateActivity", "CreateStateMachine", "CreateStateMachineAlias",
		"DeleteActivity", "DeleteStateMachine", "DeleteStateMachineAlias", "DeleteStateMachineVersion",
		"ListMapRuns", "ListStateMachineAliases", "ListStateMachineVersions", "ListTagsForResource",
		"PublishStateMachineVersion", "UpdateMapRun", "UpdateStateMachine", "UpdateStateMachineAlias",
		"ValidateStateMachineDefinition":
		return workflowQuota{100, 1}, true
	case "DescribeActivity", "DescribeStateMachine":
		return workflowQuota{200, 20}, true
	case "DescribeExecution":
		return workflowQuota{300, 50}, true
	case "DescribeMapRun", "DescribeStateMachineAlias", "DescribeStateMachineForExecution", "TagResource", "UntagResource":
		return workflowQuota{200, 1}, true
	case "GetExecutionHistory":
		return workflowQuota{400, 20}, true
	case "ListStateMachines":
		return workflowQuota{100, 5}, true
	case "RedriveExecution":
		return workflowQuota{800, 150}, true
	case "TestState":
		return workflowQuota{50, 10}, true
	case "StartExpressExecution":
		return workflowQuota{6000, 6000}, true
	case "GetActivityTask", "SendTaskFailure", "SendTaskHeartbeat", "SendTaskSuccess":
		if large {
			return workflowQuota{3000, 500}, true
		}
		return workflowQuota{1500, 300}, true
	case "ListActivities":
		if large {
			return workflowQuota{100, 10}, true
		}
		return workflowQuota{100, 5}, true
	case "ListExecutions":
		if large {
			return workflowQuota{200, 5}, true
		}
		return workflowQuota{100, 2}, true
	case "StartExecution":
		if large {
			return workflowQuota{1300, 300}, true
		}
		return workflowQuota{800, 150}, true
	case "StateTransition":
		if large {
			return workflowQuota{5000, 5000}, true
		}
		return workflowQuota{800, 800}, true
	case "StopExecution":
		if large {
			return workflowQuota{1000, 200}, true
		}
		return workflowQuota{500, 25}, true
	default:
		// StartSyncExecution scales on demand, without this fixed API bucket.
		return workflowQuota{}, false
	}
}
