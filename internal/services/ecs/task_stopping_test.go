package ecs

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	runtime "stackd/compute/ecs"
	"stackd/compute/network"
	api "stackd/internal/awsapi/ecs"
)

type stoppingPolicyRuntime struct {
	runtime.Environment
	policy      network.Policy
	applyErr    error
	running     bool
	stopTimeout time.Duration
}

func (r *stoppingPolicyRuntime) SetNetworkPolicy(_ context.Context, policy network.Policy) error {
	if r.applyErr != nil {
		return r.applyErr
	}
	r.policy = policy
	return nil
}
func (r *stoppingPolicyRuntime) Inspect(context.Context) ([]runtime.ContainerStatus, error) {
	state := runtime.ContainerExited
	if r.running {
		state = runtime.ContainerRunning
	}
	return []runtime.ContainerStatus{{Name: "web", State: state}}, nil
}
func (r *stoppingPolicyRuntime) Stop(_ context.Context, _ string, timeout time.Duration) error {
	r.running = false
	r.stopTimeout = timeout
	return nil
}

type stoppingPolicyExecutor struct {
	runtime.Executor
	processes *stoppingPolicyRuntime
}

func (e stoppingPolicyExecutor) Processes(context.Context, runtime.Specification) (runtime.TaskProcesses, error) {
	return e.processes, nil
}

type stoppingPolicyNetwork struct {
	TaskNetworks
	policy     network.Policy
	resolveErr error
}

func (n *stoppingPolicyNetwork) Resolve(context.Context, string, api.Attachment) (network.Specification, error) {
	return network.Specification{Policy: n.policy}, n.resolveErr
}

type stoppingPolicyTargets struct {
	ServiceLoadBalancers
	cancel                     context.CancelFunc
	deregisterErr, errorHealth error
	poll                       func() bool
}

func (b stoppingPolicyTargets) Deregister(context.Context, ServiceTarget) error {
	if b.deregisterErr != nil {
		b.cancel()
	}
	return b.deregisterErr
}
func (b stoppingPolicyTargets) Drained(context.Context, ServiceTarget) (bool, error) {
	if b.poll == nil || b.poll() {
		b.cancel()
	}
	return false, b.errorHealth
}

func TestStoppingTaskRefreshesOrFailsClosedBeforeTargetCleanup(t *testing.T) {
	denied := errors.New("current authority denied")
	for _, test := range []struct {
		name                                           string
		deregisterErr, healthErr, resolveErr, applyErr error
		detached                                       bool
	}{
		{name: "pending drain"},
		{name: "deregister denied", deregisterErr: denied},
		{name: "drain health denied", healthErr: denied},
		{name: "network resolve denied", resolveErr: denied, deregisterErr: denied},
		{name: "native policy replacement failed", applyErr: runtime.ErrNetworkPolicy, healthErr: denied},
		{name: "controller recovery without policy attachment", detached: true, deregisterErr: denied},
	} {
		t.Run(test.name, func(t *testing.T) {
			task, bindings := targetFixtureTask(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC))
			task.Data.DesiredStatus = new(api.String("STOPPED"))
			task.Definition.ContainerDefinitions[0].Cpu = new(api.Integer(0))
			policy := network.Policy{Subnet: netip.MustParsePrefix("10.0.0.0/24")}
			oldPolicy := policy
			oldPolicy.SecurityIngress = []network.IPRule{{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: -1}}
			native := &stoppingPolicyRuntime{policy: oldPolicy, running: true, applyErr: test.applyErr, stopTimeout: -1}
			networks := &stoppingPolicyNetwork{policy: policy, resolveErr: test.resolveErr}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			targets := stoppingPolicyTargets{cancel: cancel, deregisterErr: test.deregisterErr, errorHealth: test.healthErr}
			if test.name == "pending drain" {
				polls := 0
				targets.poll = func() bool {
					polls++
					if polls == 1 {
						networks.policy.ACLIngress = []network.ACLRule{{Number: 1, Rule: network.IPRule{CIDR: netip.MustParsePrefix("0.0.0.0/0"), Protocol: -1}, Allow: false}}
						return false
					}
					return true
				}
			}
			s := New(Config{Networks: networks, Executor: stoppingPolicyExecutor{processes: native}, LoadBalancers: targets})
			t.Cleanup(func() { _ = s.Close() })
			record := ServiceRecord{Key: ServiceKey{ClusterKey: task.Key.ClusterKey, ServiceName: task.ServiceName}, Deployments: []ServiceDeployment{{Data: api.Deployment{Id: new(api.String(task.ServiceDeploymentID))}, LoadBalancers: bindings}}}
			if err := s.repository.Update(t.Context(), func(tx Transaction) error {
				if err := tx.PutService(record); err != nil {
					return err
				}
				return tx.PutTask(task)
			}); err != nil {
				t.Fatal(err)
			}
			e := &taskExecution{service: s, key: task.Key, ctx: ctx, specification: runtime.Specification{Network: network.Specification{Policy: oldPolicy}}}
			if !test.detached {
				e.environment = native
			}
			if err := e.stop(task); err == nil {
				t.Fatal("unfinished target drain allowed task/ENI cleanup")
			}
			unsafe := test.resolveErr != nil || test.applyErr != nil || test.detached
			if unsafe {
				if native.running || native.stopTimeout != 0 {
					t.Fatalf("unsecured native process survived target cleanup failure: running=%v timeout=%v", native.running, native.stopTimeout)
				}
			} else if !native.running || !native.policy.Equal(networks.policy) {
				t.Fatalf("graceful drain did not enforce current policy: running=%v policy=%+v", native.running, native.policy)
			}
			if err := s.repository.View(t.Context(), func(r Reader) error {
				current, err := r.Task(task.Key)
				if err == nil && value(current.Data.Attachments[0].Status) != "ATTACHED" {
					t.Fatal("unfinished drain released the ENI")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
