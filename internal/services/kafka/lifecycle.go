package kafka

import (
	"context"
	"errors"
	"fmt"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"time"
)

const healthInterval = 30 * time.Second

func baseSpecification(v ClusterRecord) Specification {
	return Specification{ARN: v.ARN, Incarnation: v.Incarnation, Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, Brokers: v.Brokers, KafkaVersion: v.KafkaVersion, ServerProperties: v.ServerProperties, SecurityMode: v.SecurityMode}
}
func runtimeContext(ctx context.Context, v ClusterRecord) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, InvokedBy: "kafka.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "kafka.amazonaws.com", SourceARN: v.ARN}})
}
func (s *Service) specification(ctx context.Context, v ClusterRecord) (Specification, error) {
	spec := baseSpecification(v)
	if v.PendingConfigurationARN != "" {
		spec.ServerProperties = v.PendingServerProperties
	}
	if len(v.Secrets) > 0 && s.secrets == nil {
		return spec, errors.New("Secrets Manager owner is unavailable")
	}
	for _, ref := range v.Secrets {
		u, e := s.secrets.LoadSCRAM(ctx, v.ARN, ref)
		if e != nil {
			return spec, e
		}
		spec.Users = append(spec.Users, u)
	}
	return spec, ValidateSpecification(spec)
}

// Start fences all persisted endpoints before any caller can reuse them. Native
// resources are reattached by incarnation; shutdown never deletes their bytes.
func (s *Service) Start() error {
	e := s.repository.Update(context.Background(), func(t Transaction) error {
		rows, e := t.AllClusters()
		if e != nil {
			return e
		}
		for _, v := range rows {
			if v.State == "ACTIVE" {
				v.State = "UPDATING"
				v.Operation = "reconcile"
				v.Endpoint = Endpoint{}
				v.Version++
				v.Due = s.clock.Now()
				if e = t.PutCluster(v); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	s.jobs.Start()
	return nil
}

type clusterJobs struct{ s *Service }

func (j clusterJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	e := j.s.repository.View(ctx, func(r Reader) error {
		rows, e := r.AllClusters()
		if e != nil {
			return e
		}
		for _, v := range rows {
			if v.Due.IsZero() {
				continue
			}
			job := scheduler.Job{Key: v.ARN, Version: uint64(v.Version), Due: v.Due}
			if !found || scheduler.Compare(job, next) < 0 {
				next = job
				found = true
			}
		}
		return nil
	})
	return next, found, e
}
func (j clusterJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	var v ClusterRecord
	e := s.repository.View(ctx, func(r Reader) error { var e error; v, e = r.Cluster(job.Key); return e })
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	nativeCtx := runtimeContext(ctx, v)
	var endpoint Endpoint
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native Kafka runtime is unavailable")
	} else if v.Operation == "delete" {
		nativeErr = s.runtime.Delete(nativeCtx, baseSpecification(v))
	} else {
		var spec Specification
		spec, nativeErr = s.specification(nativeCtx, v)
		if nativeErr == nil {
			if v.Operation == "REBOOT_BROKER" {
				endpoint, nativeErr = s.runtime.Reboot(nativeCtx, spec, v.RebootBrokerID)
			} else {
				endpoint, nativeErr = s.runtime.Ensure(nativeCtx, spec)
			}
			if nativeErr == nil {
				nativeErr = validateEndpoint(v, endpoint)
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(t Transaction) error {
		current, e := t.Cluster(v.ARN)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Incarnation != v.Incarnation || current.Version != v.Version || current.Operation != v.Operation || !current.Due.Equal(v.Due) {
			return nil
		}
		if nativeErr != nil {
			current.Endpoint = Endpoint{}
			current.Failure = nativeErr.Error()
			if current.Operation != "delete" {
				current.State = "FAILED"
			}
			current.Due = s.clock.Now().Add(healthInterval)
			if current.OperationARN != "" {
				if e = finishOperation(t, current, "UPDATE_FAILED", current.Failure, s.clock.Now()); e != nil {
					return e
				}
			}
			return t.PutCluster(current)
		}
		if current.Operation == "delete" {
			return t.DeleteCluster(current.ARN)
		}
		if current.PendingConfigurationARN != "" {
			current.ConfigurationARN = current.PendingConfigurationARN
			current.ConfigurationRevision = current.PendingConfigurationRevision
			current.ServerProperties = current.PendingServerProperties
			current.PendingConfigurationARN = ""
			current.PendingConfigurationRevision = 0
			current.PendingServerProperties = ""
		}
		if current.OperationARN != "" {
			if e = finishOperation(t, current, "UPDATE_COMPLETE", "", s.clock.Now()); e != nil {
				return e
			}
		}
		current.Endpoint = endpoint
		current.State = "ACTIVE"
		current.Failure = ""
		current.Operation = ""
		current.OperationARN = ""
		current.RebootBrokerID = 0
		current.Due = s.clock.Now().Add(healthInterval)
		return t.PutCluster(current)
	})
}
func finishOperation(t Transaction, c ClusterRecord, state, message string, at time.Time) error {
	o, e := t.Operation(c.OperationARN)
	if e != nil {
		return e
	}
	o.State = state
	o.Failure = message
	o.Ended = at
	return t.PutOperation(o)
}
func validateEndpoint(v ClusterRecord, e Endpoint) error {
	if len(e.Brokers) != int(v.Brokers) || e.SecurityMode != v.SecurityMode {
		return fmt.Errorf("native Kafka readiness returned an incomplete endpoint")
	}
	ids := map[int32]bool{}
	for _, b := range e.Brokers {
		if b.Address == "" || b.ID < 1 || b.ID > v.Brokers || ids[b.ID] {
			return fmt.Errorf("native Kafka readiness returned an invalid broker")
		}
		ids[b.ID] = true
	}
	if e.SecurityMode != "PLAINTEXT" && len(e.CAPEM) == 0 {
		return fmt.Errorf("native Kafka TLS readiness omitted its CA")
	}
	return nil
}

// observe does protocol I/O outside transactions, then conditionally updates the
// endpoint. Authorization is repeated in the request's final state transaction.
func (s *Service) observe(ctx context.Context, arn, action string) error {
	var v ClusterRecord
	e := s.repository.View(ctx, func(r Reader) error { var e error; v, e = s.load(r.Context(), r, arn, action); return e })
	if e != nil {
		return e
	}
	if v.State != "ACTIVE" {
		return nil
	}
	var endpoint Endpoint
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native Kafka runtime is unavailable")
	} else {
		endpoint, nativeErr = s.runtime.Status(runtimeContext(ctx, v), baseSpecification(v))
		if nativeErr == nil {
			nativeErr = validateEndpoint(v, endpoint)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(t Transaction) error {
		current, e := t.Cluster(v.ARN)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Incarnation != v.Incarnation || current.Version != v.Version || current.State != "ACTIVE" {
			return nil
		}
		if nativeErr != nil {
			current.State = "FAILED"
			current.Failure = nativeErr.Error()
			current.Endpoint = Endpoint{}
			current.Operation = "reconcile"
			current.Version++
			current.Due = s.clock.Now()
		} else {
			current.Endpoint = endpoint
		}
		return t.PutCluster(current)
	})
}

// ResolveCluster uses the consumer's explicit describe requirement, current caller
// and resource policies, and a fresh native readiness probe.
func (s *Service) ResolveCluster(ctx context.Context, arn string, describe ClusterDescribePermission) (ClusterConnection, error) {
	if describe != RequireDescribeClusterV2 && describe != AllowEitherDescribeCluster {
		return ClusterConnection{}, invalid("A supported cluster describe permission is required")
	}
	if e := s.observe(ctx, arn, "GetBootstrapBrokers"); e != nil {
		return ClusterConnection{}, e
	}
	var out ClusterConnection
	e := s.repository.View(ctx, func(r Reader) error {
		v, e := s.load(r.Context(), r, arn, "GetBootstrapBrokers")
		if e != nil {
			return e
		}
		if e = s.authorizeClusterDescribe(r.Context(), v, describe); e != nil {
			return e
		}
		if v.State != "ACTIVE" || len(v.Endpoint.Brokers) == 0 {
			return invalid("The cluster has no protocol-ready brokers")
		}
		out = ClusterConnection{ARN: v.ARN, Incarnation: v.Incarnation, TLS: v.SecurityMode != "PLAINTEXT", ServerCAPEM: v.Endpoint.CAPEM}
		if v.SecurityMode == "SASL_SCRAM" {
			out.SASLMechanism = "SCRAM-SHA-512"
		}
		for _, b := range v.Endpoint.Brokers {
			out.Brokers = append(out.Brokers, b.Address)
		}
		return nil
	})
	return out, e
}
