package opensearch

import (
	"context"
	"errors"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

const observationInterval = 30 * time.Second

func (s *Service) Start() error {
	err := s.repository.Update(context.Background(), func(tx Transaction) error {
		domains, err := tx.AllDomains()
		if err != nil {
			return err
		}
		for _, v := range domains {
			if v.Status != "deleting" {
				v.Status = "updating"
				v.NativeEndpoint = ""
			}
			v.Version++
			v.Due = s.clock.Now()
			if err = tx.PutDomain(v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.jobs.Start()
	return nil
}

type domainJobs struct{ s *Service }

func (j domainJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var next scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		domains, err := r.AllDomains()
		if err != nil {
			return err
		}
		for _, v := range domains {
			if v.Due.IsZero() {
				continue
			}
			candidate := scheduler.Job{Key: v.Key.ARN(), Version: uint64(v.Version), Due: v.Due}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next, found = candidate, true
			}
		}
		return nil
	})
	return next, found, err
}
func (j domainJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	k, err := keyFromARN(job.Key)
	if err != nil {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, InvokedBy: "es.amazonaws.com", ServicePrincipal: awsctx.ServicePrincipal{Name: "es.amazonaws.com", SourceARN: k.ARN()}})
	var v Domain
	err = s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.Domain(k); return err })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if uint64(v.Version) != job.Version || !v.Due.Equal(job.Due) || v.Due.After(s.clock.Now()) {
		return nil
	}
	var target string
	var sample *NativeStatistics
	var nativeErr error
	if s.runtime == nil {
		nativeErr = errors.New("native OpenSearch runtime unavailable")
	} else if v.Status == "deleting" {
		nativeErr = s.runtime.Delete(ctx, v.Incarnation)
	} else {
		spec := NativeSpecification{ID: v.Incarnation, EngineVersion: v.EngineVersion, AdvancedOptions: v.AdvancedOptions}
		target, nativeErr = s.runtime.Ensure(ctx, spec)
		if nativeErr == nil && s.metrics != nil {
			stats, e := s.runtime.Statistics(ctx, spec)
			if e == nil {
				sample = &stats
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Domain(k)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Incarnation != v.Incarnation || current.Version != v.Version {
			return nil
		}
		if nativeErr != nil {
			current.LastError = nativeErr.Error()
			current.NativeEndpoint = ""
			if current.Status != "deleting" {
				current.Status = "failed"
			}
			current.Due = s.clock.Now().Add(observationInterval)
			current.Version++
			return tx.PutDomain(current)
		}
		if current.Status == "deleting" {
			return tx.DeleteDomain(k)
		}
		current.Status = "active"
		current.NativeEndpoint = target
		current.LastError = ""
		current.Version++
		current.Due = s.clock.Now().Add(observationInterval)
		if err := tx.PutDomain(current); err != nil {
			return err
		}
		if sample != nil {
			return s.publishStatistics(tx.Context(), current, *sample)
		}
		return nil
	})
}
func (s *Service) publishStatistics(ctx context.Context, v Domain, stats NativeStatistics) error {
	samples := []struct {
		name  string
		value float64
	}{{"Nodes", float64(stats.Nodes)}, {"SearchableDocuments", float64(stats.Documents)}, {"JVMMemoryPressure", stats.JVMPercent}}
	for _, health := range []string{"green", "yellow", "red"} {
		value := 0.0
		if health == stats.Health {
			value = 1
		}
		samples = append(samples, struct {
			name  string
			value float64
		}{"ClusterStatus." + health, value})
	}
	for _, sample := range samples {
		if err := s.metrics.PublishOpenSearchMetric(ctx, Metric{Domain: v.Key, Name: sample.name, Value: sample.value, At: s.clock.Now()}); err != nil {
			return err
		}
	}
	return nil
}
