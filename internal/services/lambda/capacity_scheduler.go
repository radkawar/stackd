package lambda

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	runtime "stackd/compute/lambda"
	"stackd/compute/lambda/managed"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type capacitySample struct {
	CPU uint64
	At  time.Time
}
type capacityKernel struct {
	mu          sync.Mutex
	running     map[string]bool
	next        map[string]time.Time
	samples     map[string]capacitySample
	lastBusy    map[FunctionVersionKey]time.Time
	credentials map[string]runtime.Credentials
}

func newCapacityKernel(*Service) *capacityKernel {
	return &capacityKernel{running: map[string]bool{}, next: map[string]time.Time{}, samples: map[string]capacitySample{}, lastBusy: map[FunctionVersionKey]time.Time{}, credentials: map[string]runtime.Credentials{}}
}

type capacityJobs struct{ s *Service }

func (j capacityJobs) Next(ctx context.Context) (job scheduler.Job, found bool, err error) {
	s := j.s
	if !s.started.Load() || s.closed.Load() || s.capacityBackend == nil {
		return
	}
	err = s.repository.View(ctx, func(r Reader) error {
		providers, err := r.AllCapacityProviders()
		if err != nil {
			return err
		}
		s.capacity.mu.Lock()
		defer s.capacity.mu.Unlock()
		for _, p := range providers {
			key := p.Key.ARN() + "\x00" + p.Generation
			if s.capacity.running[key] {
				continue
			}
			due := s.capacity.next[key]
			candidate := scheduler.Job{Key: key, Due: due, Version: 1}
			if !found || scheduler.Compare(candidate, job) < 0 {
				job, found = candidate, true
			}
		}
		return nil
	})
	return
}
func (j capacityJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.s
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil
	}
	s.capacity.mu.Lock()
	if s.capacity.running[job.Key] {
		s.capacity.mu.Unlock()
		s.mu.Unlock()
		return nil
	}
	s.capacity.running[job.Key] = true
	s.capacity.mu.Unlock()
	s.work.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.work.Done()
		defer func() {
			s.capacity.mu.Lock()
			delete(s.capacity.running, job.Key)
			s.capacity.next[job.Key] = s.clock.Now().Add(time.Second)
			s.capacity.mu.Unlock()
			s.jobs.Wake()
		}()
		ctx, cancel := context.WithTimeout(s.lifetime, 16*time.Minute)
		defer cancel()
		if err := s.reconcileCapacity(ctx, job); err != nil && s.lifetime.Err() == nil {
			slog.Error("Lambda managed capacity reconciliation failed", "provider", job.Key, "error", err)
		}
	}()
	return nil
}
func capacityOwnerContext(ctx context.Context, k CapacityProviderKey) context.Context {
	return awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: k.Partition, AccountID: k.Account, Region: k.Region})
}
func (s *Service) capacityProviderSnapshot(ctx context.Context, job scheduler.Job) (CapacityProviderRecord, []FunctionRecord, []CapacityGuestRecord, []CapacityEnvironmentRecord, error) {
	var p CapacityProviderRecord
	var functions []FunctionRecord
	var guests []CapacityGuestRecord
	var environments []CapacityEnvironmentRecord
	err := s.repository.View(ctx, func(r Reader) error {
		all, err := r.AllCapacityProviders()
		if err != nil {
			return err
		}
		for _, candidate := range all {
			if candidate.Key.ARN()+"\x00"+candidate.Generation == job.Key {
				p = candidate
				break
			}
		}
		if p.Generation == "" {
			return ErrNotFound
		}
		functions, err = capacityVersions(r, p.Key)
		if err != nil {
			return err
		}
		guests, err = r.CapacityGuests(p.Key)
		if err != nil {
			return err
		}
		environments, err = r.AllCapacityEnvironments()
		return err
	})
	return p, functions, guests, environments, err
}
func (s *Service) reconcileCapacity(ctx context.Context, job scheduler.Job) error {
	p, functions, guests, environments, err := s.capacityProviderSnapshot(ctx, job)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	ctx = capacityOwnerContext(ctx, p.Key)
	byFunction := map[FunctionVersionKey]FunctionRecord{}
	for _, f := range functions {
		byFunction[FunctionVersionKey{FunctionKey: f.Key, Version: f.Version}] = f
	}
	byGuest := map[string]CapacityGuestRecord{}
	for _, g := range guests {
		byGuest[g.ID] = g
	}
	// Release obsolete incarnations before reusing their physical capacity. Work
	// already accepted by a runtime drains; it is never killed by a scaling update.
	for _, e := range environments {
		g, owned := byGuest[e.GuestID]
		if !owned {
			continue
		}
		f, exists := byFunction[e.Key]
		stale := !exists || f.DeploymentRevision != e.Generation || p.State == "Deleting" || e.State == "Draining"
		if !stale {
			continue
		}
		if e.State != "Draining" {
			e.State = "Draining"
			if err = s.saveCapacityEnvironment(ctx, p, e); err != nil {
				return err
			}
		}
		if g.State == "Ready" {
			client, err := s.capacityBackend.Client(ctx, p, g)
			if err != nil {
				var remote *managed.RemoteError
				if errors.As(err, &remote) && remote.Status == 410 {
					g.State = "Failed"
					g.Error = err.Error()
					return s.saveCapacityGuest(ctx, p, g)
				}
				return err
			}
			s.drainCapacityLogs(ctx, e, f, exists && f.DeploymentRevision == e.Generation, client)
			err = client.Remove(ctx, e.ID)
			client.Close()
			var remote *managed.RemoteError
			if errors.As(err, &remote) && (remote.Status == 409) {
				continue
			}
			if err != nil && !(errors.As(err, &remote) && remote.Status == 404) {
				return err
			}
		}
		if g.State != "Ready" {
			continue
		}
		if err = s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteCapacityEnvironment(e.ID) }); err != nil {
			return err
		}
		s.capacity.mu.Lock()
		delete(s.capacity.credentials, e.ID)
		delete(s.capacity.samples, e.ID)
		s.capacity.mu.Unlock()
		return nil
	}
	if p.State == "Deleting" || len(functions) == 0 {
		if len(guests) != 0 {
			g := guests[0]
			if err = s.capacityBackend.Terminate(ctx, p, g); err != nil {
				var pending *managed.RemoteError
				if errors.As(err, &pending) && pending.Status == 409 {
					return nil
				}
				return err
			}
			return s.forgetTerminatedCapacityGuest(ctx, g)
		}
		if p.State != "Deleting" {
			return nil
		}
		return s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.CapacityProvider(p.Key)
			if err != nil {
				return err
			}
			if current.Generation != p.Generation || current.State != "Deleting" {
				return nil
			}
			return tx.DeleteCapacityProvider(p.Key)
		})
	}
	for _, g := range guests {
		if g.State == "Failed" {
			if err = s.capacityBackend.Terminate(ctx, p, g); err != nil {
				var pending *managed.RemoteError
				if errors.As(err, &pending) && pending.Status == 409 {
					return nil
				}
				return err
			}
			return s.forgetTerminatedCapacityGuest(ctx, g)
		}
		if g.State == "Ready" {
			continue
		}
		if g.InstanceID == "" {
			available := p
			for _, other := range guests {
				if other.ID != g.ID {
					available.MaxVCPUs -= other.VCPUs
				}
			}
			updated, err := s.capacityBackend.Launch(ctx, available, g)
			if err != nil {
				g.Error = err.Error()
				_ = s.saveCapacityGuest(ctx, p, g)
				return s.capacityFunctionFailure(ctx, functions, err)
			}
			if err = s.saveCapacityGuest(ctx, p, updated); err != nil {
				return err
			}
			return nil
		}
		updated, err := s.capacityBackend.Observe(ctx, p, g)
		if err != nil {
			var remote *managed.RemoteError
			if errors.As(err, &remote) {
				if remote.Status == 422 {
					g = updated
				} else if remote.Status == 410 {
					g.State = "Failed"
				}
			}
			g.Error = err.Error()
			_ = s.saveCapacityGuest(ctx, p, g)
			return s.capacityFunctionFailure(ctx, functions, err)
		}
		updated.Error = ""
		if err = s.saveCapacityGuest(ctx, p, updated); err != nil {
			return err
		}
		if updated.State != "Ready" {
			return nil
		}
		return nil
	}
	// Build actual observations outside transactions. CPU accounting uses measured
	// cumulative container CPU time; no invocation count is presented as CPU usage.
	observed := map[string]managed.Observation{}
	for _, e := range environments {
		g, owned := byGuest[e.GuestID]
		if !owned || e.State == "Draining" {
			continue
		}
		f, exists := byFunction[e.Key]
		if !exists || e.Generation != f.DeploymentRevision {
			continue
		}
		client, err := s.capacityBackend.Client(ctx, p, g)
		if err != nil {
			var remote *managed.RemoteError
			if errors.As(err, &remote) && remote.Status == 410 {
				g.State = "Failed"
				g.Error = err.Error()
				return s.saveCapacityGuest(ctx, p, g)
			}
			return err
		}
		if e.State == "Pending" {
			err = s.prepareCapacityEnvironment(ctx, p, g, e, f, client)
			client.Close()
			return err
		}
		observation, err := client.Observe(ctx, e.ID)
		if err == nil && observation.Ready {
			err = s.maintainCapacityEnvironment(ctx, p, e, f, &observation, client)
		}
		client.Close()
		var remote *managed.RemoteError
		if errors.As(err, &remote) && remote.Status == 404 {
			e.State = "Pending"
			e.CredentialsExpire = time.Time{}
			return s.saveCapacityEnvironment(ctx, p, e)
		}
		if err != nil {
			return err
		}
		if !observation.Ready {
			e.State = "Draining"
			return s.saveCapacityEnvironment(ctx, p, e)
		}
		observed[e.ID] = observation
	}
	usedCPU, usedMemory := map[string]int32{}, map[string]int32{}
	for _, e := range environments {
		if _, owned := byGuest[e.GuestID]; !owned {
			continue
		}
		if f, exists := byFunction[e.Key]; exists {
			usedCPU[e.GuestID] += capacityVCPUs(f)
			usedMemory[e.GuestID] += int32(f.MemoryMB)
		}
	}
	for _, f := range functions {
		key := FunctionVersionKey{FunctionKey: f.Key, Version: f.Version}
		var scaling CapacityScalingRecord
		if err = s.repository.View(ctx, func(r Reader) error { var err error; scaling, err = effectiveCapacityScaling(r, f); return err }); err != nil {
			return err
		}
		current := []CapacityEnvironmentRecord{}
		ready := 0
		busy := false
		cpuUse := float64(0)
		cpuSamples := 0
		for _, e := range environments {
			if e.Key != key || e.Generation != f.DeploymentRevision || e.State == "Draining" {
				continue
			}
			current = append(current, e)
			if o, ok := observed[e.ID]; ok && o.Ready {
				ready++
				if o.InFlight > 0 {
					busy = true
				}
				s.capacity.mu.Lock()
				previous := s.capacity.samples[e.ID]
				s.capacity.samples[e.ID] = capacitySample{o.CPUTimeNS, o.ObservedAt}
				s.capacity.mu.Unlock()
				if !previous.At.IsZero() && o.ObservedAt.After(previous.At) && o.CPUTimeNS >= previous.CPU {
					cpuUse += 100 * float64(o.CPUTimeNS-previous.CPU) / float64(o.ObservedAt.Sub(previous.At)) / float64(capacityVCPUs(f))
					cpuSamples++
				}
			}
		}
		wanted := max(int(scaling.MinEnvironments), len(current))
		if p.ScalingMode == "Auto" && scaling.MaxEnvironments > 0 && ready > 0 {
			saturation := false
			for _, e := range current {
				o := observed[e.ID]
				if o.MaxConcurrency > 0 && o.InFlight*4 >= o.MaxConcurrency*3 {
					saturation = true
				}
			}
			if cpuSamples > 0 {
				cpuUse /= float64(cpuSamples)
			}
			s.capacity.mu.Lock()
			lastBusy := s.capacity.lastBusy[key]
			if busy || cpuUse >= p.TargetCPU/2 {
				s.capacity.lastBusy[key] = s.clock.Now()
			} else if lastBusy.IsZero() {
				s.capacity.lastBusy[key] = s.clock.Now()
				lastBusy = s.clock.Now()
			}
			s.capacity.mu.Unlock()
			if saturation || cpuUse > p.TargetCPU {
				wanted = max(wanted+1, int(math.Ceil(float64(ready)*cpuUse/p.TargetCPU)))
			} else if !busy && s.clock.Now().Sub(lastBusy) >= 5*time.Minute && wanted > int(scaling.MinEnvironments) {
				wanted--
			}
		}
		wanted = min(wanted, int(scaling.MaxEnvironments))
		if len(current) > wanted {
			e := current[len(current)-1]
			e.State = "Draining"
			return s.saveCapacityEnvironment(ctx, p, e)
		}
		if len(current) < wanted {
			// Spread the initial baseline over three guests before packing additional
			// environments, matching managed-instance AZ resilience when subnets allow.
			var selected *CapacityGuestRecord
			preferEmpty := len(current) < min(3, int(scaling.MinEnvironments))
			for i := range guests {
				g := &guests[i]
				if g.State != "Ready" || g.VCPUs-usedCPU[g.ID] < capacityVCPUs(f) || g.MemoryMB-usedMemory[g.ID] < int32(f.MemoryMB) {
					continue
				}
				if preferEmpty && usedCPU[g.ID] != 0 {
					continue
				}
				selected = g
				break
			}
			if selected == nil {
				var allocated int32
				for _, g := range guests {
					allocated += g.VCPUs
				}
				if allocated+capacityVCPUs(f) > p.MaxVCPUs {
					return s.capacityFunctionFailure(ctx, []FunctionRecord{f}, fmt.Errorf("capacity provider MaxVCpuCount prevents requested function minimum"))
				}
				guest, err := newCapacityGuest(p, f, len(guests), s.clock.Now())
				if err != nil {
					return err
				}
				// Reserve immutable intent before EC2 admission. Launch retries use this
				// same guest generation as ClientToken after a controller restart.
				return s.repository.Update(ctx, func(tx Transaction) error {
					current, err := tx.CapacityProvider(p.Key)
					if err != nil {
						return err
					}
					if current.Generation != p.Generation || current.State != "Active" {
						return nil
					}
					return tx.PutCapacityGuest(guest)
				})
			}
			e := CapacityEnvironmentRecord{Key: key, ID: uuid.NewString(), Generation: f.DeploymentRevision, GuestID: selected.ID, State: "Pending", Modified: s.clock.Now()}
			return s.saveCapacityEnvironment(ctx, p, e)
		}
		if ready >= int(scaling.MinEnvironments) && len(current) <= int(scaling.MaxEnvironments) {
			if err = s.repository.Update(ctx, func(tx Transaction) error {
				current, err := loadDeployment(tx, key)
				if err != nil {
					return err
				}
				if current.DeploymentRevision != f.DeploymentRevision {
					return nil
				}
				actual, err := effectiveCapacityScaling(tx, current)
				if err != nil {
					return err
				}
				if actual.Generation != scaling.Generation {
					return nil
				}
				actual.AppliedMin, actual.AppliedMax = scaling.MinEnvironments, scaling.MaxEnvironments
				if err = tx.PutCapacityScaling(actual); err != nil {
					return err
				}
				state := "Active"
				if scaling.MaxEnvironments == 0 {
					state = "Inactive"
				}
				if current.State == state && current.StateReason == "" {
					return nil
				}
				current.State = state
				current.StateReason = ""
				current.StateReasonCode = ""
				current.Revision = uuid.NewString()
				return tx.SetCapacityDeploymentState(current)
			}); err != nil {
				return err
			}
		}
	}
	// An idle guest with no retained environment is physically terminated. Never
	// delete the retained ownership row merely because EC2 accepted termination.
	for _, g := range guests {
		if usedCPU[g.ID] != 0 {
			continue
		}
		if err = s.capacityBackend.Terminate(ctx, p, g); err != nil {
			var pending *managed.RemoteError
			if errors.As(err, &pending) && pending.Status == 409 {
				return nil
			}
			return err
		}
		return s.forgetTerminatedCapacityGuest(ctx, g)
	}
	return nil
}
func capacityVCPUs(f FunctionRecord) int32 {
	return int32(float64(f.MemoryMB) / (1024 * f.Capacity.MemoryGiBPerVCPU))
}
func (s *Service) saveCapacityGuest(ctx context.Context, p CapacityProviderRecord, g CapacityGuestRecord) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.CapacityProvider(p.Key)
		if err != nil {
			return err
		}
		if current.Generation != p.Generation {
			return errors.New("capacity provider incarnation changed")
		}
		g.Modified = s.clock.Now()
		return tx.PutCapacityGuest(g)
	})
}
func (s *Service) saveCapacityEnvironment(ctx context.Context, p CapacityProviderRecord, e CapacityEnvironmentRecord) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.CapacityProvider(p.Key)
		if err != nil {
			return err
		}
		if current.Generation != p.Generation {
			return errors.New("capacity provider incarnation changed")
		}
		if e.State != "Draining" {
			f, err := loadDeployment(tx, e.Key)
			if err != nil {
				return err
			}
			if f.DeploymentRevision != e.Generation {
				return errors.New("managed deployment incarnation changed")
			}
		}
		e.Modified = s.clock.Now()
		return tx.PutCapacityEnvironment(e)
	})
}
func (s *Service) capacityFunctionFailure(ctx context.Context, functions []FunctionRecord, cause error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		for _, f := range functions {
			if f.State == "Active" {
				continue
			}
			f.State = "Failed"
			f.StateReason = cause.Error()
			f.StateReasonCode = "InternalError"
			f.Revision = uuid.NewString()
			if err := tx.SetCapacityDeploymentState(f); err != nil {
				return err
			}
		}
		return nil
	})
}
func newCapacityGuest(p CapacityProviderRecord, f FunctionRecord, index int, now time.Time) (CapacityGuestRecord, error) {
	id := uuid.NewString()
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return CapacityGuestRecord{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return CapacityGuestRecord{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CapacityGuestRecord{}, err
	}
	name := "lambda-guest." + id + ".internal"
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return CapacityGuestRecord{}, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return CapacityGuestRecord{}, err
	}
	return CapacityGuestRecord{Provider: p.Key, ID: id, Generation: id, SubnetID: p.SubnetIDs[index%len(p.SubnetIDs)], AgentToken: base64.RawURLEncoding.EncodeToString(token[:]), AgentCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), AgentPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), State: "Pending", VCPUs: capacityVCPUs(f), MemoryMB: int32(f.MemoryMB), Modified: now}, nil
}
func (s *Service) prepareCapacityEnvironment(ctx context.Context, p CapacityProviderRecord, g CapacityGuestRecord, e CapacityEnvironmentRecord, f FunctionRecord, client *managed.Client) error {
	var archive CodeArchive
	var layers [][]byte
	if err := s.repository.View(ctx, func(r Reader) error {
		current, err := loadDeployment(r, e.Key)
		if err != nil {
			return err
		}
		if current.DeploymentRevision != e.Generation {
			return errors.New("managed function deployment changed")
		}
		archive, err = r.CodeArchive(CodeArchiveKey{Scope: f.Key.Scope, SHA256: f.CodeSHA256})
		if err != nil {
			return err
		}
		layers, err = deploymentLayerCode(r, f.Layers)
		return err
	}); err != nil {
		return err
	}
	credentials, err := s.capacityCredentials(ctx, f, e.ID)
	if err != nil {
		return err
	}
	e.CredentialsExpire = credentials.Expiration
	if err := s.saveCapacityEnvironment(ctx, p, e); err != nil {
		return err
	}
	spec := runtime.Specification{FunctionARN: e.Key.ARN(), FunctionName: f.Key.Name, Runtime: f.Runtime, Handler: f.Handler, Architecture: f.Architecture, Code: archive.Code, Layers: layers, Variables: f.Variables, Timeout: time.Duration(f.Timeout) * time.Second, MemoryMB: f.MemoryMB, EphemeralMB: f.EphemeralMB, Credentials: credentials, Endpoint: s.endpoint, LogGroup: functionLogGroup(f), LogStream: functionLogStream(f, s.clock.Now()), Logging: f.Logging}
	observation, err := client.Prepare(ctx, managed.Deployment{ID: e.ID, Revision: e.Generation, Specification: spec, MaxConcurrency: f.Capacity.MaxConcurrency, VCPUs: int(capacityVCPUs(f))})
	if err != nil {
		if observation, observeErr := client.Observe(ctx, e.ID); observeErr == nil {
			if logErr := s.flushCapacityLogs(ctx, e, f, observation, client); logErr != nil {
				slog.Warn("Lambda managed initialization log delivery failed", "environment", e.ID, "error", logErr)
			}
		}
		e.Error = err.Error()
		_ = s.saveCapacityEnvironment(ctx, p, e)
		return s.capacityFunctionFailure(ctx, []FunctionRecord{f}, err)
	}
	if !observation.Ready {
		return errors.New("managed guest did not reach Runtime API readiness")
	}
	e.State = "Ready"
	e.Error = ""
	e.CredentialsExpire = observation.CredentialsExpire
	return s.saveCapacityEnvironment(ctx, p, e)
}
