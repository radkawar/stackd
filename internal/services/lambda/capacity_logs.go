package lambda

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	runtime "stackd/compute/lambda"
	"stackd/compute/lambda/managed"
)

func (s *Service) capacityCredentials(ctx context.Context, f FunctionRecord, id string) (runtime.Credentials, error) {
	s.capacity.mu.Lock()
	credentials := s.capacity.credentials[id]
	s.capacity.mu.Unlock()
	if credentials.AccessKeyID != "" && s.clock.Now().Add(10*time.Minute).Before(credentials.Expiration) {
		return credentials, nil
	}
	issued, rejected := s.roles.Assume(ownerContext(ctx, f.Key), f.Role, f.Key.ARN(), f.Key.Name)
	if rejected != nil {
		return runtime.Credentials{}, rejected
	}
	s.capacity.mu.Lock()
	s.capacity.credentials[id] = issued
	s.capacity.mu.Unlock()
	return issued, nil
}
func (s *Service) maintainCapacityEnvironment(ctx context.Context, p CapacityProviderRecord, e CapacityEnvironmentRecord, f FunctionRecord, o *managed.Observation, client *managed.Client) error {
	if !s.clock.Now().Add(10 * time.Minute).Before(o.CredentialsExpire) {
		credentials, err := s.capacityCredentials(ctx, f, e.ID)
		if err != nil {
			return err
		}
		if err = client.RefreshCredentials(ctx, e.ID, credentials); err != nil {
			return err
		}
		o.CredentialsExpire = credentials.Expiration
		e.CredentialsExpire = credentials.Expiration
		if err = s.saveCapacityEnvironment(ctx, p, e); err != nil {
			return err
		}
	}
	if err := s.flushCapacityLogs(ctx, e, f, *o, client); err != nil {
		slog.Warn("Lambda managed log delivery failed", "function", f.Key.ARN(), "environment", e.ID, "error", err)
	}
	return nil
}
func (s *Service) flushCapacityLogs(ctx context.Context, e CapacityEnvironmentRecord, f FunctionRecord, o managed.Observation, client *managed.Client) error {
	batch, err := client.Logs(ctx, e.ID)
	if err != nil {
		return err
	}
	if len(batch.Data) == 0 {
		return nil
	}
	if s.logs == nil {
		return client.AcknowledgeLogs(ctx, e.ID, batch.Offset+int64(len(batch.Data)))
	}
	if o.LogGroup != functionLogGroup(f) || o.LogStream == "" {
		return errors.New("managed guest log destination differs from its deployment")
	}
	credentials, err := s.capacityCredentials(ctx, f, e.ID)
	if err != nil {
		return err
	}
	writer := s.logs.Open(ownerContext(ctx, f.Key), f.Key, credentials, o.LogGroup, o.LogStream)
	written, writeErr := writer.Write(batch.Data)
	closeErr := writer.Close()
	if writeErr == nil && written != len(batch.Data) {
		writeErr = io.ErrShortWrite
	}
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return client.AcknowledgeLogs(ctx, e.ID, batch.Offset+int64(len(batch.Data)))
}

func (s *Service) drainCapacityLogs(ctx context.Context, e CapacityEnvironmentRecord, f FunctionRecord, current bool, client *managed.Client) {
	if current {
		observation, err := client.Observe(ctx, e.ID)
		if err == nil {
			err = s.flushCapacityLogs(ctx, e, f, observation, client)
		}
		if err == nil {
			return
		}
		slog.Warn("Lambda managed final log delivery failed", "environment", e.ID, "error", err)
	}
	// Logging is best effort and cannot keep native compute alive after deletion
	// merely because the removed deployment's execution role no longer exists.
	batch, err := client.Logs(ctx, e.ID)
	if err != nil || len(batch.Data) == 0 {
		return
	}
	slog.Warn("Discarding undeliverable Lambda output during environment cleanup", "environment", e.ID, "bytes", len(batch.Data))
	if err = client.AcknowledgeLogs(ctx, e.ID, batch.Offset+int64(len(batch.Data))); err != nil {
		slog.Warn("Lambda managed output cleanup failed", "environment", e.ID, "error", err)
	}
}
