package organizations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// JobDriver exposes this service's scheduler for instance assembly. Join it
// before StartWorkers; joined services share execution and shutdown.
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }

// StartWorkers recovers accepted account requests after dependencies are wired.
func (s *Service) StartWorkers() { s.jobs.Start() }

// Close joins provisioning before returning; injected storage and time remain
// caller-owned. Pending requests resume when the retained backend is reopened.
func (s *Service) Close() error { s.jobs.Close(); return nil }

type accountCreationJobs struct{ service *Service }

func (source accountCreationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	partitions, err := source.service.storage.Partitions(ctx)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, partition := range partitions {
		record, _, err := source.service.storage.Load(ctx, partition)
		if err != nil {
			return scheduler.Job{}, false, err
		}
		for _, org := range record.Organizations {
			for _, job := range org.Creations {
				if job.State != "IN_PROGRESS" {
					continue
				}
				candidate := scheduler.Job{Key: partition + "/" + org.Organization.ID + "/" + job.ID, Due: job.Due}
				if !found || scheduler.Compare(candidate, next) < 0 {
					next, found = candidate, true
				}
			}
		}
	}
	return next, found, nil
}

func (source accountCreationJobs) Run(ctx context.Context, selected scheduler.Job) error {
	partition, rest, _ := strings.Cut(selected.Key, "/")
	orgID, id, _ := strings.Cut(rest, "/")
	s := source.service
	record, revision, err := s.storage.Load(ctx, partition)
	if err != nil {
		return err
	}
	worker := &operationState{serviceState: decodeState(record, partition, ""), instant: s.clock.Now()}
	org := worker.orgs[orgID]
	if org == nil {
		return nil
	}
	job, ok := org.creations[id]
	if !ok || job.State != "IN_PROGRESS" || !job.Due.Equal(selected.Due) || job.Due.After(worker.instant) {
		return nil
	}
	job.State, job.CompletedAt = "SUCCEEDED", worker.instant
	if _, exists := worker.knownEmails[strings.ToLower(job.Email)]; exists {
		job.State, job.FailureReason = "FAILED", "EMAIL_ALREADY_EXISTS"
	} else if worker.accountQuotaReached(org, s.accountQuotas.maximum(partition, org.organization.MasterAccountID), "") {
		job.State, job.FailureReason = "FAILED", "ACCOUNT_LIMIT_EXCEEDED"
	} else if _, exists := worker.knownAccounts[job.AccountID]; exists {
		// The local bootstrap account namespace can overlap a reserved ID.
		job.State, job.FailureReason = "FAILED", "INTERNAL_FAILURE"
	} else {
		worker.accountProvisioning = &AccountProvisioning{Partition: partition, AccountID: job.AccountID, AccountName: job.AccountName, ManagementAccountID: org.organization.MasterAccountID, AccessRoleName: job.RoleName, CreatedAt: worker.instant}
		account := account{ID: job.AccountID, ARN: org.arn(partition, "account", job.AccountID), Name: job.AccountName, Email: job.Email, State: "ACTIVE", Status: "ACTIVE", JoinedMethod: "CREATED", JoinedTimestamp: worker.timestamp()}
		org.accounts[account.ID], worker.knownAccounts[account.ID] = account, account
		org.parents[account.ID], org.tags[account.ID] = org.root.ID, job.Tags
		org.attachDefaults(account.ID)
		worker.scheduleEffectivePolicies(org, []string{account.ID}, "", awsctx.Metadata{RequestID: job.RequestID, Region: job.RequestRegion, PrincipalARN: job.ActorARN})
		worker.memberships[account.ID], worker.knownEmails[strings.ToLower(account.Email)] = orgID, account.ID
	}
	org.creations[id] = job
	worker.recordAccountCreation(org, job)
	// TODO: Comeback emit the native CreateAccountResult AwsServiceEvent with source-owned serviceEventDetails, separately from API acceptance.
	_, err = s.commit(ctx, partition, revision, worker)
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) && apiErr.StatusCode < 500 {
		// A permanent IAM provisioning rejection has rolled back both stores.
		// Publish only the failure against the same revision. Storage failures keep
		// the accepted intent pending for the driver's service-time retry.
		worker = &operationState{serviceState: decodeState(record, partition, "")}
		job.State, job.FailureReason = "FAILED", "INTERNAL_FAILURE"
		worker.orgs[orgID].creations[id] = job
		worker.recordAccountCreation(worker.orgs[orgID], job)
		_, err = s.commit(ctx, partition, revision, worker)
	}
	return err
}
