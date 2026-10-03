package resourcegroupstaggingapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/resourcegroupstaggingapi"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
)

// Start owns its transaction boundary: native S3 admission must never run inside
// the tagging transaction, and the accepted intent and API event commit together.
func registerReportStart(s *Service) {
	s.operations["StartReportCreation"] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[api.StartReportCreationInput](ctx)
		if !ok {
			return nil, failure("InternalServiceException", "Missing generated request binding.")
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		out, err := s.startReportCreation(ctx, in)
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.recordCall(completion, "StartReportCreation", in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}

func (s *Service) startReportCreation(ctx context.Context, in *api.StartReportCreationInput) (*api.StartReportCreationOutput, error) {
	if err := s.authorize(ctx, "StartReportCreation", nil, nil); err != nil {
		return nil, err
	}
	org, err := s.organization(ctx)
	if err != nil {
		return nil, err
	}
	bucket := value(in.S3Bucket)
	if len(bucket) < 3 || len(bucket) > 63 || strings.Trim(bucket, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		return nil, invalid("S3Bucket must be a valid bucket name containing 3 to 63 characters.")
	}
	if s.reports == nil {
		return nil, failure("InternalServiceException", "Report delivery is not configured.")
	}
	if err := s.reports.ValidateDestination(ctx, bucket, org.ID); err != nil {
		return nil, err
	}
	out := &api.StartReportCreationOutput{}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		previous, found, err := tx.Report(scopeFor(ctx))
		if err != nil {
			return err
		}
		if found && previous.Status == "RUNNING" {
			return failure("ConcurrentModificationException", "A report is already being generated.")
		}
		now := s.clock.Now().UTC()
		report := Report{Scope: scopeFor(ctx), Version: previous.Version + 1, OrganizationID: org.ID, Bucket: bucket, ObjectKey: "AwsTagPolicies/" + org.ID + "/" + now.Format(time.RFC3339) + "/report.csv", Status: "RUNNING", StartedAt: now, Due: now, Caller: awsctx.FromContext(ctx)}
		if err := tx.PutReport(report); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "StartReportCreation", in, out, nil)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) describeReportCreation(tx Transaction, _ *api.DescribeReportCreationInput) (*api.DescribeReportCreationOutput, error) {
	if err := s.authorize(tx.Context(), "DescribeReportCreation", nil, nil); err != nil {
		return nil, err
	}
	if _, err := s.organization(tx.Context()); err != nil {
		return nil, err
	}
	report, found, err := tx.Report(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	if !found || report.Status != "RUNNING" && !report.StartedAt.Add(90*24*time.Hour).After(s.clock.Now()) {
		return &api.DescribeReportCreationOutput{Status: new(api.Status("NO REPORT"))}, nil
	}
	out := &api.DescribeReportCreationOutput{Status: new(api.Status(report.Status)), StartDate: new(api.StartDate(report.StartedAt.UTC().Format(time.RFC3339)))}
	if report.Status == "SUCCEEDED" {
		out.S3Location = new(api.S3Location("s3://" + report.Bucket + "/" + report.ObjectKey))
	}
	if report.ErrorMessage != "" {
		out.ErrorMessage = new(api.ErrorMessage(report.ErrorMessage))
	}
	return out, nil
}

func reportKey(scope Scope) string {
	return scope.Partition + "\x00" + scope.AccountID + "\x00" + scope.Region
}

type reportJobs struct{ service *Service }

func (source reportJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var job scheduler.Job
	found := false
	err := source.service.repository.View(ctx, func(reader Reader) error {
		report, ok, err := reader.NextReport()
		found = ok
		if ok {
			job = scheduler.Job{Key: reportKey(report.Scope), Version: report.Version, Due: report.Due}
		}
		return err
	})
	return job, found, err
}
func (source reportJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := source.service
	parts := strings.Split(job.Key, "\x00")
	if len(parts) != 3 {
		return invalid("Invalid report job scope.")
	}
	scope := Scope{Partition: parts[0], AccountID: parts[1], Region: parts[2]}
	var selected Report
	claimed := false
	err := s.repository.Update(ctx, func(tx Transaction) error {
		report, found, err := tx.Report(scope)
		if err != nil || !found || report.Status != "RUNNING" || report.Version != job.Version || report.Due.After(s.clock.Now()) {
			return err
		}
		// A lease permits recovery after interruption without concurrent instances
		// publishing a stale completion. The destination key is stable on retry.
		report.Version++
		report.Due = s.clock.Now().UTC().Add(time.Minute)
		if err := tx.PutReport(report); err != nil {
			return err
		}
		selected = report
		claimed = true
		return nil
	})
	if err != nil || !claimed {
		return err
	}
	workerContext := awsctx.WithMetadata(ctx, selected.Caller)
	data, deliveryErr := s.reportCSV(workerContext, selected.OrganizationID)
	if deliveryErr == nil {
		if s.reports == nil {
			deliveryErr = failure("InternalServiceException", "Report delivery is not configured.")
		} else {
			deliveryErr = s.reports.Deliver(workerContext, selected.Bucket, selected.ObjectKey, selected.OrganizationID, data)
		}
	}
	// Cancellation keeps the intent recoverable. No transaction spans S3/KMS;
	// after a crash, re-delivery targets the same object, never a fabricated result.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		report, found, err := tx.Report(scope)
		if err != nil || !found || report.Version != selected.Version || report.Status != "RUNNING" {
			return err
		}
		report.Status = "SUCCEEDED"
		report.ErrorMessage = ""
		report.CompletedAt = s.clock.Now().UTC()
		if deliveryErr != nil {
			rejected := wireError(deliveryErr)
			report.Status = "FAILED"
			report.ErrorMessage = rejected.Code + ": " + rejected.Message
		}
		return tx.PutReport(report)
	})
}

// The native CSV column spelling/order is shown in AWS's tag-policy launch
// report: https://media.amazonwebservices.com/blog/2019/tag_report_1.png.
// Resource tags remain transient inputs to evaluation, not a persisted tag blob.
func (s *Service) reportCSV(ctx context.Context, organizationID string) ([]byte, error) {
	var data bytes.Buffer
	writer := csv.NewWriter(&data)
	if err := writer.Write([]string{"AccountId", "Region", "ResourceType", "ComplianceStatus", "NoncompliantKeys", "KeysWithNoncompliantValues", "ResourceARN"}); err != nil {
		return nil, err
	}
	err := s.repository.View(ctx, func(reader Reader) error {
		org, err := s.organization(reader.Context())
		if err != nil {
			return err
		}
		if org.ID != organizationID {
			return failure("ConstraintViolationException", "The report organization has changed.")
		}
		return s.visitCompliance(reader.Context(), reader, org, &api.GetComplianceSummaryInput{}, func(account Target, region string, resource Resource, details *api.ComplianceDetails) error {
			status := "FALSE"
			if boolean(details.ComplianceStatus) {
				status = "TRUE"
			}
			return writer.Write([]string{account.ID, region, resource.ResourceType, status, reportKeys(details.NoncompliantKeys), reportKeys(details.KeysWithNoncompliantValues), resource.ARN})
		})
	})
	if err != nil {
		return nil, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}
func reportKeys(keys api.TagKeyList) string {
	var result strings.Builder
	for i, key := range keys {
		if i > 0 {
			result.WriteByte(',')
		}
		result.WriteString(string(key))
	}
	return result.String()
}
