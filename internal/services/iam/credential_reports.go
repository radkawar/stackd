package iam

import (
	"context"
	"errors"
	"math"
	"time"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// The Get API's expiration reference points to the guide's four-hour report
// window. The live fixture confirms cache reuse, but does not age a report for
// four hours; that boundary is derived from the documentation.
const credentialReportLifetime = 4 * time.Hour

func (s *Service) generateCredentialReport(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	transaction, ok := ctx.Value(transactionKey{}).(serviceTransaction)
	tx, writable := transaction.tx.(WriteTx)
	if !ok || transaction.service != s || !writable {
		return nil, credentialReportRowsFailure()
	}
	scope := Scope{Partition: m.Partition, AccountID: m.AccountID}
	report, err := tx.CredentialReport(scope)
	if err != nil && !errors.Is(err, ErrRecordNotFound) {
		return nil, credentialReportRowsFailure()
	}
	if errors.Is(err, ErrRecordNotFound) {
		report = CredentialReportRecord{}
	}
	if err == nil {
		switch report.State {
		case CredentialReportPending:
			state := iamapi.ReportStateTypeINPROGRESS
			return &iamapi.GenerateCredentialReportOutput{State: &state}, nil
		case CredentialReportComplete:
			if !a.currentTime.After(report.GeneratedAt.Add(credentialReportLifetime)) {
				state := iamapi.ReportStateTypeCOMPLETE
				return &iamapi.GenerateCredentialReportOutput{State: &state}, nil
			}
		case CredentialReportFailed:
			// A new request retries a failed generation with a new fence.
		default:
			return nil, credentialReportRowsFailure()
		}
	}
	if report.Generation == math.MaxUint64 {
		return nil, credentialReportRowsFailure()
	}
	report = CredentialReportRecord{Generation: report.Generation + 1, State: CredentialReportPending, RequestedAt: a.currentTime}
	if err := tx.PutCredentialReport(scope, report); err != nil {
		return nil, credentialReportRowsFailure()
	}
	state := iamapi.ReportStateTypeSTARTED
	result := &iamapi.GenerateCredentialReportOutput{State: &state}
	if report.Generation == 1 {
		description := iamapi.ReportStateDescriptionType("No report exists. Starting a new report generation task")
		result.Description = &description
	}
	return result, nil
}

func (s *Service) getCredentialReport(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	var report CredentialReportRecord
	err := s.view(ctx, func(tx ReadTx) error {
		var err error
		report, err = tx.CredentialReport(Scope{Partition: m.Partition, AccountID: m.AccountID})
		return err
	})
	if errors.Is(err, ErrRecordNotFound) {
		return nil, credentialReportError("ReportNotPresent", 410)
	}
	if err != nil {
		return nil, credentialReportRowsFailure()
	}
	switch report.State {
	case CredentialReportPending:
		return nil, credentialReportError("ReportInProgress", 404)
	case CredentialReportComplete:
		if a.currentTime.After(report.GeneratedAt.Add(credentialReportLifetime)) {
			return nil, credentialReportError("ReportExpired", 410)
		}
		format := iamapi.ReportFormatTypeText_csv
		generated := iamapi.DateType(report.GeneratedAt)
		return &iamapi.GetCredentialReportOutput{Content: report.Content, ReportFormat: &format, GeneratedTime: &generated}, nil
	default:
		return nil, credentialReportRowsFailure()
	}
}

func credentialReportError(code string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: "Unknown", StatusCode: status}
}
