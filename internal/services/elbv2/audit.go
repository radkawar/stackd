package elbv2

import (
	"context"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("elbv2")
	op, ok := m.Operation(action)
	if !ok {
		return nil
	}
	readOnly := strings.HasPrefix(action, "Describe")
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnly}
	if !readOnly {
		projection.Response = &awsapi.DocumentProjection{}
	}
	call, e := projection.Call(m, op, in, out, rejected)
	if e != nil {
		return e
	}
	call.EventID = apievents.EventID(ctx)
	call.APIVersion = m.Version
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
