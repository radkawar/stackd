package authorization_test

import (
	"fmt"
	"testing"
	"time"

	"stackd/clock"
	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestCapturedEvaluationTimeIncludesZeroEpoch(t *testing.T) {
	for _, instant := range []time.Time{{}, time.Unix(0, 0).UTC(), time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)} {
		t.Run(instant.Format(time.RFC3339), func(t *testing.T) {
			source := clock.NewManual(instant)
			document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"DateEquals":{"aws:CurrentTime":%q}}}}`, instant.Format(time.RFC3339))
			evaluator := authorization.NewWithClock(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: document}}}}, nil, source)
			ctx := awsctx.WithMetadata(t.Context(), metadata(false))
			request := authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, EvaluationTime: &instant}
			if err := source.Advance(time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := evaluator.Authorize(ctx, request); err != nil {
				t.Fatal("captured transaction time was replaced:", err)
			}
			request.EvaluationTime = nil
			if err := evaluator.Authorize(ctx, request); err == nil {
				t.Fatal("uncaptured decision did not use the current service clock")
			}
		})
	}
}
