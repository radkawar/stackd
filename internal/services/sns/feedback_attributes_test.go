package sns

import (
	"context"
	"errors"
	"testing"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
)

func TestApplicationFeedbackTopicSettings(t *testing.T) {
	s := New(Config{})
	t.Cleanup(func() { _ = s.Close() })
	topic := TopicRecord{}
	ctx := context.Background()
	for _, rate := range []string{"0", "1", "100", "25", "0"} {
		if err := s.setTopicAttribute(ctx, &topic, "ApplicationSuccessFeedbackSampleRate", rate); err != nil {
			t.Fatalf("setting sample rate %s: %v", rate, err)
		}
		attributes := api.TopicAttributesMap{}
		feedbackAttributes(topic, attributes)
		if got := string(attributes["ApplicationSuccessFeedbackSampleRate"]); got != rate {
			t.Fatalf("sample rate readback = %q, want %q", got, rate)
		}
	}
	before := topic.Feedback["application"]
	for _, rate := range []string{"", "-1", "101", "1.5", "not-a-rate"} {
		err := s.setTopicAttribute(ctx, &topic, "ApplicationSuccessFeedbackSampleRate", rate)
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "InvalidParameter" {
			t.Fatalf("invalid rate %q: %v", rate, err)
		}
		if topic.Feedback["application"] != before {
			t.Fatalf("invalid rate %q changed retained feedback", rate)
		}
	}
	for _, name := range []string{"ApplicationSuccessFeedbackRoleArn", "ApplicationFailureFeedbackRoleArn"} {
		if err := s.setTopicAttribute(ctx, &topic, name, ""); err != nil {
			t.Fatalf("clearing absent mobile role %s: %v", name, err)
		}
		err := s.setTopicAttribute(ctx, &topic, name, "arn:aws:iam::738492615083:role/mobile")
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "NotImplementedException" {
			t.Fatalf("configuring an unavailable mobile feedback role: %v", err)
		}
		if topic.Feedback["application"] != before {
			t.Fatal("rejected mobile role changed retained feedback")
		}
	}
}
