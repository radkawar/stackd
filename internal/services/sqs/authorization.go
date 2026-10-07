package sqs

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func queuePermission(q *queue, action string) authorization.Request {
	values := make(map[string][]string, len(q.tags))
	for k, v := range q.tags {
		values["aws:ResourceTag/"+string(k)] = []string{string(v)}
	}
	return authorization.Request{Action: "sqs:" + action, ResourceARN: q.key.arn(), ResourcePolicies: []authorization.BoundPolicy{{Document: q.config.policy, PrincipalIDs: q.config.policyPrincipals}}, Context: values}
}
func (s *Service) permissions(r *http.Request, action string, input any) ([]authorization.Request, *awswire.Error) {
	var rawURL string
	switch in := input.(type) {
	case *api.CreateQueueInput:
		req := authorization.Request{Action: "sqs:CreateQueue", ResourceARN: requestKey(r, value(in.QueueName)).arn(), Context: make(map[string][]string)}
		for k, v := range in.Tags {
			req.Context["aws:RequestTag/"+string(k)] = []string{string(v)}
			req.Context["aws:TagKeys"] = append(req.Context["aws:TagKeys"], string(k))
		}
		slices.Sort(req.Context["aws:TagKeys"])
		out := []authorization.Request{req}
		if len(in.Tags) > 0 {
			tag := req
			tag.Action = "sqs:TagQueue"
			out = append(out, tag)
		}
		return out, nil
	case *api.ListQueuesInput:
		return []authorization.Request{{Action: "sqs:ListQueues", ResourceARN: requestKey(r, "*").arn()}}, nil
	case *api.GetQueueUrlInput:
		key := requestKey(r, value(in.QueueName))
		if owner := value(in.QueueOwnerAWSAccountId); owner != "" {
			key.account = owner
		}
		var wire *awswire.Error
		rawURL, wire = s.localURL(r, key)
		if wire != nil {
			return nil, wire
		}
	case *api.DeleteQueueInput:
		rawURL = value(in.QueueUrl)
	case *api.GetQueueAttributesInput:
		rawURL = value(in.QueueUrl)
	case *api.SetQueueAttributesInput:
		rawURL = value(in.QueueUrl)
	case *api.ListQueueTagsInput:
		rawURL = value(in.QueueUrl)
	case *api.TagQueueInput:
		rawURL = value(in.QueueUrl)
	case *api.UntagQueueInput:
		rawURL = value(in.QueueUrl)
	case *api.PurgeQueueInput:
		rawURL = value(in.QueueUrl)
	case *api.ListDeadLetterSourceQueuesInput:
		rawURL = value(in.QueueUrl)
	case *api.SendMessageInput:
		rawURL = value(in.QueueUrl)
	case *api.ReceiveMessageInput:
		rawURL = value(in.QueueUrl)
	case *api.DeleteMessageInput:
		rawURL = value(in.QueueUrl)
	case *api.ChangeMessageVisibilityInput:
		rawURL = value(in.QueueUrl)
	case *api.SendMessageBatchInput:
		rawURL = value(in.QueueUrl)
		action = "SendMessage"
	case *api.DeleteMessageBatchInput:
		rawURL = value(in.QueueUrl)
		action = "DeleteMessage"
	case *api.ChangeMessageVisibilityBatchInput:
		rawURL = value(in.QueueUrl)
		action = "ChangeMessageVisibility"
	case *api.AddPermissionInput:
		rawURL = value(in.QueueUrl)
	case *api.RemovePermissionInput:
		rawURL = value(in.QueueUrl)
	case *api.StartMessageMoveTaskInput:
		return s.movePermissions(r, action, value(in.SourceArn), value(in.DestinationArn))
	case *api.ListMessageMoveTasksInput:
		return s.movePermissions(r, action, value(in.SourceArn), "")
	case *api.CancelMessageMoveTaskInput:
		task := s.tasks[value(in.TaskHandle)]
		if task == nil {
			return nil, failure("ResourceNotFoundException", "The specified message move task does not exist.")
		}
		return s.movePermissions(r, action, privateKey(task.Source).arn(), "")
	default:
		return nil, &awswire.Error{Code: "InternalError", Message: "Missing authorization binding.", StatusCode: 500}
	}
	q, err := s.queueFor(r, rawURL)
	if err != nil {
		return nil, err
	}
	scope := awsctx.FromContext(r.Context())
	if scope.AccountID != q.key.account && slices.Contains([]string{"AddPermission", "RemovePermission", "DeleteQueue", "SetQueueAttributes", "ListQueueTags", "TagQueue", "UntagQueue", "ListDeadLetterSourceQueues"}, action) {
		return nil, &awswire.Error{Code: "AccessDenied", Message: "This action does not support cross-account permissions.", StatusCode: 403}
	}
	req := queuePermission(q, action)
	// Privileged root sessions can recover a same-account queue whose resource
	// policy denies every principal. The task policy and SCPs still apply in
	// the authorizer; this exception belongs only to queue-policy management.
	if scope.SessionType == string(identity.SessionTypeAssumeRoot) && scope.AccountID == q.key.account && (action == "GetQueueUrl" || action == "GetQueueAttributes" || action == "SetQueueAttributes") {
		req.ResourcePolicies = nil
	}
	switch in := input.(type) {
	case *api.TagQueueInput:
		for k, v := range in.Tags {
			req.Context["aws:RequestTag/"+string(k)] = []string{string(v)}
			req.Context["aws:TagKeys"] = append(req.Context["aws:TagKeys"], string(k))
		}
		slices.Sort(req.Context["aws:TagKeys"])
	case *api.UntagQueueInput:
		for _, k := range in.TagKeys {
			req.Context["aws:TagKeys"] = append(req.Context["aws:TagKeys"], string(k))
		}
		slices.Sort(req.Context["aws:TagKeys"])
	}
	return []authorization.Request{req}, nil
}

// KMS is the cryptographic boundary required for SQS-managed envelope keys.
// Calls run outside queue locks and repository callbacks. Implementations must
// enforce the caller's KMS permissions, honor context cancellation and return
// caller-owned key buffers. SQS erases plaintext when it leaves the cache.
type KMS interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
}

// NewWithDependencies constructs queues using the shared authorization and KMS
// providers. Without an authorizer, only verified roots are permitted.
func NewWithDependencies(kms KMS, authorizer authorization.Authorizer) *Service {
	return NewWithRepository(nil, kms, authorizer)
}
func serviceError(err *awswire.Error) *awswire.Error {
	if err == nil {
		return nil
	}
	if err.StatusCode >= 500 {
		// Backend failures must remain server errors rather than describing
		// the caller's KMS key as invalid.
		return err
	}
	code := strings.TrimSuffix(err.Code, "Exception")
	switch code {
	case "AccessDenied":
		code = "KmsAccessDenied"
	case "NotFound":
		code = "KmsNotFound"
	case "Disabled":
		code = "KmsDisabled"
	case "InvalidKeyUsage":
		code = "KmsInvalidKeyUsage"
	case "KMSInvalidState":
		code = "KmsInvalidState"
	case "Throttling":
		code = "KmsThrottled"
	default:
		code = "KmsInvalidState"
	}
	return failure(code, err.Message)
}
