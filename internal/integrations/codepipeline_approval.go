package integrations

import (
	"context"
	"encoding/json"
	"errors"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/awswire"
	"stackd/internal/services/codepipeline"
)

type approvalNotification struct {
	Region      string `json:"region"`
	ConsoleLink string `json:"consoleLink"`
	Approval    struct {
		PipelineName       string  `json:"pipelineName"`
		StageName          string  `json:"stageName"`
		ActionName         string  `json:"actionName"`
		Token              string  `json:"token"`
		Expires            string  `json:"expires"`
		ExternalEntityLink *string `json:"externalEntityLink"`
		ApprovalReviewLink string  `json:"approvalReviewLink"`
		CustomData         *string `json:"customData"`
	} `json:"approval"`
}

func (a *CodePipelineActions) notifyApproval(ctx context.Context, request codepipeline.ActionRequest) (codepipeline.ActionResult, error) {
	configuration := request.Action.Configuration
	name := pipelineString(request.Action.Name)
	payload := approvalNotification{
		Region:      request.Region,
		ConsoleLink: "https://console.aws.amazon.com/codesuite/codepipeline/pipelines/" + request.PipelineName + "/view?region=" + request.Region,
	}
	payload.Approval.PipelineName = request.PipelineName
	payload.Approval.StageName = request.StageName
	payload.Approval.ActionName = name
	payload.Approval.Token = request.ApprovalToken
	payload.Approval.Expires = request.ApprovalExpiresAt.UTC().Format("2006-01-02T15:04Z")
	payload.Approval.ApprovalReviewLink = payload.ConsoleLink + "#/" + request.StageName + "/" + name + "/approve/" + request.ApprovalToken
	if value, ok := configuration["ExternalEntityLink"]; ok {
		payload.Approval.ExternalEntityLink = new(string(value))
	}
	if value, ok := configuration["CustomData"]; ok {
		payload.Approval.CustomData = new(string(value))
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return codepipeline.ActionResult{}, err
	}
	subject := "APPROVAL NEEDED: AWS CodePipeline " + approvalSubjectName(request.PipelineName) + " for action " + approvalSubjectName(name)
	raw, err := pipelineCommand(ctx, a.SNS, "sns", "Publish", &api.PublishInput{
		TopicArn: new(api.TopicARN(configuration["NotificationArn"])),
		Message:  new(api.Message(body)), Subject: new(api.Subject(subject)),
	})
	if err != nil {
		if rejected, ok := err.(*awswire.Error); ok {
			var code, message string
			switch {
			case rejected.StatusCode == 403:
				code = "PermissionError"
				message = "The Pipeline or Action role does not have permission to publish to topics in Amazon SNS. Add the sns:Publish permission to the role’s policy, and then try again."
			case rejected.Code == "NotFound":
				code = "ConfigurationError"
				message = "No Amazon SNS topic with the ARN " + string(configuration["NotificationArn"]) + " was found. Update your pipeline to use an existing topic, or create a new one to use in your pipeline."
			case rejected.Code == "InvalidParameter":
				code = "ConfigurationError"
				message = "An invalid topic ARN (" + string(configuration["NotificationArn"]) + ") was provided. Update your pipeline to use a valid topic, or create a new one to use in your pipeline."
			}
			if code != "" {
				return codepipeline.ActionResult{Status: "Failed", ErrorCode: code, Summary: message, ErrorMessage: message}, nil
			}
		}
		return codepipeline.ActionResult{}, err
	}
	id := pipelineString(raw.(*api.PublishOutput).MessageId)
	if id == "" {
		return codepipeline.ActionResult{}, errors.New("SNS Publish returned no message ID")
	}
	return codepipeline.ActionResult{Status: "InProgress", ApprovalNotificationID: id}, nil
}

func approvalSubjectName(name string) string {
	if len(name) > 24 {
		return name[:24] + "..."
	}
	return name
}
