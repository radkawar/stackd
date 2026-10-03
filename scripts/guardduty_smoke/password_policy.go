package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func passwordPolicyDetection(ctx context.Context, detectorClient *gd.Client, root, denied *iam.Client, detector *string) {
	findings := func(action, outcome string) []gt.Finding {
		page, err := detectorClient.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{
			"type":                                {Equals: []string{"Stealth:IAMUser/PasswordPolicyChange"}},
			"service.action.awsApiCallAction.api": {Equals: []string{action}},
		}}})
		must(err)
		if len(page.FindingIds) == 0 {
			return nil
		}
		result, err := detectorClient.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: page.FindingIds})
		must(err)
		var out []gt.Finding
		for _, finding := range result.Findings {
			if aws.ToString(finding.Service.Action.AwsApiCallAction.ErrorCode) == outcome {
				out = append(out, finding)
			}
		}
		return out
	}
	checkFinding := func(action, outcome string, count int32) {
		got := findings(action, outcome)
		check(len(got) == 1 && aws.ToInt32(got[0].Service.Count) == count && got[0].Service.Action.AwsApiCallAction.AffectedResources["AWS::Account"] == "123456789012" && aws.ToString(got[0].Resource.ResourceType) == "AccessKey", "password policy attempt lost actual account/outcome: "+action+"/"+outcome)
	}
	_, err := root.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	code(err, "NoSuchEntity")
	check(len(findings("GetAccountPasswordPolicy", "NoSuchEntity")) == 0, "policy read produced a change finding")
	_, err = root.UpdateAccountPasswordPolicy(ctx, &iam.UpdateAccountPasswordPolicyInput{MinimumPasswordLength: aws.Int32(14), RequireSymbols: true, RequireNumbers: true, MaxPasswordAge: aws.Int32(30)})
	must(err)
	checkFinding("UpdateAccountPasswordPolicy", "", 1)
	_, err = denied.UpdateAccountPasswordPolicy(ctx, &iam.UpdateAccountPasswordPolicyInput{MinimumPasswordLength: aws.Int32(6)})
	code(err, "AccessDenied")
	checkFinding("UpdateAccountPasswordPolicy", "AccessDenied", 1)
	_, err = denied.DeleteAccountPasswordPolicy(ctx, &iam.DeleteAccountPasswordPolicyInput{})
	code(err, "AccessDenied")
	checkFinding("DeleteAccountPasswordPolicy", "AccessDenied", 1)
	retained, err := root.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	must(err)
	check(aws.ToInt32(retained.PasswordPolicy.MinimumPasswordLength) == 14 && retained.PasswordPolicy.RequireSymbols && retained.PasswordPolicy.RequireNumbers, "denied change mutated account policy")
	_, err = root.UpdateAccountPasswordPolicy(ctx, &iam.UpdateAccountPasswordPolicyInput{MinimumPasswordLength: aws.Int32(6), MaxPasswordAge: aws.Int32(90)})
	must(err)
	checkFinding("UpdateAccountPasswordPolicy", "", 2)
	weak, err := root.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	must(err)
	check(aws.ToInt32(weak.PasswordPolicy.MinimumPasswordLength) == 6 && !weak.PasswordPolicy.RequireSymbols && !weak.PasswordPolicy.RequireNumbers && aws.ToInt32(weak.PasswordPolicy.MaxPasswordAge) == 90, "successful policy update was not retained")
	_, err = root.DeleteAccountPasswordPolicy(ctx, &iam.DeleteAccountPasswordPolicyInput{})
	must(err)
	checkFinding("DeleteAccountPasswordPolicy", "", 1)
	deletedID := aws.ToString(findings("DeleteAccountPasswordPolicy", "")[0].Id)
	_, err = root.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	code(err, "NoSuchEntity")
	_, err = root.DeleteAccountPasswordPolicy(ctx, &iam.DeleteAccountPasswordPolicyInput{})
	code(err, "NoSuchEntity")
	checkFinding("DeleteAccountPasswordPolicy", "NoSuchEntityException", 2)
	check(aws.ToString(findings("DeleteAccountPasswordPolicy", "NoSuchEntityException")[0].Id) == deletedID && len(findings("DeleteAccountPasswordPolicy", "")) == 0, "latest outcome did not replace evidence within the same aggregate")
	fmt.Println("GuardDuty IAM password policy: updates aggregate; denied and missing-policy attempts retain actual outcomes without state changes: PASS")
}
