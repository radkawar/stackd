package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func roleLifecycle(ctx context.Context, cloud *controller) {
	const roleName = "AWSServiceRoleForAmazonMQ"
	admin := iam.NewFromConfig(config("us-east-1", "123456789012"), func(o *iam.Options) { o.BaseEndpoint = &cloud.endpoint })
	root := client(cloud.endpoint, "us-east-1", "123456789012")
	caller, err := admin.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("mq-role-smoke-caller"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`)})
	must(err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := admin.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: caller.Role.RoleName, PolicyName: aws.String("broker")})
		must(err)
		_, err = admin.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: caller.Role.RoleName})
		must(err)
	}()
	_, err = admin.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: caller.Role.RoleName, PolicyName: aws.String("broker"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"mq:*","Resource":"*"},{"Effect":"Deny","Action":"iam:CreateServiceLinkedRole","Resource":"*"}]}`)})
	must(err)
	sessions := sts.NewFromConfig(config("us-east-1", "123456789012"), func(o *sts.Options) { o.BaseEndpoint = &cloud.endpoint })
	session, err := sessions.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: caller.Role.Arn, RoleSessionName: aws.String("mq-role-smoke")})
	must(err)
	cfg := config("us-east-1", "123456789012")
	cfg.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
	limited := mq.NewFromConfig(cfg, func(o *mq.Options) { o.BaseEndpoint = &cloud.endpoint })
	input := func(name string) *mq.CreateBrokerInput {
		return &mq.CreateBrokerInput{BrokerName: aws.String(name), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}}
	}
	_, err = limited.CreateBroker(ctx, input("role-denied"))
	code(err, "AccessDenied")
	_, err = admin.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	code(err, "NoSuchEntity")
	list, err := root.ListBrokers(ctx, &mq.ListBrokersInput{})
	must(err)
	if len(list.BrokerSummaries) != 0 {
		panic("denied role creation retained broker")
	}
	broker, err := root.CreateBroker(ctx, input("role-owned"))
	must(err)
	id := aws.ToString(broker.BrokerId)
	remove := func(c *mq.Client, id string) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := c.DeleteBroker(ctx, &mq.DeleteBrokerInput{BrokerId: &id})
		must(err)
		wait(ctx, func() (bool, error) {
			_, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
			if err == nil {
				return false, nil
			}
			code(err, "NotFoundException")
			return true, nil
		})
	}
	defer func() {
		if id != "" {
			remove(root, id)
		}
	}()
	running(ctx, root, id)
	role, err := admin.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	must(err)
	if aws.ToString(role.Role.Path) != "/aws-service-role/mq.amazonaws.com/" {
		panic("wrong protected role path")
	}
	policies, err := admin.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	must(err)
	if len(policies.AttachedPolicies) != 1 || aws.ToString(policies.AttachedPolicies[0].PolicyArn) != "arn:aws:iam::aws:policy/aws-service-role/AmazonMQServiceRolePolicy" {
		panic("wrong MQ role policy")
	}
	_, err = admin.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(roleName)})
	code(err, "UnmodifiableEntity")
	deletion := func(want iamtypes.DeletionTaskStatusType, arn string) {
		out, err := admin.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String(roleName)})
		must(err)
		wait(ctx, func() (bool, error) {
			status, err := admin.GetServiceLinkedRoleDeletionStatus(ctx, &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: out.DeletionTaskId})
			if err != nil {
				return false, err
			}
			if status.Status == iamtypes.DeletionTaskStatusTypeInProgress || status.Status == iamtypes.DeletionTaskStatusTypeNotStarted {
				return false, nil
			}
			if status.Status != want {
				return false, fmt.Errorf("role deletion %s wanted %s: %+v", status.Status, want, status.Reason)
			}
			if arn != "" {
				found := false
				if status.Reason != nil {
					for _, usage := range status.Reason.RoleUsageList {
						for _, resource := range usage.Resources {
							found = found || resource == arn
						}
					}
				}
				if !found {
					panic("missing live broker role dependency")
				}
			}
			return true, nil
		})
	}
	deletion(iamtypes.DeletionTaskStatusTypeFailed, aws.ToString(broker.BrokerArn))
	cloud.stop()
	cloud.start(ctx)
	reopened, err := admin.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	must(err)
	if aws.ToString(reopened.Role.RoleId) != aws.ToString(role.Role.RoleId) {
		panic("role identity changed across restart")
	}
	running(ctx, root, id)
	deletion(iamtypes.DeletionTaskStatusTypeFailed, aws.ToString(broker.BrokerArn))
	reuse, err := limited.CreateBroker(ctx, input("role-reused"))
	must(err)
	reuseID := aws.ToString(reuse.BrokerId)
	defer func() {
		if reuseID != "" {
			remove(root, reuseID)
		}
	}()
	running(ctx, root, reuseID)
	remove(root, id)
	id = ""
	deletion(iamtypes.DeletionTaskStatusTypeFailed, aws.ToString(reuse.BrokerArn))
	remove(root, reuseID)
	reuseID = ""
	deletion(iamtypes.DeletionTaskStatusTypeSucceeded, "")
	_, err = admin.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	code(err, "NoSuchEntity")
	fmt.Println("RabbitMQ signed SDK denied provisioning/no orphan + protected role + native broker reuse + SQLite restart + deletion dependency/cleanup: PASS", time.Now().UTC().Format(time.RFC3339))
}
