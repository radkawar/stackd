package integrations

import "stackd/internal/services/iam"

// KafkaRoleTemplate retains the MSK-owned trust and captured managed policy.
// The service usage adapter must fence role deletion against live clusters.
func KafkaRoleTemplate() iam.ServiceLinkedRoleTemplate {
	return iam.ServiceLinkedRoleTemplate{
		Partition: "aws", ServiceName: "kafka.amazonaws.com", RoleName: "AWSServiceRoleForKafka",
		TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"kafka.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/KafkaServiceRolePolicy"},
		UsageFailureReason: "The role is in use by Amazon MSK clusters.",
		Sources: []string{
			"https://docs.aws.amazon.com/msk/latest/developerguide/slr-permissions.html",
			"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/KafkaServiceRolePolicy.html",
		},
	}
}
