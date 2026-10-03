// Code generated from the AWS Organizations backup-policy syntax; DO NOT EDIT.
// Source: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_backup_syntax.md
package organizations

var backupResourceTypes = map[string]bool{
	"arn:aws:backup-gateway:*:*:vm/*":             true,
	"arn:aws:cloudformation:*:*:stack/*":          true,
	"arn:aws:dsql:*:*:cluster/*":                  true,
	"arn:aws:dynamodb:*:*:table/*":                true,
	"arn:aws:ec2:*:*:instance/*":                  true,
	"arn:aws:ec2:*:*:volume/*":                    true,
	"arn:aws:eks:*:*:cluster/*":                   true,
	"arn:aws:elasticfilesystem:*:*:file-system/*": true,
	"arn:aws:fsx:*:*:file-system/*":               true,
	"arn:aws:fsx:*:*:volume/*":                    true,
	"arn:aws:rds:*:*:cluster:*":                   true,
	"arn:aws:rds:*:*:db:*":                        true,
	"arn:aws:redshift-serverless:*:*:namespace/*": true,
	"arn:aws:redshift:*:*:cluster:*":              true,
	"arn:aws:s3:::*":                              true,
	"arn:aws:ssm-sap:*:*:HANA/*":                  true,
	"arn:aws:storagegateway:*:*:gateway/*":        true,
	"arn:aws:timestream:*:*:database/*":           true,
}
