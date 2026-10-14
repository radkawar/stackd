#!/usr/bin/env bash
# Run against a source-built local controller with the real RDS Docker runtime.
# See docs/secretsmanager.md for installed-image and host requirements.
set -euo pipefail
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
unset AWS_PROFILE AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
endpoint="${STACKD_ENDPOINT:-http://127.0.0.1:4566}"
if [[ ! "$endpoint" =~ ^http://127\.0\.0\.1:[0-9]+$ ]]; then
  printf '%s\n' 'Use an explicit IPv4 loopback HTTP endpoint.' >&2
  exit 1
fi
prefix="cfn-secure-$(date +%s)-${RANDOM}"
work="$(mktemp -d)"
chmod 700 "$work"
stack_id=""
secret_id=""
key_id=""
parameter_name="/$prefix/password"
aws_local() { aws --endpoint-url "$endpoint" "$@"; }
cleanup() {
  set +e
  if [[ -n "$stack_id" ]]; then
    aws_local cloudformation delete-stack --stack-name "$stack_id"
    aws_local cloudformation wait stack-delete-complete --stack-name "$stack_id"
  fi
  aws_local ssm delete-parameter --name "$parameter_name"
  if [[ -n "$secret_id" ]]; then aws_local secretsmanager delete-secret --secret-id "$secret_id" --force-delete-without-recovery; fi
  if [[ -n "$key_id" ]]; then aws_local kms schedule-key-deletion --key-id "$key_id" --pending-window-in-days 7; fi
  rm -rf "$work"
}
trap cleanup EXIT
aws_local sts get-caller-identity
key_id="$(aws_local kms create-key --query KeyMetadata.KeyId --output text)"
printf '%s' 'NativeSSM-Password!72' > "$work/ssm-password"
printf '%s' 'NativeSecret-Password!83' > "$work/secret-password"
printf '%s' '{"password":"NativeSecret-Password!83"}' > "$work/secret.json"
chmod 600 "$work/ssm-password" "$work/secret-password" "$work/secret.json"
parameter_version="$(aws_local ssm put-parameter --name "$parameter_name" --type SecureString --key-id "$key_id" --value "file://$work/ssm-password" --query Version --output text)"
secret_id="$(aws_local secretsmanager create-secret --name "$prefix" --kms-key-id "$key_id" --secret-string "file://$work/secret.json" --query ARN --output text)"
write_template() {
  local reference="$1" copy_tags="$2"
  cat > "$work/template.json" <<EOF
{"Resources":{"Database":{"Type":"AWS::RDS::DBInstance","DeletionPolicy":"Delete","UpdateReplacePolicy":"Delete","Properties":{"DBInstanceIdentifier":"$prefix","DBInstanceClass":"db.t3.small","Engine":"postgres","AllocatedStorage":20,"DBName":"appdb","MasterUsername":"dbuser","MasterUserPassword":"$reference","CopyTagsToSnapshot":$copy_tags}}}}
EOF
}
write_template "{{resolve:ssm-secure:$parameter_name:$parameter_version}}" false
stack_id="$(aws_local cloudformation create-stack --stack-name "$prefix" --template-body "file://$work/template.json" --query StackId --output text)"
aws_local cloudformation wait stack-create-complete --stack-name "$stack_id"
read -r host port < <(aws_local rds describe-db-instances --db-instance-identifier "$prefix" --query 'DBInstances[0].Endpoint.[Address,Port]' --output text)
PGPASSWORD="$(cat "$work/ssm-password")" psql -h "$host" -p "$port" -U dbuser -d appdb -v ON_ERROR_STOP=1 -c 'create table secure_reference_probe (value integer); insert into secure_reference_probe values (42); select current_user, value from secure_reference_probe;'
# Moving the source does not change an explicit numeric reference, even during
# a resource update. The native PostgreSQL password must remain version one.
printf '%s' 'RotatedSSM-Password!94' > "$work/rotated-password"
chmod 600 "$work/rotated-password"
aws_local ssm put-parameter --name "$parameter_name" --type SecureString --key-id "$key_id" --value "file://$work/rotated-password" --overwrite
write_template "{{resolve:ssm-secure:$parameter_name:$parameter_version}}" true
aws_local cloudformation update-stack --stack-name "$stack_id" --template-body "file://$work/template.json"
aws_local cloudformation wait stack-update-complete --stack-name "$stack_id"
PGPASSWORD="$(cat "$work/ssm-password")" psql -h "$host" -p "$port" -U dbuser -d appdb -v ON_ERROR_STOP=1 -c 'select value from secure_reference_probe;'
# Switch the real database password to the JSON-key value from Secrets Manager.
write_template "{{resolve:secretsmanager:$secret_id:SecretString:password}}" false
aws_local cloudformation update-stack --stack-name "$stack_id" --template-body "file://$work/template.json"
aws_local cloudformation wait stack-update-complete --stack-name "$stack_id"
PGPASSWORD="$(cat "$work/secret-password")" psql -h "$host" -p "$port" -U dbuser -d appdb -v ON_ERROR_STOP=1 -c 'select current_user, value from secure_reference_probe;'
aws_local cloudformation get-template --stack-name "$stack_id" > "$work/retained-template.json"
aws_local cloudformation describe-stack-events --stack-name "$stack_id" > "$work/events.json"
# These grep checks are part of the operator smoke, not expected-output fixtures.
for secret in 'NativeSSM-Password!72' 'NativeSecret-Password!83' 'RotatedSSM-Password!94'; do
  if grep -F "$secret" "$work/retained-template.json" "$work/events.json"; then
    printf '%s\n' 'Resolved plaintext leaked into CloudFormation SDK output.' >&2
    exit 1
  fi
done
printf '%s\n' 'Native PostgreSQL consumed both secure sources; CloudFormation API history retained references only.'
