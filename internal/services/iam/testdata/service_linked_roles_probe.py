# Reproduce service-linked IAM role semantics using a uniquely owned Auto Scaling
# role. All created roles are deleted and polled to completion in finally.
# Usage: python3 internal/services/iam/testdata/service_linked_roles_probe.py
# The AWS CLI must already have credentials. No compute resources are created.
import datetime
import json
import re
import subprocess
import time
import uuid

suffix = 'stackdprobe' + uuid.uuid4().hex[:10]
name = 'AWSServiceRoleForAutoScaling_' + suffix
observations = []
created = False
deletion_task = None

def call(operation, *args):
    result = subprocess.run(['aws', 'iam', operation, *args, '--output', 'json', '--no-cli-pager'], text=True, capture_output=True)
    if result.returncode:
        match = re.search(r'An error occurred \(([^)]+)\)', result.stderr)
        return {'error': match.group(1) if match else 'CLIError', 'detail': result.stderr.strip()}
    return json.loads(result.stdout or '{}')

def record(label, result):
    observations.append({'name': label, **result})

try:
    output = call('create-service-linked-role', '--aws-service-name', 'autoscaling.amazonaws.com', '--custom-suffix', suffix)
    if 'error' in output:
        raise RuntimeError(output)
    created = True
    record('create', output)
    record('duplicate-create', call('create-service-linked-role', '--aws-service-name', 'autoscaling.amazonaws.com', '--custom-suffix', suffix))
    record('get', call('get-role', '--role-name', name))
    record('attached-policies', call('list-attached-role-policies', '--role-name', name))
    record('inline-policies', call('list-role-policies', '--role-name', name))
    record('update-description', call('update-role-description', '--role-name', name, '--description', 'Owned stackd probe updated description'))
    record('update-duration', call('update-role', '--role-name', name, '--max-session-duration', '7200'))
    record('tag-role', call('tag-role', '--role-name', name, '--tags', 'Key=purpose,Value=stackd-probe'))
    record('update-trust', call('update-assume-role-policy', '--role-name', name, '--policy-document', '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"autoscaling.amazonaws.com"},"Action":"sts:AssumeRole"}}'))
    record('put-inline-policy', call('put-role-policy', '--role-name', name, '--policy-name', 'stackd-probe', '--policy-document', '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}}'))
    record('attach-policy', call('attach-role-policy', '--role-name', name, '--policy-arn', 'arn:aws:iam::aws:policy/ReadOnlyAccess'))
    record('detach-policy', call('detach-role-policy', '--role-name', name, '--policy-arn', 'arn:aws:iam::aws:policy/aws-service-role/AutoScalingServiceRolePolicy'))
    record('delete-inline', call('delete-role-policy', '--role-name', name, '--policy-name', 'absent'))
    record('put-boundary', call('put-role-permissions-boundary', '--role-name', name, '--permissions-boundary', 'arn:aws:iam::aws:policy/ReadOnlyAccess'))
    record('delete-boundary', call('delete-role-permissions-boundary', '--role-name', name))
    record('update-role-description', call('update-role', '--role-name', name, '--description', 'Updated using UpdateRole'))
    record('delete-role-directly', call('delete-role', '--role-name', name))
    output = call('delete-service-linked-role', '--role-name', name)
    record('delete-service-linked-role', output)
    if 'DeletionTaskId' in output:
        deletion_task = output['DeletionTaskId']
        record('repeat-delete', call('delete-service-linked-role', '--role-name', name))
        record('first-status', call('get-service-linked-role-deletion-status', '--deletion-task-id', deletion_task))
finally:
    if created:
        if not deletion_task:
            output = call('delete-service-linked-role', '--role-name', name)
            deletion_task = output.get('DeletionTaskId')
            if not deletion_task:
                raise RuntimeError({'cleanup_delete_failed': output, 'role_name': name})
        for attempt in range(60):
            output = call('get-service-linked-role-deletion-status', '--deletion-task-id', deletion_task)
            if output.get('Status') == 'SUCCEEDED':
                record('completed-status', output)
                break
            if output.get('Status') == 'FAILED':
                raise RuntimeError({'cleanup_failed': output, 'role_name': name, 'task': deletion_task})
            time.sleep(2)
        else:
            raise RuntimeError({'cleanup_not_finished': output, 'role_name': name, 'task': deletion_task})

record('get-deleted-role', call('get-role', '--role-name', name))
record('unknown-task', call('get-service-linked-role-deletion-status', '--deletion-task-id', 'task/aws-service-role/autoscaling.amazonaws.com/'+name+'/00000000-0000-0000-0000-000000000000'))
record('malformed-task', call('get-service-linked-role-deletion-status', '--deletion-task-id', 'not-a-task'))
for service in ['ecs.amazonaws.com', 'elasticloadbalancing.amazonaws.com', 'rds.amazonaws.com']:
    result = call('create-service-linked-role', '--aws-service-name', service, '--custom-suffix', suffix)
    if 'Role' in result:
        # A future service might add suffix support. Clean up our uniquely
        # suffixed role before reporting that the captured contract changed.
        unexpected_name = result['Role']['RoleName']
        task = call('delete-service-linked-role', '--role-name', unexpected_name)
        if 'DeletionTaskId' not in task:
            raise RuntimeError({'cleanup_delete_failed': task, 'role_name': unexpected_name})
        for attempt in range(120):
            status = call('get-service-linked-role-deletion-status', '--deletion-task-id', task['DeletionTaskId'])
            if status.get('Status') == 'SUCCEEDED':
                break
            if status.get('Status') == 'FAILED':
                raise RuntimeError({'cleanup_failed': status, 'role_name': unexpected_name})
            time.sleep(2)
        else:
            raise RuntimeError({'cleanup_not_finished': status, 'role_name': unexpected_name})
    record('suffix-' + service, result)
fixture = {'recorded_at' : datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source':'Real AWS IAM temporary owned Auto Scaling service-linked role; role deletion completed successfully.', 'observations': observations}
encoded = json.dumps(fixture, indent=2).replace(suffix, 'stackdprobe')
encoded = re.sub(r'arn:aws:iam::\d{12}:', 'arn:aws:iam::123456789012:', encoded)
from pathlib import Path
with Path(__file__).with_name('service_linked_roles_aws.json').open('w') as f:
    f.write(encoded+'\n')
print(encoded)
