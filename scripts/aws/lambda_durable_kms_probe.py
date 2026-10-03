#!/usr/bin/env python3
"""Pin the KMS authorization-only dry run used by durable Lambda key validation."""
import argparse
import datetime
import json
from pathlib import Path
import sys
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument('--sdk-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('.stackd/probes/lambda/durable_kms_validation.json'))
    args = parser.parse_args()
    sys.path.insert(0, str(args.sdk_directory.resolve()))
    import boto3
    from botocore.exceptions import ClientError
    identity = boto3.client('sts', region_name='us-east-1').get_caller_identity()
    if identity['Account'] != args.account:
        raise RuntimeError('Unexpected native account; no resources created')
    kms = boto3.client('kms', region_name='us-east-1')
    name = 'stackd-next-durable-kms-' + uuid.uuid4().hex[:10]
    report = {'name': name, 'account': identity['Account'], 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'observations': [], 'cleanup': []}
    key = None
    policy = {'Version': '2012-10-17', 'Statement': [{'Sid': 'OwnedProbeAdministrator', 'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::' + identity['Account'] + ':root'}, 'Action': 'kms:*', 'Resource': '*'}]}
    context = {'aws:lambda:FunctionArn': 'arn:aws:lambda:us-east-1:' + identity['Account'] + ':function:' + name}
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, default=str) + '\n')
    def observe(label, **request):
        try:
            out = kms.decrypt(**request)
            row = {'label': label, 'code': 'Success', 'plaintext': '<redacted>', 'request_id': out['ResponseMetadata']['RequestId']}
        except ClientError as error:
            row = {'label': label, 'code': error.response['Error']['Code'], 'message': error.response['Error']['Message'], 'request_id': error.response['ResponseMetadata']['RequestId']}
        report['observations'].append(row)
        save()
        print(label + ': ' + row['code'], flush=True)
    try:
        key = kms.create_key(Description=name, Policy=json.dumps(policy), Tags=[{'TagKey': 'stackd-owned-probe', 'TagValue': name}])['KeyMetadata']['Arn']
        report['key_arn'] = key
        save()
        request = {'KeyId': key, 'EncryptionContext': context, 'EncryptionAlgorithm': 'SYMMETRIC_DEFAULT', 'DryRun': True, 'DryRunModifiers': ['IGNORE_CIPHERTEXT']}
        observe('ignore_without_ciphertext', **request)
        observe('ignore_invalid_ciphertext', **dict(request, CiphertextBlob=b'invalid'))
        missing = dict(request)
        del missing['KeyId']
        observe('ignore_missing_key', **missing)
        observe('real_invalid_with_modifier', **dict(request, DryRun=False, CiphertextBlob=b'invalid'))
        observe('regular_dryrun_invalid', KeyId=key, CiphertextBlob=b'invalid', DryRun=True)
        cipher = kms.encrypt(KeyId=key, Plaintext=b'owned durable key validation', EncryptionContext=context)['CiphertextBlob']
        observe('real_valid_with_modifier', **dict(request, DryRun=False, CiphertextBlob=cipher))
        observe('ignore_algorithm_mismatch', **dict(request, EncryptionAlgorithm='RSAES_OAEP_SHA_256'))
        denied = dict(policy, Statement=policy['Statement'] + [{'Sid': 'OwnedDecryptDeny', 'Effect': 'Deny', 'Principal': '*', 'Action': 'kms:Decrypt', 'Resource': '*', 'Condition': {'StringEquals': {'kms:EncryptionContext:aws:lambda:FunctionArn': context['aws:lambda:FunctionArn']}}}])
        kms.put_key_policy(KeyId=key, PolicyName='default', Policy=json.dumps(denied))
        observe('ignore_explicit_deny', **request)
        kms.put_key_policy(KeyId=key, PolicyName='default', Policy=json.dumps(policy))
        kms.disable_key(KeyId=key)
        report['cleanup'].append('disable_key')
        observe('ignore_disabled_key', **request)
        observe('real_disabled_key', KeyId=key, CiphertextBlob=cipher, EncryptionContext=context)
    finally:
        if key is not None:
            kms.put_key_policy(KeyId=key, PolicyName='default', Policy=json.dumps(policy))
            kms.disable_key(KeyId=key)
            deletion = kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
            report['cleanup'].append({'operation': 'schedule_key_deletion', 'key_arn': key, 'key_state': deletion['KeyState'], 'deletion_date': deletion['DeletionDate'], 'pending_window_days': deletion['PendingWindowInDays']})
            report['retained_by_aws'] = 'KMS requires a minimum seven-day deletion window; the owned key is disabled and PendingDeletion.'
        save()


if __name__ == '__main__':
    main()
