"""Independent consumers for owned, current-provider S3 bucket controls."""
import base64
import csv
from datetime import datetime, timedelta
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.parse import unquote_plus
from urllib.request import ProxyHandler, Request, build_opener
import uuid

import boto3
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.config import Config
from botocore.exceptions import ClientError

from local import client, expect_missing, local_endpoint, require

HTTP = build_opener(ProxyHandler({}))


class StrictPlanFailure(RuntimeError):
    def __init__(self, checks):
        self.checks = checks
        super().__init__('Strict S3 no-change plan returned2 despite a saved no-diff plan; failure retained')


def private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        os.chmod(path, 0o600)
        stream.write(content if isinstance(content, bytes) else content.encode())


def clock(endpoint, advance=None):
    request = Request(local_endpoint(endpoint) + '/_stackd/clock',
                      data=None if advance is None else json.dumps({'advance': advance}).encode(),
                      headers={'Content-Type': 'application/json'})
    with HTTP.open(request, timeout=30) as response:
        result = json.load(response)
    if advance is not None:
        with HTTP.open(Request(endpoint + '/_stackd/jobs/drain?limit=4096', data=b''), timeout=60) as response:
            json.load(response)
    return datetime.fromisoformat(result['time'].replace('Z', '+00:00'))


def accelerated_get(endpoint, bucket, region):
    request = AWSRequest(method='GET', url=local_endpoint(endpoint) + '/terraform.txt',
                         headers={'Host': bucket + '.s3-accelerate.amazonaws.com'})
    S3SigV4Auth(Credentials('test', 'test'), 's3', region).add_auth(request)
    return HTTP.open(Request(request.url, headers=dict(request.headers)), timeout=30)


def await_value(read, predicate, message, missing=()):
    deadline = time.monotonic() + 90
    while True:
        try:
            value = read()
        except ClientError as error:
            if error.response['Error']['Code'] not in missing:
                raise
        else:
            if predicate(value):
                return value
        require(time.monotonic() < deadline, message)
        time.sleep(0.25)


def denied(call, codes={'AccessDenied', 'AccessDeniedException', '403'}, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response['Error']['Code'] in codes, str(error))
    else:
        raise RuntimeError('Current authority or key state did not deny the real operation')


def object_bytes(s3, bucket, key, **kwargs):
    response = s3.get_object(Bucket=bucket, Key=key, **kwargs)
    with response['Body'] as body:
        return body.read(), response


def proxied_client(service, endpoint, region):
    # Retain SDK-generated access-point/account-prefixed Host and signing scope.
    # Only the existing owned listener receives traffic; no DNS/hosts workaround.
    return boto3.client(service, endpoint_url=local_endpoint(endpoint), region_name=region,
                        aws_access_key_id='test', aws_secret_access_key='test',
                        config=Config(signature_version='s3v4' if service == 's3' else 'v4',
                                      proxies={'http': endpoint}, connect_timeout=3, read_timeout=60,
                                      retries={'max_attempts': 0}, s3={'addressing_style': 'path'}))


def require_sdk_models(endpoint):
    # Inspect local SDK models only: no API request, Terraform mutation or skip.
    required = {
        's3': (
            'AbortMultipartUpload', 'CopyObject', 'CreateMultipartUpload', 'DeleteBucketPolicy', 'DeleteObject',
            'GetBucketAbac', 'GetBucketAccelerateConfiguration', 'GetBucketAcl', 'GetBucketAnalyticsConfiguration',
            'GetBucketCors', 'GetBucketOwnershipControls', 'GetBucketPolicy', 'GetBucketRequestPayment',
            'GetBucketTagging', 'GetBucketVersioning', 'GetObject', 'GetObjectRetention', 'GetObjectTagging',
            'GetPublicAccessBlock', 'HeadBucket', 'HeadObject', 'ListMultipartUploads', 'ListObjectsV2',
            'ListObjectVersions', 'PutBucketAcl', 'PutBucketPolicy', 'PutBucketTagging', 'PutObject',
            'PutObjectLegalHold'),
        's3control': ('GetAccessPoint', 'GetAccessPointPolicy', 'GetPublicAccessBlock', 'PutAccessPointPolicy', 'TagResource'),
        'kms': ('DescribeKey', 'DisableKey', 'EnableKey'),
        'iam': ('CreateAccessKey', 'DeleteAccessKey', 'DeleteUserPolicy', 'GetRole', 'GetRolePolicy', 'GetUser',
                'PutRolePolicy', 'PutUserPolicy'),
        'sqs': ('DeleteMessage', 'GetQueueUrl', 'ReceiveMessage'),
        'cloudwatch': ('GetMetricStatistics',),
    }
    missing = []
    for service, operations in required.items():
        modeled = set(client(service, endpoint).meta.service_model.operation_names)
        missing.extend(service + '/' + operation for operation in operations if operation not in modeled)
    require(not missing, 'Missing Python SDK model prerequisites before resource mutation: ' + ', '.join(missing)
            + '. Use boto3/botocore >=1.41.1 with the versioned S3 model containing GetBucketAbac: '
            + 'https://raw.githubusercontent.com/boto/botocore/1.41.1/botocore/data/s3/2006-03-01/service-2.json')


def run(args, root: Path, endpoint: str, terraform, variables: dict, stages: list):
    initial_endpoint = local_endpoint(endpoint)
    require_sdk_models(initial_endpoint)
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    private_write(root / 's3.tf', Path(__file__).with_suffix('.tf').read_bytes())
    variables = {key: variables[key] for key in ('name', 'endpoint', 'region', 'account_id')}
    variables['revision'] = 'initial'
    revision = 'initial'
    outputs = {}
    destroyed = False
    strict_plan_failures = []
    verification_count = 0
    varfile = root / 'local.auto.tfvars.json'
    private_write(varfile, json.dumps(variables))
    owned_buckets = [variables['name'] + '-s3-' + suffix for suffix in
                     ('data', 'site', 'reports', 'replica', 'lifecycle', 'tiering', 'payment', 'lock')]

    def tf(*command, check=True):
        try:
            return terraform(list(command), root, check=check)
        finally:
            for path in root.iterdir():
                if path.is_file() and (path.name.startswith('terraform.tfstate') or path.suffix == '.tfplan'):
                    path.chmod(0o600)

    def stage(name, **details):
        stages.append({'stage': 's3-' + name, 'status': 'passed', **details})

    def read_outputs():
        outputs.update(json.loads(tf('output', '-json', 's3').stdout))

    def no_changes(label):
        failures = []
        checks = []
        for flags, filename in ((['-refresh-only'], label + '-refresh.tfplan'),
                                ([], label + '-noop.tfplan')):
            command = ['plan', *flags, '-input=false', '-detailed-exitcode', '-out=' + filename]
            result = tf(*command, check=False)
            require(result.returncode in {0, 2}, f'S3 {label} plan failed ({result.returncode})')
            saved = json.loads(tf('show', '-json', filename).stdout)
            json_name = filename + '.json'
            private_write(root / json_name, json.dumps(saved, sort_keys=True, indent=2))
            check = {'command': command, 'returncode': result.returncode,
                     'plan': filename, 'json': json_name}
            checks.append(check)
            if result.returncode == 2:
                require('No changes.' in result.stdout and 'found no differences.' in result.stdout
                        and all(entry['change']['actions'] == ['no-op']
                                for group in ('resource_changes', 'resource_drift')
                                for entry in saved.get(group, []))
                        and all(entry['actions'] == ['no-op']
                                for entry in saved.get('output_changes', {}).values()),
                        f'S3 {label} plan contains a real resource or output difference')
                failures.append(check)
            if flags:
                tf('apply', '-input=false', '-auto-approve', filename)
        private_write(root / (label + '-strict-checks.json'), json.dumps(checks, sort_keys=True, indent=2))
        if failures:
            stages.append({'stage': 's3-' + label + '-refresh-no-change',
                           'status': 'failed', 'checks': failures})
            raise StrictPlanFailure(failures)
        stage(label + '-refresh-no-change')

    def retain_no_changes(label):
        try:
            no_changes(label)
        except StrictPlanFailure as error:
            strict_plan_failures.extend(error.checks)

    def observe_readback(label):
        plan_name = 'observe-' + label + '.tfplan'
        tf('plan', '-refresh-only', '-input=false', '-out=' + plan_name)
        saved = json.loads(tf('show', '-json', plan_name).stdout)
        private_write(root / (plan_name + '.json'), json.dumps(saved, sort_keys=True, indent=2))
        require(all(entry.get('mode') != 'managed' or entry['change']['actions'] == ['no-op']
                    for entry in saved.get('resource_changes', []))
                and not saved.get('deferred_changes'),
                'S3 readback observation contains a managed configuration action')
        expected = {
            'aws_iam_role.replication': {'inline_policy', 'tags'},
            'aws_iam_user.consumer': {'tags'},
            'aws_s3_access_point.data': {'policy', 'tags'},
            'aws_s3_bucket.locked': {'object_lock_configuration'},
            'aws_s3_bucket.owned["data"]': {'acceleration_status', 'cors_rule', 'logging',
                                          'replication_configuration', 'server_side_encryption_configuration', 'versioning'},
            'aws_s3_bucket.owned["lifecycle"]': {'lifecycle_rule', 'versioning'},
            'aws_s3_bucket.owned["payment"]': {'request_payer'},
            'aws_s3_bucket.owned["replica"]': {'versioning'},
            'aws_s3_bucket.owned["reports"]': {'policy'},
            'aws_s3_bucket.owned["site"]': {'policy', 'website', 'website_domain', 'website_endpoint'},
            'aws_s3_bucket_analytics_configuration.data': {'filter'},
            'aws_s3_bucket_intelligent_tiering_configuration.owned': {'filter'},
            'aws_s3_bucket_metric.data': {'filter'},
            'aws_s3_object.data': {'metadata', 'tags'},
            'aws_s3_object.site["error.html"]': {'metadata', 'tags'},
            'aws_s3_object.site["index.html"]': {'metadata', 'tags'},
            'aws_s3_object_copy.data': {'tags'},
            'aws_sqs_queue.events': {'policy'},
        }
        observed = []
        for entry in saved.get('resource_drift', []):
            before, after = entry['change'].get('before') or {}, entry['change'].get('after') or {}
            fields = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
            require(set(fields) <= expected.get(entry['address'], set()),
                    'S3 readback observation contains unrelated drift: ' + entry['address'] + ' ' + str(fields))
            observed.append({'address': entry['address'], 'fields': fields})
        private_write(root / ('observe-' + label + '-fields.json'), json.dumps(observed, sort_keys=True, indent=2))
        tf('apply', '-input=false', '-auto-approve', plan_name)
        read_outputs()
        stage('state-readback-observation-' + label, fields=observed)

    def purge_key(s3, bucket, key, locked=False):
        # Enumerate exact versions of our exact key, including delete markers.
        for page in s3.get_paginator('list_object_versions').paginate(Bucket=bucket, Prefix=key):
            for version in page.get('Versions', []) + page.get('DeleteMarkers', []):
                if version['Key'] != key:
                    continue
                if locked and 'Size' in version:
                    s3.put_object_legal_hold(Bucket=bucket, Key=key, VersionId=version['VersionId'],
                                             LegalHold={'Status': 'OFF'})
                s3.delete_object(Bucket=bucket, Key=key, VersionId=version['VersionId'],
                                 **({'BypassGovernanceRetention': True} if locked else {}))

    def verify(endpoint=None):
        nonlocal verification_count
        verification_count += 1
        phase = ('initial', 'updated', 'reopen')[verification_count - 1]
        payload_evidence = {}
        current = local_endpoint(endpoint or initial_endpoint)
        s3, kms, iam, sqs = (client(service, current) for service in ('s3', 'kms', 'iam', 'sqs'))
        control = proxied_client('s3control', current, variables['region'])
        buckets = outputs['buckets']
        bucket = buckets['data']
        payload = ('kms-storage-' + revision).encode()
        require(outputs['lookup_arn'] == f'arn:aws:s3:::{bucket}', 'Bucket lookup ARN differs')
        require(base64.b64decode(outputs['lookup_body_base64']) == payload, 'Terraform KMS object data bytes differ')
        require(set(outputs['lookup_keys']) == {'terraform.txt', 'copied.txt'}, 'Object listing data source differs')
        require(set(owned_buckets) <= {item['name'] for item in outputs['lookup_buckets']}, 'Bucket listing omitted owned bucket')
        notification_lookup = outputs['lookup_notifications']
        require(len(notification_lookup) == 1 and notification_lookup[0]['queue_arn'] == outputs['queue_arn']
                and notification_lookup[0]['id'] == 'objects-' + revision
                and notification_lookup[0]['filter_prefix'] == 'events/', 'Notification data source differs')
        lock_lookup = outputs['lookup_lock'][0]['default_retention'][0]
        require(lock_lookup['mode'] == 'GOVERNANCE' and lock_lookup['days'] == (1 if revision == 'initial' else 2),
                'Object lock data source differs')
        replication_lookup = outputs['lookup_replication'][0]
        require(replication_lookup['id'] == 'transfer-' + revision
                and replication_lookup['destination'][0]['bucket'] == f'arn:aws:s3:::{buckets["replica"]}',
                'Replication data source differs')
        require(any(point['name'] == outputs['access_point'] and point['bucket'] == bucket
                    for point in outputs['lookup_access_points']), 'Access point listing data source differs')
        require(not any(outputs['lookup_account_block'].values()), 'Account public block data source differs')
        for key in ('terraform.txt', 'copied.txt'):
            body, response = object_bytes(s3, bucket, key)
            require(body == payload and response['ServerSideEncryption'] == 'aws:kms'
                    and response['SSEKMSKeyId'] == outputs['key_arn'], 'Real KMS object/copy bytes or key differ')
            payload_evidence[key] = {'length': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
                                     'kms_key_arn': response['SSEKMSKeyId']}
        require(s3.get_bucket_versioning(Bucket=bucket)['Status'] == 'Enabled', 'Versioning differs')
        require(s3.get_bucket_ownership_controls(Bucket=bucket)['OwnershipControls']['Rules'][0]['ObjectOwnership']
                == 'BucketOwnerPreferred', 'Ownership controls differ')
        acl = s3.get_bucket_acl(Bucket=bucket)
        require(acl['Owner']['ID'] == outputs['canonical_id'] and len(acl['Grants']) == 1
                and acl['Grants'][0]['Permission'] == 'FULL_CONTROL', 'Private ACL/canonical identity differs')
        denied(s3.put_bucket_acl, Bucket=bucket, ACL='public-read')
        require(all(s3.get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration'].values()), 'Data public block differs')
        require(s3.get_bucket_cors(Bucket=bucket)['CORSRules'][0]['AllowedOrigins']
                == [f'https://{revision}.example.invalid'], 'CORS update differs')
        require(s3.get_bucket_abac(Bucket=bucket)['AbacStatus']['Status'] == 'Enabled', 'ABAC config differs')
        analytics = s3.get_bucket_analytics_configuration(Bucket=bucket, Id='selection')['AnalyticsConfiguration']
        require(analytics['Id'] == 'selection' and analytics['Filter']['Prefix'] == f'analytics/{revision}/',
                'Analytics selection configuration differs; no report producer claimed')
        expected_acceleration = 'Enabled' if revision == 'initial' else 'Suspended'
        require(s3.get_bucket_accelerate_configuration(Bucket=bucket)['Status'] == expected_acceleration, 'Acceleration update differs')
        try:
            response = accelerated_get(current, bucket, variables['region'])
        except HTTPError as error:
            with error:
                require(expected_acceleration == 'Suspended' and error.code == 400
                        and b'<Code>InvalidRequest</Code>' in error.read(), 'Accelerated endpoint rejection differs')
        else:
            with response:
                require(expected_acceleration == 'Enabled' and response.read() == payload,
                        'Accelerated endpoint did not enforce current status or decrypt bytes')
        require(s3.get_bucket_request_payment(Bucket=buckets['payment'])['Payer'] == 'Requester', 'Request payment differs')
        payment_key = 'owner-' + uuid.uuid4().hex
        try:
            s3.put_object(Bucket=buckets['payment'], Key=payment_key, Body=b'owner-payment-bytes')
            require(object_bytes(s3, buckets['payment'], payment_key)[0] == b'owner-payment-bytes', 'Requester-pays owner byte consumer failed')
        finally:
            s3.delete_object(Bucket=buckets['payment'], Key=payment_key)
        stage('provider-object-copy-and-control-readback-' + revision)

        # Actual CORS HTTP consumer: OPTIONS is not a signed API config read.
        request = Request(current + '/' + bucket + '/terraform.txt', method='OPTIONS',
                          headers={'Origin': f'https://{revision}.example.invalid', 'Access-Control-Request-Method': 'GET'})
        with HTTP.open(request, timeout=30) as response:
            require(response.status == 200 and response.headers['Access-Control-Allow-Origin']
                    == f'https://{revision}.example.invalid', 'CORS HTTP consumer did not apply current rule')
        site = buckets['site']
        require(json.loads(outputs['lookup_policy'])['Statement'][0]['Sid'] == 'Website' + revision, 'Policy data source differs')
        host = f'{site}.s3-website-{variables["region"]}.amazonaws.com'
        for path, expected, code in (('/', 'index.html-' + revision, 200),
                                     ('/not-present', 'error.html-' + revision, 404)):
            request = Request(current + path, headers={'Host': host})
            try:
                response = HTTP.open(request, timeout=30)
            except HTTPError as error:
                response = error
            with response:
                require(response.code == code and response.read() == expected.encode(), 'Website HTTP bytes/status differ')
        # Removing current bucket authority must affect the anonymous consumer.
        policy = s3.get_bucket_policy(Bucket=site)['Policy']
        try:
            s3.delete_bucket_policy(Bucket=site)
            try:
                HTTP.open(Request(current + '/', headers={'Host': host}), timeout=30)
            except HTTPError as error:
                require(error.code == 403, 'Anonymous website rejection differs')
                error.close()
            else:
                raise RuntimeError('Website succeeded after its current bucket policy was removed')
        finally:
            s3.put_bucket_policy(Bucket=site, Policy=policy)
        stage('http-website-policy-and-cors-consumers-' + revision)

        # Current IAM authority is checked with real credentialed object bytes.
        credential = iam.create_access_key(UserName=outputs['user'])['AccessKey']
        limited = boto3.client('s3', endpoint_url=current, region_name=variables['region'],
                               aws_access_key_id=credential['AccessKeyId'], aws_secret_access_key=credential['SecretAccessKey'],
                               config=Config(signature_version='s3v4', proxies={}, retries={'max_attempts': 0},
                                             s3={'addressing_style': 'path'}))
        temporary_policy = 'kms-consumer-' + uuid.uuid4().hex
        try:
            limited.list_objects_v2(Bucket=bucket)
            tags = s3.get_bucket_tagging(Bucket=bucket)['TagSet']
            try:
                control.tag_resource(AccountId=variables['account_id'], ResourceArn=f'arn:aws:s3:::{bucket}',
                                     Tags=[dict(tag, Value='denied') if tag['Key'] == 'Revision' else tag for tag in tags])
                denied(limited.list_objects_v2, Bucket=bucket)
            finally:
                control.tag_resource(AccountId=variables['account_id'], ResourceArn=f'arn:aws:s3:::{bucket}', Tags=tags)
            denied(limited.get_object, Bucket=bucket, Key='terraform.txt')
            denied(limited.put_object, Bucket=bucket, Key='kms-denied', Body=b'not-admitted')
            expect_missing(s3.head_object, {'404', 'NoSuchKey', 'NotFound'}, Bucket=bucket, Key='kms-denied')
            iam.put_user_policy(UserName=outputs['user'], PolicyName=temporary_policy, PolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                'Action': ['kms:Decrypt', 'kms:GenerateDataKey'], 'Resource': outputs['key_arn']}]}))
            require(object_bytes(limited, bucket, 'terraform.txt')[0] == payload, 'KMS-authorized user did not read bytes')
            binary_key = 'kms-binary-' + uuid.uuid4().hex
            copy_key = binary_key + '-copy'
            try:
                binary = b'KMS object and copy bytes\x00\xff\n'
                source_version = limited.put_object(Bucket=bucket, Key=binary_key, Body=binary)['VersionId']
                s3.copy_object(Bucket=bucket, Key=copy_key,
                    CopySource={'Bucket': bucket, 'Key': binary_key, 'VersionId': source_version},
                    ServerSideEncryption='aws:kms', SSEKMSKeyId=outputs['key_arn'])
                for key in (binary_key, copy_key):
                    body, metadata = object_bytes(limited, bucket, key)
                    require(body == binary and metadata['ServerSideEncryption'] == 'aws:kms'
                            and metadata['SSEKMSKeyId'] == outputs['key_arn'], 'KMS binary producer/copy/consumer differs')
            finally:
                purge_key(s3, bucket, binary_key)
                purge_key(s3, bucket, copy_key)
            iam.delete_user_policy(UserName=outputs['user'], PolicyName=temporary_policy)
            denied(limited.get_object, Bucket=bucket, Key='terraform.txt')
        finally:
            try:
                iam.delete_user_policy(UserName=outputs['user'], PolicyName=temporary_policy)
            except ClientError as error:
                require(error.response['Error']['Code'] == 'NoSuchEntity', str(error))
            iam.delete_access_key(UserName=outputs['user'], AccessKeyId=credential['AccessKeyId'])
        kms.disable_key(KeyId=outputs['key_id'])
        try:
            denied(s3.get_object, {'KMS.DisabledException', 'KMS.KMSInvalidStateException'}, Bucket=bucket, Key='terraform.txt')
            denied(s3.put_object, {'KMS.DisabledException', 'KMS.KMSInvalidStateException'},
                   Bucket=bucket, Key='disabled-put', Body=b'not-admitted')
            expect_missing(s3.head_object, {'404', 'NoSuchKey', 'NotFound'}, Bucket=bucket, Key='disabled-put')
            denied(s3.copy_object, {'KMS.DisabledException', 'KMS.KMSInvalidStateException'}, Bucket=bucket, Key='disabled-copy',
                   CopySource={'Bucket': bucket, 'Key': 'terraform.txt'}, ServerSideEncryption='aws:kms', SSEKMSKeyId=outputs['key_arn'])
            expect_missing(s3.head_object, {'404', 'NoSuchKey', 'NotFound'}, Bucket=bucket, Key='disabled-copy')
        finally:
            kms.enable_key(KeyId=outputs['key_id'])
        require(object_bytes(s3, bucket, 'terraform.txt')[0] == payload, 'Reenabled KMS key did not decrypt original bytes')
        stage('abac-current-kms-authority-and-disabled-key-effects-' + revision)

        require(not any(control.get_public_access_block(AccountId=variables['account_id'])['PublicAccessBlockConfiguration'].values()),
                'Owned account block conflicts with website consumer')
        require(control.get_access_point(AccountId=variables['account_id'], Name=outputs['access_point'])['Bucket'] == bucket,
                'Access point control bucket differs')
        require(outputs['lookup_access_point_arn'] == outputs['access_point_arn'], 'Access point data source ARN differs')
        point_policy = json.loads(control.get_access_point_policy(AccountId=variables['account_id'], Name=outputs['access_point'])['Policy'])
        require(point_policy['Statement'][0]['Sid'] == 'Read' + revision, 'Access point policy update differs')
        access = proxied_client('s3', current, variables['region'])
        ap_key = 'access-point-' + uuid.uuid4().hex
        binary = b'S3 access point ARN binary\x00\xff\n'
        ap_version = None
        try:
            ap_version = access.put_object(Bucket=outputs['access_point_arn'], Key=ap_key, Body=binary)['VersionId']
            require(object_bytes(access, outputs['access_point_arn'], ap_key, VersionId=ap_version)[0] == binary,
                    'Access-point ARN consumer did not read binary bytes')
            require(object_bytes(s3, bucket, ap_key, VersionId=ap_version)[0] == binary, 'Access-point bytes not in underlying bucket')
            restricted = dict(point_policy, Statement=point_policy['Statement'] + [{
                'Effect': 'Deny', 'Principal': '*', 'Action': ['s3:GetObject', 's3:GetObjectVersion'],
                'Resource': outputs['access_point_arn'] + '/object/*'}])
            try:
                control.put_access_point_policy(AccountId=variables['account_id'], Name=outputs['access_point'],
                                                Policy=json.dumps(restricted))
                denied(access.get_object, Bucket=outputs['access_point_arn'], Key=ap_key, VersionId=ap_version)
                denied(access.get_object, Bucket=outputs['access_point_arn'], Key=ap_key)
            finally:
                control.put_access_point_policy(AccountId=variables['account_id'], Name=outputs['access_point'],
                                                Policy=json.dumps(point_policy))
        finally:
            if ap_version:
                access.delete_object(Bucket=outputs['access_point_arn'], Key=ap_key, VersionId=ap_version)
        stage('access-point-arn-kms-object-bytes-' + revision)

        version_key = 'versions-' + uuid.uuid4().hex
        locked_key = 'lock-' + uuid.uuid4().hex
        try:
            versions = [s3.put_object(Bucket=bucket, Key=version_key, Body=value)['VersionId']
                        for value in (b'old\x00\xff', b'new\xff\x00')]
            require(len(set(versions)) == 2, 'Native version IDs not unique')
            for version, expected in zip(versions, (b'old\x00\xff', b'new\xff\x00')):
                require(object_bytes(s3, bucket, version_key, VersionId=version)[0] == expected, 'Historical binary bytes differ')
            locked = s3.put_object(Bucket=outputs['locked'], Key=locked_key, Body=b'locked\x00\xff')['VersionId']
            retention = s3.get_object_retention(Bucket=outputs['locked'], Key=locked_key, VersionId=locked)['Retention']
            require(retention['Mode'] == 'GOVERNANCE' and retention['RetainUntilDate'] > clock(current),
                    'Native default retention absent')
            denied(s3.delete_object, Bucket=outputs['locked'], Key=locked_key, VersionId=locked)
            s3.put_object_legal_hold(Bucket=outputs['locked'], Key=locked_key, VersionId=locked, LegalHold={'Status': 'ON'})
            denied(s3.delete_object, Bucket=outputs['locked'], Key=locked_key, VersionId=locked, BypassGovernanceRetention=True)
            require(object_bytes(s3, outputs['locked'], locked_key, VersionId=locked)[0] == b'locked\x00\xff', 'Protected bytes changed')
        finally:
            purge_key(s3, bucket, version_key)
            purge_key(s3, outputs['locked'], locked_key, locked=True)
        stage('native-version-retention-and-legal-hold-effects-' + revision)

        # Producer adoption is delayed by a local one-minute clock interval.
        clock(current, '2m')
        event_key = 'events/' + uuid.uuid4().hex
        event_version = None
        notification = None
        try:
            event_version = s3.put_object(Bucket=bucket, Key=event_key, Body=b'notification\x00\xff')['VersionId']
            def receive():
                nonlocal notification
                for message in sqs.receive_message(QueueUrl=outputs['queue'], MaxNumberOfMessages=10, WaitTimeSeconds=1).get('Messages', []):
                    body = json.loads(message['Body'])
                    for record in body.get('Records', []):
                        if unquote_plus(record['s3']['object']['key']) == event_key:
                            notification = record
                    sqs.delete_message(QueueUrl=outputs['queue'], ReceiptHandle=message['ReceiptHandle'])
                return notification
            record = await_value(receive, bool, 'Real S3 queue notification never arrived')
            require(record['eventName'] == 'ObjectCreated:Put' and record['s3']['bucket']['name'] == bucket
                    and record['s3']['configurationId'] == 'objects-' + revision
                    and record['s3']['object']['versionId'] == event_version
                    and record['s3']['object']['size'] == len(b'notification\x00\xff'), 'Notification producer payload differs')
            require(object_bytes(s3, bucket, event_key, VersionId=event_version)[0] == b'notification\x00\xff', 'Notification object consumer bytes differ')
            cw = client('cloudwatch', current)
            now = clock(current)
            for metric, minimum in (('GetRequests', 1), ('BytesDownloaded', len(b'notification\x00\xff'))):
                result = await_value(lambda: cw.get_metric_statistics(Namespace='AWS/S3', MetricName=metric,
                    Dimensions=[{'Name': 'BucketName', 'Value': bucket}, {'Name': 'FilterId', 'Value': 'requests'}],
                    StartTime=now - timedelta(minutes=1), EndTime=now + timedelta(minutes=1),
                    Period=60, Statistics=['Sum']),
                    lambda value: sum(point['Sum'] for point in value['Datapoints']) >= minimum,
                    'Real request metric sample absent: ' + metric)
        finally:
            if event_version:
                s3.delete_object(Bucket=bucket, Key=event_key, VersionId=event_version)
        stage('queue-notification-and-request-metric-consumers-' + revision)

        # Read delivered objects, not logging/inventory configuration echoes.
        clock(current, '6m')
        reports = buckets['reports']
        def log_records():
            return s3.list_objects_v2(Bucket=reports, Prefix='logs/' + revision + '/').get('Contents', [])
        logs = await_value(log_records, bool, 'Owned access-log object was not delivered')
        log_bytes = [object_bytes(s3, reports, item['Key'])[0] for item in logs]
        require(any(bucket.encode() in body and b'REST.GET.OBJECT' in body for body in log_bytes),
                'Delivered access-log bytes lack real source GET')
        clock(current, '48h')
        prefix = f'inventory/{revision}/{bucket}/daily/'
        def manifests():
            return [item for page in s3.get_paginator('list_objects_v2').paginate(Bucket=reports, Prefix=prefix)
                    for item in page.get('Contents', []) if item['Key'].endswith('/manifest.json')]
        manifests_found = await_value(manifests, bool, 'Daily inventory manifest was not delivered')
        manifest_key = max(manifests_found, key=lambda item: item['Key'])['Key']
        manifest_bytes = object_bytes(s3, reports, manifest_key)[0]
        manifest = json.loads(manifest_bytes)
        require(manifest['sourceBucket'] == bucket and manifest['fileFormat'] == 'CSV', 'Inventory manifest source/format differs')
        checksum_key = manifest_key.removesuffix('manifest.json') + 'manifest.checksum'
        checksum = await_value(lambda: object_bytes(s3, reports, checksum_key)[0], bool,
                               'Completed inventory checksum not delivered', missing={'NoSuchKey'})
        require(checksum.decode() == hashlib.md5(manifest_bytes).hexdigest(), 'Inventory manifest checksum differs')
        rows = []
        for item in manifest['files']:
            data = object_bytes(s3, reports, item['key'])[0]
            require(len(data) == item['size'] and hashlib.md5(data).hexdigest() == item['MD5checksum'], 'Delivered inventory file integrity differs')
            rows.extend(csv.reader(io.StringIO(gzip.decompress(data).decode())))
        columns = [column.strip() for column in manifest['fileSchema'].split(',')]
        records = [dict(zip(columns, row)) for row in rows]
        require(any(row.get('Bucket') == bucket and row.get('Key') == 'terraform.txt'
                    and row.get('EncryptionStatus') == 'SSE-KMS' and int(row['Size']) == len(payload) for row in records),
                'Delivered CSV inventory lacks real KMS object size/encryption')
        stage('delivered-access-log-and-inventory-byte-consumers-' + revision)

        replication_key = 'replicate/' + uuid.uuid4().hex
        rejected_key = replication_key + '-denied'
        role_policy = iam.get_role_policy(RoleName=outputs['role'], PolicyName='transfer')['PolicyDocument']
        if isinstance(role_policy, str):
            role_policy = json.loads(role_policy)
        try:
            restricted = dict(role_policy, Statement=role_policy['Statement'] + [{
                'Effect': 'Deny', 'Action': 's3:GetObjectVersionForReplication', 'Resource': '*'}])
            iam.put_role_policy(RoleName=outputs['role'], PolicyName='transfer', PolicyDocument=json.dumps(restricted))
            rejected_version = s3.put_object(Bucket=bucket, Key=rejected_key, Body=b'not-replicated')['VersionId']
            clock(current, '2m')
            await_value(lambda: s3.head_object(Bucket=bucket, Key=rejected_key, VersionId=rejected_version),
                        lambda result: result.get('ReplicationStatus') == 'FAILED', 'Replication ignored current role deny')
            expect_missing(s3.head_object, {'404', 'NoSuchKey', 'NotFound'}, Bucket=buckets['replica'], Key=rejected_key)
        finally:
            iam.put_role_policy(RoleName=outputs['role'], PolicyName='transfer', PolicyDocument=json.dumps(role_policy))
            purge_key(s3, bucket, rejected_key)
            purge_key(s3, buckets['replica'], rejected_key)
        try:
            source_version = s3.put_object(Bucket=bucket, Key=replication_key, Body=b'replicated\x00\xff',
                                           Tagging='source=consumer')['VersionId']
            clock(current, '2m')
            result = await_value(lambda: s3.head_object(Bucket=bucket, Key=replication_key, VersionId=source_version),
                                 lambda result: result.get('ReplicationStatus') == 'COMPLETED', 'Native replication did not complete')
            replica, metadata = object_bytes(s3, buckets['replica'], replication_key)
            require(replica == b'replicated\x00\xff' and metadata['ReplicationStatus'] == 'REPLICA'
                    and metadata['ServerSideEncryption'] == 'aws:kms' and metadata['SSEKMSKeyId'] == outputs['key_arn'],
                    'Independent replica KMS bytes/status differ')
            require(s3.get_object_tagging(Bucket=buckets['replica'], Key=replication_key)['TagSet']
                    == [{'Key': 'source', 'Value': 'consumer'}], 'Native replica tags differ')
            s3.delete_object(Bucket=bucket, Key=replication_key)
            clock(current, '2m')
            await_value(lambda: s3.list_object_versions(Bucket=buckets['replica'], Prefix=replication_key),
                        lambda result: any(item['Key'] == replication_key and item['IsLatest'] for item in result.get('DeleteMarkers', [])),
                        'Native replica delete marker not transferred')
            expect_missing(s3.get_object, {'NoSuchKey'}, Bucket=buckets['replica'], Key=replication_key)
        finally:
            purge_key(s3, bucket, replication_key)
            purge_key(s3, buckets['replica'], replication_key)
        stage('native-kms-replication-tags-and-delete-marker-effects-' + revision)

        expire_key = 'expire/' + uuid.uuid4().hex
        transition_key = 'transition/' + uuid.uuid4().hex
        tier_key = 'archive/' + uuid.uuid4().hex
        upload = None
        try:
            s3.put_object(Bucket=buckets['lifecycle'], Key=expire_key, Body=b'expiring')
            transition_version = s3.put_object(Bucket=buckets['lifecycle'], Key=transition_key, Body=b'x' * 131073)['VersionId']
            upload = s3.create_multipart_upload(Bucket=buckets['lifecycle'], Key=expire_key + '-multipart')['UploadId']
            s3.put_object(Bucket=buckets['tiering'], Key=tier_key, Body=b't' * 131073, StorageClass='INTELLIGENT_TIERING')
            require(object_bytes(s3, buckets['tiering'], tier_key)[0] == b't' * 131073, 'Tiering producer binary bytes differ')
            require(object_bytes(s3, buckets['lifecycle'], transition_key, VersionId=transition_version)[0]
                    == b'x' * 131073, 'Lifecycle transition source bytes differ')
            clock(current, '72h')
            await_value(lambda: s3.list_object_versions(Bucket=buckets['lifecycle'], Prefix=expire_key),
                        lambda result: any(item['Key'] == expire_key and item['IsLatest'] for item in result.get('DeleteMarkers', [])),
                        'Lifecycle expiration did not create native delete marker')
            expect_missing(s3.get_object, {'NoSuchKey'}, Bucket=buckets['lifecycle'], Key=expire_key)
            # This version became noncurrent when the observed marker was made,
            # not when its original upload first became eligible for expiry.
            clock(current, '48h')
            await_value(lambda: s3.list_object_versions(Bucket=buckets['lifecycle'], Prefix=expire_key),
                        lambda result: not any(item['Key'] == expire_key for item in result.get('Versions', [])),
                        'Lifecycle did not expire noncurrent object version')
            await_value(lambda: s3.head_object(Bucket=buckets['lifecycle'], Key=transition_key, VersionId=transition_version),
                        lambda result: result.get('StorageClass') == 'GLACIER', 'Native lifecycle storage transition absent')
            denied(s3.get_object, {'InvalidObjectState'}, Bucket=buckets['lifecycle'], Key=transition_key, VersionId=transition_version)
            await_value(lambda: s3.list_multipart_uploads(Bucket=buckets['lifecycle'], Prefix=expire_key + '-multipart'),
                        lambda result: not result.get('Uploads'), 'Lifecycle did not abort incomplete multipart upload')
            upload = None
            clock(current, '2208h')
            await_value(lambda: s3.head_object(Bucket=buckets['tiering'], Key=tier_key),
                        lambda result: result.get('ArchiveStatus') == 'ARCHIVE_ACCESS', 'Intelligent tiering did not archive real bytes')
            denied(s3.get_object, {'InvalidObjectState'}, Bucket=buckets['tiering'], Key=tier_key)
        finally:
            if upload:
                try:
                    s3.abort_multipart_upload(Bucket=buckets['lifecycle'], Key=expire_key + '-multipart', UploadId=upload)
                except ClientError as error:
                    require(error.response['Error']['Code'] == 'NoSuchUpload', str(error))
            purge_key(s3, buckets['lifecycle'], expire_key)
            purge_key(s3, buckets['lifecycle'], transition_key)
            s3.delete_object(Bucket=buckets['tiering'], Key=tier_key)
        stage('native-lifecycle-expiration-transition-abort-and-tiering-effects-' + revision)
        private_write(root / ('native-evidence-' + phase + '.json'), json.dumps({
            'phase': phase, 'revision': revision, 'kms_objects': payload_evidence,
            'owned_buckets': owned_buckets, 'access_point_arn': outputs['access_point_arn'],
        }, sort_keys=True, indent=2))
        observe_readback(phase)
        retain_no_changes('consumer-' + phase)

    def verify_reopen(endpoint=None):
        verify(endpoint)
        if strict_plan_failures:
            raise StrictPlanFailure(strict_plan_failures)

    def cleanup(endpoint=None):
        nonlocal destroyed
        if destroyed:
            return
        current = local_endpoint(endpoint or initial_endpoint)
        # The actual KMS key ID is retained even on a partially failed apply.
        state = json.loads(tf('show', '-json').stdout)
        resources = state.get('values', {}).get('root_module', {}).get('resources', [])
        key_ids = [resource['values']['key_id'] for resource in resources if resource['type'] == 'aws_kms_key']
        tf('destroy', '-input=false', '-auto-approve')
        s3 = client('s3', current)
        for bucket in owned_buckets:
            expect_missing(s3.head_bucket, {'404', 'NoSuchBucket', 'NotFound'}, Bucket=bucket)
        control = proxied_client('s3control', current, variables['region'])
        expect_missing(control.get_access_point, {'NoSuchAccessPoint', 'NoSuchAccessPointException', 'NotFound'},
                       AccountId=variables['account_id'], Name=variables['name'] + '-s3-ap')
        expect_missing(control.get_public_access_block, {'NoSuchPublicAccessBlockConfiguration'}, AccountId=variables['account_id'])
        sqs = client('sqs', current)
        expect_missing(sqs.get_queue_url, {'AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist'},
                       QueueName=variables['name'] + '-s3-events')
        iam = client('iam', current)
        expect_missing(iam.get_user, {'NoSuchEntity'}, UserName=variables['name'] + '-s3-consumer')
        expect_missing(iam.get_role, {'NoSuchEntity'}, RoleName=variables['name'] + '-s3-replication')
        if key_ids:
            clock(current, '192h')
            for key_id in key_ids:
                expect_missing(client('kms', current).describe_key, {'NotFoundException'}, KeyId=key_id)
        state = json.loads(tf('show', '-json').stdout)
        require(not state.get('values', {}).get('root_module', {}).get('resources'), 'Owned S3 Terraform state retained resources')
        destroyed = True
        stage('destroy-exact-owned-buckets-dependencies-and-expired-kms-key')

    try:
        tf('init', '-input=false')
        tf('apply', '-input=false', '-auto-approve')
        read_outputs()
        stage('create')
        verify()
        # Import controls using their provider-generated owned IDs. Object copy is
        # explicitly @NoImport; content-based objects cannot recover content input.
        state = json.loads(tf('show', '-json').stdout)
        resources = state['values']['root_module']['resources']
        imports = [(resource['address'], resource['values']['bucket'] if resource['type'] == 'aws_s3_bucket_abac'
                    else resource['values']['id']) for resource in resources
                   if resource['mode'] == 'managed' and resource['type'].startswith('aws_s3')
                   and resource['type'] not in {'aws_s3_object', 'aws_s3_object_copy'}]
        imports = [(address, outputs['access_point_arn'] if address == 'aws_s3control_access_point_policy.data' else identity)
                   for address, identity in imports]
        for index, (address, identity) in enumerate(imports):
            state_path = root / 'terraform.tfstate'
            prior = state_path.read_bytes()
            private_write(root / f'owned-pre-import-{index}.tfstate', prior)
            try:
                tf('state', 'rm', address)
                tf('import', '-input=false', address, identity)
            except BaseException:
                private_write(state_path, prior)
                raise
        stage('safe-owned-control-import', addresses=[address for address, _ in imports])
        # Restore write-only provider inputs (e.g. force_destroy) normally, never
        # through ignore_changes or state surgery, then require no-change plans.
        tf('apply', '-input=false', '-auto-approve')
        read_outputs()
        observe_readback('import')
        retain_no_changes('import')
        revision = 'updated'
        variables['revision'] = revision
        private_write(varfile, json.dumps(variables))
        tf('apply', '-input=false', '-auto-approve')
        read_outputs()
        verify()
        stage('update')
        return verify_reopen, cleanup
    except BaseException:
        cleanup()
        raise
