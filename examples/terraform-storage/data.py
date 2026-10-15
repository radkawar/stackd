"""Terraform data resources and signed binary/item consumers; no simulated engines."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from local import ACCOUNT, REGION, client, expect_missing, local_endpoint, require

PROVIDER = '''terraform {
  required_version = "= 1.15.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.68.0" }
  }
}
variable "endpoint" { type = string }
variable "name" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "revision" { type = string }
provider "aws" {
  region = var.region
  access_key = "test"
  secret_key = "test"
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_region_validation = true
  s3_use_path_style = true
  http_proxy = var.endpoint
  https_proxy = ""
  no_proxy = "127.0.0.1,localhost"
  endpoints {
    s3 = var.endpoint
    s3control = var.endpoint
    dynamodb = var.endpoint
    ec2 = var.endpoint
    iam = var.endpoint
    sts = var.endpoint
  }
}
'''


def control_client(endpoint):
    # Keep the SDK account-prefixed signed Host, but route only to our listener.
    return boto3.client('s3control', endpoint_url=local_endpoint(endpoint), region_name=REGION,
                        aws_access_key_id='test', aws_secret_access_key='test',
                        config=Config(signature_version='v4', proxies={'http': endpoint},
                                      connect_timeout=3, read_timeout=60, retries={'max_attempts': 0}))


def wait_for(read, predicate, message, missing_codes=()):
    deadline = time.monotonic() + 90
    while True:
        try:
            value = read()
        except ClientError as error:
            if error.response['Error']['Code'] not in missing_codes:
                raise
        else:
            if predicate(value):
                return value
        require(time.monotonic() < deadline, message)
        time.sleep(0.5)


def run(args, root, endpoint, terraform, variables, stages):
    services = set(args.services.split(',')) & {'s3', 'dynamodb', 'ebs'}
    root.joinpath('main.tf').write_text(PROVIDER)
    for service in sorted(services):
        shutil.copyfile(Path(__file__).with_name(service + '.tf'), root / (service + '.tf'))
    revision = 'initial'
    variables = dict(variables, revision=revision)
    varfile = root / 'local.auto.tfvars.json'
    varfile.write_text(json.dumps(variables))
    outputs = {}
    snapshot = None
    payload = (b'stackd-direct-block\x00\xff\n' * 26215)[:524288]
    payload += b'\x00' * (524288 - len(payload))
    checksum = base64.b64encode(hashlib.sha256(payload).digest()).decode()
    marker = {'pk': {'S': 'native-consumer'}, 'group': {'S': 'native'}, 'payload': {'B': b'\x00\xffnative-item'}}
    last_ec2_mutation = 0.0

    def tf(*command, check=True):
        nonlocal last_ec2_mutation
        mutating = 'ebs' in services and command[0] in {'apply', 'destroy'}
        if mutating:
            # Snapshot account-public-access mutations admit one request per 10s.
            delay = 10 - (time.monotonic() - last_ec2_mutation)
            if delay > 0:
                time.sleep(delay)
        result = terraform(list(command), root, check=check)
        if mutating:
            last_ec2_mutation = time.monotonic()
        return result

    def negative(current, service, operation):
        iam = client('iam', current)
        username = variables['name'] + '-denied'
        iam.create_user(UserName=username)
        key = None
        try:
            key = iam.create_access_key(UserName=username)['AccessKey']
            denied = boto3.client(service, endpoint_url=current, region_name=REGION,
                                  aws_access_key_id=key['AccessKeyId'], aws_secret_access_key=key['SecretAccessKey'],
                                  config=Config(signature_version='s3v4' if service == 's3' else 'v4', proxies={},
                                                retries={'max_attempts': 0}, s3={'addressing_style': 'path'}))
            try:
                operation(denied)
            except ClientError as error:
                require(error.response['Error']['Code'] in {'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', '403'}, str(error))
            else:
                raise RuntimeError('Signed current no-policy IAM identity was allowed')
        finally:
            if key:
                iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])
            iam.delete_user(UserName=username)
        stages.append({'stage': service + '-signed-current-authority-negative', 'status': 'passed'})

    def verify(current=None):
        current = current or endpoint
        if 's3' in services:
            s3 = client('s3', current)
            bucket = outputs['s3']['bucket']
            require(outputs['s3']['lookup_arn'] == f'arn:aws:s3:::{bucket}', 'Terraform bucket data source differs')
            require(base64.b64decode(outputs['s3']['lookup_body_base64']) == ('storage-' + revision).encode(), 'Terraform object data source bytes differ')
            for key in ('terraform.txt', 'copied.txt'):
                response = s3.get_object(Bucket=bucket, Key=key)
                with response['Body'] as body:
                    require(body.read() == ('storage-' + revision).encode(), 'Terraform object/copy bytes differ')
                require(response['ServerSideEncryption'] == 'AES256', 'Object encryption not enforced')
            require(s3.get_bucket_versioning(Bucket=bucket)['Status'] == 'Enabled', 'Versioning differs')
            require(s3.get_bucket_ownership_controls(Bucket=bucket)['OwnershipControls']['Rules'][0]['ObjectOwnership'] == 'BucketOwnerEnforced', 'Ownership differs')
            require(s3.get_bucket_cors(Bucket=bucket)['CORSRules'][0]['AllowedOrigins'] == [f'https://{revision}.example.invalid'], 'CORS update differs')
            encryption = s3.get_bucket_encryption(Bucket=bucket)['ServerSideEncryptionConfiguration']['Rules'][0]
            require(encryption['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256', 'Default encryption differs')
            require(all(s3.get_public_access_block(Bucket=bucket)['PublicAccessBlockConfiguration'].values()), 'Bucket public block differs')
            control = control_client(current)
            require(all(control.get_public_access_block(AccountId=ACCOUNT)['PublicAccessBlockConfiguration'].values()), 'Account public block differs')
            point = outputs['s3']['access_point']
            require(control.get_access_point(AccountId=ACCOUNT, Name=point)['Bucket'] == bucket, 'Access point bucket differs')
            policy = json.loads(control.get_access_point_policy(AccountId=ACCOUNT, Name=point)['Policy'])
            require(policy['Statement'][0]['Sid'] == 'Read' + revision, 'Access point policy update differs')
            native = b'signed-versioned-object\x00\xff'
            versions = []
            try:
                for value in (native, native + b'new'):
                    versions.append(s3.put_object(Bucket=bucket, Key='native.bin', Body=value)['VersionId'])
                require(len(set(versions)) == 2, 'Version identities not unique')
                for version, expected in zip(versions, (native, native + b'new')):
                    with s3.get_object(Bucket=bucket, Key='native.bin', VersionId=version)['Body'] as body:
                        require(body.read() == expected, 'Historical binary version differs')
            finally:
                for version in versions:
                    s3.delete_object(Bucket=bucket, Key='native.bin', VersionId=version)
            negative(current, 's3', lambda denied: denied.get_object(Bucket=bucket, Key='terraform.txt'))
        if 'dynamodb' in services:
            ddb = client('dynamodb', current)
            table = outputs['dynamodb']['table']
            require(outputs['dynamodb']['lookup_arn'] == f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{table}', 'Terraform table data source differs')
            require(outputs['dynamodb']['lookup_item']['revision'] == {'S': revision}, 'Terraform item data source differs')
            require(ddb.get_item(TableName=table, Key={'pk': {'S': 'terraform'}}, ConsistentRead=True)['Item']['revision'] == {'S': revision}, 'Terraform item update differs')
            result = wait_for(lambda: ddb.query(TableName=table, IndexName='by-group', KeyConditionExpression='#g = :g', ExpressionAttributeNames={'#g': 'group'}, ExpressionAttributeValues={':g': {'S': 'fixture'}}), lambda result: len(result['Items']) == 1 and result['Items'][0]['revision'] == {'S': revision}, 'Native GSI did not return updated item')
            require(result['Items'][0]['pk'] == {'S': 'terraform'}, 'GSI key differs')
            require(ddb.get_item(TableName=table, Key={'pk': marker['pk']}, ConsistentRead=True)['Item'] == marker, 'Native binary item lost')
            streams = client('dynamodbstreams', current)
            arn = outputs['dynamodb']['stream_arn']
            description = streams.describe_stream(StreamArn=arn)['StreamDescription']
            found = False
            for shard in description['Shards']:
                iterator = streams.get_shard_iterator(StreamArn=arn, ShardId=shard['ShardId'], ShardIteratorType='TRIM_HORIZON')['ShardIterator']
                deadline = time.monotonic() + 30
                while iterator:
                    page = streams.get_records(ShardIterator=iterator)
                    if any(record.get('dynamodb', {}).get('NewImage') == marker for record in page['Records']):
                        found = True
                        break
                    iterator = page.get('NextShardIterator')
                    if not page['Records'] or time.monotonic() >= deadline:
                        break
                if found:
                    break
            require(found, 'Real Streams consumer did not observe native binary item image')
            negative(current, 'dynamodb', lambda denied: denied.get_item(TableName=table, Key={'pk': marker['pk']}))
        if 'ebs' in services:
            ebs = client('ebs', current)
            for snapshot_id in (snapshot, outputs['ebs']['snapshot_id']):
                page = wait_for(lambda: ebs.list_snapshot_blocks(SnapshotId=snapshot_id),
                                lambda value: len(value['Blocks']) == 1, 'Snapshot block publication timed out',
                                missing_codes={'ResourceNotFoundException'})
                blocks = page['Blocks']
                require(blocks[0]['BlockIndex'] == 0, 'Unexpected snapshot block inventory')
                response = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=0, BlockToken=blocks[0]['BlockToken'])
                with response['BlockData'] as body:
                    require(body.read() == payload, 'Direct/provider copied snapshot bytes differ')
                require(response['Checksum'] == checksum, 'Snapshot block checksum differs')
            require(client('ec2', current).get_snapshot_block_public_access_state()['State'] == outputs['ebs']['public_access_state'], 'EBS public access state differs')
            negative(current, 'ebs', lambda denied: denied.list_snapshot_blocks(SnapshotId=snapshot))
        stages.append({'stage': 'data-native-consumers-' + revision, 'status': 'passed', 'services': sorted(services)})

    def cleanup(current=None):
        current = current or endpoint
        tf('destroy', '-input=false', '-auto-approve')
        if snapshot:
            ec2 = client('ec2', current)
            ec2.delete_snapshot(SnapshotId=snapshot)
            expect_missing(ec2.describe_snapshots, {'InvalidSnapshot.NotFound'}, SnapshotIds=[snapshot])
        if 's3' in outputs:
            expect_missing(client('s3', current).head_bucket, {'404', 'NoSuchBucket', 'NotFound'}, Bucket=outputs['s3']['bucket'])
            expect_missing(control_client(current).get_access_point, {'NoSuchAccessPoint', 'NoSuchAccessPointException', 'NotFound'}, AccountId=ACCOUNT, Name=outputs['s3']['access_point'])
            expect_missing(control_client(current).get_public_access_block, {'NoSuchPublicAccessBlockConfiguration'}, AccountId=ACCOUNT)
        if 'dynamodb' in outputs:
            expect_missing(client('dynamodb', current).describe_table, {'ResourceNotFoundException'}, TableName=outputs['dynamodb']['table'])
        if 'ebs' in services:
            require(client('ec2', current).get_snapshot_block_public_access_state()['State'] == 'unblocked', 'Owned EBS public access override remains')
            if 'ebs' in outputs:
                expect_missing(client('ec2', current).describe_snapshots, {'InvalidSnapshot.NotFound'}, SnapshotIds=[outputs['ebs']['snapshot_id']])
        state = json.loads(tf('show', '-json').stdout)
        require(not state.get('values', {}).get('root_module', {}).get('resources'), 'Terraform resources remain after destroy')
        stages.append({'stage': 'data-destroy-exact-owned-cleanup', 'status': 'passed'})

    try:
        tf('init', '-input=false')
        if 'ebs' in services:
            ebs = client('ebs', endpoint)
            snapshot = ebs.start_snapshot(VolumeSize=1, Description=variables['name'], ClientToken=variables['name'])['SnapshotId']
            root.joinpath('owned-snapshot.json').write_text(json.dumps({'snapshot_id': snapshot}))
            ebs.put_snapshot_block(SnapshotId=snapshot, BlockIndex=0, BlockData=payload, DataLength=len(payload), Checksum=checksum, ChecksumAlgorithm='SHA256')
            ebs.complete_snapshot(SnapshotId=snapshot, ChangedBlocksCount=1)
            wait_for(lambda: client('ec2', endpoint).describe_snapshots(SnapshotIds=[snapshot])['Snapshots'][0], lambda value: value['State'] == 'completed', 'Direct snapshot completion timed out')
            wait_for(lambda: ebs.list_snapshot_blocks(SnapshotId=snapshot), lambda value: len(value['Blocks']) == 1,
                     'Direct source snapshot readability timed out', missing_codes={'ResourceNotFoundException'})
            variables['source_snapshot_id'] = snapshot
            varfile.write_text(json.dumps(variables))
        tf('apply', '-input=false', '-auto-approve')
        outputs.update({key: value['value'] for key, value in json.loads(tf('output', '-json').stdout).items()})
        stages.append({'stage': 'data-create', 'status': 'passed', 'resources': outputs})
        if 'dynamodb' in services:
            client('dynamodb', endpoint).put_item(TableName=outputs['dynamodb']['table'], Item=marker)
        verify()
        imports = []
        if 's3' in services:
            imports.extend([('aws_s3_bucket.data', outputs['s3']['bucket']), ('aws_s3_access_point.data', ACCOUNT + ':' + outputs['s3']['access_point'])])
        if 'dynamodb' in services:
            imports.append(('aws_dynamodb_table.data', outputs['dynamodb']['table']))
        for address, identity in imports:
            tf('state', 'rm', address)
            tf('import', '-input=false', address, identity)
        if imports:
            stages.append({'stage': 'data-state-remove-import', 'status': 'passed', 'addresses': [address for address, _ in imports]})
        revision = 'updated'
        variables['revision'] = revision
        varfile.write_text(json.dumps(variables))
        tf('apply', '-input=false', '-auto-approve')
        outputs.update({key: value['value'] for key, value in json.loads(tf('output', '-json').stdout).items()})
        verify()
        stages.append({'stage': 'data-update', 'status': 'passed'})
        for flags, filename in [(['-refresh-only'], 'refresh.tfplan'), ([], 'noop.tfplan')]:
            plan = tf('plan', *flags, '-input=false', '-detailed-exitcode', '-out=' + filename, check=False)
            require(plan.returncode == 0, f'Data plan was not unchanged: {filename}, exit {plan.returncode}')
            if flags:
                tf('apply', '-input=false', '-auto-approve', filename)
        stages.append({'stage': 'data-refresh-no-change', 'status': 'passed'})
        return verify, cleanup
    except BaseException:
        cleanup()
        raise
