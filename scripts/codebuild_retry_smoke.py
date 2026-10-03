#!/usr/bin/env python3
"""Exercise retained RetryBuild inputs, current source/IAM and SQLite using real Docker."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import zipfile

spec = importlib.util.spec_from_file_location('secondaries', Path(__file__).with_name('codebuild_secondaries_smoke.py'))
secondary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secondary)
base = secondary.base


class Retries(secondary.Secondaries):
    def setup(self):
        self.role_arn = 'arn:aws:iam::' + base.ACCOUNT + ':role/' + self.role
        self.repository_arn = 'arn:aws:ecr:' + base.REGION + ':' + base.ACCOUNT + ':repository/unused'
        self.image = base.BASE_IMAGE
        self.setup_project()
        s3, cb = self.clients['s3'], self.clients['codebuild']
        s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={'Status': 'Enabled'})
        self.versioned = True
        self.buildspec = {'version': '0.2', 'phases': {'build': {'commands': [
            'printf "accepted:%s:%s\\n" "$VALUE" "$NEW" > result.txt',
            'cat value.txt "$CODEBUILD_SRC_DIR_Aux/value.txt" >> result.txt',
            'cat result.txt']}}, 'artifacts': {'files': ['result.txt']}}
        self.replace_sources('old')
        cb.update_project(name=self.project,
                          source={'type': 'S3', 'location': self.bucket + '/source.zip', 'buildspec': json.dumps(self.buildspec)},
                          secondarySources=[{'type': 'S3', 'location': self.bucket + '/aux.zip', 'sourceIdentifier': 'Aux'}])

    def replace_sources(self, revision):
        for key, source in [('source.zip', 'primary'), ('aux.zip', 'secondary')]:
            self.clients['s3'].put_object(Bucket=self.bucket, Key=key,
                                         Body=secondary.archive({'value.txt': source + '-' + revision + '\n'}))

    def consume_retry(self, build, revision):
        response = self.clients['s3'].get_object(Bucket=self.bucket, Key='artifacts/default.zip')
        with response['Body'] as stream:
            payload = stream.read()
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            actual = archive.read('result.txt')
        expected = ('accepted:original:\nprimary-' + revision + '\nsecondary-' + revision + '\n').encode()
        base.require(actual == expected, 'retry consumed wrong configuration/source bytes: ' + repr(actual))
        base.require(build['artifacts']['location'] == 'arn:aws:s3:::' + self.bucket + '/artifacts/default.zip', 'retained artifact configuration changed')
        self.note('retry-output', build_id=build['id'], body=actual.decode(), status=build['buildStatus'], initiator=build['initiator'])

    def retry(self, build_id, client=None, **options):
        result = (client or self.clients['codebuild']).retry_build(id=build_id, **options)['build']
        if result['id'] not in self.build_ids:
            self.build_ids.append(result['id'])
        return result

    def rejected(self, code, function, **request):
        try:
            function(**request)
        except self.client_error as error:
            base.require(error.response['Error']['Code'] == code, 'unexpected rejection: ' + str(error))
        else:
            raise RuntimeError('expected ' + code)

    def exercise(self):
        cb, iam = self.clients['codebuild'], self.clients['iam']
        original = self.begin(environmentVariablesOverride=[{'name': 'VALUE', 'value': 'original', 'type': 'PLAINTEXT'}],
                              buildspecOverride=json.dumps(self.buildspec))
        original = self.wait(original['id'], 'SUCCEEDED')
        self.consume_retry(original, 'old')
        self.replace_sources('new')
        cb.update_project(name=self.project, source={'type': 'NO_SOURCE', 'buildspec': 'version: 0.2\nphases:\n  build:\n    commands: ["exit 37"]\n'},
                          secondarySources=[], artifacts={'type': 'NO_ARTIFACTS'},
                          environment={'type': 'LINUX_CONTAINER', 'image': self.image, 'computeType': 'BUILD_GENERAL1_SMALL',
                                       'environmentVariables': [{'name': 'VALUE', 'value': 'changed', 'type': 'PLAINTEXT'},
                                                                {'name': 'NEW', 'value': 'project-only', 'type': 'PLAINTEXT'}]})
        self.stop()
        self.start()
        retried = self.retry(original['id'], idempotencyToken='durable-retry')
        base.require(retried['id'] != original['id'] and retried['buildNumber'] == original['buildNumber'] + 1, 'retry reused execution identity')
        retried = self.wait(retried['id'], 'SUCCEEDED')
        self.consume_retry(retried, 'new')
        self.stop()
        self.start()
        base.require(self.retry(original['id'], idempotencyToken='durable-retry')['id'] == retried['id'], 'restart lost retry token')
        self.rejected('InvalidInputException', cb.retry_build, id=original['arn'], idempotencyToken='durable-retry')
        started = self.begin(idempotencyToken='durable-retry')
        base.require(started['id'] != retried['id'], 'StartBuild shared retry token namespace')
        self.wait(started['id'], 'FAILED')
        self.note('retained-retry-after-project-mutation-and-restart', original_id=original['id'], retry_id=retried['id'], independent_start_token=True)

        iam.create_user(UserName=self.user)
        self.created.add('user')
        project_arn = 'arn:aws:codebuild:' + base.REGION + ':' + base.ACCOUNT + ':project/' + self.project
        grant = [{'Effect': 'Allow', 'Action': 'codebuild:RetryBuild', 'Resource': project_arn},
                 {'Effect': 'Deny', 'Action': ['codebuild:StartBuild', 'iam:PassRole'], 'Resource': '*'}]
        iam.put_user_policy(UserName=self.user, PolicyName='owned', PolicyDocument=base.policy(grant))
        key = iam.create_access_key(UserName=self.user)['AccessKey']
        self.access_key = key['AccessKeyId']
        self.created.add('access_key')
        user_session = self.session.__class__(aws_access_key_id=key['AccessKeyId'], aws_secret_access_key=key['SecretAccessKey'], region_name=base.REGION)
        client = self.client('codebuild', user_session)
        self.rejected('AccessDeniedException', client.start_build, projectName=self.project)
        restricted = self.retry(original['id'], client, idempotencyToken='retry-only')
        restricted = self.wait(restricted['id'], 'SUCCEEDED')
        self.consume_retry(restricted, 'new')
        iam.put_user_policy(UserName=self.user, PolicyName='owned', PolicyDocument=base.policy([{'Effect': 'Deny', 'Action': 'codebuild:RetryBuild', 'Resource': project_arn}]))
        self.rejected('AccessDeniedException', client.retry_build, id=original['id'], idempotencyToken='retry-only')
        self.note('retry-only-current-caller-authority', retry_id=restricted['id'], replay_denied_after_revocation=True, start_and_passrole_denied=True)

        self.created.add('deny_source')
        iam.put_role_policy(RoleName=self.role, PolicyName='deny-source', PolicyDocument=base.policy([
            {'Effect': 'Deny', 'Action': ['s3:GetObject', 's3:GetObjectVersion'], 'Resource': 'arn:aws:s3:::' + self.bucket + '/aux.zip'}]))
        failed = self.retry(original['id'])
        failed = self.wait(failed['id'], 'FAILED')
        base.require(any(p.get('phaseType') == 'DOWNLOAD_SOURCE' and p.get('phaseStatus') == 'FAILED' for p in failed['phases']), 'retry ignored current source denial')
        iam.delete_role_policy(RoleName=self.role, PolicyName='deny-source')
        self.created.discard('deny_source')
        self.replace_sources('restored')
        recovered = self.retry(failed['id'])
        recovered = self.wait(recovered['id'], 'SUCCEEDED')
        self.consume_retry(recovered, 'restored')
        self.note('retry-current-execution-role-denial-and-recovery', denied_id=failed['id'], recovered_id=recovered['id'])
        cb.delete_project(name=self.project)
        self.created.discard('project')
        self.rejected('ResourceNotFoundException', cb.retry_build, id=original['id'], idempotencyToken='durable-retry')
        self.note('deleted-project-precedes-retry-replay', retained_history=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--lambda-telemetry-directory')
    parser.add_argument('--keep-resources', action='store_true')
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock', choices=['unix:///var/run/docker.sock'])
    args = parser.parse_args()
    args.ecr_scanner = None
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    os.umask(0o077)
    smoke = Retries(args, boto3, Config, ClientError)
    passed = False
    try:
        smoke.prepare()
        smoke.start()
        smoke.setup()
        smoke.exercise()
        passed = True
    except Exception as error:
        if smoke.owns_state:
            smoke.note('failure', error=smoke.safe_error(error))
        else:
            print(smoke.safe_error(error), file=sys.stderr)
    finally:
        smoke.cleanup()
    if smoke.owns_state:
        smoke.note('result', passed=passed and not smoke.cleanup_errors, cleanup_errors=smoke.cleanup_errors)
    return 0 if passed and not smoke.cleanup_errors else 1


if __name__ == '__main__':
    sys.exit(main())
