#!/usr/bin/env python3
"""Signed local folder-source workflows on a parent-built stackd and real Docker."""
import argparse
import hashlib
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


class Folders(secondary.Secondaries):
    def setup(self):
        self.role_arn = 'arn:aws:iam::' + base.ACCOUNT + ':role/' + self.role
        self.repository_arn = 'arn:aws:ecr:' + base.REGION + ':' + base.ACCOUNT + ':repository/unused'
        self.image = base.BASE_IMAGE
        self.setup_project()
        s3, cb = self.clients['s3'], self.clients['codebuild']
        s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={'Status': 'Enabled'})
        self.versioned = True
        self.folder_spec = {'version': '0.2', 'phases': {'build': {'commands': [
            'echo FOLDER_READY', 'sleep ${HOLD:-0}',
            'cat "$CODEBUILD_SRC_DIR/nested/a.txt" "$CODEBUILD_SRC_DIR/deep/b.txt" "$CODEBUILD_SRC_DIR_Aux/nested/c.txt" "$CODEBUILD_SRC_DIR_Aux/z-last.txt" > result.txt',
            'test ! -e "$CODEBUILD_SRC_DIR_Aux/sibling.txt"',
            'test "$(find "$CODEBUILD_SRC_DIR_Aux/paged" -type f | wc -l | tr -d " ")" = 1001'] }},
            'artifacts': {'files': ['result.txt']}}
        objects = {'primary/buildspec.yml': json.dumps(self.folder_spec), 'primary/nested/a.txt': 'primary\n',
                   'primary/deep/b.txt': 'nested\n', 'aux/nested/c.txt': 'old\n', 'aux/z-last.txt': 'last\n',
                   'aux/buildspec.yml': 'version: 0.2\nphases:\n  build:\n    commands: [exit 99]\n',
                   'aux/': '', 'aux/empty/': '', 'aux-other/sibling.txt': 'must not enter folder', 'empty/': ''}
        for key, body in objects.items():
            s3.put_object(Bucket=self.bucket, Key=key, Body=body)
        for index in range(1001):
            s3.put_object(Bucket=self.bucket, Key='aux/paged/%04d.txt' % index, Body=str(index))
        self.sources = [{'type': 'S3', 'location': self.bucket + '/aux/', 'sourceIdentifier': 'Aux', 'buildspec': 'exit 98'}]
        cb.update_project(name=self.project, source={'type': 'S3', 'location': self.bucket + '/primary/'}, secondarySources=self.sources)

    def output(self, build, expected):
        base.require(build['buildStatus'] == 'SUCCEEDED', 'folder build failed')
        data = self.clients['s3'].get_object(Bucket=self.bucket, Key='artifacts/default.zip')['Body'].read()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            base.require(archive.namelist() == ['result.txt'] and archive.read('result.txt') == expected, 'folder output bytes differ')
        base.require(build['artifacts']['sha256sum'] == hashlib.sha256(data).hexdigest(), 'folder output checksum differs')
        return hashlib.sha256(data).hexdigest()

    def failed_source(self, build):
        build = self.wait(build['id'], 'FAILED')
        base.require(any(p.get('phaseType') == 'DOWNLOAD_SOURCE' and p.get('phaseStatus') == 'FAILED' for p in build['phases']), 'folder failure escaped source preparation')
        return build

    def exercise(self):
        cb, s3, iam = self.clients['codebuild'], self.clients['s3'], self.clients['iam']
        first = self.wait(self.begin()['id'], 'SUCCEEDED')
        digest = self.output(first, b'primary\nnested\nold\nlast\n')
        self.note('nested_primary_secondary_and_pagination', build_id=first['id'], sha256=digest, objects_after_first_page_consumed=True, secondary_buildspec_ignored=True)
        s3.put_object(Bucket=self.bucket, Key='aux/nested/c.txt', Body='current\n')
        changed = self.wait(self.begin()['id'], 'SUCCEEDED')
        digest = self.output(changed, b'primary\nnested\ncurrent\nlast\n')
        self.note('fresh_build_current_folder_objects', build_id=changed['id'], sha256=digest)
        for overrides in ({'sourceVersion': 'object-version'}, {'secondarySourcesVersionOverride': [{'sourceIdentifier': 'Aux', 'sourceVersion': 'object-version'}]}):
            try:
                self.begin(**overrides)
            except self.client_error as error:
                base.require(error.response['Error']['Code'] == 'InvalidInputException', 'wrong folder version rejection')
            else:
                raise RuntimeError('folder object-version accepted')
        for label, action, resource in [('list', 's3:ListBucket', 'arn:aws:s3:::' + self.bucket), ('read', 's3:GetObject', 'arn:aws:s3:::' + self.bucket + '/aux/z-last.txt')]:
            self.created.add('deny_source')
            iam.put_role_policy(RoleName=self.role, PolicyName='deny-source', PolicyDocument=base.policy([{'Effect': 'Deny', 'Action': action, 'Resource': resource}]))
            # The signed operator can still read: denial is the execution role,
            # not missing input or ambient/task-role credentials.
            base.require(s3.get_object(Bucket=self.bucket, Key='aux/z-last.txt')['Body'].read() == b'last\n', 'operator source read failed')
            denied = self.failed_source(self.begin())
            iam.delete_role_policy(RoleName=self.role, PolicyName='deny-source')
            self.created.discard('deny_source')
            self.note('current_folder_' + label + '_denial', build_id=denied['id'], phase='DOWNLOAD_SOURCE', operator_read_succeeded=True)
        simple = json.dumps({'version': '0.2', 'phases': {'build': {'commands': ['printf empty > result.txt']}}, 'artifacts': {'files': ['result.txt']}})
        missing = self.failed_source(self.begin(sourceLocationOverride=self.bucket + '/missing/', buildspecOverride=simple, secondarySourcesOverride=[]))
        self.note('missing_prefix_failure', build_id=missing['id'])
        empty = self.wait(self.begin(sourceLocationOverride=self.bucket + '/empty/', buildspecOverride=simple, secondarySourcesOverride=[])['id'], 'SUCCEEDED')
        self.output(empty, b'empty')
        self.note('marker_only_empty_prefix', build_id=empty['id'])
        # Traversal keys are rejected by S3 before storage; runtime traversal
        # coverage lives in TestFolderSourceWorkspaceBoundary. A file/directory
        # collision is a reachable S3 source that must fail native preparation.
        key = 'aux/nested'
        version = s3.put_object(Bucket=self.bucket, Key=key, Body='unsafe')['VersionId']
        unsafe = self.failed_source(self.begin())
        s3.delete_object(Bucket=self.bucket, Key=key, VersionId=version)
        self.note('safe_folder_boundary', key=key, build_id=unsafe['id'])
        retained = self.begin(environmentVariablesOverride=[{'name': 'HOLD', 'value': '15', 'type': 'PLAINTEXT'}])
        self.wait(retained['id'], log_prefix='FOLDER_READY')
        cb.update_project(name=self.project, secondarySources=[dict(self.sources[0], location=self.bucket + '/changed-project/')])
        s3.put_object(Bucket=self.bucket, Key='aux/nested/c.txt', Body='future\n')
        self.stop()
        self.start()
        retained = self.wait(retained['id'], 'SUCCEEDED')
        base.require(retained['secondarySources'] == self.sources, 'restart changed accepted folder source')
        digest = self.output(retained, b'primary\nnested\ncurrent\nlast\n')
        project = cb.batch_get_projects(names=[self.project])['projects'][0]
        base.require(project['secondarySources'][0]['location'].endswith('/changed-project/'), 'restart lost later project configuration')
        self.note('sqlite_accepted_folder_and_active_container_restart', build_id=retained['id'], sha256=digest, accepted_location_preserved=True, staged_bytes_preserved=True)
        cb.update_project(name=self.project, secondarySources=self.sources)
        fresh = self.wait(self.begin()['id'], 'SUCCEEDED')
        digest = self.output(fresh, b'primary\nnested\nfuture\nlast\n')
        self.note('post_restart_fresh_download', build_id=fresh['id'], sha256=digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--keep-resources', action='store_true')
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock', choices=['unix:///var/run/docker.sock'])
    args = parser.parse_args()
    args.ecr_scanner = None
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    os.umask(0o077)
    smoke = Folders(args, boto3, Config, ClientError)
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
