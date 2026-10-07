#!/usr/bin/env python3
"""Signed local Git secondaries, real HTTPS git-http-backend and Docker builds.

No AWS calls or downloads. Reuses the folder smoke's actual executable lifecycle
and S3 artifact consumer. Requires installed Git/OpenSSL and the pinned toolkit.
"""
import argparse
import base64
import http.server
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
from urllib.parse import urlsplit

spec = importlib.util.spec_from_file_location('folders', Path(__file__).with_name('codebuild_folder_smoke.py'))
folders = importlib.util.module_from_spec(spec)
spec.loader.exec_module(folders)
base = folders.base


class GitHTTP(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_git(self):
        url = urlsplit(self.path)
        repo = url.path.strip('/').split('/')[0]
        expected = self.server.tokens.get(repo)
        username = 'x-access-token' if repo == 'keep.git' else 'owned'
        if expected is None or self.headers.get('Authorization') != 'Basic ' + base64.b64encode((username + ':' + expected).encode()).decode():
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="owned-secondary"')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        environment = dict(os.environ, GIT_PROJECT_ROOT=str(self.server.root), GIT_HTTP_EXPORT_ALL='1',
                           PATH_INFO=url.path, QUERY_STRING=url.query, REQUEST_METHOD=self.command,
                           CONTENT_TYPE=self.headers.get('Content-Type', ''), REMOTE_USER='owned',
                           CONTENT_LENGTH=self.headers.get('Content-Length', '0'))
        result = subprocess.run(['git', 'http-backend'], input=self.rfile.read(int(environment['CONTENT_LENGTH'])),
                                env=environment, capture_output=True, timeout=30)
        header, separator, body = result.stdout.partition(b'\r\n\r\n')
        if result.returncode or not separator:
            self.send_error(502, 'owned native Git backend failed')
            return
        headers = [line.decode().split(':', 1) for line in header.split(b'\r\n')]
        status = next((int(value.strip().split()[0]) for key, value in headers if key.lower() == 'status'), 200)
        self.send_response(status)
        for key, value in headers:
            if key.lower() != 'status':
                self.send_header(key, value.strip())
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = handle_git


class GitSecondaries(folders.Folders):
    def git_command(self, repo, *args):
        return self.command(['git', '-C', str(repo), *args]).stdout.decode().strip()

    def commit(self, repo, branch, files):
        for name, body in files.items():
            (repo / name).write_text(body)
        self.git_command(repo, 'add', '.')
        self.git_command(repo, '-c', 'user.name=Owned Fixture', '-c', 'user.email=owned@example.invalid', 'commit', '-m', branch)
        self.git_command(repo, 'branch', branch)
        return self.git_command(repo, 'rev-parse', 'HEAD')

    def fixture(self):
        root = self.state / 'git-fixture'
        root.mkdir()
        self.command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=host.docker.internal', '-addext', 'subjectAltName=DNS:host.docker.internal', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.crt')])
        (root / 'Dockerfile').write_text('FROM ' + base.TOOLKIT_IMAGE + '\nCOPY cert.crt /usr/local/share/ca-certificates/owned-secondary.crt\nRUN update-ca-certificates\n')
        self.git_image = self.prefix + ':git-secondary'
        self.image_tags.add(self.git_image)
        self.docker('build', '--pull=false', '--network=none', '-t', self.git_image, str(root))
        repositories = {}
        for name in ('primary', 'aux', 'keep', 'module'):
            repo = root / name
            self.command(['git', 'init', str(repo)])
            repositories[name] = repo
        module = self.commit(repositories['module'], 'module', {'module.txt': 'submodule\n'})
        primary_spec = {'version': '0.2', 'phases': {'build': {'commands': [
            'echo GIT_SECONDARY_READY', 'sleep ${HOLD:-0}',
            'cat "$CODEBUILD_SRC_DIR/value.txt" "$CODEBUILD_SRC_DIR_Aux/value.txt" "$CODEBUILD_SRC_DIR_Keep/value.txt" "$CODEBUILD_SRC_DIR_Aux/module/module.txt" > result.txt',
            'printf "%s\\n" "$CODEBUILD_SOURCE_VERSION" "$CODEBUILD_SOURCE_VERSION_Aux" "$CODEBUILD_SOURCE_VERSION_Keep" >> result.txt',
            'git -C "$CODEBUILD_SRC_DIR" rev-parse HEAD >> result.txt',
            'git -C "$CODEBUILD_SRC_DIR_Aux" rev-parse HEAD >> result.txt',
            'git -C "$CODEBUILD_SRC_DIR_Keep" rev-parse HEAD >> result.txt',
            'test "$(git -C "$CODEBUILD_SRC_DIR_Aux" rev-list --count HEAD)" = "${EXPECT_DEPTH:-1}"',
            'test -z "${GIT_SOURCE_PASSWORD:-}"',
            'test ! -e /codebuild/control/credential.sh'] }}, 'artifacts': {'files': ['result.txt']}}
        self.primary_spec = primary_spec
        self.primary_old = self.commit(repositories['primary'], 'primary', {'value.txt': 'primary\n', 'buildspec.yml': json.dumps(primary_spec)})
        self.primary_new = self.commit(repositories['primary'], 'next', {'value.txt': 'primary-next\n'})
        aux = repositories['aux']
        (aux / 'module').mkdir()
        (aux / '.gitmodules').write_text('[submodule "module"]\n\tpath = module\n\turl = ../module.git\n')
        self.git_command(aux, 'update-index', '--add', '--cacheinfo', '160000,' + module + ',module')
        self.aux_old = self.commit(aux, 'old', {'value.txt': 'aux-old\n', 'buildspec.yml': 'version: 0.2\nphases:\n  build:\n    commands: [exit 99]\n'})
        self.aux_new = self.commit(aux, 'new', {'value.txt': 'aux-new\n'})
        self.keep = self.commit(repositories['keep'], 'keep', {'value.txt': 'keep\n'})
        self.keep_default = self.commit(repositories['keep'], 'default', {'value.txt': 'keep-default\n'})
        for name, repo in repositories.items():
            self.command(['git', 'clone', '--bare', str(repo), str(root / (name + '.git'))])
        self.git = http.server.ThreadingHTTPServer(('0.0.0.0', 0), GitHTTP)
        self.git.root = root
        self.git.tokens = {'primary.git': 'fake-primary-token', 'aux.git': 'fake-aux-token', 'module.git': 'fake-aux-token', 'keep.git': 'fake-import-token'}
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / 'cert.crt', root / 'key.pem')
        self.git.socket = tls.wrap_socket(self.git.socket, server_side=True)
        threading.Thread(target=self.git.serve_forever, daemon=True).start()
        self.git_url = 'https://host.docker.internal:' + str(self.git.server_port)

    def import_credential(self):
        result = self.clients['codebuild'].import_source_credentials(serverType='GITLAB_SELF_MANAGED', authType='PERSONAL_ACCESS_TOKEN', token='fake-import-token', shouldOverwrite=True)
        self.source_credential_arn = result['arn']
        self.created.add('source_credential')

    def setup(self):
        self.role_arn = 'arn:aws:iam::' + base.ACCOUNT + ':role/' + self.role
        self.repository_arn = 'arn:aws:ecr:' + base.REGION + ':' + base.ACCOUNT + ':repository/unused'
        self.image = base.BASE_IMAGE
        self.setup_project()
        self.fixture()
        secrets = self.client('secretsmanager')
        self.secrets = []
        for suffix, token in [('primary', 'fake-primary-token'), ('aux', 'fake-aux-token'), ('override', 'fake-rotated-token')]:
            self.secrets.append(secrets.create_secret(Name=self.prefix + '-' + suffix, SecretString=json.dumps({'username': 'owned', 'password': token}))['ARN'])
        self.clients['iam'].put_role_policy(RoleName=self.role, PolicyName='git-source', PolicyDocument=base.policy([{'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': self.secrets}]))
        self.import_credential()
        self.sources = [
            {'type': 'GITHUB_ENTERPRISE', 'location': self.git_url + '/aux.git', 'sourceIdentifier': 'Aux', 'gitCloneDepth': 1, 'gitSubmodulesConfig': {'fetchSubmodules': True}, 'auth': {'type': 'SECRETS_MANAGER', 'resource': self.secrets[1]}, 'buildspec': 'secondary-must-not-run.yml'},
            {'type': 'GITLAB_SELF_MANAGED', 'location': self.git_url + '/keep.git/', 'sourceIdentifier': 'Keep', 'gitCloneDepth': 1}]
        self.versions = [{'sourceIdentifier': 'Aux', 'sourceVersion': 'refs/heads/old'}, {'sourceIdentifier': 'Keep', 'sourceVersion': 'refs/heads/keep'}]
        self.clients['codebuild'].update_project(name=self.project,
            source={'type': 'GITLAB_SELF_MANAGED', 'location': self.git_url + '/primary.git', 'gitCloneDepth': 1, 'auth': {'type': 'SECRETS_MANAGER', 'resource': self.secrets[0]}}, sourceVersion='refs/heads/primary',
            secondarySources=self.sources, secondarySourceVersions=self.versions,
            environment={'type': 'LINUX_CONTAINER', 'image': self.git_image, 'computeType': 'BUILD_GENERAL1_SMALL', 'imagePullCredentialsType': 'SERVICE_ROLE'})

    def expected(self, primary='primary', aux='old', default_keep=False):
        lines = [
            'primary-next' if primary == 'next' else 'primary', 'aux-' + aux,
            'keep-default' if default_keep else 'keep', 'submodule',
            'refs/heads/' + primary, 'refs/heads/' + aux, '' if default_keep else 'refs/heads/keep',
            self.primary_new if primary == 'next' else self.primary_old,
            self.aux_new if aux == 'new' else self.aux_old,
            self.keep_default if default_keep else self.keep]
        return ('\n'.join(lines) + '\n').encode()

    def success(self, label, primary='primary', aux='old', **kwargs):
        result = self.wait(self.begin(**kwargs)['id'], 'SUCCEEDED')
        digest = self.output(result, self.expected(primary, aux, default_keep='secondarySourcesVersionOverride' in kwargs))
        self.note(label, build_id=result['id'], sha256=digest, exact_source_bytes_and_revisions=True)
        return result

    def source_failure(self, label, **kwargs):
        result = self.failed_source(self.begin(**kwargs))
        contexts = [c.get('message', '') for p in result['phases'] for c in p.get('contexts', [])]
        for token in self.git.tokens.values():
            base.require(all(token not in message for message in contexts), 'source secret escaped error masking')
        self.note(label, build_id=result['id'], phase='DOWNLOAD_SOURCE', contexts=contexts)
        return result

    def exercise(self):
        cb, iam = self.clients['codebuild'], self.clients['iam']
        self.success('distinct_primary_secondary_refs_submodules_depth')
        self.success('independent_source_versions', primary='next', aux='new', sourceVersion='refs/heads/next', secondarySourcesVersionOverride=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'refs/heads/new'}])
        changed_sources = [dict(self.sources[0], gitCloneDepth=0), self.sources[1]]
        self.success('per_build_checkout_options', aux='new', secondarySourcesOverride=changed_sources, secondarySourcesVersionOverride=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'refs/heads/new'}], environmentVariablesOverride=[{'name': 'EXPECT_DEPTH', 'value': '2', 'type': 'PLAINTEXT'}])
        self.source_failure('missing_secondary_ref', secondarySourcesVersionOverride=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'refs/heads/missing-owned'}])
        self.git.tokens['aux.git'] = self.git.tokens['module.git'] = 'fake-rotated-token'
        self.source_failure('stale_secret_authentication_failure')
        auth_override = [dict(self.sources[0], auth={'type': 'SECRETS_MANAGER', 'resource': self.secrets[2]}), self.sources[1]]
        self.success('per_build_auth_override_recovery', secondarySourcesOverride=auth_override)
        base.require(cb.batch_get_projects(names=[self.project])['projects'][0]['secondarySources'] == self.sources, 'build auth override mutated project sources')
        self.client('secretsmanager').put_secret_value(SecretId=self.secrets[1], SecretString=json.dumps({'username': 'owned', 'password': 'fake-rotated-token'}))
        self.success('current_secret_rotation_recovery')
        self.created.add('deny_source')
        iam.put_role_policy(RoleName=self.role, PolicyName='deny-source', PolicyDocument=base.policy([{'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': self.secrets[1]}]))
        self.source_failure('current_secondary_secret_role_denial')
        iam.delete_role_policy(RoleName=self.role, PolicyName='deny-source')
        self.created.discard('deny_source')
        self.created.add('deny_source')
        iam.put_role_policy(RoleName=self.role, PolicyName='deny-source', PolicyDocument=base.policy([{'Effect': 'Deny', 'Action': 'kms:Decrypt', 'Resource': '*', 'Condition': {'StringEquals': {'kms:ViaService': 'codebuild.' + base.REGION + '.amazonaws.com'}}}]))
        self.source_failure('current_imported_credential_kms_denial')
        iam.delete_role_policy(RoleName=self.role, PolicyName='deny-source')
        self.created.discard('deny_source')
        cb.delete_source_credentials(arn=self.source_credential_arn)
        self.created.discard('source_credential')
        self.source_failure('deleted_imported_credential_denial')
        self.import_credential()
        self.success('restored_imported_credential_and_role_authority')
        retained = self.begin(secondarySourcesOverride=changed_sources, secondarySourcesVersionOverride=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'refs/heads/new'}], environmentVariablesOverride=[{'name': 'EXPECT_DEPTH', 'value': '2', 'type': 'PLAINTEXT'}, {'name': 'HOLD', 'value': '15', 'type': 'PLAINTEXT'}])
        self.wait(retained['id'], log_prefix='GIT_SECONDARY_READY')
        cb.update_project(name=self.project, secondarySourceVersions=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'future-missing'}, self.versions[1]])
        self.stop()
        self.start()
        result = self.wait(retained['id'], 'SUCCEEDED')
        digest = self.output(result, self.expected(aux='new', default_keep=True))
        base.require(result['secondarySources'] == changed_sources, 'restart lost accepted checkout options')
        base.require(result['secondarySourceVersions'] == [{'sourceIdentifier': 'Aux', 'sourceVersion': 'refs/heads/new'}], 'restart lost accepted version-list replacement')
        self.note('sqlite_active_container_and_accepted_git_options', build_id=result['id'], sha256=digest)
        cb.update_project(name=self.project, secondarySourceVersions=self.versions)
        self.success('fresh_post_restart_credentials_and_source')

    def cleanup(self):
        if getattr(self, 'git', None):
            self.git.shutdown()
            self.git.server_close()
        if getattr(self, 'secrets', None) and not self.args.keep_resources and self.process is not None and self.process.poll() is None:
            try:
                self.clients['iam'].delete_role_policy(RoleName=self.role, PolicyName='git-source')
                for secret in self.secrets:
                    self.client('secretsmanager').delete_secret(SecretId=secret, ForceDeleteWithoutRecovery=True)
            except Exception as error:
                self.cleanup_errors.append('delete owned Git secrets: ' + self.safe_error(error))
        super().cleanup()


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
    smoke = GitSecondaries(args, boto3, Config, ClientError)
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
