"""Run isolated Terraform 1.15.9 / AWS 6.68.0 storage lifecycles and real consumers.

Prerequisites: build bin/stackd separately; install Python boto3 and Terraform
1.15.9; prepare an AWS 6.68.0 filesystem provider mirror. S3/EBS direct blocks
need no QEMU. DynamoDB requires local Linux Docker, unix:///var/run/docker.sock,
and the installed pinned DynamoDB Local image listed in limits.json (no pulls).
RDS additionally needs host psql and the installed pinned PostgreSQL/MySQL images;
mysql CLI is optional (pinned Docker client fallback). DocDB needs pymongo plus
its installed Mongo image. The controller must reach Docker-published loopback
ports. No AWS credentials, paid AWS probes or reused controllers occur.
Retained run directories are private and include tfstate/password material; share
only report.json, never tfstate, tfvars or logs. limits.json inventories are
UNVERIFIED: only actually executed report stages are evidence. Destruction targets
only this uniquely owned SQLite installation and its Terraform resources.
"""
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import ACCOUNT, REGION, arguments, controller, environment, require, workspace


def main():
    parser = arguments(__doc__, 14704)
    parser.add_argument('--services', default='s3,dynamodb,ebs', help='Comma-separated s3,dynamodb,ebs,rds; or standalone docdb (manual backup/expiry time)')
    parser.add_argument('--provider-mirror', type=Path, required=True, help='Prepared AWS provider 6.68.0 filesystem mirror; direct downloads disabled')
    args = parser.parse_args()
    selected = args.services.split(',')
    require(selected and len(selected) == len(set(selected)) and set(selected) <= {'s3', 'dynamodb', 'ebs', 'rds', 'docdb'}, 'Select unique supported services')
    require(shutil.which('terraform'), 'Install Terraform 1.15.9 first')
    require(args.provider_mirror.is_dir(), 'Provider mirror directory does not exist')
    root = workspace(args, 'terraform-storage')
    root.chmod(0o700)
    config = root / 'terraform.rc'
    require('docdb' not in selected or selected == ['docdb'],
            'DocDB must run alone (--services docdb): its daily backup/expiry scenarios use manual service time; other cohorts use wall time')
    config.write_text('disable_checkpoint = true\nprovider_installation {\n filesystem_mirror {\n path = ' + json.dumps(str(args.provider_mirror.resolve())) + '\n include = ["registry.terraform.io/hashicorp/aws"]\n }\n}\n')
    env = environment()
    env['TF_CLI_CONFIG_FILE'] = str(config)
    report = {'terraform': '1.15.9', 'provider': '6.68.0', 'provider_source_revision': 'c9b83d813022cdd05fc955480b07e269c6e18023', 'services': selected, 'status': 'running', 'stages': [], 'commands': [], 'inventory_defaults': 'unverified'}
    stages = report['stages']

    def terraform(command, cwd, check=True):
        result = subprocess.run(['terraform', *command], cwd=cwd, env=env, text=True, capture_output=True)
        prefix = Path(cwd) / f"terraform-{len(report['commands']):03d}-{command[0]}"
        for suffix, text in ((".stdout", result.stdout), (".stderr", result.stderr)):
            path = Path(str(prefix) + suffix)
            path.write_text(text)
            path.chmod(0o600)
        report['commands'].append({'command': ['terraform', *command], 'workspace': Path(cwd).name, 'returncode': result.returncode})
        # Never echo provider output: it may contain a database password.
        if check:
            require(result.returncode == 0, f'Terraform {command[0]} failed (exit {result.returncode}); private workspace: {cwd}')
        return result

    def docker(command):
        result = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', *command], env=env, text=True, capture_output=True, check=True)
        report['commands'].append({'command': ['docker', '--host', 'unix:///var/run/docker.sock', *command], 'returncode': result.returncode})
        return result.stdout

    def database_labels():
        labels = set()
        for identifier in docker(['ps', '-aq', '--filter', 'label=stackd.dynamodb.id']).split():
            info = json.loads(docker(['inspect', identifier]))[0]
            labels.add(info['Config']['Labels']['stackd.dynamodb.id'])
        for identifier in docker(['volume', 'ls', '-q', '--filter', 'label=stackd.dynamodb.id']).split():
            info = json.loads(docker(['volume', 'inspect', identifier]))[0]
            labels.add(info['Labels']['stackd.dynamodb.id'])
        return labels

    native = bool(set(selected) & {'dynamodb', 'rds', 'docdb'})
    extra = []
    if native:
        require(shutil.which('docker'), 'Install Docker and native pinned images described in limits.json')
        extra = ['-docker-host', 'unix:///var/run/docker.sock']
    for service in ('dynamodb', 'rds', 'docdb'):
        if service in selected:
            extra.append('-' + service + '-runtime')
    if 'docdb' in selected:
        extra.extend(['-clock-start', '2031-01-01T08:59:00Z'])
    name = 'stackd-storage-' + uuid.uuid4().hex[:12]
    callbacks = []
    owned_ddb = set()
    baseline_ddb = database_labels() if 'dynamodb' in selected else set()
    suffix = hashlib.sha256(str(root / 'stackd.sqlite').encode()).hexdigest()[:24]

    def cleanup_modules(endpoint):
        errors = []
        for _, cleanup in reversed(callbacks):
            try:
                cleanup(endpoint)
            except BaseException as error:
                errors.append(error)
        callbacks.clear()
        if errors:
            raise errors[0]

    try:
        version = json.loads(terraform(['version', '-json'], root).stdout)
        require(version['terraform_version'] == '1.15.9', 'Fixture requires exact Terraform 1.15.9')
        with controller(args, root, extra=extra) as endpoint:
            variables = {'name': name, 'endpoint': endpoint, 'region': REGION, 'account_id': ACCOUNT}
            try:
                modules = []
                if set(selected) & {'s3', 'dynamodb', 'ebs'}:
                    modules.append('data')
                modules.extend(service for service in ('rds', 'docdb') if service in selected)
                for module_name in modules:
                    directory = root / module_name
                    directory.mkdir(mode=0o700)
                    module = importlib.import_module(module_name)
                    callbacks.append(module.run(args, directory, endpoint, terraform, variables, stages))
                if 'dynamodb' in selected:
                    owned_ddb = database_labels() - baseline_ddb
                    require(owned_ddb, 'No owned real DynamoDB native database labels found')
            except BaseException:
                cleanup_modules(endpoint)
                raise
        with controller(args, root, extra=extra) as endpoint:
            try:
                for verify, _ in callbacks:
                    verify(endpoint)
                stages.append({'stage': 'sqlite-controller-reopen-native-consumers', 'status': 'passed'})
            finally:
                cleanup_modules(endpoint)
            # Native deletion is asynchronous; wait only on exactly owned labels.
            deadline = time.monotonic() + 90
            while native:
                leftovers = []
                labels = ['stackd.dynamodb.id=' + identifier for identifier in owned_ddb]
                labels.extend('stackd.' + service + '.namespace=stackd-' + service + '-' + suffix for service in ('rds', 'docdb') if service in selected)
                for label in labels:
                    leftovers.extend(docker(['ps', '-aq', '--filter', 'label=' + label]).split())
                    leftovers.extend(docker(['volume', 'ls', '-q', '--filter', 'label=' + label]).split())
                if not leftovers:
                    break
                require(time.monotonic() < deadline, 'Owned Docker containers/volumes remain: ' + ','.join(leftovers))
                time.sleep(0.5)
            if native:
                stages.append({'stage': 'exact-owned-native-container-volume-cleanup', 'status': 'passed'})
        report['status'] = 'passed'
    except BaseException as error:
        report['status'] = 'failed'
        # Error text can contain native credentials; retain only its type.
        report['error_type'] = type(error).__name__
        raise
    finally:
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Completed actual storage stages; controller stopped. Retained private artifacts:', root)


if __name__ == '__main__':
    main()
