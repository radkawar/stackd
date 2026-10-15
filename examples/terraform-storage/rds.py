"""Native expansion of .stackd/rds-provider-proof/main.tf and report.json.

Invoked only by run.py; requires Terraform 1.15.9, AWS provider 6.68.0,
Python dependencies in examples/requirements.txt, host psql, Linux Docker at
unix:///var/run/docker.sock, and both preinstalled engine digests below. An
Oracle MySQL CLI is optional; the exact MySQL image supplies the fallback CLI.
PostgreSQL SQL verifies its exact native owner's public CA and hostname; MySQL
transport is unchanged. Managed AWS storage encryption, network isolation,
automated backups and physical GiB quotas are not claimed.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

import boto3
from botocore.config import Config

from local import client, environment, expect_missing, local_endpoint, require

POSTGRES_IMAGE = "postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
MYSQL_IMAGE = "mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d"
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
ENGINES = {"postgres": "17.11", "mysql": "8.4.11"}


def run(args, root, endpoint, terraform, variables, stages):
    """Return (verify(endpoint=None), cleanup(endpoint=None)) for shared restart.

    Terraform callable: terraform(command: list[str], cwd: Path, check=True).
    root is the runner-owned private RDS subdirectory. Reports exclude passwords,
    secret values, Terraform state/plan contents and sensitive SDK request bodies.
    """
    root = Path(root)
    root.chmod(0o700)
    namespace = "stackd-rds-" + hashlib.sha256(str(root.parent / "stackd.sqlite").encode()).hexdigest()[:24]
    local_endpoint(endpoint)
    require(shutil.which("psql"), "RDS native proof requires host psql")
    require(shutil.which("docker"), "RDS runtime requires Docker CLI and local daemon")
    shutil.copyfile(Path(__file__).with_name("rds.tf"), root / "main.tf")
    initial_password = secrets.token_hex(16)
    rotated_password = secrets.token_hex(16)
    config = {key: variables[key] for key in ("name", "endpoint", "region", "account_id")}
    config.update(capacity=20, revision="initial", snapshots=False, password=initial_password)
    outputs = None
    source_rows = "1|committed"
    native_sequence = 0

    def stage(name, **details):
        stages.append({"stage": "rds-" + name, "status": "passed", **details})

    def private_variables():
        path = root / "local.auto.tfvars.json"
        with open(path, "w", opener=lambda name, flags: os.open(name, flags, 0o600)) as file:
            json.dump(config, file)
        path.chmod(0o600)

    def tf(*command, check=True):
        return terraform(list(command), root, check=check)

    def read_outputs():
        return json.loads(tf("output", "-json", "rds").stdout)

    def no_change(label):
        for mode in ([], ["-refresh-only"]):
            result = tf("plan", *mode, "-input=false", "-no-color", "-detailed-exitcode", check=False)
            require(result.returncode == 0, f"RDS {label} {'refresh' if mode else 'plan'} changed: exit {result.returncode}")
        stage(label + "-no-change")

    def command(label, argv, env=None):
        nonlocal native_sequence
        native_sequence += 1
        result = subprocess.run(argv, env=env or environment(), cwd=root,
                                text=True, capture_output=True, timeout=120)
        prefix = root / f"native-{native_sequence:03d}-{label}"
        Path(str(prefix) + ".stdout").write_text(result.stdout)
        Path(str(prefix) + ".stderr").write_text(result.stderr)
        stages.append({"stage": "rds-command-" + label, "argv": argv,
                       "returncode": result.returncode,
                       "stdout": str(prefix) + ".stdout", "stderr": str(prefix) + ".stderr"})
        return result

    def postgres_ca(target):
        rds = client("rds", endpoint)
        if "writer" in target:
            state = rds.describe_db_clusters(DBClusterIdentifier=target["identifier"])["DBClusters"][0]
            native_id = state["DbClusterResourceId"].removeprefix("cluster-")
        else:
            state = rds.describe_db_instances(DBInstanceIdentifier=target["identifier"])["DBInstances"][0]
            native_id = state["DbiResourceId"].removeprefix("db-")
        identifiers = subprocess.check_output([*DOCKER, "ps", "-q", "--filter",
            "label=stackd.rds.namespace=" + namespace, "--filter", "label=stackd.rds.id=" + native_id,
            "--filter", "label=stackd.rds.role=database"], env=environment(), text=True).split()
        require(len(identifiers) == 1, "No exact-owned native PostgreSQL writer exists")
        # This Docker admin read exports only the public CA, never the private key.
        public_ca = subprocess.check_output([*DOCKER, "exec", identifiers[0], "cat",
            "/var/lib/postgresql/data/security/ca.pem"], env=environment())
        ca = root / (native_id + "-ca.pem")
        ca.write_bytes(public_ca)
        ca.chmod(0o600)
        return ca

    def sql(engine, target, text, password, label, denied=False, *, plaintext=False, policy_denied=False):
        require(target["host"] == "127.0.0.1" and 1024 <= target["port"] <= 65535,
                "Refusing non-loopback native database endpoint")
        env = {key: value for key, value in environment().items()
               if not key.startswith(("PG", "MYSQL"))}
        if engine == "postgres":
            env["PGPASSWORD"] = password
            env["PGSSLROOTCERT"] = str(postgres_ca(target))
            mode = "disable" if plaintext else "verify-full"
            argv = ["psql", "-XqAt", "-w", "-v", "ON_ERROR_STOP=1", "-d",
                    f"host=127.0.0.1 port={target['port']} user=lindm_admin dbname=proof sslmode={mode} connect_timeout=5",
                    "-c", text]
        else:
            env["MYSQL_PWD"] = password
            prefix = [shutil.which("mysql")] if shutil.which("mysql") else [
                *DOCKER, "run", "--rm", "--pull=never", "--network", "host", "--env", "MYSQL_PWD", MYSQL_IMAGE, "mysql"]
            argv = [*prefix, "--no-defaults", "--protocol=TCP", "--ssl-mode=DISABLED", "--get-server-public-key", "--connect-timeout=5",
                    "--host=127.0.0.1", f"--port={target['port']}", "--user=lindm_admin", "--database=proof",
                    "--batch", "--skip-column-names", "-e", text]
        result = command(label, argv, env)
        if policy_denied:
            require(result.returncode != 0 and "pg_hba.conf" in result.stderr,
                    f"{label}: plaintext was not rejected by native PostgreSQL admission")
        elif denied:
            marker = "password authentication failed" if engine == "postgres" else "Access denied for user"
            require(result.returncode != 0 and marker in result.stderr,
                    f"{label}: wrong credentials were not rejected by native authentication")
        else:
            require(result.returncode == 0, f"Native {label} failed; inspect retained stderr")
        return result.stdout.strip().replace("\t", "|")

    def retained(engine, target, expected, password, label):
        result = sql(engine, target, "SELECT id, note FROM capacity_proof ORDER BY id;", password, label)
        require(result == expected, f"{label}: committed/rolled-back rows differ: {result!r}")

    def native_setting(engine, target, label):
        query = "SHOW statement_timeout;" if engine == "postgres" else "SELECT @@SESSION.wait_timeout;"
        expected = ("7s" if config["revision"] == "initial" else "9s") if engine == "postgres" else (
            "7000" if config["revision"] == "initial" else "9000")
        require(sql(engine, target, query, config["password"], label) == expected,
                f"{label}: immediate parameter-group setting was not applied natively")

    def verify_data(current_endpoint, initialize=False):
        api = client("rds-data", current_endpoint)
        for engine, target in outputs["data"].items():
            params = dict(resourceArn=target["arn"], secretArn=target["secret"], database="proof")
            def execute(text, **kwargs):
                return api.execute_statement(**params, sql=text, **kwargs)
            if initialize:
                execute("CREATE TABLE data_proof (id INTEGER PRIMARY KEY, note VARCHAR(100) NOT NULL)")
                for row, commit in ((1, True), (2, False)):
                    transaction = api.begin_transaction(**params)["transactionId"]
                    execute("INSERT INTO data_proof VALUES (:id, :note)", transactionId=transaction,
                            parameters=[{"name": "id", "value": {"longValue": row}},
                                        {"name": "note", "value": {"stringValue": "committed" if commit else "rolled back"}}])
                    finish = api.commit_transaction if commit else api.rollback_transaction
                    finish(resourceArn=target["arn"], secretArn=target["secret"], transactionId=transaction)
                execute("INSERT INTO data_proof VALUES (:id, :note)", parameters=[
                    {"name": "id", "value": {"longValue": 3}},
                    {"name": "note", "value": {"stringValue": "bound ' SQL --"}}])
            result = execute("SELECT id, note FROM data_proof ORDER BY id", includeResultMetadata=True)
            require(result.get("records") == [[{"longValue": 1}, {"stringValue": "committed"}],
                                               [{"longValue": 3}, {"stringValue": "bound ' SQL --"}]],
                    "Real Data API commit/rollback/bound rows differ")
            require(len(result.get("columnMetadata", [])) == 2, "Data API omitted real SQL column metadata")
            require(sql(engine, target, "SELECT id, note FROM data_proof ORDER BY id;", config["password"],
                        "data-native-" + engine) == "1|committed\n3|bound ' SQL --",
                    "Data API and native SQL do not share the same real database")
        stage("data-api-retained", engines=list(ENGINES))

    def verify_authority(current_endpoint):
        iam = client("iam", current_endpoint)
        username = config["name"] + "-rds-data-consumer"
        key = None
        iam.create_user(UserName=username)
        try:
            key = iam.create_access_key(UserName=username)["AccessKey"]
            api = boto3.Session(aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"],
                                region_name=config["region"]).client("rds-data", endpoint_url=current_endpoint,
                                    config=Config(connect_timeout=3, read_timeout=30, proxies={}, retries={"max_attempts": 0}))
            policy = {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": "rds-data:ExecuteStatement",
                 "Resource": [target["arn"] for target in outputs["data"].values()]},
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
                 "Resource": [target["secret"] for target in outputs["data"].values()]},
            ]}
            iam.put_user_policy(UserName=username, PolicyName="current-data", PolicyDocument=json.dumps(policy))
            for target in outputs["data"].values():
                result = api.execute_statement(resourceArn=target["arn"], secretArn=target["secret"],
                                               database="proof", sql="SELECT COUNT(*) FROM data_proof")
                require(result.get("records") == [[{"longValue": 2}]], "Current scoped Data API consumer did not read real rows")
            policy["Statement"][0]["Effect"] = "Deny"
            iam.put_user_policy(UserName=username, PolicyName="current-data", PolicyDocument=json.dumps(policy))
            for target in outputs["data"].values():
                expect_missing(api.execute_statement, {"AccessDenied", "AccessDeniedException", "ForbiddenException"},
                               resourceArn=target["arn"], secretArn=target["secret"], database="proof",
                               sql="SELECT COUNT(*) FROM data_proof")
        finally:
            if key is not None:
                iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])
            for name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                iam.delete_user_policy(UserName=username, PolicyName=name)
            iam.delete_user(UserName=username)
        stage("data-api-current-iam-allow-then-revoked")

    def verify(current_endpoint=None):
        nonlocal outputs
        current_endpoint = local_endpoint(current_endpoint or endpoint)
        rds = client("rds", current_endpoint)
        for group in ("native", "restored", "data"):
            for target in outputs[group].values():
                identifier = target.get("writer", target["identifier"])
                rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=identifier,
                                                            WaiterConfig={"Delay": 1, "MaxAttempts": 240})
        outputs = read_outputs()
        for group, lookups in outputs["lookups"].items():
            for key, lookup in lookups.items():
                target = outputs[group][key]
                require(lookup == {field: target[field] for field in lookup},
                        "Terraform data source differs from managed/native owner: " + group + "/" + key)
        stage("terraform-data-source-matches-native-owners")
        expected_tags = {"Fixture": config["name"], "Revision": config["revision"]}
        for group in ("native", "restored"):
            for engine, target in outputs[group].items():
                db = rds.describe_db_instances(DBInstanceIdentifier=target["identifier"])["DBInstances"][0]
                require(db["AllocatedStorage"] == config["capacity"] == target["capacity"], "Requested GiB intent differs")
                require(db["MasterUsername"] == "lindm_admin" and db["EngineVersion"] == ENGINES[engine],
                        "Pinned engine/underscore username differs")
                require(not db.get("StorageEncrypted") and not db.get("VpcSecurityGroups")
                        and db.get("BackupRetentionPeriod", 0) == 0, "Unexpected managed encryption/network/backup claim")
                tags = {tag["Key"]: tag["Value"] for tag in rds.list_tags_for_resource(ResourceName=target["arn"])["TagList"]}
                require(tags == expected_tags, "RDS Terraform tags differ from owner state")
                retained(engine, target, source_rows if group == "native" else "1|committed", config["password"], group + "-retained-" + engine)
                native_setting(engine, target, group + "-setting-" + engine)
                sql(engine, target, "SELECT 1;", "definitely-wrong-password", group + "-wrong-password-" + engine, denied=True)
                if engine == "postgres":
                    verify_postgres_tls(target, group + "-tls")
        for target in outputs["snapshots"].values():
            snapshot = rds.describe_db_snapshots(DBSnapshotIdentifier=target["identifier"])["DBSnapshots"][0]
            require(snapshot["Status"] == "available" and snapshot["AllocatedStorage"] == 30,
                    "Manual physical snapshot lost capacity intent/readiness")
            attributes = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=target["identifier"])["DBSnapshotAttributesResult"]
            require(attributes["DBSnapshotAttributes"] == [{"AttributeName": "restore", "AttributeValues": []}],
                    "Manual snapshot unexpectedly has shared restore authority")
        verify_data(current_endpoint)
        verify_postgres_tls(outputs["data"]["postgres"], "aurora-tls")
        verify_authority(current_endpoint)
        no_change("retained")
        stage("native-retained", capacity_intent_gib=config["capacity"], physical_quota_claimed=False)

    def verify_postgres_tls(target, label):
        observed = sql("postgres", target,
            "SELECT ssl::text || '|' || version FROM pg_stat_ssl WHERE pid = pg_backend_pid();",
            config["password"], label)
        require(observed in ("true|TLSv1.2", "true|TLSv1.3"),
                f"{label}: native SQL did not negotiate verified TLS1.2/1.3: {observed!r}")
        # This is an explicit policy challenge, not a retry/fallback for SQL use.
        sql("postgres", target, "SELECT 1;", config["password"], label + "-plaintext",
            plaintext=True, policy_denied=config["revision"] == "initial")

    def verify_sdk_force_ssl_lifecycle():
        rds = client("rds", endpoint)
        for clustered, target in ((False, outputs["native"]["postgres"]), (True, outputs["data"]["postgres"])):
            group_name = config["name"] + ("-aurora-postgres" if clustered else "-postgres")
            group_key = "DBClusterParameterGroupName" if clustered else "DBParameterGroupName"
            modify = rds.modify_db_cluster_parameter_group if clustered else rds.modify_db_parameter_group
            reset = rds.reset_db_cluster_parameter_group if clustered else rds.reset_db_parameter_group
            describe = rds.describe_db_cluster_parameters if clustered else rds.describe_db_parameters
            group = {group_key: group_name}
            label = "aurora" if clustered else "postgres"
            writer = target.get("writer", target["identifier"])
            def ready():
                rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=writer,
                    WaiterConfig={"Delay": 1, "MaxAttempts": 240})
            def projection(source):
                return next(p for p in describe(**group, Source=source)["Parameters"]
                            if p["ParameterName"] == "rds.force_ssl")
            modify(**group, Parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "0",
                                        "ApplyMethod": "pending-reboot"}])
            require(projection("user")["ParameterValue"] == "0", "SDK lost deferred force_ssl intent")
            if clustered:
                state = rds.describe_db_clusters(DBClusterIdentifier=target["identifier"])["DBClusters"][0]
                status = state["DBClusterMembers"][0]["DBClusterParameterGroupStatus"]
            else:
                state = rds.describe_db_instances(DBInstanceIdentifier=writer)["DBInstances"][0]
                status = state["DBParameterGroups"][0]["ParameterApplyStatus"]
            require(status == "pending-reboot", "SDK did not retain the explicit pending-reboot policy")
            sql("postgres", target, "SELECT 1;", config["password"], label + "-before-reboot",
                plaintext=True, policy_denied=True)
            rds.reboot_db_instance(DBInstanceIdentifier=writer)
            ready()
            sql("postgres", target, "SELECT 1;", config["password"], label + "-after-reboot",
                plaintext=True)
            reset(**group, Parameters=[{"ParameterName": "rds.force_ssl", "ApplyMethod": "immediate"}])
            ready()
            default = projection("system")
            require(default["ParameterValue"] == "1" and default["ApplyType"] == "dynamic"
                    and default["DataType"] == "boolean" and default["AllowedValues"] == "0,1",
                    "SDK reset did not expose the pinned real native force_ssl default")
            verify_postgres_tls(target, label + "-after-reset")
            # Restore the explicitly declared Terraform override without hiding drift.
            modify(**group, Parameters=[{"ParameterName": "rds.force_ssl", "ParameterValue": "1",
                                        "ApplyMethod": "immediate"}])
            ready()
        no_change("sdk-force-ssl-restored")
        stage("sdk-force-ssl-pending-reboot-reset-defaults", families=["postgres17", "aurora-postgresql17"])

    def cleanup(current_endpoint=None):
        current_endpoint = local_endpoint(current_endpoint or endpoint)
        tf("destroy", "-input=false", "-auto-approve", "-no-color", "-parallelism=2")
        rds = client("rds", current_endpoint)
        for engine in ENGINES:
            for identifier in (f"{config['name']}-{engine}", f"{config['name']}-{engine}-restored",
                               f"{config['name']}-aurora-{engine}-writer"):
                expect_missing(rds.describe_db_instances, {"DBInstanceNotFound"}, DBInstanceIdentifier=identifier)
            expect_missing(rds.describe_db_clusters, {"DBClusterNotFoundFault"},
                           DBClusterIdentifier=f"{config['name']}-aurora-{engine}")
            expect_missing(rds.describe_db_snapshots, {"DBSnapshotNotFound"},
                           DBSnapshotIdentifier=f"{config['name']}-{engine}-manual")
            expect_missing(client("secretsmanager", current_endpoint).describe_secret, {"ResourceNotFoundException"},
                           SecretId=f"{config['name']}-{engine}-data")
        state = json.loads(tf("show", "-json").stdout)
        require(not state.get("values", {}).get("root_module", {}).get("resources"), "RDS Terraform state is not empty")
        stage("destroyed")

    private_variables()
    images = command("image-prerequisites", [*DOCKER, "image", "inspect", POSTGRES_IMAGE, MYSQL_IMAGE,
                                             "--format", "{{json .RepoDigests}} {{.Id}}"])
    require(images.returncode == 0, "Preinstall the two exact RDS engine digests; runtime and CLI never pull")
    tf("init", "-input=false", "-no-color")
    try:
        tf("apply", "-input=false", "-auto-approve", "-no-color", "-parallelism=2")
        # The cluster is read before its native writer exists. Record the
        # completed topology once, then keep the strict no-change plans below.
        tf("apply", "-refresh-only", "-input=false", "-auto-approve", "-no-color")
        outputs = read_outputs()
        for engine, target in outputs["native"].items():
            version = "SELECT current_setting('server_version');" if engine == "postgres" else "SELECT VERSION();"
            require(sql(engine, target, version, initial_password, "version-" + engine).split()[0].split("-", 1)[0] == ENGINES[engine],
                    "Native engine is not the exact pinned version")
            sql(engine, target, "CREATE TABLE capacity_proof (id INTEGER PRIMARY KEY, note VARCHAR(100) NOT NULL); "
                "BEGIN; INSERT INTO capacity_proof VALUES (1, 'committed'); COMMIT; "
                "BEGIN; INSERT INTO capacity_proof VALUES (2, 'rolled back'); ROLLBACK;", initial_password, "transactions-" + engine)
        verify_data(endpoint, initialize=True)
        verify()
        verify_sdk_force_ssl_lifecycle()
        stage("initial-20-gib-proof")
        config.update(capacity=30, revision="updated", password=rotated_password)
        private_variables()
        tf("apply", "-input=false", "-auto-approve", "-no-color", "-parallelism=2")
        outputs = read_outputs()
        for group in ("native", "data"):
            for engine, target in outputs[group].items():
                sql(engine, target, "SELECT 1;", initial_password, group + "-old-password-" + engine, denied=True)
        verify()
        stage("rotation-immediate-parameters-tags-30-gib")
        # Re-import standalone instances, groups and real clusters/writers into
        # a separate state: never forget the lifecycle owner's primary state.
        imports = root / "imports"
        imports.mkdir(mode=0o700)
        shutil.copyfile(root / "main.tf", imports / "main.tf")
        shutil.copyfile(root / "local.auto.tfvars.json", imports / "local.auto.tfvars.json")
        (imports / "local.auto.tfvars.json").chmod(0o600)
        terraform(["init", "-input=false", "-no-color"], imports)
        for engine in ENGINES:
            for resource, identifier in (("aws_db_instance.native", outputs["native"][engine]["identifier"]),
                                         ("aws_db_parameter_group.native", f"{config['name']}-{engine}"),
                                         ("aws_rds_cluster.data", outputs["data"][engine]["identifier"]),
                                         ("aws_secretsmanager_secret.data", outputs["data"][engine]["secret"]),
                                         ("aws_secretsmanager_secret_version.data",
                                          outputs["data"][engine]["secret"] + "|" + client("secretsmanager", endpoint).get_secret_value(
                                              SecretId=outputs["data"][engine]["secret"])["VersionId"]),
                                         ("aws_rds_cluster_instance.writer", outputs["data"][engine]["writer"])):
                terraform(["import", "-input=false", f'{resource}["{engine}"]', identifier], imports)
        terraform(["import", "-input=false", "aws_rds_cluster_parameter_group.data",
                   config["name"] + "-aurora-postgres"], imports)
        refresh = terraform(["plan", "-refresh-only", "-input=false", "-detailed-exitcode", "-no-color",
                             "-out=import-refresh.tfplan"], imports, check=False)
        require(refresh.returncode in (0, 2), "Imported native resource refresh failed")
        # Import does not populate root outputs. Commit those observations only;
        # never apply a normal plan from the secondary ownership view.
        terraform(["apply", "-input=false", "-auto-approve", "import-refresh.tfplan"], imports)
        refresh = terraform(["plan", "-refresh-only", "-input=false", "-detailed-exitcode", "-no-color"], imports, check=False)
        require(refresh.returncode == 0, "Repeated imported native resource refresh changed state")
        addresses = [f'{resource}["{engine}"]' for engine in ENGINES for resource in (
            "aws_db_instance.native", "aws_db_parameter_group.native", "aws_rds_cluster.data",
            "aws_rds_cluster_instance.writer", "aws_secretsmanager_secret.data", "aws_secretsmanager_secret_version.data")]
        addresses.append("aws_rds_cluster_parameter_group.data")
        terraform(["state", "rm", *addresses], imports)
        stage("independent-import-refresh", password_readback_claimed=False)
        config["snapshots"] = True
        private_variables()
        tf("apply", "-input=false", "-auto-approve", "-no-color", "-parallelism=2")
        outputs = read_outputs()
        for engine, target in outputs["native"].items():
            sql(engine, target, "INSERT INTO capacity_proof VALUES (3, 'after snapshot');", rotated_password, "post-snapshot-" + engine)
        source_rows = "1|committed\n3|after snapshot"
        verify()
        stage("manual-physical-snapshot-restore-isolation")
    except BaseException:
        # Setup failures still release all resources already adopted by Terraform.
        cleanup(endpoint)
        raise
    return verify, cleanup
