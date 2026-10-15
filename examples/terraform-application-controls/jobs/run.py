"""Terraform 6.68.0 application job controls with independent signed SDK consumers.

Prerequisites: built bin/stackd, Terraform 1.15.9, examples/requirements.txt.
Control/Step Functions/S3 pipeline mode (no Docker):
  python examples/terraform-application-controls/jobs/run.py --port 14731
Offline provider installation:
  ... --provider-mirror /absolute/path/to/provider-mirror
Actual CodeBuild processes and S3 -> CodeBuild -> S3 artifact consumption:
  docker build -t local/stackd-jobs:prepared /path/to/prepared-context
  docker image inspect --format '{{.Id}}' local/stackd-jobs:prepared
  ... --docker --build-image sha256:THE_INSTALLED_IMAGE_ID --port 14732

The prepared Linux image must contain /bin/sh and python3 on PATH (Python 3.14
is suitable); no network packages, image pulls, or AWS account are needed. Docker
must be the explicitly selected local Engine, with the runtime host prerequisites
in docs/runtime-containers.md. The controller binds all interfaces only in the
explicit Docker mode; use a dedicated trusted host. No build is started in the
non-Docker mode, and project lifecycle does not imply execution support.
All state, plans and logs stay in a private uniquely owned retained workspace.
"""

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile

from botocore.exceptions import ClientError
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local import (arguments, client, controller, environment, expect_missing,
                   require, workspace)


def await_value(fetch, complete, label, seconds=180):
    deadline = time.monotonic() + seconds
    while True:
        value = fetch()
        if complete(value):
            return value
        require(time.monotonic() < deadline, f"Timed out waiting for {label}: {value}")
        time.sleep(0.25)


def object_bytes(s3, bucket, key):
    body = s3.get_object(Bucket=bucket, Key=key)["Body"]
    try:
        return body.read()
    finally:
        body.close()


def archive_bytes(payload):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        # Fixed timestamp makes unchanged source content stable across updates.
        entry = zipfile.ZipInfo("payload.bin", (2026, 1, 1, 0, 0, 0))
        archive.writestr(entry, payload)
    return base64.b64encode(data.getvalue()).decode()


def verify_workflow(sfn, outputs, arn, revision):
    payload = "independent-worker-" + uuid.uuid4().hex
    execution = sfn.start_execution(stateMachineArn=arn, name="worker-" + uuid.uuid4().hex,
                                    input=json.dumps({"payload": payload}))["executionArn"]
    token = None
    submitted = False
    try:
        task = await_value(
            lambda: sfn.get_activity_task(activityArn=outputs["activity"], workerName="terraform-real-worker"),
            lambda task: bool(task.get("taskToken")), "actual activity lease")
        token = task["taskToken"]
        request = json.loads(task["input"])
        require(request == {"revision": revision, "payload": payload},
                f"Published workflow admitted different worker input: {request}")
        # This client is the real activity worker: it consumes the task input,
        # computes a result, heartbeats, and completes the actual leased token.
        sfn.send_task_heartbeat(taskToken=token)
        result = {"revision": request["revision"],
                  "sha256": hashlib.sha256(request["payload"].encode()).hexdigest()}
        sfn.send_task_success(taskToken=token, output=json.dumps(result))
        submitted = True
        finished = await_value(lambda: sfn.describe_execution(executionArn=execution),
                               lambda row: row["status"] != "RUNNING", "workflow execution")
        require(finished["status"] == "SUCCEEDED" and json.loads(finished["output"]) == result,
                f"Actual activity result did not reach workflow output: {finished}")
        events = []
        for page in sfn.get_paginator("get_execution_history").paginate(executionArn=execution):
            events.extend(page["events"])
        require(any(event["type"] == "ActivitySucceeded" for event in events),
                "Successful workflow lacks an activity completion event")
        return {"execution": execution, "qualified_machine": arn, "result": result,
                "history_events": len(events)}
    finally:
        if token and not submitted:
            sfn.send_task_failure(taskToken=token, error="FixtureConsumerFailure")
        current = sfn.describe_execution(executionArn=execution)
        if current["status"] == "RUNNING":
            sfn.stop_execution(executionArn=execution, error="FixtureCleanup")


def verify_controls(endpoint, outputs, revision):
    sfn, build, pipeline = (client(service, endpoint) for service in
                            ("stepfunctions", "codebuild", "codepipeline"))
    for field in ("machine", "activity", "alias"):
        require(outputs["lookups"][field] == outputs[field], f"Data source identity differs: {field}")
    versions = sfn.list_state_machine_versions(stateMachineArn=outputs["machine"])["stateMachineVersions"]
    require([version["stateMachineVersionArn"] for version in versions] == outputs["lookups"]["versions"],
            "Version data source differs from independent SDK list")
    require(outputs["version"] == versions[0]["stateMachineVersionArn"], "Provider did not expose latest version")
    alias = sfn.describe_state_machine_alias(stateMachineAliasArn=outputs["alias"])
    require(alias["routingConfiguration"] == [{"stateMachineVersionArn": outputs["version"], "weight": 100}],
            "Alias did not route to Terraform's published version")
    require(alias["description"] == f"Live worker {revision}", "Alias description update missing")
    activity_tags = sfn.list_tags_for_resource(resourceArn=outputs["activity"])["tags"]
    require({tag["key"]: tag["value"] for tag in activity_tags} == {"Revision": revision},
            "Activity tag lifecycle missing")
    machine = sfn.describe_state_machine(stateMachineArn=outputs["machine"])
    require(json.loads(machine["definition"])["States"]["Prepare"]["Parameters"]["revision"] == revision,
            "State machine definition update missing")
    projects = build.batch_get_projects(names=[outputs["project_arn"], outputs["pipeline_project_arn"]])["projects"]
    require(len(projects) == 2, "Project ARN reads did not resolve both projects")
    for project in projects:
        require({tag["key"]: tag["value"] for tag in project.get("tags", [])} == {"Revision": revision},
                "Project tags did not update")
        if project["name"] == outputs["project"]:
            require(project.get("concurrentBuildLimit") == (2 if revision == "v1" else None),
                    "Removing project concurrent limit did not restore absence")
    declaration = pipeline.get_pipeline(name=outputs["pipeline"])["pipeline"]
    deploy = declaration["stages"][-1]["actions"][0]
    require(deploy["configuration"]["ObjectKey"] == revision, "Pipeline definition update missing")
    return declaration["version"]


def verify_pipeline(endpoint, outputs, revision, payload, docker):
    pipeline, s3, build = (client(service, endpoint) for service in ("codepipeline", "s3", "codebuild"))
    execution = pipeline.start_pipeline_execution(name=outputs["pipeline"], clientRequestToken=uuid.uuid4().hex)["pipelineExecutionId"]
    finished = await_value(
        lambda: pipeline.get_pipeline_execution(pipelineName=outputs["pipeline"], pipelineExecutionId=execution)["pipelineExecution"],
        lambda row: row["status"] not in ("InProgress", "Stopping"), "pipeline artifact execution", 300)
    require(finished["status"] == "Succeeded", f"Pipeline did not consume real artifacts: {finished}")
    details = []
    for page in pipeline.get_paginator("list_action_executions").paginate(
            pipelineName=outputs["pipeline"], filter={"pipelineExecutionId": execution}):
        details.extend(page["actionExecutionDetails"])
    require(len(details) == (3 if docker else 2) and all(row["status"] == "Succeeded" for row in details),
            f"Missing successful action history: {details}")
    expected = payload + b"|built:" + revision.encode() if docker else payload
    member = "result.bin" if docker else "payload.bin"
    retained = []
    for action in details:
        for artifact in action.get("output", {}).get("outputArtifacts", []):
            location = artifact["s3location"]
            raw = object_bytes(s3, location["bucket"], location["key"])
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                is_build = action["stageName"] == "Build"
                actual = archive.read("result.bin" if is_build else "payload.bin")
                require(actual == (expected if is_build else payload), "Retained pipeline artifact bytes differ")
            retained.append({"bucket": location["bucket"], "key": location["key"],
                             "sha256": hashlib.sha256(raw).hexdigest()})
        if action["stageName"] == "Build":
            build_id = action["output"]["executionResult"]["externalExecutionId"]
            actual_build = build.batch_get_builds(ids=[build_id])["builds"]
            require(len(actual_build) == 1 and actual_build[0]["buildStatus"] == "SUCCEEDED",
                    "Pipeline build handle does not identify a successful actual CodeBuild process")
    actual = object_bytes(s3, outputs["buckets"]["destination"], revision + "/" + member)
    require(actual == expected, "Independent S3 consumer received incorrect deployed bytes")
    return {"execution": execution, "pipeline_name": outputs["pipeline"],
            "destination_bucket": outputs["buckets"]["destination"],
            "docker_build": docker, "artifacts": retained,
            "actions": [{"stage": row["stageName"], "action": row["actionName"],
                         "status": row["status"],
                         "external_execution": row.get("output", {}).get("executionResult", {}).get("externalExecutionId")}
                        for row in details],
            "destination_key": revision + "/" + member,
            "destination_sha256": hashlib.sha256(actual).hexdigest(), "destination_bytes": len(actual)}


def verify_build(endpoint, outputs, revision):
    build, s3 = client("codebuild", endpoint), client("s3", endpoint)
    started = build.start_build(projectName=outputs["project"], idempotencyToken=uuid.uuid4().hex)["build"]
    try:
        finished = await_value(lambda: build.batch_get_builds(ids=[started["id"]])["builds"][0],
                               lambda row: row.get("buildComplete", False), "actual standalone build", 300)
        require(finished["buildStatus"] == "SUCCEEDED", f"Real build process failed: {finished}")
        location = finished["artifacts"]["location"]
        require(location.startswith("arn:aws:s3:::"), f"Unexpected artifact owner: {location}")
        bucket, key = location.removeprefix("arn:aws:s3:::").split("/", 1)
        require(bucket == outputs["buckets"]["build"], "Build artifact escaped its owned bucket")
        raw = object_bytes(s3, bucket, key)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            actual = archive.read("result.bin")
        require(actual == b"stackd actual build\x00\xff:" + revision.encode(),
                "Standalone build artifact does not contain actual process-produced bytes")
        return {"build": started["id"], "artifact": location,
                "artifact_sha256": hashlib.sha256(raw).hexdigest(),
                "sha256": hashlib.sha256(actual).hexdigest(), "bytes": len(actual),
                "phases": [{"phase": phase["phaseType"], "status": phase.get("phaseStatus"),
                            "contexts": phase.get("contexts", [])} for phase in finished.get("phases", [])]}
    finally:
        current = build.batch_get_builds(ids=[started["id"]])["builds"][0]
        if not current.get("buildComplete", False):
            build.stop_build(id=started["id"])


def verify_retained_consumers(endpoint, revisions):
    """Read pre-shutdown execution history and artifact bytes from reopened SQLite."""
    sfn, pipeline, build, s3 = (client(service, endpoint) for service in
                                ("stepfunctions", "codepipeline", "codebuild", "s3"))
    retained = {"workflows": [], "pipelines": [], "builds": []}
    for revision in revisions.values():
        for key, consumer in revision.items():
            if key.endswith("workflow"):
                finished = sfn.describe_execution(executionArn=consumer["execution"])
                require(finished["status"] == "SUCCEEDED" and json.loads(finished["output"]) == consumer["result"],
                        "Reopen lost a completed activity result")
                events = []
                for page in sfn.get_paginator("get_execution_history").paginate(executionArn=consumer["execution"]):
                    events.extend(page["events"])
                require(len(events) == consumer["history_events"]
                        and any(event["type"] == "ActivitySucceeded" for event in events),
                        "Reopen changed retained activity history")
                retained["workflows"].append(consumer["execution"])
            elif key == "pipeline":
                row = pipeline.get_pipeline_execution(
                    pipelineName=consumer["pipeline_name"],
                    pipelineExecutionId=consumer["execution"])["pipelineExecution"]
                require(row["status"] == "Succeeded", "Reopen lost a completed pipeline")
                for artifact in consumer["artifacts"]:
                    raw = object_bytes(s3, artifact["bucket"], artifact["key"])
                    require(hashlib.sha256(raw).hexdigest() == artifact["sha256"],
                            "Reopen changed retained pipeline ZIP bytes")
                actual = object_bytes(s3, consumer["destination_bucket"], consumer["destination_key"])
                require(len(actual) == consumer["destination_bytes"]
                        and hashlib.sha256(actual).hexdigest() == consumer["destination_sha256"],
                        "Reopen changed deployed consumer bytes")
                retained["pipelines"].append(consumer["execution"])
            elif key == "build":
                rows = build.batch_get_builds(ids=[consumer["build"]])["builds"]
                require(len(rows) == 1 and rows[0]["buildStatus"] == "SUCCEEDED"
                        and rows[0]["buildComplete"], "Reopen lost a completed actual build")
                bucket, object_key = consumer["artifact"].removeprefix("arn:aws:s3:::").split("/", 1)
                raw = object_bytes(s3, bucket, object_key)
                require(hashlib.sha256(raw).hexdigest() == consumer["artifact_sha256"],
                        "Reopen changed standalone build ZIP bytes")
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    actual = archive.read("result.bin")
                require(len(actual) == consumer["bytes"]
                        and hashlib.sha256(actual).hexdigest() == consumer["sha256"],
                        "Reopen changed standalone process-produced bytes")
                retained["builds"].append(consumer["build"])
    return retained


def stop_admitted_work(endpoint, name):
    pipeline, build = client("codepipeline", endpoint), client("codebuild", endpoint)
    stopped = {"pipelines": [], "builds": []}
    try:
        summaries = []
        for page in pipeline.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
            summaries.extend(page.get("pipelineExecutionSummaries", []))
        for summary in summaries:
            if summary["status"] in ("InProgress", "Stopping"):
                pipeline.stop_pipeline_execution(pipelineName=name,
                                                 pipelineExecutionId=summary["pipelineExecutionId"], abandon=True)
                await_value(lambda: pipeline.get_pipeline_execution(
                    pipelineName=name, pipelineExecutionId=summary["pipelineExecutionId"])["pipelineExecution"],
                    lambda row: row["status"] not in ("InProgress", "Stopping"), "pipeline cleanup")
                stopped["pipelines"].append(summary["pipelineExecutionId"])
    except ClientError as error:
        require(error.response["Error"]["Code"] == "PipelineNotFoundException", str(error))
    for project in (name + "-standalone", name + "-pipeline"):
        try:
            ids = []
            for page in build.get_paginator("list_builds_for_project").paginate(projectName=project):
                ids.extend(page.get("ids", []))
            for build_id in ids:
                row = build.batch_get_builds(ids=[build_id])["builds"][0]
                if not row.get("buildComplete", False):
                    build.stop_build(id=build_id)
                    await_value(lambda: build.batch_get_builds(ids=[build_id])["builds"][0],
                                lambda current: current.get("buildComplete", False), "build cleanup")
                    stopped["builds"].append(build_id)
        except ClientError as error:
            require(error.response["Error"]["Code"] == "ResourceNotFoundException", str(error))
    return stopped


def main():
    parser = arguments(__doc__, 14731)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--docker", action="store_true", help="Opt in to actual prepared CodeBuild containers")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--build-image", help="Installed immutable sha256 image ID or repository@sha256 digest; requires sh and python3")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install Terraform 1.15.9 first")
    require(not args.build_image or args.docker, "--build-image requires explicit --docker")
    if args.docker:
        require(args.build_image and re.fullmatch(r"(?:sha256:|[^\s]+@sha256:)[0-9a-f]{64}", args.build_image),
                "--docker requires --build-image with an already installed immutable image ID/digest")
    root = workspace(args, "terraform-jobs")
    root.chmod(0o700)
    shutil.copyfile(Path(__file__).with_name("main.tf"), root / "main.tf")
    env = environment()
    config = "disable_checkpoint = true\n"
    if args.provider_mirror:
        require(args.provider_mirror.is_dir(), "Provider mirror directory does not exist")
        config += ("provider_installation {\n  filesystem_mirror {\n    path = "
                   + json.dumps(str(args.provider_mirror.resolve()))
                   + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
    (root / "terraform.rc").write_text(config)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
    evidence = {"provider": "6.68.0", "docker": args.docker,
                "controller": str(args.stackd.resolve()), "port": args.port,
                "workspace": str(root), "stages": [], "terraform": [], "revisions": {}}
    strict_failures = []

    def save_evidence():
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")

    def stage(name):
        evidence["stages"].append(name)
        save_evidence()
        print("Stage:", name, flush=True)

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        result = subprocess.run(["terraform", *command], cwd=root, env=env,
                                text=True, capture_output=True, check=False)
        filename = f"terraform-{len(evidence['terraform']) + 1:03d}.log"
        (root / filename).write_text(result.stdout + result.stderr)
        evidence["terraform"].append({"command": list(command), "exit": result.returncode, "log": filename})
        save_evidence()
        if not capture:
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", file=sys.stderr, flush=True)
        if check:
            result.check_returncode()
        return result

    def outputs():
        return json.loads(terraform("output", "-json", "jobs", capture=True).stdout)
    def require_clean_plan(planned, filename):
        plan = json.loads(terraform("show", "-json", filename, capture=True).stdout)
        (root / (filename + ".json")).write_text(json.dumps(plan, indent=2) + "\n")
        evidence.setdefault("plans", {})[filename] = {
            "exit": planned.returncode, "applyable": plan["applyable"],
            "resource_drift": plan.get("resource_drift", []),
            "resource_changes": plan.get("resource_changes", []),
            "output_changes": plan.get("output_changes", {})}
        try:
            require(planned.returncode == 0, f"Expected clean {filename}, exit {planned.returncode}")
        except RuntimeError as error:
            # Preserve this strict failure and fail the run after ordinary
            # teardown, while still exercising independent reopened consumers.
            strict_failures.append(error)
            evidence.setdefault("strict_failures", []).append(str(error))
            print("Strict assertion failed (run will fail after cleanup):", error, flush=True)
        save_evidence()


    extra = ["-docker-host", args.docker_host, "-codebuild-runtime"] if args.docker else []
    with contextlib.ExitStack() as controllers:
        endpoint = controllers.enter_context(controller(args, root, extra=extra, containers=args.docker))
        variables = {"endpoint": endpoint, "name": "stackd-jobs-" + uuid.uuid4().hex[:12],
                     "docker": args.docker, "build_image": args.build_image or "python:3.14.5-slim-trixie"}
        payloads = {revision: b"stackd pipeline source\x00\xff:" + revision.encode() for revision in ("v1", "v2")}

        def configure(revision):
            variables.update(revision=revision, source_zip=archive_bytes(payloads[revision]))
            (root / "local.auto.tfvars.json").write_text(json.dumps(variables))

        evidence["owned"] = {"name": variables["name"],
                             "projects": [variables["name"] + "-standalone", variables["name"] + "-pipeline"],
                             "buckets": [variables["name"] + "-" + key
                                         for key in ("source", "artifacts", "destination", "build")]}
        configure("v1")
        stage("initialize")
        current = None
        try:
            terraform("init", "-input=false")
            stage("create_v1")
            terraform("apply", "-input=false", "-auto-approve")
            current = outputs()
            evidence["outputs_v1"] = current
            stage("consumers_v1")
            original_version = current["version"]
            original_pipeline_version = verify_controls(endpoint, current, "v1")
            evidence["revisions"]["v1"] = {
                "workflow": verify_workflow(client("stepfunctions", endpoint), current, current["alias"], "v1"),
                "pipeline": verify_pipeline(endpoint, current, "v1", payloads["v1"], args.docker)}
            if args.docker:
                evidence["revisions"]["v1"]["build"] = verify_build(endpoint, current, "v1")
            # Import the actual resources, never manufacture tfstate IDs. Versions
            # are owned by state_machine.publish, not a separate provider resource.
            imports = {
                "aws_codebuild_project.standalone": current["project_arn"],
                "aws_codebuild_project.pipeline": current["pipeline_project_arn"],
                "aws_codepipeline.jobs": current["pipeline"],
                "aws_sfn_state_machine.jobs": current["machine"],
                "aws_sfn_activity.worker": current["activity"],
                "aws_sfn_alias.live": current["alias"],
            }
            evidence["imports"] = imports
            stage("native_id_import")
            for address, identifier in imports.items():
                terraform("state", "rm", address)
                terraform("import", "-input=false", address, identifier)
            terraform("apply", "-input=false", "-auto-approve")
            require(outputs() == current, "Native ID import changed resource identities or lookup outputs")
            stage("update_v2")
            configure("v2")
            terraform("apply", "-input=false", "-auto-approve")
            current = outputs()
            evidence["outputs_v2"] = current
            require(current["version"] != original_version, "Definition update did not publish a new immutable version")
            updated_pipeline_version = verify_controls(endpoint, current, "v2")
            require(updated_pipeline_version > original_pipeline_version,
                    "Pipeline update did not advance the retained definition version")
            # Commit computed state after import/update before independently
            # requiring refresh-only and normal plans to have empty diffs.
            stage("reconcile_computed_state")
            terraform("apply", "-refresh-only", "-input=false", "-auto-approve")
            require(outputs() == current, "Computed-state reconciliation changed control identities or versions")
            stage("consumers_v2")
            sfn = client("stepfunctions", endpoint)
            evidence["revisions"]["v2"] = {
                "workflow": verify_workflow(sfn, current, current["alias"], "v2"),
                "unqualified_workflow": verify_workflow(sfn, current, current["machine"], "v2"),
                "retained_v1_workflow": verify_workflow(sfn, current, original_version, "v1"),
                "pipeline": verify_pipeline(endpoint, current, "v2", payloads["v2"], args.docker)}
            if args.docker:
                evidence["revisions"]["v2"]["build"] = verify_build(endpoint, current, "v2")
            stage("refresh_and_noop")
            for options, filename in [(('-refresh-only',), "refresh.tfplan"), ((), "noop.tfplan")]:
                planned = terraform("plan", *options, "-input=false", "-detailed-exitcode", "-out=" + filename, check=False)
                require_clean_plan(planned, filename)
                if options:
                    terraform("apply", "-input=false", "-auto-approve", filename)
            require(outputs() == current, "Refresh changed Terraform's resource identities or lookup outputs")
            stage("stop_controller")
            controllers.close()
            shutil.copyfile(root / "stackd.log", root / "stackd-before-reopen.log")
            evidence["controller_logs"] = ["stackd-before-reopen.log", "stackd.log"]
            stage("reopen_sqlite")
            endpoint = controllers.enter_context(controller(args, root, extra=extra, containers=args.docker))
            require(outputs() == current, "SQLite reopen changed Terraform's retained control identities")
            require(verify_controls(endpoint, current, "v2") == updated_pipeline_version,
                    "SQLite reopen changed the retained updated pipeline definition version")
            require(original_version in current["lookups"]["versions"],
                    "SQLite reopen lost the old immutable workflow publication")
            evidence["retained_after_reopen"] = verify_retained_consumers(endpoint, evidence["revisions"])
            stage("fresh_consumers_after_reopen")
            sfn = client("stepfunctions", endpoint)
            evidence["reopen"] = {
                "workflow": verify_workflow(sfn, current, current["alias"], "v2"),
                "unqualified_workflow": verify_workflow(sfn, current, current["machine"], "v2"),
                "retained_v1_workflow": verify_workflow(sfn, current, original_version, "v1"),
                "pipeline": verify_pipeline(endpoint, current, "v2", payloads["v2"], args.docker)}
            if args.docker:
                evidence["reopen"]["build"] = verify_build(endpoint, current, "v2")
            planned = terraform("plan", "-input=false", "-detailed-exitcode", "-out=reopen-noop.tfplan", check=False)
            require_clean_plan(planned, "reopen-noop.tfplan")
            require(outputs() == current, "Fresh reopened consumers changed Terraform control outputs")
            save_evidence()
        except Exception as error:
            evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
            save_evidence()
            raise
        finally:
            # Abandon does not cancel an admitted CodeBuild. Await both owners'
            # terminal statuses before removing their roles and artifact buckets.
            stage("stop_admitted_work")
            evidence["cleanup"] = stop_admitted_work(endpoint, variables["name"])
            stage("ordinary_terraform_destroy")
            terraform("destroy", "-input=false", "-auto-approve")
            evidence["cleanup"]["terraform_destroy_exit"] = 0
            save_evidence()
            if current:
                stage("signed_absence")
                sfn = client("stepfunctions", endpoint)
                expect_missing(sfn.describe_state_machine, {"StateMachineDoesNotExist"}, stateMachineArn=current["machine"])
                expect_missing(sfn.describe_state_machine_alias, {"ResourceNotFound"}, stateMachineAliasArn=current["alias"])
                expect_missing(sfn.describe_activity, {"ActivityDoesNotExist"}, activityArn=current["activity"])
                expect_missing(client("codepipeline", endpoint).get_pipeline, {"PipelineNotFoundException"}, name=current["pipeline"])
                remaining = client("codebuild", endpoint).batch_get_projects(names=[current["project_arn"], current["pipeline_project_arn"]])
                require(not remaining.get("projects"), "Destroyed CodeBuild projects still resolve")
                for bucket in current["buckets"].values():
                    expect_missing(client("s3", endpoint).head_bucket, {"404", "NoSuchBucket", "NotFound"}, Bucket=bucket)
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            require(not state.get("values", {}).get("root_module", {}).get("resources"),
                    "Terraform state retains resources after destroy")
            evidence["cleanup"]["signed_absence"] = bool(current)
            evidence["cleanup"]["empty_terraform_state"] = True
            evidence["cleanup"]["retained_owned_resources"] = []
            stage("cleanup_complete")
        if strict_failures:
            evidence["failure"] = {"type": type(strict_failures[0]).__name__,
                                   "message": str(strict_failures[0])}
            stage("failed_strict_plan_assertions")
            raise strict_failures[0]
        stage("complete")
    print(f"Jobs lifecycle and actual consumers complete. Owned artifacts: {root}", flush=True)


if __name__ == "__main__":
    main()
