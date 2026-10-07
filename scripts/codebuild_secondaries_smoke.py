#!/usr/bin/env python3
"""Run signed local CodeBuild S3 secondary-source/artifact workflows on real Docker.

Uses the existing ecr_codebuild_smoke.py local-only lifecycle. Supply a parent-built
stackd, installed busybox/toolkit images, and a fresh stackd-buildowner state dir.
No AWS requests, image downloads, or standing resources are used.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import zipfile

spec = importlib.util.spec_from_file_location("build_smoke", Path(__file__).with_name("ecr_codebuild_smoke.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as output:
        for name, data in files.items():
            output.writestr(name, data)
    return buffer.getvalue()


class Secondaries(base.Smoke):
    def artifact(self, identifier, name, packaging="ZIP"):
        return {"type": "S3", "location": self.bucket, "path": "outputs",
                "name": name, "packaging": packaging, "namespaceType": "NONE",
                "artifactIdentifier": identifier}

    def setup(self):
        self.role_arn = "arn:aws:iam::" + base.ACCOUNT + ":role/" + self.role
        self.repository_arn = "arn:aws:ecr:" + base.REGION + ":" + base.ACCOUNT + ":repository/unused"
        self.image = base.BASE_IMAGE
        self.setup_project()
        s3, cb = self.clients["s3"], self.clients["codebuild"]
        s3.put_bucket_versioning(Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"})
        self.versioned = True
        buildspec = {"version": "0.2", "phases": {"build": {"commands": [
            "echo SECONDARY_READY", "sleep ${HOLD:-0}",
            'cat "$CODEBUILD_SRC_DIR/primary.txt" "$CODEBUILD_SRC_DIR_Aux/aux.txt" "$CODEBUILD_SRC_DIR_Keep/keep.txt" > result.txt',
            'mkdir -p "$CODEBUILD_SRC_DIR_Aux/output"',
            'tr a-z A-Z < result.txt > "$CODEBUILD_SRC_DIR_Aux/output/secondary.txt"',
            'test -d "$CODEBUILD_SRC_DIR/empty" && test -d "$CODEBUILD_SRC_DIR_Aux/empty"']}},
            "artifacts": {"files": ["result.txt"], "secondary-artifacts": {
                "Extra": {"base-directory": "$CODEBUILD_SRC_DIR_Aux/output", "files": ["secondary.txt"], "name": "expanded-$OUTPUT_NAME.zip"},
                "Raw": {"base-directory": "$CODEBUILD_SRC_DIR_Aux/output", "files": ["secondary.txt"]}}}}
        self.buildspec = buildspec
        s3.put_object(Bucket=self.bucket, Key="source.zip", Body=archive({"primary.txt": "primary\n", "empty/": "", "buildspec.yml": json.dumps(buildspec)}))
        self.old = s3.put_object(Bucket=self.bucket, Key="aux.zip", Body=archive({"aux.txt": "old\n", "empty/": "", "buildspec.yml": "this secondary buildspec must not run"}))["VersionId"]
        self.new = s3.put_object(Bucket=self.bucket, Key="aux.zip", Body=archive({"aux.txt": "new\n", "empty/": ""}))["VersionId"]
        self.keep = s3.put_object(Bucket=self.bucket, Key="keep.zip", Body=archive({"keep.txt": "kept\n"}))["VersionId"]
        self.alternate = s3.put_object(Bucket=self.bucket, Key="alternate.zip", Body=archive({"aux.txt": "alternate\n", "empty/": ""}))["VersionId"]
        self.sources = [{"type": "S3", "location": self.bucket + "/aux.zip", "sourceIdentifier": "Aux", "buildspec": "exit 99"},
                        {"type": "S3", "location": self.bucket + "/keep.zip", "sourceIdentifier": "Keep"}]
        self.versions = [{"sourceIdentifier": "Aux", "sourceVersion": self.old}, {"sourceIdentifier": "Keep", "sourceVersion": self.keep}]
        self.artifacts_config = [self.artifact("Extra", "secondary.zip"), self.artifact("Raw", "raw", "NONE")]
        cb.update_project(name=self.project, secondarySources=self.sources,
                          secondarySourceVersions=self.versions, secondaryArtifacts=self.artifacts_config)
        self.assert_project(self.sources, self.versions, self.artifacts_config)

    def assert_project(self, sources, versions, artifacts):
        project = self.clients["codebuild"].batch_get_projects(names=[self.project])["projects"][0]
        base.require(project["secondarySources"] == sources and project["secondarySourceVersions"] == versions
                     and project["secondaryArtifacts"] == artifacts, "project secondary config differs")

    def begin(self, **overrides):
        build = self.clients["codebuild"].start_build(projectName=self.project, **overrides)["build"]
        self.build_ids.append(build["id"])
        return build

    def consume(self, result, expected, extra_key="outputs/secondary.zip", raw=True):
        base.require(result["buildStatus"] == "SUCCEEDED", "consumer received failed build")
        primary = result["artifacts"]
        secondaries = {row["artifactIdentifier"]: row for row in result["secondaryArtifacts"]}
        for metadata, key, member, body in [(primary, "artifacts/default.zip", "result.txt", expected),
                                            (secondaries["Extra"], extra_key, "secondary.txt", expected.upper())]:
            actual = self.clients["s3"].get_object(Bucket=self.bucket, Key=key)["Body"].read()
            base.require(metadata["location"] == "arn:aws:s3:::" + self.bucket + "/" + key, "wrong artifact location")
            base.require(metadata["md5sum"] == hashlib.md5(actual).hexdigest()
                         and metadata["sha256sum"] == hashlib.sha256(actual).hexdigest(), "artifact checksum differs from S3 bytes")
            with zipfile.ZipFile(io.BytesIO(actual)) as output:
                base.require(output.namelist() == [member] and output.read(member) == body, "independent ZIP consumer got wrong bytes")
        if raw:
            metadata = secondaries["Raw"]
            base.require(metadata["location"].endswith("/outputs/raw") and "md5sum" not in metadata and "sha256sum" not in metadata,
                         "unpackaged artifact metadata wrong")
            body = self.clients["s3"].get_object(Bucket=self.bucket, Key="outputs/raw/secondary.txt")["Body"].read()
            base.require(body == expected.upper(), "unpackaged consumer got wrong bytes")
        else:
            base.require(set(secondaries) == {"Extra"}, "artifact override did not replace project list")

    def exercise(self):
        cb, iam = self.clients["codebuild"], self.clients["iam"]
        first = self.begin()
        first = self.wait(first["id"], "SUCCEEDED")
        self.consume(first, b"primary\nold\nkept\n")
        base.require(first["secondarySourceVersions"] == self.versions, "build lost project versions")
        self.note("project_versions", build_id=first["id"], status=first["buildStatus"], primary_and_secondary_zip_checksums=True, unpackaged_bytes=True, empty_source_directories=True)

        override = self.artifact("Extra", "ignored.zip")
        override["overrideArtifactName"] = True
        current_keep = self.clients["s3"].put_object(Bucket=self.bucket, Key="keep.zip", Body=archive({"keep.txt": "kept-current\n"}))["VersionId"]
        second = self.begin(secondarySourcesVersionOverride=[{"sourceIdentifier": "Aux", "sourceVersion": self.new}],
                            secondaryArtifactsOverride=[override], environmentVariablesOverride=[{"name": "OUTPUT_NAME", "value": "override", "type": "PLAINTEXT"}])
        second = self.wait(second["id"], "SUCCEEDED")
        self.consume(second, b"primary\nnew\nkept-current\n", "outputs/expanded-override.zip", raw=False)
        self.assert_project(self.sources, self.versions, self.artifacts_config)
        base.require(second["secondarySourceVersions"] == [{"sourceIdentifier": "Aux", "sourceVersion": self.new}], "version override did not replace the project version list")
        self.note("version_and_artifact_overrides", build_id=second["id"], independently_consumed_bytes=True, project_unchanged=True)
        self.clients["s3"].delete_object(Bucket=self.bucket, Key="keep.zip", VersionId=current_keep)

        reduced_spec = json.loads(json.dumps(self.buildspec))
        commands = reduced_spec["phases"]["build"]["commands"]
        commands[2] = 'cat "$CODEBUILD_SRC_DIR/primary.txt" "$CODEBUILD_SRC_DIR_Aux/aux.txt" > result.txt'
        commands.append('test -z "${CODEBUILD_SRC_DIR_Keep:-}"')
        reduced = self.begin(secondarySourcesOverride=[self.sources[0]], buildspecOverride=json.dumps(reduced_spec))
        reduced = self.wait(reduced["id"], "SUCCEEDED")
        self.consume(reduced, b"primary\nold\n")
        base.require(reduced["secondarySourceVersions"] == [self.versions[0]] and reduced["secondarySources"] == [self.sources[0]],
                     "source override did not replace the project list and its version associations")
        self.assert_project(self.sources, self.versions, self.artifacts_config)
        self.note("source_list_replacement", build_id=reduced["id"], omitted_source_not_installed=True, project_unchanged=True)

        alternate_sources = [dict(self.sources[0], location=self.bucket + "/alternate.zip"), self.sources[1]]
        retained_artifact = self.artifact("Extra", "retained.zip")
        retained = self.begin(secondarySourcesOverride=alternate_sources,
                              secondarySourcesVersionOverride=[{"sourceIdentifier": "Aux", "sourceVersion": self.alternate}],
                              secondaryArtifactsOverride=[retained_artifact], environmentVariablesOverride=[{"name": "HOLD", "value": "15", "type": "PLAINTEXT"}])
        self.wait(retained["id"], log_prefix="SECONDARY_READY")
        cb.update_project(name=self.project, secondarySourceVersions=[{"sourceIdentifier": "Aux", "sourceVersion": self.new}, self.versions[1]],
                          secondaryArtifacts=[self.artifact("Extra", "changed-project.zip")])
        self.stop()
        self.start()
        retained = self.wait(retained["id"], "SUCCEEDED")
        self.consume(retained, b"primary\nalternate\nkept\n", "outputs/retained.zip", raw=False)
        base.require(retained["secondarySources"] == alternate_sources, "restart changed accepted source override")
        cb.update_project(name=self.project, secondarySourceVersions=self.versions, secondaryArtifacts=self.artifacts_config)
        self.note("sqlite_active_build_restart", build_id=retained["id"], accepted_config_survived_project_mutation=True, actual_output_checksums=True)

        for overrides in ({"secondarySourcesVersionOverride": [{"sourceIdentifier": "Missing", "sourceVersion": self.old}]},
                          {"secondarySourcesVersionOverride": [self.versions[0], self.versions[0]]},
                          {"secondarySourcesOverride": [self.sources[0], self.sources[0]]},
                          {"secondaryArtifactsOverride": [self.artifacts_config[0], self.artifacts_config[0]]}):
            try:
                self.begin(**overrides)
            except self.client_error as error:
                base.require(error.response["Error"]["Code"] == "InvalidInputException", "wrong override rejection code")
            else:
                raise RuntimeError("invalid secondary override accepted")

        deny = lambda action, key: base.policy([{"Effect": "Deny", "Action": action, "Resource": "arn:aws:s3:::" + self.bucket + "/" + key}])
        self.created.add("deny_source")
        iam.put_role_policy(RoleName=self.role, PolicyName="deny-source", PolicyDocument=deny("s3:GetObjectVersion", "aux.zip"))
        denied = self.begin()
        denied = self.wait(denied["id"], "FAILED")
        base.require(not denied.get("secondaryArtifacts"), "denied source fabricated output")
        iam.delete_role_policy(RoleName=self.role, PolicyName="deny-source")
        self.created.discard("deny_source")
        self.note("current_secondary_read_denial", build_id=denied["id"], status=denied["buildStatus"])

        denied_write = self.begin(secondaryArtifactsOverride=[self.artifact("Extra", "denied-write.zip")],
                                  environmentVariablesOverride=[{"name": "HOLD", "value": "5", "type": "PLAINTEXT"}])
        self.wait(denied_write["id"], log_prefix="SECONDARY_READY")
        self.created.add("deny_source")
        iam.put_role_policy(RoleName=self.role, PolicyName="deny-source", PolicyDocument=deny("s3:PutObject", "outputs/denied-write.zip"))
        denied_write = self.wait(denied_write["id"], "FAILED")
        base.require(not denied_write.get("secondaryArtifacts"), "denied secondary publication fabricated metadata")
        try:
            self.clients["s3"].get_object(Bucket=self.bucket, Key="outputs/denied-write.zip")
        except self.client_error as error:
            base.require(error.response["Error"]["Code"] == "NoSuchKey", "wrong absent output error")
        else:
            raise RuntimeError("IAM-denied secondary object was published")
        iam.delete_role_policy(RoleName=self.role, PolicyName="deny-source")
        self.created.discard("deny_source")
        restored = self.begin()
        restored = self.wait(restored["id"], "SUCCEEDED")
        self.consume(restored, b"primary\nold\nkept\n")
        self.stop()
        self.start()
        base.require(self.build(restored["id"])["secondaryArtifacts"] == restored["secondaryArtifacts"], "restart lost build output evidence")
        self.note("current_secondary_write_denial_and_restore", denied_build_id=denied_write["id"], restored_build_id=restored["id"], sqlite_output_evidence=True)

    def cleanup(self):
        if getattr(self, "versioned", False) and not self.args.keep_resources and self.process is not None and self.process.poll() is None:
            try:
                s3 = self.clients["s3"]
                for page in s3.get_paginator("list_object_versions").paginate(Bucket=self.bucket):
                    for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                        s3.delete_object(Bucket=self.bucket, Key=item["Key"], VersionId=item["VersionId"])
            except Exception as error:
                self.cleanup_errors.append("delete owned source versions: " + self.safe_error(error))
        super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--keep-resources", action="store_true")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock", choices=["unix:///var/run/docker.sock"])
    args = parser.parse_args()
    args.ecr_scanner = None
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    os.umask(0o077)
    smoke = Secondaries(args, boto3, Config, ClientError)
    passed = False
    try:
        smoke.prepare()
        smoke.start()
        smoke.setup()
        smoke.exercise()
        passed = True
    except Exception as error:
        if smoke.owns_state:
            smoke.note("failure", error=smoke.safe_error(error))
        else:
            print(smoke.safe_error(error), file=sys.stderr)
    finally:
        smoke.cleanup()
    if smoke.owns_state:
        smoke.note("result", passed=passed and not smoke.cleanup_errors, cleanup_errors=smoke.cleanup_errors)
    return 0 if passed and not smoke.cleanup_errors else 1


if __name__ == "__main__":
    sys.exit(main())
