#!/usr/bin/env python3
"""Real QEMU/ASG/EC2/k3s managed-worker lifecycle, packet and restart proof.

Requires two explicit offline firmware images (k3s 1.32.8 and 1.33.4), prepared
with eks_worker_image.py and the workload/official Pod Identity OCI archives.
Nothing is downloaded into guests. The controller, AWS CLI, kubectl, QEMU and
Docker are the actual installed executables; no fake worker or AWS responses.
"""
import argparse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import ssl
import subprocess
import sys
import time
import threading
import uuid
import urllib.request

from botocore.exceptions import ClientError
from ec2_launch_template_smoke import Smoke as FirmwareSmoke
from ssm_managed_guest_smoke import REGION

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from eks_podidentity_smoke import exercise_pod_identity


class Smoke(FirmwareSmoke):
    def __init__(self, args):
        super().__init__(args)
        self.account = args.account or f"{uuid.uuid4().int % 10**12:012d}"
        self.prefix = "stackd-eks-worker-" + uuid.uuid4().hex[:10]
        self.data.update(account=self.account, prefix=self.prefix, source=__doc__.splitlines()[0])
        self.controller_args = ["-eks-k3d", str(args.k3d), "-eks-state-directory", str(self.state / "kubernetes"),
                                "-eks-worker-advertise-host", args.worker_advertise_host]
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith("AWS_") and k != "KUBECONFIG"}
        self.environment.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION=REGION,
                                AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="", AWS_CA_BUNDLE=str(self.state / "server.crt"),
                                AWS_CONFIG_FILE=str(self.state / "aws-config"), AWS_SHARED_CREDENTIALS_FILE=str(self.state / "aws-credentials"),
                                KUBECONFIG=str(self.state / "kubeconfig"))
        self.owned.update(images={}, snapshots={}, instances=[], volumes=[], enis=[], managedTemplates=[], managedProfiles=[])
        self.save()

    def command(self, argv, stdin=None, success=True, timeout=180):
        process = subprocess.run(argv, env=self.environment, input=stdin, text=True, capture_output=True, timeout=timeout)
        if success and process.returncode:
            raise RuntimeError(f"{argv[:4]}: {process.stderr[-5000:]}")
        if not success and process.returncode == 0:
            raise AssertionError(f"Expected failure: {argv[:4]}")
        # Projected tokens and credential exports stay ephemeral, never in evidence.
        return process.stdout if success else process.stderr

    def kube(self, *args, stdin=None, success=True):
        return self.command(["kubectl", "--request-timeout=90s", *args], stdin, success)

    def kube_json(self, *args):
        return json.loads(self.kube(*args, "-o", "json"))

    def restart(self):
        self.stop()
        self.start()
        self.wait("Kubernetes proxy reattached", self.kubernetes_version, bool, 120)

    def kubernetes_version(self):
        result = subprocess.run(["kubectl", "--request-timeout=5s", "get", "--raw", "/version"],
                                env=self.environment, text=True, capture_output=True, timeout=15)
        return json.loads(result.stdout) if result.returncode == 0 else {}

    def import_version(self, minor, raw):
        original_prefix, original_image = self.prefix, self.args.raw_image
        try:
            self.prefix, self.args.raw_image = original_prefix + "-" + minor.replace(".", "-"), raw
            self.import_image()
            self.owned["images"][minor] = self.owned.pop("image")
            self.owned["snapshots"][minor] = self.owned.pop("snapshot")
            self.data["observations"]["imageImport" + minor] = self.data["observations"].pop("image_import")
            self.save()
        finally:
            self.prefix, self.args.raw_image = original_prefix, original_image

    def publish_images(self):
        releases = {"1.32":"v1.32.8+k3s1", "1.33":"v1.33.4+k3s1"}
        image_map = {minor:{"imageId":image, "releaseVersion":releases[minor], "amiType":"CUSTOM"}
                     for minor, image in self.owned["images"].items()}
        path = self.state / "eks-node-images.json"
        path.write_text(json.dumps(image_map) + "\n")
        if "-eks-node-images" not in self.controller_args:
            self.controller_args.extend(["-eks-node-images", str(path)])
        self.stop()
        self.start()
        self.data["observations"]["publicWorkerImageMap"] = image_map
        self.save()
        return image_map

    def nodegroup(self):
        return self.client("eks").describe_nodegroup(clusterName=self.owned["cluster"], nodegroupName="workers")["nodegroup"]

    def active_workers(self, count, minor):
        group = self.nodegroup()
        if group["status"] in ("CREATE_FAILED", "DEGRADED", "DELETE_FAILED"):
            raise RuntimeError("Managed worker failure: " + json.dumps(group.get("health")))
        if group["status"] != "ACTIVE":
            return None
        workers = self.kube_json("get", "nodes", "-l", "eks.amazonaws.com/nodegroup=workers")["items"]
        if len(workers) != count:
            return None
        if any(not n["status"]["nodeInfo"]["kubeletVersion"].startswith("v" + minor + ".") or
               not any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"]) for n in workers):
            return None
        asg_name = group["resources"]["autoScalingGroups"][0]["name"]
        asg = self.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        actual_ids = {i["InstanceId"] for i in asg["Instances"] if i["LifecycleState"] == "InService"}
        if {n["metadata"]["name"] for n in workers} != actual_ids:
            return None
        self.owned["asg"] = asg_name
        template = asg["LaunchTemplate"]
        self.remember("managedTemplates", template["LaunchTemplateId"])
        version = self.client("ec2").describe_launch_template_versions(LaunchTemplateId=template["LaunchTemplateId"], Versions=[template["Version"]])["LaunchTemplateVersions"][0]
        profile = version["LaunchTemplateData"]["IamInstanceProfile"]
        self.remember("managedProfiles", profile.get("Name") or profile["Arn"].rsplit("/", 1)[-1])
        reservations = self.client("ec2").describe_instances(InstanceIds=sorted(actual_ids))["Reservations"] if actual_ids else []
        instances = {i["InstanceId"]: i for r in reservations for i in r["Instances"]}
        for node in workers:
            instance = instances[node["metadata"]["name"]]
            assert instance["State"]["Name"] == "running"
            assert instance["ImageId"] == self.owned["images"][minor]
            assert node["spec"]["providerID"] == f"aws:///{instance['Placement']['AvailabilityZone']}/{instance['InstanceId']}"
            assert any(a["type"] == "InternalIP" and a["address"] == instance["PrivateIpAddress"] for a in node["status"]["addresses"])
            self.remember("instances", instance["InstanceId"])
            for volume in instance.get("BlockDeviceMappings", []):
                self.remember("volumes", volume["Ebs"]["VolumeId"])
            for interface in instance.get("NetworkInterfaces", []):
                self.remember("enis", interface["NetworkInterfaceId"])
        self.save()
        return workers

    def remember(self, kind, value):
        if value not in self.owned[kind]:
            self.owned[kind].append(value)

    def capture_worker_inventory(self):
        o = self.owned
        instances, volumes, interfaces = [], [], []
        if o.get("nodegroupID"):
            reservations = self.client("ec2").describe_instances(Filters=[{"Name":"tag:eks", "Values":[o["nodegroupID"]]}])["Reservations"]
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    self.remember("instances", instance["InstanceId"])
                    instances.append(instance["InstanceId"])
                    for mapping in instance.get("BlockDeviceMappings", []):
                        self.remember("volumes", mapping["Ebs"]["VolumeId"])
                    for interface in instance.get("NetworkInterfaces", []):
                        self.remember("enis", interface["NetworkInterfaceId"])
        snapshots = set(o["snapshots"].values())
        for volume in self.client("ec2").describe_volumes()["Volumes"]:
            if volume.get("SnapshotId") in snapshots:
                self.remember("volumes", volume["VolumeId"])
                volumes.append(volume["VolumeId"])
        if o.get("vpc"):
            for interface in self.client("ec2").describe_network_interfaces(Filters=[{"Name":"vpc-id", "Values":[o["vpc"]]}])["NetworkInterfaces"]:
                self.remember("enis", interface["NetworkInterfaceId"])
                interfaces.append(interface["NetworkInterfaceId"])
        return {"nodegroupID":o.get("nodegroupID"), "allHistoricalInstances":sorted(instances),
                "retainedImageRootVolumes":sorted(volumes), "retainedVpcInterfaces":sorted(interfaces)}

    def wait_update(self, update):
        def state():
            value = self.client("eks").describe_update(name=self.owned["cluster"], nodegroupName="workers", updateId=update["id"])["update"]
            if value["status"] in ("Failed", "Cancelled"):
                raise RuntimeError(json.dumps(value, default=str))
            return value
        return self.wait("managed update successful", state, lambda v: v["status"] == "Successful", 1200, 3)

    def update_config(self, **kwargs):
        request = dict(clusterName=self.owned["cluster"], nodegroupName="workers", clientRequestToken=uuid.uuid4().hex, **kwargs)
        result = self.call("update-worker-config", "eks", "update_nodegroup_config", **request)["update"]
        expected = {}
        fields = {"labels":{"addOrUpdateLabels":"LabelsToAdd", "removeLabels":"LabelsToRemove"},
                  "taints":{"addOrUpdateTaints":"TaintsToAdd", "removeTaints":"TaintsToRemove"},
                  "scalingConfig":{"minSize":"MinSize", "maxSize":"MaxSize", "desiredSize":"DesiredSize"},
                  "updateConfig":{"maxUnavailable":"MaxUnavailable", "maxUnavailablePercentage":"MaxUnavailablePercentage", "updateStrategy":"UpdateStrategy"}}
        for section, values in kwargs.items():
            for name, value in values.items():
                expected[fields[section][name]] = value
        def parameters(update):
            parsed = {}
            for param in update["params"]:
                try:
                    value = json.loads(param["value"])
                except json.JSONDecodeError:
                    value = param["value"]
                parsed[param["type"]] = value
            return parsed
        assert parameters(result) == expected, result
        completed = self.wait_update(result)
        replay = self.call("replay-worker-config", "eks", "update_nodegroup_config", **request)["update"]
        assert replay["id"] == result["id"] and parameters(replay) == expected and parameters(completed) == expected

    def worker_drain_reservations(self):
        database = sqlite3.connect((self.state / "state.sqlite").resolve().as_uri()+"?mode=ro", uri=True)
        try:
            rows = database.execute(
                "SELECT instance_id,node_uid,drain_started,drain_completed FROM eks_nodegroup_worker "
                "WHERE partition='aws' AND account_id=? AND region=? AND cluster_name=? AND name='workers' AND drain_started>0",
                (self.account, REGION, self.owned["cluster"])).fetchall()
            return {instance:{"uid":uid, "drainStarted":str(started), "drainCompleted":str(completed) if completed > 0 else None}
                    for instance, uid, started, completed in rows}
        finally:
            database.close()

    def eviction_rejections(self):
        metrics = self.kube("get", "--raw", "/metrics")
        return int(sum(float(line.rsplit(" ", 1)[1]) for line in metrics.splitlines()
                       if line.startswith("apiserver_request_total{") and 'resource="pods"' in line
                       and 'subresource="eviction"' in line and 'code="429"' in line))

    def rollout_observation(self, update_id, strategy):
        state = self.client("eks").describe_update(name=self.owned["cluster"], nodegroupName="workers", updateId=update_id)["update"]
        assert state["status"] not in ("Failed", "Cancelled"), state
        reservations = self.worker_drain_reservations()
        nodes = {n["metadata"]["name"]:n for n in self.kube_json("get", "nodes", "-l", "eks.amazonaws.com/nodegroup=workers")["items"]}
        group = self.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[self.owned["asg"]])["AutoScalingGroups"][0]
        draining, completed, terminating, available = [], [], [], 0
        for member in group["Instances"]:
            instance = member["InstanceId"]
            node, reservation = nodes.get(instance), reservations.get(instance)
            cordoned = node is not None and node["spec"].get("unschedulable", False)
            if member["LifecycleState"].startswith("Terminating"):
                terminating.append(instance)
            # Completed drains and lingering ASG termination records are not active evictions.
            if reservation is not None and node is not None and node["metadata"]["uid"] == reservation["uid"] and not node["metadata"].get("deletionTimestamp"):
                (completed if reservation["drainCompleted"] else draining).append(instance)
            retiring = reservation is not None or instance in terminating
            if node is not None and not node["metadata"].get("deletionTimestamp") and not retiring and (strategy == "MINIMAL" or not cordoned) and member["LifecycleState"] == "InService" and any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]):
                available += 1
        assert len(draining) <= 2, draining
        assert available >= (3 if strategy == "DEFAULT" else 1), (strategy, available, draining)
        return {"status":state["status"], "draining":sorted(draining), "completedDrains":sorted(completed),
                "terminatingInstances":sorted(terminating), "available":available, "nodes":nodes, "reservations":reservations,
                "asg":{key:group[key] for key in ("DesiredCapacity", "MaxSize", "AvailabilityZones")}}

    def rollout_budgets(self, template_version, strategies=("DEFAULT", "MINIMAL")):
        o = self.owned
        namespace = o["namespace"]
        self.kube("-n", namespace, "patch", "pdb", "backend", "--type=merge", "-p", '{"spec":{"minAvailable":0}}')
        evidence = self.data["observations"].setdefault("rolloutBudgets", {})
        for strategy in strategies:
            config = {"DEFAULT":{"maxUnavailable":2}, "MINIMAL":{"maxUnavailablePercentage":50}}[strategy]
            config["updateStrategy"] = strategy
            self.update_config(scalingConfig={"minSize":1, "maxSize":3, "desiredSize":3}, updateConfig=config)
            workers = self.wait("three Ready workers for budget", lambda:self.active_workers(3, "1.33"), bool, 1200, 3)
            old = {n["metadata"]["name"]:n["metadata"]["uid"] for n in workers}
            label = {"rollout-budget":strategy.lower()}
            pods = [{"apiVersion":"v1", "kind":"Pod", "metadata":{"name":f"budget-{strategy.lower()}-{i}", "namespace":namespace, "labels":label},
                     "spec":{"nodeName":n["metadata"]["name"], "tolerations":[{"operator":"Exists"}],
                             "containers":[{"name":"hold", "image":self.args.workload_image, "imagePullPolicy":"Never", "command":["sleep", "86400"]}]}} for i, n in enumerate(workers)]
            pdb_name = "budget-" + strategy.lower()
            pdb = {"apiVersion":"policy/v1", "kind":"PodDisruptionBudget", "metadata":{"name":pdb_name, "namespace":namespace},
                   "spec":{"minAvailable":3, "selector":{"matchLabels":label}}}
            self.kube("apply", "-f", "-", stdin=json.dumps({"apiVersion":"v1", "kind":"List", "items":[*pods, pdb]}))
            self.kube("-n", namespace, "wait", "--for=condition=Ready", "pods", "-l", "rollout-budget="+strategy.lower(), "--timeout=180s")
            self.wait("PDB observes all workers", lambda:self.kube_json("-n", namespace, "get", "pdb", pdb_name),
                      lambda p:p.get("status", {}).get("currentHealthy") == 3 and p["status"].get("disruptionsAllowed") == 0, 120, 2)
            if strategy == "DEFAULT":
                self.call("external-asg-maximum", "autoscaling", "update_auto_scaling_group",
                          AutoScalingGroupName=o["asg"], MaxSize=5)
            baseline = self.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[o["asg"]])["AutoScalingGroups"][0]
            baseline_scaling = {key:baseline[key] for key in ("DesiredCapacity", "MaxSize", "AvailabilityZones")}
            surge = max(2*len(baseline["AvailabilityZones"]), 2) if strategy == "DEFAULT" else 0
            template_version = self.call("budget-template-"+strategy.lower(), "ec2", "create_launch_template_version",
                                         LaunchTemplateId=o["template"], SourceVersion=str(template_version),
                                         LaunchTemplateData={"ImageId":o["images"]["1.33"]})["LaunchTemplateVersion"]["VersionNumber"]
            rejected_before = self.eviction_rejections() if strategy == "MINIMAL" else None
            update = self.call("budget-rollout-"+strategy.lower(), "eks", "update_nodegroup_version", clusterName=o["cluster"],
                               nodegroupName="workers", launchTemplate={"id":o["template"], "version":str(template_version)})["update"]
            started = time.monotonic()
            peak, minimum = 0, 3
            def observe():
                nonlocal peak, minimum
                observed = self.rollout_observation(update["id"], strategy)
                peak, minimum = max(peak, len(observed["draining"])), min(minimum, observed["available"])
                return observed
            blocked = self.wait("two real simultaneous PDB-blocked drains", observe, lambda v:len(v["draining"]) == 2, 1200, 3)
            assert blocked["asg"]["DesiredCapacity"] == baseline["DesiredCapacity"]+surge, blocked["asg"]
            assert blocked["asg"]["MaxSize"] == baseline["MaxSize"]+surge, blocked["asg"]
            new_nodes = {name:node for name, node in blocked["nodes"].items() if name not in old}
            if strategy == "DEFAULT":
                assert len(new_nodes) == surge and all(not node["spec"].get("unschedulable", False) and any(condition["type"] == "Ready" and condition["status"] == "True" for condition in node["status"]["conditions"]) for node in new_nodes.values()), new_nodes
            else:
                assert not new_nodes, new_nodes
                assert all(blocked["nodes"][name]["spec"].get("unschedulable", False) and blocked["nodes"][name]["metadata"]["labels"].get("node.kubernetes.io/exclude-from-external-load-balancers") == "true" for name in old), blocked["nodes"]
                assert {name:value["uid"] for name, value in blocked["reservations"].items()} == {name:old[name] for name in blocked["draining"]}, blocked["reservations"]
                rejected_blocked = self.wait("native PDB eviction rejections", self.eviction_rejections, lambda count:count >= rejected_before+2, 120, 2)
                pdb_rejections = {"beforeUpdate":rejected_before, "blocked":rejected_blocked}
            selected = blocked["draining"]
            for restarted in (False, True):
                if restarted:
                    self.restart()
                for _ in range(3):
                    time.sleep(5)
                    pending = observe()
                    assert pending["status"] == "InProgress" and pending["draining"] == selected, pending
                    assert all(pending["nodes"].get(name, {}).get("metadata", {}).get("uid") == uid for name, uid in old.items()), pending
                    if strategy == "MINIMAL":
                        assert pending["reservations"] == blocked["reservations"], pending["reservations"]
                        assert all(pending["nodes"][name]["spec"].get("unschedulable", False) for name in old), pending["nodes"]
                if strategy == "MINIMAL":
                    observed_pdb = self.kube_json("-n", namespace, "get", "pdb", pdb_name)
                    assert observed_pdb["status"]["currentHealthy"] == 3 and observed_pdb["status"]["disruptionsAllowed"] == 0, observed_pdb
                    observed_rejections = self.eviction_rejections()
                    if restarted:
                        assert observed_rejections >= pdb_rejections["beforeRestart"]+2, observed_rejections
                    pdb_rejections["afterRestart" if restarted else "beforeRestart"] = observed_rejections
            evidence[strategy] = {"config":config, "updateID":update["id"], "status":"InProgress",
                                  "pdbBlockedBatchAcrossRestart":selected, "replacedInstances":old,
                                  "baselineASG":baseline_scaling, "pdbBlockedASG":blocked["asg"],
                                  "readySurgeInstances":{name:node["metadata"]["uid"] for name, node in new_nodes.items()},
                                  "retainedDrainReservations":blocked["reservations"]}
            if strategy == "MINIMAL":
                evidence[strategy]["allOldNodesCordoned"] = {name:node["metadata"]["uid"] for name, node in blocked["nodes"].items() if name in old}
                evidence[strategy]["nativePDBRejections"] = pdb_rejections
            self.save()
            self.kube("-n", namespace, "patch", "pdb", pdb_name, "--type=merge", "-p", '{"spec":{"minAvailable":0}}')
            self.wait("budgeted real ASG replacements", observe, lambda v:v["status"] == "Successful", 1200, 3)
            final = self.wait("budget replacements Ready", lambda:self.active_workers(3, "1.33"), bool, 1200, 3)
            assert not set(old).intersection(n["metadata"]["name"] for n in final)
            final_asg = self.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[o["asg"]])["AutoScalingGroups"][0]
            final_scaling = {key:final_asg[key] for key in ("DesiredCapacity", "MaxSize", "AvailabilityZones")}
            assert final_scaling == baseline_scaling, (baseline_scaling, final_scaling)
            evidence[strategy].update({"status":"Successful", "peakConcurrentEvictions":peak,
                                      "elapsedSeconds":round(time.monotonic()-started, 3), "minimumAvailable":minimum,
                                      "finalASG":final_scaling,
                                      "finalInstances":{n["metadata"]["name"]:n["metadata"]["uid"] for n in final},
                                      "availabilityDefinition":"Ready InService members without a retained drain reservation; MINIMAL intentionally cordons all old nodes.",
                                      "evictionDefinition":"Current Node UID-fenced reservations without drain completion; completed drains and ASG termination records are separate."})
            self.save()
            self.kube("-n", namespace, "delete", "pdb", pdb_name)
            self.kube("-n", namespace, "delete", "pods", "-l", "rollout-budget="+strategy.lower(), "--ignore-not-found")

    def workload(self, bootstrap_node):
        namespace = "worker-proof"
        self.owned["namespace"] = namespace
        tolerations = [{"key":"dedicated", "operator":"Equal", "value":"worker-proof", "effect":"NoSchedule"}]
        labels = {"app":"worker-proof"}
        backend = {"apiVersion":"apps/v1", "kind":"Deployment", "metadata":{"name":"backend", "namespace":namespace},
                   "spec":{"replicas":1, "selector":{"matchLabels":labels}, "template":{"metadata":{"labels":labels}, "spec":{
                   "nodeSelector":{"eks.amazonaws.com/nodegroup":"workers"}, "tolerations":tolerations,
                   "containers":[{"name":"web", "image":self.args.workload_image, "imagePullPolicy":"Never", "command":["sh","-ec",f"mkdir -p /www; echo {self.prefix} >/www/index.html; echo {self.prefix}; exec httpd -f -p 8080 -h /www"]}]}}}}
        documents = [{"apiVersion":"v1", "kind":"Namespace", "metadata":{"name":namespace}}, backend,
                     {"apiVersion":"v1", "kind":"Service", "metadata":{"name":"backend", "namespace":namespace}, "spec":{"selector":labels,"ports":[{"port":8080,"targetPort":8080}]}},
                     {"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"client", "namespace":namespace}, "spec":{"nodeName":bootstrap_node, "containers":[{"name":"client","image":self.args.workload_image,"imagePullPolicy":"Never","command":["sleep","86400"]}]}},
                     {"apiVersion":"policy/v1", "kind":"PodDisruptionBudget", "metadata":{"name":"backend", "namespace":namespace}, "spec":{"minAvailable":1,"selector":{"matchLabels":labels}}}]
        self.kube("apply", "-f", "-", stdin=json.dumps({"apiVersion":"v1","kind":"List","items":documents}))
        self.kube("-n", namespace, "rollout", "status", "deployment/backend", "--timeout=300s")
        self.kube("-n", namespace, "wait", "--for=condition=Ready", "pod/client", "--timeout=180s")
        self.packet(True)
        assert self.prefix in self.kube("-n", namespace, "logs", "deployment/backend")
        assert self.prefix in self.kube("-n", namespace, "exec", "deployment/backend", "--", "cat", "/www/index.html")
        self.data["observations"]["workerExecLogsAndCrossNodeService"] = True

    def packet(self, success, converge=False):
        def probe():
            result = subprocess.run(["kubectl", "--request-timeout=90s", "-n", self.owned["namespace"], "exec", "client", "--",
                                     "wget", "-T", "4", "-q", "-O-", "http://backend.worker-proof.svc.cluster.local:8080"],
                                    env=self.environment, text=True, capture_output=True, timeout=100)
            if result.returncode == 0:
                assert self.prefix in result.stdout, result.stdout
            elif "wget:" not in result.stderr or "timed out" not in result.stderr:
                raise RuntimeError("Packet probe failed outside the remote timeout: " + result.stderr)
            return result
        try:
            if converge:
                # EC2 commits policy intent before its native observer applies it.
                result = self.wait("fresh packet policy convergence", probe, lambda value:(value.returncode == 0) == success, 30)
            else:
                result = probe()
            if (result.returncode == 0) != success:
                raise RuntimeError(f"Expected packet success={success}: {result.stderr}")
        except Exception:
            if success:
                self.packet_diagnostics()
            raise
        return result.stdout if success else result.stderr

    def packet_diagnostics(self):
        """Retain the failed packet path before exact-owned cleanup removes it."""
        evidence = self.data["observations"].setdefault("packetFailure", {})
        def capture(label, operation):
            try:
                evidence[label] = operation()
            except Exception as error:
                evidence[label] = {"error":str(error)}
            self.save()
        def command(*argv):
            result = subprocess.run(argv, env=self.environment, text=True, capture_output=True, timeout=90)
            return {"code":result.returncode, "stdout":result.stdout[-50000:], "stderr":result.stderr[-5000:]}
        namespace = self.owned["namespace"]
        capture("nodes", lambda:[{"name":n["metadata"]["name"], "podCIDRs":n["spec"].get("podCIDRs"),
                                 "addresses":n["status"].get("addresses"), "flannel":{k:v for k,v in n["metadata"].get("annotations", {}).items() if k.startswith("flannel.")}}
                                for n in self.kube_json("get", "nodes")["items"]])
        capture("pods", lambda:[{"name":p["metadata"]["name"], "node":p["spec"].get("nodeName"), "status":p["status"]}
                               for p in self.kube_json("-n", namespace, "get", "pods")["items"]])
        capture("service", lambda:self.kube_json("-n", namespace, "get", "service", "backend"))
        capture("endpoints", lambda:self.kube_json("-n", namespace, "get", "endpointslice", "-l", "kubernetes.io/service-name=backend"))
        capture("clientDNS", lambda:command("kubectl", "-n", namespace, "exec", "client", "--", "nslookup", "backend.worker-proof.svc.cluster.local"))
        capture("backendHTTP", lambda:command("kubectl", "-n", namespace, "exec", "deployment/backend", "--", "wget", "-T", "4", "-O-", "http://127.0.0.1:8080"))
        for pod in evidence.get("pods", []) if isinstance(evidence.get("pods"), list) else []:
            if not pod["name"].startswith("backend-") or not pod["node"]:
                continue
            address = pod["status"].get("podIP")
            if address:
                capture("directPodHTTP", lambda:command("kubectl", "-n", namespace, "exec", "client", "--", "wget", "-T", "4", "-O-", f"http://{address}:8080"))
            capture("workerNetwork", lambda:self.guest_packet_diagnostics(pod["node"]))
            break
        def bootstrap_network():
            container = self.command(["docker", "container", "ls", "-q", "--filter", f"label=stackd.eks.id={self.owned['nativeID']}", "--filter", "name=agent-0"]).strip()
            return command("docker", "exec", container, "sh", "-c", "ip -d link show type vxlan; ip route; /sbin/bridge fdb show; cat /etc/rancher/k3s/stackd-flannel.json")
        capture("bootstrapNetwork", bootstrap_network)
        capture("securityGroup", lambda:self.client("ec2").describe_security_groups(GroupIds=[self.owned["sg"]]))
        capture("networkACL", lambda:self.client("ec2").describe_network_acls(NetworkAclIds=[self.owned["acl"]]))

    def guest_packet_diagnostics(self, node):
        # A kubelet proxy failure can also prevent exec/logs. The actual debug
        # pod sends its read-only host observations directly to this receiver.
        received, path = {}, "/" + uuid.uuid4().hex
        class Receiver(BaseHTTPRequestHandler):
            def do_POST(handler):
                size = int(handler.headers.get("Content-Length", "0"))
                if handler.path != path or not 0 < size <= 262144:
                    handler.send_error(400)
                    return
                handler.connection.settimeout(10)
                text = handler.rfile.read(size).decode("utf-8", errors="replace")
                text = re.sub(r"K10[0-9a-fA-F]+::\S+", "[redacted]", text)
                received["output"] = re.sub(r"(?i)((?:token|password|secret)[=: ]+)\S+", r"\1[redacted]", text)
                handler.send_response(204)
                handler.end_headers()
            def log_message(handler, *_):
                pass
        server = ThreadingHTTPServer(("0.0.0.0", 0), Receiver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://{self.args.gateway}:{server.server_port}{path}"
            inspect = ("ip -d link show type vxlan; ip -s link; ip route show table all; /usr/sbin/bridge fdb show; ss -lntu; "
                       "cat /proc/net/snmp; iptables-save; nft list ruleset; "
                       "for file in /proc/sys/net/ipv4/conf/*/rp_filter; do printf '%s ' \"$file\"; cat \"$file\"; done; "
                       "if command -v ethtool >/dev/null; then for link in /sys/class/net/*; do ethtool -k \"${link##*/}\"; done; fi; dmesg --level=err,warn; "
                       "cat /etc/rancher/k3s/stackd-flannel.json; journalctl -u k3s-agent --no-pager -n 120")
            script = f"chroot /host /bin/sh -c {shlex.quote(inspect)} > /tmp/network.txt 2>&1; wget -T 10 -O /dev/null --post-file=/tmp/network.txt {shlex.quote(target)}; sleep 3600"
            diagnostic = {"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"packet-diagnostic-" + path[1:9], "namespace":self.owned["namespace"]},
                          "spec":{"nodeName":node, "hostNetwork":True, "hostPID":True, "tolerations":[{"operator":"Exists"}],
                                  "containers":[{"name":"inspect", "image":self.args.workload_image, "imagePullPolicy":"Never",
                                                 "command":["sh", "-ec", script], "securityContext":{"privileged":True},
                                                 "volumeMounts":[{"name":"host", "mountPath":"/host", "readOnly":True}]}],
                                  "volumes":[{"name":"host", "hostPath":{"path":"/"}}]}}
            self.kube("apply", "-f", "-", stdin=json.dumps(diagnostic))
            return self.wait("actual guest network diagnostic delivery", lambda:received.get("output"), bool, 90)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def packet_policies(self, port):
        ingress = [{"IpProtocol":"-1", "IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]
        self.call("block-worker-security-group", "ec2", "revoke_security_group_ingress", GroupId=self.owned["sg"], IpPermissions=ingress)
        try:
            self.packet(False, converge=True)
        finally:
            self.call("restore-worker-security-group", "ec2", "authorize_security_group_ingress", GroupId=self.owned["sg"], IpPermissions=ingress)
        self.packet(True, converge=True)
        self.call("block-worker-vxlan-acl", "ec2", "create_network_acl_entry", NetworkAclId=self.owned["acl"], RuleNumber=1, Protocol="17", RuleAction="deny", Egress=False, CidrBlock="0.0.0.0/0", PortRange={"From":port,"To":port})
        self.owned["denyRule"] = True
        try:
            self.packet(False, converge=True)
        finally:
            self.call("restore-worker-vxlan-acl", "ec2", "delete_network_acl_entry", NetworkAclId=self.owned["acl"], RuleNumber=1, Egress=False)
            self.owned["denyRule"] = False
        self.packet(True, converge=True)
        self.data["observations"]["securityGroupAndACLDropThenRestoreActualPackets"] = True
        self.save()

    def run(self):
        self.prepare()
        o = self.owned
        o["vpc"] = self.call("worker-vpc", "ec2", "create_vpc", CidrBlock=self.args.cidr)["Vpc"]["VpcId"]
        o["subnets"] = []
        for index, cidr in enumerate(self.args.subnet):
            o["subnets"].append(self.call("worker-subnet", "ec2", "create_subnet", VpcId=o["vpc"], CidrBlock=cidr, AvailabilityZone=REGION + chr(97+index))["Subnet"]["SubnetId"])
        o["sg"] = self.call("worker-security-group", "ec2", "create_security_group", VpcId=o["vpc"], GroupName=self.prefix, Description=self.prefix)["GroupId"]
        self.call("worker-ingress", "ec2", "authorize_security_group_ingress", GroupId=o["sg"], IpPermissions=[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}])
        o["igw"] = self.call("worker-real-igw", "ec2", "create_internet_gateway")["InternetGateway"]["InternetGatewayId"]
        self.call("attach-worker-igw", "ec2", "attach_internet_gateway", VpcId=o["vpc"], InternetGatewayId=o["igw"])
        o["routeTable"] = self.client("ec2").describe_route_tables(Filters=[{"Name":"vpc-id","Values":[o["vpc"]]}])["RouteTables"][0]["RouteTableId"]
        self.call("worker-public-default-route", "ec2", "create_route", RouteTableId=o["routeTable"], DestinationCidrBlock="0.0.0.0/0", GatewayId=o["igw"])
        o["acl"] = self.client("ec2").describe_network_acls(Filters=[{"Name":"vpc-id","Values":[o["vpc"]]}])["NetworkAcls"][0]["NetworkAclId"]
        role_arns = {}
        o["roles"] = {}
        for kind, principal in (("control","eks.amazonaws.com"),("node","ec2.amazonaws.com")):
            name = self.prefix + "-" + kind
            trust = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":principal},"Action":"sts:AssumeRole"}]}
            role_arns[kind] = self.call("worker-"+kind+"-role", "iam", "create_role", RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
            o["roles"][kind] = name
        control_policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeSubnets","ec2:DescribeSecurityGroups"],"Resource":"*"}]}
        self.call("control-network-ownership", "iam", "put_role_policy", RoleName=o["roles"]["control"], PolicyName="worker-proof", PolicyDocument=json.dumps(control_policy))
        o.setdefault("rolePolicies", {})[o["roles"]["control"]] = ["worker-proof"]
        o["cluster"] = self.prefix
        self.call("create-worker-control", "eks", "create_cluster", name=o["cluster"], version="1.32", roleArn=role_arns["control"], resourcesVpcConfig={"subnetIds":o["subnets"],"securityGroupIds":[o["sg"]]}, accessConfig={"authenticationMode":"API_AND_CONFIG_MAP"})
        with sqlite3.connect(self.state / "state.sqlite") as db:
            o["nativeID"] = db.execute("SELECT id FROM eks_cluster WHERE name=?",(o["cluster"],)).fetchone()[0]
        self.save()
        def control_ready():
            cluster = self.client("eks").describe_cluster(name=o["cluster"])["cluster"]
            if cluster["status"] == "FAILED":
                self.data["observations"]["failedNativeControl"] = cluster
                self.save()
                raise RuntimeError("Native control failed: " + json.dumps(cluster.get("health"), default=str))
            return cluster
        self.wait("real control ready", control_ready, lambda c:c["status"]=="ACTIVE",600)
        self.import_version("1.32", self.args.raw_image)
        image_map = self.publish_images()
        cluster_arn = f"arn:aws:eks:{REGION}:{self.account}:cluster/{o['cluster']}"
        self.call("node-current-auth", "iam", "put_role_policy", RoleName=o["roles"]["node"], PolicyName="worker-proof", PolicyDocument=json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"eks-auth:AssumeRoleForPodIdentity","Resource":cluster_arn}]}))
        o.setdefault("rolePolicies", {})[o["roles"]["node"]] = ["worker-proof"]
        self.command(["aws","--endpoint-url",self.endpoint,"--region",REGION,"eks","update-kubeconfig","--name",o["cluster"],"--kubeconfig",str(self.state/"kubeconfig")])
        native_id = o["nativeID"]
        server = self.command(["docker","container","ls","-q","--no-trunc","--filter",f"label=stackd.eks.id={native_id}","--filter","name=server-0"]).strip()
        inspection = json.loads(self.command(["docker","inspect",server]))[0]
        binding = inspection["HostConfig"]["PortBindings"]["6443/tcp"]
        assert len(binding) == 1 and binding[0]["HostIp"] == self.args.worker_advertise_host
        self.data["observations"]["nativeApiBinding"] = binding
        advertised = self.kube_json("-n", "default", "get", "endpoints", "kubernetes")["subsets"]
        endpoints = [(address["ip"], port["port"]) for subset in advertised for address in subset["addresses"] for port in subset["ports"]]
        assert endpoints == [(self.args.worker_advertise_host, int(binding[0]["HostPort"]))], advertised
        self.data["observations"]["nativeAdvertisedEndpoint"] = advertised
        agent = self.command(["docker","container","ls","-q","--no-trunc","--filter",f"label=stackd.eks.id={native_id}","--filter","name=agent-0"]).strip()
        agent_inspection = json.loads(self.command(["docker","inspect",agent]))[0]
        archive = "/tmp/stackd-workload-images.tar"
        self.command(["docker","cp",str(self.args.workload_archive),agent+":"+archive])
        try:
            self.command(["docker","exec",agent,"ctr","images","import",archive],timeout=300)
        finally:
            self.command(["docker","exec",agent,"rm","-f",archive])
        overlay_port = next(int(k.split("/")[0]) for k in agent_inspection["HostConfig"]["PortBindings"] if k.endswith("/udp"))
        overlay_binding = agent_inspection["HostConfig"]["PortBindings"][f"{overlay_port}/udp"]
        assert overlay_binding == [{"HostIp":self.args.worker_advertise_host, "HostPort":str(overlay_port)}]
        assert str(overlay_port) == binding[0]["HostPort"]
        self.data["observations"]["nativeWorkerOverlayBinding"] = overlay_binding
        bootstrap_node = agent_inspection["Name"].lstrip("/")
        template = {"InstanceType":"t3.small","MetadataOptions":{"HttpTokens":"required","HttpPutResponseHopLimit":2},
                    "NetworkInterfaces":[{"DeviceIndex":0,"Groups":[o["sg"]],"AssociatePublicIpAddress":True,"DeleteOnTermination":True}]}
        o["template"] = self.call("customer-worker-template", "ec2", "create_launch_template", LaunchTemplateName=self.prefix, LaunchTemplateData=template)["LaunchTemplate"]["LaunchTemplateId"]
        request = {"clusterName":o["cluster"],"nodegroupName":"workers","nodeRole":role_arns["node"],"subnets":o["subnets"],"launchTemplate":{"id":o["template"],"version":"1"},"scalingConfig":{"minSize":1,"maxSize":2,"desiredSize":1},"labels":{"proof":"original"},"clientRequestToken":"stable-worker-create"}
        created = self.call("create-managed-workers", "eks", "create_nodegroup", **request)["nodegroup"]
        o["nodegroup"] = "workers"
        o["nodegroupID"] = created["nodegroupArn"].rsplit("/", 1)[-1]
        replay = self.call("replay-managed-worker-create", "eks", "create_nodegroup", **request)["nodegroup"]
        assert replay["nodegroupArn"] == created["nodegroupArn"]
        workers = self.wait("actual 1.32 firmware worker Ready",lambda:self.active_workers(1,"1.32"),bool,1200,3)
        assert self.nodegroup()["releaseVersion"] == image_map["1.32"]["releaseVersion"]
        original_node = workers[0]
        self.exercise_workers(original_node, bootstrap_node, overlay_port)

    def exercise_workers(self, original_node, bootstrap_node, overlay_port):
        o = self.owned
        self.workload(bootstrap_node)
        self.packet_policies(overlay_port)
        self.restart()
        retained = self.wait("retained real worker",lambda:self.active_workers(1,"1.32"),bool,180,2)[0]
        assert retained["metadata"]["uid"] == original_node["metadata"]["uid"]
        self.data["observations"]["restartRetainsWorkerUID"] = retained["metadata"]["uid"]
        self.update_config(labels={"addOrUpdateLabels":{"proof":"updated"}},taints={"addOrUpdateTaints":[{"key":"dedicated","value":"worker-proof","effect":"NO_SCHEDULE"}]})
        configured = self.kube_json("get","node",retained["metadata"]["name"])
        assert configured["metadata"]["uid"] == retained["metadata"]["uid"] and configured["metadata"]["labels"]["proof"] == "updated"
        assert {"key":"dedicated","value":"worker-proof","effect":"NoSchedule"} in configured["spec"]["taints"]
        self.update_config(scalingConfig={"desiredSize":2})
        scaled = self.wait("second actual worker",lambda:self.active_workers(2,"1.32"),bool,1200,3)
        assert {n["metadata"]["labels"]["proof"] for n in scaled} == {"updated"}
        self.update_config(scalingConfig={"desiredSize":1})
        before_upgrade = self.wait("scale in real worker",lambda:self.active_workers(1,"1.32"),bool,600,2)[0]
        self.kube("-n",o["namespace"],"rollout","status","deployment/backend","--timeout=300s")
        self.import_version("1.33", self.args.upgrade_image)
        image_map = self.publish_images()
        self.wait("proxy reattached after upgrade image publication", self.kubernetes_version, bool, 120)
        retained = self.wait("worker retained after upgrade image publication",lambda:self.active_workers(1,"1.32"),bool,180,2)[0]
        assert retained["metadata"]["uid"] == before_upgrade["metadata"]["uid"]
        self.exercise_identity_and_rollouts(before_upgrade, image_map)

    def exercise_identity_and_rollouts(self, before_upgrade, image_map):
        o = self.owned
        def control_plane_update(probe):
            def continuity():
                node = self.kube_json("get", "node", before_upgrade["metadata"]["name"])
                pods = self.kube_json("-n", o["namespace"], "get", "pods", "-l", "app=worker-proof")["items"]
                return {"nodeName":node["metadata"]["name"], "nodeUID":node["metadata"]["uid"],
                        "kubeletVersion":node["status"]["nodeInfo"]["kubeletVersion"],
                        "pods":{p["metadata"]["name"]:{"uid":p["metadata"]["uid"], "nodeName":p["spec"]["nodeName"],
                                "containers":{c["name"]:{"containerID":c["containerID"], "restartCount":c["restartCount"]}
                                              for c in p["status"]["containerStatuses"]}} for p in pods}}
            before = continuity()
            control_update = self.call("upgrade-real-control", "eks", "update_cluster_version", name=o["cluster"], version="1.33")["update"]
            evidence = {"observed":False, "reason":"No target-version native API was observed while the cluster remained UPDATING."}
            try:
                deadline = time.monotonic() + 600
                while time.monotonic() < deadline:
                    state = self.client("eks").describe_cluster(name=o["cluster"])["cluster"]["status"]
                    if state == "ACTIVE":
                        break
                    if state != "UPDATING":
                        raise RuntimeError("Unexpected cluster status during control upgrade: " + state)
                    # Do not probe the old server just before its intentional
                    # restart, or manufacture an UPDATING window with a delay.
                    version = self.kubernetes_version()
                    if version.get("gitVersion", "").startswith("v1.33."):
                        evidence = probe()
                        break
                    time.sleep(1)
            finally:
                self.wait("real 1.33 control", self.kubernetes_version, lambda v:v.get("gitVersion", "").startswith("v1.33."), 600, 3)
                self.wait("control upgrade committed", lambda:self.client("eks").describe_cluster(name=o["cluster"])["cluster"], lambda c:c["status"] == "ACTIVE", 600)
            terminal = self.client("eks").describe_update(name=o["cluster"], updateId=control_update["id"])["update"]
            assert terminal["status"] == "Successful", terminal
            after = continuity()
            assert before == after, {"before":before, "after":after}
            evidence.update(updateID=control_update["id"], continuity={"before":before, "after":after})
            self.data["observations"]["controlUpgradeRetainsManagedWorkload"] = evidence["continuity"]
            self.save()
            return evidence
        exercise_pod_identity(self, self.kube, o["cluster"], before_upgrade["metadata"]["name"], o["roles"]["node"], self.restart, control_plane_update)
        upgrade = self.call("rolling-real-worker-version", "eks", "update_nodegroup_version", clusterName=o["cluster"],nodegroupName="workers",version="1.33",releaseVersion=image_map["1.33"]["releaseVersion"])["update"]
        self.exercise_worker_rollouts(before_upgrade, image_map, upgrade)

    def exercise_worker_rollouts(self, before_upgrade, image_map, upgrade):
        o = self.owned
        old_name, old_uid = before_upgrade["metadata"]["name"], before_upgrade["metadata"]["uid"]
        self.wait("PDB blocks real drain",lambda:self.kube_json("get","node",old_name),lambda n:n["spec"].get("unschedulable",False),1200,3)
        time.sleep(12)
        pending = self.client("eks").describe_update(name=o["cluster"],nodegroupName="workers",updateId=upgrade["id"])["update"]
        assert pending["status"] == "InProgress" and self.kube_json("get","node",old_name)["metadata"]["uid"] == old_uid
        self.restart()
        self.kube("-n",o["namespace"],"patch","pdb","backend","--type=merge","-p",'{"spec":{"minAvailable":0}}')
        self.wait_update(upgrade)
        upgraded = self.wait("real upgraded worker",lambda:self.active_workers(1,"1.33"),bool,1200,3)[0]
        assert self.nodegroup()["releaseVersion"] == image_map["1.33"]["releaseVersion"]
        assert upgraded["metadata"]["uid"] != old_uid and upgraded["metadata"]["name"] != old_name
        assert not self.kube("get","node",old_name,"--ignore-not-found","-o","json").strip()
        self.kube("-n",o["namespace"],"rollout","status","deployment/backend","--timeout=300s")
        self.packet(True)
        self.data["observations"]["realWorkerVersionUpgrade"] = {"updateID":upgrade["id"],"oldInstance":old_name,"oldUID":old_uid,"oldKubeletVersion":before_upgrade["status"]["nodeInfo"]["kubeletVersion"],"newInstance":upgraded["metadata"]["name"],"newUID":upgraded["metadata"]["uid"],"kubeletVersion":upgraded["status"]["nodeInfo"]["kubeletVersion"],"pdbBlockedThenReleased":True}
        self.exercise_forced_and_budget_rollouts(upgraded)
        self.data["passed"] = True
        self.save()

    def exercise_forced_and_budget_rollouts(self, upgraded):
        o = self.owned
        # A new template generation with force must bypass the actual PDB, not
        # report success while retaining the old instance or Kubernetes node.
        self.kube("-n",o["namespace"],"patch","pdb","backend","--type=merge","-p",'{"spec":{"minAvailable":1}}')
        pdb = self.wait("force targets a PDB-protected workload", lambda:self.kube_json("-n",o["namespace"],"get","pdb","backend"),
                        lambda p:p.get("status",{}).get("currentHealthy") == 1 and p["status"].get("desiredHealthy") == 1 and p["status"].get("disruptionsAllowed") == 0, 120, 2)
        custom_version = self.call("customer-force-template", "ec2", "create_launch_template_version", LaunchTemplateId=o["template"],SourceVersion="1",LaunchTemplateData={"ImageId":o["images"]["1.33"]})["LaunchTemplateVersion"]["VersionNumber"]
        forced = self.call("force-real-worker-drain", "eks", "update_nodegroup_version",clusterName=o["cluster"],nodegroupName="workers",launchTemplate={"id":o["template"],"version":str(custom_version)},force=True)["update"]
        self.wait_update(forced)
        final_node = self.wait("forced replacement Ready",lambda:self.active_workers(1,"1.33"),bool,1200,3)[0]
        assert final_node["metadata"]["uid"] != upgraded["metadata"]["uid"]
        assert not self.kube("get","node",upgraded["metadata"]["name"],"--ignore-not-found","-o","json").strip()
        self.kube("-n",o["namespace"],"rollout","status","deployment/backend","--timeout=300s")
        self.packet(True)
        self.data["observations"]["forcedDrainReplacesActualNode"] = {"updateID":forced["id"],"oldInstance":upgraded["metadata"]["name"],
                                                                   "oldUID":upgraded["metadata"]["uid"],"newInstance":final_node["metadata"]["name"],
                                                                   "newUID":final_node["metadata"]["uid"],"pdbBeforeForce":pdb["status"]}
        self.rollout_budgets(custom_version)
        self.save()

    def expire_cleanup_service_sessions(self, roles):
        if not roles:
            return
        arns = [role["Arn"] for role in roles]
        with sqlite3.connect(self.state / "state.sqlite") as db:
            expiry = db.execute("SELECT MAX(credential_expiration) FROM iam_credential WHERE credential_account_id=? AND status='Active' AND credential_issuer_arn IN (" +
                                ",".join("?" for _ in arns) + ")", [self.account, *arns]).fetchone()[0]
        if not expiry:
            return
        boundary = datetime.strptime(expiry[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) + timedelta(seconds=2)
        if boundary <= datetime.now(timezone.utc):
            return
        # Native workers and the control plane are already absent. Only cleanup
        # uses manual service time; no live credentials are revoked or bypassed.
        self.stop()
        self.controller_args.extend(["-clock-start", boundary.isoformat().replace("+00:00", "Z")])
        self.start()
        with urllib.request.urlopen(self.endpoint + "/_stackd/clock", context=ssl.create_default_context(cafile=str(self.state / "server.crt")), timeout=15) as response:
            clock = json.load(response)
        assert datetime.fromisoformat(clock["time"].replace("Z", "+00:00")) >= boundary, clock
        self.data["observations"]["serviceRoleCleanupClock"] = {"lastSessionExpiry":expiry, "serviceClock":clock}
        self.save()

    def cleanup(self):
        errors, absent = [], {}
        def attempt(label, service, method, **kwargs):
            try:
                return self.call(label,service,method,**kwargs)
            except Exception as error:
                errors.append({"label":label,"error":str(error)})
        def missing(service, method, code, **kwargs):
            try:
                getattr(self.client(service),method)(**kwargs)
            except ClientError as error:
                if error.response["Error"]["Code"] == code:
                    return True
                raise
            return False
        o = self.owned
        if self.process is not None:
            try:
                self.data["observations"]["cleanupOwnedWorkerInventory"] = self.capture_worker_inventory()
                self.save()
            except Exception as error:
                errors.append({"label":"owned-worker-inventory","error":str(error)})
            if o.get("nodegroup"):
                attempt("delete-managed-workers","eks","delete_nodegroup",clusterName=o["cluster"],nodegroupName=o["nodegroup"])
                try:
                    absent["nodegroup"] = self.wait("managed owner cleanup",lambda:missing("eks","describe_nodegroup","ResourceNotFoundException",clusterName=o["cluster"],nodegroupName=o["nodegroup"]),bool,1200,3)
                except Exception as error:
                    errors.append({"label":"managed-owner-cleanup","error":str(error)})
            if o.get("cluster"):
                attempt("delete-worker-control","eks","delete_cluster",name=o["cluster"])
                try:
                    absent["cluster"] = self.wait("native control cleanup",lambda:missing("eks","describe_cluster","ResourceNotFoundException",name=o["cluster"]),bool,600,2)
                except Exception as error:
                    errors.append({"label":"native-control-cleanup","error":str(error)})
            for instance in o["instances"]:
                try:
                    self.wait("actual worker terminated",lambda:self.client("ec2").describe_instances(InstanceIds=[instance]),lambda r:r["Reservations"][0]["Instances"][0]["State"]["Name"]=="terminated",300)
                    absent[instance] = True
                except Exception as error:
                    errors.append({"label":instance,"error":str(error)})
            for kind, method, field, code in (("managedTemplates","describe_launch_templates","LaunchTemplateIds","InvalidLaunchTemplateId.NotFound"),("volumes","describe_volumes","VolumeIds","InvalidVolume.NotFound"),("enis","describe_network_interfaces","NetworkInterfaceIds","InvalidNetworkInterfaceID.NotFound")):
                for value in o[kind]:
                    try:
                        absent[value] = missing("ec2",method,code,**{field:[value]})
                        if not absent[value]:
                            raise RuntimeError("resource retained after nodegroup cleanup")
                    except Exception as error:
                        errors.append({"label":value,"error":str(error)})
            for profile in o["managedProfiles"]:
                try:
                    absent[profile] = missing("iam","get_instance_profile","NoSuchEntity",InstanceProfileName=profile)
                    if not absent[profile]:
                        raise RuntimeError("managed instance profile retained")
                except Exception as error:
                    errors.append({"label":profile,"error":str(error)})
            if o.get("asg"):
                try:
                    absent["autoscaling"] = not self.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[o["asg"]])["AutoScalingGroups"]
                    assert absent["autoscaling"]
                except Exception as error:
                    errors.append({"label":"autoscaling","error":str(error)})
            if o.get("template"):
                attempt("delete-customer-template","ec2","delete_launch_template",LaunchTemplateId=o["template"])
            for image in list(o["images"].values()) + ([o["image"]] if o.get("image") else []):
                attempt("deregister-worker-image","ec2","deregister_image",ImageId=image)
                try:
                    absent[image] = not self.client("ec2").describe_images(ImageIds=[image])["Images"]
                    assert absent[image], "owned image remains available"
                except Exception as error:
                    errors.append({"label":image,"error":str(error)})
            for snapshot in list(o["snapshots"].values()) + ([o["snapshot"]] if o.get("snapshot") else []):
                attempt("delete-worker-snapshot","ec2","delete_snapshot",SnapshotId=snapshot)
                try:
                    absent[snapshot] = missing("ec2","describe_snapshots","InvalidSnapshot.NotFound",SnapshotIds=[snapshot])
                    assert absent[snapshot], "owned firmware snapshot remains"
                except Exception as error:
                    errors.append({"label":snapshot,"error":str(error)})
            for role in o.get("roles",{}).values():
                for policy in o.get("rolePolicies", {}).get(role, []):
                    attempt("delete-owned-role-policy","iam","delete_role_policy",RoleName=role,PolicyName=policy)
                attempt("delete-worker-role","iam","delete_role",RoleName=role)
                try:
                    absent[role] = missing("iam","get_role","NoSuchEntity",RoleName=role)
                    assert absent[role], "owned IAM role remains"
                except Exception as error:
                    errors.append({"label":role,"error":str(error)})
            if o.get("denyRule"):
                attempt("delete-worker-deny-rule","ec2","delete_network_acl_entry",NetworkAclId=o["acl"],RuleNumber=1,Egress=False)
            if o.get("routeTable"):
                attempt("delete-worker-default-route","ec2","delete_route",RouteTableId=o["routeTable"],DestinationCidrBlock="0.0.0.0/0")
            if o.get("igw"):
                attempt("detach-worker-igw","ec2","detach_internet_gateway",VpcId=o["vpc"],InternetGatewayId=o["igw"])
                attempt("delete-worker-igw","ec2","delete_internet_gateway",InternetGatewayId=o["igw"])
            if o.get("sg"):
                attempt("delete-worker-security-group","ec2","delete_security_group",GroupId=o["sg"])
            for subnet in o.get("subnets",[]):
                attempt("delete-worker-subnet","ec2","delete_subnet",SubnetId=subnet)
            if o.get("vpc"):
                attempt("delete-worker-vpc","ec2","delete_vpc",VpcId=o["vpc"])
            for key, method, field, code in (("template","describe_launch_templates","LaunchTemplateIds","InvalidLaunchTemplateId.NotFound"),
                                            ("sg","describe_security_groups","GroupIds","InvalidGroup.NotFound"),
                                            ("igw","describe_internet_gateways","InternetGatewayIds","InvalidInternetGatewayID.NotFound"),
                                            ("routeTable","describe_route_tables","RouteTableIds","InvalidRouteTableID.NotFound"),
                                            ("acl","describe_network_acls","NetworkAclIds","InvalidNetworkAclID.NotFound"),
                                            ("vpc","describe_vpcs","VpcIds","InvalidVpcID.NotFound"),
                                            ("subnets","describe_subnets","SubnetIds","InvalidSubnetID.NotFound")):
                values = o.get(key, []) if key == "subnets" else ([o[key]] if o.get(key) else [])
                for value in values:
                    try:
                        absent[value] = missing("ec2",method,code,**{field:[value]})
                        assert absent[value], "owned resource remains"
                    except Exception as error:
                        errors.append({"label":value,"error":str(error)})
            if o.get("nativeID"):
                try:
                    for resource in ("container","network","volume"):
                        assert not self.command(["docker",resource,"ls","-q","--filter",f"label=stackd.eks.id={o['nativeID']}"]).strip()
                    absent["nativeKubernetesResources"] = True
                except Exception as error:
                    errors.append({"label":"native-resources","error":str(error)})
            try:
                linked = [role for role in self.client("iam").list_roles(PathPrefix="/aws-service-role/")["Roles"]
                          if role["RoleName"] in ("AWSServiceRoleForAmazonEKSNodegroup","AWSServiceRoleForAutoScaling","AWSServiceRoleForAmazonEKS")]
                if not errors and (not o.get("nativeID") or absent.get("nativeKubernetesResources")):
                    self.expire_cleanup_service_sessions(linked)
                for role in linked:
                    task = self.call("delete-owned-service-linked-role","iam","delete_service_linked_role",RoleName=role["RoleName"])["DeletionTaskId"]
                    result = self.wait("service-linked-role cleanup",lambda:self.client("iam").get_service_linked_role_deletion_status(DeletionTaskId=task),lambda r:r["Status"] in ("SUCCEEDED","FAILED"),120)
                    if result["Status"] != "SUCCEEDED":
                        raise RuntimeError(json.dumps({"role":role["RoleName"], "task":task, "result":result}, default=str))
                    absent[role["RoleName"]] = missing("iam","get_role","NoSuchEntity",RoleName=role["RoleName"])
                    assert absent[role["RoleName"]]
            except Exception as error:
                errors.append({"label":"service-linked-roles","error":str(error)})
        self.data["cleanup"] = {"errors":errors,"absent":absent,"resource_deletes_completed":not errors,"shared_inputs":"Original raw images, official binaries and archives were not modified or deleted."}
        self.save()
        self.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary","k3d","raw-image","upgrade-image","workload-archive","state-directory","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--account")
    parser.add_argument("--bios",type=Path,default=Path("/usr/share/seabios/bios-256k.bin"))
    parser.add_argument("--workload-image",default="busybox:1.37.0")
    parser.add_argument("--port",type=int,default=48576)
    parser.add_argument("--cidr",default="10.195.0.0/16")
    parser.add_argument("--subnet",action="append",default=None)
    parser.add_argument("--gateway",default="10.195.0.1")
    parser.add_argument("--worker-advertise-host", required=True, help="Existing guest-reachable host IP for the native API; independent of the EC2 VPC gateway")
    parser.add_argument("--retain-on-failure", action="store_true", help="Retain exact-owned controller and guests for live diagnosis after failure; explicit cleanup remains required")
    args = parser.parse_args()
    args.subnet = args.subnet or ["10.195.1.0/24","10.195.2.0/24"]
    for name in ("binary","k3d","raw_image","upgrade_image","workload_archive","bios"):
        setattr(args,name,getattr(args,name).resolve(strict=True))
    smoke = Smoke(args)
    try:
        smoke.run()
    except BaseException as error:
        smoke.data["failure"] = {"type":type(error).__name__,"message":str(error)}
        smoke.save()
        raise
    finally:
        if args.retain_on_failure and smoke.data.get("failure"):
            smoke.data["cleanup"] = {"resource_deletes_completed":False, "retainedForDiagnosis":True,
                                     "controllerPID":smoke.process.pid if smoke.process else None,
                                     "stateDirectory":str(smoke.state), "cleanupRequired":True}
            smoke.save()
        else:
            smoke.cleanup()
    if not smoke.data["cleanup"]["resource_deletes_completed"]:
        raise RuntimeError(json.dumps(smoke.data["cleanup"]["errors"]))
    print(json.dumps({"passed":smoke.data["passed"],"observations":list(smoke.data["observations"]),"cleanupVerified":smoke.data["cleanup"]["absent"]},sort_keys=True))


if __name__ == "__main__":
    main()
