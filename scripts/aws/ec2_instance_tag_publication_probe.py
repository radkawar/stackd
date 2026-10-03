#!/usr/bin/env python3
"""Bounded running-guest EC2 tag publication capture using InstanceCapture.

One owned t3.nano, one 8-GiB gp3 root, no public network, key pair or guest
credential reads. Each console envelope repeats all timestamped guest samples, so
console publication delay cannot be confused with unchanged IMDS responses.
No account defaults or standing resources are modified. Cleanup is mandatory.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import signal
import time
import zlib

from ec2_instance_metadata_probe import DOCS
from ec2_instances_probe import InstanceCapture, console_records, interrupt
from ebs_encryption_probe import now
from ebs_volume_controls_probe import sanitized

GUEST = r'''#!/usr/bin/python3
import base64,datetime,json,pathlib,time,urllib.error,urllib.request,zlib
base="http://169.254.169.254"
boot=pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
paths=("tags","tags/instance","tags/instance/change","tags/instance/remove",
       "tags/instance/add","tags/instance/empty","tags/instance/suite",
       "tags/instance/absent","tag-sets","tag-sets/instance",
       "tags/instance/","tag-sets/instance/","/2020-10-27/meta-data/tags/instance")
records=[]
def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def get(path,token=None,method="GET"):
    headers={"X-aws-ec2-metadata-token":token} if token else {"X-aws-ec2-metadata-token-ttl-seconds":"21600"}
    try:
        response=urllib.request.urlopen(urllib.request.Request(base+path,method=method,headers=headers),timeout=2)
    except urllib.error.HTTPError as error: response=error
    except Exception as error: return {"path":path,"code":0,"error_type":type(error).__name__},""
    with response:
        body=response.read().decode()
        return {"path":path,"code":response.code,"body":body if method=="GET" else "<token-redacted>",
                "headers":{"Content-Type":response.headers.get("Content-Type","")}},body
row,token=get("/latest/api/token",method="PUT")
if row["code"]!=200: raise RuntimeError("No metadata token")
started=time.monotonic()
while time.monotonic()-started<850:
    sample={"sample":len(records),"kernel_boot_id":boot,"started_at":utc(),"http":[]}
    for leaf in paths:
        path=leaf if leaf.startswith("/") else "/latest/meta-data/"+leaf
        row,_=get(path,token)
        sample["http"].append(row)
    sample["finished_at"]=utc()
    records.append(sample)
    encoded=base64.b64encode(zlib.compress(json.dumps(records,separators=(",",":")).encode())).decode()
    with open("/dev/console","w") as console:
        console.write("STACKD_GUEST "+json.dumps({"boot_id":boot+"-sample-"+str(sample["sample"]),
            "boot_count":sample["sample"]+1,"records_zlib_base64":encoded},separators=(",",":"))+"\n")
    time.sleep(10)
'''


def decoded_samples(envelopes):
    samples={}
    for envelope in envelopes:
        for sample in json.loads(zlib.decompress(base64.b64decode(envelope["records_zlib_base64"]))):
            samples[(sample["kernel_boot_id"],sample["sample"])]=sample
    return sorted(samples.values(),key=lambda sample:sample["started_at"])


def matches(sample, expected, enabled):
    rows={row["path"]:row for row in sample["http"]}
    prefix="/latest/meta-data/"
    if not enabled:
        return all(row["code"]==404 for row in sample["http"])
    menu=rows[prefix+"tags/instance"]
    sets=rows[prefix+"tag-sets/instance"]
    if sets["code"]!=200: return False
    try: values=json.loads(sets["body"])
    except (KeyError,ValueError): return False
    if values!=expected: return False
    if expected:
        if menu["code"]!=200 or set(menu["body"].splitlines())!=set(expected): return False
    elif any(row["code"]!=404 for row in sample["http"] if row["path"].startswith(prefix+"tags")):
        return False
    for key in ("change","remove","add","empty","suite","absent"):
        row=rows[prefix+"tags/instance/"+key]
        if key in expected:
            if row["code"]!=200 or row["body"]!=expected[key]: return False
        elif row["code"]!=404: return False
    return True


class TagPublicationCapture(InstanceCapture):
    def __init__(self,args):
        super().__init__(args)
        if not args.cleanup_only:
            self.data.update(scope=__doc__,guest_program=GUEST,tag_phases=[])
            self.data["documentation"].extend(DOCS)
            self.data["bounds"]["max_simultaneous_instances"]=1
        self.save()

    def samples(self,iid,label):
        result=self.ec2(label,"get_console_output",{"InstanceId":iid,"Latest":True})
        envelopes=list(console_records(result.get("Output","")))
        return decoded_samples(envelopes)

    def api_state(self,iid,label):
        self.ec2(label+"-instances","describe_instances",{"InstanceIds":[iid]},required=True)
        self.ec2(label+"-tags","describe_tags",{"Filters":[{"Name":"resource-id","Values":[iid]}]},required=True)

    def phase(self,iid,name,expected,enabled=True,seconds=150):
        phase={"name":name,"started_at":now(),"expected_tags":dict(expected),"enabled":enabled,
               "observation_bound_seconds":seconds}
        self.data["tag_phases"].append(phase)
        self.save()
        self.api_state(iid,name+"-before")
        deadline=time.monotonic()+seconds
        attempt=0
        while True:
            samples=self.samples(iid,name+"-console-"+str(attempt))
            fresh=[sample for sample in samples if sample["started_at"]>=phase["started_at"]]
            observed=next((sample for sample in fresh if matches(sample,expected,enabled)),None)
            if fresh:
                phase["latest_guest_sample_at"]=fresh[-1]["finished_at"]
            if observed:
                phase["matched_sample"]={key:observed[key] for key in ("kernel_boot_id","sample","started_at","finished_at")}
                break
            if time.monotonic()>=deadline:
                phase["gap"]="No matching guest sample in bounded console capture; only decoded timestamped samples establish IMDS state."
                self.data["gaps"].append(name+": "+phase["gap"])
                break
            time.sleep(10)
            attempt+=1
        phase["finished_at"]=now()
        self.api_state(iid,name+"-after")
        self.save()
        return "matched_sample" in phase

    def run(self):
        self.deadline=time.monotonic()+self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.setup()
        request=self.request()
        request.pop("IamInstanceProfile")
        request["BlockDeviceMappings"]=request["BlockDeviceMappings"][:1]
        request["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"]=True
        expected={"suite":self.data["prefix"],"change":"initial","remove":"initial","empty":""}
        request["TagSpecifications"][0]["Tags"]=[{"Key":key,"Value":value} for key,value in expected.items()]
        request["UserData"]="#!/bin/bash\nset -eu\numask 077\nprintf '%s' '"+base64.b64encode(GUEST.encode()).decode()+"' | base64 -d > /root/stackd-tag-probe.py\ntimeout 860 python3 /root/stackd-tag-probe.py\n"
        self.data["user_data_sha256"]=hashlib.sha256(request["UserData"].encode()).hexdigest()
        self.save()
        iid=self.launch("run-tag-publication-guest",request,required=True)["Instances"][0]["InstanceId"]
        self.state(iid,"running","tag-publication-running")
        if not self.phase(iid,"initial",expected,seconds=180):
            raise RuntimeError("Initial tag guest state was not observed; refusing uncorrelated mutations")
        self.ec2("update-and-add","create_tags",{"Resources":[iid],"Tags":[{"Key":"change","Value":"updated"},{"Key":"add","Value":"added"}]},required=True)
        self.ec2("remove-one","delete_tags",{"Resources":[iid],"Tags":[{"Key":"remove"}]},required=True)
        expected.update(change="updated",add="added")
        del expected["remove"]
        self.phase(iid,"mutated",expected)
        self.ec2("disable-tag-metadata","modify_instance_metadata_options",{"InstanceId":iid,"InstanceMetadataTags":"disabled"},required=True)
        self.phase(iid,"disabled",expected,False,seconds=90)
        self.ec2("update-while-disabled","create_tags",{"Resources":[iid],"Tags":[{"Key":"change","Value":"while-disabled"}]},required=True)
        expected["change"]="while-disabled"
        self.ec2("reenable-tag-metadata","modify_instance_metadata_options",{"InstanceId":iid,"InstanceMetadataTags":"enabled"},required=True)
        self.phase(iid,"reenabled",expected)
        self.ec2("remove-all-tags","delete_tags",{"Resources":[iid]},required=True)
        self.phase(iid,"empty",{},seconds=150)
        self.data["capture_complete_at"]=now()
        self.save()

    def handoff(self):
        super().handoff()
        path=self.args.output.with_name(self.args.output.stem+"_handoff.json")
        summary=json.loads(path.read_text())
        samples=decoded_samples(row["guest"] for row in self.data["guest_observations"])
        self.data["guest_decoding"]={
            "boundary":"SDK console Output remains verbatim. Each compressed envelope repeats all preceding guest samples; decoded samples are deduplicated by kernel_boot_id and sample index.",
            "counter_boundary":"Envelope boot_id and boot_count are sample framing, not kernel boot or disk counters. Only kernel_boot_id from /proc/sys/kernel/random/boot_id establishes the guest's kernel boot identity."}
        self.save()
        phases=[]
        for original in self.data.get("tag_phases",[]):
            phase=dict(original)
            settled=next((sample for sample in samples
                if phase["started_at"]<=sample["started_at"]<=phase["finished_at"]
                and matches(sample,phase["expected_tags"],phase["enabled"])),None)
            if settled:
                phase["settled_sample"]={key:settled[key] for key in ("kernel_boot_id","sample","started_at","finished_at")}
            phases.append(phase)
        summary.update(tag_phases=phases,samples=samples,
            guest_decoding=self.data["guest_decoding"],
            documentation=list(dict.fromkeys(summary["documentation"]+[
                "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_"+name+".html"
                for name in ("CreateTags","DeleteTags","ModifyInstanceMetadataOptions")])),
            phase_analysis_boundary="Live gap fields remain unchanged. settled_sample is derived from retained timestamped HTTP rows, including empty hierarchical directories returning 404 rather than 200 with an empty body.",
            mutation_calls=[row for row in self.data["calls"] if row["operation"] in ("CreateTags","DeleteTags","ModifyInstanceMetadataOptions")],
            observation_boundary="Guest sample timestamps measure reads; GetConsoleOutput call times measure console delivery only. Sequential paths are not an atomic snapshot. Bounded waits establish no AWS propagation constant. One continuously running guest; no stop/start required by the documented contract.",
            tag_documentation={"source_url":DOCS[-1],"contract":"If you add or remove an instance tag, the instance metadata is updated while the instance is running, without needing to stop and then start the instance.","timing":"No propagation deadline is specified."})
        path.write_text(json.dumps(sanitized(summary),indent=2)+"\n")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region",default="us-east-1",choices=["us-east-1"])
    parser.add_argument("--output",type=Path,default=Path(".stackd/probes/ec2/instances_tag_publication.json"))
    parser.add_argument("--cleanup-only",action="store_true")
    parser.add_argument("--live-seconds",type=int,default=900,choices=range(720,901),metavar="720..900")
    args=parser.parse_args()
    args.audit_only=False
    capture=TagPublicationCapture(args)
    for signum in (signal.SIGALRM,signal.SIGINT,signal.SIGTERM): signal.signal(signum,interrupt)
    try:
        if not args.cleanup_only: capture.run()
    except Exception as error:
        capture.data["failure"]={"type":type(error).__name__,"message":str(error),"at":now()}
        capture.save()
        raise
    finally:
        capture.cleanup()
        capture.handoff()


if __name__=="__main__": main()
