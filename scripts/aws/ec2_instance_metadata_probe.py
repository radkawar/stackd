#!/usr/bin/env python3
"""One owned t3.nano guest: native IMDS version/directory and DMI evidence.

Reuses InstanceCapture's identity guard, isolated network, owned launch and strict
finally cleanup. One 8-GiB gp3 root and, with --secondary-ebs, one 1-GiB gp3
data disk; no public networking/credentials endpoint. Tokens remain in guest
memory. Console rows retain nonsecret metadata HTTP bodies and exact paths;
user-data bodies are represented by size/hash only.
The complete matrix attaches the owned instance profile and an imported public
key; no private key or credential document is retained. Menus are conditional on
that instance configuration. Historical category introduction dates come from
the separate retained AWS category documentation, not guessed menu aliases.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import signal
import time
import urllib.request
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ec2_instances_probe import InstanceCapture, interrupt
from ebs_encryption_probe import now
from ebs_volume_controls_probe import sanitized

DOCS = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/" + name + ".html" for name in (
    "instancedata-data-retrieval", "identify_ec2_instances", "ec2-instance-metadata",
    "instance-identity-documents", "work-with-tags-in-IMDS")]


def category_reference():
    url=DOCS[2]
    with urllib.request.urlopen(url.removesuffix(".html")+".md",timeout=30) as response:
        markdown=response.read().decode()
    category=None
    rows=[]
    for line in markdown.splitlines():
        if line.startswith("## Instance metadata categories"): category="meta-data"
        elif line.startswith("## Dynamic data categories"): category="dynamic"
        if not category or not line.startswith("|"): continue
        cells=[cell.strip() for cell in re.split(r"(?<!\\)\|",line.strip().strip("|"))]
        if len(cells)==3 and cells[0] not in ("Category","---"):
            rows.append({"root":category,"category":cells[0],"description":cells[1],"introduced_version":cells[2] or None})
    if not rows: raise RuntimeError("Primary metadata category tables were not found")
    return {"source_url":url,"retrieved_at":now(),"source_markdown":markdown,"categories":rows,
        "boundary":"Documentation-derived category introductions/conditions, separate from observed guest directory menus. Blank introduction versions remain unknown; no public IP, Spot or other unavailable resource is invented."}
GUEST = r'''#!/usr/bin/python3
import base64,hashlib,json,pathlib,time,urllib.request,urllib.error,zlib
base="http://169.254.169.254"
EXPECT_EMPTY_TAGS = False
boot=pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
sequence=0
records=[]
def emit(row,done=False):
    global sequence
    sequence+=1
    row.update(boot_id=boot+"-row-"+str(sequence),kernel_boot_id=boot,boot_count=int(done))
    records.append(row)
    if done:
        encoded=base64.b64encode(zlib.compress(json.dumps(records,separators=(",",":")).encode())).decode()
        with open("/dev/console","w") as console:
            console.write("STACKD_GUEST "+json.dumps({"boot_id":boot,"boot_count":1,"records_zlib_base64":encoded},separators=(",",":"))+"\n")
def get(path,token=None,method="GET",extra=None):
    headers=dict(extra or {})
    if token is not None: headers["X-aws-ec2-metadata-token"]=token
    if method=="PUT": headers.setdefault("X-aws-ec2-metadata-token-ttl-seconds","300")
    try:
        response=urllib.request.urlopen(urllib.request.Request(base+path,method=method,headers=headers),timeout=3)
    except urllib.error.HTTPError as error:
        response=error
    except Exception as error:
        return {"path":path,"method":method,"token_supplied":token is not None,"code":0,"error_type":type(error).__name__},""
    with response:
        body=response.read().decode()
        row={"path":path,"method":method,"token_supplied":token is not None,"code":response.code,
             "headers":{key:response.headers[key] for key in ("Content-Type","Content-Length","Server","Allow","X-aws-ec2-metadata-token-ttl-seconds") if key in response.headers}}
    if extra: row["request_headers"]=extra
    if method=="PUT":
        row["body"]="<token-redacted>" if row["code"]==200 else body
    elif "user-data" in path:
        row.update(body_length=len(body.encode()),body_sha256=hashlib.sha256(body.encode()).hexdigest())
    else: row["body"]=body
    return row,body
row,token=get("/latest/api/token",method="PUT")
emit(row)
if row["code"]!=200: raise RuntimeError("No metadata token")
for leaf in ("tag-sets","tag-sets/","tag-sets/instance","tag-sets/instance/"):
    row,body=get("/latest/meta-data/"+leaf,token)
    emit(row)
if EXPECT_EMPTY_TAGS:
    for attempt in range(25):
        row,body=get("/latest/meta-data/tags/instance",token)
        row["empty_tag_poll"]=attempt
        emit(row)
        if row["code"]==404 or (row["code"]==200 and not body):
            break
        time.sleep(5)
dmi={}
for key in ("product_uuid","sys_vendor","product_name","board_asset_tag"):
    try: dmi[key]=pathlib.Path("/sys/class/dmi/id/"+key).read_text().strip()
    except Exception as error: dmi[key]={"error_type":type(error).__name__}
emit({"dmi":dmi})
paths=["/","/latest","/latest/","/latest/meta-data","/latest/meta-data/","/latest/dynamic","/latest/dynamic/",
       "/2009-04-04/meta-data","/2009-04-04/meta-data/","/2009-04-04/","/2016-09-02/","/2018-09-24/","/2021-03-23/",
       "/2021-03-23/meta-data","/2021-03-23/meta-data/","/2021-03-23/dynamic/","/latest/user-data","/2009-04-04/user-data",
       "/0000-00-00/","/0000-00-00/meta-data/instance-id","/2021-03-24/","/2021-03-24/meta-data/instance-id"]
versions=[]
for path in paths:
    for auth in (None,token):
        row,body=get(path,auth)
        emit(row)
        if path=="/" and auth is not None and row["code"]==200: versions=body.splitlines()
for version in versions[:50]:
    if version and all(char in "0123456789-.latest" for char in version):
        for suffix in ("/meta-data/instance-id","/meta-data/","/dynamic/"):
            row,body=get("/"+version+suffix,token)
            emit(row)
leaves=("ami-manifest-path","profile","instance-action","instance-life-cycle","system","system/","system/hypervisor",
        "block-device-mapping","block-device-mapping/","block-device-mapping/ami","block-device-mapping/root",
        "block-device-mapping/ebs0","block-device-mapping/ebs1","placement","placement/","placement/availability-zone",
        "placement/availability-zone-id","placement/region","services","services/","services/domain","services/partition",
        "public-keys","public-keys/","public-keys/0","public-keys/0/","public-keys/0/openssh-key",
        "tags","tags/","tags/instance","tags/instance/","tags/instance/suite","tags/instance/absent",
        "network","network/","network/interfaces","network/interfaces/","network/interfaces/macs","network/interfaces/macs/",
        "public-ipv4","public-hostname","ipv6","spot/instance-action","autoscaling/target-lifecycle-state")
for leaf in leaves:
    row,body=get("/latest/meta-data/"+leaf,token)
    emit(row)
row,mac=get("/latest/meta-data/mac",token)
emit(row)
if row["code"]==200:
    network="network/interfaces/macs/"+mac
    for leaf in ("","/","/device-number","/network-card","/interface-id","/local-hostname","/local-ipv4s","/mac",
                 "/owner-id","/security-groups","/security-group-ids","/subnet-id","/subnet-ipv4-cidr-block",
                 "/vpc-id","/vpc-ipv4-cidr-block","/vpc-ipv4-cidr-blocks","/ipv6s","/public-ipv4s","/ipv4-associations/"):
        row,body=get("/latest/meta-data/"+network+leaf,token)
        emit(row)
    for version in ("2009-04-04","2011-01-01","2016-04-19","2016-06-30","2019-10-01","2020-10-27","2021-01-03"):
        for leaf in ("placement/","placement/availability-zone-id","placement/region","services/","services/partition",
                     network+"/",network+"/network-card",network+"/vpc-ipv4-cidr-blocks"):
            row,body=get("/"+version+"/meta-data/"+leaf,token)
            emit(row)
for path in ("/latest/dynamic/instance-identity","/latest/dynamic/instance-identity/","/latest/dynamic/instance-identity/document",
             "/latest/dynamic/fws/","/latest/dynamic/fws/instance-monitoring","/latest/meta-data/instance-id/",
             "/latest//meta-data/instance-id","/latest/meta-data/./instance-id","/latest/meta-data/instance-id?x=1",
             "/latest/meta-data/%69nstance-id"):
    row,body=get(path,token)
    emit(row)
for repeat in range(2):
    for leaf in ("document","signature","pkcs7","rsa2048"):
        row,body=get("/latest/dynamic/instance-identity/"+leaf,token)
        row["repeat"]=repeat
        emit(row)
for method in ("HEAD","POST","DELETE","OPTIONS"):
    row,body=get("/latest/meta-data/instance-id",token,method)
    emit(row)
for headers in ({"X-Forwarded-For":"192.0.2.1"}, *({"X-aws-ec2-metadata-token-ttl-seconds":ttl} for ttl in ("0","1","-1","21601","invalid"))):
    row,body=get("/latest/api/token",method="PUT",extra=headers)
    emit(row)
    if headers.get("X-aws-ec2-metadata-token-ttl-seconds")=="0" and row["code"]==200:
        for delay in (0,1):
            time.sleep(delay)
            zero_row,_=get("/latest/meta-data/instance-id",body)
            zero_row.update(token_requested_ttl=0,delay_seconds=delay)
            emit(zero_row)
for path in ("/2021-03-23/api/token","/2009-04-04/api/token","/latest/api/token/"):
    for auth in (None,token):
        row,body=get(path,auth,method="PUT")
        emit(row)
del token
emit({"finished":True,"request_rows":sequence,"versions":versions},done=True)
'''


class MetadataCapture(InstanceCapture):
    def __init__(self,args):
        super().__init__(args)
        if not args.cleanup_only:
            disks="8-GiB gp3 root"+(" and one 1-GiB gp3 data disk" if args.secondary_ebs else "")
            self.data.update(scope="One isolated owned AL2023 t3.nano with "+disks+"; nonsecret IMDS path/version/DMI capture only",guest_program=GUEST)
            self.data["documentation"].extend(DOCS)
            self.data["bounds"]["max_simultaneous_instances"]=1
        self.save()

    def run(self):
        self.deadline=time.monotonic()+self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.setup()
        key_name=self.data["prefix"]+"-metadata"
        self.data["owned"]["key_pair"]=key_name
        self.save()
        public=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH,serialization.PublicFormat.OpenSSH)
        self.ec2("owned-metadata-public-key","import_key_pair",{"KeyName":key_name,"PublicKeyMaterial":public,
            "TagSpecifications":self.tags("key-pair")},required=True)
        request=self.request()
        if not self.args.secondary_ebs:
            request["BlockDeviceMappings"]=request["BlockDeviceMappings"][:1]
        for mapping in request["BlockDeviceMappings"]:
            mapping["Ebs"]["DeleteOnTermination"]=True
        request["KeyName"]=key_name
        guest=GUEST.replace("EXPECT_EMPTY_TAGS = False","EXPECT_EMPTY_TAGS = "+str(self.args.without_tags))
        self.data["guest_program"]=guest
        request["UserData"]="#!/bin/bash\nset -eu\nprintf '%s' '"+base64.b64encode(guest.encode()).decode()+"' | base64 -d > /root/stackd-imds-probe.py\ntimeout 180 python3 /root/stackd-imds-probe.py\n"
        self.data["user_data_sha256"]=hashlib.sha256(request["UserData"].encode()).hexdigest()
        self.save()
        iid=self.launch("run-imds-route-guest",request,required=True)["Instances"][0]["InstanceId"]
        if self.args.without_tags:
            self.ec2("remove-owned-instance-tags","delete_tags",{"Resources":[iid],"Tags":[{"Key":"suite"}]},required=True)
        self.state(iid,"running","imds-route-running")
        record=self.console(iid,1,"imds-route-console",seconds=240)
        if record is None:
            raise RuntimeError("Guest IMDS route evidence incomplete")
        self.data["capture_complete_at"]=now()
        self.save()

    def cleanup(self):
        if self.data.get("cleanup"):
            self.data.setdefault("cleanup_attempts",[]).append(self.data["cleanup"])
            self.save()
        try:
            super().cleanup()
        finally:
            key_name=self.data["owned"].get("key_pair")
            if key_name:
                self.ec2("cleanup-metadata-key","delete_key_pair",{"KeyName":key_name})
                self.ec2("cleanup-metadata-key-absence","describe_key_pairs",{"KeyNames":[key_name]})
                absent=self.data["calls"][-1]["code"]=="InvalidKeyPair.NotFound"
                self.data["cleanup"]["key_pair_absent_verified"]=absent
                self.data["cleanup"]["complete"]=self.data["cleanup"].get("complete",False) and absent
                self.save()
                if not absent: raise RuntimeError("Owned metadata public key cleanup unverified")

    def handoff(self):
        super().handoff()
        path=self.args.output.with_name(self.args.output.stem+"_handoff.json")
        summary=json.loads(path.read_text())
        rows=[row["guest"] for row in self.data["guest_observations"]]
        expanded=[]
        for row in rows:
            if "records_zlib_base64" in row:
                expanded.extend(json.loads(zlib.decompress(base64.b64decode(row["records_zlib_base64"]))))
            else: expanded.append(row)
        rows=expanded
        finished=[row for row in rows if row.get("finished")]
        expected_rows=finished[0]["request_rows"]+1 if len(finished)==1 else None
        summary["console_completeness"]={"captured_rows":len(rows),"expected_rows":expected_rows,
            "all_emitted_rows_decoded":expected_rows is not None and len(rows)==expected_rows}
        summary.update(metadata_http=[row for row in rows if "path" in row],dmi=[row["dmi"] for row in rows if "dmi" in row],
            completed=[row for row in rows if row.get("finished")],user_data_sha256=self.data.get("user_data_sha256"),
            admission_boundary="HttpTokens=required on this guest. Tokenless statuses do not establish HttpTokens=optional behavior. Version list is observed on this freshly launched Nitro guest, not timeless universal availability.",
            guest_decoding={"boundary":"Native console retains one compressed JSON envelope to avoid serial ring truncation; metadata_http contains losslessly decoded rows. kernel_boot_id is the real Linux boot identity; per-row IDs and completion counter are capture framing, not disk counters."},
            runtime_boundary="Native AL2023 IMDS/DMI paths only; local QEMU/KVM cloud-init compatibility is separately exercised.")
        if self.data.get("cleanup_attempts"):
            summary["cleanup_attempts"]=self.data["cleanup_attempts"]
        polls=[row for row in rows if "empty_tag_poll" in row]
        if polls:
            summary["tag_publication"]={"poll_count":len(polls),
                "empty_observed":any(row["code"]==404 or (row["code"]==200 and not row.get("body")) for row in polls),
                "boundary":"SDK DeleteTags precedes guest polling; native metadata may retain removed tags throughout this bounded observation. No convergence time or empty-menu behavior is inferred without an observed empty result."}
        summary["versioned_token_boundary"]={
            "documented":"AWS documents PUT on a version-specific api/token path returning 403.",
            "observed":[{"path":row["path"],"code":row["code"],"token_supplied":row["token_supplied"]}
                for row in rows if row.get("method")=="PUT" and not row["path"].startswith("/latest/")],
            "unobserved":"HttpTokens=optional. Do not generalize token-required admission precedence to optional-token instances."}
        summary["version_directories"]={version:{
            category:next(({"code":row["code"],"body":row.get("body"),"headers":row.get("headers")} for row in rows
                if row.get("path")=="/"+version+"/"+category+"/" and row.get("token_supplied") and row.get("method")=="GET"),None)
            for category in ("meta-data","dynamic")}
            for version in (finished[0]["versions"] if finished else [])}
        summary["launch_context"]=[row["input"] for row in self.data["calls"] if row["operation"]=="RunInstances" and row["code"]=="Success"]
        try:
            summary["category_reference"]=category_reference()
        except Exception as error:
            summary["category_reference"]={"source_url":DOCS[2],"error_type":type(error).__name__,"message":str(error)}
        path.write_text(json.dumps(sanitized(summary),indent=2)+"\n")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region",default="us-east-1",choices=["us-east-1"])
    parser.add_argument("--output",type=Path,default=Path(".stackd/probes/ec2/instances_metadata_routes.json"))
    parser.add_argument("--cleanup-only",action="store_true")
    parser.add_argument("--without-tags",action="store_true",help="Remove only this owned instance's suite tag before guest boot to capture empty-tag menus")
    parser.add_argument("--secondary-ebs",action="store_true",help="Retain the shared probe's bounded 1-GiB /dev/sdf launch disk to capture secondary metadata spelling")
    parser.add_argument("--live-seconds",type=int,default=600,choices=range(300,721),metavar="300..720")
    args=parser.parse_args()
    args.audit_only=False
    capture=MetadataCapture(args)
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
