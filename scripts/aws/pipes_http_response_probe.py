#!/usr/bin/env python3
"""Bounded native HTTP coding/decoded-response capture; reuse exact-owned harness.

Requires independent ethics approval before native execution. Cleanup-only uses
this capture's original inventory. No payload padding or API key is retained.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import signal
import time
import urllib.request
import zlib

from pipes_http_enrichment_probe import Probe, now

HANDLER = '''import base64,boto3,gzip,hashlib,hmac,json,os,time,zlib
from botocore.config import Config
sqs=boto3.client("sqs",config=Config(connect_timeout=1,read_timeout=1,retries={"total_max_attempts":1}))
def handler(event,context):
    headers=event.get("headers",{})
    if not hmac.compare_digest(headers.get("x-owned-key",""),os.environ["KEY"]):
        return {"statusCode":403,"body":"forbidden"}
    if time.time()>float(os.environ["EXPIRES"]):
        return {"statusCode":410,"body":"expired"}
    try:
        payload=json.loads(event.get("body",""))
        rows=payload if isinstance(payload,list) else [payload]
        decoded=[]
        for row in rows:
            body=row.get("body",row)
            if isinstance(body,str): body=json.loads(body)
            if not isinstance(body,dict) or not body.get("marker","").startswith(os.environ["PREFIX"]):
                return {"statusCode":400,"body":"foreign marker"}
            decoded.append(body)
        mode=decoded[0]["mode"]
        result=[{"marker":r["marker"],"calculated":int(r["number"])*7+3,"upper":r["text"].upper(),"derived":"first"} for r in decoded]
        if mode=="multi":
            result.append(dict(result[0],calculated=result[0]["calculated"]+1,derived="second"))
        sizes={"identity-over-1m":1048577,"gzip-over-1m":1048577,"gzip-6m":6291456,"gzip-over-6m":6291457}
        if mode in sizes:
            result[0]["padding"]=""
            initial=json.dumps(result,separators=(",",":")).encode()
            result[0]["padding"]="x"*(sizes[mode]-len(initial))
        plain=json.dumps(result,separators=(",",":")).encode()
        encoding="gzip" if mode.startswith("gzip") else "deflate" if mode in ("zlib","raw-deflate") else None
        wire=gzip.compress(plain,mtime=0) if encoding=="gzip" else zlib.compress(plain) if mode=="zlib" else zlib.compress(plain,wbits=-15) if mode=="raw-deflate" else plain
        if mode=="gzip-truncated": wire=wire[:-8]
        audit={"request_id":context.aws_request_id,"at":time.time(),"path":event.get("rawPath"),"marker":decoded[0]["marker"],"mode":mode,"headers":{k:v for k,v in headers.items() if k in ("range","accept-encoding","content-type","user-agent")},"response_status":200,"content_encoding":encoding,"decoded_bytes":len(plain),"decoded_sha256":hashlib.sha256(plain).hexdigest(),"wire_bytes":len(wire),"wire_sha256":hashlib.sha256(wire).hexdigest(),"results":[{k:v for k,v in r.items() if k!="padding"} for r in result]}
        sqs.send_message(QueueUrl=os.environ["AUDIT"],MessageBody=json.dumps(audit,separators=(",",":")))
        response_headers={"content-type":"application/json"}
        if encoding: response_headers["content-encoding"]=encoding
        return {"statusCode":200,"headers":response_headers,"isBase64Encoded":True,"body":base64.b64encode(wire).decode()}
    except Exception as error:
        return {"statusCode":500,"body":type(error).__name__}
'''

CASES = ("identity", "gzip", "zlib", "raw-deflate", "multi",
         "identity-over-1m", "gzip-over-1m", "gzip-6m", "gzip-over-6m", "gzip-truncated")
TARGET_TEMPLATE = '{"marker":<$.marker>,"calculated":<$.calculated>,"upper":<$.upper>,"derived":<$.derived>}'


class ResponseProbe(Probe):
    handler = HANDLER

    def wire_check(self, mode):
        payload = {"marker": self.prefix + "-wire-" + mode, "mode": mode,
                   "number": 4, "text": "owned-native"}
        row = {"mode": mode, "at": now()}
        self.data.setdefault("wire_checks", []).append(row)
        request = urllib.request.Request(self.owned["url"] + "wire", method="POST",
            data=json.dumps(payload).encode(), headers={"x-owned-key": self.key,
            "Content-Type": "application/json", "Accept-Encoding": "gzip,deflate"})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                wire = response.read(2 * 1024 * 1024)
                row.update(status=response.status, headers=dict(response.headers.items()),
                    wire_bytes=len(wire), wire_sha256=hashlib.sha256(wire).hexdigest())
            try:
                plain = gzip.decompress(wire) if mode.startswith("gzip") else zlib.decompress(wire) if mode == "zlib" else zlib.decompress(wire, -15) if mode == "raw-deflate" else wire
                result = json.loads(plain)
                row.update(decoded_bytes=len(plain), decoded_sha256=hashlib.sha256(plain).hexdigest(),
                    results=[{k: v for k, v in item.items() if k != "padding"} for item in result])
            except (EOFError, OSError, zlib.error, ValueError) as error:
                row["decode_error"] = {"type": type(error).__name__, "message": str(error)}
                if mode != "gzip-truncated":
                    raise
        except BaseException as error:
            row["failure"] = {"type": type(error).__name__, "message": str(error)}
            raise
        finally:
            self.save()

    def drain_source(self, case):
        self.call("stop-after-" + case, "pipes", "stop_pipe", {"Name": self.prefix})
        self.wait_pipe("STOPPED")
        deadline = time.monotonic() + 35
        removed = []
        while time.monotonic() < deadline:
            out = self.call("read-drain-" + case, "sqs", "receive_message", {
                "QueueUrl": self.owned["queues"]["source"]["url"], "WaitTimeSeconds": 2,
                "MaxNumberOfMessages": 10})
            for message in out.get("Messages", []):
                body = json.loads(message["Body"])
                if not body.get("marker", "").startswith(self.prefix + "-"):
                    raise RuntimeError("Foreign source message")
                removed.append(body)
                self.call("ack-drain-" + case, "sqs", "delete_message", {
                    "QueueUrl": self.owned["queues"]["source"]["url"], "ReceiptHandle": message["ReceiptHandle"]})
            if removed:
                break
        self.data["cases"][case]["source_drained"] = removed
        self.save()
        self.call("start-after-" + case, "pipes", "start_pipe", {"Name": self.prefix})
        self.wait_pipe("RUNNING")

    def run(self):
        self.data.update(probe_kind="http-response", response_probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            ethics_review={"decision": "allow", "reviewed_at": "2026-10-01", "scope": "One exact-owned resource set; max20 source messages/20min; direct owned known-key wire validation; coding and decoded-size boundary; no standing-role writes", "reason": "permitted"},
            limitations=["Bounded non-observation is not permanent failure or an inferred size limit.",
                "No retry timing conclusions; failed cases stop and drain exact-owned source.",
                "Direct Function URL wire checks and Pipes execution are recorded separately.",
                "Repetitive padding measures decoded bytes, not general response complexity or compressed-wire limits."])
        cases = CASES
        if self.args.corrected_prerequisite:
            cases = ("raw-deflate", "gzip", "zlib")
            self.data["ethics_review"]["scope"] = "Corrected-prerequisite second resource set explicitly approved; first fully absent; rate10; three source messages; cumulative successful messages15 and original20min deadline; no new sizes."
        self.save()
        self.setup()
        if self.args.corrected_prerequisite:
            self.call("correct-destination-admission", "events", "update_api_destination",
                {"Name": self.prefix, "InvocationRateLimitPerSecond": 10})
        self.call("target-strip-padding", "pipes", "update_pipe", {"Name": self.prefix,
            "RoleArn": self.owned["pipe_role_arn"], "TargetParameters": {"InputTemplate": TARGET_TEMPLATE}})
        self.wait_pipe("RUNNING")
        for case in cases:
            self.wire_check(case)
            time.sleep(2)
            self.send(case, mode=case)
            self.observe(case, seconds=40, target_count=2 if case == "multi" else 1)
            messages = self.data["cases"][case]["windows"][-1]["observed"]
            targets = [m["body"] for m in messages if m["queue"] == "target" and self.prefix + "-" + case + "-0" in json.dumps(m["body"])]
            audits = [m["body"] for m in messages if m["queue"] == "audit" and m["body"].get("marker") == self.prefix + "-" + case + "-0"]
            self.data["cases"][case]["finding"] = {"targets": targets, "pipe_audits": audits,
                "observation": "target observed" if targets else "no target in bounded window"}
            self.save()
            print("FINDING " + json.dumps({"case": case, "targets": targets, "pipe_audits": audits}), flush=True)
            if not targets:
                self.drain_source(case)
        self.observe("audit-settle", seconds=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/pipes/http_response.json"))
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--corrected-prerequisite", action="store_true",
                        help="Separately reviewed three-case rate10 admission correction")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    probe = ResponseProbe(args)
    def interrupted(signum, frame):
        raise RuntimeError("Interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        if not args.cleanup_only:
            probe.run()
    except BaseException as error:
        probe.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        probe.save()
        raise
    finally:
        probe.cleanup()
    print(json.dumps({"capture": str(args.output), "cleanup": probe.data["cleanup"]}), flush=True)


if __name__ == "__main__":
    main()
