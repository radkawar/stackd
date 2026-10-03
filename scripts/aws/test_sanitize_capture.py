"""Offline behavior checks for publishing identity-redacted captures."""

import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from sanitize_capture import Sanitizer, account_prefix


ACCOUNT = "012345678900"
REPLACEMENT = "000000000000"


class SanitizeCaptureTest(unittest.TestCase):
    def test_nested_gzip_base64_zip_and_binary_payloads(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.comment = ACCOUNT.encode()
            entry = zipfile.ZipInfo(ACCOUNT + "/payload.json")
            entry.comment = ACCOUNT.encode()
            output.writestr(entry, json.dumps({"Account": ACCOUNT, "Other": "111111111111"}))
        capture = {
            "archive": base64.b64encode(gzip.compress(archive.getvalue(), mtime=0)).decode(),
            "binary": base64.b64encode(b"\xff\x00" + ACCOUNT.encode()).decode(),
            "url": "https://example.invalid/" + "".join("%%%02X" % ord(c) for c in ACCOUNT),
            "numeric": int(ACCOUNT),
        }
        cleaned = Sanitizer(ACCOUNT).capture(json.dumps(capture).encode())
        result = json.loads(cleaned)
        with zipfile.ZipFile(io.BytesIO(gzip.decompress(base64.b64decode(result["archive"])))) as incoming:
            self.assertEqual(incoming.comment, REPLACEMENT.encode())
            entry = incoming.getinfo(REPLACEMENT + "/payload.json")
            self.assertEqual(entry.comment, REPLACEMENT.encode())
            self.assertEqual(json.loads(incoming.read(entry)), {"Account": REPLACEMENT, "Other": "111111111111"})
        self.assertEqual(base64.b64decode(result["binary"]), b"\xff\x00" + REPLACEMENT.encode())
        self.assertEqual(result["url"], "https://example.invalid/" + "%30" * 12)
        self.assertEqual(result["numeric"], 0)
        self.assertEqual(Sanitizer(ACCOUNT).capture(cleaned), cleaned)

    def test_message_body_whitespace_and_md5_remain_consistent(self):
        body = '{\n  "Account": "' + ACCOUNT + '",\n  "Message": "kept"\n}'
        source = json.dumps({"Messages": [{"Body": body, "MD5OfBody": hashlib.md5(body.encode()).hexdigest()}]})
        result = json.loads(Sanitizer(ACCOUNT).capture(source.encode()))["Messages"][0]
        self.assertEqual(result["Body"], body.replace(ACCOUNT, REPLACEMENT))
        self.assertEqual(result["MD5OfBody"], hashlib.md5(result["Body"].encode()).hexdigest())

    def test_encoded_capture_sha256_tracks_redacted_bytes(self):
        body = ('{"account":"' + ACCOUNT + '","message":"retained whitespace"}\n').encode()
        source = {
            "Body": {
                "base64": base64.b64encode(body).decode(),
                "utf8": body.decode(),
                "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            },
            "negative": {"sha256": hashlib.sha256(b"wrong payload").hexdigest()},
        }
        cleaned = Sanitizer(ACCOUNT).capture(json.dumps(source).encode())
        result = json.loads(cleaned)
        decoded = base64.b64decode(result["Body"]["base64"])
        self.assertEqual(decoded, body.replace(ACCOUNT.encode(), REPLACEMENT.encode()))
        self.assertEqual(result["Body"]["utf8"], decoded.decode())
        self.assertEqual(result["Body"]["size"], len(decoded))
        self.assertEqual(result["Body"]["sha256"], hashlib.sha256(decoded).hexdigest())
        self.assertEqual(result["negative"], source["negative"])
        self.assertEqual(Sanitizer(ACCOUNT).capture(cleaned), cleaned)

    def test_modern_access_key_account_and_masked_suffix(self):
        odd_account = "012345678901"
        key = "ASIA" + account_prefix(odd_account) + "QABCDEFG"
        result = json.loads(Sanitizer(odd_account).capture(json.dumps({"Key": key, "Masked": "********8901"}).encode()))
        self.assertEqual(result["Key"], "ASIAQAAAAAAAAABCDEFG")
        self.assertEqual(result["Masked"], "********0000")

    def test_malformed_nested_gzip_negative_case_is_preserved(self):
        malformed = gzip.compress(b"an intentionally invalid member", mtime=0)[:12]
        source = json.dumps({"Data": base64.b64encode(malformed).decode(), "Account": ACCOUNT}).encode()
        result = json.loads(Sanitizer(ACCOUNT).capture(source))
        self.assertEqual(base64.b64decode(result["Data"]), malformed)
        self.assertEqual(result["Account"], REPLACEMENT)

    def test_foreign_account_remains_distinct_without_rewriting_resource_ids(self):
        body = json.dumps({"Owner": ACCOUNT, "Foreign": REPLACEMENT, "Snapshot": "snap-" + "0" * 17, "Count": 0})
        capture = {"Body": body, "MD5OfBody": hashlib.md5(body.encode()).hexdigest()}
        result = json.loads(Sanitizer(ACCOUNT).capture(json.dumps(capture).encode()))
        changed = json.loads(result["Body"])
        self.assertEqual(changed["Owner"], REPLACEMENT)
        self.assertEqual(changed["Foreign"], "999000999000")
        self.assertEqual(changed["Snapshot"], "snap-" + "0" * 17)
        self.assertEqual(changed["Count"], 0)
        self.assertEqual(result["MD5OfBody"], hashlib.md5(result["Body"].encode()).hexdigest())

    def test_prefix_only_redaction_keeps_already_anonymized_account(self):
        source = {"Account": REPLACEMENT, "UserId": "AIDA" + account_prefix(ACCOUNT) + "ABCDEFGH"}
        result = json.loads(Sanitizer(ACCOUNT).capture(json.dumps(source).encode()))
        self.assertEqual(result["Account"], REPLACEMENT)
        self.assertNotEqual(result["UserId"], source["UserId"])

    def test_cli_keeps_private_source_and_checks_published_output(self):
        script = Path(__file__).with_name("sanitize_capture.py")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "private.json"
            destination = Path(directory) / "published.json"
            original = json.dumps({"Account": ACCOUNT}).encode()
            source.write_bytes(original)
            command = [sys.executable, str(script), "--account", ACCOUNT]
            rejected = subprocess.run(command + ["--input", str(source), "--check"], capture_output=True)
            self.assertEqual(rejected.returncode, 1)
            published = subprocess.run(command + ["--input", str(source), "--output", str(destination)], capture_output=True)
            self.assertEqual(published.returncode, 0, published.stderr.decode())
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(json.loads(destination.read_bytes()), {"Account": REPLACEMENT})
            checked = subprocess.run(command + ["--input", str(destination), "--check"], capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())
            overwrite = subprocess.run(command + ["--input", str(source), "--output", str(source)], capture_output=True)
            self.assertEqual(overwrite.returncode, 2)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
