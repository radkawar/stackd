#!/usr/bin/env python3
"""Publish account-redacted captures from a private probe workspace.

This is an identity transformation, not a cryptographic re-signing operation.
Authenticated fixtures need separately regenerated, explicitly local vectors.
Raw captures and cleanup manifests must remain private and unchanged.
"""

import argparse
import base64
import binascii
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile
import zlib


_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_PEM = re.compile(r"(-----BEGIN ([A-Z0-9 ]+)-----\s*)([A-Za-z0-9+/=\s]+?)(\s*-----END \2-----)")
_DIGEST_FIELDS = {"MD5OfBody", "MD5OfMessageBody", "ContentMD5", "content-md5", "sha256", "SHA256"}


def account_id(value):
    if not re.fullmatch(r"[0-9]{12}", value):
        raise argparse.ArgumentTypeError("account must contain exactly 12 ASCII digits")
    return value


def account_prefix(account):
    """Return the modern account-bearing eight-character AWS identity prefix."""
    number = (1 << 39) + int(account) // 2
    return base64.b32encode(number.to_bytes(5, "big")).decode("ascii")


class Sanitizer:
    """Redact direct and encoded identity references without exposing the source ID."""

    def __init__(self, account, replacement="000000000000", *, _literal_only=False):
        self.account = account_id(account)
        self.replacement = account_id(replacement)
        self.source_prefix = account_prefix(account)
        self.target_prefix = account_prefix(replacement)
        self.digests = {}
        self.literal_only = _literal_only
        self.account_changed = False
        # Also match account digits escaped individually in a URL or text capture.
        self.escaped_account = re.compile(
            "".join("(?:" + digit + "|%" + format(ord(digit), "02x") + ")" for digit in account),
            re.IGNORECASE,
        )

    def _remember(self, before, after):
        if before != after:
            for algorithm in (hashlib.md5, hashlib.sha256):
                old_digest, new_digest = algorithm(before).digest(), algorithm(after).digest()
                self.digests[old_digest.hex()] = new_digest.hex()
                self.digests[base64.b64encode(old_digest).decode()] = base64.b64encode(new_digest).decode()
        return after

    def _direct(self, text):
        if self.literal_only:
            return re.sub(r"(?<![A-Za-z0-9])" + self.account + r"(?![A-Za-z0-9])", self.replacement, text)
        self.account_changed |= self.account in text
        text = text.replace(self.account, self.replacement)
        if str(int(self.account)) != self.account:
            text, replacements = re.subn(r"(?<![0-9])" + str(int(self.account)) + r"(?![0-9])", str(int(self.replacement)), text)
            self.account_changed |= replacements != 0
        def identity(match):
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            suffix = match.group(2)
            parity = 16 if int(self.replacement) % 2 else 0
            first = alphabet[alphabet.index(suffix[0]) % 16 + parity]
            return match.group(1) + self.target_prefix + first + suffix[1:]

        text = re.sub(r"(A[A-Z0-9]{3})" + self.source_prefix + r"([A-Z2-7]{8,9})(?![A-Z2-7])", identity, text)
        text = text.replace(self.source_prefix, self.target_prefix)
        text = re.sub(r"\*{4,}" + re.escape(self.account[-4:]), lambda m: m.group()[:-4] + self.replacement[-4:], text)

        def escaped(match):
            self.account_changed = True
            original = match.group()
            if "%" not in original:
                return self.replacement
            units = re.findall(r"%[0-9a-fA-F]{2}|.", original)
            return "".join("%" + format(ord(new), "02X") if old.startswith("%") else new for old, new in zip(units, self.replacement))

        return self.escaped_account.sub(escaped, text)

    def _base64(self, match, depth):
        token = match.group()
        if len(token.rstrip("=")) % 4 == 1:
            return token
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        except (ValueError, binascii.Error):
            return token
        changed = self.bytes(decoded, depth + 1)
        if changed == decoded:
            return token
        encoder = base64.urlsafe_b64encode if "-" in token or "_" in token else base64.b64encode
        encoded = encoder(changed).decode("ascii")
        return encoded if token.endswith("=") else encoded.rstrip("=")

    def text(self, text, depth=0):
        if depth > 64:
            raise ValueError("capture encoding nesting exceeds the supported limit")
        original = text
        text = self._direct(text)
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            # Rewrite string tokens rather than serializing the whole document:
            # preserve capture formatting and exact message-body whitespace.
            def string_token(match):
                token = match.group()
                value = json.loads(token)
                changed = self.text(value, depth + 1)
                if changed == value:
                    return token
                return json.dumps(changed, ensure_ascii="\\u" in token)
            text = _JSON_STRING.sub(string_token, text)
        else:
            def pem(match):
                encoded = re.sub(r"\s+", "", match.group(3))
                try:
                    decoded = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error):
                    return match.group()
                changed = self.bytes(decoded, depth + 1)
                if changed == decoded:
                    return match.group()
                body = base64.b64encode(changed).decode("ascii")
                return match.group(1) + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + match.group(4)
            text = _PEM.sub(pem, text)
            text = _BASE64.sub(lambda m: self._base64(m, depth), text)
        self._remember(original.encode(), text.encode())
        return text

    def bytes(self, data, depth=0):
        if depth > 64:
            raise ValueError("capture encoding nesting exceeds the supported limit")
        if data.startswith(b"\x1f\x8b"):
            try:
                plain = gzip.decompress(data)
            except (OSError, EOFError, zlib.error):
                plain = None
            if plain is not None:
                changed = self.bytes(plain, depth + 1)
                header_changed = self.account.encode() in data or self.source_prefix.encode() in data
                return data if changed == plain and not header_changed else self._remember(data, gzip.compress(changed, mtime=0))
        if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
            source = io.BytesIO(data)
            if zipfile.is_zipfile(source):
                target = io.BytesIO()
                changed_any = False
                with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(target, "w") as outgoing:
                    outgoing.comment = self.bytes(incoming.comment, depth + 1)
                    changed_any |= outgoing.comment != incoming.comment
                    for entry in incoming.infolist():
                        plain = incoming.read(entry)
                        changed = self.bytes(plain, depth + 1)
                        filename = self._direct(entry.filename)
                        comment = self.bytes(entry.comment, depth + 1)
                        changed_any |= changed != plain or filename != entry.filename or comment != entry.comment
                        entry.filename = filename
                        entry.comment = comment
                        outgoing.writestr(entry, changed)
                return self._remember(data, target.getvalue()) if changed_any else data
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if self.literal_only:
                return self._remember(data, self._direct(data.decode("latin-1")).encode("latin-1"))
            # Account substitutions are same-width inside binary Ion/ASN.1/AAD.
            self.account_changed |= self.account.encode() in data
            changed = data.replace(self.account.encode(), self.replacement.encode())
            changed = changed.replace(self.source_prefix.encode(), self.target_prefix.encode())
            return self._remember(data, changed)
        return self._remember(data, self.text(text, depth).encode("utf-8"))

    def _capture(self, data):
        changed = self.bytes(data)
        compressed = changed.startswith(b"\x1f\x8b")
        plain = gzip.decompress(changed) if compressed else changed
        try:
            text = plain.decode("utf-8")
            value = json.loads(text)
            before = json.loads(gzip.decompress(data) if data.startswith(b"\x1f\x8b") else data)
        except (UnicodeDecodeError, ValueError):
            return changed

        def remember_strings(old, new):
            if isinstance(old, str) and isinstance(new, str):
                self._remember(old.encode(), new.encode())
            elif isinstance(old, dict) and isinstance(new, dict):
                for left, right in zip(old.values(), new.values()):
                    remember_strings(left, right)
            elif isinstance(old, list) and isinstance(new, list):
                for left, right in zip(old, new):
                    remember_strings(left, right)

        remember_strings(before, value)
        # Keep captured payload MD5/SHA256 fields consistent with changed bytes.
        # Deliberately invalid digests do not match and remain negative vectors.
        field_pattern = re.compile(r'("(?:' + "|".join(re.escape(name) for name in _DIGEST_FIELDS) + r')"\s*:\s*)"([^"\\]+)"')
        updated = field_pattern.sub(lambda m: m.group(1) + json.dumps(self.digests.get(m.group(2), m.group(2))), text)
        if updated == text:
            return changed
        payload = updated.encode()
        return gzip.compress(payload, mtime=0) if compressed else payload

    def capture(self, data):
        """Keep an existing foreign account distinct from the replacement."""
        result = self._capture(data)
        if result == data or self.literal_only or not self.account_changed:
            return result
        reserved_account = next(
            alias for alias in ("999000999000", "999000999001", "999000999002")
            if alias not in (self.account, self.replacement)
        )
        reserved = Sanitizer(self.replacement, reserved_account, _literal_only=True)._capture(data)
        if reserved == data:
            return result
        occupied = Sanitizer(reserved_account, self.replacement, _literal_only=True)._capture(data)
        if occupied != data:
            raise ValueError("reserved fixture account is already present; choose an unused --replacement")
        return Sanitizer(self.account, self.replacement)._capture(reserved)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, type=account_id, help="source account to remove; never stored in output")
    parser.add_argument("--replacement", default="000000000000", type=account_id)
    parser.add_argument("--input", required=True, type=Path, help="private capture file (JSON, gzip, ZIP or text)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="sanitized publication destination")
    mode.add_argument("--check", action="store_true", help="exit 1 if direct or decoded identity references remain")
    args = parser.parse_args()
    if args.account == args.replacement:
        parser.error("source and replacement accounts must differ")
    if args.output and args.input.resolve() == args.output.resolve():
        parser.error("keep the raw input private; output must be a different file")
    try:
        original = args.input.read_bytes()
        sanitized = Sanitizer(args.account, args.replacement).capture(original)
        if args.check:
            if sanitized != original:
                print("Capture still contains source-account references.", file=sys.stderr)
                return 1
            print("No source-account references found in supported encodings.")
            return 0
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(sanitized)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    print("Published redacted capture. Signatures/authenticated ciphertext over changed fields require separately regenerated test vectors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
