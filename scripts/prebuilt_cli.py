#!/usr/bin/env python3
"""Fetch the pinned, signed ldap-cli release binary for one target.

The CLI lives in its own repository (miyako/ldap-cli), which builds, signs and
notarizes it. cli/release.json pins the release tag and the SHA-256 of each
asset. This module downloads an asset over HTTPS from github.com only,
verifies the digest before opening it, extracts the one executable, and for
macOS takes the requested slice out of the universal binary with `lipo -thin`
(each slice keeps its own Developer ID signature, so the universal binary
reassembled by `ci_config.py assemble` verifies again).
"""
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile

ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
ARCH = {"macos-arm64": "arm64", "macos-x64": "x86_64"}
LIMIT = 64 * 1024 * 1024


def load_pin(root):
    path = Path(root) / "cli" / "release.json"
    pin = json.loads(path.read_text(encoding="utf-8"))
    ok = (isinstance(pin, dict) and pin.get("schema") == 1
          and re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", str(pin.get("repository", "")))
          and re.fullmatch(r"v?\d+\.\d+\.\d+", str(pin.get("tag", "")))
          and re.fullmatch(r"\d+\.\d+\.\d+", str(pin.get("version", "")))
          and isinstance(pin.get("assets"), dict))
    if not ok:
        raise ValueError("cli/release.json must hold schema 1, repository, tag, version and assets")
    for key in ("macos", "windows-x64"):
        asset = pin["assets"].get(key)
        if (not isinstance(asset, dict)
                or not re.fullmatch(r"[A-Za-z0-9._-]+\.zip", str(asset.get("name", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(asset.get("sha256", "")))
                or not re.fullmatch(r"[A-Za-z0-9._-]+", str(asset.get("member", "")))):
            raise ValueError(f"cli/release.json asset {key} needs name, sha256 and member")
    return pin


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(request, response, code, message, headers, newurl)


def _check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("refusing download location: " + parsed.scheme + "://" + str(parsed.hostname))


def download(pin, asset):
    url = (f"https://github.com/{pin['repository']}/releases/download/"
           f"{urllib.parse.quote(pin['tag'])}/{urllib.parse.quote(asset['name'])}")
    _check_url(url)
    opener = urllib.request.build_opener(_CheckedRedirect())
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "ldap-component-build"}),
                     timeout=120) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("release asset is larger than expected")
    digest = hashlib.sha256(data).hexdigest()
    if digest != asset["sha256"]:
        raise ValueError(f"SHA-256 mismatch for {asset['name']}: {digest}")
    return data


def extract(data, member):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [info for info in archive.infolist() if info.filename == member]
        if len(names) != 1 or names[0].is_dir():
            raise ValueError(f"release asset must contain exactly one {member}")
        return archive.read(names[0])


def fetch(root, target, executable):
    """Write the target's executable; return a toolchain description for provenance."""
    pin = load_pin(root)
    asset = pin["assets"]["windows-x64" if target == "windows-x64" else "macos"]
    binary = extract(download(pin, asset), asset["member"])
    if target == "windows-x64":
        executable.write_bytes(binary)
    else:
        with tempfile.TemporaryDirectory() as scratch:
            universal = Path(scratch) / "universal"
            universal.write_bytes(binary)
            subprocess.run(["lipo", str(universal), "-thin", ARCH[target], "-output", str(executable)],
                           check=True, timeout=60)
        subprocess.run(["codesign", "--verify", "--strict", str(executable)], check=True, timeout=60)
    executable.chmod(0o755)
    return f"prebuilt {pin['repository']} {pin['tag']} ({asset['name']} sha256 {asset['sha256']})"
