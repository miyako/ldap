"""Tests for the pinned upstream CLI (cli/release.json, scripts/prebuilt_cli.py).

The CLI is built, signed and released by miyako/ldap-cli. These tests check the
pin and the fetch safeguards offline. When CI selects the CLI language
(TEST_CLI_LANGUAGE), they also fetch the native binary and run quoting round
trips through it, from a path that contains spaces.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import prebuilt_cli  # noqa: E402


def zipped(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class PinTests(unittest.TestCase):
    def test_pin_is_complete(self):
        pin = prebuilt_cli.load_pin(ROOT)
        self.assertEqual(pin["repository"], "miyako/ldap-cli")
        self.assertEqual(pin["assets"]["macos"]["member"], "ldap")
        self.assertEqual(pin["assets"]["windows-x64"]["member"], "ldap.exe")

    def test_malformed_pins_are_rejected(self):
        good = json.loads((ROOT / "cli/release.json").read_text(encoding="utf-8"))
        mutations = [
            lambda p: p.update(schema=2),
            lambda p: p.update(repository="../evil"),
            lambda p: p.update(tag="latest"),
            lambda p: p["assets"].pop("windows-x64"),
            lambda p: p["assets"]["macos"].update(sha256="0" * 63),
            lambda p: p["assets"]["macos"].update(member="../ldap"),
            lambda p: p["assets"]["macos"].update(name="ldap.tar.gz"),
        ]
        for mutate in mutations:
            pin = json.loads(json.dumps(good))
            mutate(pin)
            with tempfile.TemporaryDirectory() as scratch, self.subTest(pin=pin):
                (Path(scratch) / "cli").mkdir()
                (Path(scratch) / "cli/release.json").write_text(json.dumps(pin))
                with self.assertRaises(ValueError):
                    prebuilt_cli.load_pin(scratch)

    def test_download_locations_are_restricted(self):
        prebuilt_cli._check_url("https://github.com/miyako/ldap-cli/releases/download/v0.1.0/x.zip")
        prebuilt_cli._check_url("https://release-assets.githubusercontent.com/github-production-release-asset/1")
        for url in ("http://github.com/x", "https://example.com/x", "https://user:pw@github.com/x",
                    "https://github.com:8443/x", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                prebuilt_cli._check_url(url)

    def test_digest_is_checked_before_use(self):
        pin = prebuilt_cli.load_pin(ROOT)
        asset = dict(pin["assets"]["macos"])

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        data = zipped({"ldap": b"tampered"})
        with patch("urllib.request.OpenerDirector.open", side_effect=lambda *a, **k: Response(data)):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                prebuilt_cli.download(pin, asset)
            asset["sha256"] = hashlib.sha256(data).hexdigest()
            self.assertEqual(prebuilt_cli.download(pin, asset), data)

    def test_archive_must_hold_exactly_one_executable(self):
        self.assertEqual(prebuilt_cli.extract(zipped({"ldap": b"x", "README.md": b"r"}), "ldap"), b"x")
        for entries in ({"README.md": b"r"}, {"bin/ldap": b"x"}, {"ldap/": b""}):
            with self.subTest(entries=list(entries)), self.assertRaises(ValueError):
                prebuilt_cli.extract(zipped(entries), "ldap")


class NativeRoundTrips(unittest.TestCase):
    """Fetch the real pinned binary and pass awkward arguments through it."""

    @classmethod
    def setUpClass(cls):
        selected = os.environ.get("TEST_CLI_LANGUAGE")
        if selected in (None, "none"):
            raise unittest.SkipTest("network fetch runs only when CI selects the CLI language")
        system, machine = platform.system(), platform.machine().lower()
        if system == "Darwin":
            target = "macos-arm64" if machine == "arm64" else "macos-x64"
        elif system == "Windows" and machine in ("amd64", "x86_64"):
            target = "windows-x64"
        else:
            raise unittest.SkipTest("no pinned binary for " + system + "/" + machine)
        scratch = tempfile.TemporaryDirectory(prefix=".cli-test path ", dir=Path(__file__).parent)
        cls.addClassCleanup(scratch.cleanup)
        folder = Path(scratch.name) / "executables with spaces"
        folder.mkdir()
        cls.executable = folder / ("ldap.exe" if target == "windows-x64" else "ldap")
        prebuilt_cli.fetch(ROOT, target, cls.executable)

    def run_cli(self, *arguments):
        return subprocess.run([os.fspath(self.executable), *arguments], capture_output=True, timeout=20)

    def test_version_matches_pin(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, ("ldap " + prebuilt_cli.load_pin(ROOT)["version"] + "\n").encode())

    def test_filter_escaping_round_trips(self):
        def reference(value):
            return (value.replace("\\", "\\5c").replace("*", "\\2a")
                    .replace("(", "\\28").replace(")", "\\29"))
        values = ["World", "two words", " leading and trailing ", "世界 café 😀", 'a"b\\c',
                  "line\nbreak", "<>&/ ", "--version", "$(echo no); `echo no`", "trailing\\"]
        for value in values:
            with self.subTest(value=value):
                result = self.run_cli("escape", "filter", "--", value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.decode("utf-8"), reference(value) + "\n")

    def test_usage_errors_exit_2_without_contacting_a_server(self):
        result = self.run_cli("search")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"no server given", result.stderr)


if __name__ == "__main__":
    unittest.main()
