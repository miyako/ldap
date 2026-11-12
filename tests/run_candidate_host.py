#!/usr/bin/env python3
"""Opt-in native development fixture, never a release-pin or runtime override.

Run as LDAP_KERBEROS_TEST_HOOK inside ldap-cli's bounded kerberos-macos.sh
fixture. LDAP_CANDIDATE, LDAP_CANDIDATE_SHA256 and LDAP_CANDIDATE_REVISION bind
the development binary; LDAP_TEST_* describes only its synthetic local server.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compile_component import compile_component, input_digest, output_digest
from package_component import include_project, write_zip
from test_4d import _no_symlinks, test_4d


def main():
    required = ("LDAP_CANDIDATE", "LDAP_CANDIDATE_SHA256", "LDAP_CANDIDATE_REVISION",
                "LDAP_TEST_URI", "LDAP_TEST_CA_CERT", "LDAP_TEST_BASE",
                "LDAP_TEST_USER_A", "LDAP_TEST_USER_B", "LDAP_TEST_PASSWORD_A",
                "LDAP_TEST_PASSWORD_B", "LDAP_TEST_IDENTITY_A", "LDAP_TEST_IDENTITY_B")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise ValueError("missing synthetic fixture inputs: " + ", ".join(missing))
    candidate = Path(os.environ["LDAP_CANDIDATE"])
    _no_symlinks(candidate, recursive=False)
    candidate = candidate.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ["LDAP_CANDIDATE_REVISION"]):
        raise ValueError("candidate revision must be the full source commit SHA")
    binary = candidate.read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    if digest != os.environ["LDAP_CANDIDATE_SHA256"]:
        raise ValueError("candidate SHA256 mismatch")
    tool4d = Path(os.environ.get("TOOL4D", ROOT / ".tools/tool4d.app/Contents/MacOS/tool4d")).resolve(strict=True)
    output = ROOT / "build/candidate-host-integration"
    output.mkdir(parents=True, exist_ok=True)
    protected = ("cli/release.json", "component/ldap/Resources/bin/macOS/ldap",
                 "dist/ldap.zip", "dist/ldap.acceptance.json")
    protected_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in protected}
    report = {"scope": "native-development-fixture", "release_ready": False,
              "finished": False, "result": "failed",
              "candidate": {"sha256": digest, "revision": os.environ["LDAP_CANDIDATE_REVISION"],
                            "signing": "not_run"},
              "real_ad": {"status": "not_run", "reason": "synthetic MIT KDC/OpenLDAP, not AD Always policy"},
              "unchanged_production_inputs": protected_hashes,
              "steps": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="candidate-host-", dir=ROOT / "build") as scratch:
            fixture = Path(scratch)
            for name in ("template.json", "package.json", "LICENSE", "workflow-contract.json"):
                shutil.copy2(ROOT / name, fixture / name)
            ignore = shutil.ignore_patterns("DerivedData", "Libraries", "bin", "Data", "Logs", "userPreferences.*")
            component = fixture / "component/ldap"
            for name in ("component/ldap", "tooling/compiler", "tests/host"):
                _no_symlinks(ROOT / name)
            shutil.copytree(ROOT / "component/ldap", component, ignore=ignore)
            shutil.copytree(ROOT / "tooling/compiler", fixture / "tooling/compiler", ignore=ignore)
            host = fixture / "tests/host"
            shutil.copytree(ROOT / "tests/host", host, ignore=ignore)
            executable = component / "Resources/bin/macOS/ldap"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(binary)
            executable.chmod(0o755)
            version = subprocess.run([str(executable), "--version"], check=True,
                                     capture_output=True, text=True, timeout=20).stdout
            if not re.fullmatch(r"ldap [0-9]+\.[0-9]+\.[0-9]+\n", version):
                raise ValueError("candidate version must identify ldap and a stable version")
            report["candidate"]["version"] = version.strip()
            config = {key: os.environ[env] for key, env in (
                ("uri", "LDAP_TEST_URI"), ("caCert", "LDAP_TEST_CA_CERT"), ("base", "LDAP_TEST_BASE"),
                ("userA", "LDAP_TEST_USER_A"), ("userB", "LDAP_TEST_USER_B"),
                ("passwordA", "LDAP_TEST_PASSWORD_A"), ("passwordB", "LDAP_TEST_PASSWORD_B"))}
            (host / "Resources").mkdir(exist_ok=True)
            (host / "Resources/candidate.json").write_text(json.dumps(config), encoding="utf-8")
            methods = host / "Project/Sources/Methods"
            for method in (ROOT / "tests/candidate").glob("*.4dm"):
                shutil.copy2(method, methods / method.name)
            smoke = methods / "Smoke.4dm"
            source = smoke.read_text(encoding="utf-8")
            marker = "$report.finished:=True"
            if source.count(marker) != 1:
                raise ValueError("candidate fixture requires the established single host completion marker")
            smoke.write_text(source.replace(marker, "$report.candidate:=Candidate_auth()\n" + marker),
                             encoding="utf-8")
            contract_path = host / "contract.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            # The candidate passes capability checks, then reaches the unreachable
            # transport probe. Only the copied fixture's legacy expectations change.
            updates = {"/legacyCapabilityGate/error/code": "connection",
                       "/legacyCapabilityGate/exitCode": 3,
                       "/explicitLoginGate/errors/0/errCode": 81,
                       "/saslPasswordLogin/errors/0/errCode": 81}
            for assertion in contract["feature"]["assertions"]:
                if assertion["path"] in updates:
                    assertion["equals"] = updates[assertion["path"]]
                if assertion["path"] == "/version/value":
                    assertion["equals"] = version.strip()
            for assertion in contract["execution"]["assertions"]:
                if assertion["path"] == "/renamedExecutable":
                    assertion["equals"]["stdout"] = version
            def expect(path, value):
                contract["feature"]["assertions"].append({"path": "/candidate/" + path, "equals": value})
            for field, user, identity, uid in (
                    ("alice", "LDAP_TEST_USER_A", "LDAP_TEST_IDENTITY_A", "alice"),
                    ("bob", "LDAP_TEST_USER_B", "LDAP_TEST_IDENTITY_B", "bob"),
                    ("workerAlice", "LDAP_TEST_USER_A", "LDAP_TEST_IDENTITY_A", "alice"),
                    ("workerBob", "LDAP_TEST_USER_B", "LDAP_TEST_IDENTITY_B", "bob")):
                for suffix, value in (("errors", None), ("sessionPresent", True),
                                      ("user", os.environ[user]), ("whoami/ok", True),
                                      ("whoami/value", os.environ[identity]), ("entry/uid", uid)):
                    expect(field + "/" + suffix, value)
            for field, error in (("wrongPassword", 49), ("replacementWrongPassword", 49), ("missingPassword", 49),
                                 ("untrustedTLS", 81), ("wrongHostname", 81)):
                expect(field + "/sessionPresent", False)
                expect(field + "/errors/0/errCode", error)
            expect("mainLoginErrors", None)
            expect("workersFinished", True)
            expect("mainUserAfterWorkers", os.environ["LDAP_TEST_USER_A"])
            expect("mainIdentityAfterWorkers/ok", True)
            expect("mainIdentityAfterWorkers/value", os.environ["LDAP_TEST_IDENTITY_A"])
            contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
            report["steps"]["source_host"] = {"status": "failed"}
            try:
                status = test_4d(fixture, tool4d)
            finally:
                path = fixture / "build/host-status.json"
                if path.is_file():
                    shutil.copy2(path, output / "source-host-status.json")
            report["steps"]["source_host"] = {"status": "passed", "report": status}
            report["steps"]["compile"] = {"status": "failed"}
            try:
                compiled = compile_component(fixture, tool4d)
            finally:
                path = fixture / "build/compile-status.json"
                if path.is_file():
                    shutil.copy2(path, output / "compile-status.json")
            report["steps"]["compile"] = {"status": "passed", "report": compiled}
            if compiled["input_sha256"] != input_digest(fixture):
                raise ValueError("candidate component inputs changed after compilation")
            if compiled["output_sha256"] != output_digest(component):
                raise ValueError("candidate compiled outputs changed")
            compiled_copy = fixture / "compiled-candidate.4dbase"
            compiled_copy.mkdir()
            project_entries = []
            for path in sorted(component.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(component)
                if include_project(relative):
                    project_entries.append((relative.as_posix(), path.read_bytes(), 0o644))
                elif relative.parts[0] in ("Resources", "Documentation", "Libraries"):
                    destination = compiled_copy / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
            # A native-only test fixture is not a distributable package. Use the
            # established 4DZ layout/ZIP writer, never mixed-platform fake slices.
            write_zip(compiled_copy / "ldap.4DZ", project_entries)
            report["native_only_fixture"] = {
                "packed_project_sha256": hashlib.sha256((compiled_copy / "ldap.4DZ").read_bytes()).hexdigest(),
                "cli_sha256": hashlib.sha256((compiled_copy / "Resources/bin/macOS/ldap").read_bytes()).hexdigest()}
            report["steps"]["compiled_host"] = {"status": "failed"}
            try:
                status = test_4d(fixture, tool4d, compiled_copy)
            finally:
                path = fixture / "build/host-status.json"
                if path.is_file():
                    shutil.copy2(path, output / "compiled-host-status.json")
            report["steps"]["compiled_host"] = {"status": "passed", "report": status}
            report.update(finished=True, result="partial")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise
    finally:
        current_hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in protected}
        if current_hashes != protected_hashes:
            report.update(finished=False, result="failed", error="production inputs changed during candidate fixture")
        (output / "evidence.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["result"] == "failed":
        raise ValueError(report["error"])
    print(json.dumps({"result": report["result"], "release_ready": False,
                      "evidence": str(output / "evidence.json")}, indent=2))


if __name__ == "__main__":
    main()
