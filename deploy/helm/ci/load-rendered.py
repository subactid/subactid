#!/usr/bin/env python3
"""Loads the configuration each rendered container gets, with the server itself.

    helm template subactid deploy/helm/subactid -f values.yaml | load-rendered.py <SubactId.Server.dll>

Every Deployment, Job and Pod container that is given Subact ID settings is run as `doctor` with
exactly that environment. A value from a Secret is replaced by a placeholder of its own, and each
signing key file by a key generated for the run. A container passes when doctor reports its
configuration as loaded. Nothing else doctor checks is reachable here, so the rest is ignored.
The generated keys are removed on exit, and a doctor that does not finish fails its container.
"""
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml


def placeholder(name):
    digest = hashlib.sha256(name.encode()).hexdigest()
    if name.endswith("ConnectionString"):
        return f"Host=127.0.0.1;Port=1;Username=placeholder;Password={digest};Timeout=1"
    return digest


def containers(documents):
    for doc in documents:
        if not doc or doc.get("kind") not in ("Deployment", "Job", "Pod"):
            continue
        spec = doc["spec"] if doc["kind"] == "Pod" else doc["spec"]["template"]["spec"]
        for container in spec.get("containers", []):
            yield f"{doc['kind']}/{doc['metadata']['name']}/{container['name']}", container


# doctor gives up on the identity provider after ten seconds and on the database after one, so
# a run that takes this long is stuck.
DOCTOR_TIMEOUT_SECONDS = 60


def main():
    with tempfile.TemporaryDirectory(prefix="subactid-keys-") as keys:
        return check(sys.argv[1], pathlib.Path(keys))


def check(server, keys):
    failed = 0
    checked = 0
    for label, container in containers(yaml.safe_load_all(sys.stdin)):
        mounts = [m["mountPath"].rstrip("/") + "/" for m in container.get("volumeMounts", []) if m["name"] == "signing"]
        env = {}
        for entry in container.get("env") or []:
            name = entry["name"]
            if "valueFrom" in entry:
                env[name] = placeholder(name)
                continue
            value = str(entry.get("value", ""))
            for mount in mounts:
                if value.startswith(mount):
                    key = keys / value[len(mount):]
                    if not key.exists():
                        subprocess.run(["dotnet", server, "keys", "generate", "--out", str(key)], check=True, capture_output=True)
                    value = str(key)
            env[name] = value
        if not any(name.startswith("SubactId__") for name in env):
            continue

        checked += 1
        base = {k: os.environ[k] for k in ("PATH", "HOME", "DOTNET_ROOT") if k in os.environ}
        try:
            run = subprocess.run(["dotnet", server, "doctor"], env={**base, **env}, capture_output=True, text=True, timeout=DOCTOR_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            failed += 1
            print(f"FAIL  {label}: doctor did not finish within {DOCTOR_TIMEOUT_SECONDS} seconds")
            continue
        lines = run.stdout.splitlines()
        index = next((i for i, line in enumerate(lines) if line[6:].startswith("configuration")), None)
        if index is not None and lines[index].startswith("ok") and lines[index].rstrip().endswith("Loaded."):
            print(f"ok    {label}: {sum(1 for n in env if n.startswith('SubactId__'))} settings loaded")
            continue

        failed += 1
        print(f"FAIL  {label}: the server does not load this configuration")
        # doctor's configuration notes name settings, never their values.
        if index is None:
            for line in lines[:20]:
                print(f"      {line.strip()}")
            continue
        print(f"      {lines[index].strip()}")
        for line in lines[index + 1:]:
            if not line.startswith(" "):
                break
            print(f"      {line.strip()}")

    if checked == 0:
        print("FAIL  no container was given Subact ID settings")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
