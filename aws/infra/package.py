"""Package the NetOps tool Lambda and the request interceptor as one zip (S1, S3).

    python -m aws.infra.package --bundle dist/bundle --out dist/netops_lambda.zip

Handlers: aws.tool_lambda.handler.lambda_handler and aws.interceptor.handler.lambda_handler.
Third-party wheels are fetched for Linux x86_64 / Python 3.12 (the Lambda runtime), never from this machine's
site-packages. Keys, .env files and state/ are never included.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PACKAGES = ("aws", "common", "gateway", "license", "model")
DEPS = ("PyJWT>=2.8", "cryptography", "numpy")
BUNDLE_FILES = ("data/incidents.jsonl", "data/scores.jsonl", "al.db")
FORBIDDEN = (".pem", ".env", ".key")


def collect(root: str = ROOT, bundle: str | None = None) -> list[tuple[str, str]]:
    """(source path, archive name) pairs for the repo code and, optionally, the smoke-test bundle."""
    out = []
    for pkg in PACKAGES:
        for d, dirs, files in os.walk(os.path.join(root, pkg)):
            dirs[:] = [x for x in dirs if x != "__pycache__"]
            out += [(os.path.join(d, f), os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/"))
                    for f in files if f.endswith(".py")]
    if bundle:
        for f in BUNDLE_FILES:
            src = os.path.join(bundle, f)
            if not os.path.exists(src):
                raise SystemExit(f"bundle is missing {f}; run python -m aws.infra.stub_bundle first")
            out.append((src, f"bundle/{f}"))
    bad = [a for _, a in out if a.endswith(FORBIDDEN) or a.startswith("state/")]
    if bad:
        raise SystemExit(f"refusing to package secrets or state: {bad}")
    return out


def build(out: str, bundle: str | None, deps: bool = True) -> str:
    files = collect(ROOT, bundle)
    with tempfile.TemporaryDirectory() as tmp:
        if deps:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--target", tmp,
                                   "--platform", "manylinux2014_x86_64", "--implementation", "cp",
                                   "--python-version", "3.12", "--only-binary=:all:", *DEPS])
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for d, _, fs in os.walk(tmp):
                for f in fs:
                    p = os.path.join(d, f)
                    if "__pycache__" not in p:
                        z.write(p, os.path.relpath(p, tmp).replace(os.sep, "/"))
            for src, arc in files:
                z.write(src, arc)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist/netops_lambda.zip")
    ap.add_argument("--bundle", default=None, help="stub (or real) bundle dir to ship inside the zip")
    ap.add_argument("--no-deps", action="store_true")
    a = ap.parse_args()
    p = build(a.out, a.bundle, deps=not a.no_deps)
    print(p, f"{os.path.getsize(p) / 1e6:.1f} MB")
