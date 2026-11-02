"""Host the console (Next.js) and its engine (FastAPI) on one Lightsail server, behind a password and HTTPS.

    python -m aws.infra.console_host apply      # bundle, upload, create server + HTTPS distribution (~$14.50/month)
    python -m aws.infra.console_host status     # is the server set up, is the HTTPS link live
    python -m aws.infra.console_host destroy    # delete everything this created; billing stops

The engine needs no AWS service at runtime: it reads state/ (data and demo signing keys) and the two live-evidence
files in dist/. The bundle goes up through a private S3 bucket and a short presigned link, and its object is
deleted once the server has it. The server runs Caddy on port 80 (basic auth) -> next start (3000) -> uvicorn (8000);
a Lightsail distribution in front gives an https://*.cloudfront.net address and caches nothing.

Cost: a Lightsail instance bills whether running or stopped, so only `destroy` stops the charge. The distribution
is a fixed monthly plan. The URL and password are written to state/hosting.json (git-ignored), never printed.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import secrets
import string
import tarfile
import time
import urllib.error
import urllib.request

import boto3

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.path.join(ROOT, "state", "hosting.json")
NAME = "al-console"
USER = "demo"

# what the engine imports (api.server and everything it loads), plus data, state and the console source
PACKAGES = ("api", "aws", "calibration", "common", "data", "demo", "evaluation", "federation", "gateway", "license",
            "model", "orchestrator", "state", "web")
FILES = ("requirements.txt", "dist/smoke_evidence.json", "dist/attacks_live.json")
SKIP_DIRS = {"node_modules", ".next", "__pycache__", ".pytest_cache"}
SKIP_SUFFIXES = (".pyc", ".db", ".db-shm", ".db-wal", ".tsbuildinfo")
SKIP_FILES = {"hosting.json"}


def evidence_members(root: str = ROOT) -> list[str]:
    """What the console's live strip reads: judging.json, declarations and record files. Not the per-item files."""
    dist = os.path.join(root, "dist")
    bases = [""] + ([f"dist/{n}/" for n in sorted(os.listdir(dist)) if n.startswith("rehearsal")] if os.path.isdir(dist) else [])
    out = []
    for b in bases:
        if os.path.isfile(os.path.join(root, b, "judging.json")):
            out.append(f"{b}judging.json")
        for d, _, files in os.walk(os.path.join(root, b, "evidence")):
            out += [os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/") for f in sorted(files)
                    if f == "record.json" or os.path.basename(d) == "declared"]
    return out


def bundle_members(root: str = ROOT) -> list[str]:
    """Relative paths that go to the server: source and data, never installed packages, builds or local databases."""
    out = [f for f in FILES if os.path.isfile(os.path.join(root, f))] + evidence_members(root)
    for top in PACKAGES:
        for d, dirs, files in os.walk(os.path.join(root, top)):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for f in sorted(files):
                if f in SKIP_FILES or f.endswith(SKIP_SUFFIXES):
                    continue
                out.append(os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/"))
    return out


def bundle(root: str = ROOT) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in bundle_members(root):
            tar.add(os.path.join(root, rel), arcname=rel)
    return buf.getvalue()


def user_data(bundle_url: str, password: str) -> str:
    """First-boot script for Ubuntu 24.04. The password is hashed on the server; only the hash reaches Caddy."""
    assert password.isalnum(), "the password is pasted into a shell script"
    # Lightsail runs user data after its own #!/bin/sh script, so this is plain sh that hands the setup to bash
    return "#!/bin/sh\ncat > /root/al-setup.sh <<'ALSETUP'\n" + setup_script(bundle_url, password) + \
        "ALSETUP\nnohup bash /root/al-setup.sh >/dev/null 2>&1 &\n"


def setup_script(bundle_url: str, password: str) -> str:
    return f"""#!/bin/bash
set -euxo pipefail
exec > /var/log/al-setup.log 2>&1
export DEBIAN_FRONTEND=noninteractive
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
apt-get update
apt-get install -y python3-venv curl ca-certificates gnupg
apt-get install -y caddy || {{
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt -o /etc/apt/sources.list.d/caddy-stable.list
  apt-get update && apt-get install -y caddy
}}
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs
mkdir -p /opt/al
curl -fsSL '{bundle_url}' -o /tmp/al.tgz
tar xzf /tmp/al.tgz -C /opt/al && rm /tmp/al.tgz
useradd --system --home /opt/al --shell /usr/sbin/nologin al || true
python3 -m venv /opt/al/.venv
grep -vE '^(streamlit|pytest)' /opt/al/requirements.txt > /tmp/req.txt
/opt/al/.venv/bin/pip install -q -r /tmp/req.txt
cd /opt/al/web && npm ci --no-audit --no-fund && npx next build
chown -R al:al /opt/al
cat > /etc/systemd/system/al-api.service <<'EOF'
[Unit]
Description=Autonomy License engine
After=network.target
[Service]
User=al
WorkingDirectory=/opt/al
ExecStart=/opt/al/.venv/bin/python -m uvicorn api.server:app --host 127.0.0.1 --port 8000
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/al-web.service <<'EOF'
[Unit]
Description=Autonomy License console
After=al-api.service
[Service]
User=al
WorkingDirectory=/opt/al/web
Environment=NODE_ENV=production
ExecStart=/usr/bin/npx next start -H 127.0.0.1 -p 3000
Restart=always
[Install]
WantedBy=multi-user.target
EOF
HASH=$(caddy hash-password --plaintext '{password}')
printf ':80 {{\\n\\tbasicauth {{\\n\\t\\t{USER} %s\\n\\t}}\\n\\treverse_proxy 127.0.0.1:3000\\n}}\\n' "$HASH" > /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable --now al-api al-web
systemctl restart caddy
touch /opt/al/READY
"""


def cheapest(bundles: list[dict], ram_gb: float) -> dict:
    """The cheapest active Linux plan with this much memory and a public IPv4 address (IPv6-only plans can't be
    a distribution origin)."""
    ok = [b for b in bundles if b.get("isActive") and b.get("ramSizeInGb") == ram_gb
          and "LINUX_UNIX" in b.get("supportedPlatforms", []) and "ipv6" not in b["bundleId"]
          and b.get("publicIpv4AddressCount", 1) >= 1]
    return min(ok, key=lambda b: b["price"])


def _get(url: str, password: str | None = None) -> int:
    req = urllib.request.Request(url)
    if password:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{USER}:{password}".encode()).decode())
    try:
        return urllib.request.urlopen(req, timeout=15).status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return 0


def apply(sess, region: str) -> dict:
    ls, s3 = sess.client("lightsail"), sess.client("s3")
    account = sess.client("sts").get_caller_identity()["Account"]
    bucket = f"{NAME}-{account}-{region}"
    password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))

    try:
        s3.head_bucket(Bucket=bucket)
    except s3.exceptions.ClientError:
        s3.create_bucket(Bucket=bucket)          # new buckets block public access by default
    s3.put_object(Bucket=bucket, Key="bundle.tgz", Body=bundle(), ServerSideEncryption="AES256")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": "bundle.tgz"}, ExpiresIn=7200)

    plan = cheapest(ls.get_bundles(includeInactive=False)["bundles"], 2.0)
    info = {"region": region, "bucket": bucket, "instance": NAME, "distribution": f"{NAME}-https", "user": USER,
            "password": password}
    _save(info)                                  # saved before anything bills, so destroy always works
    ls.create_instances(instanceNames=[NAME], availabilityZone=f"{region}a", blueprintId="ubuntu_24_04",
                        bundleId=plan["bundleId"], userData=user_data(url, password),
                        tags=[{"key": "project", "value": "autonomy-license"}])
    _wait(lambda: ls.get_instance(instanceName=NAME)["instance"]["state"]["name"] == "running", 600, "server")
    ls.allocate_static_ip(staticIpName=f"{NAME}-ip")
    ls.attach_static_ip(staticIpName=f"{NAME}-ip", instanceName=NAME)
    ls.open_instance_public_ports(instanceName=NAME, portInfo={"fromPort": 80, "toPort": 80, "protocol": "tcp"})
    ip = ls.get_static_ip(staticIpName=f"{NAME}-ip")["staticIp"]["ipAddress"]

    dist_plan = min((b for b in ls.get_distribution_bundles()["bundles"] if b.get("isActive")), key=lambda b: b["price"])
    dist = ls.create_distribution(
        distributionName=info["distribution"], bundleId=dist_plan["bundleId"],   # names are unique across Lightsail
        origin={"name": NAME, "regionName": region, "protocolPolicy": "http-only"},
        defaultCacheBehavior={"behavior": "dont-cache"},
        cacheBehaviorSettings={"allowedHTTPMethods": "GET,HEAD,OPTIONS,PUT,PATCH,POST,DELETE",   # moments POST
                               # Lightsail has no "all" for headers; Authorization carries the password
                               "forwardedHeaders": {"option": "allow-list",
                                                    "headersAllowList": ["Authorization", "Accept", "Origin", "Referer"]},
                               "forwardedCookies": {"option": "all"},
                               "forwardedQueryStrings": {"option": True}})["distribution"]

    info |= {"plan": plan["bundleId"], "plan_usd_month": plan["price"], "distribution_usd_month": dist_plan["price"],
             "ip": ip, "url": f"https://{dist['domainName']}"}
    _save(info)
    return info


def _save(info: dict):
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=1)


def _wait(ready, seconds: int, what: str):
    end = time.time() + seconds
    while time.time() < end:
        if ready():
            return
        time.sleep(10)
    raise TimeoutError(f"{what} not ready after {seconds}s")


def status(sess, info: dict, wait: int = 0) -> dict:
    """Server set up = the password gate answers with the engine behind it. Link live = the same over HTTPS."""
    ls, s3 = sess.client("lightsail"), sess.client("s3")
    server = lambda: _get(f"http://{info['ip']}/api/state", info["password"]) == 200
    link = lambda: _get(f"{info['url']}/api/state", info["password"]) == 200
    if wait:
        _wait(lambda: server() and link(), wait, "hosted console")
    out = {"server_ready": server(), "link_ready": link(),
           "link_rejects_no_password": _get(f"{info['url']}/", None) == 401,
           "distribution": ls.get_distributions(distributionName=info["distribution"])["distributions"][0]["status"]}
    if out["server_ready"]:   # the server has unpacked the bundle; the copy in S3 is no longer needed
        s3.delete_object(Bucket=info["bucket"], Key="bundle.tgz")
    return out


def destroy(sess, info: dict):
    ls, s3 = sess.client("lightsail"), sess.client("s3")
    gone = (ls.exceptions.NotFoundException, ls.exceptions.InvalidInputException)

    def dist_gone():
        try:
            ls.get_distributions(distributionName=info["distribution"])
            return False
        except gone:
            return True

    for step in (lambda: ls.delete_distribution(distributionName=info["distribution"]),
                 lambda: _wait(dist_gone, 1200, "distribution deletion"),   # the server is its origin until then
                 lambda: ls.detach_static_ip(staticIpName=f"{NAME}-ip"),
                 lambda: ls.release_static_ip(staticIpName=f"{NAME}-ip"),
                 lambda: ls.delete_instance(instanceName=info["instance"], forceDeleteAddOns=True)):
        try:
            step()
        except gone:
            pass
    try:
        for o in s3.list_objects_v2(Bucket=info["bucket"]).get("Contents", []):
            s3.delete_object(Bucket=info["bucket"], Key=o["Key"])
        s3.delete_bucket(Bucket=info["bucket"])
    except s3.exceptions.NoSuchBucket:
        pass
    os.remove(STATE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("op", choices=["apply", "status", "destroy"])
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile")
    ap.add_argument("--wait", type=int, default=0, help="status: seconds to wait for the link to come up")
    a = ap.parse_args()
    sess = boto3.session.Session(profile_name=a.profile, region_name=a.region)
    if a.op == "apply":
        if os.path.exists(STATE):
            raise SystemExit(f"already hosted, see {STATE}; destroy first")
        info = apply(sess, a.region)
        print(f"created {info['instance']} ({info['plan']}, ${info['plan_usd_month']}/month) and "
              f"{info['distribution']} (${info['distribution_usd_month']}/month)")
        print(f"link: {info['url']}  (user and password in {STATE}; setup takes about 15 minutes)")
        return
    with open(STATE, encoding="utf-8") as f:
        info = json.load(f)
    if a.op == "status":
        print(json.dumps({"url": info["url"], **status(sess, info, a.wait)}, indent=1))
    else:
        destroy(sess, info)
        print("deleted the server, its address, the HTTPS distribution and the bucket")


if __name__ == "__main__":
    main()
