"""Hosting the console: what goes to the server, the first-boot script, and the plan choice. All offline."""
import os

import pytest

from aws.infra import console_host as ch


def _touch(root, rel):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").close()


def test_bundle_carries_source_data_and_keys_but_no_installs_builds_or_local_state(tmp_path):
    for rel in ("api/server.py", "license/issue.py", "state/data/splits.json", "state/keys/issuer.pem",
                "state/web.db", "state/web.db-wal", "state/hosting.json", "web/package.json", "web/src/app/page.tsx",
                "web/node_modules/next/index.js", "web/.next/build-manifest.json", "web/tsconfig.tsbuildinfo",
                "api/__pycache__/server.cpython-313.pyc", "tests/test_api.py", "console/app.py",
                "dist/smoke_evidence.json", "dist/attacks_live.json", "dist/netops_lambda.zip", "requirements.txt"):
        _touch(str(tmp_path), rel)
    got = set(ch.bundle_members(str(tmp_path)))
    for rel in ("api/server.py", "license/issue.py", "state/data/splits.json", "state/keys/issuer.pem",
                "web/package.json", "web/src/app/page.tsx", "dist/smoke_evidence.json", "dist/attacks_live.json",
                "requirements.txt"):
        assert rel in got
    for rel in ("state/web.db", "state/web.db-wal", "state/hosting.json", "web/node_modules/next/index.js",
                "web/.next/build-manifest.json", "web/tsconfig.tsbuildinfo", "api/__pycache__/server.cpython-313.pyc",
                "tests/test_api.py", "console/app.py", "dist/netops_lambda.zip"):
        assert rel not in got


def test_first_boot_script_gates_everything_behind_a_hashed_password():
    script = ch.user_data("https://example.invalid/bundle.tgz?sig=1", "Abc123")
    # Lightsail runs user data under /bin/sh after its own script: no bash-only lines outside the bash file
    outer = script.split("<<'ALSETUP'")[0] + script.split("\nALSETUP\n")[1]
    assert script.startswith("#!/bin/sh") and "pipefail" not in outer and "bash /root/al-setup.sh" in outer
    assert "caddy hash-password --plaintext 'Abc123'" in script
    assert script.count("Abc123") == 1                       # only hashed, never written into a config
    assert "basicauth" in script and "reverse_proxy 127.0.0.1:3000" in script
    assert "--host 127.0.0.1 --port 8000" in script          # the engine is reachable only through the console
    assert "next build" in script and "touch /opt/al/READY" in script
    with pytest.raises(AssertionError):
        ch.user_data("https://example.invalid/b", "pa'ss")


def test_plan_is_the_cheapest_2gb_linux_plan_with_a_public_ipv4():
    plans = [
        {"bundleId": "small_ipv6_3_0", "price": 7.0, "ramSizeInGb": 2.0, "isActive": True,
         "supportedPlatforms": ["LINUX_UNIX"], "publicIpv4AddressCount": 0},
        {"bundleId": "small_win_3_0", "price": 9.0, "ramSizeInGb": 2.0, "isActive": True,
         "supportedPlatforms": ["WINDOWS"]},
        {"bundleId": "small_3_0", "price": 12.0, "ramSizeInGb": 2.0, "isActive": True,
         "supportedPlatforms": ["LINUX_UNIX"], "publicIpv4AddressCount": 1},
        {"bundleId": "medium_3_0", "price": 24.0, "ramSizeInGb": 4.0, "isActive": True,
         "supportedPlatforms": ["LINUX_UNIX"]},
    ]
    assert ch.cheapest(plans, 2.0)["bundleId"] == "small_3_0"


def test_hosted_bundle_has_the_strip_files_but_no_item_files(tmp_path):
    from aws.infra import console_host as C
    runs = tmp_path / "dist" / "rehearsal-1" / "evidence" / "runs" / "r1"
    runs.mkdir(parents=True)
    (runs / "record.json").write_text("{}")
    (runs / "items.jsonl").write_text("{}")
    (runs / "records.jsonl").write_text("{}")
    (tmp_path / "dist" / "rehearsal-1" / "judging.json").write_text("{}")
    assert sorted(C.evidence_members(str(tmp_path))) == ["dist/rehearsal-1/evidence/runs/r1/record.json",
                                                         "dist/rehearsal-1/judging.json"]
