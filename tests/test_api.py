"""Web API: moments run through the same engine; numbers come from it, nothing hardcoded."""
import pytest
from fastapi.testclient import TestClient

from api import server
from demo.engine import Demo


@pytest.fixture
def client(data_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_demo", Demo(data_dir=data_dir, db=str(tmp_path / "w.db"), fresh=True))
    server._last.clear()
    return TestClient(server.app)


def test_needs_licence_before_act(client):
    assert client.post("/moment/act").status_code == 409


def test_earn_then_block_denies_with_no_state_change(client):
    s = client.post("/moment/earn").json()
    assert s["data_source"] == "synthetic" and s["licence"]["status"] == "active"
    s = client.post("/moment/block").json()
    assert s["last"]["name"] == "block" and s["last"]["result"]["state_changes"] == 0


def test_revoke_shows_revoked_status(client):
    client.post("/moment/earn")
    assert client.post("/moment/revoke").json()["licence"]["status"] == "revoked"


def test_unknown_moment_404(client):
    assert client.post("/moment/nope").status_code == 404


def test_revoked_licence_blocks_licensed_moments_until_recertify(client):
    assert client.post("/moment/recertify").status_code == 409
    client.post("/moment/earn")
    client.post("/moment/revoke")
    assert client.post("/moment/warning").status_code == 409
    assert client.post("/moment/recertify").json()["licence"]["status"] == "active"
    assert client.post("/moment/warning").status_code == 200


def test_warning_runs_twice_while_the_first_is_in_force(client):
    # The receiver allows one active warning per (issuer, category); a second run shows the one in force
    # instead of failing, and the warned category still goes to a human.
    client.post("/moment/earn")
    first = client.post("/moment/warning").json()["last"]["result"]
    r = client.post("/moment/warning")
    assert r.status_code == 200
    again = r.json()["last"]["result"]
    assert not first["warning"]["already_active"] and again["warning"]["already_active"]
    assert again["warning"]["category"] == first["warning"]["category"]
    assert again["A_same_category"]["outcome"] == "HUMAN"


def test_reset_starts_the_demo_over(client):
    # A second run of the demo must look like the first: no licence, no warning still in force, empty audit,
    # and a confident diagnosis is fixed alone again.
    client.post("/moment/earn")
    first_act = client.post("/moment/act").json()["last"]["result"]["auto"]["outcome"]
    client.post("/moment/warning")
    s = client.post("/reset").json()
    assert s["licence"] is None and s["warned_categories"] == [] and s["audit"] == [] and s["last"] is None
    assert s["approvals"] == []
    assert client.post("/moment/act").status_code == 409          # still fails closed: no licence after a reset
    client.post("/moment/earn")
    assert client.post("/moment/act").json()["last"]["result"]["auto"]["outcome"] == first_act == "AUTO_APPLIED"


def test_licence_events_keep_the_lineage_past_the_audit_tail(client):
    # Revoke, re-certify, then enough moments to push both licence events out of the 30-row audit tail: the state
    # still lists the issue of the current licence and the revocation of the one it replaced.
    client.post("/moment/earn")
    old = client.get("/state").json()["licence"]["jti"]
    client.post("/moment/revoke")
    client.post("/moment/recertify")
    for _ in range(8):
        client.post("/moment/block")
    s = client.get("/state").json()
    new = s["licence"]["jti"]
    assert new != old
    assert not any(r["kind"].startswith("licence_") for r in s["audit"])        # gone from the tail
    ev = {(r["kind"], r["detail"]["jti"]) for r in s["licence_events"]}
    assert {("licence_issued", old), ("licence_revoked", old), ("licence_issued", new)} <= ev
    assert all(r["kind"] in ("licence_issued", "licence_revoked", "licence_auto_revoked") for r in s["licence_events"])


def test_block_trace_shows_the_claim_next_to_the_server_count(client):
    # The agent lists 5 cells and claims cell_count 2; the interceptor drops the claim and counts 5, so F1 fires.
    client.post("/moment/earn")
    step = client.post("/moment/block").json()["last"]["result"]["agent"]["steps"][0]
    c = step["checked"]
    assert c["claimed"] == {"cell_count": 2} and c["listed_cells"] == 5
    assert c["server"]["cell_count"] == 5 and "cell_count" in c["dropped"]
    assert step["policy"]["decision"] == "DENY" and step["policy"]["policies"] == ["F1"]


def test_policies_are_the_text_the_engine_evaluates(client):
    from aws.cedar.engine import PolicyEngine
    p = client.get("/policies").json()["policies"]
    assert "context.input.cell_count > 3" in p["F1"] and p["F1"].startswith("// F1")
    assert all(text in PolicyEngine().text for text in p.values())


def test_demo_data_dir_comes_from_env(data_dir, monkeypatch):
    monkeypatch.setattr(server, "_demo", None)
    monkeypatch.setattr(server, "ROOT", str(__import__("pathlib").Path(data_dir).parent))
    monkeypatch.setenv("AL_DEMO_DATA", data_dir)
    try:
        assert server.demo().data_dir == data_dir
    finally:
        server._demo = None


def test_data_source_label_comes_from_the_data(client):
    """The badge must not say synthetic on real data, or the reverse: it is read from split_hashes.json."""
    import json
    import os
    src = json.load(open(os.path.join(server._demo.data_dir, "split_hashes.json")))["source"]
    assert client.get("/state").json()["data_source"] == src


def _runs(base, team="T1", bucket="t-data-1-use2", passed=True):
    """A judging.json with a licence and a deny run, and their declarations and record files."""
    import json
    results = {}
    for rid, unit, value, n in (("r-licence", "licence", 0.0119, 450), ("r-deny", "deny", 0.9, 10)):
        (base / "evidence" / "declared").mkdir(parents=True, exist_ok=True)
        (base / "evidence" / "runs" / rid).mkdir(parents=True)
        (base / "evidence" / "declared" / f"{rid}.json").write_text(json.dumps(
            {"items": [{}] * n, "declared_at": "2026-11-03T01:00:00Z", "policy_mode": "ENFORCE", "licence": {"signer": "kms"}}))
        (base / "evidence" / "runs" / rid / "record.json").write_text(json.dumps(
            {"result": {"pass": passed, "value": value}, "licence": {"data_source": "telelogs"}}))
        results[rid] = {"unit": unit, "pass": True, "value": 1.0}      # the record file decides, not this
    (base / "judging.json").write_text(json.dumps({"team_code": team, "evidence": {"bucket": bucket}, "reported_results": results}))


def test_live_strip_reads_the_declared_runs_never_hardcoded(tmp_path):
    assert server.live_evidence(str(tmp_path)) is None
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "smoke_evidence.json").write_text("{}")      # the old undeclared files no longer count
    assert server.live_evidence(str(tmp_path)) is None
    _runs(tmp_path)
    ev = server.live_evidence(str(tmp_path))
    assert ev["scope"] == "team" and ev["data_source"] == "telelogs" and ev["signer"] == "kms"
    assert ev["units"]["licence"]["value"] == 0.0119 and ev["units"]["deny"]["items"] == 10


def test_live_strip_labels_anything_outside_the_team_account(tmp_path):
    (tmp_path / "dist" / "rehearsal-old").mkdir(parents=True)
    (tmp_path / "dist" / "rehearsal-new").mkdir()
    _runs(tmp_path / "dist" / "rehearsal-new", team="old")
    assert server.live_evidence(str(tmp_path))["scope"] == "rehearsal"       # found in dist/rehearsal*: always a rehearsal
    _runs(tmp_path, team="T1", bucket="al-evidence-1-us-east-1")
    assert server.live_evidence(str(tmp_path))["scope"] == "personal"        # the root wins; the fallback bucket says so


def test_live_strip_believes_the_record_file_and_skips_unreadable_runs(tmp_path):
    import json
    _runs(tmp_path, passed=False)
    assert server.live_evidence(str(tmp_path))["units"]["deny"]["passed"] is False
    (tmp_path / "evidence" / "runs" / "r-deny" / "record.json").unlink()
    assert "deny" not in server.live_evidence(str(tmp_path))["units"]
    (tmp_path / "judging.json").write_text(json.dumps({"reported_results": {}}))
    assert server.live_evidence(str(tmp_path)) is None
