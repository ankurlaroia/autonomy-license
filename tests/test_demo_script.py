"""scripts/demo.py runs end to end even on a console whose default encoding cannot print λ̂ or ≤."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_demo_script_runs_with_cp1252_console(tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "demo.py"), "--data", str(tmp_path / "data")],
                       cwd=ROOT, env=env, capture_output=True, timeout=300)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-800:]
    out = r.stdout.decode("utf-8")
    assert "[1 EARN]" in out and "[3 BLOCK]" in out and "[6 WARNING]" in out


def test_real_incidents_without_scores_fail_closed_not_synthetic(tmp_path):
    """Real (TeleLogs) incidents never get synthetic scores filled in: the demo stops and says to score them."""
    import json
    import pytest
    from demo.engine import Demo
    data = tmp_path / "data"
    data.mkdir()
    (data / "incidents.jsonl").write_text('{"incident_id": "x"}\n')
    (data / "split_hashes.json").write_text(json.dumps({"source": "telelogs"}))
    with pytest.raises(SystemExit, match="no scores.jsonl"):
        Demo(data_dir=str(data), db=str(tmp_path / "a.db"), fresh=True)
    assert not (data / "scores.jsonl").exists()
