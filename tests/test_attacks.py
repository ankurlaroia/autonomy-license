"""P2 attack scorecard: every scenario is blocked and none changes the simulator."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts"))
import attacks  # noqa: E402


def test_every_attack_blocked_without_state_change(data_dir, tmp_path):
    rows = attacks.run(data_dir=data_dir, db=str(tmp_path / "a.db"))
    assert len(rows) == 8
    assert all(r["blocked"] and r["state_changes"] == 0 for r in rows), rows
    assert rows[0]["by"] == "Cedar forbid F1"
