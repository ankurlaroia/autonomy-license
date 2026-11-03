"""What Git may publish: secrets, data and internal documents stay out, and the hand-in files stay in."""
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(not (ROOT / ".git").exists() or not shutil.which("git"), reason="needs a Git checkout")


def ignored(path):
    # --no-index: judge the rule itself, even for a file already tracked
    return subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT).returncode == 0


@pytest.mark.parametrize("path", [
    ".env", ".env.local", "fyuz.env", "aws/.env", "licence.pem", "issuer.key", "aws/credentials", ".aws/config",
    "secrets.json", "web/.npmrc", "state/data/test.json", "data/telelogs.csv", "data/telelogs.parquet", "out.jsonl",
    "dist/rehearsal/judging.json", "local.db", "weights.safetensors", "organiser-files/guide.html", "guide.pdf",
    "GUIDE.md", "DEMO_SCRIPT.md", "aws/infra/SMOKE_TEST.md", "web/README.md", "web/AGENTS.md",
    "demo-run/00-start.png", "ui-snapshots/attack-scorecard.txt", ".claude/launch.json",
])
def test_stays_out(path):
    assert ignored(path)


@pytest.mark.parametrize("path", [
    "README.md", "DATA.md", "GAPS.md", "judging.json", "evidence/declared/run.json", "evidence/runs/run/items.jsonl",
    "evidence/runs/run/records.jsonl", "evidence/reward.csv", ".env.example", "requirements.txt",
    "aws/infra/tool_schemas.json", "aws/cedar/netops.cedar", "tools/rebuild.py", "web/package-lock.json",
])
def test_stays_in(path):
    assert not ignored(path)


@pytest.mark.parametrize("path", ["evidence/runs/run/items.jsonl", "evidence/declared/run.json", "judging.json"])
def test_git_keeps_evidence_bytes_exact(path):      # tools/rebuild.py hashes these files
    out = subprocess.run(["git", "check-attr", "text", "--", path], cwd=ROOT, capture_output=True, text=True).stdout
    assert out.strip().endswith("text: unset")
