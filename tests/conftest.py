import os
import shutil
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory):
    """Synthetic stand-in, generated fresh: the release checklist needs incidents of known shapes (e.g. a small
    C2 above the threshold, which the real held-out set does not contain). AL_TEST_DATA=real runs on
    state/data instead; real-data behaviour is otherwise covered live by aws.infra.smoke / attacks_live."""
    d = tmp_path_factory.mktemp("data")
    src = os.path.join(ROOT, "state", "data")
    if os.environ.get("AL_TEST_DATA") == "real" and os.path.exists(os.path.join(src, "scores.jsonl")):
        for f in ("incidents.jsonl", "splits.json", "split_hashes.json", "categories.json", "scores.jsonl"):
            shutil.copy(os.path.join(src, f), d / f)
    return str(d)


@pytest.fixture
def demo(data_dir, tmp_path):
    from demo.engine import Demo
    d = Demo(data_dir=data_dir, db=str(tmp_path / "t.db"), fresh=True)
    d.moment1_earn()
    return d
