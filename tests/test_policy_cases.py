"""Cedar policy cases (spec 10.4) evaluated with the exact policy text deployed to AgentCore."""
import pytest

from aws.cedar.engine import PolicyEngine

AGENT = {"role": "netops-agent", "lic_state": "active", "lic_cats": "|k1|k2|k3|k4|", "warned": "||"}
ENG = {"role": "noc-engineer"}
BASE = {"incident_id": "INC-1", "mode": "autonomous", "category": "k2", "score_ok": True, "licence_ok": True,
        "cell_count": 2, "action": "adjust_tilt", "cells": ["a", "b"]}


@pytest.fixture(scope="module")
def eng():
    return PolicyEngine()


@pytest.mark.parametrize("tags,inp,expect,policy", [
    (AGENT, {}, "ALLOW", "P2k2"),                                                  # licensed tilt, 2 cells
    (AGENT, {"cell_count": 4}, "DENY", "F1"),                                      # blast radius
    (AGENT, {"action": "power_down_cells"}, "DENY", "F2"),                         # never autonomous
    ({**AGENT, "warned": "|k2|"}, {}, "DENY", "F3k2"),                             # warned category
    ({k: v for k, v in AGENT.items() if k != "lic_state"}, {}, "DENY", None),      # no licence tag
    (AGENT, {"score_ok": False}, "DENY", None),                                    # below threshold
    (AGENT, {"licence_ok": False}, "DENY", None),                                  # revoked / invalid now
    (AGENT, {"category": "k9"}, "DENY", None),                                     # unlicensed category
    (AGENT, {"action": "rebalance_scheduler"}, "DENY", None),                      # HUMAN-class action
    (ENG, {"mode": "approved", "approval_id": "APR-1", "cell_count": 6}, "DENY", "F1"),   # T12 absolute
    (ENG, {"mode": "approved", "approval_id": "APR-1"}, "ALLOW", "P3"),
    (AGENT, {"mode": "approved", "approval_id": "APR-1"}, "DENY", None),           # agent can't self-approve
    (ENG, {"mode": "approved"}, "DENY", None),                                     # no approval id
])
def test_policy(eng, tags, inp, expect, policy):
    r = eng.evaluate("p", tags, "apply_remediation", {**BASE, **inp})
    assert r["decision"] == expect, r
    if policy:
        assert policy in r["policies"]


def test_read_tools_allowed_for_agent(eng):
    assert eng.evaluate("p", AGENT, "get_incident", {"incident_id": "x"})["decision"] == "ALLOW"
