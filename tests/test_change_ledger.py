"""F1 across calls: a change bigger than the blast radius cannot be split into calls that each fit."""
import pytest

from aws.tool_lambda.ledger import DynamoLedger, LedgerError, SqliteLedger
from aws.tool_lambda.tools import NetOpsTools, ToolError
from common.catalogue import BLAST_RADIUS, CATALOGUE
from common.store import Store

AGENT = {"role": "netops-agent"}


def test_sqlite_ledger_counts_cells_across_calls(tmp_path):
    led = SqliteLedger(Store(str(tmp_path / "l.db")))
    led.claim("i1", ["a", "b"])
    led.claim("i1", ["a", "b", "c"])          # repeating cells already changed adds nothing
    with pytest.raises(LedgerError, match="hard rule"):
        led.claim("i1", ["d"])
    led.claim("i2", ["d"])                    # other incidents have their own count
    assert led.changed("i1") == {"a", "b", "c"}


def test_reset_clears_the_ledger(tmp_path):
    s = Store(str(tmp_path / "l.db"))
    SqliteLedger(s).claim("i1", ["a", "b", "c"])
    s.reset()
    SqliteLedger(s).claim("i1", ["d"])


class Conditional(Exception):
    pass


Conditional.__name__ = "ConditionalCheckFailedException"


class FakeDdb:
    def __init__(self, race=0):
        self.items, self.race = {}, race

    def get_item(self, TableName, Key, ConsistentRead):
        assert ConsistentRead and TableName == "al-changes"
        it = self.items.get(Key["incident_id"]["S"])
        return {"Item": it} if it else {}

    def put_item(self, TableName, Item, ConditionExpression, ExpressionAttributeValues=None):
        k = Item["incident_id"]["S"]
        if self.race:                         # another Lambda wrote first
            self.race -= 1
            self.items[k] = {"incident_id": {"S": k}, "cells": {"SS": ["x", "y"]}, "ver": {"N": "7"}}
            raise Conditional("ConditionalCheckFailed")
        cur = self.items.get(k)
        if ConditionExpression.startswith("attribute_not_exists"):
            ok = cur is None
        else:
            ok = cur is not None and cur["ver"]["N"] == ExpressionAttributeValues[":v"]["N"]
        if not ok:
            raise Conditional("ConditionalCheckFailed")
        self.items[k] = Item


def test_dynamo_ledger_counts_cells_across_calls():
    led = DynamoLedger(FakeDdb())
    led.claim("i1", ["a", "b", "c"])
    with pytest.raises(LedgerError):
        led.claim("i1", ["d"])
    assert led.changed("i1") == {"a", "b", "c"}


def test_dynamo_ledger_rereads_after_a_concurrent_claim():
    led = DynamoLedger(FakeDdb(race=1))
    with pytest.raises(LedgerError, match="hard rule"):     # x, y were taken meanwhile: x, y, a, b is too many
        led.claim("i1", ["a", "b"])


def test_dynamo_ledger_fails_closed_when_it_keeps_losing():
    with pytest.raises(LedgerError, match="concurrent"):
        DynamoLedger(FakeDdb(race=99), tries=3).claim("i1", ["x"])


def test_dynamo_ledger_passes_other_errors_through():
    class Broken(FakeDdb):
        def put_item(self, **kw):
            raise RuntimeError("throttled")
    with pytest.raises(RuntimeError):
        DynamoLedger(Broken()).claim("i1", ["a"])


def big_incident(d):
    t = d.threshold()

    def fits(i):
        s = d.scores.get(i)
        return (CATALOGUE[s["pred"]]["cls"] == "AUTO" and s["score"] >= t
                and len(d.trusted.public_incident(i)["cells"]) > BLAST_RADIUS)
    iid = d.heldout_where(fits)
    if iid is None:
        pytest.skip("no AUTO incident above the threshold with more cells than the blast radius")
    cells = [c["cell_id"] for c in d.trusted.public_incident(iid)["cells"]]
    return iid, CATALOGUE[d.scores.get(iid)["pred"]]["action"], cells


def test_split_change_is_refused_by_the_tool(demo):
    iid, action, cells = big_incident(demo)
    tools = NetOpsTools(demo.trusted)
    call = {"incident_id": iid, "action": action, "mode": "autonomous"}
    tools.apply_remediation(AGENT, {**call, "cells": cells[:BLAST_RADIUS]})
    n = demo.store.q("SELECT COUNT(*) FROM sim_actions")[0][0]
    with pytest.raises(ToolError, match="in total"):
        tools.apply_remediation(AGENT, {**call, "cells": cells[BLAST_RADIUS:BLAST_RADIUS + 1]})
    assert demo.store.q("SELECT COUNT(*) FROM sim_actions")[0][0] == n                      # nothing changed
    refused = demo.store.q("SELECT record FROM audit WHERE kind='tool_refused'")
    assert any("in total" in r[0] for r in refused)
    tools.apply_remediation(AGENT, {**call, "cells": cells[:2]})                            # same cells again: fine
