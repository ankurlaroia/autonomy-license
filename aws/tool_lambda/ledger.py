"""Cells already changed per incident, so the hard rule F1 (at most BLAST_RADIUS cells) holds across calls too.

Cedar and the per-call check see one call at a time: a 5-cell change sent as 3 cells then 2 passes both. The
ledger closes that. Before a change, the tool Lambda claims its cells for the incident; the claim fails when the
cells already changed plus the new ones exceed the limit, for anyone, in any mode. A claim is kept even if the
change then fails (fail closed: a reserved cell can only make the next call stricter).

Local: a SQLite table. On AWS: DynamoDB <prefix>-changes (pk incident_id), written with a version check so two
Lambdas cannot both claim the last free cell.
"""
from __future__ import annotations

from common.catalogue import BLAST_RADIUS


class LedgerError(Exception):
    pass


def _over(done: set, new: set, limit: int) -> str | None:
    total = done | new
    if len(total) > limit:
        return (f"hard rule: {len(total)} cells changed for this incident in total "
                f"({len(done)} before, {len(new - done)} new), limit {limit}")
    return None


class SqliteLedger:
    def __init__(self, store, limit: int = BLAST_RADIUS):
        self.s, self.limit = store, limit       # table changed_cells is in common/store.py SCHEMA

    def changed(self, incident_id: str) -> set:
        return {r[0] for r in self.s.q("SELECT cell_id FROM changed_cells WHERE incident_id=?", (incident_id,))}

    def claim(self, incident_id: str, cells: list[str]):
        with self.s._lock:
            why = _over(self.changed(incident_id), set(cells), self.limit)
            if why:
                raise LedgerError(why)
            for c in cells:
                self.s.x("INSERT OR IGNORE INTO changed_cells VALUES (?,?)", (incident_id, c))


class DynamoLedger:
    def __init__(self, client, prefix: str = "al", limit: int = BLAST_RADIUS, tries: int = 5):
        self.c, self.table, self.limit, self.tries = client, f"{prefix}-changes", limit, tries

    def changed(self, incident_id: str) -> set:
        r = self.c.get_item(TableName=self.table, Key={"incident_id": {"S": incident_id}}, ConsistentRead=True)
        return set(r.get("Item", {}).get("cells", {}).get("SS", []))

    def claim(self, incident_id: str, cells: list[str]):
        for _ in range(self.tries):
            r = self.c.get_item(TableName=self.table, Key={"incident_id": {"S": incident_id}}, ConsistentRead=True)
            item = r.get("Item")
            done = set(item["cells"]["SS"]) if item else set()
            why = _over(done, set(cells), self.limit)
            if why:
                raise LedgerError(why)
            ver = int(item["ver"]["N"]) if item else 0
            cond = ("attribute_not_exists(incident_id)", {}) if not item else \
                ("ver = :v", {":v": {"N": str(ver)}})
            try:
                self.c.put_item(TableName=self.table,
                                Item={"incident_id": {"S": incident_id}, "cells": {"SS": sorted(done | set(cells))},
                                      "ver": {"N": str(ver + 1)}},
                                ConditionExpression=cond[0], **({"ExpressionAttributeValues": cond[1]} if cond[1] else {}))
                return
            except Exception as e:      # another Lambda claimed first: read again
                if "ConditionalCheckFailed" not in type(e).__name__ and "ConditionalCheckFailed" not in str(e):
                    raise
        raise LedgerError("could not claim cells (concurrent changes); refused")
