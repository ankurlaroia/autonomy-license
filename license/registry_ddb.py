"""Licence status registry and received warnings in DynamoDB, shared by every Lambda (spec 9.4).

Same interface as license.registry.Registry. Each Lambda keeps its own SQLite copy for audit and the
simulator, but licence status and warnings must be shared, or a revocation written by one would not
be seen by the others (demo moment 4, S5).

Tables (on-demand): <prefix>-licences (pk jti), <prefix>-warnings (pk nonce). Both stay tiny, so
current() and warned_categories() scan them. Revoked is terminal: a withdrawn licence is never switched
back on; re-certification issues a new jti.
"""
from __future__ import annotations

import time

STATUSES = ("active", "suspended", "revoked")


class DynamoRegistry:
    def __init__(self, client, prefix: str = "al"):
        self.c = client
        self.licences, self.warnings = f"{prefix}-licences", f"{prefix}-warnings"

    def put(self, jti: str, token: str, status: str = "active"):
        assert status in STATUSES
        now = int(time.time())
        self.c.put_item(TableName=self.licences, Item={
            "jti": {"S": jti}, "token": {"S": token}, "status": {"S": status},
            "issued_at": {"N": str(now)}, "updated_at": {"N": str(now)}, "note": {"S": ""}},
            ConditionExpression="attribute_not_exists(jti)")

    def status(self, jti: str) -> str:
        r = self.c.get_item(TableName=self.licences, Key={"jti": {"S": jti}}, ConsistentRead=True)
        return r["Item"]["status"]["S"] if "Item" in r else "unknown"

    def set_status(self, jti: str, status: str, note: str = ""):
        assert status in STATUSES
        self.c.update_item(
            TableName=self.licences, Key={"jti": {"S": jti}},
            UpdateExpression="SET #s = :s, updated_at = :t, note = :n",
            ConditionExpression="attribute_exists(jti) AND #s <> :revoked",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": {"S": status}, ":t": {"N": str(int(time.time()))},
                                       ":n": {"S": note[:200]}, ":revoked": {"S": "revoked"}})

    def _scan(self, table: str) -> list[dict]:
        items, kw = [], {"TableName": table, "ConsistentRead": True}
        while True:
            r = self.c.scan(**kw)
            items += r.get("Items", [])
            if "LastEvaluatedKey" not in r:
                return items
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def current(self) -> tuple[str, str] | None:
        """Most recent licence (jti, token), whatever its status."""
        items = self._scan(self.licences)
        if not items:
            return None
        top = max(items, key=lambda i: (int(i["issued_at"]["N"]), i["jti"]["S"]))
        return top["jti"]["S"], top["token"]["S"]

    def warned_categories(self, receiver: str, now: int | None = None) -> set[str]:
        now = now or int(time.time())
        return {i["category"]["S"] for i in self._scan(self.warnings)
                if i["receiver"]["S"] == receiver and i["status"]["S"] == "active" and int(i["exp"]["N"]) > now}

    # ---- P1 warnings (claims already verified by federation.warnings.verify_warning) ----
    def add_warning(self, claims: dict, receiver: str, now: int | None = None):
        """Same replay and rate limits as the SQLite receiver. Warnings only ever reduce autonomy."""
        from federation.warnings import MAX_PER_HOUR, WarningError
        now = now or int(time.time())
        mine = [i for i in self._scan(self.warnings)
                if i["issuer"]["S"] == claims["issuer"] and i["receiver"]["S"] == receiver]
        if any(i["status"]["S"] == "active" and i["category"]["S"] == claims["category"] and int(i["exp"]["N"]) > now
               for i in mine):
            raise WarningError("rate limit: one active warning per (issuer, category)")
        if sum(int(i["iat"]["N"]) > now - 3600 for i in mine) >= MAX_PER_HOUR:
            raise WarningError("rate limit: at most 3 warnings per issuer per hour")
        try:
            self.c.put_item(TableName=self.warnings, Item={
                "nonce": {"S": claims["nonce"]}, "issuer": {"S": claims["issuer"]}, "receiver": {"S": receiver},
                "category": {"S": claims["category"]}, "signal": {"S": claims["signal"]},
                "iat": {"N": str(claims["iat"])}, "exp": {"N": str(claims["exp"])}, "status": {"S": "active"}},
                ConditionExpression="attribute_not_exists(nonce)")
        except Exception as e:
            if "Conditional" in type(e).__name__ or "CondFail" in type(e).__name__:
                raise WarningError("replayed nonce") from None
            raise

    def clear_warnings(self, receiver: str) -> int:
        n = 0
        for i in self._scan(self.warnings):
            if i["receiver"]["S"] == receiver and i["status"]["S"] == "active":
                self.c.update_item(TableName=self.warnings, Key={"nonce": i["nonce"]},
                                   UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
                                   ExpressionAttributeValues={":s": {"S": "cleared"}})
                n += 1
        return n
