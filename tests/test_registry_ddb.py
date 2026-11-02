"""The DynamoDB registry behaves like the SQLite one where the enforcement paths depend on it, and a
revocation is visible to every reader at once (one shared table)."""
import pytest

from license.registry_ddb import DynamoRegistry


class CondFail(Exception):
    pass


class FakeDdb:
    """Just enough of the DynamoDB client for the registry: items, conditions, paged scans."""

    def __init__(self, page=2):
        self.t, self.page = {}, page

    def put_item(self, TableName, Item, ConditionExpression=None):
        pk = "jti" if "jti" in Item else "nonce"
        tbl = self.t.setdefault(TableName, {})
        if ConditionExpression == "attribute_not_exists(jti)" and Item[pk]["S"] in tbl:
            raise CondFail()
        tbl[Item[pk]["S"]] = dict(Item)

    def get_item(self, TableName, Key, ConsistentRead=False):
        it = self.t.get(TableName, {}).get(next(iter(Key.values()))["S"])
        return {"Item": it} if it else {}

    def update_item(self, TableName, Key, UpdateExpression, ConditionExpression, ExpressionAttributeNames,
                    ExpressionAttributeValues):
        it = self.t.get(TableName, {}).get(Key["jti"]["S"])
        if it is None or it["status"]["S"] == "revoked":
            raise CondFail()
        v = ExpressionAttributeValues
        it.update(status=v[":s"], updated_at=v[":t"], note=v[":n"])

    def scan(self, TableName, ConsistentRead=False, ExclusiveStartKey=None):
        items = list(self.t.get(TableName, {}).values())
        start = ExclusiveStartKey or 0
        r = {"Items": items[start:start + self.page]}
        if start + self.page < len(items):
            r["LastEvaluatedKey"] = start + self.page
        return r


@pytest.fixture
def ddb():
    return FakeDdb()


def test_status_and_current(ddb, monkeypatch):
    r = DynamoRegistry(ddb)
    assert r.current() is None and r.status("x") == "unknown"
    t = iter([100, 200, 300])
    monkeypatch.setattr("license.registry_ddb.time.time", lambda: next(t))
    r.put("a", "tok-a")
    r.put("b", "tok-b")
    r.put("c", "tok-c")
    assert r.current() == ("c", "tok-c")          # paged scan still finds the newest
    assert r.status("b") == "active"


def test_revocation_is_seen_by_every_reader_and_is_terminal(ddb):
    writer, reader = DynamoRegistry(ddb), DynamoRegistry(ddb)   # e.g. console and tool Lambda
    writer.put("j1", "tok")
    writer.set_status("j1", "revoked", "demo")
    assert reader.status("j1") == "revoked"
    with pytest.raises(CondFail):
        writer.set_status("j1", "active")
    assert reader.status("j1") == "revoked"


def test_jti_cannot_be_overwritten(ddb):
    r = DynamoRegistry(ddb)
    r.put("j1", "tok")
    with pytest.raises(CondFail):
        r.put("j1", "other-token")


def test_set_status_on_unknown_licence_fails(ddb):
    with pytest.raises(CondFail):
        DynamoRegistry(ddb).set_status("nope", "suspended")


def test_bad_status_rejected(ddb):
    r = DynamoRegistry(ddb)
    r.put("j1", "tok")
    with pytest.raises(AssertionError):
        r.set_status("j1", "reinstated")


def test_warned_categories_filters_receiver_status_and_expiry(ddb):
    r = DynamoRegistry(ddb)
    for n, (recv, cat, st, exp) in enumerate([("A", "k2", "active", 2000), ("A", "k3", "cleared", 2000),
                                              ("A", "k4", "active", 500), ("B", "k1", "active", 2000)]):
        ddb.put_item(TableName="al-warnings", Item={"nonce": {"S": str(n)}, "receiver": {"S": recv},
                                                    "category": {"S": cat}, "status": {"S": st},
                                                    "exp": {"N": str(exp)}})
    assert r.warned_categories("A", now=1000) == {"k2"}
