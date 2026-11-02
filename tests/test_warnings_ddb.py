"""P1 on AWS: a signed warning verified by the receiver lands in the shared DynamoDB table, every Lambda's
registry then masks that category, and replay / rate limits hold as in the SQLite receiver."""
import time

import pytest

from federation.warnings import MAX_TTL, WarningError, make_warning, verify_warning
from license.registry_ddb import DynamoRegistry
from license.signer import LocalSigner
from tests.test_registry_ddb import CondFail, FakeDdb


class Ddb(FakeDdb):
    def put_item(self, TableName, Item, ConditionExpression=None):
        if ConditionExpression == "attribute_not_exists(nonce)" and Item["nonce"]["S"] in self.t.get(TableName, {}):
            raise CondFail()
        return super().put_item(TableName, Item, ConditionExpression)

    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeNames, ExpressionAttributeValues,
                    ConditionExpression=None):
        if "nonce" in Key:
            self.t[TableName][Key["nonce"]["S"]]["status"] = ExpressionAttributeValues[":s"]
            return
        return super().update_item(TableName, Key, UpdateExpression, ConditionExpression, ExpressionAttributeNames,
                                   ExpressionAttributeValues)


B = LocalSigner(kid="op-B")
KEYS = {"B": B.public_key()}
NOW = int(time.time())


def warn(cat="k2", now=NOW, ttl=MAX_TTL, signer=B):
    return make_warning(signer, "B", cat, "hard_rule_deny", "sha256:x", reviewer="sec-1", ttl_s=ttl, now=now)


def test_verified_warning_masks_category_for_every_reader():
    ddb = Ddb()
    writer, tool_lambda = DynamoRegistry(ddb), DynamoRegistry(ddb)
    writer.add_warning(verify_warning(warn(), KEYS), "A", now=NOW)
    assert tool_lambda.warned_categories("A", now=NOW + 1) == {"k2"}
    assert tool_lambda.warned_categories("C", now=NOW + 1) == set()
    assert tool_lambda.warned_categories("A", now=NOW + MAX_TTL + 1) == set()       # expiry restores autonomy


def test_replay_and_rate_limits():
    r = DynamoRegistry(Ddb())
    c = verify_warning(warn(), KEYS)
    r.add_warning(c, "A", now=NOW)
    with pytest.raises(WarningError, match="one active"):
        r.add_warning(verify_warning(warn(), KEYS), "A", now=NOW)
    with pytest.raises(WarningError):
        r.add_warning(c, "C", now=NOW)                                                  # same nonce elsewhere
    r.add_warning(verify_warning(warn("k3"), KEYS), "A", now=NOW)
    r.add_warning(verify_warning(warn("k4"), KEYS), "A", now=NOW)
    with pytest.raises(WarningError, match="3 warnings"):
        r.add_warning(verify_warning(warn("k1"), KEYS), "A", now=NOW)


def test_forged_unknown_or_overlong_warning_never_reaches_the_table():
    with pytest.raises(WarningError):
        verify_warning(warn(signer=LocalSigner(kid="op-B")), KEYS)                     # wrong key
    with pytest.raises(WarningError):
        verify_warning(warn(), {})                                                      # unknown issuer
    with pytest.raises(WarningError):
        verify_warning(warn(now=NOW, ttl=MAX_TTL + 60), KEYS)


def test_clear_restores_autonomy():
    r = DynamoRegistry(Ddb())
    r.add_warning(verify_warning(warn(), KEYS), "A", now=NOW)
    assert r.clear_warnings("A") == 1 and r.warned_categories("A", now=NOW) == set()
