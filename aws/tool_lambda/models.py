"""Withdrawing a model: the track's pause. Status lives in DynamoDB <prefix>-models (pk model_id), so a withdrawal
reaches every Lambda on the next call, with no deploy and nothing deleted. A model with no item is active.

The interceptor sets model_ok from this table and Cedar F4 forbids a call to a withdrawn model; the tool checks again.
Withdrawing the classifier makes licence_ok false, so its diagnoses cannot be acted on alone. Fail closed: a status
that cannot be read counts as withdrawn.
"""
from __future__ import annotations

import time

CLASSIFIER = "att/OTel-LLM-8.3B-Classification"


class DynamoModels:
    def __init__(self, client, prefix: str = "al"):
        self.c, self.table = client, f"{prefix}-models"

    def status(self, model_id: str) -> str:
        r = self.c.get_item(TableName=self.table, Key={"model_id": {"S": model_id}}, ConsistentRead=True)
        return r.get("Item", {}).get("status", {}).get("S", "active")

    def set_status(self, model_id: str, status: str, reason: str = ""):
        if status not in ("active", "withdrawn"):
            raise ValueError("status must be active or withdrawn")
        self.c.put_item(TableName=self.table, Item={"model_id": {"S": model_id}, "status": {"S": status},
                                                    "reason": {"S": reason[:200]}, "at": {"N": str(int(time.time()))}})


def model_ok(trusted, model_id: str) -> bool:
    """Local runs have no model registry, so nothing can be withdrawn there; on AWS one is always set."""
    models = getattr(trusted, "models", None)
    if models is None:
        return True
    try:
        return models.status(model_id) == "active"
    except Exception:
        return False


def team_model(trusted) -> str:
    from aws.tool_lambda.team import DEFAULT_MODEL
    specialist = getattr(trusted, "specialist", None)
    return specialist.model if specialist else DEFAULT_MODEL
