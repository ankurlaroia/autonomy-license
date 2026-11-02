"""Trusted services shared by the token minter (Path A), the interceptor (Path C) and the tool
Lambda (Path B). On AWS these are: the deployment registry (expected fingerprint), the licence
registry + warnings (DynamoDB), the score cache (S3/DynamoDB), the incident store and the issuer's
public key. The agent has no write access to any of them.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from common.store import Store
from license.registry import Registry
from model.scorer import ScoreCache


@dataclass
class Trusted:
    store: Store
    incidents: dict                    # incident_id -> full record (label kept server-side only)
    scores: ScoreCache
    issuer_public_key: object
    expected_fingerprint: str
    issuer: str = "autonomy-license/calibrator"
    audience: str = "netops-verifier"
    registry: Registry = field(init=False)

    def __post_init__(self):
        self.registry = Registry(self.store)

    # ---- server-side facts the agent cannot set ----
    def category(self, incident_id: str) -> str:
        return self.incidents[incident_id]["category"]

    def score(self, incident_id: str) -> dict:
        return self.scores.get(incident_id)

    def cell_ids(self, incident_id: str) -> set[str]:
        return {c["cell_id"] for c in self.incidents[incident_id]["cells"]}

    def public_incident(self, incident_id: str) -> dict:
        inc = self.incidents[incident_id]
        return {"incident_id": incident_id, "category": inc["category"],
                "cells": inc["cells"], "features": inc["features"]}   # no label, no margins

    @classmethod
    def from_dir(cls, data_dir: str, store: Store, issuer_public_key, expected_fingerprint: str):
        inc = {}
        for line in open(os.path.join(data_dir, "incidents.jsonl")):
            x = json.loads(line)
            inc[x["incident_id"]] = x
        return cls(store, inc, ScoreCache(os.path.join(data_dir, "scores.jsonl")), issuer_public_key,
                   expected_fingerprint)
