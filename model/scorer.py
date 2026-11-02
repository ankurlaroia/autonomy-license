"""Scorers: P(C1..C8 | incident) -> prediction + confidence s = max probability.

* SyntheticScorer  - deterministic stand-in classifier for the synthetic data (NOT an NLM).
* HFClassifierScorer - att/OTel-LLM-8.3B-Classification (8-class head) via transformers.
  Input = the raw TeleLogs question text, tokenised as in the authors' inference_telelogs.py (no chat
  template, max 5000 tokens). Its head predicts TeleLogs codes (config id2label 0..7 = "C1".."C8", checked
  at revision ac5eb8bf), which differ in meaning from the catalogue codes, so probabilities are re-ordered
  through each incident's code_map (data/telelogs_parse.py).

Score once, cache forever (spec 5.5): calibration, federation and evaluation read the cache;
the cache is the 'trusted score service' that the interceptor and tool Lambda consult, so the
agent can never supply its own confidence.
"""
from __future__ import annotations

import hashlib
import json
import os

import numpy as np

from common.catalogue import CAUSES


def softmax(z):
    z = np.asarray(z, float) - np.max(z)
    e = np.exp(z)
    return e / e.sum()


def config_fingerprint(model_id: str, model_version: str, prompt_template: str,
                       decoding: dict, scorer_code_sha: str) -> str:
    blob = json.dumps({"model_id": model_id, "model_version": model_version,
                       "prompt_sha": hashlib.sha256(prompt_template.encode()).hexdigest(),
                       "decoding": decoding, "scorer_sha": scorer_code_sha}, sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _code_sha(path=__file__) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


class SyntheticScorer:
    model_id = "synthetic-standin"
    model_version = "v1"
    prompt_template = "features->evidence (no prompt)"
    decoding = {"noise_sigma": 1.5, "gain": 2.6, "seeded": True}

    def evidence(self, inc):
        f = inc["features"]
        s = next(c for c in inc["cells"] if c["role"] == "serving")
        return np.array([
            (f["speed_kmh"] - 40) / 18,
            (s["downtilt_deg"] - 9) / 2.5,
            (f["serving_distance_m"] - 1000) / 300,
            (3 - f["cofreq_gap_db"]) / 2.5,
            1.2 if f["pci_mod30_clash"] else -1.2,
            (f["n_handovers"] - 4) / 2.5,
            (s["ho_a3_offset_db"] - 3) / 2.0,
            (160 - f["avg_rb"]) / 30,
        ])

    def predict(self, inc) -> dict:
        seed = int(hashlib.sha256(inc["incident_id"].encode()).hexdigest()[:8], 16)
        rng = np.random.default_rng(seed)
        z = self.decoding["gain"] * self.evidence(inc) + rng.normal(0, self.decoding["noise_sigma"], 8)
        p = softmax(z)
        j = int(p.argmax())
        return {"pred": CAUSES[j], "score": float(round(p[j], 6)), "probs": [round(float(x), 6) for x in p]}

    def fingerprint(self) -> str:
        return config_fingerprint(self.model_id, self.model_version, self.prompt_template,
                                  self.decoding, _code_sha())


REVISION = "ac5eb8bfdf0f0ba2fa7cc2c77569b8e9dd09fe53"
HEAD_LABELS = [f"C{i}" for i in range(1, 9)]


def to_catalogue(probs, code_map: dict | None):
    """Head probabilities (TeleLogs code order) -> catalogue order. Identity when the incident has no map."""
    probs = np.asarray(probs, float)
    if not code_map:
        return probs
    out = np.zeros(8)
    for i, code in enumerate(HEAD_LABELS):
        out[CAUSES.index(code_map[code])] += probs[i]
    return out


class HFClassifierScorer:   # pragma: no cover - needs GPU, model access
    model_id = "att/OTel-LLM-8.3B-Classification"
    prompt_template = ("Symptom: downlink throughput below 600 Mbps during a drive test.\n"
                       "Engineering parameters:\n{cells}\nDrive-test summary:\n{features}\nRoot cause?")
    decoding = {"head": "classification", "max_len": 5000, "dtype": "bf16"}

    def __init__(self, revision: str = REVISION):
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        import torch
        self.torch = torch
        self.model_version = revision
        self.tok = AutoTokenizer.from_pretrained(self.model_id, revision=revision)
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_id, revision=revision, torch_dtype=torch.bfloat16, device_map="auto").eval()
        id2label = {int(k): v for k, v in self.model.config.id2label.items()}
        if [id2label[i] for i in range(8)] != HEAD_LABELS:
            raise RuntimeError(f"unexpected label order in the model head: {id2label}")

    def serialise(self, inc) -> str:
        if inc.get("raw_text"):
            return inc["raw_text"]            # exactly what the model was fine-tuned on
        cells = "\n".join(",".join(f"{k}={v}" for k, v in c.items()) for c in inc["cells"])
        feats = ",".join(f"{k}={v}" for k, v in inc["features"].items())
        return self.prompt_template.format(cells=cells, features=feats)

    def predict(self, inc) -> dict:
        x = self.tok(self.serialise(inc), return_tensors="pt", truncation=True, max_length=5000).to(self.model.device)
        with self.torch.no_grad():
            logits = self.model(**x).logits[0].float().cpu().numpy()
        p = to_catalogue(softmax(logits[:8]), inc.get("code_map"))
        j = int(p.argmax())
        return {"pred": CAUSES[j], "score": float(p[j]), "probs": p.round(6).tolist()}

    def fingerprint(self) -> str:
        return config_fingerprint(self.model_id, self.model_version, self.prompt_template,
                                  self.decoding, _code_sha())


class ScoreCache:
    """Trusted score service. On AWS: an S3 object / DynamoDB table readable only by the
    interceptor and tool Lambdas (not writable by the agent)."""

    def __init__(self, path: str):
        self.path = path
        self.rows = {}
        self.fingerprint = None
        if os.path.exists(path):
            for line in open(path):
                r = json.loads(line)
                if "fingerprint" in r and "incident_id" not in r:
                    self.fingerprint = r["fingerprint"]
                else:
                    self.rows[r["incident_id"]] = r

    def build(self, incidents, scorer):
        self.fingerprint = scorer.fingerprint()
        self.rows = {}
        for inc in incidents:
            r = scorer.predict(inc)
            r["incident_id"] = inc["incident_id"]
            r["correct"] = (r["pred"] == inc["label"])   # evaluation-side only
            self.rows[inc["incident_id"]] = r
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as f:
            f.write(json.dumps({"fingerprint": self.fingerprint}) + "\n")
            for r in self.rows.values():
                f.write(json.dumps(r) + "\n")
        return self

    def get(self, incident_id: str) -> dict:
        return self.rows[incident_id]
