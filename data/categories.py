"""Incident categories k1-k4: k-means over engineering parameters observable at arrival.

Never uses the root-cause label, so every operator computes the same category and the agent
cannot choose it (the tool Lambda / interceptor recompute it from the incident id).
"""
from __future__ import annotations

import numpy as np

FEATURES = ["downtilt_deg", "ho_ttt_ms", "rb_scheduled", "speed_kmh", "serving_distance_m"]


def _vec(inc):
    s = next(c for c in inc["cells"] if c["role"] == "serving")
    f = inc["features"]
    return np.array([s["downtilt_deg"], s["ho_ttt_ms"], s["rb_scheduled"], f["speed_kmh"],
                     f["serving_distance_m"]], dtype=float)


def fit_categories(incidents, k: int = 4, seed: int = 7, iters: int = 50) -> dict:
    X = np.stack([_vec(x) for x in incidents])
    mu, sd = X.mean(0), X.std(0) + 1e-9
    Z = (X - mu) / sd
    rng = np.random.default_rng(seed)
    C = Z[rng.choice(len(Z), k, replace=False)]
    for _ in range(iters):
        lab = ((Z[:, None, :] - C[None]) ** 2).sum(-1).argmin(1)
        C = np.stack([Z[lab == j].mean(0) if (lab == j).any() else C[j] for j in range(k)])
    return {"features": FEATURES, "mean": mu.tolist(), "std": sd.tolist(), "centroids": C.tolist()}


def assign_category(incident, cents: dict) -> str:
    z = (_vec(incident) - np.array(cents["mean"])) / np.array(cents["std"])
    j = int(((np.array(cents["centroids"]) - z) ** 2).sum(1).argmin())
    return f"k{j + 1}"
