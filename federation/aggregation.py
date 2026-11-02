"""Pairwise-masking secure aggregation (prototype fallback).

Each pair of operators (i, j) shares a seed s_ij (prototype: from config;
production: X25519 key agreement). For round r, both expand the seed into the
same mask vector m_ij. Operator i adds m_ij for every j > i and subtracts
m_ji for every j < i (all mod 2^61 - 1). The aggregator sums the masked
vectors; masks cancel; only the total is revealed.

Threat model: honest-but-curious aggregator; no aggregator-operator collusion;
no dropouts (a missing operator aborts the round); operators report honestly.
NOT differential privacy; NOT robust to malicious participants.
"""
from __future__ import annotations

import hashlib

import numpy as np

P = (1 << 61) - 1  # Mersenne prime modulus


def _mask(seed: bytes, round_id: str, length: int) -> np.ndarray:
    out, counter = [], 0
    while len(out) < length:
        h = hashlib.sha256(seed + round_id.encode() + counter.to_bytes(4, "big")).digest()
        for off in range(0, 32, 8):
            out.append(int.from_bytes(h[off:off + 8], "big") % P)
        counter += 1
    return np.array(out[:length], dtype=object)


def mask_vector(me: str, counts, peers_seeds: dict[str, bytes], round_id: str) -> list[int]:
    """counts: 1-D integer vector, e.g. concat(n, k). peers_seeds: {peer: seed}."""
    v = np.array([int(c) % P for c in counts], dtype=object)
    for peer, seed in peers_seeds.items():
        m = _mask(seed, round_id, len(v))
        v = (v + m) % P if me < peer else (v - m) % P
    return [int(x) for x in v]


def aggregate(masked_vectors: list[list[int]]) -> list[int]:
    total = np.zeros(len(masked_vectors[0]), dtype=object)
    for vec in masked_vectors:
        total = (total + np.array(vec, dtype=object)) % P
    return [int(x) for x in total]
