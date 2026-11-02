"""Operations console (spec 14.4). Adapted layout from the Edge NLM Streamlit app, re-pointed from its
fault dropdown to the pre-registered held-out TeleLogs incident list.

    streamlit run console/app.py

Replay mode is the default: everything runs on cached scores through the local Gateway stack.
"""
import json
import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demo.engine import Demo  # noqa: E402

st.set_page_config(page_title="Autonomy License — NOC console", layout="wide")


@st.cache_resource
def get_demo():
    d = Demo(data_dir=os.environ.get("AL_DEMO_DATA"), fresh=True)   # unset: state/data (real once scored)
    d.store.kv_set("last", {})
    return d


d = get_demo()
if "log" not in st.session_state:
    st.session_state.log = []


def run(name, fn):
    res = fn()
    st.session_state.log.insert(0, (name, res))
    st.session_state.last = (name, res)
    st.rerun()          # redraw the licence strip and button states from the new registry state


# ---------------------------------------------------------------- header + licence strip
st.title("Autonomy License — From Proof to Action")
st.caption("Synthetic stand-in data until TeleLogs access is granted · simulated network only · "
           "the bound covers wrong autonomous diagnoses, not action safety")

claims = d.licence_claims()
jti = claims["jti"] if claims else None
status = d.trusted.registry.status(jti) if jti else "UNLICENSED"
warned = sorted(d.trusted.registry.warned_categories("A"))
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Licence (operator A)", status.upper() if jti else "UNLICENSED")
c2.metric("Threshold λ̂", f"{claims['risk']['threshold']:.3f}" if claims else "—")
c3.metric("Bound U (official α)", f"{claims['risk']['upper_bound']:.2%} ≤ {claims['risk']['alpha']:.0%}" if claims else "—")
c4.metric("Evidence n / k", f"{claims['risk']['n']} / {claims['risk']['k']}" if claims else "—")
c5.metric("Masked categories", ", ".join(warned) or "none")

# ---------------------------------------------------------------- moment buttons
st.subheader("Demo moments")
b = st.columns(7)
if b[0].button("1 · Earn", use_container_width=True):
    run("1 Earn", d.moment1_earn)
if b[1].button("2 · Act", use_container_width=True, disabled=not jti):
    run("2 Act", d.moment2_act)
if b[2].button("3 · Block", use_container_width=True, disabled=not jti):
    run("3 Block", d.moment3_block)
if b[3].button("4 · Revoke", use_container_width=True, disabled=not jti):
    run("4 Revoke", d.moment4_revoke)
if b[4].button("Re-certify", use_container_width=True):
    run("Re-certify", lambda: {"licence": d.reinstate()["jti"]})
if b[5].button("5 · Federation (P1)", use_container_width=True):
    run("5 Federation", d.moment5_federation)
if b[6].button("6 · Warning (P1)", use_container_width=True, disabled=not jti):
    run("6 Warning", d.moment6_warning)


def trace_card(t, title):
    if not t:
        return
    st.markdown(f"**{title}** · `{t['incident_id']}` · category **{t['category']}** · predicted **{t['pred']}** "
                f"· score **{t['score']:.3f}** vs λ̂ {t['threshold']} → **{t['outcome']}**")
    for s in t["steps"]:
        if s["call"] == "apply_remediation":
            if s["isError"]:
                pol = (s.get("policy") or {}).get("policies")
                st.error(f"Cedar: DENY {pol or '(default deny)'} — {s['text']}")
            else:
                st.success(f"Cedar: ALLOW {(s.get('policy') or {}).get('policies')} — action applied on simulator")
                r = s["result"]
                rows = [{"cell": c, **{k: f"{r['before'][c].get(k)} → {r['after'][c].get(k)}"
                                       for k in ("downtilt_deg", "pci", "ho_ttt_ms", "ho_a3_offset_db")
                                       if r['before'][c].get(k) != r['after'][c].get(k)}} for c in r["before"]]
                st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
                st.caption(f"Throughput {r['kpi_before']} → {r['kpi_after']} Mbps · resolved={r['resolved']} "
                           "(simulated; decided from ground truth)")
        else:
            st.info(f"Routed to human review ({s.get('reason')}) · approval {(s.get('result') or {}).get('approval_id')}")


# ---------------------------------------------------------------- last moment detail
left, right = st.columns([3, 2])
with left:
    st.subheader("Network view and decision")
    last = st.session_state.get("last")
    if last:
        name, res = last
        if name == "1 Earn":
            cal = res["calibration"]
            st.write(f"Licensed: **{cal['licensed']}** · λ̂ = {cal['threshold']} · n = {cal['n']}, k = {cal['k']}, "
                     f"U = {cal['upper_bound']:.4f} ≤ α = {cal['alpha']} (δ = {cal['delta']}) · "
                     f"PREREG {cal['prereg'][:23]}…")
            st.dataframe(pd.DataFrame(cal["trace"], columns=["threshold", "n accepted", "k errors", "U", "passes"]),
                         hide_index=True, use_container_width=True)
            h = res["heldout"]
            st.write(f"Held-out: autonomy **{h['autonomy_rate']:.1%}** ({h['n_auto']}/{h['n_eligible']}), "
                     f"selective error **{h['errors']}/{h['n_auto']}**, 90% CI {tuple(round(x, 4) for x in h['ci90'])}")
        elif name == "2 Act":
            trace_card(res["auto"], "Autonomous")
            trace_card(res["human"], "Below threshold")
            ex = res["engineer_execution"]
            if ex:
                (st.success if not ex["isError"] else st.error)(
                    f"Engineer approved once → {'ALLOW ' + str(ex['policies']) if not ex['isError'] else ex['text']}")
        elif name == "3 Block":
            trace_card(res["agent"], "Agent requests 5 cells (claims 2)")
            e = res["engineer_with_approval"]
            if e:
                st.error(f"Engineer with valid approval, 5 cells → {e['text']} {e['policies']}")
            st.write(f"Simulator state changes: **{res['state_changes']}**")
        elif name == "4 Revoke":
            st.warning(f"Licence {res['revoked_jti'][:8]}… revoked")
            trace_card(res["next_call"], "Next incident")
        elif name == "5 Federation":
            rows = [{"operator": o, "licensed alone": v["licensed"], "λ alone": v["threshold"],
                     "first test n/k": f"{v['first_test']['n']}/{v['first_test']['k']}"} for o, v in res["alone"].items()]
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            p = res["pooled"]
            st.success(f"Pooled ({res['mode']}, sum verified={res['sum_correct']}): licensed={p['licensed']} "
                       f"λ̂={p['threshold']} n={p['n']} k={p['k']}")
            st.dataframe(pd.DataFrame([{"operator": o, "own autonomy": f"{v['autonomy_rate']:.1%}",
                                        "own errors": f"{v['errors']}/{v['n_auto']}",
                                        "90% CI": tuple(round(x, 3) for x in v["ci90"]) if v["ci90"] else None}
                                       for o, v in res["per_operator_heldout"].items()]),
                         hide_index=True, use_container_width=True)
            st.caption(res["claim"])
        elif name == "6 Warning":
            trace_card(res["B_attempt"], "Operator B")
            st.warning(f"Signed warning from {res['warning']['issuer']}: category {res['warning']['category']} "
                       f"({res['warning']['signal']}, reviewer-confirmed)")
            trace_card(res["A_same_category"], "Operator A, same category")
            trace_card(res["A_other_category"], "Operator A, other category")
        else:
            st.json(res)
    else:
        st.info("Press 1 · Earn to calibrate and issue the licence.")

with right:
    st.subheader("Approval queue")
    pend = d.approvals.pending()
    if pend:
        st.dataframe(pd.DataFrame([{"id": p["approval_id"], "action": p["request"]["action"],
                                    "cells": len(p["request"]["cells"]), "reason": p["request"]["reason"][:40]}
                                   for p in pend]), hide_index=True, use_container_width=True)
    else:
        st.caption("No pending approvals")
    st.subheader("α slider (exploratory)")
    alphas = d.exploratory_alphas()
    pick = st.select_slider("Target α", options=[a["alpha"] for a in alphas], value=d.alpha)
    a = next(x for x in alphas if x["alpha"] == pick)
    label = "OFFICIAL (pre-registered)" if a["official"] else "EXPLORATORY — not certified"
    if a["licensed"]:
        st.write(f"{label}: λ = {a['threshold']}, held-out autonomy {a['heldout_autonomy']:.1%}, "
                 f"error {a['heldout_error']:.2%}")
    else:
        st.write(f"{label}: not licensable — insufficient evidence")

st.subheader("Audit log (append-only; incident ids hashed)")
audit = d.store.audit_tail(30)
if audit:
    st.dataframe(pd.DataFrame([{"seq": a["seq"], "op": a["operator"], "kind": a["kind"],
                                "incident": (a.get("incident_hash") or "")[:18],
                                "detail": json.dumps({k: v for k, v in a.items() if k not in
                                                      ("seq", "ts", "operator", "kind", "incident_hash")})[:140]}
                               for a in audit]), hide_index=True, use_container_width=True)
