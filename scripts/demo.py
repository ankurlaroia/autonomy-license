"""Run the full local demo end to end and print each moment.

  python scripts/demo.py            # P0 moments 1-4, P1 moments 5-6, then 7 (self-revoking licence)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")   # λ̂, ≤, δ: Windows consoles default to cp1252
from demo.engine import Demo  # noqa: E402


def show(title, obj):
    print(f"\n=== {title} ===")
    print(json.dumps(obj, indent=1, default=str)[:4000])


def step_line(t):
    s = [f"{st['call']}: " + ("DENY " + str((st.get('policy') or {}).get('policies')) + " " + (st.get('text') or '')
                               if st.get("isError") else "ok") for st in t["steps"]]
    return (f"{t['incident_id']} cat={t['category']} pred={t['pred']} score={t['score']:.3f} "
            f"λ̂={t['threshold']} action={t['action']} cells={len(t['cells'])} -> {t['outcome']} | " + "; ".join(s))


if __name__ == "__main__":
    data = sys.argv[sys.argv.index("--data") + 1] if "--data" in sys.argv else None
    d = Demo(data_dir=data, fresh=True)
    m1 = d.moment1_earn()
    c = m1["calibration"]
    if not c["licensed"]:   # an honest outcome on real data: no threshold meets alpha, so everything stays with humans
        print(f"\n[1 EARN] licensed=False: no threshold in the preregistered grid has U <= α={c['alpha']} "
              f"(δ={c['delta']}); every incident goes to an engineer")
        sys.exit(0)
    print(f"\n[1 EARN] licensed={c['licensed']} λ̂={c['threshold']} n={c['n']} k={c['k']} "
          f"U={c['upper_bound']:.4f} ≤ α={c['alpha']} (δ={c['delta']}); prereg {c['prereg'][:19]}…")
    h = m1["heldout"]
    print(f"         held-out: autonomy {h['autonomy_rate']:.1%} ({h['n_auto']}/{h['n_eligible']}), "
          f"selective error {h['errors']}/{h['n_auto']}, 90% CI {tuple(round(x, 4) for x in h['ci90'])}")
    m2 = d.moment2_act()
    print("\n[2 ACT]   " + step_line(m2["auto"]))
    r = m2["auto"]["steps"][0].get("result") or {}
    for cid in r.get("before", {}):
        changed = {k: (v, r["after"][cid][k]) for k, v in r["before"][cid].items() if r["after"][cid].get(k) != v}
        print(f"          {cid}: " + ", ".join(f"{k} {a} -> {b}" for k, (a, b) in changed.items()))
    print("          " + step_line(m2["human"]))
    print(f"          engineer approves once -> {m2['engineer_execution']}")
    m3 = d.moment3_block()
    print("\n[3 BLOCK] " + step_line(m3["agent"]))
    print(f"          engineer with approval, 5 cells -> {m3['engineer_with_approval']['text']} "
          f"{m3['engineer_with_approval']['policies']}; state changes: {m3['state_changes']}")
    m4 = d.moment4_revoke()
    print(f"\n[4 REVOKE] jti {m4['revoked_jti'][:8]}… revoked -> " + step_line(m4["next_call"]))
    d.reinstate()
    m5 = d.moment5_federation()
    print("\n[5 FEDERATION] (P1) masked sum correct:", m5["sum_correct"])
    for o, v in m5["alone"].items():
        ft = v["first_test"]
        print(f"          {o} alone: licensed={v['licensed']} λ={v['threshold']} "
              f"(first test λ={ft['threshold']}: n={ft['n']} k={ft['k']} U={ft['U']})")
    p = m5["pooled"]
    print(f"          pooled: licensed={p['licensed']} λ̂={p['threshold']} n={p['n']} k={p['k']} U={p['upper_bound']}")
    for o, v in m5["per_operator_heldout"].items():
        print(f"          {o} own held-out: autonomy {v['autonomy_rate']:.1%}, errors {v['errors']}/{v['n_auto']}")
    m6 = d.moment6_warning()
    print("\n[6 WARNING] (P1) B: " + step_line(m6["B_attempt"]))
    print(f"          warning {m6['warning']}")
    print("          A same category:  " + step_line(m6["A_same_category"]))
    print("          A other category: " + step_line(m6["A_other_category"]))
    m7 = d.moment7_self_revoke()
    a, b = m7["in_distribution"], m7["synthetic_drift"]
    print(f"\n[7 SELF-REVOKE] anytime-valid test, revoke when E >= {m7['revoke_at_e']:.0f} (alpha={m7['alpha']}, delta={m7['delta']})")
    print(f"          in distribution, licence {a['jti'][:8]}: {a['errors']}/{a['outcomes']} wrong, peak E {a['peak_e']} -> {a['status']}")
    print(f"          fresh licence {m7['jti'][:8]}, SYNTHETIC drift from its first action "
          f"(+{b['score_offset']} score offset, {b['incidents']}): {b['errors']}/{b['outcomes']} wrong, "
          f"peak E {b['peak_e']} -> " + (f"revoked after {b['revoked_after']} outcomes" if b["revoked_after"]
                                         else f"still {m7['status']}"))
    print("          next call: " + step_line(m7["next_call"]))
