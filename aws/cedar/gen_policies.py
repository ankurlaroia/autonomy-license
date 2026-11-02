"""Generate the AgentCore Policy (Cedar) set for the NetOps gateway (spec 10.4, v1.2.1).

AgentCore facts the policies rely on (spec 10.2): OAuth callers are AgentCore::OAuthUser; JWT
claims become string tags (hasTag/getTag); only context.input (tool arguments) is available;
action names are <Target>___<tool>; forbid wins; default deny.

v1.2.1: the request interceptor OVERWRITES cell_count, category, score_ok and licence_ok in
context.input with server-computed values, so Cedar acts on trusted values, not agent claims.
  score_ok   = trusted cached score >= licence threshold
  licence_ok = licence re-verified against the live registry (status, cfg, scope, warnings)

Usage: python -m aws.cedar.gen_policies --gateway-arn <ARN> > aws/cedar/netops.cedar
"""
from __future__ import annotations

import argparse

from common.catalogue import AUTO_ACTIONS, BLAST_RADIUS, CATEGORIES, NEVER_AUTONOMOUS

TARGET = "NetOps"


def _list(xs):
    return "[" + ", ".join(f'"{x}"' for x in xs) + "]"


# Optional in the tool schema (the interceptor adds them), so AgentCore's validator requires a `has`
# guard before each read. Missing -> the permit cannot match -> default deny.
TRUST_FIELDS = ("category", "cell_count", "score_ok", "licence_ok")


def _has(fields):
    return " && ".join(f"context.input has {f}" for f in fields)


def policies(gateway: str = "GW") -> str:
    R = f'AgentCore::Gateway::"{gateway}"'
    A = lambda t: f'AgentCore::Action::"{TARGET}___{t}"'  # noqa: E731
    out = [f"""// P1  agent and engineers may read incidents and request approval
permit(principal is AgentCore::OAuthUser,
       action in [{A("get_incident")}, {A("request_human_approval")}],
       resource == {R})
when {{ principal.hasTag("role") &&
       (principal.getTag("role") == "netops-agent" || principal.getTag("role") == "noc-engineer") }};
"""]
    for k in CATEGORIES:
        out.append(f"""// P2{k}  licensed autonomous remediation in category {k}
permit(principal is AgentCore::OAuthUser,
       action == {A("apply_remediation")},
       resource == {R})
when {{
  principal.hasTag("role")      && principal.getTag("role") == "netops-agent" &&
  principal.hasTag("lic_state") && principal.getTag("lic_state") == "active" &&
  principal.hasTag("lic_cats")  && principal.getTag("lic_cats") like "*|{k}|*" &&
  context.input.mode == "autonomous" &&
  {_has(TRUST_FIELDS)} &&
  context.input.category == "{k}" &&
  context.input.licence_ok == true && context.input.score_ok == true &&
  context.input.cell_count <= {BLAST_RADIUS} &&
  {_list(AUTO_ACTIONS)}.contains(context.input.action)
}};
""")
    out.append(f"""// P3  a human engineer executes an approved change (approval verified by the tool Lambda)
permit(principal is AgentCore::OAuthUser,
       action == {A("apply_remediation")},
       resource == {R})
when {{ principal.hasTag("role") && principal.getTag("role") == "noc-engineer" &&
       context.input.mode == "approved" && context.input has approval_id }};

// F1  hard rule: blast radius, absolute (engineers included). cell_count is server-computed.
forbid(principal is AgentCore::OAuthUser,
       action == {A("apply_remediation")},
       resource == {R})
when {{ context.input has cell_count && context.input.cell_count > {BLAST_RADIUS} }};

// F1m a call without the server-computed cell_count (interceptor did not run) is refused (fail closed)
forbid(principal is AgentCore::OAuthUser,
       action == {A("apply_remediation")},
       resource == {R})
unless {{ context.input has cell_count }};

// F2  hard rule: never-autonomous actions
forbid(principal is AgentCore::OAuthUser,
       action == {A("apply_remediation")},
       resource == {R})
when {{ {_list(NEVER_AUTONOMOUS)}.contains(context.input.action) && context.input.mode == "autonomous" }};
""")
    for k in CATEGORIES:
        out.append(f"""// F3{k}  (P1) warned category: belt and braces with lic_cats
forbid(principal is AgentCore::OAuthUser,
       action == {A("apply_remediation")},
       resource == {R})
when {{ context.input.mode == "autonomous" &&
       context.input has category && context.input.category == "{k}" &&
       principal.hasTag("warned") && principal.getTag("warned") like "*|{k}|*" }};
""")
    return "\n".join(out)


def policy_names() -> list[str]:
    """Names in the order cedarpy assigns ids policy0, policy1, ..."""
    return ["P1"] + [f"P2{k}" for k in CATEGORIES] + ["P3", "F1", "F1m", "F2"] + [f"F3{k}" for k in CATEGORIES]


def policy_statements(gateway: str = "GW") -> list[tuple[str, str]]:
    """(name, statement) pairs, one per AgentCore policy, in policy_names() order. Each statement keeps
    its comment, so the console shows why the rule exists."""
    import re
    text = policies(gateway)
    starts = [m.start() for m in re.finditer(r"^// (\S+)", text, flags=re.M)]
    blocks = [text[a:b].strip() for a, b in zip(starts, starts[1:] + [len(text)])]
    names = [re.match(r"// (\S+)", b).group(1) for b in blocks]
    assert names == policy_names(), names
    return list(zip(names, blocks))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway-arn", default="GW")
    print(policies(ap.parse_args().gateway_arn))
