# Gaps: what does not work, or is not built

Declared before judging, with the unit each one limits. Run ids are in `judging.json`; a gap with "no run id"
has no declared run behind it.

## Evidence and process

| Gap | Limits | Detail |
|---|---|---|
| Built before 1 Nov | all | The engine, calibration, licence, Cedar policies and AWS stack were written 30–31 Oct 2026, before the event. The declared-run, audit and judging code was added 1 Nov |
| First live results came from a personal AWS account | all | The 31 Oct results (6/6 live attacks blocked, ALLOW and F1 DENY: `dist/attacks_live.json`, `dist/smoke_evidence.json`) ran in a personal account in us-east-1 with no run id or declaration. They are superseded by the declared runs in the team account and are not reported as results |
| Test set frozen before results, but not in Git | licence | The split hashes and the target (α = 5%, δ = 10%) were fixed in `PREREG.yaml` before calibration on 31 Oct, but the repository had no Git history then and no AWS timestamp predates the first calibration. The `licence` declaration restates the same hashes; we had seen the 31 Oct result (U = 1.19%) before writing it |
| Scores were computed once, outside the team account | licence | All 818 incidents were scored on 31 Oct by a SageMaker job in the personal account. The team-account runs reuse that score cache, tied by its fingerprint; scoring was not re-run under a run id |
| One model only | technical innovation | "Every model compared under one configuration" is not done: only `att/OTel-LLM-8.3B-Classification` is calibrated |
| Same distribution | licence | The classifier was fine-tuned on TeleLogs. We use the test split minus rows seen in train, but it is the same distribution, so the high accuracy says little about other networks |

## Track 3 scope

| Gap | Limits | Detail |
|---|---|---|
| No NLM swarm | allow, deny, trace | The "agent" is a scripted caller; the diagnosis comes from the classifier, not a language-model planner. There are no agent-to-agent calls apart from signed federation warnings between operators |
| No Bedrock Guardrails | all | No generative model is in the loop, so there is no model input or output to guard |
| Autonomous changes skip the human | allow | By design: inside a valid licence the agent acts alone (that is the barrier we remove). Outside it a person decides. The engineer's approve-and-execute path is wired only in the local console; on AWS, approvals live in one Lambda container and are not in a declared run |
| "Pause" withdraws a licence, not a model | pause | Revoking the licence refuses every autonomous call; the model itself is not unregistered |
| Trace id relies on the JSON-RPC id | trace | The interceptor takes the trace id from the request id the Gateway passes it. If the Gateway rewrites that id, the trace check fails and the run says so |

## Enforcement limits

| Gap | Limits | Detail |
|---|---|---|
| Cell limit is per incident only | deny, adversarial | At most 3 cells per incident in total, across calls and Lambdas (`aws/tool_lambda/ledger.py`, DynamoDB `al-changes`); splitting a 5-cell change into 3 + 2 is refused and is the seventh attack. There is no limit per hour or across incidents, and the count never resets except by `Reset demo` (local) or deleting the item (AWS) |
| No rate limit, no suspension on probing | adversarial | Refused calls are recorded, but repeated refusals do not suspend the licence |
| Agent sandboxing is not built | adversarial | The licence controls calls through the Gateway. Keeping the agent from going around it (no other network path, no cloud credentials) is a deployment requirement we state but did not build |
| A change can outlive a failed completion record | trace | Every call is recorded before anything changes (no record, no action). If the record written after the simulated change fails, that change has no completion record; the trace check then fails for it |
| Agent-written reasons reach the engineer | approvals | The approval screen shows the agent's own reason text next to the server's facts |

## Simulation and data

| Gap | Limits | Detail |
|---|---|---|
| Simulated network | allow, pause | Changes go to a simulator; "resolved" comes from the ground-truth label. The organisers' digital twins were not used |
| No self-learning loop | — | There is no retraining. A new model would have to earn a new licence (re-certify), and the anytime-valid monitor revokes on outcomes; both are local only, not in a declared AWS run |
| Federation is masked counts | — | Operators pool counts with pairwise masking (honest-but-curious aggregator, no dropout, no DP). Not the CrossFrame service. A pooled licence covers the federation, not each operator |
| Moment 7 drift is synthetic | — | Injected on a fresh licence with stand-in incidents |
| Hosted console uses the local engine | demo | The public console (Lightsail, personal account) runs the engine locally; it does not read the AWS records |
| Live view is local only and not a declared run | demo | The Live button appears only with `AL_LIVE=1` on the presenter's machine. Its calls are real, go through the deployed Gateway and are recorded under the run id `undeclared`, so they are not reported results. The network behind them is the simulator. Cedar leaves no record of its own: a forbid is read from the Gateway's reply and a permit is inferred from the tool running, and the panel says which. "Issue a new licence" re-runs the calibration on the same frozen data and has no declaration |
| Incident ids in AWS records | — | The AWS audit stores `TL-` ids so a judge can name an item. The local audit stores salted hashes |

## Platform blocks

| Time (UTC) | Service | Exact error | Request id | Who we told | Effect |
|---|---|---|---|---|---|
| Sun 1 Nov 2026 23:20:54 | IAM Identity Center sign-in (TIP portal, us-east-1) | The portal recognises our user but asks for a password that was never set; "Forgot password?" returns "Something doesn't compute. Access denied, check for any typos or contact your administrator." | 2fbaa491-d2ba-4903-b813-d9c3e4a84840 | Organisers, via the hackathon Slack / in the room (1 Nov) | No access to the team account yet, so the declared runs cannot run there. Rehearsed instead in a personal account (all six units passed, not reported as results) |
