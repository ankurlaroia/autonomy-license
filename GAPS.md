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
| One model only | technical innovation | "Every model compared under one configuration" is not done: only `att/OTel-LLM-8.3B-Classification` is calibrated. The specialist's Nova Lite writes notes and decides nothing, so it is not calibrated |
| Same distribution | licence | The classifier was fine-tuned on TeleLogs. We use the test split minus rows seen in train, but it is the same distribution, so the high accuracy says little about other networks |

## Track 3 scope

| Gap | Limits | Detail |
|---|---|---|
| A small team, and the planner has little real choice | allow, deny, trace, team, lead | The `lead` unit asks a model (Amazon Nova Lite) to name each step, but the diagnosis still comes from the classifier, and every argument comes from server facts. Nova Lite did not reliably follow a free-form plan in rehearsal: it repeated finished steps. So the server now lists the open steps, the model is told to name the first, and a case ends without asking once a change is applied or queued. Any other answer ends the case with no change. The units `allow`, `deny` and `trace` still use a scripted caller. The one agent-to-agent call is the tool `ask_agent`: it goes through the Gateway, and Cedar lets only the lead make it. The specialist runs inside the tool Lambda and answers with a note (Amazon Nova Lite). It has its own Cognito identity, used to read incidents and to show its other calls refused, but it is not a separate service and makes no onward calls |
| Guardrails cover the specialist's model only | team | Bedrock `ApplyGuardrail` checks the specialist's input and output and fails closed. The classifier's scores are a cache, so no model runs at decision time. There are two layers: Cedar `when guardrails` rules at the Gateway (P4g for the task, G1 for the reply), then `ApplyGuardrail` in the tool Lambda. A rehearsal showed P4g denying a prompt attack; G1 was accepted by the service, but no rehearsal has produced a harmful reply, so G1 has never fired. The local Cedar parser cannot read these rules, so offline tests decide on the plain P4. The prompt-attack check gives false positives: it denied the planner task "act_under_licence: DENY. Which step is next?", so we reworded that task, and an unusual but honest task can be refused. A blocked output and an unavailable guardrail are covered only by tests with fakes |
| Autonomous changes skip the human | allow | By design: inside a valid licence the agent acts alone (that is the barrier we remove). Outside it, a person decides |
| The engineer is a role, not a named person | team | Approvals on AWS are shared in DynamoDB and decided through the Gateway (`decide_approval`). The approver recorded is the verified role `noc-engineer`, from a machine-to-machine Cognito client, so a record cannot say which person decided. In the `team` unit a script drives the engineer's steps, which shows the checks, not human judgement. A person can decide with `python -m aws.infra.team approve <id>`, or with Approve and Deny in the console's Live view, which runs only on the machine with the AWS sign-in. The public console has no such buttons |
| An approval can be spent with no change | team | If the simulator fails after an approval is spent, the approval and the claimed cells stay used and nothing changes (fail closed). A new request is needed, and only for cells still under the limit. That failure leaves a `tool_call` record and an error reply, but no `tool_refused` record |
| Withdrawing a model is a status flag | pause | The `pause` unit withdraws the licence and the models. The status lives in DynamoDB, the interceptor reads it, and Cedar rule F4 refuses a call to a withdrawn model, as the tool also does; an unreadable status counts as withdrawn. The models stay deployed, and the classifier's scores are a cache, so withdrawing the classifier stops autonomous changes rather than a running model. The unit restores the models at its end and leaves the licence withdrawn |
| Trace id relies on the JSON-RPC id | trace | The interceptor takes the trace id from the request id the Gateway passes it. If the Gateway rewrites that id, the trace check fails and the run says so |

## Enforcement limits

| Gap | Limits | Detail |
|---|---|---|
| Cell limit is per incident only | deny, adversarial | At most 3 cells per incident in total, across calls and Lambdas (`aws/tool_lambda/ledger.py`, DynamoDB `al-changes`); splitting a 5-cell change into 3 + 2 is refused and is the seventh attack. There is no limit per hour or across incidents, and the count never resets except by `Reset demo` (local) or deleting the item (AWS) |
| No rate limit, no suspension on probing | adversarial | Refused calls are recorded, but repeated refusals do not suspend the licence |
| Agent sandboxing is not built | adversarial | The licence controls calls through the Gateway. Keeping the agent from going around it (no other network path, no cloud credentials) is a deployment requirement we state but did not build |
| A change can outlive a failed completion record | trace | Every call is recorded before anything changes (no record, no action). If the record written after the simulated change fails, that change has no completion record; the trace check then fails for it |
| Agent-written reasons reach the engineer | approvals | The approval screen shows the agent's own reason text next to the server's facts. On AWS the reason is the specialist's note, which is model text and can mislead: in a rehearsal it said "affecting five cells" (the incident's total) for a change naming two. Nothing parses the note, and the approval binds to the exact action and cells |

## Simulation and data

| Gap | Limits | Detail |
|---|---|---|
| Simulated network | allow, pause, team | Changes go to a simulator; "resolved" comes from the ground-truth label. A cell parameter that is empty or absent in the data counts as 0. The organisers' digital twins were not used |
| No self-learning loop | — | There is no retraining. A new model would have to earn a new licence (re-certify), and the anytime-valid monitor revokes on outcomes; both are local only, not in a declared AWS run |
| Federation is masked counts | — | Operators pool counts with pairwise masking (honest-but-curious aggregator, no dropout, no DP). Not the CrossFrame service. A pooled licence covers the federation, not each operator |
| Moment 7 drift is synthetic | — | Injected on a fresh licence with stand-in incidents |
| Hosted console uses the local engine | demo | The public console (Lightsail, personal account) runs the engine locally; it does not read the AWS records |
| Live view is local only and not a declared run | demo | The Live button appears only with `AL_LIVE=1` on the presenter's machine. Its calls are real, go through the deployed Gateway and are recorded under the run id `undeclared`, so they are not reported results. The network behind them is the simulator. Cedar leaves no record of its own: a forbid is read from the Gateway's reply and a permit is inferred from the tool running, and the panel says which. "Issue a new licence" re-runs the calibration on the same frozen data and has no declaration |
| Incident ids in AWS records | — | The AWS audit stores `TL-` ids so a judge can name an item. The local audit stores salted hashes |

## Platform blocks

| Time (UTC) | Service | Exact error | Request id | Who we told | Effect |
|---|---|---|---|---|---|
| Sun 1 Nov 2026 23:20:54 | IAM Identity Center sign-in (TIP portal, us-east-1) | The portal recognises our user but asks for a password that was never set; "Forgot password?" returns "Something doesn't compute. Access denied, check for any typos or contact your administrator." | 2fbaa491-d2ba-4903-b813-d9c3e4a84840 | Organisers, via the hackathon Slack / in the room (1 Nov) | No access to the team account yet, so the declared runs cannot run there. Rehearsed instead in a personal account (all six units passed, and on 2 Nov the `team` unit passed 16 of 16 steps; not reported as results). The team account's permissions boundary and Bedrock access for the guardrail and model are untested |
