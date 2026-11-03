Primary track: Track 3, Multi-Agent Swarms for Application Enablement through NLMs (evidence chain cross-cutting)

# Autonomy License — From Proof to Action

**The problem, in three lines.** Operators will not let an AI agent change a live network on its own.
Nothing today turns "this model is usually right" into a permission a risk owner can sign, check and withdraw.
And an agent that grades or vouches for itself can cheat.

**What we built.** The agent may act alone only while a statistical test on a frozen test set shows its
autonomous diagnoses are wrong at most 5% of the time (90% confidence). That evidence becomes a KMS-signed,
expiring licence. On every tool call, Cedar policy on the AgentCore Gateway checks the licence using facts the
server computes (the agent's own claims are dropped). Hard rules hold whatever the licence says, and withdrawing
the licence hands control back to people. Every decision leaves a record in DynamoDB and CloudWatch under one run
id.

**Architecture.** Agent → Cognito token → AgentCore Gateway → interceptor Lambda (drops the agent's trust fields,
writes the server's cell count, category, score and licence checks; records the request) → Cedar policy (permit
or forbid, default deny) → tool Lambda (re-checks everything, records the call before acting) → simulated
network. Licence status and warnings live in DynamoDB, so a withdrawal reaches every Lambda at once.

**One command per stage** (team account, `AWS_PROFILE=fyuz`, us-east-2):

| Stage | Command |
|---|---|
| Prepare data (frozen splits, PREREG) | `python data/prepare_telelogs.py --source telelogs --out state/data` |
| Score (SageMaker GPU, once) | `python -m aws.infra.score_job run --data state/data` |
| Calibrate, sign, deploy (unit `licence`) | `python -m aws.infra.judged_run --profile fyuz --team-code <code> --units licence` |
| Live allow, deny, attacks, trace, pause | `python -m aws.infra.judged_run --profile fyuz --team-code <code> --units allow,deny,adversarial,trace,team,lead,pause` |
| Live test (read-only) | `python tools/show_record.py --run-id <run_id> --item <TL-id>` |
| Rebuild (no AWS) | `python tools/rebuild.py` |
| A person's approval (changes state, not part of the read-only test) | `python -m aws.infra.team ask`, then `pending`, then `approve <id>` |

Each run writes `evidence/declared/<run_id>.json` to the team bucket **before** it starts (unit, target, frozen
test-set hash, model id, grader, the exact items), then its per-item outputs, records and a pass/fail record file
under `evidence/runs/<run_id>/`, mirrored in this repository. `judging.json` lists the run ids and commands;
[DATA.md](DATA.md) the data and model outputs; [GAPS.md](GAPS.md) what does not work.

**Before Nov 1.** The engine, calibration, licence, Cedar policies and the first AWS stack were built on
30–31 Oct 2026, before the event, and first run in a personal AWS account. The evidence chain (declared runs, the
append-only audit table, the live-test and rebuild tools) was added on 1 Nov, and the judged runs are in the team
account. See GAPS.md.

---

Build for the Breaking Barriers Hackathon @ FYUZ 2026, following build spec **v1.2.1**.

A network AI agent diagnoses 5G faults but may act alone only when calibration evidence bounds the
error rate of the diagnoses it would act on. The permission is a signed, expiring licence; Cedar
policies enforce it on every tool call; hard rules hold whatever the licence says; revocation sends
control back to humans.

> **Reported results: declared runs in the team account (`team11`, us-east-2, 2–3 Nov 2026).** All eight units
> pass; run ids and values are in `judging.json`. Upper bound on wrong autonomous diagnoses 1.19% against a 5% target;
> 10 of 10 licensed changes applied; 10 of 10 oversized changes refused with no change; 7 of 7 attacks blocked; 5 of 5
> traces complete; 16 of 16 team steps as declared; 3 of 3 model-led cases governed; 11 of 11 calls refused after the
> licence and models were withdrawn. The network is simulated. Limits are in [GAPS.md](GAPS.md).
>
> **First results (31 Oct 2026, personal account, superseded by the runs above).** 818 single-cause TeleLogs test incidents scored by
> att/OTel-LLM-8.3B-Classification on a SageMaker GPU; PREREG written from the 60 pilot scores before calibration
> (`sha256:a6a487c7…`, the id inside the licence); calibration licensed λ̂ = 0.70 with n = 446 accepted, k = 2 wrong, U = 1.19% ≤ α = 5%
> (δ = 10%); held-out 308: autonomy 99.0% (305), 3 wrong, selective error 0.98% (90% CI 0.27–2.52%).
> The licence is signed by KMS (`alias/al-licence-issuer`) and deployed; live Gateway in ENFORCE: 2-cell ALLOW,
> 5-cell DENY by Cedar F1, and 6/6 live attacks blocked (`dist/smoke_evidence.json`, `dist/attacks_live.json`).
> The synthetic stand-in (`state/data.synthetic`) still drives the offline demos and tests; numbers from it are
> synthetic.

## Run it

```bash
pip install -r requirements.txt
python scripts/demo.py              # all seven demo moments in the terminal
python scripts/attacks.py           # P2: 8 attack scenarios, each must say BLOCKED with no state change
python -m aws.infra.attacks_live    # P2: 7 attacks as real calls to the deployed Gateway
cd web && npm run dev               # operations console (Next.js); console/app.py is the Streamlit fallback
AL_LIVE=1 python -m uvicorn api.server:app --port 8000   # adds the Live button: real AWS calls, this machine only
pytest                              # release checklist + AWS request checks
```

## What is built

| Path step | Module | Status |
|---|---|---|
| TeleLogs parsing (cause codes mapped by meaning), train-overlap / single-cause filter | `data/telelogs_parse.py`, `data/prepare_telelogs.py` | **Run on TeleLogs 31 Oct**: 818 incidents (pilot 60, calibration 450, held-out 308) |
| Scorer + trusted score cache, pilot check | `model/scorer.py`, `model/score_cache.py` | **Run 31 Oct** on SageMaker: pilot 20/20 correct; all 818 scored |
| Fixed-sequence Clopper–Pearson calibration, PREREG | `calibration/` | Tested; a PREREG from another model is moved aside |
| Licence issue / verify (ES256), KMS signer | `license/` | **Live licence signed by KMS 31 Oct** |
| Path A tags: Cognito V3_0 pre-token Lambda | `aws/pretoken/` | Tested offline |
| Path C interceptor + HMAC caller attestation | `aws/interceptor/`, `aws/caller.py` | Tested offline against the documented event shape |
| Cedar policies, strict schema validation | `aws/cedar/` | Validated locally with the same strict rules AgentCore applies |
| Path B tool Lambda, shared DynamoDB registry | `aws/tool_lambda/`, `license/registry_ddb.py` | Tested offline |
| AWS deploy (IAM, DynamoDB, Lambda, Cognito, Policy, Gateway) + smoke client | `aws/infra/` | **Applied live 31 Oct**; redeployed with the real KMS licence; ALLOW + F1 DENY in ENFORCE (`dist/smoke_evidence.json`) |
| GPU scoring as a SageMaker training job (ml.g5.2xlarge, on-demand; spot quota is 0) | `aws/infra/score_job.py`, `aws/scoring/` | **Run 31 Oct**: pilot 616 s, full 1014 s billed (about $0.70); a first try on ml.g5.xlarge ran out of RAM |
| Self-revoking licence: anytime-valid e-process on autonomous outcomes | `license/monitor.py`, moment 7 | Tested; false revocation <= delta at any stopping time (Ville); drift demo is synthetic |
| P1 federation (masking) and signed warnings, local and DynamoDB | `federation/`, `deploy warn` | Tested |
| P2 attack scorecard, local and live | `scripts/attacks.py`, `aws/infra/attacks_live.py` | 8/8 local; **7/7 live in the declared `adversarial` run** (team account), including the split-change attack |
| Console | `web/` (Next.js), `console/app.py` | Works locally |

Not built (by decision): Strands planner, IoT, offline edge authority, a second model, real network control.

## Pausing the stack

The stack stays deployed but **paused** (`python -m aws.infra.pause pause`: every Lambda throttled to 0, so nothing
runs or bills; the KMS key still costs about $1/month). Before a live demo: `pause resume`, then rebuild the expired
licence: `stub_bundle --data state/data --kms-key alias/al-licence-issuer` → `package` → `deploy apply`. The console's
Help page has the step-by-step guide and architecture diagrams.

## Honest limits (say them on stage)

- The classifier was fine-tuned on TeleLogs. We use only the test split and drop rows whose text also appears in
  train, but it is the same distribution, so the high accuracy is expected and says little about other networks.
- The bound covers **wrong autonomous diagnoses** for the filtered single-cause population, not action safety.
- Simulator "resolved" is decided from the ground-truth label: it shows enforcement, not remediation efficacy.
- Pooled (P1) licences are federation-level; per-operator results are measurements, not guarantees.
- Pairwise masking: honest-but-curious aggregator, no collusion, no dropout, honest counts. No DP.
- The self-revoking monitor tests the same quantity as the licence (wrong autonomous diagnoses), using
  ground-truth outcomes from the trusted side. Its guarantee is on false revocations; how fast it catches drift
  depends on the drift, and a long clean history slows it (the wealth has to recover first).
- Never commit TeleLogs data or keys. `state/` is git-ignored.
