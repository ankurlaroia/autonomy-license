# Data and model outputs

Every dataset and every model output this project relies on, with its source, licence and hash. No operator logs
and no customer data are used. The data files themselves are not in this repository (`state/` is git-ignored);
the hashes below let anyone who downloads the same source check they have the same items.

## TeleLogs (troubleshooting config): the only real dataset

| | |
|---|---|
| Source | Hugging Face `netop/TeleLogs`, config `troubleshooting` (paper: arXiv 2507.21974) |
| Licence | MIT (dataset card metadata). Access is gated with automatic approval: accept the terms on Hugging Face |
| What we use | The **test** split only. Rows whose question also appears in the train split are dropped, and only rows whose answer names exactly one cause are kept (`data/telelogs_parse.py`, `data/prepare_telelogs.py`) |
| Result | 818 single-cause incidents: pilot 60, calibration 450, held-out 308 (seed 20261101) |
| Frozen split hashes | pilot `sha256:4a1071b946aa6aa957b10b8050dc4df7543265a5d0de2d740621358aaa9d9967`<br>calibration `sha256:8bb67991857034e24077615fcd53caa29d2d2c937f587ad94b623a6cd83fd0cd`<br>held-out `sha256:668db0d77f79b75e26e18554f9ba3547987de704ac7d659b902fd63feebf687f` |
| Pre-registration | `state/data/PREREG.yaml`: the threshold grid, α = 0.05, δ = 0.10, the split hashes and the model fingerprint, written from the pilot scores before calibration. Its file hash is in every `licence` declaration |
| Labels | TeleLogs' own ground-truth cause (`\boxed{Cn}`), mapped to our catalogue by meaning. No model wrote or edited a label |
| Rebuild | `python data/prepare_telelogs.py --source telelogs --out state/data` (needs the Hugging Face terms accepted) |

What leaves the machine: incident ids (`TL-` + the first 12 hex characters of the SHA-256 of the question
text), cell ids, scores, predicted cause codes, whether a prediction was right, and decisions. Never the question
text, the drive-test tables or the labels themselves.

## Model outputs relied on

| | |
|---|---|
| Model | `att/OTel-LLM-8.3B-Classification` (Hugging Face), a classifier fine-tuned on TeleLogs by its authors. **Licence: read it on the model card before reuse; we could not confirm it from here** |
| Output | One softmax over the eight causes per incident; the score is the top probability (`model/scorer.py`) |
| Prompt | The fixed template in `model/scorer.py` (`prompt_template`), part of the fingerprint below |
| Where it ran | A SageMaker training job (ml.g5.2xlarge) on 31 Oct 2026, `aws/infra/score_job.py`; all 818 incidents scored once |
| Output hash | Score-cache fingerprint `sha256:fdbe90344cc65f578cc850038d33f45b8340c2ff01b1baaa4ad137d57191650f` (model id, revision, prompt and scores). The Lambdas refuse any cache with another fingerprint |
| Grader | Rule-based: the predicted code against the TeleLogs label. The model never grades itself, and no other model grades it |

No generative model output is used anywhere in a decision.

## Synthetic stand-in (tests and offline demo only)

`data/synthetic_telelogs.py` generates incidents in the same format with a seeded random generator. It drives the
unit tests and the offline console demo. Numbers from it are synthetic and are never reported as results.

## Injected drift (demo moment 7)

Synthetic: wrong outcomes are injected on a fresh licence using stand-in incidents, to show the licence revoking
itself. Real outcomes are never altered.
