# NTK Phase 6B - Operational milestone

Date: 2026-10-22

## System

Java SAST combining OpenGrep, CodeQL, IRIS Stage 3,
local fine-tuned LoRA and SAST V2.2.

Research scope: CWE-22, CWE-78, CWE-79, CWE-89.

## Verified operational result

Project: Apache Shiro (shiro-main.zip)

Job: fp6b_56407aa94e8ef12966fa

- Java files: 855
- OpenGrep findings: 1
- CodeQL findings: 65
- Total findings: 66
- Native inference requests: 4
- Accepted sink labels: 2
- Abstain: 2
- Exact model-dataflow links: 0
- Four report hashes: PASS
- Operational blockers: 0
- Closeout warnings: 2

Result manifest SHA256:
c789a8aeda26a8409669e7a1342e7fbfed0d39f2ca6ac21419b933c4c8f4b748

## Training baseline

- Qwen2.5-Coder-0.5B-Instruct
- LoRA Epoch 1 / Epoch 2
- Training dataset: 950 weak/silver samples
- Validation dataset: 137 weak samples

These datasets are not independently reviewed gold data.

## Scientific limitations

- Accepted AI labels are not confirmed vulnerabilities.
- Exact AI-dataflow links are not exploit confirmations.
- Shiro had no exact model-dataflow links.
- Eighteen HIGH findings contain wording that can
  incorrectly imply vulnerability confirmation.
- SAST scores are review priorities, not exploit probabilities.
- CodeQL no-build analysis may have coverage limitations.

## Next development

1. Audit provenance, leakage, API identities and labels.
2. Improve CWE-78 and CWE-79 sink coverage.
3. Freeze an independent evaluation benchmark.
4. Fine-tune and compare local models.
5. Evaluate experimental scoring against frozen SAST V2.2.
6. Integrate and test on the laptop.

Do not overwrite historical frozen artifacts.
Do not publish private research archives or model weights.
