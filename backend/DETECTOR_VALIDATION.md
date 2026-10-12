# Detector validation (prototype)

## Result

The current offline detectors are **not ready to support consequential decisions**. A separate, hand-written challenge set of 20 prompts (10 benign, 10 malicious) exposed substantial generalization problems.

| Detector / dataset | Accuracy | Benign recall | Malicious recall | False positives |
|---|---:|---:|---:|---:|
| TF-IDF/logistic regression, random holdout from bundled synthetic CSV (40 prompts) | 95% | 90% | 100% | 2 / 20 benign |
| TF-IDF/logistic regression, hand-written challenge set (20 prompts) | 55% | 10% | 100% | 9 / 10 benign |
| Rule detector, hand-written challenge set (20 prompts; any rule match = positive) | 55% | 70% | 40% | 3 / 10 benign |

Reproduce with `python evaluate_detector.py` from `backend/`. The script trains the classifier only on the CSV training split before scoring either holdout. It reports confusion matrices and class-level precision/recall/F1.

## Interpretation and limits

The 95% score is misleading for deployment: the CSV has only 200 synthetic examples, and the random split puts closely related examples on both sides. The separately written prompts use paraphrases, quoted attack language, and benign security discussion. The ML model flags most benign challenge prompts as malicious; the rules miss most malicious challenge prompts and also flag benign quoted text.

The challenge set is small and hand-written, so its metrics are not a population estimate either. No Gemini or end-to-end hybrid evaluation was possible in this offline run. Existing Gemini tests require external API access and failed with connection errors here. The reported hybrid score and confidence are not calibrated probabilities.

## Readiness decision

Keep the dashboard in demonstration mode. Do not use ALLOW/SANITIZE/BLOCK to gate production requests or treat SANITIZE as an implemented sanitization action. Before reconsidering, build a larger independently labeled dataset representative of intended use, split it by source/template (not random rows), evaluate false-positive and false-negative costs, test adversarial paraphrases and benign quoted discussions, calibrate thresholds, and assess the complete hybrid pipeline with a documented Gemini model/version and repeatable fixtures.
