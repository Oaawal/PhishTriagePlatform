# Collecting data to train PhishTriage's own model

The goal is a model trained on real Nigerian scam and normal messages, used
alongside the rules engine. This needs labelled examples, collected with
consent and without personal details.

## How messages are collected (opt-in only)

| Where | What the user does | What is stored |
|---|---|---|
| App, after a scan | Answers "Was this right?" | The answer and the engine's verdict. **No text** |
| App, after a scan | Also ticks "Share this message anonymously" | The redacted message, plus the answer |
| App, report a number or account | Ticks "Allow anonymous use of the message" | The redacted message, labelled *scam* once a moderator approves the report |
| WhatsApp bot | Replies **SCAM** or **SAFE** after a verdict | The redacted message and the answer. The sender's number is not stored |

Redaction (`engine.redact_for_training`) replaces phone numbers, account
numbers, 11-digit BVN/NIN, card numbers, emails and one-time codes with
`<PHONE>`, `<ACCOUNT>`, `<ID>`, `<CARD>`, `<EMAIL>`, `<CODE>`. Names and other
free text can remain, which is why every shared message is reviewed.

Set `TRAINING_COLLECTION=false` on the server to switch collection off.

## Review (analyst console > Training data)

For each shared message: **Scam**, **Safe** or **Discard**. Discard anything
that still contains a name, address or other personal detail, or that is not a
real message. Only moderator-labelled samples are exported for training.

The tab also shows how often the engine agreed with users' answers, and how
many scams it missed and false alarms it raised. Use the missed scams to add
rules.

## Train and evaluate

```bash
cd PhishTriagePlatform
pip install -r requirements-train.txt
ADMIN_API_KEY=<key> python scripts/train_model.py --api https://phishtriageplatform.onrender.com
```

This writes `models/scam_model.joblib` and `models/metrics.json`, comparing:
- the trained model alone
- the rules engine alone
- the two combined (flag if either flags)

## When to use the model in the app

Only when, on 1,000+ reviewed samples with plenty of both scam and safe:
- the combined result catches clearly more scams than the rules alone, and
- false alarms stay low (under about 5%).

Then the model can be added to the API as one more signal, like the Safe
Browsing check.
