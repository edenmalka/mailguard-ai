# MailGuard Demo Runbook

How to demonstrate MailGuard live, with fallbacks. Total time: about 10–15 minutes.

## 1. Preflight (the day before, and again 15 minutes before)

| Check | How | Expected |
|---|---|---|
| Backend is up and warm | `curl -s https://<your-service-url>/health` | `{"status":"ok"}` (the first call after idle may take ~3 s: Cloud Run scales to zero) |
| Add-on runs the latest code | Apps Script → `Code.gs` matches [`addon/Code.gs`](../addon/Code.gs) | Normal emails show **"Low risk"** (not "Safe") |
| Live demo emails are in your inbox | Section 3 | Two emails from your second account |
| Offline fallback works | `cd backend && uv run python -m app.cli ../demo/*.eml` | Seven reports, no network needed |
| Nothing sensitive on screen | Close Apps Script **Project Settings** (Script Properties hold the HMAC secret), terminals with secrets, unrelated mail | — |

## 2. Demo flow

1. **Architecture (2 min).** Use the README diagram: thin add-on → HMAC-signed request → Cloud Run → parse once → analyzers → scoring → card. Mention that the email is never stored and links are never visited.
2. **Low risk (1 min).** Open a real newsletter. Point out the authentication line: *reported by Gmail, not re-checked by MailGuard*.
3. **Credential phishing, live (2 min).** Open demo email **A** (section 3). Show "Looks like: Credential phishing", the **What to do** advice, the **Why** rows adding up to the score, and the defanged evidence under **Technical details**.
4. **Payment fraud, live (1 min).** Open demo email **B**. Show that no technical trick is present: the pattern comes from a free webmail sender **plus** a money request.
5. **What Gmail will not deliver, offline (2 min).** Gmail blocks executable attachments, and a second Gmail account cannot fail DMARC. Show these with the offline analyzer, which runs the same pipeline:
   ```bash
   cd backend
   uv run python -m app.cli ../demo/04_malware_delivery.eml ../demo/05_sender_spoofing.eml ../demo/07_inconclusive_archive.eml ../demo/08_credential_theft_by_reply.eml
   ```
6. **Trade-offs and limitations (3–5 min).** See section 4.

## 3. Sending the live demo emails (from a second Gmail account)

Use Gmail's **Insert link** button to set the link text and address separately. Do not click the links: they use reserved `.example` domains that lead nowhere.

| Email | Sender name (Settings → Accounts → *Send mail as* → edit info) | Body | Expected card |
|---|---|---|---|
| **A** | `PayPal Support` | "Please verify your account within 24 hours." plus a link with text `www.paypal.com` and address `https://paypa1-login.example/` | **Malicious**, credential phishing |
| **B** | your normal name | "Are you available? I need a favor. Buy gift cards for a client and keep this confidential." | **Suspicious**, payment fraud |

Change the sender name back afterwards.

## 4. Talking points

- **Why a thin add-on:** detection logic in Python is testable (500+ tests); Apps Script only reads the opened message, signs the request, validates the response and renders it.
- **Trust model:** authentication results are *reported* by Gmail (only the topmost `Authentication-Results` header from `mx.google.com` is trusted; forged ones are ignored), never claimed as verified by MailGuard.
- **Explainable scoring:** category budgets stop correlated evidence from stacking; attack patterns reward *independent* evidence; the card's points always add up to the score.
- **Learning from an unseen test:** a live Gmail test exposed a real gap (an email asking for a password and verification code *by reply* scored 0). The fix detects explicit requests to send a secret, measured on three fresh held-out rounds with every problem disclosed.
- **Honesty over confidence:** incomplete analysis is "Inconclusive", never "Safe"; wording alone can never make an email Suspicious.
- **Anti-overfitting:** every analyzer was checked against held-out cases written before running; the scoring was calibrated on a development set and measured once on a separate held-out set.
- **Limitations:** synthetic calibration data, English-only wording rules, no image/QR analysis, no reputation lookups or link following (deliberate: privacy and SSRF).
- **With more time:** a real labeled email corpus for calibration, reputation lookups by hash, DKIM re-verification, an opt-in language-model classifier for wording.

## 5. Fallbacks

| Problem | Fallback |
|---|---|
| No internet or Gmail is slow | Offline analyzer on `demo/*.eml` (section 2, step 5) |
| Card shows "could not authenticate" | The add-on's `HMAC_SECRET` does not match the backend's secret version; show the offline analyzer and explain the HMAC design |
| Card shows "unexpected response" | The add-on code is outdated; re-paste `addon/Code.gs` |
