# MailGuard AI

A Gmail Add-on that analyzes an opened email and shows a **maliciousness score**, a clear
**verdict**, and the **reasoning** behind it.

> Status: work in progress. Sections marked _TBD_ will be completed as the project is built.

## Overview

_TBD — what the add-on does and what the user sees._

## Architecture

```
Gmail (opened email)
   │  contextual trigger
   ▼
Apps Script Add-on (thin client, CardService UI)
   │  raw message + HMAC-signed request over HTTPS
   ▼
FastAPI backend (Google Cloud Run)
   ├─ Parser       – safe MIME parsing with size limits
   ├─ Analyzers    – authentication, sender identity, links, attachments, content
   └─ Scoring      – weighted signals → score (0–100), verdict, ranked reasons
```

_TBD — design decisions and data flow in detail._

## Detection Signals

_TBD_

## Security Design

_TBD — threat model, handling of untrusted input, secrets, and private data._

## Repository Layout

```
backend/   FastAPI service (Python) – analysis and scoring
addon/     Gmail Add-on (Google Apps Script) – added in a later step
docs/      Assignment brief and supporting material
```

## Running Locally

Requirements: [uv](https://docs.astral.sh/uv/) (installs the right Python version automatically).

```bash
cd backend
uv sync                 # create .venv and install dependencies
uv run pytest           # run tests
uv run ruff check .     # lint (includes security checks)

cp .env.example .env    # then set MAILGUARD_HMAC_SECRET (32+ characters)
uv run uvicorn app.main:create_app --factory --reload
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness check |
| `POST /analyze` | HMAC signature | Body: `{"raw_message": "<base64url RFC 822 email>"}` |

## Deployment

The backend runs on **Google Cloud Run**; the add-on runs on **Google Apps Script**.
Replace `PROJECT_ID`, `PROJECT_NUMBER`, and `REGION` with your own values
(this project uses `europe-west1`).

### 1. One-time Google Cloud setup

```bash
gcloud auth login
gcloud config set project PROJECT_ID

# Only the APIs this project needs.
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com

# Shared HMAC secret: generated and piped straight into Secret Manager, never printed.
python3 -c "import secrets,sys; sys.stdout.write(secrets.token_urlsafe(32))" \
  | gcloud secrets create mailguard-hmac-secret --replication-policy=automatic --data-file=-
```

### 2. Least-privilege service accounts

| Account | Used for | Permissions |
|---|---|---|
| `mailguard-backend` | Running the service | Secret Accessor on `mailguard-hmac-secret` only |
| `mailguard-builder` | Building the image | Object Viewer on the source bucket, Artifact Registry Writer on the image repo, Logs Writer |

The default compute service account is not used and holds no roles.

```bash
P=PROJECT_ID
gcloud iam service-accounts create mailguard-backend
gcloud iam service-accounts create mailguard-builder

gcloud secrets add-iam-policy-binding mailguard-hmac-secret \
  --member=serviceAccount:mailguard-backend@$P.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor

# The source bucket and image repo are created by the first `gcloud run deploy --source`.
gcloud storage buckets add-iam-policy-binding gs://run-sources-$P-REGION \
  --member=serviceAccount:mailguard-builder@$P.iam.gserviceaccount.com --role=roles/storage.objectViewer
gcloud artifacts repositories add-iam-policy-binding cloud-run-source-deploy --location=REGION \
  --member=serviceAccount:mailguard-builder@$P.iam.gserviceaccount.com --role=roles/artifactregistry.writer
gcloud projects add-iam-policy-binding $P \
  --member=serviceAccount:mailguard-builder@$P.iam.gserviceaccount.com --role=roles/logging.logWriter
```

### 3. Deploy the backend

```bash
gcloud run deploy mailguard-backend \
  --source backend --region REGION \
  --build-service-account projects/$P/serviceAccounts/mailguard-builder@$P.iam.gserviceaccount.com \
  --service-account mailguard-backend@$P.iam.gserviceaccount.com \
  --allow-unauthenticated \
  --set-secrets MAILGUARD_HMAC_SECRET=mailguard-hmac-secret:latest \
  --min-instances 0 --max-instances 2 --memory 512Mi --cpu 1 --concurrency 20 --timeout 30
```

`--allow-unauthenticated` is required because Apps Script cannot present an identity token that
Cloud Run IAM accepts. `/analyze` is protected by the HMAC signature instead; only `/health` is open.
Scaling to zero and a 2-instance cap keep costs within the free tier.

### 4. Install the Gmail add-on (test deployment)

1. Go to [script.google.com](https://script.google.com) → **New project**, name it `MailGuard`.
2. **Project Settings** → enable **Show "appsscript.json" manifest file in editor**.
3. In the editor, replace the contents of `appsscript.json` and `Code.gs` with the files in
   [`addon/`](addon/). Update `urlFetchWhitelist` if your backend URL differs.
4. **Project Settings → Script Properties**, add:
   - `BACKEND_URL` = `https://mailguard-backend-PROJECT_NUMBER.REGION.run.app`
   - `HMAC_SECRET` = the secret value. Copy it without displaying it:
     `gcloud secrets versions access latest --secret=mailguard-hmac-secret | pbcopy`
     (then clear the clipboard with `pbcopy < /dev/null`).
5. **Deploy → Test deployments → Install**.
6. Open Gmail, open any email, click the MailGuard icon in the right sidebar, and authorize.

## Trade-offs, Limitations, and Future Work

_TBD_
