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

_TBD — Cloud Run and add-on deployment steps._

## Trade-offs, Limitations, and Future Work

_TBD_
