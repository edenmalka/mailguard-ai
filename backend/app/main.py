"""FastAPI application: HTTP endpoints and the request-handling pipeline.

Run locally with:
    uv run uvicorn app.main:create_app --factory --reload
"""

import logging

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app import __version__
from app.config import Settings
from app.pipeline import analyze_email
from app.schemas import AnalyzeRequest, AnalyzeResponse, decode_raw_message
from app.security import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify_signature

logger = logging.getLogger("mailguard")


async def read_limited_body(request: Request, limit: int) -> bytes:
    """Read the request body, refusing to buffer more than `limit` bytes.

    Checking Content-Length first rejects honest oversized requests cheaply; counting
    bytes while streaming also stops clients that lie about the length.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        if not (declared.isascii() and declared.isdigit()):
            raise HTTPException(status_code=400, detail="Invalid Content-Length")
        if int(declared) > limit:
            raise HTTPException(status_code=413, detail="Request too large")

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail="Request too large")
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()  # fails fast if MAILGUARD_HMAC_SECRET is missing
    logging.basicConfig(level=settings.log_level.upper())
    trusted_authserv_ids = frozenset(i.lower() for i in settings.trusted_authserv_ids)

    app = FastAPI(
        title="MailGuard API",
        version=__version__,
        # API docs are off by default so production does not advertise its schema.
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/analyze", response_model=AnalyzeResponse)
    async def analyze(request: Request) -> AnalyzeResponse:
        # 1. Size cap: never buffer an unbounded body from the network.
        body = await read_limited_body(request, settings.max_request_bytes)

        # 2. Authenticate BEFORE parsing, so untrusted senders never reach the JSON parser.
        if not verify_signature(
            secret=settings.hmac_secret.get_secret_value().encode(),
            timestamp=request.headers.get(TIMESTAMP_HEADER),
            signature=request.headers.get(SIGNATURE_HEADER),
            body=body,
            max_age_seconds=settings.signature_max_age_seconds,
        ):
            raise HTTPException(status_code=401, detail="Unauthorized")

        # 3. Validate the payload shape. Error details are not echoed back to the client.
        try:
            payload = AnalyzeRequest.model_validate_json(body)
            raw_message = decode_raw_message(payload.raw_message)
        except (ValidationError, ValueError):
            raise HTTPException(status_code=422, detail="Invalid request payload") from None

        if len(raw_message) > settings.max_message_bytes:
            raise HTTPException(status_code=413, detail="Message too large")

        # 4. Analyze in a worker thread: analysis is CPU-bound, and running it directly in
        #    this async handler would block every other request on the instance while it runs.
        #    Exceptions are reduced to their type name before logging, because exception
        #    messages can quote parts of the (private) email.
        try:
            result = await run_in_threadpool(analyze_email, raw_message, trusted_authserv_ids)
        except Exception as exc:
            logger.error("analysis failed: error_type=%s", type(exc).__name__)
            raise HTTPException(status_code=500, detail="Analysis failed") from None

        # Log metadata only: never the email content, sender, or recipients.
        logger.info(
            "analyze done: message_bytes=%d score=%d verdict=%s signals=%d",
            len(raw_message),
            result.score,
            result.verdict,
            len(result.signals),
        )
        return result

    return app
